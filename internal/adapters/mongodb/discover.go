package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
)

// dangerousRoleNames is a fallback for an incomplete role observation. A
// complete rolesInfo showPrivileges result is classified from actions and
// resources instead of trusting a display name.
var dangerousRoleNames = []string{
	"root",
	"__system",
	"dbOwner",
	"userAdmin",
	"clusterAdmin",
	"userAdminAnyDatabase",
	"dbAdminAnyDatabase",
	"readWriteAnyDatabase",
	"clusterManager",
	"clusterMonitor",
	"hostManager",
	"restore",
	"backup",
}

// dangerousRole reports whether an incompletely observed role name must fail
// closed as dangerous.
func dangerousRole(name string) bool { return slices.Contains(dangerousRoleNames, name) }

// Discover выполняет полную инвентаризацию: topology, databases и их объекты
// (collections, views, indexes), users, built-in и custom roles, role
// assignments. Все команды читают только метаданные; мутаций discovery не
// выполняет.
//
// Ошибка перечисления объектов или ролей отдельной базы не валит discovery
// целиком: база пропускается, а причина фиксируется в
// Topology["skipped_databases"] / Topology["skipped_roles"].
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	rolePolicyTemplates, err := mongodbconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		return nil, fmt.Errorf("mongodb: discover: role policy catalog: %w", err)
	}
	client, err := a.connect(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("mongodb: discover: %w", err)
	}
	defer disconnect(client)

	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: time.Now(),
	}

	hello, err := runHello(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("mongodb: discover: %w", err)
	}
	targetIdentity, topology, identityErr := discoverMongoTargetIdentity(ctx, client, hello)
	snap.Topology = topology
	snap.Topology["target_identity_available"] = identityErr == nil
	snap.ServerVersion = serverVersion(ctx, client)

	dbNames, err := client.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("mongodb: discover: list databases: %w", err)
	}
	slices.Sort(dbNames)

	dbSet := make(map[string]bool, len(dbNames))
	for _, name := range dbNames {
		dbSet[name] = true
		snap.Resources = append(snap.Resources, databaseResource(name))
	}

	var skippedDatabases []map[string]string
	for _, name := range dbNames {
		objects, objErr := discoverDatabaseObjects(ctx, client, name)
		if objErr != nil {
			skippedDatabases = append(skippedDatabases, map[string]string{
				"name":  name,
				"error": objErr.Error(),
			})
			continue
		}
		snap.Resources = append(snap.Resources, objects...)
	}
	if len(skippedDatabases) > 0 {
		snap.Topology["skipped_databases"] = skippedDatabases
	}

	accounts, bindings, assigned, err := discoverUsers(ctx, client, dbSet)
	if err != nil {
		return nil, fmt.Errorf("mongodb: discover: %w", err)
	}

	custom, skippedRoles := discoverRoles(ctx, client, dbNames)
	if len(skippedRoles) > 0 {
		snap.Topology["skipped_roles"] = skippedRoles
	}

	// Транзитивные роли: custom-роль наследует привилегии других ролей, и
	// пользователь, которому она назначена, фактически обладает и ими.
	// Раскрытие обязано идти ДО buildPermissions: унаследованная роль может
	// быть встроенной и никому напрямую не назначенной, а binding без
	// permission ломает консистентность снапшота.
	inheritedBindings, inheritedRoles := inheritedRoleBindings(bindings, custom, dbSet)
	for r := range inheritedRoles {
		assigned[r] = true
	}
	bindings = append(bindings, inheritedBindings...)

	permissions := buildPermissions(custom, assigned, dbSet)
	if len(rolePolicyTemplates) > 0 {
		writablePrimary, _ := snap.Topology["writable_primary"].(bool)
		policies, anySupported := discoverMongoRolePolicies(
			ctx, client, cfg, rolePolicyTemplates, targetIdentity, identityErr, writablePrimary,
		)
		snap.RolePolicies = policies
		snap.Topology[mongoRolePolicyCatalogFingerprintKey] =
			mongodbconfig.CatalogFingerprint(rolePolicyTemplates)
		snap.Topology[mongoRolePolicyApplySupportedKey] = anySupported
		permissions = annotateMongoRolePolicyPermissions(permissions, policies, dbSet)
	}

	snap.Accounts = accounts
	snap.Permissions = permissions
	snap.Bindings = bindings
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// topologyFromHello определяет тип топологии по ответу admin-команды hello:
// поле msg == "isdbgrid" — sharded (подключение к mongos); непустой setName —
// replica set; иначе standalone.
func topologyFromHello(hello bson.M) map[string]any {
	setName, _ := hello["setName"].(string)
	msg, _ := hello["msg"].(string)
	writablePrimary, _ := hello["isWritablePrimary"].(bool)

	topology := "standalone"
	switch {
	case msg == "isdbgrid":
		topology = "sharded"
	case setName != "":
		topology = "replica_set"
	}

	out := map[string]any{
		adapterutil.TopologyKey: topology,
		"writable_primary":      writablePrimary,
	}
	if setName != "" {
		out["set_name"] = setName
	}
	if hosts := stringSlice(hello["hosts"]); len(hosts) > 0 {
		out["hosts"] = hosts
	}
	return out
}

// serverVersion читает версию сервера через admin-команду buildInfo; при
// ошибке возвращает пустую строку (версия не критична для инвентаризации).
func serverVersion(ctx context.Context, client *mongo.Client) string {
	var info struct {
		Version string `bson:"version"`
	}
	if err := client.Database(adminDatabase).
		RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).
		Decode(&info); err != nil {
		return ""
	}
	return info.Version
}

// discoverDatabaseObjects перечисляет collections, views и indexes одной базы.
// Системные коллекции (префикс "system.") исключаются.
func discoverDatabaseObjects(ctx context.Context, client *mongo.Client, dbName string) ([]adapter.ObservedResource, error) {
	db := client.Database(dbName)
	cursor, err := db.ListCollections(ctx, bson.D{})
	if err != nil {
		return nil, fmt.Errorf("list collections in %q: %w", dbName, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var out []adapter.ObservedResource
	for cursor.Next(ctx) {
		var spec bson.M
		if err := cursor.Decode(&spec); err != nil {
			return nil, fmt.Errorf("decode collection in %q: %w", dbName, err)
		}
		name, _ := spec["name"].(string)
		if name == "" || strings.HasPrefix(name, "system.") {
			continue
		}
		collType, _ := spec["type"].(string)
		isView := collType == "view"

		attrs := map[string]any{}
		if opts := normalizeValue(spec["options"]); opts != nil {
			attrs["options"] = opts
		}
		if uuid := collectionUUID(spec); uuid != "" {
			attrs["uuid"] = uuid
		}

		if isView {
			id := viewExternalID(dbName, name)
			out = append(out, adapter.ObservedResource{
				Kind:             "view",
				ExternalID:       id,
				ParentExternalID: databaseExternalID(dbName),
				Name:             name,
				CanonicalPath:    dbName + "." + name,
				Attributes:       attrs,
				Fingerprint:      fingerprint("view", id, attrs),
			})
			continue
		}

		id := collectionExternalID(dbName, name)
		out = append(out, adapter.ObservedResource{
			Kind:             "collection",
			ExternalID:       id,
			ParentExternalID: databaseExternalID(dbName),
			Name:             name,
			CanonicalPath:    dbName + "." + name,
			Attributes:       attrs,
			Fingerprint:      fingerprint("collection", id, attrs),
		})

		indexes, err := discoverIndexes(ctx, db, dbName, name)
		if err != nil {
			return nil, err
		}
		out = append(out, indexes...)
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("read collections in %q: %w", dbName, err)
	}
	return out, nil
}

// discoverIndexes перечисляет индексы коллекции; родителем индекса считается
// его коллекция.
func discoverIndexes(ctx context.Context, db *mongo.Database, dbName, coll string) ([]adapter.ObservedResource, error) {
	cursor, err := db.Collection(coll).Indexes().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list indexes of %q.%q: %w", dbName, coll, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var out []adapter.ObservedResource
	for cursor.Next(ctx) {
		var spec bson.M
		if err := cursor.Decode(&spec); err != nil {
			return nil, fmt.Errorf("decode index of %q.%q: %w", dbName, coll, err)
		}
		name, _ := spec["name"].(string)
		if name == "" {
			continue
		}
		unique, _ := spec["unique"].(bool)
		attrs := map[string]any{
			"keys":   normalizeValue(spec["key"]),
			"unique": unique,
		}
		id := indexExternalID(dbName, coll, name)
		out = append(out, adapter.ObservedResource{
			Kind:             "index",
			ExternalID:       id,
			ParentExternalID: collectionExternalID(dbName, coll),
			Name:             name,
			CanonicalPath:    dbName + "." + coll + "." + name,
			Attributes:       attrs,
			Fingerprint:      fingerprint("index", id, attrs),
		})
	}
	if err := cursor.Err(); err != nil {
		return nil, fmt.Errorf("read indexes of %q.%q: %w", dbName, coll, err)
	}
	return out, nil
}

// roleRef — пара {role, db} назначения роли или наследования.
type roleRef struct {
	Role string `bson:"role"`
	DB   string `bson:"db"`
}

// userInfo — запись пользователя из usersInfo.
type userInfo struct {
	User  string    `bson:"user"`
	DB    string    `bson:"db"`
	Roles []roleRef `bson:"roles"`
}

// discoverUsers читает всех пользователей кластера через admin-команду
// usersInfo forAllDBs и превращает их в аккаунты и bindings. Возвращает также
// множество назначенных ролей, чтобы для каждой из них гарантированно создать
// permission (built-in роли отдельно не листятся).
func discoverUsers(ctx context.Context, client *mongo.Client, dbSet map[string]bool) ([]adapter.ObservedAccount, []adapter.ObservedBinding, map[roleRef]bool, error) {
	var result struct {
		Users []userInfo `bson:"users"`
	}
	cmd := bson.D{{Key: "usersInfo", Value: bson.D{{Key: "forAllDBs", Value: true}}}}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&result); err != nil {
		return nil, nil, nil, fmt.Errorf("read users: %w", err)
	}

	accounts := make([]adapter.ObservedAccount, 0, len(result.Users))
	var bindings []adapter.ObservedBinding
	assigned := map[roleRef]bool{}

	for _, u := range result.Users {
		if u.User == "" || u.DB == "" {
			continue
		}
		identity := engineIdentity(u.User, u.DB)
		accounts = append(accounts, adapter.ObservedAccount{
			Kind:           "login",
			EngineIdentity: identity,
			Attributes: map[string]any{
				"user":    u.User,
				"auth_db": u.DB,
			},
		})
		for _, r := range u.Roles {
			if r.Role == "" || r.DB == "" {
				continue
			}
			assigned[r] = true
			scope := ""
			if dbSet[r.DB] {
				scope = databaseExternalID(r.DB)
			}
			bindings = append(bindings, adapter.ObservedBinding{
				AccountEngineIdentity: identity,
				PermissionExternalID:  rolePermissionID(r.DB, r.Role),
				ScopeExternalID:       scope,
			})
		}
	}
	return accounts, bindings, assigned, nil
}

// customRole is the typed, secret-free subset of rolesInfo showPrivileges.
// DirectRoles/DirectPrivileges are the mutable role definition; inherited
// fields are the server-computed effective access used for danger analysis.
// Authentication restrictions are deliberately kept only as counts: the
// current template contract cannot reproduce them and therefore blocks
// mutation instead of silently removing or serializing raw BSON.
type customRole struct {
	Role                                string          `bson:"role"`
	DB                                  string          `bson:"db"`
	IsBuiltin                           bool            `bson:"isBuiltin"`
	DirectRoles                         []roleRef       `bson:"roles"`
	DirectPrivileges                    []rolePrivilege `bson:"privileges"`
	InheritedRoles                      []roleRef       `bson:"inheritedRoles"`
	InheritedPrivileges                 []rolePrivilege `bson:"inheritedPrivileges"`
	AuthenticationRestrictions          []bson.Raw      `bson:"authenticationRestrictions"`
	InheritedAuthenticationRestrictions []bson.Raw      `bson:"inheritedAuthenticationRestrictions"`
	ObservationComplete                 bool            `bson:"-"`
}

type rolePrivilege struct {
	Resource roleResource `bson:"resource"`
	Actions  []string     `bson:"actions"`
}

type roleResource struct {
	DB             string          `bson:"db"`
	Collection     string          `bson:"collection"`
	Cluster        bool            `bson:"cluster"`
	AnyResource    bool            `bson:"anyResource"`
	SystemBuckets  *string         `bson:"system_buckets,omitempty"`
	Unknown        map[string]any  `bson:",inline"`
	observedFields map[string]bool `bson:"-"`
}

// discoverRoles читает роли движка: встроенные (read, readWrite, dbAdmin, ...)
// и пользовательские.
//
// Встроенные читаются с showBuiltinRoles=true и раньше в каталог не попадали
// вовсе: permission для встроенной роли появлялся, только если она уже кому-то
// назначена, поэтому выдать read или readWrite через grantor было нельзя, а
// манифест такую роль не резолвил.
//
// Пользовательские берутся из admin.system.roles, а не из per-database
// rolesInfo: listDatabases не показывает базу без коллекций, и роль такой базы
// приходила без типа и без наследования — эскалация через неё была не видна.
// admin.system.roles авторитетен для всех баз сразу. Если коллекция
// недоступна, остаётся per-database путь: он беднее, но не молчит.
//
// Ошибка отдельной базы пропускается и фиксируется в skipped.
func discoverRoles(ctx context.Context, client *mongo.Client, dbNames []string) ([]customRole, []map[string]string) {
	var out []customRole
	var skipped []map[string]string
	seen := map[roleRef]int{}
	add := func(r customRole, fallbackDB string) {
		if r.Role == "" {
			return
		}
		if r.DB == "" {
			r.DB = fallbackDB
		}
		ref := roleRef{DB: r.DB, Role: r.Role}
		if index, exists := seen[ref]; exists {
			// admin.system.roles is only an enumeration fallback. A rolesInfo
			// result with showPrivileges always replaces that incomplete row.
			if r.ObservationComplete && !out[index].ObservationComplete {
				out[index] = r
			}
			return
		}
		seen[ref] = len(out)
		out = append(out, r)
	}

	// Пользовательские роли всех баз одним чтением.
	cur, err := client.Database("admin").Collection("system.roles").Find(ctx, bson.D{})
	if err != nil {
		skipped = append(skipped, map[string]string{"db": "admin.system.roles", "error": err.Error()})
	} else {
		var stored []customRole
		if err := cur.All(ctx, &stored); err != nil {
			skipped = append(skipped, map[string]string{"db": "admin.system.roles", "error": err.Error()})
		}
		for _, r := range stored {
			add(r, "")
		}
	}

	// All roles of every visible database, including built-ins. showPrivileges
	// is mandatory: role names and direct inheritance alone are insufficient
	// to classify custom access safely.
	targetSet := map[string]bool{"admin": true}
	for _, name := range dbNames {
		targetSet[name] = true
	}
	targets := make([]string, 0, len(targetSet))
	for name := range targetSet {
		targets = append(targets, name)
	}
	slices.Sort(targets)
	for _, name := range targets {
		var result struct {
			Roles []customRole `bson:"roles"`
		}
		cmd := bson.D{
			{Key: "rolesInfo", Value: 1},
			{Key: "showBuiltinRoles", Value: true},
			{Key: "showPrivileges", Value: true},
			{Key: "showAuthenticationRestrictions", Value: true},
		}
		if err := client.Database(name).RunCommand(ctx, cmd).Decode(&result); err != nil {
			skipped = append(skipped, map[string]string{"db": name, "error": err.Error()})
			continue
		}
		for _, r := range result.Roles {
			r.ObservationComplete = true
			add(r, name)
		}
	}

	// A custom role can belong to a database with no materialized collections,
	// so ListDatabases does not necessarily include its database. system.roles
	// discovered the identity above; fetch each still-incomplete definition
	// through rolesInfo to obtain exact direct and inherited privileges.
	for _, candidate := range slices.Clone(out) {
		if candidate.ObservationComplete || candidate.Role == "" || candidate.DB == "" {
			continue
		}
		var result struct {
			Roles []customRole `bson:"roles"`
		}
		cmd := bson.D{
			{Key: "rolesInfo", Value: bson.D{
				{Key: "role", Value: candidate.Role},
				{Key: "db", Value: candidate.DB},
			}},
			{Key: "showPrivileges", Value: true},
			{Key: "showAuthenticationRestrictions", Value: true},
		}
		if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&result); err != nil {
			skipped = append(skipped, map[string]string{
				"db": candidate.DB, "role": candidate.Role, "error": err.Error(),
			})
			continue
		}
		for _, role := range result.Roles {
			role.ObservationComplete = true
			add(role, candidate.DB)
		}
	}
	return out, skipped
}

// inheritedRoleBindings раскрывает транзитивное наследование ролей.
//
// В MongoDB custom-роль наследует привилегии других ролей (customRole.roles),
// поэтому пользователь, которому она назначена, фактически обладает и правами
// унаследованных ролей. Прямые назначения дают только первое звено — без
// раскрытия унаследованное право не появлялось в инвентаре вовсе.
//
// Возвращает дополнительные bindings и набор ролей, которым необходимо
// создать permission: унаследованная роль бывает встроенной и никому
// напрямую не назначенной, а binding без permission ломает консистентность
// снапшота (её проверяет contract suite).
func inheritedRoleBindings(userBindings []adapter.ObservedBinding, custom []customRole,
	dbSet map[string]bool) ([]adapter.ObservedBinding, map[roleRef]bool) {
	if len(custom) == 0 || len(userBindings) == 0 {
		return nil, nil
	}

	edges := make([]adapterutil.MembershipEdge, 0, len(userBindings)+len(custom))
	// Прямые назначения: роль -> пользователь.
	for _, b := range userBindings {
		edges = append(edges, adapterutil.MembershipEdge{
			Role:   b.PermissionExternalID,
			Member: b.AccountEngineIdentity,
		})
	}
	// Наследование: унаследованная роль -> наследующая роль.
	for _, r := range custom {
		child := rolePermissionID(r.DB, r.Role)
		for _, ir := range r.DirectRoles {
			if ir.Role == "" || ir.DB == "" {
				continue
			}
			edges = append(edges, adapterutil.MembershipEdge{
				Role:   rolePermissionID(ir.DB, ir.Role),
				Member: child,
			})
		}
	}

	// Учётные записи отличаются от ролей по тому, что их identity не
	// встречается среди ключей ролей: роль всегда адресуется role:<db>.<name>.
	accountIdentities := map[string]bool{}
	for _, b := range userBindings {
		accountIdentities[b.AccountEngineIdentity] = true
	}

	var out []adapter.ObservedBinding
	roles := map[roleRef]bool{}
	for _, e := range adapterutil.InheritedMemberships(edges) {
		if !accountIdentities[e.Member] {
			continue
		}
		ref, ok := roleRefFromPermissionID(e.Role)
		if !ok {
			continue
		}
		scope := ""
		if dbSet[ref.DB] {
			scope = databaseExternalID(ref.DB)
		}
		roles[ref] = true
		out = append(out, adapter.ObservedBinding{
			AccountEngineIdentity: e.Member,
			PermissionExternalID:  e.Role,
			ScopeExternalID:       scope,
			Inherited:             true,
			Attributes:            map[string]any{"inherited": true},
		})
	}
	return out, roles
}

// roleRefFromPermissionID разбирает role:<db>.<name> обратно в пару.
// Разбор однозначен: имя базы в MongoDB не может содержать точку, поэтому
// первая точка после префикса всегда разделяет базу и имя роли.
func roleRefFromPermissionID(id string) (roleRef, bool) {
	rest, ok := strings.CutPrefix(id, "role:")
	if !ok {
		return roleRef{}, false
	}
	db, name, ok := strings.Cut(rest, ".")
	if !ok || db == "" || name == "" {
		return roleRef{}, false
	}
	return roleRef{DB: db, Role: name}, true
}

// buildPermissions собирает permissions из ролей движка и назначенных ролей.
// Каждая назначенная роль обязана получить permission, иначе binding сослался
// бы на несуществующий permission (contract suite проверяет консистентность).
// Полностью наблюдаемая роль классифицируется по effective actions/resources;
// имя не является доказательством безопасности. Для incomplete fallback
// используется консервативная классификация.
//
// Ветка assigned остаётся страховкой: роль, назначенная пользователю, но не
// вернувшаяся ни из admin.system.roles, ни из rolesInfo (недоступная база,
// урезанные права admin-учётки), всё равно обязана появиться в каталоге —
// иначе снапшот не консистентен.
func buildPermissions(custom []customRole, assigned map[roleRef]bool, dbSet map[string]bool) []adapter.ObservedPermission {
	byID := map[string]adapter.ObservedPermission{}

	for _, r := range custom {
		id := rolePermissionID(r.DB, r.Role)
		inherited := make([]string, 0, len(r.DirectRoles))
		reasons := roleDangerReasons(r)
		// A complete rolesInfo showPrivileges result is classified from its
		// effective actions/resources. Only incomplete fallback observations
		// use role names conservatively; no partial custom role becomes safe.
		dangerous := len(reasons) > 0
		for _, ir := range r.DirectRoles {
			inherited = append(inherited, ir.DB+"."+ir.Role)
			if !r.ObservationComplete && dangerousRole(ir.Role) {
				dangerous = true
			}
		}
		if !r.ObservationComplete && dangerousRole(r.Role) {
			dangerous = true
		}
		// Preserve the existing product contract: MongoDB's built-in read and
		// readWrite permissions remain ordinary assignable permissions. Their
		// server-defined action sets may grow between versions, but their
		// identity and semantics are owned by MongoDB, not by a custom policy.
		if r.IsBuiltin && (r.Role == "read" || r.Role == "readWrite") {
			dangerous = false
		}
		slices.Sort(inherited)
		byID[id] = adapter.ObservedPermission{
			ExternalID:      id,
			Name:            r.Role,
			ScopeExternalID: scopeForDB(r.DB, dbSet),
			Assignable:      r.ObservationComplete && !roleHasUnsupportedResource(r),
			Dangerous:       dangerous,
			Attributes: map[string]any{
				"role_db":             r.DB,
				"builtin":             r.IsBuiltin,
				"inherited_roles":     inherited,
				"privileges_observed": r.ObservationComplete,
			},
		}
	}

	for r := range assigned {
		id := rolePermissionID(r.DB, r.Role)
		if _, ok := byID[id]; ok {
			continue
		}
		legacyBuiltin := r.Role == "read" || r.Role == "readWrite"
		byID[id] = adapter.ObservedPermission{
			ExternalID:      id,
			Name:            r.Role,
			ScopeExternalID: scopeForDB(r.DB, dbSet),
			Assignable:      legacyBuiltin,
			Dangerous:       !legacyBuiltin,
			Attributes: map[string]any{
				"role_db":                r.DB,
				"builtin":                legacyBuiltin,
				"privileges_observed":    false,
				"observation_incomplete": true,
			},
		}
	}

	out := make([]adapter.ObservedPermission, 0, len(byID))
	for _, p := range byID {
		out = append(out, p)
	}
	return out
}

// scopeForDB возвращает external id базы как scope permission, если такая база
// присутствует в инвентаре; иначе пустую строку (cluster-wide/неизвестный
// scope).
func scopeForDB(db string, dbSet map[string]bool) string {
	if dbSet[db] {
		return databaseExternalID(db)
	}
	return ""
}

// collectionUUID извлекает UUID коллекции из info.uuid как hex-строку.
func collectionUUID(spec bson.M) string {
	info, ok := spec["info"].(bson.M)
	if !ok {
		return ""
	}
	if bin, ok := info["uuid"].(primitive.Binary); ok {
		return hex.EncodeToString(bin.Data)
	}
	return ""
}

// databaseResource строит ресурс kind database.
func databaseResource(name string) adapter.ObservedResource {
	attrs := map[string]any{}
	id := databaseExternalID(name)
	return adapter.ObservedResource{
		Kind:          "database",
		ExternalID:    id,
		Name:          name,
		CanonicalPath: name,
		Attributes:    attrs,
		Fingerprint:   fingerprint("database", id, attrs),
	}
}

// engineIdentity кодирует пару (username, auth_database) в EngineIdentity.
func engineIdentity(user, authDB string) string { return user + "@" + authDB }

// databaseExternalID возвращает external id базы.
func databaseExternalID(db string) string { return "db:" + db }

// collectionExternalID возвращает external id коллекции.
func collectionExternalID(db, name string) string { return "collection:" + db + "." + name }

// viewExternalID возвращает external id представления.
func viewExternalID(db, name string) string { return "view:" + db + "." + name }

// indexExternalID возвращает external id индекса.
func indexExternalID(db, coll, name string) string {
	return "index:" + db + "." + coll + "." + name
}

// rolePermissionID возвращает external id permission для роли, scoped к db.
func rolePermissionID(db, name string) string { return "role:" + db + "." + name }

// stringSlice приводит значение bson-массива к []string, отбрасывая
// нестроковые элементы. Понимает bson.A, []any и []string.
func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case bson.A:
		return elementsToStrings(t)
	case []any:
		return elementsToStrings(t)
	default:
		return nil
	}
}

// elementsToStrings собирает строковые элементы среза any.
func elementsToStrings(in []any) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// normalizeValue приводит произвольное bson-значение к «плоским» Go-типам
// (map[string]any / []any / скаляры), заменяя driver-специфичные типы
// стабильными строковыми представлениями. Это гарантирует детерминированную
// сериализацию для fingerprint и корректное хранение в jsonb.
func normalizeValue(v any) any {
	switch t := v.(type) {
	case bson.M:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = normalizeValue(val)
		}
		return m
	case bson.D:
		m := make(map[string]any, len(t))
		for _, e := range t {
			m[e.Key] = normalizeValue(e.Value)
		}
		return m
	case map[string]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = normalizeValue(val)
		}
		return m
	case bson.A:
		return normalizeSlice(t)
	case []any:
		return normalizeSlice(t)
	case primitive.Binary:
		return hex.EncodeToString(t.Data)
	case primitive.ObjectID:
		return t.Hex()
	case primitive.DateTime:
		return t.Time().UTC().Format(time.RFC3339Nano)
	case primitive.Timestamp:
		return fmt.Sprintf("%d:%d", t.T, t.I)
	default:
		return v
	}
}

// normalizeSlice нормализует элементы среза.
func normalizeSlice(in []any) []any {
	out := make([]any, len(in))
	for i, e := range in {
		out[i] = normalizeValue(e)
	}
	return out
}

// fingerprint строит стабильный отпечаток ресурса по kind, external id и
// атрибутам. Ключи атрибутов сортируются, а значения кодируются каноничным
// JSON (encoding/json сортирует ключи вложенных map), поэтому одно и то же
// содержимое всегда даёт один и тот же отпечаток независимо от порядка map.
func fingerprint(kind, externalID string, attrs map[string]any) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(attrs)+2)
	parts = append(parts, kind, externalID)
	for _, k := range keys {
		enc, err := json.Marshal(attrs[k])
		if err != nil {
			enc = []byte(fmt.Sprintf("%v", attrs[k]))
		}
		parts = append(parts, k+"="+string(enc))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])[:16]
}

// sortSnapshot приводит snapshot к детерминированному порядку: contract suite
// требует стабильности между повторными discovery.
func sortSnapshot(snap *adapter.Snapshot) {
	slices.SortFunc(snap.Resources, func(a, b adapter.ObservedResource) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	slices.SortFunc(snap.Accounts, func(a, b adapter.ObservedAccount) int {
		return strings.Compare(a.EngineIdentity, b.EngineIdentity)
	})
	slices.SortFunc(snap.Permissions, func(a, b adapter.ObservedPermission) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
	slices.SortFunc(snap.Bindings, func(a, b adapter.ObservedBinding) int {
		if c := strings.Compare(a.AccountEngineIdentity, b.AccountEngineIdentity); c != 0 {
			return c
		}
		if c := strings.Compare(a.PermissionExternalID, b.PermissionExternalID); c != 0 {
			return c
		}
		return strings.Compare(a.ScopeExternalID, b.ScopeExternalID)
	})
	slices.SortFunc(snap.RolePolicies, func(a, b adapter.ObservedRolePolicy) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
}
