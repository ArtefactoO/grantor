package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// systemDatabases — служебные базы ClickHouse, исключаемые из инвентаризации.
var systemDatabases = map[string]bool{
	"system":             true,
	"INFORMATION_SCHEMA": true,
	"information_schema": true,
}

// Discover выполняет полную инвентаризацию сервера: топология
// (system.clusters), базы данных, пользователи, роли, ролевые назначения и
// прямые privilege-гранты. Все запросы читают только системные таблицы;
// мутаций discovery не выполняет.
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	client, err := a.newClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}

	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: time.Now(),
	}

	version, err := client.serverVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}
	snap.ServerVersion = version

	hosts, err := client.clusterHosts(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}
	snap.Topology = topologyFromClusters(hosts)

	databases, err := client.listDatabases(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}
	dbSet := make(map[string]bool, len(databases))
	for _, d := range databases {
		if systemDatabases[d.Name] {
			continue
		}
		dbSet[d.Name] = true
		snap.Resources = append(snap.Resources, databaseResource(d))
	}

	users, err := client.listUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}
	userSet := make(map[string]bool, len(users))
	for _, u := range users {
		if u.Name == "" {
			continue
		}
		userSet[u.Name] = true
		snap.Accounts = append(snap.Accounts, userToObserved(u))
	}

	roles, err := client.listRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}
	grants, err := client.listGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}

	// Гранты делятся на определения ролей (role_name) и прямые гранты
	// пользователей (user_name). Первые формируют dangerous-признак и
	// атрибуты роли, вторые — наблюдаемые priv-permissions и bindings.
	grantsByRole := map[string][]chGrant{}
	var userGrants []chGrant
	for _, g := range grants {
		switch {
		case g.RoleName != "":
			grantsByRole[g.RoleName] = append(grantsByRole[g.RoleName], g)
		case g.UserName != "":
			userGrants = append(userGrants, g)
		}
	}

	roleGrants, err := client.listRoleGrants(ctx)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: discover: %w", err)
	}

	// Роли, вложенные в роль. Нужны до построения permissions: dangerous
	// считается по действующим правам роли, а не только по собственным.
	nestedRoles := map[string][]string{}
	for _, rg := range roleGrants {
		if rg.RoleName != "" && rg.GrantedRole != "" {
			nestedRoles[rg.RoleName] = append(nestedRoles[rg.RoleName], rg.GrantedRole)
		}
	}
	effectiveGrants := effectiveRoleGrants(grantsByRole, nestedRoles)
	danger := client.loadDangerousPrivileges(ctx)

	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		if r.Name == "" {
			continue
		}
		roleSet[r.Name] = true
		snap.Permissions = append(snap.Permissions,
			rolePermission(r, grantsByRole[r.Name], effectiveGrants[r.Name], danger))
	}

	privPerms, privBindings := buildPrivilegeGrants(userGrants, userSet, dbSet, danger)
	snap.Permissions = append(snap.Permissions, privPerms...)
	snap.Bindings = append(snap.Bindings, privBindings...)

	// Граф членства: рёбра пользователь→роль и роль→роль. Вторые сами по
	// себе bindings не порождают (у роли нет учётной записи), но без них
	// нельзя раскрыть цепочки.
	membership := make([]adapterutil.MembershipEdge, 0, len(roleGrants))
	for _, rg := range roleGrants {
		member := rg.UserName
		if member == "" {
			member = rg.RoleName
		}
		if member != "" && rg.GrantedRole != "" {
			membership = append(membership,
				adapterutil.MembershipEdge{Role: rg.GrantedRole, Member: member})
		}

		// Binding создаётся только для рёбер пользователь→роль, где обе
		// вершины присутствуют в инвентаре (contract suite проверяет
		// консистентность); рёбра роль→роль пропускаются.
		if rg.UserName == "" || !userSet[rg.UserName] || !roleSet[rg.GrantedRole] {
			continue
		}
		snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
			AccountEngineIdentity: rg.UserName,
			PermissionExternalID:  rolePermissionID(rg.GrantedRole),
			Attributes: map[string]any{
				"admin_option": rg.AdminOption,
				"default_role": rg.DefaultRole,
				// Роль вне набора по умолчанию доступа не даёт: она есть в
				// system.role_grants, а запрос отвергается ACCESS_DENIED.
				adapter.AttrBindingEffective: rg.DefaultRole,
			},
		})
	}

	// Роль, выданная роли, приносит свои права и пользователю. Без раскрытия
	// такое право не попадало в инвентарь вовсе. admin_option и default_role
	// не переносятся: они описывают прямой грант.
	for _, e := range adapterutil.InheritedMemberships(membership) {
		if !userSet[e.Member] || !roleSet[e.Role] {
			continue
		}
		snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
			AccountEngineIdentity: e.Member,
			PermissionExternalID:  rolePermissionID(e.Role),
			Inherited:             true,
			Attributes:            map[string]any{"inherited": true},
		})
	}
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// --- Чтение системных таблиц ---

// serverVersion читает версию сервера.
func (c *chClient) serverVersion(ctx context.Context) (string, error) {
	rows, err := c.query(ctx, `SELECT version() AS version`, nil)
	if err != nil {
		return "", fmt.Errorf("read server version: %w", err)
	}
	if len(rows) == 0 {
		return "", errors.New("read server version: empty response")
	}
	return rawString(rows[0], "version"), nil
}

// chClusterHost — строка system.clusters.
type chClusterHost struct {
	Cluster  string
	HostName string
	Port     int64
	IsLocal  bool
}

// clusterHosts читает участников кластеров из system.clusters.
func (c *chClient) clusterHosts(ctx context.Context) ([]chClusterHost, error) {
	rows, err := c.query(ctx,
		`SELECT cluster, host_name, port, is_local FROM system.clusters ORDER BY cluster, shard_num, replica_num`, nil)
	if err != nil {
		return nil, fmt.Errorf("read clusters: %w", err)
	}
	out := make([]chClusterHost, 0, len(rows))
	for _, row := range rows {
		out = append(out, chClusterHost{
			Cluster:  rawString(row, "cluster"),
			HostName: rawString(row, "host_name"),
			Port:     rawInt(row, "port"),
			IsLocal:  rawBool(row, "is_local"),
		})
	}
	return out, nil
}

// chDatabase — строка system.databases.
type chDatabase struct {
	Name   string
	Engine string
}

// listDatabases читает базы данных из system.databases.
func (c *chClient) listDatabases(ctx context.Context) ([]chDatabase, error) {
	rows, err := c.query(ctx, `SELECT name, engine FROM system.databases ORDER BY name`, nil)
	if err != nil {
		return nil, fmt.Errorf("read databases: %w", err)
	}
	out := make([]chDatabase, 0, len(rows))
	for _, row := range rows {
		out = append(out, chDatabase{Name: rawString(row, "name"), Engine: rawString(row, "engine")})
	}
	return out, nil
}

// chUser — строка system.users.
type chUser struct {
	Name       string
	Storage    string
	AuthTypes  []string
	HostIP     []string
	HostNames  []string
	HostRegexp []string
	HostLike   []string
}

// listUsers читает пользователей из system.users.
func (c *chClient) listUsers(ctx context.Context) ([]chUser, error) {
	rows, err := c.query(ctx,
		`SELECT name, storage, auth_type, host_ip, host_names, host_names_regexp, host_names_like
FROM system.users ORDER BY name`, nil)
	if err != nil {
		return nil, fmt.Errorf("read users: %w", err)
	}
	out := make([]chUser, 0, len(rows))
	for _, row := range rows {
		out = append(out, parseUser(row))
	}
	return out, nil
}

// parseUser разбирает строку system.users. auth_type может быть строкой
// (до 24.9) или массивом строк (24.9+, несколько методов аутентификации).
func parseUser(row map[string]json.RawMessage) chUser {
	return chUser{
		Name:       rawString(row, "name"),
		Storage:    rawString(row, "storage"),
		AuthTypes:  parseAuthTypes(row["auth_type"]),
		HostIP:     rawStrings(row, "host_ip"),
		HostNames:  rawStrings(row, "host_names"),
		HostRegexp: rawStrings(row, "host_names_regexp"),
		HostLike:   rawStrings(row, "host_names_like"),
	}
}

// chRole — строка system.roles.
type chRole struct {
	Name    string
	Storage string
}

// listRoles читает роли из system.roles.
func (c *chClient) listRoles(ctx context.Context) ([]chRole, error) {
	rows, err := c.query(ctx, `SELECT name, storage FROM system.roles ORDER BY name`, nil)
	if err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	out := make([]chRole, 0, len(rows))
	for _, row := range rows {
		out = append(out, chRole{Name: rawString(row, "name"), Storage: rawString(row, "storage")})
	}
	return out, nil
}

// chRoleGrant — строка system.role_grants.
type chRoleGrant struct {
	UserName    string
	RoleName    string
	GrantedRole string
	AdminOption bool
	DefaultRole bool
}

// listRoleGrants читает ролевые назначения из system.role_grants.
func (c *chClient) listRoleGrants(ctx context.Context) ([]chRoleGrant, error) {
	rows, err := c.query(ctx,
		`SELECT user_name, role_name, granted_role_name, granted_role_is_default, with_admin_option
FROM system.role_grants ORDER BY user_name, role_name, granted_role_name`, nil)
	if err != nil {
		return nil, fmt.Errorf("read role grants: %w", err)
	}
	out := make([]chRoleGrant, 0, len(rows))
	for _, row := range rows {
		out = append(out, chRoleGrant{
			UserName:    rawString(row, "user_name"),
			RoleName:    rawString(row, "role_name"),
			GrantedRole: rawString(row, "granted_role_name"),
			AdminOption: rawBool(row, "with_admin_option"),
			DefaultRole: rawBool(row, "granted_role_is_default"),
		})
	}
	return out, nil
}

// chGrant — строка system.grants (privilege-грант пользователя или роли).
type chGrant struct {
	UserName      string
	RoleName      string
	AccessType    string
	Database      string
	Table         string
	Column        string
	PartialRevoke bool
	GrantOption   bool
}

// listGrants читает privilege-гранты из system.grants.
func (c *chClient) listGrants(ctx context.Context) ([]chGrant, error) {
	rows, err := c.query(ctx,
		"SELECT user_name, role_name, access_type, database, `table`, `column`, is_partial_revoke, grant_option\n"+
			"FROM system.grants ORDER BY user_name, role_name, access_type, database, `table`, `column`", nil)
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	out := make([]chGrant, 0, len(rows))
	for _, row := range rows {
		out = append(out, chGrant{
			UserName:      rawString(row, "user_name"),
			RoleName:      rawString(row, "role_name"),
			AccessType:    rawString(row, "access_type"),
			Database:      rawString(row, "database"),
			Table:         rawString(row, "table"),
			Column:        rawString(row, "column"),
			PartialRevoke: rawBool(row, "is_partial_revoke"),
			GrantOption:   rawBool(row, "grant_option"),
		})
	}
	return out, nil
}

// --- Отображение в snapshot ---

// databaseResource строит ресурс kind database.
func databaseResource(d chDatabase) adapter.ObservedResource {
	attrs := map[string]any{}
	if d.Engine != "" {
		attrs["engine"] = d.Engine
	}
	id := databaseExternalID(d.Name)
	return adapter.ObservedResource{
		Kind:          "database",
		ExternalID:    id,
		Name:          d.Name,
		CanonicalPath: d.Name,
		Attributes:    attrs,
		Fingerprint:   fingerprint("database", id, attrs),
	}
}

// userToObserved превращает пользователя в аккаунт. Disabled определяется по
// пустому набору host-ограничений (состояние HOST NONE, см. doc-комментарий
// пакета).
func userToObserved(u chUser) adapter.ObservedAccount {
	attrs := map[string]any{}
	if u.Storage != "" {
		attrs["storage"] = u.Storage
	}
	if len(u.AuthTypes) > 0 {
		attrs["auth_types"] = u.AuthTypes
	}
	if len(u.HostIP) > 0 {
		attrs["host_ip"] = u.HostIP
	}
	if len(u.HostNames) > 0 {
		attrs["host_names"] = u.HostNames
	}
	if len(u.HostRegexp) > 0 {
		attrs["host_names_regexp"] = u.HostRegexp
	}
	if len(u.HostLike) > 0 {
		attrs["host_names_like"] = u.HostLike
	}
	return adapter.ObservedAccount{
		Kind:           "login",
		EngineIdentity: u.Name,
		Disabled:       hostNone(u),
		Attributes:     attrs,
	}
}

// hostNone сообщает, что у пользователя нет ни одного разрешённого host
// (состояние HOST NONE — подключение запрещено отовсюду). HOST ANY
// отображается в system.users как host_ip ['::/0'], поэтому пустота всех
// четырёх списков возможна только после HOST NONE.
func hostNone(u chUser) bool {
	return len(u.HostIP) == 0 && len(u.HostNames) == 0 && len(u.HostRegexp) == 0 && len(u.HostLike) == 0
}

// rolePermission строит назначаемую permission из роли и её грантов.
// effective — гранты роли вместе с грантами всех вложенных в неё ролей;
// в атрибуты попадают только собственные, а dangerous считается по
// действующим (см. roleDangerous).
func rolePermission(r chRole, grants, effective []chGrant, danger dangerSet) adapter.ObservedPermission {
	attrs := map[string]any{"kind": "role"}
	if r.Storage != "" {
		attrs["storage"] = r.Storage
	}
	var privs []string
	for _, g := range grants {
		if g.PartialRevoke {
			continue
		}
		privs = append(privs, formatGrant(g))
	}
	if len(privs) > 0 {
		slices.Sort(privs)
		attrs["privileges"] = privs
	}
	return adapter.ObservedPermission{
		ExternalID: rolePermissionID(r.Name),
		Name:       r.Name,
		Assignable: true,
		Dangerous:  roleDangerous(effective, danger),
		Attributes: attrs,
	}
}

// roleDangerous сообщает, содержит ли набор грантов опасные привилегии:
// привилегию из опасной группы, глобальный ALL или любой грант
// WITH GRANT OPTION.
func roleDangerous(grants []chGrant, danger dangerSet) bool {
	for _, g := range grants {
		if g.PartialRevoke {
			continue
		}
		if g.GrantOption || dangerousAccessType(danger, g.AccessType, g.Database == "") {
			return true
		}
	}
	return false
}

// effectiveRoleGrants возвращает для каждой роли её собственные гранты плюс
// гранты всех вложенных ролей.
//
// Роль, которой выдана другая роль, наделяет своих членов и её правами:
// обёртка над ACCESS MANAGEMENT даёт то же управление доступом. Пока
// dangerous считался только по собственным грантам, такая обёртка проходила
// гейт как безобидная — а через унаследованный WITH GRANT OPTION её член
// раздавал чужой доступ.
//
// nested[role] — роли, выданные роли role. Цикл в графе невозможен (ClickHouse
// его не создаёт), но обход всё равно защищён от повторного входа.
func effectiveRoleGrants(own map[string][]chGrant, nested map[string][]string) map[string][]chGrant {
	out := make(map[string][]chGrant, len(own))
	for role := range nested {
		if _, ok := own[role]; !ok {
			own[role] = nil
		}
	}
	for role := range own {
		seen := map[string]bool{role: true}
		queue := append([]string(nil), nested[role]...)
		grants := append([]chGrant(nil), own[role]...)
		for len(queue) > 0 {
			next := queue[0]
			queue = queue[1:]
			if seen[next] {
				continue
			}
			seen[next] = true
			grants = append(grants, own[next]...)
			queue = append(queue, nested[next]...)
		}
		out[role] = grants
	}
	return out
}

// buildPrivilegeGrants строит наблюдаемые priv-permissions и bindings из
// прямых грантов пользователей. Учитываются только глобальные гранты и
// гранты уровня базы (таблицы/колонки и partial revokes пропускаются, как и
// гранты на базы вне инвентаря).
func buildPrivilegeGrants(grants []chGrant, userSet, dbSet map[string]bool, danger dangerSet) ([]adapter.ObservedPermission, []adapter.ObservedBinding) {
	var permissions []adapter.ObservedPermission
	var bindings []adapter.ObservedBinding
	seen := map[string]bool{}
	for _, g := range grants {
		if !userSet[g.UserName] {
			continue
		}
		id := privPermissionID(g)
		// Scope — база, если она есть в инвентаре. Гранты на таблицу и
		// колонку остаются в scope своей базы: ресурсов уровня таблицы
		// adapter не публикует, поэтому объект уточняется атрибутами и
		// именем права.
		scope := ""
		if g.Database != "" && dbSet[g.Database] {
			scope = databaseExternalID(g.Database)
		}
		if !seen[id] {
			seen[id] = true
			attrs := map[string]any{
				"kind":        "privilege",
				"access_type": g.AccessType,
			}
			if g.Database != "" {
				attrs["database"] = g.Database
			}
			if g.Table != "" {
				attrs["table"] = g.Table
			}
			if g.Column != "" {
				attrs["column"] = g.Column
			}
			if g.PartialRevoke {
				attrs["partial_revoke"] = true
			}
			permissions = append(permissions, adapter.ObservedPermission{
				ExternalID:      id,
				Name:            privPermissionName(g),
				ScopeExternalID: scope,
				// Прямые гранты — наблюдаемые: adapter выдаёт доступ только
				// через роли (см. doc-комментарий пакета).
				Assignable: false,
				// Частичный revoke сужает доступ, а не расширяет: опасным он
				// быть не может.
				Dangerous:  !g.PartialRevoke && dangerousAccessType(danger, g.AccessType, g.Database == ""),
				Attributes: attrs,
			})
		}
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: g.UserName,
			PermissionExternalID:  id,
			ScopeExternalID:       scope,
			Attributes:            map[string]any{"grant_option": g.GrantOption},
		})
	}
	return permissions, bindings
}

// dangerousPrivilegeGroups — группы привилегий ClickHouse, дающие
// административный контроль над сервером, управление доступом или чтение
// чужих секретов. Калибровка та же, что у mysql adapter
// (dangerousGlobalPrivileges): опасно то, что ведёт к эскалации или к
// контролю над сервером, а не то, что просто разрушительно в своей области.
// Поэтому SELECT/INSERT/ALTER/DROP на *.* сами по себе сюда не входят.
var dangerousPrivilegeGroups = []string{
	"ACCESS MANAGEMENT",             // управление пользователями и ролями
	"SYSTEM",                        // SHUTDOWN, RELOAD, RESTART REPLICA, ...
	"SOURCES",                       // FILE/URL/REMOTE/MYSQL/S3: чтение извне и чужие креды
	"INTROSPECTION",                 // addressToSymbol и прочая интроспекция процесса
	"NAMED COLLECTION ADMIN",        // именованные коллекции хранят секреты подключений
	"displaySecretsInShowAndSelect", // показ секретов в SHOW CREATE и SELECT
	"SET DEFINER",                   // выполнение от имени другого пользователя
}

// staticDangerousPrivileges — offline-список членов опасных групп. Основной
// источник — system.privileges самого сервера (loadDangerousPrivileges); этот
// список нужен там, где сервера под рукой нет: объяснение опасности по уже
// сохранённым атрибутам (privilegeLooksDangerous) и старые версии ClickHouse
// без system.privileges. Состав ACCESS MANAGEMENT и SOURCES стабилен между
// версиями; группа SYSTEM ловится префиксом в dangerSet.has.
var staticDangerousPrivileges = []string{
	// ACCESS MANAGEMENT
	"CREATE USER", "ALTER USER", "DROP USER",
	"CREATE ROLE", "ALTER ROLE", "DROP ROLE", "ROLE ADMIN",
	"CREATE ROW POLICY", "ALTER ROW POLICY", "DROP ROW POLICY",
	"CREATE QUOTA", "ALTER QUOTA", "DROP QUOTA",
	"CREATE SETTINGS PROFILE", "ALTER SETTINGS PROFILE", "DROP SETTINGS PROFILE",
	"ALLOW SQL SECURITY NONE", "SHOW ACCESS",
	// SOURCES
	"FILE", "URL", "REMOTE", "MONGO", "REDIS", "MYSQL", "POSTGRES",
	"SQLITE", "ODBC", "JDBC", "HDFS", "S3", "HIVE", "AZURE",
	// INTROSPECTION
	"addressToLine", "addressToLineWithInlines", "addressToSymbol", "demangle",
}

// dangerSet — набор access_type, считающихся опасными, в нижнем регистре.
// Строится по system.privileges конкретного сервера: ClickHouse хранит в
// system.grants КОНКРЕТНЫЙ тип, а не группу (GRANT ALL разворачивается в
// список типов, GRANT SYSTEM — в SYSTEM SHUTDOWN, SYSTEM RELOAD и так далее),
// поэтому сравнение с именами групп само по себе ничего не ловит.
type dangerSet map[string]bool

// has сообщает, что тип привилегии опасен. Отдельная ветка для SYSTEM:
// все члены группы называются "SYSTEM <действие>", поэтому префикс покрывает
// и те, которых нет ни в справочнике сервера, ни в статическом списке.
func (d dangerSet) has(access string) bool {
	a := strings.ToLower(strings.TrimSpace(access))
	return d[a] || strings.HasPrefix(a, "system ")
}

// newDangerSet строит набор из имён групп и статического списка их членов.
func newDangerSet() dangerSet {
	out := dangerSet{}
	for _, g := range dangerousPrivilegeGroups {
		out[strings.ToLower(g)] = true
	}
	for _, p := range staticDangerousPrivileges {
		out[strings.ToLower(p)] = true
	}
	return out
}

// loadDangerousPrivileges строит набор опасных access_type, разворачивая
// группы из dangerousPrivilegeGroups по иерархии system.privileges.
//
// Справочник читается с самого сервера, а не зашит в код: состав групп
// меняется между версиями ClickHouse, и устаревший список означал бы
// пропущенное опасное право. Если таблицы нет (старая версия) или она
// недоступна, остаются сами имена групп — беднее, но не опаснее прежнего.
func (c *chClient) loadDangerousPrivileges(ctx context.Context) dangerSet {
	out := newDangerSet()
	rows, err := c.query(ctx, `SELECT privilege, parent_group FROM system.privileges`, nil)
	if err != nil {
		return out
	}
	children := map[string][]string{}
	for _, row := range rows {
		parent := strings.ToLower(strings.TrimSpace(rawString(row, "parent_group")))
		priv := strings.TrimSpace(rawString(row, "privilege"))
		if parent == "" || priv == "" {
			continue
		}
		children[parent] = append(children[parent], priv)
	}
	queue := make([]string, 0, len(out))
	for g := range out {
		queue = append(queue, g)
	}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			key := strings.ToLower(child)
			if out[key] {
				continue
			}
			out[key] = true
			queue = append(queue, key)
		}
	}
	return out
}

// dangerousAccessType сообщает, является ли привилегия опасной: любая
// привилегия из опасной группы (в любом scope) либо ALL на глобальном *.*.
//
// Про ALL: ClickHouse разворачивает GRANT ALL в отдельные типы и агрегат в
// system.grants не хранит, поэтому ветка нужна только для полноты контракта —
// реальные глобальные ALL ловятся содержимым групп.
func dangerousAccessType(danger dangerSet, access string, global bool) bool {
	if danger.has(access) {
		return true
	}
	a := strings.ToUpper(strings.TrimSpace(access))
	return global && (a == "ALL" || a == "ALL PRIVILEGES")
}

// formatGrant форматирует грант для атрибутов роли: "SELECT ON appdb.*",
// "SELECT(col) ON appdb.events", "ALL ON *.* WITH GRANT OPTION".
func formatGrant(g chGrant) string {
	access := g.AccessType
	if g.Column != "" {
		access += "(" + g.Column + ")"
	}
	scope := "*.*"
	switch {
	case g.Database != "" && g.Table != "":
		scope = g.Database + "." + g.Table
	case g.Database != "":
		scope = g.Database + ".*"
	}
	s := access + " ON " + scope
	if g.GrantOption {
		s += " WITH GRANT OPTION"
	}
	return s
}

// topologyFromClusters определяет топологию по system.clusters: сервер —
// участник кластера, если существует кластер, где он локальная реплика И есть
// хотя бы один удалённый хост. Кластеры целиком из локальных реплик
// (демо-конфигурация одного узла) считаются standalone.
func topologyFromClusters(hosts []chClusterHost) map[string]any {
	type clusterAgg struct {
		local  bool
		remote int
		hosts  []string
	}
	byCluster := map[string]*clusterAgg{}
	for _, h := range hosts {
		if h.Cluster == "" {
			continue
		}
		agg, ok := byCluster[h.Cluster]
		if !ok {
			agg = &clusterAgg{}
			byCluster[h.Cluster] = agg
		}
		if h.HostName != "" {
			agg.hosts = append(agg.hosts, net.JoinHostPort(h.HostName, strconv.FormatInt(h.Port, 10)))
		}
		if h.IsLocal {
			agg.local = true
		} else {
			agg.remote++
		}
	}

	var participating []string
	for name, agg := range byCluster {
		if agg.local && agg.remote > 0 {
			participating = append(participating, name)
		}
	}
	if len(participating) == 0 {
		return map[string]any{adapterutil.TopologyKey: "standalone"}
	}
	slices.Sort(participating)

	first := byCluster[participating[0]]
	members := slices.Clone(first.hosts)
	slices.Sort(members)
	members = slices.Compact(members)
	return map[string]any{
		adapterutil.TopologyKey: "cluster",
		"clusters":              participating,
		"cluster_name":          participating[0],
		"hosts":                 members,
		"host_count":            len(members),
	}
}

// --- Разбор значений FORMAT JSON ---

// rawString возвращает строковое значение колонки; отсутствие ключа, null или
// нестроковое значение — "".
func rawString(row map[string]json.RawMessage, key string) string {
	raw, ok := row[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// rawStrings возвращает массив строк колонки; отсутствие ключа или null — nil.
func rawStrings(row map[string]json.RawMessage, key string) []string {
	raw, ok := row[key]
	if !ok {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// rawBool возвращает булево значение UInt8-колонки: принимает 0/1 (число),
// "0"/"1" (строку — 64-битные целые FORMAT JSON выводит строками) и
// true/false.
func rawBool(row map[string]json.RawMessage, key string) bool {
	raw, ok := row[key]
	if !ok {
		return false
	}
	switch strings.Trim(string(raw), `"`) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// rawInt возвращает целое значение колонки (число или строка с числом);
// 0 при неудаче разбора.
func rawInt(row map[string]json.RawMessage, key string) int64 {
	raw, ok := row[key]
	if !ok {
		return 0
	}
	n, err := strconv.ParseInt(strings.Trim(string(raw), `"`), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// parseAuthTypes разбирает system.users.auth_type: строка (до 24.9) или
// массив строк (24.9+, несколько методов аутентификации).
func parseAuthTypes(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil && s != "" {
		return []string{s}
	}
	return nil
}

// --- External IDs и отпечатки ---

// Префиксы external id permission-определений: роли и наблюдаемые прямые
// гранты живут в разных пространствах и не пересекаются с external id баз
// ("db:").
const (
	rolePermissionPrefix = "role:"
	privPermissionPrefix = "priv:"
)

// databaseExternalID возвращает external id базы данных.
func databaseExternalID(name string) string { return "db:" + name }

// rolePermissionID возвращает external id permission для роли.
func rolePermissionID(name string) string { return rolePermissionPrefix + name }

// privPermissionID возвращает external id наблюдаемого прямого гранта:
// "priv:<ACCESS TYPE>" для глобального, "priv:<ACCESS TYPE>:db:<db>" для
// уровня базы, с добавлением ":table:<t>" и ":col:<c>" для более узких
// грантов. Частичный revoke получает суффикс ":revoke", иначе он совпал бы
// по id с одноимённым грантом и затёр его.
func privPermissionID(g chGrant) string {
	id := privPermissionPrefix + g.AccessType
	if g.Database != "" {
		id += ":" + databaseExternalID(g.Database)
	}
	if g.Table != "" {
		id += ":table:" + g.Table
	}
	if g.Column != "" {
		id += ":col:" + g.Column
	}
	if g.PartialRevoke {
		id += ":revoke"
	}
	return id
}

// privPermissionName возвращает человекочитаемое имя прямого гранта в
// нотации ClickHouse: "SELECT ON appdb.events", "SELECT(id) ON appdb.events".
func privPermissionName(g chGrant) string {
	access := g.AccessType
	if g.Column != "" {
		access += "(" + g.Column + ")"
	}
	scope := "*.*"
	switch {
	case g.Database != "" && g.Table != "":
		scope = g.Database + "." + g.Table
	case g.Database != "":
		scope = g.Database + ".*"
	}
	name := access + " ON " + scope
	if g.PartialRevoke {
		name = "REVOKE " + name
	}
	return name
}

// fingerprint строит стабильный отпечаток ресурса по kind, external id и
// атрибутам. Ключи атрибутов сортируются, а значения кодируются каноничным
// JSON, поэтому одно и то же содержимое всегда даёт один и тот же отпечаток
// независимо от порядка map.
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
}
