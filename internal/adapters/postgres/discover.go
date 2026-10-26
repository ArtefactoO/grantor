package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

// Discover выполняет полную инвентаризацию кластера: databases и их объекты
// (schemas, relations, indexes), roles и memberships. Все запросы читают
// только системные каталоги; мутаций discovery не выполняет.
//
// Ошибка подключения к отдельной базе не валит discovery целиком: база
// пропускается, а причина фиксируется в Topology["skipped_databases"].
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	conn, err := a.connect(ctx, cfg, maintenanceDatabase(cfg))
	if err != nil {
		return nil, fmt.Errorf("postgres: discover: %w", err)
	}
	defer closeQuietly(ctx, conn)

	now := time.Now()
	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: now,
	}
	if err := conn.QueryRow(ctx, `select current_setting('server_version')`).Scan(&snap.ServerVersion); err != nil {
		return nil, fmt.Errorf("postgres: discover: read server version: %w", err)
	}
	var inRecovery bool
	if err := conn.QueryRow(ctx, `select pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		return nil, fmt.Errorf("postgres: discover: read recovery state: %w", err)
	}
	snap.Topology["in_recovery"] = inRecovery
	// Дискриминатор топологии: реплика в recovery-режиме vs обычный
	// standalone-primary. Значение под общим ключом adapterutil.TopologyKey.
	snap.Topology[adapterutil.TopologyKey] = "standalone"
	if inRecovery {
		snap.Topology[adapterutil.TopologyKey] = "replica"
	}
	systemIdentifier := ""
	if discoveredIdentifier, ok := discoverSystemIdentifier(ctx, conn); ok {
		systemIdentifier = discoveredIdentifier
		snap.Topology["system_identifier"] = systemIdentifier
	}
	provisioningAuthority := observePostgresAdminAuthority(ctx, conn, cfg, now, systemIdentifier)
	snap.Topology[adapter.PostgresProvisioningAuthorityTopologyKey] = provisioningAuthority
	snap.Topology["postgres_access_evidence"] = a.discoverAccessEvidence(ctx, cfg, conn, systemIdentifier)

	// Opportunistic TLS detection: при незашифрованном режиме (disabled или
	// пустой mode) по лучшему усилию проверяем, умеет ли сервер TLS, чтобы
	// API мог показать finding tls_available_but_disabled. Фактический режим
	// подключения не меняется; неудача детекта ключ не пишет.
	if cfg.TLS.Mode == "" || cfg.TLS.Mode == "disabled" {
		if supported, ok := a.serverSupportsTLS(ctx, cfg.Endpoints[0]); ok {
			snap.Topology["server_supports_tls"] = supported
		}
	}

	// Правила pg_hba: сеть и SQL-права — только два из трёх условий доступа,
	// третье живёт в файле, который grantor не видит. Чтение
	// best-effort: view требует superuser (или явного GRANT) и появилась в
	// PostgreSQL 15, поэтому отказ доступа никогда не валит discovery — ключ
	// просто не пишется, и UI показывает раздел как недоступный.
	if rules, truncated, ok := discoverHBARules(ctx, conn); ok {
		snap.Topology[hbaRulesKey] = rules
		if truncated {
			snap.Topology[hbaTruncatedKey] = true
		}
	}

	databases, err := discoverDatabases(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("postgres: discover: %w", err)
	}
	for _, db := range databases {
		snap.Resources = append(snap.Resources, databaseResource(db))
	}

	var skipped []map[string]string
	objectScopes := map[string]map[string]bool{}
	for _, db := range databases {
		objects, objErr := a.discoverDatabaseObjects(ctx, cfg, db.name)
		if objErr != nil {
			snap.IncompleteScopes = append(snap.IncompleteScopes, databaseExternalID(db.name))
			// Текст ошибки не содержит секретов: connect не включает
			// пароль ни в свои сообщения, ни в сообщения pgx.
			skipped = append(skipped, map[string]string{
				"name":  db.name,
				"error": objErr.Error(),
			})
			continue
		}
		snap.Resources = append(snap.Resources, objects...)
		objectScopes[db.name] = map[string]bool{databaseExternalID(db.name): true}
		for _, r := range objects {
			if r.Kind != "index" {
				objectScopes[db.name][r.ExternalID] = true
			}
		}
	}
	if len(skipped) > 0 {
		snap.Topology["skipped_databases"] = skipped
	}

	roles, err := discoverRoles(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("postgres: discover: %w", err)
	}
	accounts, permissions := rolesToObserved(roles, now)

	memberships, err := discoverMemberships(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("postgres: discover: %w", err)
	}
	roleByName := make(map[string]roleInfo, len(roles))
	for _, r := range roles {
		if ProtectedRole(r.name) && r.name != StatsRole {
			continue
		}
		roleByName[r.name] = r
	}
	knownPermissions := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		knownPermissions[p.ExternalID] = true
	}
	rolePolicyTemplates, err := postgresconfig.FromAttributes(cfg.Attributes)
	if err != nil {
		return nil, fmt.Errorf("postgres: discover: role policy templates: %w", err)
	}
	policyMutationReady := provisioningAuthority.Status == adapter.ProvisioningAuthorityConfirmed &&
		provisioningAuthority.Reason == adapter.ProvisioningAuthoritySuperuserConfirmed
	snap.Topology[rolePolicyCatalogFingerprintKey] = postgresconfig.CatalogFingerprint(rolePolicyTemplates)
	snap.Topology[rolePolicyApplySupportedKey] = policyMutationReady
	snap.Topology[rolePolicyCreateSupportedKey] = policyMutationReady
	if len(rolePolicyTemplates) > 0 {
		expectedSystemIdentifier, _ := snap.Topology["system_identifier"].(string)
		policies, provenSystemIdentifier := a.discoverRolePolicies(
			ctx, cfg, rolePolicyTemplates, expectedSystemIdentifier, provisioningAuthority,
		)
		snap.RolePolicies = policies
		if expectedSystemIdentifier == "" && provenSystemIdentifier != "" {
			snap.Topology["system_identifier"] = provenSystemIdentifier
		}
	}
	bindings, loginPermissions := membershipsToObserved(memberships, roleByName, knownPermissions)
	permissions = append(permissions, loginPermissions...)
	defaultPrivileges := []map[string]any{}
	for _, db := range databases {
		if slices.Contains(snap.IncompleteScopes, databaseExternalID(db.name)) {
			continue
		}
		if systemIdentifier == "" {
			snap.IncompleteScopes = append(snap.IncompleteScopes, databaseExternalID(db.name))
			continue
		}
		acl, aclErr := a.discoverObjectACLs(ctx, cfg, db, "postgres:system:"+systemIdentifier, policyMutationReady, roleByName)
		if aclErr == nil {
			observedScopes := map[string]bool{}
			for _, permission := range acl.permissions {
				observedScopes[permission.ScopeExternalID] = true
			}
			if len(observedScopes) != len(objectScopes[db.name]) {
				aclErr = fmt.Errorf("object catalog changed during ACL discovery")
			}
			for scope := range observedScopes {
				if !objectScopes[db.name][scope] {
					aclErr = fmt.Errorf("object catalog changed during ACL discovery")
				}
			}
		}
		if aclErr != nil {
			snap.IncompleteScopes = append(snap.IncompleteScopes, databaseExternalID(db.name))
			skipped = append(skipped, map[string]string{"name": db.name, "error": aclErr.Error()})
			continue
		}
		permissions = append(permissions, acl.permissions...)
		bindings = append(bindings, acl.bindings...)
		defaultPrivileges = append(defaultPrivileges, acl.defaults...)
		for i := range snap.Resources {
			r := &snap.Resources[i]
			if public := acl.public[r.ExternalID]; len(public) > 0 {
				r.Attributes["public_privileges"] = public
				r.Fingerprint = fingerprint(r.Kind, r.ExternalID, r.Attributes)
			}
		}
	}
	if len(skipped) > 0 {
		snap.Topology["skipped_databases"] = skipped
	}
	snap.Topology["postgres_default_privileges"] = defaultPrivileges
	snap.Topology["postgres_object_acl_version"] = 1
	if len(snap.IncompleteScopes) > 0 {
		snap.Topology["postgres_object_acl_incomplete_scopes"] = slices.Clone(snap.IncompleteScopes)
	}
	if len(snap.RolePolicies) > 0 {
		permissions = annotateRolePolicyPermissions(permissions, snap.RolePolicies)
	}

	snap.Accounts = accounts
	snap.Permissions = permissions
	snap.Bindings = bindings
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// discoverSystemIdentifier reads the stable PostgreSQL cluster epoch used to
// fence queued mutations from endpoint/TLS reconfiguration to another
// cluster. It is best-effort for inventory-only connections; managed
// provisioning requires a proved value independently of this read.
func discoverSystemIdentifier(ctx context.Context, conn *pgx.Conn) (string, bool) {
	var identifier string
	if err := conn.QueryRow(ctx,
		`select system_identifier::text from pg_catalog.pg_control_system()`).Scan(&identifier); err != nil {
		return "", false
	}
	return identifier, identifier != ""
}

// databaseInfo — строка из pg_database.
type databaseInfo struct {
	name     string
	owner    string
	oid      uint32
	ownerOID uint32
}

// roleInfo — строка из pg_roles.
type roleInfo struct {
	oid         uint32
	name        string
	super       bool
	createDB    bool
	createRole  bool
	replication bool
	bypassRLS   bool
	canLogin    bool
	validUntil  *time.Time
}

// dangerous сообщает, даёт ли роль привилегии, требующие особого контроля
// (SUPERUSER, CREATEROLE, REPLICATION, BYPASSRLS).
//
// CREATEDB сознательно НЕ считается опасным. Признак dangerous в grantor —
// это не «широкая» привилегия вообще, а гейт на admin + явный confirm, и он
// зарезервирован за привилегиями, которые ведут к захвату контроля над
// кластером или чтению чужих данных: SUPERUSER (всё), CREATEROLE (в
// PostgreSQL 16+ позволяет создавать роли и управлять их membership, то есть
// эскалировать доступ), REPLICATION (полная физическая копия кластера,
// включая содержимое всех баз), BYPASSRLS (обход row level security).
// CREATEDB ни к одной из этих категорий не относится: владелец новой базы не
// получает доступа к существующим и не может повысить свои привилегии,
// последствия ограничены потреблением ресурсов и удалением СВОИХ баз. Гейт
// admin+confirm на такой привилегии дал бы шум вместо сигнала; сам флаг
// виден оператору в атрибутах роли (flagAttributes -> createdb).
func (r roleInfo) dangerous() bool {
	return r.super || r.createRole || r.replication || r.bypassRLS
}

// flagAttributes возвращает атрибуты с привилегиями роли.
func (r roleInfo) flagAttributes() map[string]any {
	return map[string]any{
		"role_oid":    r.oid,
		"superuser":   r.super,
		"createdb":    r.createDB,
		"createrole":  r.createRole,
		"replication": r.replication,
		"bypassrls":   r.bypassRLS,
	}
}

// account строит ObservedAccount для роли: LOGIN-роли становятся аккаунтами
// kind login, остальные — group. Роль с истёкшим rolvaliduntil считается
// отключённой.
func (r roleInfo) account(now time.Time) adapter.ObservedAccount {
	attrs := r.flagAttributes()
	attrs["can_login"] = r.canLogin
	if r.validUntil != nil {
		attrs["valid_until"] = r.validUntil.UTC().Format(time.RFC3339)
	}
	kind := "group"
	if r.canLogin {
		kind = "login"
	}
	return adapter.ObservedAccount{
		Kind:           kind,
		EngineIdentity: r.name,
		Disabled:       r.validUntil != nil && r.validUntil.Before(now),
		Attributes:     attrs,
	}
}

// permission строит cluster-wide ObservedPermission для группы (NOLOGIN
// роли), которую можно назначать аккаунтам.
//
// AccountEngineIdentity заполняется всегда: в PostgreSQL роль и учётная
// запись — одна сущность (pg_roles), и выключенная grantor учётка тоже
// становится NOLOGIN, то есть внешне неотличима от группы. Связь позволяет
// ядру не предлагать к выдаче собственную учётную запись (см.
// adapter.ObservedPermission.AccountEngineIdentity).
func (r roleInfo) permission() adapter.ObservedPermission {
	attrs := r.flagAttributes()
	if r.canLogin {
		attrs["login_role"] = true
	}
	permission := adapter.ObservedPermission{
		ExternalID:            rolePermissionID(r.name),
		Name:                  r.name,
		Assignable:            !r.canLogin,
		Dangerous:             r.dangerous(),
		Attributes:            attrs,
		AccountEngineIdentity: r.name,
	}
	if r.name == StatsRole {
		permission.AccountEngineIdentity = ""
		permission.Attributes["protected_builtin"] = true
		permission.Assignable = !r.canLogin && !r.dangerous() && !r.createDB && r.oid != 0
	}
	return permission
}

// membershipInfo — строка из pg_auth_members.
type membershipInfo struct {
	role          string
	member        string
	adminOption   bool
	inheritOption bool
	setOption     bool
	grantRows     int
}

// discoverDatabases читает список баз, доступных для подключения; template
// базы и базы с запретом подключений не учитываются.
func discoverDatabases(ctx context.Context, conn *pgx.Conn) ([]databaseInfo, error) {
	const q = `
select d.datname, owner_role.rolname, d.oid, owner_role.oid
from pg_database d
join pg_roles owner_role on owner_role.oid = d.datdba
where not d.datistemplate and d.datallowconn
order by d.datname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query databases: %w", err)
	}
	defer rows.Close()

	var out []databaseInfo
	for rows.Next() {
		var db databaseInfo
		if err := rows.Scan(&db.name, &db.owner, &db.oid, &db.ownerOID); err != nil {
			return nil, fmt.Errorf("scan database row: %w", err)
		}
		out = append(out, db)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read databases: %w", err)
	}
	return out, nil
}

// discoverDatabaseObjects собирает schemas, relations и indexes одной базы
// через отдельное подключение к ней. Имя базы попадает только в конфигурацию
// подключения и никогда не конкатенируется в SQL.
func (a *Adapter) discoverDatabaseObjects(ctx context.Context, cfg adapter.Connection, dbName string) ([]adapter.ObservedResource, error) {
	conn, err := a.connect(ctx, cfg, dbName)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)

	var out []adapter.ObservedResource
	schemas, err := discoverSchemas(ctx, conn, dbName)
	if err != nil {
		return nil, err
	}
	out = append(out, schemas...)

	relations, err := discoverRelations(ctx, conn, dbName)
	if err != nil {
		return nil, err
	}
	out = append(out, relations...)

	indexes, err := discoverIndexes(ctx, conn, dbName)
	if err != nil {
		return nil, err
	}
	out = append(out, indexes...)
	return out, nil
}

// discoverSchemas читает пользовательские схемы базы; системные схемы
// pg_catalog, information_schema, pg_toast* и pg_temp* исключаются.
func discoverSchemas(ctx context.Context, conn *pgx.Conn, dbName string) ([]adapter.ObservedResource, error) {
	const q = `
select n.nspname, pg_get_userbyid(n.nspowner) as owner
from pg_namespace n
where n.nspname <> 'information_schema' and n.nspname not like 'pg\_%'
order by n.nspname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query schemas in %q: %w", dbName, err)
	}
	defer rows.Close()

	var out []adapter.ObservedResource
	for rows.Next() {
		var name, owner string
		if err := rows.Scan(&name, &owner); err != nil {
			return nil, fmt.Errorf("scan schema row in %q: %w", dbName, err)
		}
		attrs := map[string]any{"owner": owner}
		id := schemaExternalID(dbName, name)
		out = append(out, adapter.ObservedResource{
			Kind:             "schema",
			ExternalID:       id,
			ParentExternalID: databaseExternalID(dbName),
			Name:             name,
			CanonicalPath:    dbName + "." + name,
			Attributes:       attrs,
			Fingerprint:      fingerprint("schema", id, attrs),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read schemas in %q: %w", dbName, err)
	}
	return out, nil
}

// discoverRelations читает таблицы, представления, materialized views и
// sequences пользовательских схем базы.
func discoverRelations(ctx context.Context, conn *pgx.Conn, dbName string) ([]adapter.ObservedResource, error) {
	const q = `
select n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner) as owner
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r', 'p', 'f', 'v', 'm', 'S')
  and n.nspname <> 'information_schema' and n.nspname not like 'pg\_%'
order by n.nspname, c.relname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query relations in %q: %w", dbName, err)
	}
	defer rows.Close()

	var out []adapter.ObservedResource
	for rows.Next() {
		var nsp, rel, relkind, owner string
		if err := rows.Scan(&nsp, &rel, &relkind, &owner); err != nil {
			return nil, fmt.Errorf("scan relation row in %q: %w", dbName, err)
		}
		kind, ok := relkindToKind(relkind)
		if !ok {
			continue
		}
		attrs := map[string]any{"owner": owner, "relkind": relkind}
		id := relationExternalID(kind, dbName, nsp, rel)
		out = append(out, adapter.ObservedResource{
			Kind:             kind,
			ExternalID:       id,
			ParentExternalID: schemaExternalID(dbName, nsp),
			Name:             rel,
			CanonicalPath:    dbName + "." + nsp + "." + rel,
			Attributes:       attrs,
			Fingerprint:      fingerprint(kind, id, attrs),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read relations in %q: %w", dbName, err)
	}
	return out, nil
}

// discoverIndexes читает индексы пользовательских схем базы; родителем
// индекса считается его таблица (или materialized view).
func discoverIndexes(ctx context.Context, conn *pgx.Conn, dbName string) ([]adapter.ObservedResource, error) {
	const q = `
select n.nspname,
       ic.relname as index_name,
       tc.relname as table_name,
       tc.relkind::text as table_relkind,
       i.indisunique,
       i.indisprimary,
       pg_get_indexdef(i.indexrelid) as definition
from pg_index i
join pg_class ic on ic.oid = i.indexrelid
join pg_class tc on tc.oid = i.indrelid
join pg_namespace n on n.oid = tc.relnamespace
where n.nspname <> 'information_schema' and n.nspname not like 'pg\_%'
order by n.nspname, ic.relname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query indexes in %q: %w", dbName, err)
	}
	defer rows.Close()

	var out []adapter.ObservedResource
	for rows.Next() {
		var nsp, idxName, tblName, tblRelkind, definition string
		var unique, primary bool
		if err := rows.Scan(&nsp, &idxName, &tblName, &tblRelkind, &unique, &primary, &definition); err != nil {
			return nil, fmt.Errorf("scan index row in %q: %w", dbName, err)
		}
		parentKind, ok := relkindToKind(tblRelkind)
		if !ok {
			continue
		}
		attrs := map[string]any{
			"unique":     unique,
			"primary":    primary,
			"definition": definition,
		}
		id := indexExternalID(dbName, nsp, idxName)
		out = append(out, adapter.ObservedResource{
			Kind:             "index",
			ExternalID:       id,
			ParentExternalID: relationExternalID(parentKind, dbName, nsp, tblName),
			Name:             idxName,
			CanonicalPath:    dbName + "." + nsp + "." + idxName,
			Attributes:       attrs,
			Fingerprint:      fingerprint("index", id, attrs),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read indexes in %q: %w", dbName, err)
	}
	return out, nil
}

// discoverRoles читает роли кластера; служебные роли pg_% исключаются.
// Значения rolvaliduntil "infinity"/"-infinity" приводятся к NULL, чтобы не
// падать на сканировании в time.Time.
func discoverRoles(ctx context.Context, conn *pgx.Conn) ([]roleInfo, error) {
	const q = `
select oid, rolname, rolsuper, rolcreatedb, rolcreaterole, rolreplication,
       rolbypassrls, rolcanlogin,
       nullif(nullif(rolvaliduntil, 'infinity'::timestamptz), '-infinity'::timestamptz) as rolvaliduntil
from pg_roles
where rolname not like 'pg\_%' or rolname = 'pg_read_all_stats'
order by rolname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query roles: %w", err)
	}
	defer rows.Close()

	var out []roleInfo
	for rows.Next() {
		var r roleInfo
		if err := rows.Scan(&r.oid, &r.name, &r.super, &r.createDB, &r.createRole,
			&r.replication, &r.bypassRLS, &r.canLogin, &r.validUntil); err != nil {
			return nil, fmt.Errorf("scan role row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read roles: %w", err)
	}
	return out, nil
}

// discoverMemberships читает membership ролей, исключая служебные pg_% роли
// с обеих сторон. С PostgreSQL 16 одна пара role/member может иметь записи
// от нескольких grantors, поэтому admin_option агрегируется через bool_or.
func discoverMemberships(ctx context.Context, conn *pgx.Conn) ([]membershipInfo, error) {
	const q = `
select r.rolname as role_name, m.rolname as member_name,
       bool_or(am.admin_option) as admin_option,
       bool_or(coalesce((to_jsonb(am)->>'inherit_option')::boolean, false)),
       bool_or(coalesce((to_jsonb(am)->>'set_option')::boolean, false)),
       count(*)::integer
from pg_auth_members am
join pg_roles r on r.oid = am.roleid
join pg_roles m on m.oid = am.member
where (r.rolname not like 'pg\_%' or r.rolname = 'pg_read_all_stats') and m.rolname not like 'pg\_%'
group by r.rolname, m.rolname
order by r.rolname, m.rolname`
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query role memberships: %w", err)
	}
	defer rows.Close()

	var out []membershipInfo
	for rows.Next() {
		var m membershipInfo
		if err := rows.Scan(&m.role, &m.member, &m.adminOption,
			&m.inheritOption, &m.setOption, &m.grantRows); err != nil {
			return nil, fmt.Errorf("scan role membership row: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read role memberships: %w", err)
	}
	return out, nil
}

// rolesToObserved превращает роли в аккаунты и permissions: каждая роль —
// аккаунт (login/group), каждая NOLOGIN-роль — назначаемая permission.
// LOGIN-роли остаются наблюдаемыми, но неназначаемыми permissions, даже
// когда у них больше нет членов. Их отсутствие в memberships не означает DROP ROLE.
func rolesToObserved(roles []roleInfo, now time.Time) ([]adapter.ObservedAccount, []adapter.ObservedPermission) {
	accounts := make([]adapter.ObservedAccount, 0, len(roles))
	var permissions []adapter.ObservedPermission
	for _, r := range roles {
		if ProtectedRole(r.name) && r.name != StatsRole {
			continue
		}
		if !ProtectedRole(r.name) {
			accounts = append(accounts, r.account(now))
		}
		// A LOGIN role still exists after its last membership is removed.
		// Retain a nonassignable observation instead of marking its old catalog
		// entry Missing while the corresponding account remains active.
		permissions = append(permissions, r.permission())
	}
	return accounts, permissions
}

// membershipsToObserved превращает memberships в bindings. Если родительская
// роль — LOGIN (permission для неё в rolesToObserved не создавалась), для
// неё добирается неназначаемая permission с атрибутом login_role, чтобы
// каждый binding ссылался на существующую permission.
//
// Кроме прямых членств раскрываются транзитивные: членство в роли, которая
// сама входит в другую роль, даёт права обеих. Без раскрытия унаследованное
// право не появлялось в инвентаре вовсе — оператор не видел ни его, ни того,
// откуда оно взялось. Такие bindings помечаются Inherited: ядро сохраняет
// признак в bindings.source, и интерфейс отличает их от прямых.
func membershipsToObserved(memberships []membershipInfo, roles map[string]roleInfo, known map[string]bool) ([]adapter.ObservedBinding, []adapter.ObservedPermission) {
	var bindings []adapter.ObservedBinding
	var extra []adapter.ObservedPermission

	// permissionFor добирает permission для роли, у которой её ещё нет
	// (LOGIN-роль в роли permission не публикуется).
	permissionFor := func(role string) string {
		permID := rolePermissionID(role)
		if !known[permID] {
			extra = append(extra, adapter.ObservedPermission{
				ExternalID: permID,
				Name:       role,
				Assignable: false,
				Dangerous:  roles[role].dangerous(),
				Attributes: map[string]any{"login_role": true},
			})
			known[permID] = true
		}
		return permID
	}

	edges := make([]adapterutil.MembershipEdge, 0, len(memberships))
	for _, m := range memberships {
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: m.member,
			PermissionExternalID:  permissionFor(m.role),
			Inherited:             false,
			Attributes: map[string]any{
				"admin_option": m.adminOption, "inherit_option": m.inheritOption,
				"set_option": m.setOption, "grant_rows": m.grantRows,
			},
		})
		edges = append(edges, adapterutil.MembershipEdge{Role: m.role, Member: m.member})
	}

	for _, e := range adapterutil.InheritedMemberships(edges) {
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: e.Member,
			PermissionExternalID:  permissionFor(e.Role),
			Inherited:             true,
			// admin_option по цепочке не наследуется: право администрировать
			// роль даёт только прямой грант WITH ADMIN OPTION.
			Attributes: map[string]any{"inherited": true},
		})
	}
	return bindings, extra
}

// databaseResource строит ресурс kind database.
func databaseResource(db databaseInfo) adapter.ObservedResource {
	attrs := map[string]any{"owner": db.owner, "database_oid": db.oid, "owner_oid": db.ownerOID}
	id := databaseExternalID(db.name)
	return adapter.ObservedResource{
		Kind:          "database",
		ExternalID:    id,
		Name:          db.name,
		CanonicalPath: db.name,
		Attributes:    attrs,
		Fingerprint:   fingerprint("database", id, attrs),
	}
}

// relkindToKind переводит pg_class.relkind в resource kind adapter.
func relkindToKind(relkind string) (string, bool) {
	switch relkind {
	case "r", "p", "f":
		return "table", true
	case "v":
		return "view", true
	case "m":
		return "materialized_view", true
	case "S":
		return "sequence", true
	default:
		return "", false
	}
}

// databaseExternalID возвращает external id базы.
func databaseExternalID(db string) string { return "db:" + db }

// schemaExternalID возвращает external id схемы.
func schemaExternalID(db, schema string) string { return "schema:" + db + "." + schema }

// relationExternalID возвращает external id relation указанного kind.
func relationExternalID(kind, db, schema, name string) string {
	return kind + ":" + db + "." + schema + "." + name
}

// indexExternalID возвращает external id индекса.
func indexExternalID(db, schema, index string) string {
	return relationExternalID("index", db, schema, index)
}

// rolePermissionID возвращает external id permission для роли кластера.
func rolePermissionID(role string) string { return "role:" + role }

// fingerprint строит стабильный отпечаток ресурса по kind, external id и
// атрибутам. Ключи атрибутов сортируются, поэтому одно и то же содержимое
// всегда даёт один и тот же отпечаток независимо от порядка map.
func fingerprint(kind, externalID string, attrs map[string]any) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	parts := make([]string, 0, len(attrs)+2)
	parts = append(parts, kind, externalID)
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, attrs[k]))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])[:16]
}

// sortSnapshot приводит snapshot к детерминированному порядку: contract
// suite требует стабильности между повторными discovery.
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
		return strings.Compare(a.PermissionExternalID, b.PermissionExternalID)
	})
	slices.SortFunc(snap.RolePolicies, func(a, b adapter.ObservedRolePolicy) int {
		return strings.Compare(a.ExternalID, b.ExternalID)
	})
}

// Ключи Topology с правилами pg_hba (контракт описан в architecture §11.1).
const (
	hbaRulesKey     = "hba_rules"
	hbaTruncatedKey = "hba_rules_truncated"
)

// maxHBARules — предел числа правил в снапшоте. Topology уезжает в jsonb
// подключения и в каждый ответ GET /connections/{id}: патологически длинный
// pg_hba не должен раздувать их без границы.
const maxHBARules = 500

// discoverHBARules читает pg_hba_file_rules. Возвращает ok=false при любой
// невозможности прочитать (нет прав, нет view, ошибка запроса): отсутствие
// доступа к конфигурации — не повод провалить инвентаризацию.
//
// Строки с непустым error сохраняются намеренно: сломанное правило само по
// себе сигнал, и прятать его было бы хуже, чем показать.
func discoverHBARules(ctx context.Context, conn *pgx.Conn) (rules []map[string]any, truncated, ok bool) {
	// Порядок фиксирован rule_number: DiscoveryIsRepeatable требует
	// стабильного снапшота между вызовами.
	rows, err := conn.Query(ctx, `
		select rule_number, type,
		       coalesce(database, '{}'), coalesce(user_name, '{}'),
		       coalesce(address, ''), coalesce(netmask, ''),
		       coalesce(auth_method, ''), coalesce(options, '{}'),
		       coalesce(error, '')
		from pg_hba_file_rules
		order by rule_number`)
	if err != nil {
		return nil, false, false
	}
	defer rows.Close()

	for rows.Next() {
		var (
			number                 int
			ruleType               string
			databases, users, opts []string
			address, netmask       string
			authMethod, ruleError  string
		)
		if err := rows.Scan(&number, &ruleType, &databases, &users,
			&address, &netmask, &authMethod, &opts, &ruleError); err != nil {
			return nil, false, false
		}
		if len(rules) >= maxHBARules {
			truncated = true
			break
		}
		// Authentication options can contain LDAP bind credentials. Presence
		// matters for diagnostics; their values never belong in inventory.
		if len(opts) > 0 {
			opts = []string{"configured"}
		}
		if ruleError != "" {
			ruleError = "invalid_hba_rule"
		}
		rules = append(rules, map[string]any{
			"number": number, "type": ruleType,
			"databases": databases, "users": users,
			"address": address, "netmask": netmask,
			"auth_method": authMethod, "options": opts,
			"error": ruleError,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, false, false
	}
	return rules, truncated, true
}
