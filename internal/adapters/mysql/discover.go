package mysql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// systemSchemas — служебные схемы MySQL, исключаемые из инвентаризации.
var systemSchemas = []string{"information_schema", "performance_schema", "mysql", "sys"}

// systemAccounts — служебные аккаунты MySQL (пользователи внутренних
// компонентов), исключаемые из инвентаризации accounts и bindings. root
// сознательно оставляется видимым.
var systemAccounts = map[string]bool{
	"mysql.sys":        true,
	"mysql.session":    true,
	"mysql.infoschema": true,
}

// Discover выполняет полную инвентаризацию сервера: databases и их объекты
// (tables, views, indexes), accounts (user@host), roles и role memberships.
// Все запросы читают только системные каталоги; мутаций discovery не
// выполняет. Discovery ролей gate'ится по версии сервера: на MariaDB и
// MySQL < 8.0 роли пропускаются, инвентарь ресурсов и аккаунтов работает как
// обычно.
func (a *Adapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	db, err := a.open(ctx, cfg, defaultDatabase(cfg))
	if err != nil {
		return nil, fmt.Errorf("mysql: discover: %w", err)
	}
	defer closeQuietly(db)

	now := time.Now()
	snap := &adapter.Snapshot{
		Topology:   map[string]any{},
		ObservedAt: now,
	}
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&snap.ServerVersion); err != nil {
		return nil, fmt.Errorf("mysql: discover: read server version: %w", err)
	}
	rolesOK := supportsRoles(snap.ServerVersion)
	if err := discoverTopology(ctx, db, snap); err != nil {
		return nil, fmt.Errorf("mysql: discover: %w", err)
	}
	snap.Topology["roles_supported"] = rolesOK

	resources, err := discoverResources(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("mysql: discover: %w", err)
	}
	snap.Resources = resources

	accounts, err := discoverAccounts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("mysql: discover: %w", err)
	}
	snap.Accounts = accounts

	if rolesOK {
		// Выданная роль сама по себе не означает доступа: при
		// activate_all_roles_on_login=OFF (значение MySQL по умолчанию) она
		// активируется на логине, только если входит в mysql.default_roles.
		// Инвентаризация default roles (docs/architecture.md, 13.1) даёт
		// observed-состоянию тот же признак, который проверяет Verify мутаций,
		// поэтому снимок отличает выданную роль от фактически активной.
		defaults, err := discoverDefaultRoles(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("mysql: discover: %w", err)
		}
		activateAll, err := activateAllRolesOnLogin(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("mysql: discover: %w", err)
		}
		snap.Topology["activate_all_roles_on_login"] = activateAll
		annotateDefaultRoles(snap.Accounts, defaults)

		accountSet := make(map[string]bool, len(accounts))
		// roles — все роли движка, а не только те, что кому-то выданы:
		// mysql.role_edges содержит лишь выданные, поэтому свежесозданную
		// роль нельзя было выдать через grantor, пока её не выдадут мимо
		// него. Роль распознаётся при инвентаризации аккаунтов (isRoleRow).
		roles := make([][2]string, 0, len(accounts))
		for _, acc := range accounts {
			accountSet[acc.EngineIdentity] = true
			if acc.Kind != "group" {
				continue
			}
			if uh, err := parseUserHost(acc.EngineIdentity); err == nil {
				roles = append(roles, [2]string{uh.user, uh.host})
			}
		}
		permissions, bindings, err := discoverRoles(ctx, db, accountSet, roles, defaults, activateAll)
		if err != nil {
			return nil, fmt.Errorf("mysql: discover: %w", err)
		}
		snap.Permissions = permissions
		snap.Bindings = bindings
	}
	publishAdminCredentialAssessment(ctx, a, cfg, snap.Topology)

	sortSnapshot(snap)
	return snap, nil
}

// discoverTopology определяет топологию сервера по @@read_only,
// @@super_read_only и статусу репликации. Значения read_only/replica пишутся
// в Snapshot.Topology.
func discoverTopology(ctx context.Context, db *sql.DB, snap *adapter.Snapshot) error {
	var readOnly int64
	if err := db.QueryRowContext(ctx, `SELECT @@global.read_only`).Scan(&readOnly); err != nil {
		return fmt.Errorf("read read_only: %w", err)
	}
	// super_read_only есть не на всех сборках (например, старые MariaDB) —
	// читаем best-effort.
	var superReadOnly int64
	if err := db.QueryRowContext(ctx, `SELECT @@global.super_read_only`).Scan(&superReadOnly); err != nil {
		superReadOnly = 0
	}

	hasReplicaStatus := replicationStatusPresent(ctx, db)
	hasReplicas := replicasPresent(ctx, db)

	snap.Topology[adapterutil.TopologyKey] = classifyTopology(readOnly != 0, superReadOnly != 0, hasReplicaStatus, hasReplicas)
	snap.Topology["read_only"] = readOnly != 0
	snap.Topology["super_read_only"] = superReadOnly != 0
	snap.Topology["version"] = snap.ServerVersion
	return nil
}

// classifyTopology классифицирует топологию по флагам. Определение упрощено
// (docs/architecture.md, раздел 13): сервер считается replica, если он в
// read-only режиме или у него есть статус репликации; если он не replica, но
// у него есть подключённые реплики — source; иначе standalone. Точное
// определение source требует прав REPLICATION SLAVE ADMIN на SHOW REPLICAS и
// потому выполняется только best-effort.
func classifyTopology(readOnly, superReadOnly, hasReplicaStatus, hasReplicas bool) string {
	if readOnly || superReadOnly || hasReplicaStatus {
		return "replica"
	}
	if hasReplicas {
		return "source"
	}
	return "standalone"
}

// replicationStatusPresent сообщает, есть ли у сервера статус репликации
// (сервер является репликой). Пробует современную SHOW REPLICA STATUS
// (MySQL 8.0.22+), затем откатывается на SHOW SLAVE STATUS. Ошибки и
// отсутствие прав трактуются как «статуса нет».
func replicationStatusPresent(ctx context.Context, db *sql.DB) bool {
	for _, q := range []string{`SHOW REPLICA STATUS`, `SHOW SLAVE STATUS`} {
		present, ok := queryHasRows(ctx, db, q)
		if ok {
			return present
		}
	}
	return false
}

// replicasPresent сообщает, есть ли у сервера подключённые реплики. Пробует
// SHOW REPLICAS (MySQL 8.0.22+), затем SHOW SLAVE HOSTS. Best-effort: без
// прав или на старых версиях возвращает false.
func replicasPresent(ctx context.Context, db *sql.DB) bool {
	for _, q := range []string{`SHOW REPLICAS`, `SHOW SLAVE HOSTS`} {
		present, ok := queryHasRows(ctx, db, q)
		if ok {
			return present
		}
	}
	return false
}

// queryHasRows выполняет запрос и сообщает, вернул ли он хотя бы одну строку.
// ok=false означает, что запрос не удалось выполнить (нет прав, неизвестный
// синтаксис на старой версии) — вызывающий должен попробовать альтернативу.
func queryHasRows(ctx context.Context, db *sql.DB, query string) (present, ok bool) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return false, false
	}
	defer func() { _ = rows.Close() }()
	has := rows.Next()
	if err := rows.Err(); err != nil {
		return false, false
	}
	return has, true
}

// discoverResources собирает databases, tables/views и indexes.
func discoverResources(ctx context.Context, db *sql.DB) ([]adapter.ObservedResource, error) {
	var out []adapter.ObservedResource

	databases, err := discoverDatabases(ctx, db)
	if err != nil {
		return nil, err
	}
	out = append(out, databases...)

	tables, err := discoverTables(ctx, db)
	if err != nil {
		return nil, err
	}
	out = append(out, tables...)

	indexes, err := discoverIndexes(ctx, db)
	if err != nil {
		return nil, err
	}
	out = append(out, indexes...)
	return out, nil
}

// schemaFilter возвращает SQL-фрагмент `col NOT IN (...)` и аргументы для
// исключения служебных схем.
func schemaFilter(col string) (string, []any) {
	placeholders := make([]string, len(systemSchemas))
	args := make([]any, len(systemSchemas))
	for i, s := range systemSchemas {
		placeholders[i] = "?"
		args[i] = s
	}
	return col + " NOT IN (" + strings.Join(placeholders, ", ") + ")", args
}

// discoverDatabases читает пользовательские схемы из
// information_schema.SCHEMATA.
func discoverDatabases(ctx context.Context, db *sql.DB) ([]adapter.ObservedResource, error) {
	filter, args := schemaFilter("SCHEMA_NAME")
	q := `SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
FROM information_schema.SCHEMATA
WHERE ` + filter + `
ORDER BY SCHEMA_NAME`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query databases: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []adapter.ObservedResource
	for rows.Next() {
		var name, charset, collation string
		if err := rows.Scan(&name, &charset, &collation); err != nil {
			return nil, fmt.Errorf("scan database row: %w", err)
		}
		attrs := map[string]any{"charset": charset, "collation": collation}
		id := databaseExternalID(name)
		out = append(out, adapter.ObservedResource{
			Kind:          "database",
			ExternalID:    id,
			Name:          name,
			CanonicalPath: name,
			Attributes:    attrs,
			Fingerprint:   fingerprint("database", id, attrs),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read databases: %w", err)
	}
	return out, nil
}

// discoverTables читает таблицы и представления из
// information_schema.TABLES. BASE TABLE становится ресурсом kind table,
// VIEW — kind view; прочие типы (например SYSTEM VIEW) пропускаются.
func discoverTables(ctx context.Context, db *sql.DB) ([]adapter.ObservedResource, error) {
	filter, args := schemaFilter("TABLE_SCHEMA")
	q := `SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ENGINE
FROM information_schema.TABLES
WHERE ` + filter + `
ORDER BY TABLE_SCHEMA, TABLE_NAME`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []adapter.ObservedResource
	for rows.Next() {
		var schema, name, tableType string
		var engine sql.NullString
		if err := rows.Scan(&schema, &name, &tableType, &engine); err != nil {
			return nil, fmt.Errorf("scan table row: %w", err)
		}
		kind, ok := tableTypeToKind(tableType)
		if !ok {
			continue
		}
		attrs := map[string]any{"table_type": tableType}
		if engine.Valid {
			attrs["engine"] = engine.String
		}
		id := relationExternalID(kind, schema, name)
		out = append(out, adapter.ObservedResource{
			Kind:             kind,
			ExternalID:       id,
			ParentExternalID: databaseExternalID(schema),
			Name:             name,
			CanonicalPath:    schema + "." + name,
			Attributes:       attrs,
			Fingerprint:      fingerprint(kind, id, attrs),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read tables: %w", err)
	}
	return out, nil
}

// discoverIndexes читает индексы из information_schema.STATISTICS и
// группирует строки по (schema, table, index). Родителем индекса считается
// его таблица.
func discoverIndexes(ctx context.Context, db *sql.DB) ([]adapter.ObservedResource, error) {
	filter, args := schemaFilter("TABLE_SCHEMA")
	q := `SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, COLUMN_NAME
FROM information_schema.STATISTICS
WHERE ` + filter + `
ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX`
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query indexes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type indexKey struct {
		schema, table, index string
	}
	// order сохраняет порядок первого появления индекса для детерминизма.
	var order []indexKey
	agg := make(map[indexKey]*indexAccumulator)
	for rows.Next() {
		var schema, table, index string
		var nonUnique int64
		var seq int64
		var column sql.NullString
		if err := rows.Scan(&schema, &table, &index, &nonUnique, &seq, &column); err != nil {
			return nil, fmt.Errorf("scan index row: %w", err)
		}
		key := indexKey{schema: schema, table: table, index: index}
		acc, ok := agg[key]
		if !ok {
			acc = &indexAccumulator{unique: nonUnique == 0, primary: index == "PRIMARY"}
			agg[key] = acc
			order = append(order, key)
		}
		if column.Valid {
			acc.columns = append(acc.columns, column.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read indexes: %w", err)
	}

	out := make([]adapter.ObservedResource, 0, len(order))
	for _, key := range order {
		acc := agg[key]
		attrs := map[string]any{
			"unique":  acc.unique,
			"primary": acc.primary,
			"columns": acc.columns,
		}
		id := indexExternalID(key.schema, key.table, key.index)
		out = append(out, adapter.ObservedResource{
			Kind:             "index",
			ExternalID:       id,
			ParentExternalID: relationExternalID("table", key.schema, key.table),
			Name:             key.index,
			CanonicalPath:    key.schema + "." + key.table + "." + key.index,
			Attributes:       attrs,
			Fingerprint:      fingerprint("index", id, attrs),
		})
	}
	return out, nil
}

// indexAccumulator накапливает строки STATISTICS одного индекса.
type indexAccumulator struct {
	unique  bool
	primary bool
	columns []string
}

// isRoleRow распознаёт роль MySQL 8 среди строк mysql.user.
//
// Отдельной таблицы для ролей в MySQL нет: `CREATE ROLE` создаёт строку в
// mysql.user, заблокированную, с истёкшим паролем и пустой строкой
// аутентификации. Ровно эта тройка признаков и отличает роль от учётной
// записи — по отдельности каждый встречается и у обычных учёток.
//
// Почему это важно: пока роль отдавалась как login-аккаунт, оператор мог
// принять её под управление и «включить», а `ACCOUNT UNLOCK` превращал её в
// живую учётку без пароля с хостом `%` — то есть в вход в СУБД для любого,
// кто знает имя роли (имена ролей grantor публикует в каталоге прав).
func isRoleRow(locked, expired string, emptyAuth bool) bool {
	return strings.EqualFold(locked, "Y") && strings.EqualFold(expired, "Y") && emptyAuth
}

// discoverAccounts читает аккаунты из mysql.user. Каждый аккаунт —
// EngineIdentity "user@host"; Disabled определяется по account_locked.
// Служебные аккаунты MySQL исключаются.
//
// Kind различает учётную запись и роль (см. isRoleRow): роль не имеет своего
// пароля, и lifecycle-операции над ней запрещены ядром по kind.
func discoverAccounts(ctx context.Context, db *sql.DB) ([]adapter.ObservedAccount, error) {
	const q = `SELECT User, Host, account_locked, password_expired,
       (authentication_string = '') AS empty_auth
FROM mysql.user
ORDER BY User, Host`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query accounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []adapter.ObservedAccount
	for rows.Next() {
		var user, host, locked, expired string
		var emptyAuth bool
		if err := rows.Scan(&user, &host, &locked, &expired, &emptyAuth); err != nil {
			return nil, fmt.Errorf("scan account row: %w", err)
		}
		if systemAccounts[user] {
			continue
		}
		role := isRoleRow(locked, expired, emptyAuth)
		attrs := map[string]any{
			"account_locked":   locked,
			"password_expired": expired,
			"host":             host,
		}
		kind := "login"
		if role {
			// Роль не имеет своего пароля: ядро по kind запрещает ей
			// enable/rotate/share и кредовые режимы adopt.
			kind = "group"
			attrs["role"] = true
		}
		out = append(out, adapter.ObservedAccount{
			Kind:           kind,
			EngineIdentity: userHostIdentity(user, host),
			// Заблокированность роли — её обычное состояние, а не признак
			// отключения: помечать роль disabled значило бы предлагать
			// оператору «включить» её.
			Disabled:   !role && strings.EqualFold(locked, "Y"),
			Attributes: attrs,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read accounts: %w", err)
	}
	return out, nil
}

// discoverDefaultRoles читает mysql.default_roles — набор ролей, которые
// сервер активирует на логине учётной записи. Ключ результата — "user@host"
// аккаунта, значение — отсортированные identity его default roles. Таблица
// существует только на MySQL 8.0+, поэтому вызывается под тем же
// version gate, что и остальная инвентаризация ролей.
func discoverDefaultRoles(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	const q = `SELECT USER, HOST, DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST
FROM mysql.default_roles`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query default roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]string)
	for rows.Next() {
		var user, host, roleUser, roleHost string
		if err := rows.Scan(&user, &host, &roleUser, &roleHost); err != nil {
			return nil, fmt.Errorf("scan default role row: %w", err)
		}
		key := userHostIdentity(user, host)
		out[key] = append(out[key], userHostIdentity(roleUser, roleHost))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read default roles: %w", err)
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out, nil
}

// annotateDefaultRoles дописывает каждому аккаунту его набор default roles.
// Атрибут задаётся всегда (пустым срезом при отсутствии записей), чтобы
// снимок не смешивал «ролей нет» с «не читали».
func annotateDefaultRoles(accounts []adapter.ObservedAccount, defaults map[string][]string) {
	for i := range accounts {
		roles := defaults[accounts[i].EngineIdentity]
		if roles == nil {
			roles = []string{}
		}
		if accounts[i].Attributes == nil {
			accounts[i].Attributes = map[string]any{}
		}
		accounts[i].Attributes["default_roles"] = roles
	}
}

// discoverRoles строит permissions и bindings из mysql.role_edges. Роль —
// это вершина FROM_USER@FROM_HOST любого ребра; она становится назначаемой
// permission "role:<user>@<host>". Ребро FROM->TO становится binding
// (TO получает роль FROM). Опасность роли определяется её глобальными
// привилегиями. Bindings, ссылающиеся на исключённый (служебный) аккаунт,
// пропускаются ради консистентности snapshot.
//
// В атрибутах binding наблюдаемая выдача отделена от фактической активности:
// default_role сообщает, входит ли роль в mysql.default_roles аккаунта, а
// active — активируется ли она на логине (default role либо глобальный
// activate_all_roles_on_login=ON).
func discoverRoles(
	ctx context.Context,
	db *sql.DB,
	accountSet map[string]bool,
	roles [][2]string,
	defaults map[string][]string,
	activateAll bool,
) ([]adapter.ObservedPermission, []adapter.ObservedBinding, error) {
	globalPrivs, err := discoverGlobalPrivileges(ctx, db)
	if err != nil {
		return nil, nil, err
	}

	edges, err := discoverRoleEdges(ctx, db)
	if err != nil {
		return nil, nil, err
	}

	permByID := make(map[string]bool)
	var permissions []adapter.ObservedPermission
	addPermission := func(user, host string) {
		id := rolePermissionID(user, host)
		if permByID[id] {
			return
		}
		permByID[id] = true
		privs := globalPrivs[userHostIdentity(user, host)]
		attrs := map[string]any{"host": host}
		if len(privs) > 0 {
			attrs["global_privileges"] = privs
		}
		permissions = append(permissions, adapter.ObservedPermission{
			ExternalID: id,
			Name:       userHostIdentity(user, host),
			Assignable: true,
			Dangerous:  dangerousPrivileges(privs),
			Attributes: attrs,
		})
	}

	// Каталог строится от списка ролей движка, а не от рёбер: роль без
	// членов — обычное состояние только что созданной роли, и она обязана
	// быть назначаемой.
	for _, r := range roles {
		addPermission(r[0], r[1])
	}

	var bindings []adapter.ObservedBinding
	// roleByIdentity — обратная карта identity роли в её пару user/host:
	// раскрытие цепочек работает с identity, а permission id строится из пары.
	roleByIdentity := map[string][2]string{}
	graph := make([]adapterutil.MembershipEdge, 0, len(edges))

	for _, e := range edges {
		// Роль-вершина обязана существовать как permission, даже если на неё
		// ссылается несколько рёбер (консистентность snapshot).
		addPermission(e.fromUser, e.fromHost)

		role := userHostIdentity(e.fromUser, e.fromHost)
		member := userHostIdentity(e.toUser, e.toHost)
		roleByIdentity[role] = [2]string{e.fromUser, e.fromHost}
		graph = append(graph, adapterutil.MembershipEdge{Role: role, Member: member})

		if !accountSet[member] {
			continue
		}
		isDefault := slices.Contains(defaults[member], role)
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: member,
			PermissionExternalID:  rolePermissionID(e.fromUser, e.fromHost),
			Attributes: map[string]any{
				"admin_option": strings.EqualFold(e.adminOption, "Y"),
				"default_role": isDefault,
				// Роль, не входящая в набор по умолчанию, числится выданной
				// и не даёт ничего: SHOW GRANTS её показывает, а запрос
				// отвергается с ERROR 1142. Ядро обязано увидеть это как
				// дрифт, а не как synced.
				adapter.AttrBindingEffective: isDefault || activateAll,
			},
		})
	}

	// Транзитивные членства: роль, выданная роли, приносит свои права и
	// учётной записи. Промежуточные вершины графа — сами роли, поэтому
	// закрытие считается по всем рёбрам, а bindings создаются только тем
	// членам, которые являются учётными записями.
	//
	// admin_option, default_role и active по цепочке не проставляются: они
	// описывают прямой грант, и переносить их на унаследованное право
	// значило бы утверждать то, чего мы не проверяли.
	for _, e := range adapterutil.InheritedMemberships(graph) {
		if !accountSet[e.Member] {
			continue
		}
		pair, ok := roleByIdentity[e.Role]
		if !ok {
			continue
		}
		bindings = append(bindings, adapter.ObservedBinding{
			AccountEngineIdentity: e.Member,
			PermissionExternalID:  rolePermissionID(pair[0], pair[1]),
			Inherited:             true,
			Attributes:            map[string]any{"inherited": true},
		})
	}
	return permissions, bindings, nil
}

// roleEdge — строка mysql.role_edges.
type roleEdge struct {
	fromUser, fromHost string
	toUser, toHost     string
	adminOption        string
}

// discoverRoleEdges читает рёбра ролей из mysql.role_edges.
func discoverRoleEdges(ctx context.Context, db *sql.DB) ([]roleEdge, error) {
	const q = `SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST, WITH_ADMIN_OPTION
FROM mysql.role_edges
ORDER BY TO_USER, TO_HOST, FROM_USER, FROM_HOST`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query role edges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []roleEdge
	for rows.Next() {
		var e roleEdge
		if err := rows.Scan(&e.fromUser, &e.fromHost, &e.toUser, &e.toHost, &e.adminOption); err != nil {
			return nil, fmt.Errorf("scan role edge row: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read role edges: %w", err)
	}
	return out, nil
}

// discoverGlobalPrivileges читает глобальные привилегии всех grantee из
// information_schema.USER_PRIVILEGES. Ключ результата — "user@host".
func discoverGlobalPrivileges(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	const q = `SELECT GRANTEE, PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("query global privileges: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]string)
	for rows.Next() {
		var grantee, priv string
		if err := rows.Scan(&grantee, &priv); err != nil {
			return nil, fmt.Errorf("scan global privilege row: %w", err)
		}
		user, host, ok := parseGrantee(grantee)
		if !ok {
			continue
		}
		key := userHostIdentity(user, host)
		out[key] = append(out[key], priv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read global privileges: %w", err)
	}
	for k := range out {
		slices.Sort(out[k])
	}
	return out, nil
}

// dangerousGlobalPrivileges — глобальные привилегии, дающие административный
// контроль над сервером. Роль или аккаунт с любой из них считается опасным.
var dangerousGlobalPrivileges = map[string]bool{
	"SUPER":             true,
	"GRANT OPTION":      true,
	"CREATE USER":       true,
	"RELOAD":            true,
	"SHUTDOWN":          true,
	"FILE":              true,
	"PROCESS":           true,
	"REPLICATION SLAVE": true,
	"SYSTEM_USER":       true,
	"ROLE_ADMIN":        true,
}

// dangerousPrivileges сообщает, содержит ли набор глобальных привилегий хотя
// бы одну опасную (SUPER, GRANT OPTION, административные привилегии). Пустой
// набор — не опасен.
func dangerousPrivileges(privs []string) bool {
	for _, p := range privs {
		if dangerousGlobalPrivileges[strings.ToUpper(strings.TrimSpace(p))] {
			return true
		}
	}
	return false
}

// parseGrantee разбирает GRANTEE вида 'user'@'host' из
// information_schema.USER_PRIVILEGES в пару (user, host). Разделителем
// считается первое вхождение "'@'".
func parseGrantee(grantee string) (user, host string, ok bool) {
	s := strings.TrimSpace(grantee)
	const sep = "'@'"
	idx := strings.Index(s, sep)
	if idx < 0 || !strings.HasPrefix(s, "'") || !strings.HasSuffix(s, "'") {
		return "", "", false
	}
	user = s[1:idx]
	host = s[idx+len(sep) : len(s)-1]
	return user, host, true
}

// tableTypeToKind переводит information_schema.TABLES.TABLE_TYPE в resource
// kind adapter.
func tableTypeToKind(tableType string) (string, bool) {
	switch strings.ToUpper(tableType) {
	case "BASE TABLE":
		return "table", true
	case "VIEW":
		return "view", true
	default:
		return "", false
	}
}

// userHostIdentity собирает EngineIdentity аккаунта/роли из user и host.
func userHostIdentity(user, host string) string { return user + "@" + host }

// databaseExternalID возвращает external id базы.
func databaseExternalID(db string) string { return "db:" + db }

// relationExternalID возвращает external id relation указанного kind. В MySQL
// нет отдельного слоя схемы: контейнером таблицы служит база (schema).
func relationExternalID(kind, db, name string) string {
	return kind + ":" + db + "." + name
}

// indexExternalID возвращает external id индекса.
func indexExternalID(db, table, index string) string {
	return "index:" + db + "." + table + "." + index
}

// rolePermissionID возвращает external id permission для роли user@host.
func rolePermissionID(user, host string) string {
	return "role:" + userHostIdentity(user, host)
}

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
		return strings.Compare(a.PermissionExternalID, b.PermissionExternalID)
	})
}
