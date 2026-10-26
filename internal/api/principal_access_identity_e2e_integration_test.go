//go:build integration

// Сквозные e2e-тесты principal-centric выдачи доступа против реальных MySQL
// (GRANTOR_TEST_MYSQL_DSN) и MongoDB (GRANTOR_TEST_MONGO_URI) с полноценным
// River worker. Закрывают два связанных бага ручного E2E:
//
//   - engine identity по умолчанию. Ядро выводит из принципала базовое имя
//     ("e2e_global"), а mysql требует user@host и mongodb — user@authdb.
//     До фикса POST /principals/{id}/access на этих движках ВСЕГДА падал без
//     недокументированного поля engine_identity в теле. Здесь запрос идёт
//     БЕЗ него, и проверяется, что учётка реально создана и логинится.
//
//   - фантомные аккаунты. Провалившийся account.create оставлял строку
//     active/managed на общем секрете принципала, хотя пользователя в целевой
//     системе нет. Такие записи переживали discovery, не попадали в дрифт,
//     плодили дубли при повторе и делали массовые операции принципала вечно
//     partial. Здесь провал моделируется явно и проверяется, что аккаунт не
//     остаётся живым, повтор не создаёт второй строки, ротация не ломается,
//     а расхождение видно в дрифте.
package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// registry глобален, Register паникует на дубликате.
var (
	registerMySQLOnceAPI sync.Once
)

// mongoIdentityDatabase — база, в которой тест заводит custom-роль: роли
// MongoDB scoped к базе, а discovery отдаёт их как "role:<db>.<name>".
const mongoIdentityDatabase = "appdb"

// targetConnectionParams — параметры создания подключения к целевой системе
// через API (тот же путь, что у оператора в UI).
type targetConnectionParams struct {
	engine          string
	endpoint        string
	adminUser       string
	adminPassword   string
	discoveryConfig map[string]string
}

// createTargetConnection создаёт connection через API, запускает refresh и
// дожидается active: без успешного discovery выдача доступа запрещена.
func createTargetConnection(t *testing.T, env *testEnv, admin, operator auth.Session,
	environment string, params targetConnectionParams) uuid.UUID {
	t.Helper()
	body := map[string]any{
		"display_name":     "itest-identity-" + uniqueSuffix(),
		"engine":           params.engine,
		"environment":      environment,
		"endpoints":        []string{params.endpoint},
		"tls_config":       map[string]string{"mode": "disabled"},
		"admin_credential": map[string]string{"username": params.adminUser, "password": params.adminPassword},
	}
	if params.discoveryConfig != nil {
		body["discovery_config"] = params.discoveryConfig
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var connOut struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&connOut); err != nil {
		t.Fatalf("decode connection: %v", err)
	}

	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+connOut.ID.String()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var refreshOut struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshOut); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	waitOperation(t, env, refreshOut.OperationID, operations.StatusSuccess, 120*time.Second)
	return connOut.ID
}

// createServicePrincipal создаёт service-принципала с заданным display name:
// именно из него выводится базовое имя engine identity.
func createServicePrincipal(t *testing.T, env *testEnv, operator auth.Session, displayName string) uuid.UUID {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/principals", map[string]any{
		"type": "service", "display_name": displayName,
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode principal: %v", err)
	}
	return out.ID
}

// grantAccessDefaultIdentity выполняет POST /principals/{id}/access БЕЗ поля
// engine_identity — обычный UI-сценарий «выдать доступ пользователю».
func grantAccessDefaultIdentity(t *testing.T, env *testEnv, sess auth.Session,
	principalID uuid.UUID, items []map[string]any) struct {
	OperationID uuid.UUID                  `json:"operation_id"`
	Children    []principalAccessChildBody `json:"children"`
} {
	t.Helper()
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principalID.String()+"/access",
		map[string]any{"items": items}, &sess, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID                  `json:"operation_id"`
		Children    []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode access response: %v", err)
	}
	return out
}

// accountRowForIdentity читает строку аккаунта из metadata.
func accountRowForIdentity(t *testing.T, env *testEnv, id uuid.UUID) inventory.Account {
	t.Helper()
	acct, err := inventory.NewStore().GetAccount(context.Background(), env.pool, id)
	if err != nil {
		t.Fatalf("get account %s: %v", id, err)
	}
	return acct
}

// connectionAccounts возвращает все аккаунты подключения — тест дублей
// смотрит именно на их количество.
func connectionAccounts(t *testing.T, env *testEnv, connID uuid.UUID) []inventory.Account {
	t.Helper()
	accts, err := inventory.NewStore().ListAccounts(context.Background(), env.pool, connID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	return accts
}

// connectionDrift читает drift-сводку подключения через API.
func connectionDrift(t *testing.T, env *testEnv, sess auth.Session, connID uuid.UUID) struct {
	UnmanagedBindings       int `json:"unmanaged_bindings"`
	DriftBindings           int `json:"drift_bindings"`
	MissingManagedResources int `json:"missing_managed_resources"`
	MissingManagedAccounts  int `json:"missing_managed_accounts"`
} {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+connID.String(), nil, &sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Drift struct {
			UnmanagedBindings       int `json:"unmanaged_bindings"`
			DriftBindings           int `json:"drift_bindings"`
			MissingManagedResources int `json:"missing_managed_resources"`
			MissingManagedAccounts  int `json:"missing_managed_accounts"`
		} `json:"drift"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode connection: %v", err)
	}
	return out.Drift
}

// --- MySQL ---------------------------------------------------------------

// mysqlAdminConfig разбирает GRANTOR_TEST_MYSQL_DSN; без переменной тест
// пропускается.
func mysqlAdminConfig(t *testing.T) *mysqldriver.Config {
	t.Helper()
	dsn := os.Getenv("GRANTOR_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_MYSQL_DSN is not set; skipping mysql identity e2e test")
	}
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_MYSQL_DSN: %v", err)
	}
	return cc
}

// mysqlAdminDB открывает пул к целевому MySQL под admin.
func mysqlAdminDB(t *testing.T, cc *mysqldriver.Config) *sql.DB {
	t.Helper()
	clone := *cc
	clone.DBName = ""
	connector, err := mysqldriver.NewConnector(&clone)
	if err != nil {
		t.Fatalf("build mysql connector: %v", err)
	}
	db := sql.OpenDB(connector)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// mysqlLoginWorks сообщает, логинится ли user@host в целевой MySQL под
// заданным паролем. Именно эта проверка отвечает на вопрос «аккаунт
// действительно рабочий», а не «строка в metadata есть».
func mysqlLoginWorks(ctx context.Context, t *testing.T, cc *mysqldriver.Config, user, password string) bool {
	t.Helper()
	clone := *cc
	clone.User = user
	clone.Passwd = password
	clone.DBName = ""
	connector, err := mysqldriver.NewConnector(&clone)
	if err != nil {
		t.Fatalf("build mysql connector: %v", err)
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	return db.PingContext(ctx) == nil
}

// ensureMySQLIdentityRole создаёт assignable роль, которую тест выдаёт
// принципалу, и «затравочного» пользователя с этой ролью: mysql adapter
// строит permissions из mysql.role_edges, поэтому никем не выданная роль в
// discovery не попадает.
func ensureMySQLIdentityRole(ctx context.Context, t *testing.T, db *sql.DB, role, seedUser string) {
	t.Helper()
	stmts := []string{
		"CREATE ROLE IF NOT EXISTS '" + role + "'@'%'",
		"CREATE USER IF NOT EXISTS '" + seedUser + "'@'%' IDENTIFIED BY 'Seed-Pass-1'",
		"GRANT '" + role + "'@'%' TO '" + seedUser + "'@'%'",
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply mysql role fixture: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DROP USER IF EXISTS '"+seedUser+"'@'%'")
		_, _ = db.ExecContext(context.Background(), "DROP ROLE IF EXISTS '"+role+"'@'%'")
	})
}

// mysqlSupportsRoles — роли появились в MySQL 8.0; на MariaDB семантика иная.
func mysqlSupportsRoles(ctx context.Context, t *testing.T, db *sql.DB) bool {
	t.Helper()
	var version string
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		t.Fatalf("read mysql version: %v", err)
	}
	lower := strings.ToLower(version)
	return !strings.Contains(lower, "mariadb") && version[0] >= '8'
}

// TestIntegrationPrincipalAccessDefaultIdentityMySQLE2E — баг 1 на MySQL:
// выдача доступа БЕЗ engine_identity должна создать рабочую учётку
// "<slug>@%" и реально залогиниться общим паролем принципала.
func TestIntegrationPrincipalAccessDefaultIdentityMySQLE2E(t *testing.T) {
	cc := mysqlAdminConfig(t)
	vaultClient := newTestVault(t)
	registerMySQLOnceAPI.Do(func() {
		adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.New() })
	})
	ctx := context.Background()
	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	adminDB := mysqlAdminDB(t, cc)
	if !mysqlSupportsRoles(ctx, t, adminDB) {
		t.Skip("target mysql does not support 8.0 roles; skipping identity e2e test")
	}
	sfx := uniqueSuffix()[:8]
	role := "gr_ident_ro_" + sfx
	ensureMySQLIdentityRole(ctx, t, adminDB, role, "gr_ident_seed_"+sfx)

	connID := createTargetConnection(t, env, admin, operator, "ident-mysql-"+sfx, targetConnectionParams{
		engine:        mysql.Engine,
		endpoint:      cc.Addr,
		adminUser:     cc.User,
		adminPassword: cc.Passwd,
	})
	perm := findPermission(t, env.pool, connID, "role:"+role+"@%")

	// Display name без спецсимволов даёт предсказуемый slug.
	base := "gr_ident_p_" + sfx
	principalID := createServicePrincipal(t, env, operator, base)
	wantIdentity := base + "@%"
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), "DROP USER IF EXISTS '"+base+"'@'%'")
	})

	access := grantAccessDefaultIdentity(t, env, operator, principalID, []map[string]any{
		{"connection_id": connID, "permission_id": perm.ID},
	})
	if len(access.Children) != 1 || access.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want single created account", access.Children)
	}
	child := access.Children[0]
	waitOperation(t, env, *child.AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, child.GrantOperationID, operations.StatusSuccess, 120*time.Second)

	acct := accountRowForIdentity(t, env, child.AccountID)
	if acct.EngineIdentity != wantIdentity {
		t.Errorf("engine identity = %q, want %q", acct.EngineIdentity, wantIdentity)
	}
	if acct.Status != inventory.AccountActive {
		t.Errorf("account status = %q, want active", acct.Status)
	}

	// Учётка реально существует и логинится общим паролем принципала.
	password := principalSharedPassword(t, vaultClient, principalID, "ident-mysql-"+sfx)
	if !mysqlLoginWorks(ctx, t, cc, base, password) {
		t.Errorf("account %q cannot log in to mysql with the principal shared password", wantIdentity)
	}
}

// TestIntegrationPrincipalAccessFailedCreateMySQLE2E — баг 2: провал
// account.create не должен оставлять живой managed-аккаунт, повтор не должен
// плодить дубли, а массовая ротация принципала не должна ломаться о такую
// запись.
//
// Провал моделируется явным engine_identity "@%" — mysql отвергает его на
// этапе Plan ("empty user part"), не трогая целевую систему. Это тот же класс
// отказа, что и исходный баг (adapter не принял identity), но детерминирован.
func TestIntegrationPrincipalAccessFailedCreateMySQLE2E(t *testing.T) {
	cc := mysqlAdminConfig(t)
	vaultClient := newTestVault(t)
	registerMySQLOnceAPI.Do(func() {
		adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.New() })
	})
	ctx := context.Background()
	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	adminDB := mysqlAdminDB(t, cc)
	if !mysqlSupportsRoles(ctx, t, adminDB) {
		t.Skip("target mysql does not support 8.0 roles; skipping phantom account e2e test")
	}
	sfx := uniqueSuffix()[:8]
	role := "gr_phan_ro_" + sfx
	ensureMySQLIdentityRole(ctx, t, adminDB, role, "gr_phan_seed_"+sfx)

	env2 := "phantom-mysql-" + sfx
	connID := createTargetConnection(t, env, admin, operator, env2, targetConnectionParams{
		engine:        mysql.Engine,
		endpoint:      cc.Addr,
		adminUser:     cc.User,
		adminPassword: cc.Passwd,
	})
	perm := findPermission(t, env.pool, connID, "role:"+role+"@%")

	base := "gr_phan_p_" + sfx
	principalID := createServicePrincipal(t, env, operator, base)
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), "DROP USER IF EXISTS '"+base+"'@'%'")
	})

	items := []map[string]any{{"connection_id": connID, "permission_id": perm.ID}}
	bad := grantPrincipalAccessItems(t, env, &operator, principalID, "@%", items)
	if len(bad.Children) != 1 || bad.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want single created account", bad.Children)
	}
	phantomID := bad.Children[0].AccountID
	waitOperation(t, env, *bad.Children[0].AccountCreateOperationID, operations.StatusFailed, 120*time.Second)

	// 1. Аккаунт не остался живым managed: он в provisioning, а значит не
	// участвует в массовых операциях и виден как расхождение.
	phantom := accountRowForIdentity(t, env, phantomID)
	if phantom.Status != inventory.AccountProvisioning {
		t.Errorf("after failed create account status = %q, want provisioning", phantom.Status)
	}
	if inventory.IsLiveAccountStatus(phantom.Status) {
		t.Errorf("account status %q is still treated as live", phantom.Status)
	}

	// 2. Повторная попытка с той же identity переиспользует ту же строку —
	// второго аккаунта не появляется.
	before := len(connectionAccounts(t, env, connID))
	retry := grantPrincipalAccessItems(t, env, &operator, principalID, "@%", items)
	if len(retry.Children) != 1 {
		t.Fatalf("retry children = %+v, want single child", retry.Children)
	}
	if retry.Children[0].AccountID != phantomID {
		t.Errorf("retry account id = %s, want reused %s", retry.Children[0].AccountID, phantomID)
	}
	if retry.Children[0].AccountCreateOperationID == nil {
		t.Error("retry did not re-enqueue account.create for the unprovisioned account")
	} else {
		waitOperation(t, env, *retry.Children[0].AccountCreateOperationID, operations.StatusFailed, 120*time.Second)
	}
	if after := len(connectionAccounts(t, env, connID)); after != before {
		t.Errorf("accounts in connection = %d after retry, want %d (no duplicates)", after, before)
	}

	// 3. Discovery не «легализует» фантом: он остаётся не-живым и после
	// повторного снимка инвентаря.
	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+connID.String()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var refreshOut struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshOut); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	waitOperation(t, env, refreshOut.OperationID, operations.StatusSuccess, 120*time.Second)
	if got := accountRowForIdentity(t, env, phantomID).Status; got != inventory.AccountProvisioning {
		t.Errorf("after discovery account status = %q, want provisioning", got)
	}

	// 4. Расхождение видно в дрифте — раньше фантом был невидим.
	if drift := connectionDrift(t, env, operator, connID); drift.MissingManagedAccounts < 1 {
		t.Errorf("drift.missing_managed_accounts = %d, want >= 1", drift.MissingManagedAccounts)
	}

	// 5. Рабочий аккаунт того же принципала (identity по умолчанию) создаётся
	// и работает несмотря на фантом.
	good := grantAccessDefaultIdentity(t, env, operator, principalID, items)
	if len(good.Children) != 1 || good.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("default-identity access children = %+v, want created account", good.Children)
	}
	waitOperation(t, env, *good.Children[0].AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, good.Children[0].GrantOperationID, operations.StatusSuccess, 120*time.Second)

	// 6. Глобальная ротация принципала не спотыкается о фантом: дочерняя
	// операция ставится только по живому аккаунту, а parent завершается
	// success (раньше был вечный partial).
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principalID.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var rotate struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			AccountID   uuid.UUID `json:"account_id"`
			OperationID uuid.UUID `json:"operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotate); err != nil {
		t.Fatalf("decode rotate: %v", err)
	}
	for _, c := range rotate.Children {
		if c.AccountID == phantomID {
			t.Errorf("rotate scheduled a child for phantom account %s", phantomID)
		}
		waitOperation(t, env, c.OperationID, operations.StatusSuccess, 120*time.Second)
	}
	waitOperation(t, env, rotate.OperationID, operations.StatusSuccess, 120*time.Second)
}

// --- MongoDB -------------------------------------------------------------

// mongoTargetURI возвращает URI целевого MongoDB; без переменной тест
// пропускается.
func mongoTargetURI(t *testing.T) string {
	t.Helper()
	uri := os.Getenv("GRANTOR_TEST_MONGO_URI")
	if uri == "" {
		t.Skip("GRANTOR_TEST_MONGO_URI is not set; skipping mongodb identity e2e test")
	}
	return uri
}

// mongoAdminParts вытаскивает из URI host:port и admin-креды.
func mongoAdminParts(t *testing.T, uri string) (endpoint, user, password string) {
	t.Helper()
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_MONGO_URI: %v", err)
	}
	pwd, _ := u.User.Password()
	return u.Host, u.User.Username(), pwd
}

// mongoAdminClientIdentity открывает клиент к целевому MongoDB под admin.
func mongoAdminClientIdentity(ctx context.Context, t *testing.T, uri string) *mongo.Client {
	t.Helper()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatalf("connect mongo: %v", err)
	}
	t.Cleanup(func() { _ = client.Disconnect(context.Background()) })
	return client
}

// ensureMongoIdentityRole создаёт custom-роль в базе фикстуры. База должна
// существовать физически: discovery перечисляет роли только по базам,
// которые видит listDatabases, поэтому сначала пишется документ.
func ensureMongoIdentityRole(ctx context.Context, t *testing.T, client *mongo.Client, role string) {
	t.Helper()
	db := client.Database(mongoIdentityDatabase)
	if _, err := db.Collection("identity_fixture").InsertOne(ctx, bson.D{{Key: "seed", Value: 1}}); err != nil {
		t.Fatalf("seed mongo fixture database: %v", err)
	}
	cmd := bson.D{
		{Key: "createRole", Value: role},
		{Key: "privileges", Value: bson.A{bson.D{
			{Key: "resource", Value: bson.D{{Key: "db", Value: mongoIdentityDatabase}, {Key: "collection", Value: ""}}},
			{Key: "actions", Value: bson.A{"find"}},
		}}},
		{Key: "roles", Value: bson.A{}},
	}
	if err := db.RunCommand(ctx, cmd).Err(); err != nil && !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("create mongo role: %v", err)
	}
	t.Cleanup(func() {
		_ = db.RunCommand(context.Background(), bson.D{{Key: "dropRole", Value: role}}).Err()
	})
}

// mongoLoginWorks сообщает, аутентифицируется ли user в authDB с паролем.
func mongoLoginWorks(ctx context.Context, t *testing.T, endpoint, authDB, user, password string) bool {
	t.Helper()
	opts := options.Client().
		SetHosts([]string{endpoint}).
		SetAuth(options.Credential{AuthSource: authDB, Username: user, Password: password})
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return false
	}
	defer func() { _ = client.Disconnect(context.Background()) }()
	return client.Database(authDB).RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Err() == nil
}

// TestIntegrationPrincipalAccessDefaultIdentityMongoE2E — баг 1 на MongoDB:
// выдача доступа БЕЗ engine_identity должна создать рабочую учётку
// "<slug>@admin" и реально аутентифицироваться общим паролем принципала.
func TestIntegrationPrincipalAccessDefaultIdentityMongoE2E(t *testing.T) {
	uri := mongoTargetURI(t)
	vaultClient := newTestVault(t)
	registerMongoOnceAPI.Do(func() {
		adapter.Register(mongodb.Engine, func() adapter.Adapter { return mongodb.New() })
	})
	ctx := context.Background()
	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	endpoint, adminUser, adminPassword := mongoAdminParts(t, uri)
	client := mongoAdminClientIdentity(ctx, t, uri)
	sfx := uniqueSuffix()[:8]
	role := "gr_ident_ro_" + sfx
	ensureMongoIdentityRole(ctx, t, client, role)

	connID := createTargetConnection(t, env, admin, operator, "ident-mongo-"+sfx, targetConnectionParams{
		engine:        mongodb.Engine,
		endpoint:      endpoint,
		adminUser:     adminUser,
		adminPassword: adminPassword,
	})
	perm := findPermission(t, env.pool, connID, "role:"+mongoIdentityDatabase+"."+role)

	base := "gr_ident_p_" + sfx
	principalID := createServicePrincipal(t, env, operator, base)
	wantIdentity := base + "@admin"
	t.Cleanup(func() {
		_ = client.Database("admin").RunCommand(context.Background(),
			bson.D{{Key: "dropUser", Value: base}}).Err()
	})

	access := grantAccessDefaultIdentity(t, env, operator, principalID, []map[string]any{
		{"connection_id": connID, "permission_id": perm.ID},
	})
	if len(access.Children) != 1 || access.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want single created account", access.Children)
	}
	child := access.Children[0]
	waitOperation(t, env, *child.AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, child.GrantOperationID, operations.StatusSuccess, 120*time.Second)

	acct := accountRowForIdentity(t, env, child.AccountID)
	if acct.EngineIdentity != wantIdentity {
		t.Errorf("engine identity = %q, want %q", acct.EngineIdentity, wantIdentity)
	}
	if acct.Status != inventory.AccountActive {
		t.Errorf("account status = %q, want active", acct.Status)
	}

	password := principalSharedPassword(t, vaultClient, principalID, "ident-mongo-"+sfx)
	if !mongoLoginWorks(ctx, t, endpoint, "admin", base, password) {
		t.Errorf("account %q cannot authenticate in mongodb with the principal shared password", wantIdentity)
	}
}

// principalSharedPassword читает общий секрет принципала для окружения —
// именно им должны логиниться созданные учётки.
func principalSharedPassword(t *testing.T, vaultClient *vault.Client, principalID uuid.UUID, environment string) string {
	t.Helper()
	password, _, err := credentials.NewService(vaultClient, nil).
		GetPrincipalCredential(context.Background(), principalID, environment)
	if err != nil {
		t.Fatalf("read principal shared credential: %v", err)
	}
	if len(password) == 0 {
		t.Fatal("principal shared credential has empty password")
	}
	return string(password)
}
