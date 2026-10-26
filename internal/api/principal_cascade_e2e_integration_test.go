//go:build integration

// Сквозной e2e-тест каскада принципала против реального целевого
// PostgreSQL (GRANTOR_TEST_TARGET_PG_DSN) и Vault: API-сервер собирается с
// ПОЛНОЦЕННЫМ River worker (не insert-only), поэтому поставленные каскадом
// операции реально исполняются в целевой системе. Проверяется:
//   - disable каскадит account.disable — роли в целевом PG становятся
//     NOLOGIN; enable возвращает LOGIN;
//   - offboard отзывает bindings (membership пропадает) и меняет ОБА вида
//     пароля — общий секрет принципала и личный кред аккаунта: старым в
//     целевую БД уже не войти, новым можно. Роли и аккаунты остаются
//     живыми (offboard обратим), привязанный unmanaged-аккаунт не
//     трогается и попадает в ответ.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// registerPostgresOnceAPI защищает от повторной регистрации postgres
// adapter в процессе тестов api (registry глобален, Register паникует на
// дубликате).
var registerPostgresOnceAPI sync.Once

// newCascadeWorkerEnv собирает testEnv, у которого диспетчер — полноценный
// River с worker на отдельной очереди: операции, поставленные API,
// исполняются MainExecutor против реальных target/Vault. Очередь уникальна
// на прогон, чтобы worker не подбирал pending-jobs других тестов на общей
// базе (insert-only тесты используют очередь по умолчанию).
func newCascadeWorkerEnv(t *testing.T, vaultClient *vault.Client) *testEnv {
	t.Helper()
	return newWorkerEnv(t, vaultClient, testEnvOpts{})
}

// newWorkerEnv — newCascadeWorkerEnv с дополнительными параметрами сборки
// сервера (vault и dispatcher задаются здесь и в opts игнорируются).
func newWorkerEnv(t *testing.T, vaultClient *vault.Client, opts testEnvOpts) *testEnv {
	t.Helper()
	pool := pgtest.Pool(t)
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connections.NewStore(),
		Inventory:   inventory.NewStore(),
		Audit:       audit.NewWriter(),
		Vault:       vaultClient,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{Credentials: credSvc})
	// WorkerCount=1: последовательное исполнение в порядке вставки — та же
	// гарантия порядка зависимых операций (account.create -> access.grant,
	// access.revoke -> account.delete), на которую полагается API-слой
	// (advisory lock + вставка по порядку; см. TODO о явной зависимости в
	// grantPrincipalAccess). Конкурентная гонка порядка при нескольких
	// workers дополнительно закрыта идемпотентным no-op revoke
	// (recordRevokeNoop), но e2e-проверка держится детерминированной.
	r, err := jobs.New(pool, operations.NewStore(), executor, jobs.Config{
		Queue:        "cascade-e2e-" + uniqueSuffix()[:8],
		WorkerCount:  1,
		MaxAttempts:  2,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start river: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := r.Stop(stopCtx); err != nil {
			t.Errorf("stop river: %v", err)
		}
	})
	opts.vault = vaultClient
	opts.enforcement = policy.EnforcementDisabled
	opts.dispatcher = r
	return buildTestEnv(t, opts)
}

// waitOperation ждёт перехода операции в want (не дольше timeout);
// терминальный не-want статус — немедленный Fatal с ошибкой операции.
func waitOperation(t *testing.T, env *testEnv, id uuid.UUID, want operations.Status, timeout time.Duration) {
	t.Helper()
	store := operations.NewStore()
	deadline := time.Now().Add(timeout)
	for {
		op, err := store.Get(context.Background(), env.pool, id)
		if err != nil {
			t.Fatalf("get operation %s: %v", id, err)
		}
		if op.Status == want {
			return
		}
		if op.Status.IsTerminal() || op.Status == operations.StatusFailed {
			t.Fatalf("operation %s (%s) reached %q (want %q); error: %s", id, op.Kind, op.Status, want, op.Error)
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s (%s) stuck in %q (want %q)", id, op.Kind, op.Status, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// targetExec выполняет statement в целевом PostgreSQL под admin.
func targetExec(ctx context.Context, t *testing.T, dsn, stmt string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	if _, err := conn.Exec(ctx, stmt); err != nil {
		t.Fatalf("target exec %q: %v", stmt, err)
	}
}

// targetQueryBool возвращает булев результат запроса к целевому PostgreSQL.
func targetQueryBool(ctx context.Context, t *testing.T, dsn, query string, args ...any) bool {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	var out bool
	if err := conn.QueryRow(ctx, query, args...).Scan(&out); err != nil {
		t.Fatalf("target query %q: %v", query, err)
	}
	return out
}

// targetRoleExists — роль существует в целевом PG (независимо от login).
func targetRoleExists(ctx context.Context, t *testing.T, dsn, role string) bool {
	return targetQueryBool(ctx, t, dsn,
		`select exists (select 1 from pg_roles where rolname = $1)`, role)
}

// targetRoleCanLogin — роль существует и может логиниться.
func targetRoleCanLogin(ctx context.Context, t *testing.T, dsn, role string) bool {
	return targetQueryBool(ctx, t, dsn,
		`select coalesce((select rolcanlogin from pg_roles where rolname = $1), false)`, role)
}

// targetSecretPassword читает пароль и номер версии секрета тестового
// Vault. Значение нужно, чтобы проверить смену пароля на самой целевой
// системе; в логи и сообщения тестов оно не попадает — сравнивается только
// РЕЗУЛЬТАТ попытки входа.
func targetSecretPassword(ctx context.Context, t *testing.T, client *vault.Client, path string) (string, int) {
	t.Helper()
	data, version, err := client.Get(ctx, path)
	if err != nil {
		t.Fatalf("read secret %s: %v", path, err)
	}
	password, _ := data["password"].(string)
	if password == "" {
		t.Fatalf("secret %s has no password field", path)
	}
	return password, version
}

// targetCanAuthenticate пробует подключиться к целевому PG учётными данными
// аккаунта. Проверяет то, ради чего offboard меняет пароль: catalog-флаг
// rolcanlogin ещё не значит, что старый пароль отвергнут.
func targetCanAuthenticate(ctx context.Context, t *testing.T, admin *pgx.ConnConfig, user, password string) bool {
	t.Helper()
	cfg := admin.Copy()
	cfg.User = user
	cfg.Password = password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close(ctx) }()
	return true
}

// targetHasMembership — member входит в role в целевом PG.
func targetHasMembership(ctx context.Context, t *testing.T, dsn, role, member string) bool {
	return targetQueryBool(ctx, t, dsn, `
		select exists (
			select 1 from pg_auth_members m
			join pg_roles r on r.oid = m.roleid
			join pg_roles mem on mem.oid = m.member
			where r.rolname = $1 and mem.rolname = $2
		)`, role, member)
}

func TestIntegrationPrincipalCascadeOffboardPostgresE2E(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping cascade e2e test")
	}
	vaultClient := newTestVault(t)
	registerPostgresOnceAPI.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})
	ctx := context.Background()
	env := newCascadeWorkerEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	cc, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	sfx := uniqueSuffix()[:8]
	groupRole := "gr_offb_readers_" + sfx
	targetExec(ctx, t, targetDSN,
		`do $$ begin create role `+groupRole+` nologin; exception when duplicate_object then null; end $$`)

	// Подключение через API: admin credential уходит в Vault, refresh
	// запускает discovery, worker доводит connection до active.
	discoveryConfig, err := json.Marshal(map[string]string{"database": cc.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections", map[string]any{
		"display_name":     "itest-cascade-e2e-" + sfx,
		"engine":           postgres.Engine,
		"environment":      "offb",
		"endpoints":        []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		"tls_config":       map[string]string{"mode": "disabled"},
		"discovery_config": json.RawMessage(discoveryConfig),
		"admin_credential": map[string]string{"username": cc.User, "password": cc.Password},
	}, &admin, true)
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
	waitOperation(t, env, refreshOut.OperationID, operations.StatusSuccess, 90*time.Second)

	// Принципал и два managed-аккаунта: A — через principal-access flow
	// (общий секрет + грант группы), B — через POST /accounts (собственный
	// generated-кред в accounts/<id>/credential).
	resp = env.do(t, http.MethodPost, "/api/v1/principals", map[string]any{
		"type": "service", "display_name": "Cascade E2E " + sfx,
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var principal struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}
	perm := findPermission(t, env.pool, connOut.ID, "role:"+groupRole)
	idA := "gr_offb_a_" + sfx
	idB := "gr_offb_b_" + sfx

	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, idA, []map[string]any{
		{"connection_id": connOut.ID, "permission_id": perm.ID},
	})
	if len(access.Children) != 1 || access.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want single created account", access.Children)
	}
	waitOperation(t, env, *access.Children[0].AccountCreateOperationID, operations.StatusSuccess, 60*time.Second)
	waitOperation(t, env, access.Children[0].GrantOperationID, operations.StatusSuccess, 60*time.Second)

	resp = env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{
		"connection_id":   connOut.ID,
		"engine_identity": idB,
		"principal_id":    principal.ID,
		"credential":      map[string]string{"mode": "generated"},
	}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var acctBOut struct {
		AccountID   uuid.UUID `json:"account_id"`
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&acctBOut); err != nil {
		t.Fatalf("decode create account: %v", err)
	}
	waitOperation(t, env, acctBOut.OperationID, operations.StatusSuccess, 60*time.Second)

	if !targetRoleCanLogin(ctx, t, targetDSN, idA) || !targetRoleCanLogin(ctx, t, targetDSN, idB) {
		t.Fatalf("roles %s/%s not provisioned with login in target", idA, idB)
	}
	if !targetHasMembership(ctx, t, targetDSN, groupRole, idA) {
		t.Fatalf("membership %s -> %s not found after grant", idA, groupRole)
	}

	// 1. Disable каскадит: оба аккаунта становятся NOLOGIN, принципал
	// disabled; enable возвращает LOGIN.
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var disabled cascadeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode disable: %v", err)
	}
	if len(disabled.Children) != 2 {
		t.Fatalf("disable children = %d, want 2", len(disabled.Children))
	}
	for _, child := range disabled.Children {
		waitOperation(t, env, child.OperationID, operations.StatusSuccess, 60*time.Second)
	}
	for _, id := range []string{idA, idB} {
		if targetRoleCanLogin(ctx, t, targetDSN, id) {
			t.Errorf("role %s still can login after cascade disable", id)
		}
		if !targetRoleExists(ctx, t, targetDSN, id) {
			t.Errorf("role %s dropped by disable (must be NOLOGIN, not dropped)", id)
		}
	}

	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/enable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var enabled cascadeStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&enabled); err != nil {
		t.Fatalf("decode enable: %v", err)
	}
	if len(enabled.Children) != 2 {
		t.Fatalf("enable children = %d, want 2", len(enabled.Children))
	}
	for _, child := range enabled.Children {
		waitOperation(t, env, child.OperationID, operations.StatusSuccess, 60*time.Second)
	}
	for _, id := range []string{idA, idB} {
		if !targetRoleCanLogin(ctx, t, targetDSN, id) {
			t.Errorf("role %s cannot login after cascade enable", id)
		}
	}

	// Привязанный unmanaged-аккаунт (admin-учётка из discovery) offboard
	// трогать не должен.
	adminAcct := findAccount(t, env.pool, connOut.ID, cc.User)
	if adminAcct.Ownership != inventory.OwnershipUnmanaged {
		t.Fatalf("admin account ownership = %q, want unmanaged", adminAcct.Ownership)
	}
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+adminAcct.ID.String()+"/link",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusOK)

	// 2. Offboard: revoke + rotate children исполняются worker. Роли
	// ОСТАЮТСЯ в целевом PG (offboard обратим), но membership снимается, а
	// оба пароля — общий секрет принципала (аккаунт A) и личный кред
	// аккаунта B — меняются на новые. Проверяется главное свойство: старым
	// паролем в целевую БД больше не войти, а новым — можно.
	sharedPath := "principals/" + principal.ID.String() + "/environments/offb/credential"
	ownPathB := "accounts/" + acctBOut.AccountID.String() + "/credential"
	oldSharedPassword, sharedVersionBefore := targetSecretPassword(ctx, t, vaultClient, sharedPath)
	oldOwnPassword, ownVersionBefore := targetSecretPassword(ctx, t, vaultClient, ownPathB)
	if !targetCanAuthenticate(ctx, t, cc, idA, oldSharedPassword) {
		t.Fatalf("account A cannot authenticate before offboard")
	}
	if !targetCanAuthenticate(ctx, t, cc, idB, oldOwnPassword) {
		t.Fatalf("account B cannot authenticate before offboard")
	}

	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/offboard?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var offb offboardResponse
	if err := json.NewDecoder(resp.Body).Decode(&offb); err != nil {
		t.Fatalf("decode offboard: %v", err)
	}
	// A: 1 revoke + 1 rotate общего секрета; B: 1 rotate личного пароля.
	if len(offb.Children) != 3 {
		t.Fatalf("offboard children = %d, want 3: %+v", len(offb.Children), offb.Children)
	}
	for _, child := range offb.Children {
		waitOperation(t, env, child.OperationID, operations.StatusSuccess, 90*time.Second)
	}
	if len(offb.UnmanagedAccounts) != 1 || offb.UnmanagedAccounts[0].EngineIdentity != cc.User {
		t.Errorf("unmanaged_accounts = %+v, want [%s]", offb.UnmanagedAccounts, cc.User)
	}
	// Оба пароля grantor принадлежат ему самому, поэтому принимать нечего.
	if len(offb.CredentialTakeoverRequired) != 0 {
		t.Errorf("credential_takeover_required = %+v, want empty", offb.CredentialTakeoverRequired)
	}

	for _, id := range []string{idA, idB} {
		if !targetRoleExists(ctx, t, targetDSN, id) {
			t.Errorf("role %s dropped by offboard (must stay: offboard is reversible)", id)
		}
	}
	if targetHasMembership(ctx, t, targetDSN, groupRole, idA) {
		t.Errorf("membership %s -> %s survived offboard", idA, groupRole)
	}
	if !targetRoleExists(ctx, t, targetDSN, cc.User) {
		t.Errorf("unmanaged admin role %s disappeared from target", cc.User)
	}

	// Пароли: новые версии в Vault и реальная смена на target. Старый пароль
	// обязан быть отвергнут — иначе отзыв прав закрыл бы двери, оставив
	// открытым окно.
	newSharedPassword, sharedVersionAfter := targetSecretPassword(ctx, t, vaultClient, sharedPath)
	newOwnPassword, ownVersionAfter := targetSecretPassword(ctx, t, vaultClient, ownPathB)
	if sharedVersionAfter <= sharedVersionBefore {
		t.Errorf("shared secret version = %d, want greater than %d", sharedVersionAfter, sharedVersionBefore)
	}
	if ownVersionAfter <= ownVersionBefore {
		t.Errorf("own credential version = %d, want greater than %d", ownVersionAfter, ownVersionBefore)
	}
	if targetCanAuthenticate(ctx, t, cc, idA, oldSharedPassword) {
		t.Error("account A still authenticates with the pre-offboard password")
	}
	if targetCanAuthenticate(ctx, t, cc, idB, oldOwnPassword) {
		t.Error("account B still authenticates with the pre-offboard password")
	}
	if !targetCanAuthenticate(ctx, t, cc, idA, newSharedPassword) {
		t.Error("account A does not authenticate with the rotated password")
	}
	if !targetCanAuthenticate(ctx, t, cc, idB, newOwnPassword) {
		t.Error("account B does not authenticate with the rotated password")
	}

	stored, err := principals.NewStore().Get(ctx, env.pool, principal.ID)
	if err != nil {
		t.Fatalf("get principal: %v", err)
	}
	if stored.Status != principals.StatusPendingPurge {
		t.Errorf("principal status = %q, want pending_purge", stored.Status)
	}
	if stored.PurgeAfter == nil {
		t.Error("principal has no purge_after deadline")
	}
	adminAfter, err := inventory.NewStore().GetAccount(ctx, env.pool, adminAcct.ID)
	if err != nil {
		t.Fatalf("get admin account: %v", err)
	}
	if adminAfter.Ownership != inventory.OwnershipUnmanaged || adminAfter.Status == inventory.AccountDeleted {
		t.Errorf("unmanaged account changed by offboard: ownership=%q status=%q", adminAfter.Ownership, adminAfter.Status)
	}
	// Аккаунты остаются живыми: удаляет их только истечение срока хранения.
	for _, id := range []uuid.UUID{access.Children[0].AccountID, acctBOut.AccountID} {
		acct, err := inventory.NewStore().GetAccount(ctx, env.pool, id)
		if err != nil {
			t.Fatalf("get account %s: %v", id, err)
		}
		if acct.Status != inventory.AccountActive {
			t.Errorf("account %s status = %q, want active (offboard deletes nothing)", id, acct.Status)
		}
	}
	events, err := audit.NewWriter().List(ctx, env.pool, audit.Filter{Actions: []string{"principal.offboarded"}}, 100, 0)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	found := false
	for _, ev := range events {
		if ev.PrincipalID != nil && *ev.PrincipalID == principal.ID {
			found = true
		}
	}
	if !found {
		t.Error("principal.offboarded audit event not found")
	}
}
