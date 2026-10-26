//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// Роли фикстуры мутационного теста в целевом PostgreSQL. Отдельный
// префикс gr_mut_, чтобы не пересекаться с фикстурой postgres adapter.
const (
	mutRoleReaders = "gr_mut_readers"
	mutRoleAdmin   = "gr_mut_admin"
	mutRoleSvc     = "gr_mut_svc"
)

// newTestVaultClient возвращает клиента реального Vault из окружения или
// пропускает тест.
func newTestVaultClient(t *testing.T) *vault.Client {
	t.Helper()
	addr := os.Getenv("GRANTOR_TEST_VAULT_ADDR")
	token := os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set GRANTOR_TEST_VAULT_ADDR and GRANTOR_TEST_VAULT_TOKEN to run mutation integration tests")
	}
	mount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	c, err := vault.New(vault.Config{Address: addr, Token: token, Mount: mount})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

// connectMutTarget открывает прямое подключение к целевому PostgreSQL.
func connectMutTarget(ctx context.Context, t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect to target postgres: %v", err)
	}
	return conn
}

// ensureMutationFixture идемпотентно создаёт роли фикстуры и сбрасывает
// membership, который выдаёт grant-сценарий.
func ensureMutationFixture(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()
	admin := connectMutTarget(ctx, t, dsn)
	defer admin.Close(ctx) //nolint:errcheck

	stmts := []string{
		`do $$ begin create role ` + mutRoleReaders + ` nologin; exception when duplicate_object then null; end $$`,
		`do $$ begin create role ` + mutRoleAdmin + ` nologin createrole; exception when duplicate_object then null; end $$`,
		`do $$ begin create role ` + mutRoleSvc + ` login password 'x'; exception when duplicate_object then null; end $$`,
		`revoke ` + mutRoleReaders + ` from ` + mutRoleSvc,
	}
	for _, stmt := range stmts {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("apply mutation fixture %q: %v", stmt, err)
		}
	}
}

// hasMembership проверяет в целевом PostgreSQL, что member входит в role.
func hasMembership(ctx context.Context, t *testing.T, dsn, role, member string) bool {
	t.Helper()
	conn := connectMutTarget(ctx, t, dsn)
	defer conn.Close(ctx) //nolint:errcheck

	var ok bool
	if err := conn.QueryRow(ctx, `
		select exists (
			select 1 from pg_auth_members m
			join pg_roles r on r.oid = m.roleid
			join pg_roles mem on mem.oid = m.member
			where r.rolname = $1 and mem.rolname = $2
		)`, role, member).Scan(&ok); err != nil {
		t.Fatalf("check membership %s in %s: %v", member, role, err)
	}
	return ok
}

// roleExists проверяет существование login-роли в целевом PostgreSQL.
func roleExists(ctx context.Context, t *testing.T, dsn, role string) bool {
	t.Helper()
	conn := connectMutTarget(ctx, t, dsn)
	defer conn.Close(ctx) //nolint:errcheck

	var ok bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1 and rolcanlogin)`, role,
	).Scan(&ok); err != nil {
		t.Fatalf("check role %s: %v", role, err)
	}
	return ok
}

// enqueueOperation создаёт операцию и ставит её в очередь одной
// транзакцией (как API).
func enqueueOperation(t *testing.T, pool *pgxpool.Pool, r *jobs.River, store *operations.Store, params operations.CreateParams) operations.Operation {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	op, _, err := store.Create(ctx, tx, params)
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	return op
}

// mutAccount находит аккаунт connection по identity.
func mutAccount(t *testing.T, pool *pgxpool.Pool, inv *inventory.Store, connID uuid.UUID, identity string) inventory.Account {
	t.Helper()
	accounts, err := inv.ListAccounts(context.Background(), pool, connID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	for _, a := range accounts {
		if a.EngineIdentity == identity {
			return a
		}
	}
	t.Fatalf("account %q not found among %d", identity, len(accounts))
	return inventory.Account{}
}

// mutPermission находит permission connection по external id.
func mutPermission(t *testing.T, pool *pgxpool.Pool, inv *inventory.Store, connID uuid.UUID, externalID string) inventory.Permission {
	t.Helper()
	perms, err := inv.ListPermissions(context.Background(), pool, connID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	for _, p := range perms {
		if p.ExternalID == externalID {
			return p
		}
	}
	t.Fatalf("permission %q not found among %d", externalID, len(perms))
	return inventory.Permission{}
}

// accessPayload собирает payload access-операции.
func accessPayload(t *testing.T, bindingID uuid.UUID, confirmed bool) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccessPayload{BindingID: bindingID, Confirmed: confirmed})
	if err != nil {
		t.Fatalf("marshal access payload: %v", err)
	}
	return raw
}

// accountPayload собирает payload account-операции.
func accountPayload(t *testing.T, accountID uuid.UUID) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccountPayload{AccountID: accountID})
	if err != nil {
		t.Fatalf("marshal account payload: %v", err)
	}
	return raw
}

// TestMutationsLifecyclePostgres — сквозной цикл этапа 1b поверх реальных
// целевого PostgreSQL и Vault: discovery -> grant (с проверкой membership
// в целевой системе) -> отказ dangerous grant без подтверждения ->
// revoke -> account.create -> credential.rotate (новая версия в Vault и
// рабочий логин) -> account.delete.
func TestMutationsLifecyclePostgres(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping mutation lifecycle test")
	}
	vaultClient := newTestVaultClient(t)
	ctx := context.Background()
	pool := pgtest.Pool(t)

	cc, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	registerPostgresOnce.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})
	ensureMutationFixture(ctx, t, targetDSN)

	// Admin credential подключения — в реальном Vault.
	adminPath := fmt.Sprintf("itest/mutations/%s/admin", uuid.NewString())
	if _, err := vaultClient.Put(ctx, adminPath, map[string]any{
		"username": cc.User,
		"password": cc.Password,
	}); err != nil {
		t.Fatalf("put admin credential: %v", err)
	}

	connStore := connections.NewStore()
	discoveryConfig, err := json.Marshal(map[string]string{"database": cc.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-mutations-" + uuid.NewString(),
		Engine:              postgres.Engine,
		Endpoints:           []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      adminPath,
		DiscoveryConfig:     discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating); err != nil {
		t.Fatalf("transition to validating: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusValidating, connections.StatusDiscovering); err != nil {
		t.Fatalf("transition to discovering: %v", err)
	}

	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	auditWriter := audit.NewWriter()
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       vaultClient,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{Credentials: credSvc})
	r, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  2,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	startRiver(t, r)

	// Discovery: инвентарь фикстуры попадает в metadata.
	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)
	conn, err = connStore.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("reload discovered connection: %v", err)
	}
	if !slices.Contains(conn.Capabilities, string(adapter.CapPostgresSuperuserDirectV1)) {
		t.Fatalf("discovery did not confirm PostgreSQL SUPERUSER direct capability: %v", conn.Capabilities)
	}

	svc := mutAccount(t, pool, invStore, conn.ID, mutRoleSvc)
	readers := mutPermission(t, pool, invStore, conn.ID, "role:"+mutRoleReaders)
	dangerous := mutPermission(t, pool, invStore, conn.ID, "role:"+mutRoleAdmin)
	if !dangerous.Dangerous {
		t.Fatalf("permission %q is not dangerous; fixture assumption broken", dangerous.ExternalID)
	}

	// --- Grant: gr_mut_svc -> gr_mut_readers. ---
	binding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    svc.ID,
		PermissionID: readers.ID,
		DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure binding: %v", err)
	}
	grantOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessGrant,
		ConnectionID:  &conn.ID,
		AccountID:     &svc.ID,
		BindingID:     &binding.ID,
		Payload:       accessPayload(t, binding.ID, false),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	done := waitForStatus(t, pool, opStore, grantOp.ID, operations.StatusSuccess, 60*time.Second)
	if len(done.Plan) == 0 || len(done.Result) == 0 {
		t.Errorf("grant operation plan/result are empty: plan=%d result=%d bytes", len(done.Plan), len(done.Result))
	}
	if !hasMembership(ctx, t, targetDSN, mutRoleReaders, mutRoleSvc) {
		t.Errorf("membership %s -> %s not found in target after grant", mutRoleSvc, mutRoleReaders)
	}
	got, err := invStore.GetBinding(ctx, pool, binding.ID)
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if got.ObservedState != inventory.BindingPresent || got.Status != inventory.BindingStatusSynced {
		t.Errorf("binding observed/status = %q/%q, want present/synced", got.ObservedState, got.Status)
	}
	events, err := auditWriter.List(ctx, pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:      []string{"access.granted"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("no access.granted audit event")
	}

	// --- Defense in depth: dangerous grant без confirmed падает. ---
	dangerousBinding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    svc.ID,
		PermissionID: dangerous.ID,
		DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure dangerous binding: %v", err)
	}
	dangerousOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessGrant,
		ConnectionID:  &conn.ID,
		AccountID:     &svc.ID,
		BindingID:     &dangerousBinding.ID,
		Payload:       accessPayload(t, dangerousBinding.ID, false),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	failed := waitForStatus(t, pool, opStore, dangerousOp.ID, operations.StatusFailed, 60*time.Second)
	if !strings.Contains(failed.Error, "confirmed") {
		t.Errorf("dangerous grant error = %q, want mention of confirmed payload", failed.Error)
	}
	if hasMembership(ctx, t, targetDSN, mutRoleAdmin, mutRoleSvc) {
		t.Errorf("dangerous membership %s -> %s appeared in target despite refusal", mutRoleSvc, mutRoleAdmin)
	}

	// --- Revoke: возврат к absent. ---
	if _, err := invStore.SetBindingDesired(ctx, pool, binding.ID, inventory.BindingAbsent); err != nil {
		t.Fatalf("set binding desired absent: %v", err)
	}
	revokeOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessRevoke,
		ConnectionID:  &conn.ID,
		AccountID:     &svc.ID,
		BindingID:     &binding.ID,
		Payload:       accessPayload(t, binding.ID, false),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, revokeOp.ID, operations.StatusSuccess, 60*time.Second)
	if hasMembership(ctx, t, targetDSN, mutRoleReaders, mutRoleSvc) {
		t.Errorf("membership %s -> %s still present in target after revoke", mutRoleSvc, mutRoleReaders)
	}
	got, err = invStore.GetBinding(ctx, pool, binding.ID)
	if err != nil {
		t.Fatalf("get binding after revoke: %v", err)
	}
	if got.ObservedState != inventory.BindingAbsent || got.Status != inventory.BindingStatusSynced {
		t.Errorf("binding observed/status = %q/%q, want absent/synced", got.ObservedState, got.Status)
	}

	// --- Account lifecycle: create -> rotate -> delete. ---
	identity := "gr_mut_m" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: identity,
		CredentialMode: "generated",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	firstVersion, path, err := credSvc.PutAccountCredential(ctx, acct.ID, identity, []byte("itest-initial-"+uuid.NewString()))
	if err != nil {
		t.Fatalf("put account credential: %v", err)
	}
	if firstVersion != 1 {
		t.Errorf("first credential version = %d, want 1", firstVersion)
	}
	if err := invStore.SetAccountVaultPath(ctx, pool, acct.ID, path); err != nil {
		t.Fatalf("set account vault path: %v", err)
	}

	createPayload, err := json.Marshal(jobs.AccountPayload{AccountID: acct.ID,
		ExpectedAdminIdentity: cc.User, ExpectedTargetIdentity: connections.TargetIdentity(conn),
		ExpectedConfigIncarnation: connections.ConfigIncarnation(conn), ExpectedCredentialIncarnation: 1})
	if err != nil {
		t.Fatal(err)
	}
	createOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindPostgresAccountCreateV2,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       createPayload,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, createOp.ID, operations.StatusSuccess, 60*time.Second)
	if !roleExists(ctx, t, targetDSN, identity) {
		t.Fatalf("login role %q not found in target after account.create", identity)
	}

	rotateOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindCredentialRotate,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       accountPayload(t, acct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, rotateOp.ID, operations.StatusSuccess, 60*time.Second)

	data, version, err := vaultClient.Get(ctx, path)
	if err != nil {
		t.Fatalf("vault get rotated credential: %v", err)
	}
	if version != firstVersion+1 {
		t.Errorf("vault version after rotate = %d, want %d", version, firstVersion+1)
	}
	rotatedPassword, _ := data["password"].(string)
	if rotatedPassword == "" {
		t.Fatal("rotated password is empty in vault")
	}
	// Новый пароль реально работает в целевой системе.
	loginCfg, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse target dsn for login check: %v", err)
	}
	loginCfg.User = identity
	loginCfg.Password = rotatedPassword
	loginConn, err := pgx.ConnectConfig(ctx, loginCfg)
	if err != nil {
		t.Fatalf("login with rotated credential: %v", err)
	}
	_ = loginConn.Close(ctx)

	const deleteReason = "itest offboarding cleanup"
	deletePayload, err := json.Marshal(jobs.AccountPayload{AccountID: acct.ID, Reason: deleteReason})
	if err != nil {
		t.Fatalf("marshal delete payload: %v", err)
	}
	deleteOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountDelete,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       deletePayload,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, deleteOp.ID, operations.StatusSuccess, 60*time.Second)
	if roleExists(ctx, t, targetDSN, identity) {
		t.Errorf("login role %q still exists in target after account.delete", identity)
	}
	// Метаданные удаление переживают: строка account остаётся со статусом
	// deleted (soft delete — см. inventory.MarkAccountDeleted), а bindings
	// аккаунта удаляются. Tombstone фиксирует кто/когда/почему удалил:
	// deleted_at/deleted_by — из операции, delete_reason — из payload.
	deletedAcct, err := invStore.GetAccount(ctx, pool, acct.ID)
	if err != nil {
		t.Fatalf("get account after delete: %v", err)
	}
	if deletedAcct.Status != "deleted" {
		t.Errorf("account status after delete = %q, want deleted", deletedAcct.Status)
	}
	if deletedAcct.DeletedAt == nil {
		t.Error("deleted_at is not set after account.delete")
	}
	if deletedAcct.DeletedBy == nil || *deletedAcct.DeletedBy != t.Name() {
		t.Errorf("deleted_by = %v, want %q", deletedAcct.DeletedBy, t.Name())
	}
	if deletedAcct.DeleteReason == nil || *deletedAcct.DeleteReason != deleteReason {
		t.Errorf("delete_reason = %v, want %q", deletedAcct.DeleteReason, deleteReason)
	}
	leftBindings, err := invStore.ListBindingsByAccount(ctx, pool, acct.ID)
	if err != nil {
		t.Fatalf("list bindings after delete: %v", err)
	}
	if len(leftBindings) != 0 {
		t.Errorf("bindings of deleted account = %d, want 0", len(leftBindings))
	}
}
