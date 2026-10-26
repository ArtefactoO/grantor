//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// sharedAccountPayload собирает payload account/credential-операции с
// путём общего секрета принципала.
func sharedAccountPayload(t *testing.T, accountID uuid.UUID, sharedPath string) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccountPayload{AccountID: accountID, SharedCredentialPath: sharedPath})
	if err != nil {
		t.Fatalf("marshal shared account payload: %v", err)
	}
	return raw
}

// loginWorks сообщает, удаётся ли залогиниться в целевой PostgreSQL под
// user/password. Успешное подключение закрывается.
func loginWorks(ctx context.Context, t *testing.T, dsn, user, password string) bool {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn for login check: %v", err)
	}
	cfg.User = user
	cfg.Password = password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return false
	}
	_ = conn.Close(ctx)
	return true
}

// TestPrincipalSharedCredentialLifecyclePostgres проверяет модель
// shared-per-principal-per-environment на реальном целевом PostgreSQL и
// Vault: два managed-аккаунта принципала в одном окружении делят один
// пароль (оба логинятся им), ротация общего секрета переводит ОБА на новый
// пароль (старый перестаёт работать), а grant роли одному из аккаунтов
// применяется в целевой системе.
func TestPrincipalSharedCredentialLifecyclePostgres(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping principal shared credential test")
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

	adminPath := fmt.Sprintf("itest/principal/%s/admin", uuid.NewString())
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
		DisplayName:         "itest-principal-" + uuid.NewString(),
		Engine:              postgres.Engine,
		Environment:         "itest",
		Endpoints:           []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      adminPath,
		DiscoveryConfig:     discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	for _, step := range []struct{ from, to connections.Status }{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
	} {
		if _, err := connStore.Transition(ctx, pool, conn.ID, step.from, step.to); err != nil {
			t.Fatalf("transition %s -> %s: %v", step.from, step.to, err)
		}
	}

	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	prStore := principals.NewStore()
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

	// Discovery приводит connection в active.
	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)

	// Принципал и общий секрет для окружения itest.
	principal, err := prStore.Create(ctx, pool, principals.CreateParams{
		Type:        principals.TypeService,
		DisplayName: "itest-principal-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	const env = "itest"
	sharedPath, created, err := credSvc.EnsurePrincipalCredential(ctx, principal.ID, env, func() ([]byte, error) {
		return credentials.GeneratePassword(credentials.DefaultPasswordLength)
	})
	if err != nil {
		t.Fatalf("ensure principal credential: %v", err)
	}
	if !created {
		t.Fatal("first EnsurePrincipalCredential created = false, want true")
	}
	// Повторный вызов переиспользует секрет (created=false, тот же путь).
	againPath, created, err := credSvc.EnsurePrincipalCredential(ctx, principal.ID, env, func() ([]byte, error) {
		return credentials.GeneratePassword(credentials.DefaultPasswordLength)
	})
	if err != nil {
		t.Fatalf("ensure principal credential (again): %v", err)
	}
	if created || againPath != sharedPath {
		t.Errorf("second ensure = (%q, created=%v), want (%q, false)", againPath, created, sharedPath)
	}

	initialPw, _, err := credSvc.GetPrincipalCredential(ctx, principal.ID, env)
	if err != nil {
		t.Fatalf("get principal credential: %v", err)
	}
	initialPassword := string(initialPw)

	// Existing discovered unmanaged login -> managed principal link. Worker
	// обязан rotate+prove target credential и только затем атомарно записать
	// principal/ownership/shared ref.
	existing := mutAccount(t, pool, invStore, conn.ID, mutRoleSvc)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := invStore.ReserveAccountLifecycle(ctx, tx, existing.ID, inventory.AccountActive)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("reserve managed link: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	managedLinkPayload, err := json.Marshal(jobs.AccountPayload{
		AccountID: existing.ID, ExpectedStatus: inventory.AccountActive,
		ExpectedLifecycleVersion: reserved.LifecycleVersion,
		SharedCredentialPath:     sharedPath, ManagedLinkPrincipalID: &principal.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	managedLinkOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind: jobs.KindCredentialRotate, ConnectionID: &conn.ID, PrincipalID: &principal.ID,
		AccountID: &existing.ID, Payload: managedLinkPayload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, managedLinkOp.ID, operations.StatusSuccess, 60*time.Second)
	linked, err := invStore.GetAccount(ctx, pool, existing.ID)
	if err != nil {
		t.Fatal(err)
	}
	if linked.Ownership != inventory.OwnershipManaged || linked.PrincipalID == nil ||
		*linked.PrincipalID != principal.ID || linked.CredentialMode == nil ||
		*linked.CredentialMode != inventory.CredentialModeExistingVaultRef || linked.VaultPath != sharedPath {
		t.Fatalf("managed link metadata not committed atomically: %+v", linked)
	}
	if !loginWorks(ctx, t, targetDSN, existing.EngineIdentity, initialPassword) {
		t.Fatal("managed-link target credential was not rotated/proved")
	}
	// Crash-window replay after metadata commit must converge without treating
	// the now-managed account as a conflict.
	replay := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind: jobs.KindCredentialRotate, ConnectionID: &conn.ID, PrincipalID: &principal.ID,
		AccountID: &existing.ID, Payload: managedLinkPayload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, replay.ID, operations.StatusSuccess, 60*time.Second)

	// Два managed-аккаунта принципала в одном подключении на общем секрете.
	identity1 := "gr_pr_a" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	identity2 := "gr_pr_b" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	var accts []inventory.Account
	for _, id := range []string{identity1, identity2} {
		acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
			ConnectionID:   conn.ID,
			EngineIdentity: id,
			PrincipalID:    &principal.ID,
			CredentialMode: "existing_vault_ref",
			VaultPath:      sharedPath,
		})
		if err != nil {
			t.Fatalf("create managed account %q: %v", id, err)
		}
		accts = append(accts, acct)
		createPayload, err := json.Marshal(pinPostgresV2AccountPayload(t, pool, conn.ID,
			jobs.AccountPayload{AccountID: acct.ID, SharedCredentialPath: sharedPath}))
		if err != nil {
			t.Fatalf("marshal PostgreSQL v2 account payload: %v", err)
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
		if !roleExists(ctx, t, targetDSN, id) {
			t.Fatalf("login role %q not created in target", id)
		}
	}

	// Оба аккаунта логинятся ОДНИМ общим паролем.
	if !loginWorks(ctx, t, targetDSN, identity1, initialPassword) {
		t.Errorf("account %q cannot log in with shared password", identity1)
	}
	if !loginWorks(ctx, t, targetDSN, identity2, initialPassword) {
		t.Errorf("account %q cannot log in with shared password", identity2)
	}
	// Имитируем локальную per-account ротацию: следующая
	// глобальная ротация этого окружения должна вернуть аккаунт
	// на общий credential вместе со вторым аккаунтом.
	localPath := "accounts/" + accts[0].ID.String() + "/credential"
	if _, err := pool.Exec(ctx, `
		update accounts set credential_mode = 'generated', vault_path = $2 where id = $1`,
		accts[0].ID, localPath); err != nil {
		t.Fatalf("mark account as locally rotated: %v", err)
	}

	// Ротация общего секрета: новая версия + применение к обоим аккаунтам.
	newPw, err := credentials.GeneratePassword(credentials.DefaultPasswordLength)
	if err != nil {
		t.Fatalf("generate rotated password: %v", err)
	}
	newPassword := string(newPw)
	if newPassword == initialPassword {
		t.Fatal("rotated password equals initial password")
	}
	version, err := credSvc.RotatePrincipalCredential(ctx, principal.ID, env, newPw)
	if err != nil {
		t.Fatalf("rotate principal credential: %v", err)
	}
	if version < 2 {
		t.Errorf("rotated version = %d, want >= 2", version)
	}
	for _, acct := range accts {
		rotateOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindCredentialRotate,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       sharedAccountPayload(t, acct.ID, sharedPath),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, rotateOp.ID, operations.StatusSuccess, 60*time.Second)
		updated, err := invStore.GetAccount(ctx, pool, acct.ID)
		if err != nil {
			t.Fatalf("get rotated account: %v", err)
		}
		if updated.CredentialMode == nil ||
			*updated.CredentialMode != inventory.CredentialModeExistingVaultRef ||
			updated.VaultPath != sharedPath {
			t.Errorf("rotated account did not converge to shared credential: %+v", updated)
		}
	}

	// Оба аккаунта логинятся НОВЫМ общим паролем; старый больше не работает.
	for _, id := range []string{identity1, identity2} {
		if !loginWorks(ctx, t, targetDSN, id, newPassword) {
			t.Errorf("account %q cannot log in with rotated shared password", id)
		}
		if loginWorks(ctx, t, targetDSN, id, initialPassword) {
			t.Errorf("account %q still logs in with old password after rotation", id)
		}
	}

	// Grant роли одному из аккаунтов применяется в целевой системе.
	readers := mutPermission(t, pool, invStore, conn.ID, "role:"+mutRoleReaders)
	binding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    accts[0].ID,
		PermissionID: readers.ID,
		DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure binding: %v", err)
	}
	grantOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessGrant,
		ConnectionID:  &conn.ID,
		AccountID:     &accts[0].ID,
		BindingID:     &binding.ID,
		Payload:       accessPayload(t, binding.ID, false),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, grantOp.ID, operations.StatusSuccess, 60*time.Second)
	if !hasMembership(ctx, t, targetDSN, mutRoleReaders, identity1) {
		t.Errorf("membership %s -> %s not found after grant", identity1, mutRoleReaders)
	}
}
