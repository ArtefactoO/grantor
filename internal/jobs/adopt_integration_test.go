//go:build integration

// Сквозной цикл adopt существующего unmanaged-аккаунта поверх реальных
// целевого PostgreSQL и Vault: discovery находит существующие login-роли,
// операция credential.rotate с флагом adopt применяет предзаписанный
// API-слоем пароль (перезапись тем же или новым значением) и переводит
// ownership в managed; metadata-принятый аккаунт получает секрет первой
// обычной ротацией. Работоспособность пароля проверяется РЕАЛЬНЫМ логином
// в целевой PostgreSQL.
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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// adoptPayload собирает payload adopt-операции credential.rotate (режим
// password: пароль предзаписан API-слоем, executor читает его версию).
func adoptPayload(t *testing.T, accountID uuid.UUID) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccountPayload{AccountID: accountID, Adopt: true})
	if err != nil {
		t.Fatalf("marshal adopt payload: %v", err)
	}
	return raw
}

// adoptGeneratePayload собирает payload adopt-операции credential.rotate в
// режиме generate: Adopt переводит ownership, AdoptGenerate выбирает
// generate-источник — executor сам генерирует пароль (пароль API-слоем не
// предзаписан).
func adoptGeneratePayload(t *testing.T, accountID uuid.UUID) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccountPayload{AccountID: accountID, Adopt: true, AdoptGenerate: true})
	if err != nil {
		t.Fatalf("marshal adopt generate payload: %v", err)
	}
	return raw
}

// targetLogin проверяет реальный логин в целевой PostgreSQL заданной
// учёткой; возвращает ошибку подключения (nil — логин работает).
func targetLogin(ctx context.Context, t *testing.T, dsn, user, password string) error {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse target dsn: %v", err)
	}
	cfg.User = user
	cfg.Password = password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	_ = conn.Close(ctx)
	return nil
}

// requireRotatedAudit проверяет, что успех ротации аккаунта попал в audit
// и (для adopt) несёт маркер adopted.
func requireRotatedAudit(ctx context.Context, t *testing.T, pool *pgxpool.Pool, accountID uuid.UUID, wantAdopted bool) {
	t.Helper()
	events, err := audit.NewWriter().List(ctx, pool, audit.Filter{
		AccountID: &accountID,
		Actions:   []string{"credential.rotated"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no credential.rotated audit event")
	}
	var meta struct {
		Adopted bool `json:"adopted"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata %s: %v", events[0].Metadata, err)
	}
	if meta.Adopted != wantAdopted {
		t.Errorf("audit adopted marker = %v, want %v (metadata %s)", meta.Adopted, wantAdopted, events[0].Metadata)
	}
}

func TestAdoptCredentialLifecyclePostgres(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping adopt lifecycle test")
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

	// Фикстура: СУЩЕСТВУЮЩИЕ login-роли с известными паролями — то, что
	// grantor берёт под управление. Пароли только [a-z0-9-] и в SQL-литерал
	// попадают как есть.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	sameIdentity := "gr_adopt_same_" + suffix
	newIdentity := "gr_adopt_new_" + suffix
	metaIdentity := "gr_adopt_meta_" + suffix
	samePassword := "itest-adopt-same-" + suffix
	oldPassword := "itest-adopt-old-" + suffix
	newPassword := "itest-adopt-new-" + suffix
	admin := connectMutTarget(ctx, t, targetDSN)
	for identity, password := range map[string]string{
		sameIdentity: samePassword,
		newIdentity:  oldPassword,
		metaIdentity: oldPassword,
	} {
		if _, err := admin.Exec(ctx,
			fmt.Sprintf(`create role %s login password '%s'`, identity, password)); err != nil {
			t.Fatalf("create fixture role %s: %v", identity, err)
		}
	}
	_ = admin.Close(ctx)

	adminPath := fmt.Sprintf("itest/adopt/%s/admin", uuid.NewString())
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
		DisplayName:         "itest-adopt-" + uuid.NewString(),
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
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       audit.NewWriter(),
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

	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)

	// enqueueAdopt повторяет порядок API-слоя adopt mode=password: пароль
	// сначала в Vault (accounts/<id>/credential, username = engine identity),
	// затем операция credential.rotate с флагом adopt.
	enqueueAdopt := func(acct inventory.Account, password string) operations.Operation {
		t.Helper()
		if _, _, err := credSvc.PutAccountCredential(ctx, acct.ID, acct.EngineIdentity, []byte(password)); err != nil {
			t.Fatalf("put adopted credential: %v", err)
		}
		return enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindCredentialRotate,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       adoptPayload(t, acct.ID),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
	}
	// requireManagedWithCredential проверяет метаданные после успеха:
	// ownership managed, путь секрета и режим credential.
	requireManagedWithCredential := func(id uuid.UUID, wantMode string) inventory.Account {
		t.Helper()
		acct, err := invStore.GetAccount(ctx, pool, id)
		if err != nil {
			t.Fatalf("get account: %v", err)
		}
		if acct.Ownership != inventory.OwnershipManaged {
			t.Errorf("account %s ownership = %q, want managed", acct.EngineIdentity, acct.Ownership)
		}
		wantPath := "accounts/" + id.String() + "/credential"
		if acct.VaultPath != wantPath {
			t.Errorf("account %s vault_path = %q, want %q", acct.EngineIdentity, acct.VaultPath, wantPath)
		}
		if acct.CredentialMode == nil || *acct.CredentialMode != wantMode {
			t.Errorf("account %s credential_mode = %v, want %q", acct.EngineIdentity, acct.CredentialMode, wantMode)
		}
		return acct
	}

	// --- Adopt с ТЕМ ЖЕ паролем: безопасная перезапись, логин продолжает
	// работать. ---
	sameAcct := mutAccount(t, pool, invStore, conn.ID, sameIdentity)
	if sameAcct.Ownership != inventory.OwnershipUnmanaged {
		t.Fatalf("fixture account %s ownership = %q, want unmanaged", sameIdentity, sameAcct.Ownership)
	}
	sameOp := enqueueAdopt(sameAcct, samePassword)
	waitForStatus(t, pool, opStore, sameOp.ID, operations.StatusSuccess, 60*time.Second)
	requireManagedWithCredential(sameAcct.ID, "provided")
	if err := targetLogin(ctx, t, targetDSN, sameIdentity, samePassword); err != nil {
		t.Errorf("login with the same password after adopt: %v", err)
	}
	if _, version, err := vaultClient.Get(ctx, "accounts/"+sameAcct.ID.String()+"/credential"); err != nil || version != 1 {
		t.Errorf("vault version after same-password adopt = %d (err=%v), want 1", version, err)
	}
	requireRotatedAudit(ctx, t, pool, sameAcct.ID, true)

	// --- Adopt с НОВЫМ паролем: старый перестаёт работать, новый работает. ---
	newAcct := mutAccount(t, pool, invStore, conn.ID, newIdentity)
	newOp := enqueueAdopt(newAcct, newPassword)
	waitForStatus(t, pool, opStore, newOp.ID, operations.StatusSuccess, 60*time.Second)
	requireManagedWithCredential(newAcct.ID, "provided")
	if err := targetLogin(ctx, t, targetDSN, newIdentity, newPassword); err != nil {
		t.Errorf("login with the new password after adopt: %v", err)
	}
	if err := targetLogin(ctx, t, targetDSN, newIdentity, oldPassword); err == nil {
		t.Error("login with the overwritten password still works, want failure")
	}

	// --- Metadata-принятый аккаунт (ownership managed, vault_path пуст):
	// первая ОБЫЧНАЯ ротация генерирует секрет, применяет его и заполняет
	// vault_path/credential_mode. ---
	metaAcct := mutAccount(t, pool, invStore, conn.ID, metaIdentity)
	if _, err := invStore.SetAccountManaged(ctx, pool, metaAcct.ID, "", ""); err != nil {
		t.Fatalf("metadata adopt: %v", err)
	}
	rotateOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindCredentialRotate,
		ConnectionID:  &conn.ID,
		AccountID:     &metaAcct.ID,
		Payload:       accountPayload(t, metaAcct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, rotateOp.ID, operations.StatusSuccess, 60*time.Second)
	metaManaged := requireManagedWithCredential(metaAcct.ID, "generated")
	data, _, err := vaultClient.Get(ctx, metaManaged.VaultPath)
	if err != nil {
		t.Fatalf("vault get rotated credential: %v", err)
	}
	rotatedPassword, _ := data["password"].(string)
	if rotatedPassword == "" {
		t.Fatal("rotated password is empty in vault")
	}
	if err := targetLogin(ctx, t, targetDSN, metaIdentity, rotatedPassword); err != nil {
		t.Errorf("login after first rotation of metadata-adopted account: %v", err)
	}
	requireRotatedAudit(ctx, t, pool, metaAcct.ID, false)

	// --- Канарейки: заданные оператором пароли не встречаются нигде в
	// operations и audit. ---
	for _, canary := range []string{samePassword, oldPassword, newPassword} {
		var n int
		if err := pool.QueryRow(ctx, `
			select (select count(*) from operations
			         where payload::text like '%' || $1 || '%'
			            or coalesce(plan::text, '') like '%' || $1 || '%'
			            or coalesce(result::text, '') like '%' || $1 || '%'
			            or error like '%' || $1 || '%')
			     + (select count(*) from audit_events
			         where metadata::text like '%' || $1 || '%')`, canary).Scan(&n); err != nil {
			t.Fatalf("canary sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("password canary %q found in operations/audit: %d rows", canary, n)
		}
	}
}

// TestAdoptGenerateCredentialLifecyclePostgres — сквозной цикл adopt
// mode=generate поверх реальных целевого PostgreSQL и Vault: у существующей
// unmanaged login-роли (со СВОИМ исходным паролем) grantor генерирует новый
// пароль движковым генератором (adapter.GenerateCredential — engine-safe
// алфавит), пишет его в Vault, применяет к целевой системе и переводит
// ownership в managed с credential_mode=generated. Валидность
// сгенерированного пароля доказывается РЕАЛЬНЫМ логином в целевой
// PostgreSQL сохранённым из Vault значением. Отдельно проверяется, что
// сгенерированный пароль не утёк в operations/audit.
func TestAdoptGenerateCredentialLifecyclePostgres(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping adopt generate lifecycle test")
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

	// Фикстура: СУЩЕСТВУЮЩАЯ login-роль с известным исходным паролем — то, что
	// grantor берёт под управление в режиме generate.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	genIdentity := "gr_adoptgen_" + suffix
	initialPassword := "itest-adoptgen-initial-" + suffix
	admin := connectMutTarget(ctx, t, targetDSN)
	if _, err := admin.Exec(ctx,
		fmt.Sprintf(`create role %s login password '%s'`, genIdentity, initialPassword)); err != nil {
		t.Fatalf("create fixture role %s: %v", genIdentity, err)
	}
	_ = admin.Close(ctx)

	adminPath := fmt.Sprintf("itest/adoptgen/%s/admin", uuid.NewString())
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
		DisplayName:         "itest-adoptgen-" + uuid.NewString(),
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
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       audit.NewWriter(),
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

	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)

	// Discovery нашёл unmanaged login-роль.
	genAcct := mutAccount(t, pool, invStore, conn.ID, genIdentity)
	if genAcct.Ownership != inventory.OwnershipUnmanaged {
		t.Fatalf("fixture account %s ownership = %q, want unmanaged", genIdentity, genAcct.Ownership)
	}

	// adopt mode=generate: НИЧЕГО не предзаписываем в Vault — пароль
	// сгенерирует executor. Операция credential.rotate с флагами
	// adopt+adopt_generate.
	genOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindCredentialRotate,
		ConnectionID:  &conn.ID,
		AccountID:     &genAcct.ID,
		Payload:       adoptGeneratePayload(t, genAcct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, genOp.ID, operations.StatusSuccess, 60*time.Second)

	// Ownership managed, путь секрета per-account, режим generated.
	managed, err := invStore.GetAccount(ctx, pool, genAcct.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if managed.Ownership != inventory.OwnershipManaged {
		t.Errorf("account ownership = %q, want managed", managed.Ownership)
	}
	wantPath := "accounts/" + genAcct.ID.String() + "/credential"
	if managed.VaultPath != wantPath {
		t.Errorf("account vault_path = %q, want %q", managed.VaultPath, wantPath)
	}
	if managed.CredentialMode == nil || *managed.CredentialMode != "generated" {
		t.Errorf("account credential_mode = %v, want generated", managed.CredentialMode)
	}

	// В Vault лежит сгенерированный пароль; РЕАЛЬНЫЙ логин им работает —
	// доказательство, что генератор выдал приемлемый для движка пароль.
	data, version, err := vaultClient.Get(ctx, wantPath)
	if err != nil {
		t.Fatalf("vault get generated credential: %v", err)
	}
	if version != 1 {
		t.Errorf("vault version after generate-adopt = %d, want 1", version)
	}
	generatedPassword, _ := data["password"].(string)
	if generatedPassword == "" {
		t.Fatal("generated password is empty in vault")
	}
	if generatedPassword == initialPassword {
		t.Error("generated password equals the fixture initial password, want a fresh secret")
	}
	if err := targetLogin(ctx, t, targetDSN, genIdentity, generatedPassword); err != nil {
		t.Errorf("login with the generated password after adopt: %v", err)
	}
	// Исходный пароль перезаписан — им логин больше не проходит.
	if err := targetLogin(ctx, t, targetDSN, genIdentity, initialPassword); err == nil {
		t.Error("login with the overwritten initial password still works, want failure")
	}

	// Успех generate-adopt несёт маркер adopted в audit (как password-режим).
	requireRotatedAudit(ctx, t, pool, genAcct.ID, true)

	// Канарейка: сгенерированный пароль не встречается в operations и audit
	// (он течёт только Vault-write -> target-apply, как обычная ротация).
	var n int
	if err := pool.QueryRow(ctx, `
		select (select count(*) from operations
		         where payload::text like '%' || $1 || '%'
		            or coalesce(plan::text, '') like '%' || $1 || '%'
		            or coalesce(result::text, '') like '%' || $1 || '%'
		            or error like '%' || $1 || '%')
		     + (select count(*) from audit_events
		         where metadata::text like '%' || $1 || '%')`, generatedPassword).Scan(&n); err != nil {
		t.Fatalf("canary sweep: %v", err)
	}
	if n != 0 {
		t.Errorf("generated password found in operations/audit: %d rows", n)
	}
}

// TestAdoptVerifyCredentialLifecyclePostgres — сквозной цикл adopt
// mode=verify_password поверх реальных целевого PostgreSQL и Vault.
//
// Проверяется главное отличие режима от set_password: целевая система НЕ
// мутируется. Для верного пароля это доказывается РЕАЛЬНЫМ логином тем же
// самым (не новым) паролем после успеха операции; для неверного — тем, что
// исходный пароль продолжает работать, канонический путь секрета так и не
// появился, а аккаунт остался unmanaged.
func TestAdoptVerifyCredentialLifecyclePostgres(t *testing.T) {
	t.Run("direct", func(t *testing.T) { testAdoptVerifyCredentialLifecyclePostgres(t, connections.ExecutionModeDirect) })
	t.Run("connector", func(t *testing.T) { testAdoptVerifyCredentialLifecyclePostgres(t, connections.ExecutionModeConnector) })
}

func testAdoptVerifyCredentialLifecyclePostgres(t *testing.T, executionMode string) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping adopt verify lifecycle test")
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

	// Фикстура: две существующие login-роли с известными паролями. Первую
	// принимаем с ВЕРНЫМ паролем, вторую пытаемся принять с НЕВЕРНЫМ.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	okIdentity := "gr_adoptok_" + suffix
	badIdentity := "gr_adoptbad_" + suffix
	realPassword := "itest-adopt-real-" + suffix
	wrongPassword := "itest-adopt-wrong-" + suffix
	admin := connectMutTarget(ctx, t, targetDSN)
	for _, identity := range []string{okIdentity, badIdentity} {
		if _, err := admin.Exec(ctx,
			fmt.Sprintf(`create role %s login password '%s'`, identity, realPassword)); err != nil {
			t.Fatalf("create fixture role %s: %v", identity, err)
		}
	}
	_ = admin.Close(ctx)

	adminPath := fmt.Sprintf("itest/adoptverify/%s/admin", uuid.NewString())
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
		DisplayName:         "itest-adoptverify-" + uuid.NewString(),
		Engine:              postgres.Engine,
		ExecutionMode:       executionMode,
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
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       audit.NewWriter(),
		Vault:       vaultClient,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{Credentials: credSvc})
	if executionMode == connections.ExecutionModeConnector {
		executor.WithConnector(jobs.ConnectorDeps{Dispatcher: startAdoptProofConnector(t)})
	}
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

	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)

	// enqueueAdoptVerify повторяет порядок API-слоя adopt
	// mode=verify_password: проверяемый пароль — во ВРЕМЕННЫЙ adopt-proof,
	// его версия закреплена в payload операции account.adopt_verify.
	enqueueAdoptVerify := func(acct inventory.Account, password string) operations.Operation {
		t.Helper()
		version, err := credSvc.PutAccountAdoptProof(ctx, acct.ID, acct.EngineIdentity, []byte(password))
		if err != nil {
			t.Fatalf("put adopt proof: %v", err)
		}
		raw, err := json.Marshal(jobs.AccountPayload{
			AccountID: acct.ID, Adopt: true,
			ExpectedStatus: acct.Status, ExpectedLifecycleVersion: acct.LifecycleVersion,
			CredentialVaultVersion: version,
		})
		if err != nil {
			t.Fatalf("marshal adopt verify payload: %v", err)
		}
		return enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccountAdoptVerify,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       raw,
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
	}

	// --- Верный пароль: аккаунт становится managed, а пароль на целевой
	// системе НЕ меняется — тот же самый логин продолжает работать. ---
	okAcct := mutAccount(t, pool, invStore, conn.ID, okIdentity)
	if okAcct.Ownership != inventory.OwnershipUnmanaged {
		t.Fatalf("fixture account %s ownership = %q, want unmanaged", okIdentity, okAcct.Ownership)
	}
	okOp := enqueueAdoptVerify(okAcct, realPassword)
	waitForStatus(t, pool, opStore, okOp.ID, operations.StatusSuccess, 60*time.Second)

	okManaged, err := invStore.GetAccount(ctx, pool, okAcct.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	wantPath := "accounts/" + okAcct.ID.String() + "/credential"
	if okManaged.Ownership != inventory.OwnershipManaged || okManaged.VaultPath != wantPath {
		t.Errorf("account after verification = %q/%q, want managed with %q",
			okManaged.Ownership, okManaged.VaultPath, wantPath)
	}
	if okManaged.CredentialMode == nil || *okManaged.CredentialMode != "provided" {
		t.Errorf("credential_mode = %v, want provided", okManaged.CredentialMode)
	}
	if err := targetLogin(ctx, t, targetDSN, okIdentity, realPassword); err != nil {
		t.Errorf("login with the SAME password after verification adopt: %v", err)
	}
	// В Vault лежит именно подтверждённое значение, и лежит по каноническому
	// пути; временный adopt-proof убран.
	data, version, err := vaultClient.Get(ctx, wantPath)
	if err != nil {
		t.Fatalf("vault get verified credential: %v", err)
	}
	if data["username"] != okIdentity || data["password"] != realPassword {
		t.Errorf("vault secret username = %v, password matches = %v",
			data["username"], data["password"] == realPassword)
	}
	if version != 1 {
		t.Errorf("vault version after verification = %d, want 1", version)
	}
	if _, _, err := vaultClient.Get(ctx, "accounts/"+okAcct.ID.String()+"/adopt-proof"); err == nil {
		t.Error("adopt proof survived a successful verification")
	}
	requireAdoptVerifiedAudit(ctx, t, pool, okAcct.ID)

	// --- Неверный пароль: операция падает терминально, а учётка на целевой
	// системе остаётся нетронутой — исходный пароль по-прежнему работает. ---
	badAcct := mutAccount(t, pool, invStore, conn.ID, badIdentity)
	badOp := enqueueAdoptVerify(badAcct, wrongPassword)
	failed := waitForStatus(t, pool, opStore, badOp.ID, operations.StatusFailed, 60*time.Second)
	if !strings.Contains(failed.Error, "password_rejected") {
		t.Errorf("failed operation error = %q, want a sanitized password_rejected code", failed.Error)
	}
	if err := targetLogin(ctx, t, targetDSN, badIdentity, realPassword); err != nil {
		t.Errorf("login with the original password after a REJECTED verification: %v", err)
	}
	if err := targetLogin(ctx, t, targetDSN, badIdentity, wrongPassword); err == nil {
		t.Error("the wrong password works on the target: verification mutated the account")
	}
	badAfter, err := invStore.GetAccount(ctx, pool, badAcct.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if badAfter.Ownership != inventory.OwnershipUnmanaged || badAfter.VaultPath != "" {
		t.Errorf("account after rejection = %q/%q, want untouched unmanaged",
			badAfter.Ownership, badAfter.VaultPath)
	}
	// Ни «неактивированной» версии по каноническому пути, ни оставшегося
	// proof-секрета отказ не оставляет.
	if _, _, err := vaultClient.Get(ctx, "accounts/"+badAcct.ID.String()+"/credential"); err == nil {
		t.Error("rejected verification left a credential version at the canonical path")
	}
	if _, _, err := vaultClient.Get(ctx, "accounts/"+badAcct.ID.String()+"/adopt-proof"); err == nil {
		t.Error("rejected verification left the unproved password in vault")
	}

	// --- Канарейки: ни подтверждённый, ни отвергнутый пароль не попадают в
	// operations и audit. ---
	for _, canary := range []string{realPassword, wrongPassword} {
		var n int
		if err := pool.QueryRow(ctx, `
			select (select count(*) from operations
			         where payload::text like '%' || $1 || '%'
			            or coalesce(plan::text, '') like '%' || $1 || '%'
			            or coalesce(result::text, '') like '%' || $1 || '%'
			            or error like '%' || $1 || '%')
			     + (select count(*) from audit_events
			         where metadata::text like '%' || $1 || '%')`, canary).Scan(&n); err != nil {
			t.Fatalf("canary sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("password canary %q found in operations/audit: %d rows", canary, n)
		}
	}
}

// requireAdoptVerifiedAudit проверяет, что успех подтверждения попал в audit
// событием account.adopted с маркером доказанного пароля.
func requireAdoptVerifiedAudit(ctx context.Context, t *testing.T, pool *pgxpool.Pool, accountID uuid.UUID) {
	t.Helper()
	events, err := audit.NewWriter().List(ctx, pool, audit.Filter{
		AccountID: &accountID,
		Actions:   []string{"account.adopted"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no account.adopted audit event")
	}
	var meta struct {
		Mode             string `json:"mode"`
		CredentialProved bool   `json:"credential_proved"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata %s: %v", events[0].Metadata, err)
	}
	if meta.Mode != "verify_password" || !meta.CredentialProved {
		t.Errorf("audit metadata %s, want mode=verify_password with credential_proved", events[0].Metadata)
	}
}
