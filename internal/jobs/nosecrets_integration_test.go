//go:build integration

package jobs_test

// Автоматическая проверка инварианта «секреты не попадают в metadata
// database, operation payload/plan/result и audit» (docs/threat-model.md,
// разделы 1.2 и 5; чеклист раздела 6, P2). Тест прогоняет представительный
// мутирующий lifecycle через fake adapter поверх реальных metadata
// PostgreSQL и Vault, подставляя отличительные canary-значения вместо всех
// секретов (admin credential подключения, initial credential аккаунта,
// общий секрет принципала), а затем сканирует ВСЕ текстовые/json/jsonb
// колонки всех таблиц metadata-базы: canary не должен встретиться нигде.
// Сканирование по information_schema, а не по фиксированному списку таблиц,
// чтобы новые таблицы/колонки попадали под проверку автоматически.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// registerFakeOnce защищает от повторной регистрации fake adapter:
// registry пакета adapter живёт на весь процесс.
var registerFakeOnce sync.Once

// sweepQuerier — общий контракт pgxpool.Pool и pgx.Tx, достаточный для
// сканирования: позитивный self-test выполняет sweep внутри откатываемой
// транзакции.
type sweepQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// textishColumn — колонка metadata-базы, способная хранить текст.
type textishColumn struct {
	Table    string
	Column   string
	DataType string
}

// canaryHit — найденное вхождение canary.
type canaryHit struct {
	Table  string
	Column string
	Rows   int
}

// listTextishColumns перечисляет все колонки base-таблиц схемы public,
// в которых может оказаться текст (включая json/jsonb, массивы, enum и
// bytea). Динамическое перечисление делает проверку future-proof: новая
// таблица или колонка автоматически попадает в скан.
func listTextishColumns(ctx context.Context, q sweepQuerier) ([]textishColumn, error) {
	rows, err := q.Query(ctx, `
		select c.table_name, c.column_name, c.data_type
		from information_schema.columns c
		join information_schema.tables t
		  on t.table_schema = c.table_schema and t.table_name = c.table_name
		where c.table_schema = 'public'
		  and t.table_type = 'BASE TABLE'
		  and c.data_type in ('text', 'character varying', 'character',
		                      'json', 'jsonb', 'ARRAY', 'USER-DEFINED', 'bytea')
		order by c.table_name, c.column_name`)
	if err != nil {
		return nil, fmt.Errorf("list textish columns: %w", err)
	}
	defer rows.Close()

	var cols []textishColumn
	for rows.Next() {
		var c textishColumn
		if err := rows.Scan(&c.Table, &c.Column, &c.DataType); err != nil {
			return nil, fmt.Errorf("scan textish column: %w", err)
		}
		cols = append(cols, c)
	}
	return cols, rows.Err()
}

// sweepForCanary ищет подстроку canary во всех перечисленных колонках и
// возвращает найденные вхождения. Идентификаторы экранируются
// pgx.Identifier: сами имена приходят из information_schema, но правило
// «никогда не собирать SQL конкатенацией сырых имён» здесь то же, что и в
// adapters.
func sweepForCanary(ctx context.Context, q sweepQuerier, cols []textishColumn, canary string) ([]canaryHit, error) {
	var hits []canaryHit
	for _, c := range cols {
		table := pgx.Identifier{c.Table}.Sanitize()
		column := pgx.Identifier{c.Column}.Sanitize()
		var (
			query string
			arg   any
		)
		if c.DataType == "bytea" {
			query = fmt.Sprintf(`select count(*) from %s where position($1::bytea in %s) > 0`, table, column)
			arg = []byte(canary)
		} else {
			query = fmt.Sprintf(`select count(*) from %s where strpos(cast(%s as text), $1) > 0`, table, column)
			arg = canary
		}
		var n int
		if err := q.QueryRow(ctx, query, arg).Scan(&n); err != nil {
			return nil, fmt.Errorf("sweep %s.%s: %w", c.Table, c.Column, err)
		}
		if n > 0 {
			hits = append(hits, canaryHit{Table: c.Table, Column: c.Column, Rows: n})
		}
	}
	return hits, nil
}

// TestIntegrationNoSecretsInMetadataDB — сквозной lifecycle с canary вместо
// секретов и полный скан metadata-базы: canary не должен оказаться ни в
// operations.payload/plan/result/error, ни в audit_events.metadata, ни в
// любой другой текстовой колонке любой таблицы.
func TestIntegrationNoSecretsInMetadataDB(t *testing.T) {
	vaultClient := newTestVaultClient(t)
	ctx := context.Background()
	pool := pgtest.Pool(t)

	registerFakeOnce.Do(func() {
		adapter.Register(fake.Engine, func() adapter.Adapter { return fake.New() })
	})

	// Canary: уникальный маркер прогона + суффикс роли секрета. Скан ищет
	// общий префикс, поэтому ловит любой из трёх секретов.
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		t.Fatalf("generate canary seed: %v", err)
	}
	canary := "SECRET-CANARY-" + hex.EncodeToString(seed[:])
	adminCanary := canary + "-admin"
	initialCanary := canary + "-initial"
	sharedCanary := canary + "-shared"

	// Позитивный self-test механизма сканирования: подложенный в текстовую
	// колонку canary обязан находиться. Транзакция откатывается — база
	// остаётся чистой.
	selfTestSweep(ctx, t, pool, canary)

	// Admin credential подключения — в реальном Vault, пароль-canary.
	adminPath := fmt.Sprintf("itest/nosecrets/%s/admin", uuid.NewString())
	if _, err := vaultClient.Put(ctx, adminPath, map[string]any{
		"username": "fake-admin",
		"password": adminCanary,
	}); err != nil {
		t.Fatalf("put admin credential: %v", err)
	}

	connStore := connections.NewStore()
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-nosecrets-" + uuid.NewString(),
		Engine:              fake.Engine,
		Endpoints:           []string{"fake-target:1"},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      adminPath,
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

	// --- Discovery фикстуры fake adapter (svc-a, readers, роли app-*). ---
	discoverOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, discoverOp.ID, operations.StatusSuccess, 60*time.Second)

	svc := mutAccount(t, pool, invStore, conn.ID, "svc-a")
	readonly := mutPermission(t, pool, invStore, conn.ID, "role:app-readonly")
	superuser := mutPermission(t, pool, invStore, conn.ID, "role:superuser")
	if !superuser.Dangerous {
		t.Fatalf("permission %q is not dangerous; fake fixture assumption broken", superuser.ExternalID)
	}

	// --- Grant: успешная мутация с plan/result в operations. ---
	binding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    svc.ID,
		PermissionID: readonly.ID,
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
	grantDone := waitForStatus(t, pool, opStore, grantOp.ID, operations.StatusSuccess, 60*time.Second)
	// Контроль представительности: скан бессмыслен, если plan/result пусты.
	if len(grantDone.Plan) == 0 || len(grantDone.Result) == 0 {
		t.Fatalf("grant operation plan/result are empty: plan=%d result=%d bytes", len(grantDone.Plan), len(grantDone.Result))
	}

	// --- Failure-путь: dangerous grant без подтверждения пишет ошибку в
	// operations.error и audit-событие *_failed. ---
	dangerousBinding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    svc.ID,
		PermissionID: superuser.ID,
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
	waitForStatus(t, pool, opStore, dangerousOp.ID, operations.StatusFailed, 60*time.Second)

	// --- Revoke: обратная мутация. ---
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

	// --- Account create: initial credential-canary проходит через Vault ->
	// executor -> adapter. ---
	identity := "nosec" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: identity,
		CredentialMode: "generated",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	if _, path, err := credSvc.PutAccountCredential(ctx, acct.ID, identity, []byte(initialCanary)); err != nil {
		t.Fatalf("put account credential: %v", err)
	} else if err := invStore.SetAccountVaultPath(ctx, pool, acct.ID, path); err != nil {
		t.Fatalf("set account vault path: %v", err)
	}
	createOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountCreate,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       accountPayload(t, acct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, createOp.ID, operations.StatusSuccess, 60*time.Second)

	// --- Credential rotate по shared-пути принципала: canary читается из
	// Vault и применяется adapter-ом. Ротируется svc-a из фикстуры fake
	// (каждый adapter.New даёт свежую фикстуру, где создан только svc-a);
	// для этого discovered-аккаунт помечается managed напрямую в metadata.
	sharedPath := fmt.Sprintf("itest/nosecrets/%s/shared", uuid.NewString())
	if _, err := vaultClient.Put(ctx, sharedPath, map[string]any{
		"username": svc.EngineIdentity,
		"password": sharedCanary,
	}); err != nil {
		t.Fatalf("put shared credential: %v", err)
	}
	if _, err := pool.Exec(ctx, `update accounts set ownership = 'managed' where id = $1`, svc.ID); err != nil {
		t.Fatalf("mark account managed: %v", err)
	}
	rotatePayload, err := json.Marshal(jobs.AccountPayload{AccountID: svc.ID, SharedCredentialPath: sharedPath})
	if err != nil {
		t.Fatalf("marshal rotate payload: %v", err)
	}
	rotateOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindCredentialRotate,
		ConnectionID:  &conn.ID,
		AccountID:     &svc.ID,
		Payload:       rotatePayload,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, rotateOp.ID, operations.StatusSuccess, 60*time.Second)

	// --- Account delete: завершение lifecycle. ---
	deleteOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountDelete,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       accountPayload(t, acct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, deleteOp.ID, operations.StatusSuccess, 60*time.Second)

	// Позитивный контроль: canary реально прошли через контур и лежат в
	// Vault (единственном месте, где секретам разрешено находиться).
	assertVaultPassword(ctx, t, vaultClient, adminPath, adminCanary)
	assertVaultPassword(ctx, t, vaultClient, sharedPath, sharedCanary)

	// --- Сам скан: canary не должен встретиться ни в одной текстовой
	// колонке ни одной таблицы metadata-базы. ---
	cols, err := listTextishColumns(ctx, pool)
	if err != nil {
		t.Fatalf("list textish columns: %v", err)
	}
	if len(cols) == 0 {
		t.Fatal("no textish columns found in metadata database; sweep is vacuous")
	}
	hits, err := sweepForCanary(ctx, pool, cols, canary)
	if err != nil {
		t.Fatalf("sweep metadata database: %v", err)
	}
	for _, h := range hits {
		t.Errorf("secret canary %q leaked into metadata database: %s.%s (%d rows) — secrets must live only in Vault",
			canary, h.Table, h.Column, h.Rows)
	}
	t.Logf("no-secrets sweep: %d columns scanned, %d canary hits", len(cols), len(hits))
}

// selfTestSweep проверяет сам механизм сканирования: подложенный canary
// обязан находиться. Всё выполняется в откатываемой транзакции.
func selfTestSweep(ctx context.Context, t *testing.T, pool *pgxpool.Pool, canary string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("sweep self-test: begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx,
		`insert into principals (type, display_name) values ('service', $1)`,
		"sweep-self-test-"+canary,
	); err != nil {
		t.Fatalf("sweep self-test: insert planted canary: %v", err)
	}
	cols, err := listTextishColumns(ctx, tx)
	if err != nil {
		t.Fatalf("sweep self-test: list columns: %v", err)
	}
	hits, err := sweepForCanary(ctx, tx, cols, canary)
	if err != nil {
		t.Fatalf("sweep self-test: sweep: %v", err)
	}
	found := false
	for _, h := range hits {
		if h.Table == "principals" && h.Column == "display_name" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sweep self-test: planted canary in principals.display_name was not detected (hits: %+v)", hits)
	}
}

// assertVaultPassword проверяет, что по пути Vault лежит ожидаемый пароль
// (позитивный контроль прохождения canary через контур).
func assertVaultPassword(ctx context.Context, t *testing.T, c *vault.Client, path, want string) {
	t.Helper()
	data, _, err := c.Get(ctx, path)
	if err != nil {
		t.Fatalf("vault get %s: %v", path, err)
	}
	if got, _ := data["password"].(string); got != want {
		t.Fatalf("vault %s password does not match canary; lifecycle did not exercise the secret", path)
	}
}
