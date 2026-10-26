//go:build integration

package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// newConn создаёт подключение-носитель тестовых данных: все проверки
// скоупятся его id, чтобы тесты не мешали друг другу в общей базе.
// RunOnce, однако, работает глобально по всей базе — поэтому счётчики
// Stats проверяются как «не меньше ожидаемого», а точная корректность —
// по состоянию конкретных строк этого connection.
func newConn(ctx context.Context, t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-maintenance-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return conn
}

// insertResource вставляет ресурс с явными observed_at/updated_at
// (относительно now) и возвращает его id.
func insertResource(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	connectionID uuid.UUID, externalID, status, ownership string, age time.Duration) uuid.UUID {
	t.Helper()
	ts := time.Now().Add(-age)
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		insert into resources (
			connection_id, kind, external_id, name, canonical_path,
			status, ownership, observed_at, updated_at
		) values ($1, 'table', $2, $2, $2, $3, $4, $5, $5)
		returning id`,
		connectionID, externalID, status, ownership, ts,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert resource %q: %v", externalID, err)
	}
	return id
}

// insertOperation вставляет операцию с явным finished_at и возвращает id.
func insertOperation(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	kind, status string, finishedAge time.Duration) uuid.UUID {
	t.Helper()
	finishedAt := time.Now().Add(-finishedAge)
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		insert into operations (kind, status, finished_at, actor_type, actor_id)
		values ($1, $2, $3, 'test', 'maintenance-itest')
		returning id`,
		kind, status, finishedAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert operation %q/%q: %v", kind, status, err)
	}
	return id
}

// insertBinding вставляет binding с заданными desired/expires_at и
// возвращает id. observed_state='present', status='synced' — типичное
// состояние выданного гранта.
func insertBinding(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	accountID, permissionID uuid.UUID, desired string, expiresAt *time.Time) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		insert into bindings (
			account_id, permission_definition_id, source,
			desired_state, observed_state, status, expires_at
		) values ($1, $2, 'service', $3, 'present', 'synced', $4)
		returning id`,
		accountID, permissionID, desired, expiresAt,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	return id
}

// insertPermission вставляет assignable permission definition и
// возвращает id.
func insertPermission(ctx context.Context, t *testing.T, pool *pgxpool.Pool, connectionID uuid.UUID) uuid.UUID {
	t.Helper()
	external := "role:" + uuid.NewString()
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		insert into permission_definitions (connection_id, engine, external_id, name, assignable)
		values ($1, 'postgres', $2, $2, true)
		returning id`,
		connectionID, external,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert permission: %v", err)
	}
	return id
}

// resourceExists сообщает, существует ли ресурс с указанным id.
func resourceExists(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `select exists(select 1 from resources where id = $1)`, id).Scan(&exists); err != nil {
		t.Fatalf("check resource %s: %v", id, err)
	}
	return exists
}

// operationExists сообщает, существует ли операция с указанным id.
func operationExists(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) bool {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(ctx, `select exists(select 1 from operations where id = $1)`, id).Scan(&exists); err != nil {
		t.Fatalf("check operation %s: %v", id, err)
	}
	return exists
}

// bindingDesired возвращает desired_state binding как строку ("" для NULL).
func bindingDesired(ctx context.Context, t *testing.T, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var desired *string
	if err := pool.QueryRow(ctx, `select desired_state from bindings where id = $1`, id).Scan(&desired); err != nil {
		t.Fatalf("read binding %s desired: %v", id, err)
	}
	if desired == nil {
		return ""
	}
	return *desired
}

func TestRunOnceGCAndTTL(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := newConn(ctx, t, pool)

	// resources: старый missing (лист) удаляется; свежий missing и
	// managed observed остаются (retention по умолчанию 30 суток).
	oldMissing := insertResource(ctx, t, pool, conn.ID, "t:old-missing", "missing", "unmanaged", 60*24*time.Hour)
	freshMissing := insertResource(ctx, t, pool, conn.ID, "t:fresh-missing", "missing", "unmanaged", time.Hour)
	managedActive := insertResource(ctx, t, pool, conn.ID, "t:managed", "observed", "managed", 60*24*time.Hour)

	// operations: старые success/cancelled удаляются; свежий success и
	// старый failed остаются (retention по умолчанию 90 суток).
	oldSuccess := insertOperation(ctx, t, pool, "test.gc-success", "success", 100*24*time.Hour)
	oldCancelled := insertOperation(ctx, t, pool, "test.gc-cancelled", "cancelled", 100*24*time.Hour)
	freshSuccess := insertOperation(ctx, t, pool, "test.gc-fresh", "success", time.Hour)
	oldFailed := insertOperation(ctx, t, pool, "test.gc-failed", "failed", 100*24*time.Hour)

	// bindings: истёкший present → absent; будущий и бессрочный present
	// остаются; истёкший absent не считается (desired не present).
	account, err := inventory.NewStore().CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "svc-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	perm := insertPermission(ctx, t, pool, conn.ID)
	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(24 * time.Hour)
	expiredBinding := insertBinding(ctx, t, pool, account.ID, perm, "present", &past)
	futurePerm := insertPermission(ctx, t, pool, conn.ID)
	futureBinding := insertBinding(ctx, t, pool, account.ID, futurePerm, "present", &future)
	noExpiryPerm := insertPermission(ctx, t, pool, conn.ID)
	noExpiryBinding := insertBinding(ctx, t, pool, account.ID, noExpiryPerm, "present", nil)
	absentPerm := insertPermission(ctx, t, pool, conn.ID)
	absentBinding := insertBinding(ctx, t, pool, account.ID, absentPerm, "absent", &past)

	runner := New(pool, Config{}).WithAudit(audit.NewWriter())
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	// Счётчики: RunOnce работает глобально, поэтому «не меньше» ожидаемого
	// по этому connection (свежих старых данных другие тесты не создают).
	if stats.MissingResourcesDeleted < 1 {
		t.Errorf("MissingResourcesDeleted = %d, want >= 1", stats.MissingResourcesDeleted)
	}
	if stats.OperationsDeleted < 2 {
		t.Errorf("OperationsDeleted = %d, want >= 2", stats.OperationsDeleted)
	}
	if stats.BindingsExpired < 1 {
		t.Errorf("BindingsExpired = %d, want >= 1", stats.BindingsExpired)
	}

	// resources.
	if resourceExists(ctx, t, pool, oldMissing) {
		t.Error("old missing resource not deleted")
	}
	if !resourceExists(ctx, t, pool, freshMissing) {
		t.Error("fresh missing resource deleted, want kept")
	}
	if !resourceExists(ctx, t, pool, managedActive) {
		t.Error("managed observed resource deleted, want kept")
	}

	// operations.
	if operationExists(ctx, t, pool, oldSuccess) {
		t.Error("old success operation not deleted")
	}
	if operationExists(ctx, t, pool, oldCancelled) {
		t.Error("old cancelled operation not deleted")
	}
	if !operationExists(ctx, t, pool, freshSuccess) {
		t.Error("fresh success operation deleted, want kept")
	}
	if !operationExists(ctx, t, pool, oldFailed) {
		t.Error("old failed operation deleted, want kept (failed is not terminal-for-GC)")
	}

	// bindings.
	if got := bindingDesired(ctx, t, pool, expiredBinding); got != "absent" {
		t.Errorf("expired binding desired = %q, want absent", got)
	}
	if got := bindingDesired(ctx, t, pool, futureBinding); got != "present" {
		t.Errorf("future binding desired = %q, want present (untouched)", got)
	}
	if got := bindingDesired(ctx, t, pool, noExpiryBinding); got != "present" {
		t.Errorf("no-expiry binding desired = %q, want present (untouched)", got)
	}
	if got := bindingDesired(ctx, t, pool, absentBinding); got != "absent" {
		t.Errorf("already-absent expired binding desired = %q, want absent (untouched)", got)
	}

	// audit: событие binding.expired записано для истёкшего binding.
	var auditCount int
	if err := pool.QueryRow(ctx, `
		select count(*) from audit_events
		where action = 'binding.expired'
		  and account_id = $1
		  and metadata->>'reason' = 'ttl_expired'`,
		account.ID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("binding.expired audit events = %d, want 1", auditCount)
	}
}

func TestRunOnceSkipsWhenLockHeld(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := newConn(ctx, t, pool)

	old := insertResource(ctx, t, pool, conn.ID, "t:lock-old-missing", "missing", "unmanaged", 60*24*time.Hour)

	// Держим singleton advisory lock в отдельной транзакции на своём
	// соединении: RunOnce возьмёт другое соединение из пула, pg_try вернёт
	// false, прогон станет no-op.
	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder tx: %v", err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck

	var acquired bool
	if err := holder.QueryRow(ctx, `select pg_try_advisory_xact_lock($1, $2)`,
		maintenanceLockClass, maintenanceLockObj).Scan(&acquired); err != nil {
		t.Fatalf("holder acquire lock: %v", err)
	}
	if !acquired {
		t.Fatal("holder could not acquire singleton lock")
	}

	runner := New(pool, Config{})
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce while lock held: %v", err)
	}
	if !stats.IsZero() {
		t.Errorf("RunOnce while lock held: stats = %+v, want zero (no-op)", stats)
	}
	if !resourceExists(ctx, t, pool, old) {
		t.Error("old missing resource deleted while singleton lock held by peer")
	}

	// Освобождаем lock и повторяем: теперь ресурс удаляется.
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release holder lock: %v", err)
	}
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after lock released: %v", err)
	}
	if resourceExists(ctx, t, pool, old) {
		t.Error("old missing resource not deleted after singleton lock released")
	}
}
