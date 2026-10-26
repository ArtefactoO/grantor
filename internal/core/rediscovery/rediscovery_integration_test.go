//go:build integration

package rediscovery

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// newConnWithSnapshot создаёт подключение и переводит его прямым SQL в
// нужный статус с нужным возрастом снимка (last_discovery_at = now-age;
// age < 0 оставляет снимок NULL). Прямой SQL вместо цепочки Transition:
// тест наполняет состояние, а не проверяет state machine.
func newConnWithSnapshot(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	status connections.Status, age time.Duration) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-rediscovery-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	var lastDiscoveryAt *time.Time
	if age >= 0 {
		ts := time.Now().Add(-age)
		lastDiscoveryAt = &ts
	}
	if _, err := pool.Exec(ctx,
		`update connections set status = $2, last_discovery_at = $3 where id = $1`,
		conn.ID, status, lastDiscoveryAt,
	); err != nil {
		t.Fatalf("prime connection %s: %v", conn.ID, err)
	}
	return conn
}

// discoverOperations возвращает id операций connection.discover данного
// connection.
func discoverOperations(ctx context.Context, t *testing.T, pool *pgxpool.Pool, connectionID uuid.UUID) []uuid.UUID {
	t.Helper()
	rows, err := pool.Query(ctx,
		`select id from operations where connection_id = $1 and kind = $2 order by created_at`,
		connectionID, jobs.KindConnectionDiscover,
	)
	if err != nil {
		t.Fatalf("select operations for %s: %v", connectionID, err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatalf("scan operation id: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("select operations for %s: %v", connectionID, err)
	}
	return ids
}

func TestRunOnceRequestsDiscoveryForStaleConnections(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)

	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatalf("jobs.NewInsertOnly: %v", err)
	}

	interval := time.Hour
	// Кандидаты: active/degraded со старым снимком и active без снимка.
	staleActive := newConnWithSnapshot(ctx, t, pool, connections.StatusActive, 2*time.Hour)
	staleDegraded := newConnWithSnapshot(ctx, t, pool, connections.StatusDegraded, 2*time.Hour)
	neverDiscovered := newConnWithSnapshot(ctx, t, pool, connections.StatusActive, -1)
	// Не кандидаты: свежий снимок и статусы, где discovery не ставится.
	freshActive := newConnWithSnapshot(ctx, t, pool, connections.StatusActive, time.Minute)
	staleDisabled := newConnWithSnapshot(ctx, t, pool, connections.StatusDisabled, 2*time.Hour)
	staleDraft := newConnWithSnapshot(ctx, t, pool, connections.StatusDraft, 2*time.Hour)

	runner := New(pool, Config{Interval: interval}, dispatcher).WithAudit(audit.NewWriter())
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// RunOnce работает глобально по базе, поэтому счётчик — «не меньше»;
	// точная корректность — по операциям конкретных connections ниже.
	if stats.DiscoveriesRequested < 3 {
		t.Errorf("DiscoveriesRequested = %d, want >= 3", stats.DiscoveriesRequested)
	}

	for _, tc := range []struct {
		name string
		conn connections.Connection
		want int
	}{
		{"stale active", staleActive, 1},
		{"stale degraded", staleDegraded, 1},
		{"never discovered active", neverDiscovered, 1},
		{"fresh active", freshActive, 0},
		{"stale disabled", staleDisabled, 0},
		{"stale draft", staleDraft, 0},
	} {
		ops := discoverOperations(ctx, t, pool, tc.conn.ID)
		if len(ops) != tc.want {
			t.Errorf("%s: discover operations = %d, want %d", tc.name, len(ops), tc.want)
		}
	}

	// Операция создана от сервисного актора и enqueue-нута в River.
	ops := discoverOperations(ctx, t, pool, staleActive.ID)
	if len(ops) == 1 {
		var actorType, actorID string
		if err := pool.QueryRow(ctx,
			`select actor_type, actor_id from operations where id = $1`, ops[0],
		).Scan(&actorType, &actorID); err != nil {
			t.Fatalf("read operation actor: %v", err)
		}
		if actorType != "service" || actorID != "grantor-rediscovery" {
			t.Errorf("operation actor = %s/%s, want service/grantor-rediscovery", actorType, actorID)
		}
		var jobCount int
		if err := pool.QueryRow(ctx,
			`select count(*) from river_job where args->>'operation_id' = $1`, ops[0].String(),
		).Scan(&jobCount); err != nil {
			t.Fatalf("count river jobs: %v", err)
		}
		if jobCount != 1 {
			t.Errorf("river jobs for operation = %d, want 1", jobCount)
		}
		// Audit: connection.autodiscovery_requested с причиной stale_snapshot.
		var auditCount int
		if err := pool.QueryRow(ctx, `
			select count(*) from audit_events
			where action = 'connection.autodiscovery_requested'
			  and connection_id = $1
			  and operation_id = $2
			  and metadata->>'reason' = 'stale_snapshot'`,
			staleActive.ID, ops[0],
		).Scan(&auditCount); err != nil {
			t.Fatalf("count audit events: %v", err)
		}
		if auditCount != 1 {
			t.Errorf("autodiscovery_requested audit events = %d, want 1", auditCount)
		}
	}

	// Повторный прогон: у stale-connections уже висит pending discovery —
	// новые операции не ставятся.
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("second RunOnce: %v", err)
	}
	if ops := discoverOperations(ctx, t, pool, staleActive.ID); len(ops) != 1 {
		t.Errorf("after second run: discover operations = %d, want 1 (pending operation must suppress a new one)", len(ops))
	}
}

func TestRunOnceSkipsWhenLockHeld(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)

	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatalf("jobs.NewInsertOnly: %v", err)
	}
	stale := newConnWithSnapshot(ctx, t, pool, connections.StatusActive, 2*time.Hour)

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
		rediscoveryLockClass, rediscoveryLockObj).Scan(&acquired); err != nil {
		t.Fatalf("holder acquire lock: %v", err)
	}
	if !acquired {
		t.Fatal("holder could not acquire singleton lock")
	}

	runner := New(pool, Config{Interval: time.Hour}, dispatcher)
	stats, err := runner.RunOnce(ctx)
	if err != nil {
		t.Fatalf("RunOnce while lock held: %v", err)
	}
	if !stats.IsZero() {
		t.Errorf("RunOnce while lock held: stats = %+v, want zero (no-op)", stats)
	}
	if ops := discoverOperations(ctx, t, pool, stale.ID); len(ops) != 0 {
		t.Errorf("discover operations while lock held = %d, want 0", len(ops))
	}

	// Освобождаем lock и повторяем: теперь операция ставится.
	if err := holder.Rollback(ctx); err != nil {
		t.Fatalf("release holder lock: %v", err)
	}
	if _, err := runner.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce after lock released: %v", err)
	}
	if ops := discoverOperations(ctx, t, pool, stale.ID); len(ops) != 1 {
		t.Errorf("discover operations after lock released = %d, want 1", len(ops))
	}
}
