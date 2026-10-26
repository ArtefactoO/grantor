//go:build integration

package operations_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// TestStoreListPageUsesCallerSnapshot доказывает контракт, на который
// опирается API: если ListPage получает read-only REPEATABLE READ tx, count и
// rows видят один snapshot даже при завершившейся конкурентной вставке.
func TestStoreListPageUsesCallerSnapshot(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	kind := "itest.list-snapshot-" + uuid.NewString()

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `delete from operations where kind = $1`, kind); err != nil {
			t.Errorf("cleanup operations: %v", err)
		}
	})

	insert := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `
			insert into operations (kind, status, actor_type, actor_id)
			values ($1, 'success', 'test', $2)`, kind, t.Name()); err != nil {
			t.Fatalf("insert operation: %v", err)
		}
	}
	insert()

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatalf("begin repeatable-read tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Первый SELECT фиксирует snapshot с одной строкой.
	var snapshotRows int
	if err := tx.QueryRow(ctx, `select count(*) from operations where kind = $1`, kind).Scan(&snapshotRows); err != nil {
		t.Fatalf("establish snapshot: %v", err)
	}
	if snapshotRows != 1 {
		t.Fatalf("initial snapshot rows = %d, want 1", snapshotRows)
	}

	// Вставка вне tx успешно коммитится, но не должна попасть ни в total, ни
	// в rows ListPage внутри уже зафиксированного snapshot.
	insert()
	ops, total, err := store.ListPage(ctx, tx, operations.Filter{
		Kinds: []string{kind},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListPage in snapshot: %v", err)
	}
	if total != 1 || len(ops) != 1 {
		t.Fatalf("snapshot page = total %d, rows %d; want total 1, rows 1", total, len(ops))
	}
	totals, err := store.CountStatusTotals(ctx, tx, operations.Filter{
		Statuses: []operations.Status{operations.StatusPending},
		Kinds:    []string{kind},
	})
	if err != nil {
		t.Fatalf("CountStatusTotals in snapshot: %v", err)
	}
	if totals.Active != 0 || totals.Errors != 0 || totals.All != 1 {
		t.Fatalf("snapshot status totals = %+v, want active=0 errors=0 all=1", totals)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit repeatable-read tx: %v", err)
	}

	// Новый snapshot уже видит обе строки.
	ops, total, err = store.ListPage(ctx, pool, operations.Filter{
		Kinds: []string{kind},
		Limit: 10,
	})
	if err != nil {
		t.Fatalf("ListPage fresh snapshot: %v", err)
	}
	if total != 2 || len(ops) != 2 {
		t.Fatalf("fresh page = total %d, rows %d; want total 2, rows 2", total, len(ops))
	}
}
