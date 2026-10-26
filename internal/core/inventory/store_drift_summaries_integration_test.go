//go:build integration

package inventory_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type countedDriftRead struct {
	inventory.Querier
	calls int
}

func (q *countedDriftRead) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	q.calls++
	return q.Querier.Query(ctx, sql, args...)
}

func legacyDriftCounters(t *testing.T, q inventory.Querier, connectionID uuid.UUID) inventory.DriftCounters {
	t.Helper()
	var counters inventory.DriftCounters
	err := q.QueryRow(t.Context(), `select
		(select count(*) from bindings b join accounts a on a.id=b.account_id
		 where a.connection_id=$1 and b.source='external' and b.desired_state is null),
		(select count(*) from bindings b join accounts a on a.id=b.account_id
		 where a.connection_id=$1 and b.status in ('drift','failed')),
		(select count(*) from resources where connection_id=$1 and status='missing' and ownership='managed'),
		(select count(*) from accounts where connection_id=$1 and ownership='managed' and status in ('missing','provisioning'))`, connectionID).
		Scan(&counters.UnmanagedBindings, &counters.DriftBindings, &counters.MissingManagedResources, &counters.MissingManagedAccounts)
	if err != nil {
		t.Fatal(err)
	}
	return counters
}

func seedDriftSummaryRows(t *testing.T, pool *pgxpool.Pool, connectionID uuid.UUID) {
	t.Helper()
	accountRows := [][]any{}
	accountIDs := []uuid.UUID{}
	for i, state := range [][2]string{{"active", "unmanaged"}, {"deleted", "unmanaged"}, {"missing", "managed"}, {"provisioning", "managed"}, {"disabled", "managed"}, {"deleted", "managed"}, {"missing", "unmanaged"}, {"provisioning", "unmanaged"}} {
		id := uuid.New()
		accountIDs = append(accountIDs, id)
		accountRows = append(accountRows, []any{id, connectionID, "login", fmt.Sprintf("drift_account_%d", i), state[0], state[1]})
	}
	if _, err := pool.CopyFrom(t.Context(), pgx.Identifier{"accounts"}, []string{"id", "connection_id", "kind", "engine_identity", "status", "ownership"}, pgx.CopyFromRows(accountRows)); err != nil {
		t.Fatal(err)
	}
	for i, state := range [][2]string{{"missing", "managed"}, {"missing", "managed"}, {"missing", "unmanaged"}, {"observed", "managed"}, {"planned", "managed"}} {
		name := fmt.Sprintf("drift_resource_%d", i)
		if _, err := pool.Exec(t.Context(), `insert into resources(connection_id,kind,external_id,name,canonical_path,status,ownership) values ($1,'database',$2,$2,$2,$3,$4)`, connectionID, name, state[0], state[1]); err != nil {
			t.Fatal(err)
		}
	}
	for i, row := range []struct {
		source   string
		desired  any
		observed string
		status   string
		account  int
	}{
		{"external", nil, "present", "observed", 0},
		{"external", nil, "absent", "failed", 0},
		{"external", nil, "unknown", "observed", 0},
		{"service", nil, "present", "drift", 0},
		{"external", "present", "present", "drift", 0},
		{"external", "absent", "present", "failed", 0},
		{"inherited", nil, "present", "observed", 0},
		{"external", nil, "present", "observed", 0},
		{"external", nil, "present", "observed", 1},
	} {
		var permissionID uuid.UUID
		name := fmt.Sprintf("role:drift_%d", i)
		if err := pool.QueryRow(t.Context(), `insert into permission_definitions(connection_id,engine,external_id,name) values($1,'postgres',$2,$2) returning id`, connectionID, name).Scan(&permissionID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `insert into bindings(account_id,permission_definition_id,source,desired_state,observed_state,status,observed_attributes) values($1,$2,$3,$4,$5,$6,'{"managed_binding_eligible":false}')`, accountIDs[row.account], permissionID, row.source, row.desired, row.observed, row.status); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDriftSummariesMatchLegacyCountsWithinRequestedScope(t *testing.T) {
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	visible := newTestConnection(t.Context(), t, pool)
	foreign := newTestConnection(t.Context(), t, pool)
	empty := newTestConnection(t.Context(), t, pool)
	seedDriftSummaryRows(t, pool, visible.ID)
	seedDriftSummaryRows(t, pool, foreign.ID)
	unknown := uuid.New()
	ids := []uuid.UUID{visible.ID, empty.ID, unknown, uuid.Nil, visible.ID}
	for range 44 {
		ids = append(ids, newTestConnection(t.Context(), t, pool).ID)
	}
	q := &countedDriftRead{Querier: pool}
	got, err := store.DriftSummaries(t.Context(), q, ids)
	if err != nil || q.calls != 1 {
		t.Fatalf("batch queries=%d err=%v", q.calls, err)
	}
	if len(got) != len(ids)-1 {
		t.Fatalf("duplicate scope inflated map: %d", len(got))
	}
	if _, leaked := got[foreign.ID]; leaked {
		t.Fatal("unrequested connection counters leaked")
	}
	for id, counters := range got {
		want := legacyDriftCounters(t, pool, id)
		if counters != want {
			t.Fatalf("connection %s: got=%+v legacy=%+v", id, counters, want)
		}
	}
	if got[visible.ID] != (inventory.DriftCounters{UnmanagedBindings: 5, DriftBindings: 4, MissingManagedResources: 2, MissingManagedAccounts: 2}) {
		t.Fatalf("mixed status semantics or joins changed: %+v", got[visible.ID])
	}
	for _, id := range []uuid.UUID{empty.ID, unknown, uuid.Nil} {
		if got[id] != (inventory.DriftCounters{}) {
			t.Fatalf("empty/unknown connection has nonzero counters: %+v", got[id])
		}
	}
	q.calls = 0
	one, err := store.DriftSummary(t.Context(), q, visible.ID)
	if err != nil || q.calls != 1 || one != got[visible.ID] {
		t.Fatalf("single wrapper = %+v queries=%d err=%v", one, q.calls, err)
	}
	q.calls = 0
	if blank, err := store.DriftSummaries(t.Context(), q, nil); err != nil || len(blank) != 0 || q.calls != 0 {
		t.Fatalf("empty scope read = %v queries=%d err=%v", blank, q.calls, err)
	}
}

func TestDriftSummariesRespectCallerSnapshotDuringConcurrentMutation(t *testing.T) {
	pool := pgtest.Pool(t)
	conn := newTestConnection(t.Context(), t, pool)
	seedDriftSummaryRows(t, pool, conn.ID)
	tx, err := pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	before := legacyDriftCounters(t, tx, conn.ID)
	committed := make(chan error, 1)
	go func() {
		write, err := pool.Begin(t.Context())
		if err != nil {
			committed <- err
			return
		}
		defer write.Rollback(t.Context()) //nolint:errcheck
		if _, err = write.Exec(t.Context(), `update bindings set desired_state='present',status='synced' where account_id in(select id from accounts where connection_id=$1)`, conn.ID); err == nil {
			_, err = write.Exec(t.Context(), `update resources set status='observed' where connection_id=$1`, conn.ID)
		}
		if err == nil {
			_, err = write.Exec(t.Context(), `update accounts set status='active' where connection_id=$1`, conn.ID)
		}
		if err == nil {
			err = write.Commit(t.Context())
		}
		committed <- err
	}()
	if err := <-committed; err != nil {
		t.Fatal(err)
	}
	q := &countedDriftRead{Querier: tx}
	batch, err := inventory.NewStore().DriftSummaries(t.Context(), q, []uuid.UUID{conn.ID})
	if err != nil || q.calls != 1 || batch[conn.ID] != before {
		t.Fatalf("caller snapshot changed: %v queries=%d err=%v", batch, q.calls, err)
	}
	after := legacyDriftCounters(t, pool, conn.ID)
	if reflect.DeepEqual(before, after) || after != (inventory.DriftCounters{}) {
		t.Fatalf("concurrent mutation did not commit all source changes: before=%+v after=%+v", before, after)
	}
	fresh, err := inventory.NewStore().DriftSummaries(t.Context(), pool, []uuid.UUID{conn.ID})
	if err != nil || fresh[conn.ID] != after {
		t.Fatalf("fresh batch = %v err=%v", fresh, err)
	}
}
