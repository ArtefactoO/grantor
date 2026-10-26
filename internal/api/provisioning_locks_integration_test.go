//go:build integration

package api

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/locks"
)

// Real transaction locks prove the cross-engine exclusion contract used by
// bulk grants, manifests and rotations, independent of item order. A blocked
// first connection must not leave a later connection locked by that request.
func TestIntegrationProvisioningLocksSerializeOppositeMixedEngineRequests(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_DB_DSN is required")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, engines := range [][]string{{"redis", "postgres", "redis"}, {"postgres", "redis", "postgres"}} {
		t.Run(strings.Join(engines, "-"), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
			slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
			items := make([]connections.Connection, len(ids))
			for i, id := range ids {
				items[i] = connections.Connection{ID: id, Engine: engines[i]}
			}
			blocker, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background()) //nolint:errcheck
			if err = locks.AcquireTx(ctx, blocker, ids[0]); err != nil {
				t.Fatal(err)
			}
			type lockResult struct {
				index int
				err   error
			}
			results := make(chan lockResult, 2)
			releases := []chan struct{}{make(chan struct{}), make(chan struct{})}
			pids := make([]uint32, 2)
			for i := range 2 {
				tx, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				pids[i] = tx.Conn().PgConn().PID()
				order := slices.Clone(items)
				if i == 1 {
					slices.Reverse(order)
				}
				go func(index int) {
					defer tx.Rollback(context.Background()) //nolint:errcheck
					err := lockProvisioningConnections(ctx, tx, order)
					results <- lockResult{index: index, err: err}
					if err == nil {
						select {
						case <-releases[index]:
						case <-ctx.Done():
						}
					}
				}(i)
			}
			// Both requests must wait on the same first lock, rather than one taking
			// PostgreSQL first and another taking Redis first.
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(10 * time.Millisecond)
			defer tick.Stop()
		waitBlocked:
			for {
				select {
				case got := <-results:
					t.Fatalf("request %d bypassed first mixed-engine lock: %v", got.index, got.err)
				case <-deadline.C:
					t.Fatal("opposite requests did not reach the common first lock")
				case <-tick.C:
					var blocked int
					if err = pool.QueryRow(ctx, `select count(*) from pg_stat_activity where pid=any($1::int[]) and wait_event='advisory'`, []int32{int32(pids[0]), int32(pids[1])}).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked == 2 {
						break waitBlocked
					}
				}
			}
			probe, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			acquired, err := locks.TryAcquireTx(ctx, probe, ids[2])
			if err != nil || !acquired {
				t.Fatalf("later connection was locked before first: %v %v", acquired, err)
			}
			if err = probe.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err = blocker.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				got := <-results
				if got.err != nil {
					t.Fatal(got.err)
				}
				probe, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range ids {
					acquired, err := locks.TryAcquireTx(ctx, probe, id)
					if err != nil || acquired {
						t.Fatalf("request %d omitted connection %s: %v %v", got.index, id, acquired, err)
					}
				}
				if err = probe.Rollback(ctx); err != nil {
					t.Fatal(err)
				}
				close(releases[got.index])
			}
		})
	}
}
