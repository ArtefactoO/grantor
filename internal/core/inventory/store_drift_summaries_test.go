package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type driftQueryFailure struct {
	calls int
	ids   []uuid.UUID
	err   error
}

func (*driftQueryFailure) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected mutation")
}
func (*driftQueryFailure) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected per-connection read")
}
func (q *driftQueryFailure) Query(_ context.Context, _ string, args ...any) (pgx.Rows, error) {
	q.calls++
	q.ids = args[0].([]uuid.UUID)
	return nil, q.err
}

func TestDriftSummariesEmptyScopeDoesNotQuery(t *testing.T) {
	q := &driftQueryFailure{}
	for _, ids := range [][]uuid.UUID{nil, {}} {
		got, err := NewStore().DriftSummaries(t.Context(), q, ids)
		if err != nil || got == nil || len(got) != 0 || q.calls != 0 {
			t.Fatalf("empty scope = %v, err=%v, queries=%d", got, err, q.calls)
		}
	}
}

func TestDriftSummariesDeduplicatesScopeAndPropagatesFailure(t *testing.T) {
	failure := errors.New("synthetic read failure")
	q := &driftQueryFailure{err: failure}
	id := uuid.New()
	got, err := NewStore().DriftSummaries(t.Context(), q, []uuid.UUID{id, id, uuid.Nil, uuid.Nil})
	if !errors.Is(err, failure) || got != nil || q.calls != 1 || len(q.ids) != 2 || q.ids[0] != id || q.ids[1] != uuid.Nil {
		t.Fatalf("batch = %v, err=%v, queries=%d, scope=%v", got, err, q.calls, q.ids)
	}
	q.calls = 0
	if _, err := NewStore().DriftSummary(t.Context(), q, id); !errors.Is(err, failure) || q.calls != 1 {
		t.Fatalf("single wrapper err=%v queries=%d", err, q.calls)
	}
}
