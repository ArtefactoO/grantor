package gateway

import (
	"context"
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector"
)

func TestMemoryDedupRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := newMemoryDedup()

	if _, ok, err := d.Lookup(ctx, "idem:a"); err != nil || ok {
		t.Fatalf("Lookup on empty store = (ok=%v, err=%v), want miss", ok, err)
	}

	want := connector.JobResult{JobID: "job-1", Status: connector.JobSuccess}
	if err := d.Store(ctx, "idem:a", want); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, ok, err := d.Lookup(ctx, "idem:a")
	if err != nil || !ok {
		t.Fatalf("Lookup after store = (ok=%v, err=%v), want hit", ok, err)
	}
	if got.JobID != want.JobID || got.Status != want.Status {
		t.Errorf("Lookup = %+v, want %+v", got, want)
	}

	// First write wins: повторная запись того же ключа не перезаписывает
	// уже сохранённый результат.
	if err := d.Store(ctx, "idem:a", connector.JobResult{JobID: "job-2", Status: connector.JobSuccess}); err != nil {
		t.Fatalf("Store duplicate: %v", err)
	}
	got, _, _ = d.Lookup(ctx, "idem:a")
	if got.JobID != "job-1" {
		t.Errorf("after duplicate store JobID = %q, want first write %q", got.JobID, "job-1")
	}
}

func TestDedupKey(t *testing.T) {
	cases := []struct {
		name string
		job  connector.Job
		want string
	}{
		{"idempotency key wins", connector.Job{IdempotencyKey: "op-1", Nonce: "n-1"}, "idem:op-1"},
		{"nonce fallback", connector.Job{Nonce: "n-1"}, "nonce:n-1"},
		{"no key", connector.Job{}, ""},
	}
	for _, tc := range cases {
		if got := dedupKey(tc.job); got != tc.want {
			t.Errorf("%s: dedupKey = %q, want %q", tc.name, got, tc.want)
		}
	}
}
