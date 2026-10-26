//go:build integration

package connectorjobs_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// TestStoreRoundTrip — durable-store дедупликации: miss на пустом ключе,
// hit после записи (jsonb сравнивается разобранным значением, не
// подстрокой), first-write-wins на конфликте ключа.
func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connectorjobs.NewStore(pool, 0)

	key := "idem:itest-" + uuid.NewString()
	if _, ok, err := store.Lookup(ctx, key); err != nil {
		t.Fatalf("Lookup miss: %v", err)
	} else if ok {
		t.Fatalf("Lookup(%q) = hit on empty store", key)
	}

	want := connector.JobResult{
		JobID:      "job-" + uuid.NewString(),
		Status:     connector.JobSuccess,
		Result:     json.RawMessage(`{"server_version":"16.1","resources":[]}`),
		ObservedAt: time.Now().Unix(),
	}
	if err := store.Store(ctx, key, want); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, ok, err := store.Lookup(ctx, key)
	if err != nil || !ok {
		t.Fatalf("Lookup after store = (ok=%v, err=%v), want hit", ok, err)
	}
	if got.JobID != want.JobID || got.Status != want.Status || got.ObservedAt != want.ObservedAt {
		t.Errorf("Lookup = %+v, want %+v", got, want)
	}
	// jsonb нормализует форматирование — сравниваем разобранные значения.
	var gotResult, wantResult map[string]any
	if err := json.Unmarshal(got.Result, &gotResult); err != nil {
		t.Fatalf("unmarshal cached result payload: %v", err)
	}
	if err := json.Unmarshal(want.Result, &wantResult); err != nil {
		t.Fatalf("unmarshal expected result payload: %v", err)
	}
	if gotResult["server_version"] != wantResult["server_version"] {
		t.Errorf("cached result payload = %v, want %v", gotResult, wantResult)
	}

	// First write wins: конкурентная повторная запись того же ключа не
	// перезаписывает результат.
	other := want
	other.JobID = "job-overwrite"
	if err := store.Store(ctx, key, other); err != nil {
		t.Fatalf("Store duplicate: %v", err)
	}
	got, _, err = store.Lookup(ctx, key)
	if err != nil {
		t.Fatalf("Lookup after duplicate store: %v", err)
	}
	if got.JobID != want.JobID {
		t.Errorf("after duplicate store JobID = %q, want first write %q", got.JobID, want.JobID)
	}
}

// TestStoreGCExpiredEntries — cleanup-on-insert: запись старше TTL удаляется
// при следующей вставке, свежая остаётся.
func TestStoreGCExpiredEntries(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := connectorjobs.NewStore(pool, time.Hour)

	oldKey := "idem:itest-old-" + uuid.NewString()
	freshKey := "idem:itest-fresh-" + uuid.NewString()
	res := connector.JobResult{JobID: "job-gc", Status: connector.JobSuccess}
	if err := store.Store(ctx, oldKey, res); err != nil {
		t.Fatalf("Store old: %v", err)
	}
	// Состариваем запись за порог TTL напрямую в таблице.
	if _, err := pool.Exec(ctx,
		`update connector_job_dedup set created_at = now() - interval '2 hours' where dedup_key = $1`,
		oldKey,
	); err != nil {
		t.Fatalf("age old entry: %v", err)
	}

	if err := store.Store(ctx, freshKey, res); err != nil {
		t.Fatalf("Store fresh: %v", err)
	}

	if _, ok, err := store.Lookup(ctx, oldKey); err != nil {
		t.Fatalf("Lookup old: %v", err)
	} else if ok {
		t.Errorf("expired entry %q survived cleanup-on-insert", oldKey)
	}
	if _, ok, err := store.Lookup(ctx, freshKey); err != nil || !ok {
		t.Errorf("fresh entry %q lost: (ok=%v, err=%v)", freshKey, ok, err)
	}
}
