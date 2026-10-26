//go:build integration

// Integration-тесты token-bucket против реального PostgreSQL (pgtest,
// GRANTOR_TEST_DB_DSN): исчерпание burst, refill по времени и атомарность
// под конкуренцией. Без базы тесты пропускаются в pgtest.Pool.
package ratelimit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/ratelimit"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestIntegrationTokenBucketBurstAndRefill(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	lim := ratelimit.New(pool)
	key := "test:burst:" + uuid.NewString()
	// Rate высокий, чтобы после сдвига updated_at назад refill наполнил ведро.
	params := ratelimit.Limit{Rate: 20, Burst: 3}

	// Полное ведро отдаёт ровно Burst разрешений.
	for i := 0; i < 3; i++ {
		allowed, _, err := lim.Allow(ctx, key, params)
		if err != nil {
			t.Fatalf("allow %d: %v", i, err)
		}
		if !allowed {
			t.Fatalf("request %d denied, want allowed within burst", i)
		}
	}

	// Burst исчерпан — отказ с ненулевым retryAfter.
	allowed, retryAfter, err := lim.Allow(ctx, key, params)
	if err != nil {
		t.Fatalf("allow after burst: %v", err)
	}
	if allowed {
		t.Fatal("request past burst allowed, want denied")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0 after exhaustion", retryAfter)
	}

	// Сдвигаем updated_at в прошлое: refill = Rate*elapsed наполняет ведро
	// (детерминированно, без sleep).
	if _, err := pool.Exec(ctx,
		"update rate_limit_buckets set updated_at = now() - interval '10 seconds' where key = $1", key); err != nil {
		t.Fatalf("shift updated_at: %v", err)
	}
	allowed, _, err = lim.Allow(ctx, key, params)
	if err != nil {
		t.Fatalf("allow after refill: %v", err)
	}
	if !allowed {
		t.Error("request after refill denied, want allowed")
	}
}

func TestIntegrationTokenBucketIndependentKeys(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	lim := ratelimit.New(pool)
	params := ratelimit.Limit{Rate: 0, Burst: 1}
	keyA := "test:indep:a:" + uuid.NewString()
	keyB := "test:indep:b:" + uuid.NewString()

	// Исчерпываем ведро A.
	if allowed, _, err := lim.Allow(ctx, keyA, params); err != nil || !allowed {
		t.Fatalf("first A: allowed=%v err=%v", allowed, err)
	}
	if allowed, _, err := lim.Allow(ctx, keyA, params); err != nil || allowed {
		t.Fatalf("second A: allowed=%v err=%v, want denied", allowed, err)
	}
	// Ведро B независимо и всё ещё полно.
	if allowed, _, err := lim.Allow(ctx, keyB, params); err != nil || !allowed {
		t.Fatalf("first B: allowed=%v err=%v, want allowed", allowed, err)
	}
}

func TestIntegrationTokenBucketConcurrent(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	lim := ratelimit.New(pool)
	key := "test:concurrent:" + uuid.NewString()
	// Rate 0: без пополнения, поэтому суммарно допустимо РОВНО Burst списаний,
	// что даёт крепкий инвариант атомарности под конкуренцией.
	const burst = 10
	const goroutines = 50
	params := ratelimit.Limit{Rate: 0, Burst: burst}

	var allowedCount int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			allowed, _, err := lim.Allow(ctx, key, params)
			if err != nil {
				errs <- err
				return
			}
			if allowed {
				atomic.AddInt64(&allowedCount, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent allow: %v", err)
	}

	// Атомарность: списаний ровно Burst, ни больше (гонка допустила бы
	// больше), ни меньше.
	if allowedCount != burst {
		t.Errorf("allowed = %d, want exactly %d (burst)", allowedCount, burst)
	}
}
