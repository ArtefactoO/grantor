//go:build integration

// Integration-тесты детектора аномалий против реального PostgreSQL (pgtest,
// GRANTOR_TEST_DB_DSN): скользящее окно, троттлинг сигнала до одного на
// субъект за окно, независимость субъектов и атомарность под конкуренцией.
package ratelimit_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/ratelimit"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestIntegrationAnomalyThresholdAndThrottle(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	det := ratelimit.NewAnomalyDetector(pool)
	key := "reveal:test:" + uuid.NewString()
	// Порог 3, окно длинное (сдвигаем window_start вручную, без sleep).
	w := ratelimit.AnomalyWindow{Threshold: 3, Window: time.Hour}

	// Под порогом — сигнала нет.
	for i := 1; i < 3; i++ {
		count, alert, err := det.Observe(ctx, key, w)
		if err != nil {
			t.Fatalf("observe %d: %v", i, err)
		}
		if count != i {
			t.Errorf("observe %d: count = %d, want %d", i, count, i)
		}
		if alert {
			t.Errorf("observe %d: alert = true under threshold", i)
		}
	}

	// Ровно на пороге — единственный сигнал.
	count, alert, err := det.Observe(ctx, key, w)
	if err != nil {
		t.Fatalf("observe at threshold: %v", err)
	}
	if count != 3 || !alert {
		t.Errorf("observe at threshold: count=%d alert=%v, want 3/true", count, alert)
	}

	// Дальше в том же окне — счётчик растёт, но сигнал троттлится.
	for i := 4; i <= 6; i++ {
		_, alert, err := det.Observe(ctx, key, w)
		if err != nil {
			t.Fatalf("observe %d: %v", i, err)
		}
		if alert {
			t.Errorf("observe %d past threshold: alert = true, want throttled", i)
		}
	}

	// Начало нового окна: и window_start, и last_alerted_at в прошлое.
	// Счётчик сбрасывается, а следующий выход за порог снова сигналит.
	if _, err := pool.Exec(ctx, `
		update credential_reveal_windows
		set window_start = now() - interval '2 hours',
		    last_alerted_at = now() - interval '2 hours'
		where subject = $1`, key); err != nil {
		t.Fatalf("shift window: %v", err)
	}
	// Первое событие нового окна — count сбрасывается в 1, без сигнала.
	count, alert, err = det.Observe(ctx, key, w)
	if err != nil {
		t.Fatalf("observe new window: %v", err)
	}
	if count != 1 || alert {
		t.Errorf("observe new window: count=%d alert=%v, want 1/false", count, alert)
	}
}

func TestIntegrationAnomalyIndependentSubjects(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	det := ratelimit.NewAnomalyDetector(pool)
	w := ratelimit.AnomalyWindow{Threshold: 1, Window: time.Hour}
	keyA := "reveal:test:a:" + uuid.NewString()
	keyB := "reveal:test:b:" + uuid.NewString()

	if _, alert, err := det.Observe(ctx, keyA, w); err != nil || !alert {
		t.Fatalf("A: alert=%v err=%v, want alert", alert, err)
	}
	// B независим: его первый вызов тоже сигналит (своё окно/счётчик).
	if _, alert, err := det.Observe(ctx, keyB, w); err != nil || !alert {
		t.Fatalf("B: alert=%v err=%v, want alert", alert, err)
	}
	// A в том же окне — троттлится.
	if _, alert, err := det.Observe(ctx, keyA, w); err != nil || alert {
		t.Fatalf("A second: alert=%v err=%v, want throttled", alert, err)
	}
}

func TestIntegrationAnomalyDisabled(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	det := ratelimit.NewAnomalyDetector(pool)
	key := "reveal:test:disabled:" + uuid.NewString()

	// Порог 0 — детекция выключена, no-op без обращения к базе.
	count, alert, err := det.Observe(ctx, key, ratelimit.AnomalyWindow{Threshold: 0, Window: time.Hour})
	if err != nil || count != 0 || alert {
		t.Errorf("disabled Observe = (%d, %v, %v), want (0, false, nil)", count, alert, err)
	}
}

func TestIntegrationAnomalyConcurrentSingleAlert(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	det := ratelimit.NewAnomalyDetector(pool)
	key := "reveal:test:concurrent:" + uuid.NewString()
	// Порог 1: каждый вызов «за порогом», но троттлинг «один сигнал за окно»
	// должен пропустить РОВНО один сигнал даже под конкуренцией.
	w := ratelimit.AnomalyWindow{Threshold: 1, Window: time.Hour}

	const goroutines = 40
	var alertCount int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, alert, err := det.Observe(ctx, key, w)
			if err != nil {
				errs <- err
				return
			}
			if alert {
				atomic.AddInt64(&alertCount, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent observe: %v", err)
	}
	if alertCount != 1 {
		t.Errorf("alerts = %d, want exactly 1 (throttled across replicas)", alertCount)
	}
}
