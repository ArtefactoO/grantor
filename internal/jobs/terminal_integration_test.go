//go:build integration

package jobs_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// terminalErrorMarker — префикс, которым worker помечает детерминированную
// причину в operations.error (internal/jobs/terminal.go). Тест держит копию
// константы сознательно: она часть наблюдаемого контракта операции.
const terminalErrorMarker = "not retryable: "

// terminalTestOperation — параметры простой операции без connection: терминальную
// классификацию задаёт исход executor, а не движок, поэтому целевой системы тест
// не требует.
func terminalTestOperation(t *testing.T, kind string) operations.CreateParams {
	t.Helper()
	return operations.CreateParams{
		Kind:          kind,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	}
}

// jobStates возвращает состояния и номера попыток всех river_job операции.
func jobStates(t *testing.T, pool *pgxpool.Pool, opID uuid.UUID) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`select state || ':' || attempt from river_job
		 where args->>'operation_id' = $1 order by id`, opID.String())
	if err != nil {
		t.Fatalf("query river_job: %v", err)
	}
	defer rows.Close()

	var states []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan river_job: %v", err)
		}
		states = append(states, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("query river_job: %v", err)
	}
	return states
}

// waitForJobStates поллит состояния jobs операции до want или таймаута.
func waitForJobStates(t *testing.T, pool *pgxpool.Pool, opID uuid.UUID, want []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got []string
	for {
		got = jobStates(t, pool, opID)
		if strings.Join(got, ",") == strings.Join(want, ",") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("river_job states = %v, want %v within %s", got, want, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestRiverCancelsTerminalOperation — регрессия на детерминированный отказ:
// операция, чьё изменение движок не поддерживает, обязана упасть с ПЕРВОЙ
// попытки (river_job переходит в cancelled, а не в retryable), сохранив
// исходный текст причины. Раньше такая операция висела в ретраях минутами.
func TestRiverCancelsTerminalOperation(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	// Тот же вид ошибки, что даёт adapter движка без нужной capability.
	unsupported := fmt.Errorf("jobs: account.disable operation: mongodb: plan account.disable: %w",
		adapter.ErrUnsupportedChange)
	exec := &selectiveExecutor{behavior: func(operations.Operation) error { return unsupported }}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  1,
		MaxAttempts:  5,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	op := enqueueOperation(t, pool, r, store, terminalTestOperation(t, "itest.terminal-unsupported"))

	startRiver(t, r)

	failed := waitForStatus(t, pool, store, op.ID, operations.StatusFailed, 30*time.Second)
	if !strings.HasPrefix(failed.Error, terminalErrorMarker) {
		t.Errorf("operation error = %q, want the terminal marker %q", failed.Error, terminalErrorMarker)
	}
	if !strings.Contains(failed.Error, unsupported.Error()) {
		t.Errorf("operation error = %q, want the original cause %q", failed.Error, unsupported.Error())
	}

	// Единственный job операции — cancelled на первой попытке: ретраев нет.
	waitForJobStates(t, pool, op.ID, []string{"cancelled:1"}, 30*time.Second)

	// Никаких повторных выполнений после отмены.
	time.Sleep(2 * time.Second)
	if got := exec.calls.Load(); got != 1 {
		t.Errorf("executor calls = %d, want 1 (terminal failure must not be retried)", got)
	}
	if states := jobStates(t, pool, op.ID); strings.Join(states, ",") != "cancelled:1" {
		t.Errorf("river_job states = %v, want [cancelled:1]", states)
	}
	if again, err := store.Get(ctx, pool, op.ID); err != nil {
		t.Fatalf("get operation: %v", err)
	} else if again.Error != failed.Error {
		t.Errorf("operation error changed to %q, want %q", again.Error, failed.Error)
	}
}

// TestRiverKeepsTerminalErrorOnRedelivery — защита от затирания: повторная
// доставка job уже терминально упавшей операции не выполняет её заново и не
// подменяет исходную причину более поздней (в проде это была
// «lifecycle conflict» после посторонней успешной операции над тем же
// аккаунтом).
func TestRiverKeepsTerminalErrorOnRedelivery(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	unsupported := fmt.Errorf("kafka: credential.rotate: %w: connection uses sasl mechanism \"plain\"",
		adapter.ErrUnsupportedChange)
	misleading := fmt.Errorf("account: lifecycle version 3, expected 2: %w",
		inventory.ErrAccountLifecycleConflict)
	var calls atomic.Int32
	exec := &selectiveExecutor{behavior: func(operations.Operation) error {
		if calls.Add(1) == 1 {
			return unsupported
		}
		return misleading
	}}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  1,
		MaxAttempts:  5,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	op := enqueueOperation(t, pool, r, store, terminalTestOperation(t, "itest.terminal-redelivery"))

	startRiver(t, r)

	failed := waitForStatus(t, pool, store, op.ID, operations.StatusFailed, 30*time.Second)
	if !strings.Contains(failed.Error, unsupported.Error()) {
		t.Fatalf("operation error = %q, want the original cause %q", failed.Error, unsupported.Error())
	}
	waitForJobStates(t, pool, op.ID, []string{"cancelled:1"}, 30*time.Second)

	// Повторная доставка: второй job той же операции (дубль постановки или
	// redelivery после сбоя). Ручной retry сюда не относится — он сам
	// переводит операцию в pending.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue redelivery: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit redelivery: %v", err)
	}

	// Второй job тоже отменяется на первой попытке, операция не трогается.
	waitForJobStates(t, pool, op.ID, []string{"cancelled:1", "cancelled:1"}, 30*time.Second)
	if got := exec.calls.Load(); got != 1 {
		t.Errorf("executor calls = %d, want 1 (redelivery must not re-execute)", got)
	}
	again, err := store.Get(ctx, pool, op.ID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if again.Error != failed.Error {
		t.Errorf("operation error = %q, want unchanged %q", again.Error, failed.Error)
	}
	if strings.Contains(again.Error, misleading.Error()) {
		t.Error("later attempt overwrote the original terminal cause")
	}
}

// TestRiverRetriesTransientFailure — контроль границы: обычный (временный)
// отказ обязан ретраиться как раньше, без маркера терминальной причины.
func TestRiverRetriesTransientFailure(t *testing.T) {
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	transient := fmt.Errorf("dial target: connection refused")
	exec := &selectiveExecutor{behavior: func(operations.Operation) error { return transient }}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  1,
		MaxAttempts:  5,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	op := enqueueOperation(t, pool, r, store, terminalTestOperation(t, "itest.transient"))

	startRiver(t, r)

	failed := waitForStatus(t, pool, store, op.ID, operations.StatusFailed, 30*time.Second)
	if strings.HasPrefix(failed.Error, terminalErrorMarker) {
		t.Errorf("operation error = %q, transient failure must not be marked terminal", failed.Error)
	}
	// River повторяет job: второй вызов executor доказывает, что политика
	// ретраев для временных отказов не изменилась. Конкретный attempt не
	// фиксируется — backoff и момент опроса недетерминированы.
	deadline := time.Now().Add(30 * time.Second)
	for exec.calls.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("executor calls = %d, want >= 2 (transient failure must be retried); river_job states = %v",
				exec.calls.Load(), jobStates(t, pool, op.ID))
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, state := range jobStates(t, pool, op.ID) {
		if strings.HasPrefix(state, "cancelled") {
			t.Errorf("river_job state = %q, transient failure must not cancel the job", state)
		}
	}
}
