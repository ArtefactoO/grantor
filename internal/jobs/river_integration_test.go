//go:build integration

package jobs_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type orderedExecutor struct {
	mu    sync.Mutex
	kinds []string
}

func (e *orderedExecutor) Execute(_ context.Context, op operations.Operation) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.kinds = append(e.kinds, op.Kind)
	return nil
}

// fakeExecutor имитирует бизнес-исполнителя: держит выполнение delay и
// через атомарные счётчики фиксирует максимум одновременных Execute.
type fakeExecutor struct {
	delay time.Duration

	calls         atomic.Int32
	current       atomic.Int32
	maxConcurrent atomic.Int32
}

func (f *fakeExecutor) Execute(ctx context.Context, _ operations.Operation) error {
	f.calls.Add(1)
	cur := f.current.Add(1)
	defer f.current.Add(-1)
	for {
		maxSeen := f.maxConcurrent.Load()
		if cur <= maxSeen || f.maxConcurrent.CompareAndSwap(maxSeen, cur) {
			break
		}
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// testQueue возвращает уникальное имя очереди River, чтобы тесты (и
// остатки прежних прогонов в той же базе) не подхватывали чужие jobs.
func testQueue() string {
	return "itest-" + uuid.NewString()
}

// startRiver запускает диспетчер и регистрирует его остановку.
func startRiver(t *testing.T, r *jobs.River) {
	t.Helper()
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start river: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := r.Stop(ctx); err != nil {
			t.Errorf("stop river: %v", err)
		}
	})
}

// waitForStatus поллит операцию до нужного статуса или падает по
// таймауту.
func waitForStatus(t *testing.T, pool *pgxpool.Pool, store *operations.Store, id uuid.UUID, want operations.Status, timeout time.Duration) operations.Operation {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for {
		op, err := store.Get(ctx, pool, id)
		if err != nil {
			t.Fatalf("get operation %s: %v", id, err)
		}
		if op.Status == want {
			return op
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s: status %q (error %q), want %q within %s",
				id, op.Status, op.Error, want, timeout)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestRiverExecutesOperation(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &fakeExecutor{}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	// Создание операции и постановка job — одна транзакция: durable
	// enqueue без окна потери.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	op, created, err := store.Create(ctx, tx, operations.CreateParams{
		Kind:          "itest.noop",
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if !created {
		t.Fatal("create operation: created = false, want true")
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	startRiver(t, r)

	done := waitForStatus(t, pool, store, op.ID, operations.StatusSuccess, 30*time.Second)
	if done.StartedAt == nil || done.FinishedAt == nil {
		t.Error("started_at/finished_at not set on success")
	}
	if got := exec.calls.Load(); got != 1 {
		t.Errorf("executor calls = %d, want 1", got)
	}
}

func TestRiverExecutesExplicitSequenceInOrder(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &orderedExecutor{}
	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue: testQueue(), WorkerCount: 4, SnoozeOnLock: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	create, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind: "account.create", ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create prerequisite: %v", err)
	}
	grant, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind: "access.grant", ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create dependent: %v", err)
	}
	if err := r.EnqueueOperationSequenceTx(ctx, tx, create.ID, grant.ID); err != nil {
		t.Fatalf("enqueue sequence: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit sequence: %v", err)
	}

	startRiver(t, r)
	waitForStatus(t, pool, store, grant.ID, operations.StatusSuccess, 30*time.Second)
	exec.mu.Lock()
	defer exec.mu.Unlock()
	if got, want := fmt.Sprint(exec.kinds), "[account.create access.grant]"; got != want {
		t.Errorf("execution order = %s, want %s", got, want)
	}
}

// TestRiverHoldsPendingApprovalUntilApproved проверяет approval gate на уровне
// диспетчера (ADR-0010): операция в pending_approval поставлена в очередь, но
// worker её не выполняет (snooze), пока approve не переведёт её в pending.
func TestRiverHoldsPendingApprovalUntilApproved(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &fakeExecutor{}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	op, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind:             "itest.approval",
		ActorType:        "user",
		ActorID:          "requester@grantor.dev",
		CorrelationID:    uuid.NewString(),
		RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if op.Status != operations.StatusPendingApproval {
		t.Fatalf("status = %q, want pending_approval", op.Status)
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	startRiver(t, r)

	// Дать worker несколько циклов poll/snooze: операция не должна выполниться.
	time.Sleep(1 * time.Second)
	held, err := store.Get(ctx, pool, op.ID)
	if err != nil {
		t.Fatalf("get held operation: %v", err)
	}
	if held.Status != operations.StatusPendingApproval {
		t.Errorf("status = %q, want pending_approval (must not dispatch before approval)", held.Status)
	}
	if got := exec.calls.Load(); got != 0 {
		t.Errorf("executor calls = %d before approval, want 0", got)
	}

	// Approve вторым admin → операция становится pending и подхватывается уже
	// поставленным job.
	if _, err := store.Approve(ctx, pool, op.ID, "admin-b@grantor.dev", "reviewed"); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	waitForStatus(t, pool, store, op.ID, operations.StatusSuccess, 30*time.Second)
	if got := exec.calls.Load(); got != 1 {
		t.Errorf("executor calls = %d after approval, want 1", got)
	}
}

// TestRiverBatchApproveDispatchesChildren проверяет полный цикл batch-решения
// (расширение ADR-0010, approve-children): дети parent в pending_approval
// поставлены в очередь и снузятся worker'ом; approve всех детей одной
// транзакцией (как decideChildren в API) переводит их в pending, и уже
// поставленные jobs подхватывают и выполняют операции — параллельного
// диспатча approve не создаёт.
func TestRiverBatchApproveDispatchesChildren(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &fakeExecutor{}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	parent, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind:          "itest.batch-parent",
		ActorType:     "user",
		ActorID:       "requester@grantor.dev",
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	var childIDs []uuid.UUID
	for range 3 {
		child, _, err := store.Create(ctx, tx, operations.CreateParams{
			Kind:             "itest.batch-child",
			ParentID:         &parent.ID,
			ActorType:        "user",
			ActorID:          "requester@grantor.dev",
			CorrelationID:    uuid.NewString(),
			RequiresApproval: true,
		})
		if err != nil {
			t.Fatalf("create child: %v", err)
		}
		if err := r.EnqueueOperationTx(ctx, tx, child.ID); err != nil {
			t.Fatalf("enqueue child: %v", err)
		}
		childIDs = append(childIDs, child.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	startRiver(t, r)

	// Несколько циклов poll/snooze: ни один ребёнок не должен выполниться.
	time.Sleep(1 * time.Second)
	if got := exec.calls.Load(); got != 0 {
		t.Errorf("executor calls = %d before batch approval, want 0", got)
	}

	// Batch approve одной транзакцией — как decideChildren в API.
	decideTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin decide tx: %v", err)
	}
	defer decideTx.Rollback(ctx) //nolint:errcheck
	for _, id := range childIDs {
		if _, err := store.Approve(ctx, decideTx, id, "admin@grantor.dev", "batch"); err != nil {
			t.Fatalf("approve child %s: %v", id, err)
		}
	}
	if err := decideTx.Commit(ctx); err != nil {
		t.Fatalf("commit decide tx: %v", err)
	}

	for _, id := range childIDs {
		waitForStatus(t, pool, store, id, operations.StatusSuccess, 30*time.Second)
	}
	if got := exec.calls.Load(); got != 3 {
		t.Errorf("executor calls = %d after batch approval, want 3", got)
	}
}

// selectiveExecutor — фейковый исполнитель с программируемым исходом:
// результат Execute определяет behavior по самой операции. Счётчик calls
// атомарный: Execute зовётся из параллельных worker.
type selectiveExecutor struct {
	behavior func(op operations.Operation) error
	calls    atomic.Int32
}

func (f *selectiveExecutor) Execute(_ context.Context, op operations.Operation) error {
	f.calls.Add(1)
	return f.behavior(op)
}

// enqueueBulkFamily создаёт parent bulk-операции (сразу running, как
// runBulkParent в API) и детей заданных kinds, ставя каждого ребёнка в
// очередь — всё одной транзакцией. Возвращает parent и детей.
func enqueueBulkFamily(t *testing.T, pool *pgxpool.Pool, store *operations.Store, r *jobs.River, childKinds []string) (operations.Operation, []operations.Operation) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	parent, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind:          "itest.bulk-parent",
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, err = store.Transition(ctx, tx, parent.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{})
	if err != nil {
		t.Fatalf("parent pending->running: %v", err)
	}

	children := make([]operations.Operation, 0, len(childKinds))
	for _, kind := range childKinds {
		child, _, err := store.Create(ctx, tx, operations.CreateParams{
			Kind:          kind,
			ParentID:      &parent.ID,
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		if err != nil {
			t.Fatalf("create child: %v", err)
		}
		if err := r.EnqueueOperationTx(ctx, tx, child.ID); err != nil {
			t.Fatalf("enqueue child: %v", err)
		}
		children = append(children, child)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}
	return parent, children
}

// TestRiverFinalizesBulkParentPartial: bulk parent с тремя детьми, один из
// которых падает, — при завершении последнего ребёнка worker финализирует
// parent в базе: running -> partial (durable статус строки, не только
// aggregate_status на чтении).
func TestRiverFinalizesBulkParentPartial(t *testing.T) {
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &selectiveExecutor{behavior: func(op operations.Operation) error {
		if op.Kind == "itest.bulk-child-fail" {
			return fmt.Errorf("itest: simulated child failure")
		}
		return nil
	}}

	// MaxAttempts=1: failed-ребёнок не ретраится River, итог parent
	// стабилен для проверки.
	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  1,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	parent, children := enqueueBulkFamily(t, pool, store, r, []string{
		"itest.bulk-child-ok", "itest.bulk-child-fail", "itest.bulk-child-ok",
	})

	startRiver(t, r)

	done := waitForStatus(t, pool, store, parent.ID, operations.StatusPartial, 30*time.Second)
	if done.FinishedAt == nil {
		t.Error("parent finished_at is nil after finalize")
	}
	for _, child := range children {
		got, err := store.Get(context.Background(), pool, child.ID)
		if err != nil {
			t.Fatalf("get child: %v", err)
		}
		want := operations.StatusSuccess
		if child.Kind == "itest.bulk-child-fail" {
			want = operations.StatusFailed
		}
		if got.Status != want {
			t.Errorf("child %s status = %q, want %q", child.ID, got.Status, want)
		}
	}
}

// TestRiverFinalizesBulkParentSuccess: все дети успешны — parent
// финализируется в success.
func TestRiverFinalizesBulkParentSuccess(t *testing.T) {
	pool := pgtest.Pool(t)
	store := operations.NewStore()
	exec := &selectiveExecutor{behavior: func(operations.Operation) error { return nil }}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  1,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	parent, _ := enqueueBulkFamily(t, pool, store, r, []string{
		"itest.bulk-child-ok", "itest.bulk-child-ok",
	})

	startRiver(t, r)

	done := waitForStatus(t, pool, store, parent.ID, operations.StatusSuccess, 30*time.Second)
	if done.FinishedAt == nil {
		t.Error("parent finished_at is nil after finalize")
	}
}

// TestRiverRevivesBulkParentOnRetry: ребёнок падает на первой попытке
// (parent финализируется в partial), retry River сбрасывает ребёнка в
// pending и оживляет parent (partial -> running), после успешной второй
// попытки parent финализируется заново — уже в success.
func TestRiverRevivesBulkParentOnRetry(t *testing.T) {
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	var failedOnce atomic.Bool
	exec := &selectiveExecutor{behavior: func(op operations.Operation) error {
		if op.Kind == "itest.bulk-child-flaky" && failedOnce.CompareAndSwap(false, true) {
			return fmt.Errorf("itest: transient child failure")
		}
		return nil
	}}

	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  3,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	parent, children := enqueueBulkFamily(t, pool, store, r, []string{
		"itest.bulk-child-ok", "itest.bulk-child-flaky",
	})

	startRiver(t, r)

	// Итог после retry: оба ребёнка success, parent повторно финализирован
	// в success (промежуточный partial и оживление в running между
	// попытками здесь не поллятся — backoff River делает момент
	// недетерминированным).
	waitForStatus(t, pool, store, parent.ID, operations.StatusSuccess, 60*time.Second)
	for _, child := range children {
		got, err := store.Get(context.Background(), pool, child.ID)
		if err != nil {
			t.Fatalf("get child: %v", err)
		}
		if got.Status != operations.StatusSuccess {
			t.Errorf("child %s status = %q, want success", child.ID, got.Status)
		}
	}
	if got := exec.calls.Load(); got != 3 {
		t.Errorf("executor calls = %d, want 3 (ok + flaky fail + flaky retry)", got)
	}
}

func TestRiverSerializesPerConnection(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	var connID uuid.UUID
	if err := pool.QueryRow(ctx,
		"insert into connections (display_name, engine) values ($1, 'fake') returning id",
		"itest-serialization-"+uuid.NewString(),
	).Scan(&connID); err != nil {
		t.Fatalf("create connection: %v", err)
	}

	exec := &fakeExecutor{delay: 300 * time.Millisecond}
	r, err := jobs.New(pool, store, exec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  4,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var opIDs []uuid.UUID
	for range 2 {
		op, _, err := store.Create(ctx, tx, operations.CreateParams{
			Kind:          "itest.serialized",
			ConnectionID:  &connID,
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		if err != nil {
			t.Fatalf("create operation: %v", err)
		}
		if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			t.Fatalf("enqueue operation: %v", err)
		}
		opIDs = append(opIDs, op.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	startRiver(t, r)

	for _, id := range opIDs {
		waitForStatus(t, pool, store, id, operations.StatusSuccess, 30*time.Second)
	}
	if got := exec.calls.Load(); got != 2 {
		t.Errorf("executor calls = %d, want 2", got)
	}
	if got := exec.maxConcurrent.Load(); got != 1 {
		t.Errorf("max concurrent executions on one connection = %d, want 1", got)
	}
}
