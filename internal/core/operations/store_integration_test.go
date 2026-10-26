//go:build integration

package operations_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestStoreCreateIdempotency(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	key := "test-idem-" + uuid.NewString()
	params := operations.CreateParams{
		Kind:           "test.noop",
		IdempotencyKey: &key,
		Payload:        []byte(`{"reason":"idempotency test"}`),
		ActorType:      "test",
		ActorID:        t.Name(),
		CorrelationID:  uuid.NewString(),
	}

	first, created, err := store.Create(ctx, pool, params)
	if err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if !created {
		t.Fatal("first Create: created = false, want true")
	}
	if first.Status != operations.StatusPending {
		t.Errorf("first Create: status = %q, want %q", first.Status, operations.StatusPending)
	}
	if first.IdempotencyKey == nil || *first.IdempotencyKey != key {
		t.Errorf("first Create: idempotency key not persisted")
	}

	second, created, err := store.Create(ctx, pool, params)
	if err != nil {
		t.Fatalf("second Create: %v", err)
	}
	if created {
		t.Error("second Create: created = true, want false")
	}
	if second.ID != first.ID {
		t.Errorf("second Create returned different operation: %s != %s", second.ID, first.ID)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"select count(*) from operations where idempotency_key = $1", key,
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("rows with idempotency key = %d, want 1", count)
	}
}

func TestStoreCreateRequiresApproval(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op, created, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:             "test.approval",
		ActorType:        "test",
		ActorID:          t.Name(),
		RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !created {
		t.Fatal("Create: created = false, want true")
	}
	if op.Status != operations.StatusPendingApproval {
		t.Errorf("status = %q, want %q", op.Status, operations.StatusPendingApproval)
	}
}

func TestStoreApprove(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op := createPendingApproval(t, ctx, pool, store)

	approved, err := store.Approve(ctx, pool, op.ID, "admin-b@grantor.dev", "looks fine")
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if approved.Status != operations.StatusPending {
		t.Errorf("status = %q, want %q", approved.Status, operations.StatusPending)
	}
	if approved.ApprovedBy == nil || *approved.ApprovedBy != "admin-b@grantor.dev" {
		t.Errorf("approved_by = %v, want admin-b@grantor.dev", approved.ApprovedBy)
	}
	if approved.ApprovedAt == nil {
		t.Error("approved_at is nil after approve")
	}
	if approved.DecisionReason != "looks fine" {
		t.Errorf("decision_reason = %q, want %q", approved.DecisionReason, "looks fine")
	}
	if approved.StartedAt != nil {
		t.Error("started_at must not be set by approve (only worker sets it)")
	}

	// Повторный approve (строка уже pending) обязан упасть конфликтом: guard
	// по status=pending_approval не сработает. Идемпотентность no-op —
	// ответственность API-слоя.
	if _, err := store.Approve(ctx, pool, op.ID, "admin-c@grantor.dev", ""); !errors.Is(err, operations.ErrStatusConflict) {
		t.Errorf("second Approve: err = %v, want ErrStatusConflict", err)
	}
}

func TestStoreReject(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op := createPendingApproval(t, ctx, pool, store)

	rejected, err := store.Reject(ctx, pool, op.ID, "not allowed")
	if err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if rejected.Status != operations.StatusCancelled {
		t.Errorf("status = %q, want %q", rejected.Status, operations.StatusCancelled)
	}
	if !rejected.Status.IsTerminal() {
		t.Error("rejected operation must be terminal")
	}
	if rejected.DecisionReason != "not allowed" {
		t.Errorf("decision_reason = %q, want %q", rejected.DecisionReason, "not allowed")
	}
	if rejected.FinishedAt == nil {
		t.Error("finished_at is nil after reject (cancelled is finished)")
	}
	if rejected.ApprovedBy != nil {
		t.Errorf("approved_by must stay nil on reject, got %v", rejected.ApprovedBy)
	}

	// Approve уже отклонённой операции — конфликт (терминальный статус).
	if _, err := store.Approve(ctx, pool, op.ID, "admin-b@grantor.dev", ""); !errors.Is(err, operations.ErrStatusConflict) {
		t.Errorf("Approve after reject: err = %v, want ErrStatusConflict", err)
	}
}

func TestStoreApproveNotFound(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	if _, err := store.Approve(ctx, pool, uuid.New(), "admin@grantor.dev", ""); !errors.Is(err, operations.ErrNotFound) {
		t.Errorf("Approve(random uuid): err = %v, want ErrNotFound", err)
	}
}

func TestStoreListByStatus(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	pending := createPendingApproval(t, ctx, pool, store)
	// Обычная (не требующая approval) операция не должна попасть в выборку.
	if _, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind: "test.plain", ActorType: "test", ActorID: t.Name(),
	}); err != nil {
		t.Fatalf("Create plain: %v", err)
	}

	ops, err := store.List(ctx, pool, operations.Filter{Status: operations.StatusPendingApproval})
	if err != nil {
		t.Fatalf("List by status: %v", err)
	}
	found := false
	for i := range ops {
		if ops[i].Status != operations.StatusPendingApproval {
			t.Errorf("List returned status %q, want only pending_approval", ops[i].Status)
		}
		if ops[i].ID == pending.ID {
			found = true
		}
	}
	if !found {
		t.Error("pending_approval operation not returned by status filter")
	}
}

// TestStoreListByStatusesAndKinds: Filter.Statuses, Filter.Kinds и
// Filter.ActorTypes — any-of условия экранов операций и Overview.
func TestStoreListByStatusesAndKinds(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	kindA := "test.filter-a-" + uuid.NewString()
	kindB := "test.filter-b-" + uuid.NewString()
	opA, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind: kindA, ActorType: "user", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatalf("Create opA: %v", err)
	}
	opB, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind: kindB, ActorType: "service", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatalf("Create opB: %v", err)
	}
	if _, err := store.Transition(ctx, pool, opB.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("opB pending->running: %v", err)
	}
	if _, err := store.Transition(ctx, pool, opB.ID,
		operations.StatusRunning, operations.StatusFailed, operations.TransitionOpts{Error: "boom"}); err != nil {
		t.Fatalf("opB running->failed: %v", err)
	}

	// Statuses: множественный статусный фильтр возвращает только их.
	ops, err := store.List(ctx, pool, operations.Filter{
		Statuses: []operations.Status{operations.StatusFailed, operations.StatusPartial},
		Kinds:    []string{kindA, kindB},
	})
	if err != nil {
		t.Fatalf("List by statuses: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != opB.ID {
		t.Errorf("List(statuses=failed|partial, kinds) = %v, want exactly opB %s", ops, opB.ID)
	}

	// Kinds без статусов возвращает обе операции.
	ops, err = store.List(ctx, pool, operations.Filter{Kinds: []string{kindA, kindB}})
	if err != nil {
		t.Fatalf("List by kinds: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("List(kinds) returned %d operations, want 2", len(ops))
	}
	got := map[uuid.UUID]bool{ops[0].ID: true, ops[1].ID: true}
	if !got[opA.ID] || !got[opB.ID] {
		t.Errorf("List(kinds) = %v, want opA and opB", ops)
	}

	ops, err = store.List(ctx, pool, operations.Filter{
		Kinds:      []string{kindA, kindB},
		ActorTypes: []string{"user"},
	})
	if err != nil {
		t.Fatalf("List by actor type: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != opA.ID {
		t.Errorf("List(actor_types=user, kinds) = %v, want exactly opA %s", ops, opA.ID)
	}

	child, _, err := store.Create(ctx, pool, operations.CreateParams{
		ParentID:  &opA.ID,
		Kind:      kindA,
		ActorType: "user",
		ActorID:   "operator@grantor.dev",
	})
	if err != nil {
		t.Fatalf("Create child: %v", err)
	}
	ops, err = store.List(ctx, pool, operations.Filter{
		Kinds:        []string{kindA, kindB},
		ActorTypes:   []string{"user"},
		TopLevelOnly: true,
	})
	if err != nil {
		t.Fatalf("List top-level operator operations: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != opA.ID {
		t.Errorf("List(top_level_only) = %v, want parent %s without child %s", ops, opA.ID, child.ID)
	}
}

// createPendingApproval создаёт операцию в статусе pending_approval.
func createPendingApproval(t *testing.T, ctx context.Context, pool operations.Querier, store *operations.Store) operations.Operation {
	t.Helper()
	op, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:             "test.approval",
		ActorType:        "user",
		ActorID:          "requester@grantor.dev",
		RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("create pending_approval operation: %v", err)
	}
	return op
}

// createRunningParent создаёт parent-операцию и переводит её в running —
// как runBulkParent в API.
func createRunningParent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *operations.Store) operations.Operation {
	t.Helper()
	parent, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.bulk-parent",
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	parent, err = store.Transition(ctx, pool, parent.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{})
	if err != nil {
		t.Fatalf("parent pending->running: %v", err)
	}
	return parent
}

// createChild создаёт дочернюю операцию parent в статусе pending.
func createChild(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *operations.Store, parentID uuid.UUID) operations.Operation {
	t.Helper()
	child, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.bulk-child",
		ParentID:  &parentID,
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	return child
}

// finishChild доводит pending-ребёнка до final (success или failed).
func finishChild(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *operations.Store, id uuid.UUID, final operations.Status) {
	t.Helper()
	if _, err := store.Transition(ctx, pool, id,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("child pending->running: %v", err)
	}
	if _, err := store.Transition(ctx, pool, id,
		operations.StatusRunning, final, operations.TransitionOpts{}); err != nil {
		t.Fatalf("child running->%s: %v", final, err)
	}
}

// finalizeInTx вызывает FinalizeParent в отдельной транзакции (row-level
// lock требует транзакции) и коммитит её.
func finalizeInTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool, store *operations.Store, parentID uuid.UUID) (operations.Operation, bool) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin finalize tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, finalized, err := store.FinalizeParent(ctx, tx, parentID)
	if err != nil {
		t.Fatalf("FinalizeParent: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit finalize tx: %v", err)
	}
	return op, finalized
}

func TestStoreFinalizeParentPartial(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	childA := createChild(t, ctx, pool, store, parent.ID)
	childB := createChild(t, ctx, pool, store, parent.ID)

	// Дети ещё pending — финализировать нечего.
	if _, finalized := finalizeInTx(t, ctx, pool, store, parent.ID); finalized {
		t.Fatal("FinalizeParent with pending children: finalized = true, want false")
	}

	// Первый ребёнок завершился, второй нет — parent остаётся running.
	finishChild(t, ctx, pool, store, childA.ID, operations.StatusSuccess)
	if _, finalized := finalizeInTx(t, ctx, pool, store, parent.ID); finalized {
		t.Fatal("FinalizeParent with unfinished child: finalized = true, want false")
	}

	// Последний ребёнок failed — parent финализируется в partial.
	finishChild(t, ctx, pool, store, childB.ID, operations.StatusFailed)
	done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID)
	if !finalized {
		t.Fatal("FinalizeParent after last child: finalized = false, want true")
	}
	if done.Status != operations.StatusPartial {
		t.Errorf("parent status = %q, want %q", done.Status, operations.StatusPartial)
	}
	if done.FinishedAt == nil {
		t.Error("parent finished_at is nil after finalize")
	}

	// Повторный вызов идемпотентен: parent уже не в running.
	if _, finalized := finalizeInTx(t, ctx, pool, store, parent.ID); finalized {
		t.Error("second FinalizeParent: finalized = true, want false")
	}
}

func TestStoreFinalizeParentAllSuccess(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	for range 2 {
		child := createChild(t, ctx, pool, store, parent.ID)
		finishChild(t, ctx, pool, store, child.ID, operations.StatusSuccess)
	}

	done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID)
	if !finalized {
		t.Fatal("FinalizeParent: finalized = false, want true")
	}
	if done.Status != operations.StatusSuccess {
		t.Errorf("parent status = %q, want %q", done.Status, operations.StatusSuccess)
	}
}

func TestStoreFinalizeParentAllCancelled(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	for range 2 {
		child, _, err := store.Create(ctx, pool, operations.CreateParams{
			Kind:             "test.bulk-child",
			ParentID:         &parent.ID,
			ActorType:        "test",
			ActorID:          t.Name(),
			RequiresApproval: true,
		})
		if err != nil {
			t.Fatalf("create child: %v", err)
		}
		if _, err := store.Reject(ctx, pool, child.ID, "not allowed"); err != nil {
			t.Fatalf("reject child: %v", err)
		}
	}

	// cancelled считается неуспехом: все дети отклонены — parent failed.
	done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID)
	if !finalized {
		t.Fatal("FinalizeParent: finalized = false, want true")
	}
	if done.Status != operations.StatusFailed {
		t.Errorf("parent status = %q, want %q", done.Status, operations.StatusFailed)
	}
}

// TestStoreFinalizeParentNoChildren: parent без детей финализируется в
// success — parent и дети создаются одной транзакцией, поэтому снаружи
// running-parent без детей навсегда остался бы running (регрессия: вечно
// «идущие» offboard и manifest apply без действий).
func TestStoreFinalizeParentNoChildren(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID)
	if !finalized {
		t.Fatal("FinalizeParent without children: finalized = false, want true")
	}
	if done.Status != operations.StatusSuccess {
		t.Errorf("parent status = %q, want %q", done.Status, operations.StatusSuccess)
	}
	if done.FinishedAt == nil {
		t.Error("parent finished_at is nil after finalize")
	}
}

func TestStoreFinalizeParentNotFound(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, _, err := store.FinalizeParent(ctx, tx, uuid.New()); !errors.Is(err, operations.ErrNotFound) {
		t.Errorf("FinalizeParent(random uuid): err = %v, want ErrNotFound", err)
	}
}

// TestStoreFinalizeParentConcurrent проверяет сериализацию конкурентных
// финализаций: два ребёнка завершаются в двух параллельных транзакциях,
// каждая вызывает FinalizeParent. Row-level lock строки parent гарантирует,
// что финализирует ровно одна, и parent получает итог по обоим детям.
func TestStoreFinalizeParentConcurrent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	children := []operations.Operation{
		createChild(t, ctx, pool, store, parent.ID),
		createChild(t, ctx, pool, store, parent.ID),
	}
	for i := range children {
		if _, err := store.Transition(ctx, pool, children[i].ID,
			operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
			t.Fatalf("child pending->running: %v", err)
		}
	}

	finalizedCount := make(chan bool, len(children))
	errs := make(chan error, len(children))
	var wg sync.WaitGroup
	for i := range children {
		wg.Add(1)
		go func(childID uuid.UUID) {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				errs <- fmt.Errorf("begin tx: %w", err)
				return
			}
			defer tx.Rollback(ctx) //nolint:errcheck
			if _, err := store.Transition(ctx, tx, childID,
				operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
				errs <- fmt.Errorf("child running->success: %w", err)
				return
			}
			_, finalized, err := store.FinalizeParent(ctx, tx, parent.ID)
			if err != nil {
				errs <- fmt.Errorf("finalize parent: %w", err)
				return
			}
			if err := tx.Commit(ctx); err != nil {
				errs <- fmt.Errorf("commit: %w", err)
				return
			}
			finalizedCount <- finalized
		}(children[i].ID)
	}
	wg.Wait()
	close(errs)
	close(finalizedCount)
	for err := range errs {
		t.Fatalf("concurrent finalize: %v", err)
	}

	got := 0
	for finalized := range finalizedCount {
		if finalized {
			got++
		}
	}
	if got != 1 {
		t.Errorf("finalized count = %d, want exactly 1", got)
	}
	current, err := store.Get(ctx, pool, parent.ID)
	if err != nil {
		t.Fatalf("get parent: %v", err)
	}
	if current.Status != operations.StatusSuccess {
		t.Errorf("parent status = %q, want %q", current.Status, operations.StatusSuccess)
	}
}

func TestStoreReviveParent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent := createRunningParent(t, ctx, pool, store)
	childA := createChild(t, ctx, pool, store, parent.ID)
	childB := createChild(t, ctx, pool, store, parent.ID)
	finishChild(t, ctx, pool, store, childA.ID, operations.StatusSuccess)
	finishChild(t, ctx, pool, store, childB.ID, operations.StatusFailed)
	if done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID); !finalized || done.Status != operations.StatusPartial {
		t.Fatalf("finalize: finalized=%v status=%q, want true/partial", finalized, done.Status)
	}

	// Retry failed-ребёнка: parent оживает partial -> pending -> running.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revive tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := store.Transition(ctx, tx, childB.ID,
		operations.StatusFailed, operations.StatusPending, operations.TransitionOpts{}); err != nil {
		t.Fatalf("child failed->pending: %v", err)
	}
	revived, ok, err := store.ReviveParent(ctx, tx, parent.ID)
	if err != nil {
		t.Fatalf("ReviveParent: %v", err)
	}
	if !ok {
		t.Fatal("ReviveParent: revived = false, want true")
	}
	if revived.Status != operations.StatusRunning {
		t.Errorf("parent status = %q, want running", revived.Status)
	}
	// Повторный revive в той же транзакции — идемпотентный no-op.
	if _, ok, err := store.ReviveParent(ctx, tx, parent.ID); err != nil || ok {
		t.Errorf("second ReviveParent: ok=%v err=%v, want false/nil", ok, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit revive tx: %v", err)
	}

	// Ребёнок завершился успехом со второй попытки — parent финализируется
	// заново, теперь в success.
	finishChild(t, ctx, pool, store, childB.ID, operations.StatusSuccess)
	done, finalized := finalizeInTx(t, ctx, pool, store, parent.ID)
	if !finalized {
		t.Fatal("finalize after retry: finalized = false, want true")
	}
	if done.Status != operations.StatusSuccess {
		t.Errorf("parent status = %q, want %q", done.Status, operations.StatusSuccess)
	}
}

func TestStoreTransitionHappyPath(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.happy",
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	running, err := store.Transition(ctx, pool, op.ID,
		operations.StatusPending, operations.StatusRunning,
		operations.TransitionOpts{Plan: []byte(`{"steps":[]}`)})
	if err != nil {
		t.Fatalf("Transition pending->running: %v", err)
	}
	if running.Status != operations.StatusRunning {
		t.Errorf("status = %q, want %q", running.Status, operations.StatusRunning)
	}
	if running.StartedAt == nil {
		t.Error("started_at is nil after pending->running")
	}
	if running.FinishedAt != nil {
		t.Error("finished_at is set before completion")
	}

	done, err := store.Transition(ctx, pool, op.ID,
		operations.StatusRunning, operations.StatusSuccess,
		operations.TransitionOpts{Result: []byte(`{"applied":true}`)})
	if err != nil {
		t.Fatalf("Transition running->success: %v", err)
	}
	if done.Status != operations.StatusSuccess {
		t.Errorf("status = %q, want %q", done.Status, operations.StatusSuccess)
	}
	if done.FinishedAt == nil {
		t.Error("finished_at is nil after running->success")
	}
	if string(done.Plan) == "" {
		t.Error("plan lost after running->success (expected coalesce to keep it)")
	}
	if len(done.Result) == 0 {
		t.Error("result not persisted")
	}
}

func TestStoreTransitionStatusConflict(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.conflict",
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Переход валиден (running->success), но строка сейчас в pending —
	// guard по from обязан не сработать.
	_, err = store.Transition(ctx, pool, op.ID,
		operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{})
	if !errors.Is(err, operations.ErrStatusConflict) {
		t.Errorf("Transition with wrong from: err = %v, want ErrStatusConflict", err)
	}
}

func TestStoreTransitionInvalid(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	op, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.invalid-transition",
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = store.Transition(ctx, pool, op.ID,
		operations.StatusPending, operations.StatusSuccess, operations.TransitionOpts{})
	if !errors.Is(err, operations.ErrInvalidTransition) {
		t.Errorf("Transition pending->success: err = %v, want ErrInvalidTransition", err)
	}
}

func TestStoreGetNotFound(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	if _, err := store.Get(ctx, pool, uuid.New()); !errors.Is(err, operations.ErrNotFound) {
		t.Errorf("Get(random uuid): err = %v, want ErrNotFound", err)
	}
}

func TestStoreListByParent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := operations.NewStore()

	parent, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind:      "test.bulk",
		ActorType: "test",
		ActorID:   t.Name(),
	})
	if err != nil {
		t.Fatalf("Create parent: %v", err)
	}

	childIDs := make(map[uuid.UUID]bool, 2)
	for range 2 {
		child, _, err := store.Create(ctx, pool, operations.CreateParams{
			Kind:      "test.bulk-child",
			ParentID:  &parent.ID,
			ActorType: "test",
			ActorID:   t.Name(),
		})
		if err != nil {
			t.Fatalf("Create child: %v", err)
		}
		childIDs[child.ID] = true
	}

	children, err := store.ListByParent(ctx, pool, parent.ID)
	if err != nil {
		t.Fatalf("ListByParent: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("ListByParent returned %d operations, want 2", len(children))
	}
	for _, child := range children {
		if !childIDs[child.ID] {
			t.Errorf("unexpected child %s", child.ID)
		}
		if child.ParentID == nil || *child.ParentID != parent.ID {
			t.Errorf("child %s has wrong parent", child.ID)
		}
	}
}
