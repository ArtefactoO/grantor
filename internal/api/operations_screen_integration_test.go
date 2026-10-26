//go:build integration

// Integration-тесты экрана «Операции»: серверные фильтры списка
// (status/kind CSV) и ручной retry неуспешных детей bulk parent
// (POST /operations/{id}/retry) с полноценным River worker — parent
// проходит цикл partial -> retry -> running -> повторная финализация.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// operationRow — подмножество operationJSON для разбора списков.
type operationRow struct {
	ID     uuid.UUID `json:"id"`
	Kind   string    `json:"kind"`
	Status string    `json:"status"`
}

// listOps выполняет GET /api/v1/operations с query и разбирает ответ.
func listOps(t *testing.T, env *testEnv, sess *auth.Session, query string) []operationRow {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/operations?"+query, nil, sess, false)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		Operations []operationRow `json:"operations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode operations list: %v", err)
	}
	return out.Operations
}

// createFinished создаёт операцию и доводит её до final (или оставляет
// pending при final="pending").
func createFinished(t *testing.T, pool *pgxpool.Pool, store *operations.Store, kind string, final operations.Status) operations.Operation {
	t.Helper()
	ctx := context.Background()
	op, _, err := store.Create(ctx, pool, operations.CreateParams{
		Kind: kind, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create operation %s: %v", kind, err)
	}
	if final == operations.StatusPending {
		return op
	}
	if op, err = store.Transition(ctx, pool, op.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("transition %s pending->running: %v", kind, err)
	}
	if op, err = store.Transition(ctx, pool, op.ID,
		operations.StatusRunning, final, operations.TransitionOpts{}); err != nil {
		t.Fatalf("transition %s running->%s: %v", kind, final, err)
	}
	return op
}

// TestIntegrationOperationsListStatusAndKindFilters проверяет серверные
// CSV-фильтры GET /operations: status ограничивает статусной группой
// (вкладки UI), kind — конкретными kind; неизвестный статус — 400.
func TestIntegrationOperationsListStatusAndKindFilters(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	store := operations.NewStore()

	suffix := uniqueSuffix()
	kindPending := "itest.filter-pending-" + suffix
	kindFailed := "itest.filter-failed-" + suffix
	kindOK := "itest.filter-ok-" + suffix
	opPending := createFinished(t, env.pool, store, kindPending, operations.StatusPending)
	opFailed := createFinished(t, env.pool, store, kindFailed, operations.StatusFailed)
	opSuccess := createFinished(t, env.pool, store, kindOK, operations.StatusSuccess)

	// Вкладка «Ошибки»: только failed/partial/cancelled; pending и success
	// операции в выборку не попадают.
	rows := listOps(t, env, &viewer, "status=failed,partial,cancelled&limit=200")
	found := map[uuid.UUID]bool{}
	for _, row := range rows {
		if row.Status != "failed" && row.Status != "partial" && row.Status != "cancelled" {
			t.Errorf("status filter leaked operation %s with status %q", row.ID, row.Status)
		}
		found[row.ID] = true
	}
	if !found[opFailed.ID] {
		t.Errorf("failed operation %s not in error-tab selection", opFailed.ID)
	}
	if found[opPending.ID] || found[opSuccess.ID] {
		t.Error("pending/success operations leaked into error-tab selection")
	}

	// Фильтр по kind (CSV из двух значений).
	rows = listOps(t, env, &viewer, "kind="+kindPending+","+kindOK+"&limit=200")
	found = map[uuid.UUID]bool{}
	for _, row := range rows {
		if row.Kind != kindPending && row.Kind != kindOK {
			t.Errorf("kind filter leaked operation %s with kind %q", row.ID, row.Kind)
		}
		found[row.ID] = true
	}
	if !found[opPending.ID] || !found[opSuccess.ID] {
		t.Error("operations of requested kinds not returned by kind filter")
	}

	// Комбинация status+kind сужает до одной операции.
	rows = listOps(t, env, &viewer, "status=pending&kind="+kindPending+"&limit=200")
	if len(rows) != 1 || rows[0].ID != opPending.ID {
		t.Errorf("status+kind selection = %v, want exactly %s", rows, opPending.ID)
	}

	// Неизвестный статус — 400, а не пустая выборка.
	resp := env.do(t, http.MethodGet, "/api/v1/operations?status=bogus", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
}

// retryFlakyExecutor падает на первом Execute операции flaky-kind, все
// последующие вызовы успешны — имитация транзиентной ошибки, устраняемой
// ручным retry.
type retryFlakyExecutor struct {
	flakyKind  string
	failedOnce atomic.Bool
	calls      atomic.Int32
}

func (f *retryFlakyExecutor) Execute(_ context.Context, op operations.Operation) error {
	f.calls.Add(1)
	if op.Kind == f.flakyKind && f.failedOnce.CompareAndSwap(false, true) {
		return fmt.Errorf("itest: simulated transient child failure")
	}
	return nil
}

// newRetryWorkerEnv собирает testEnv с полноценным River worker поверх
// retryFlakyExecutor: MaxAttempts=1, чтобы авторетраи River не смазывали
// картину — единственный повтор ребёнка ставит ручной retry-эндпоинт.
func newRetryWorkerEnv(t *testing.T, exec *retryFlakyExecutor) (*testEnv, *jobs.River) {
	t.Helper()
	pool := pgtest.Pool(t)
	r, err := jobs.New(pool, operations.NewStore(), exec, jobs.Config{
		Queue:        "retry-itest-" + uniqueSuffix()[:8],
		WorkerCount:  2,
		MaxAttempts:  1,
		SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start river: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := r.Stop(stopCtx); err != nil {
			t.Errorf("stop river: %v", err)
		}
	})
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: r})
	return env, r
}

// enqueueRetryFamily создаёт bulk parent (сразу running, как runBulkParent)
// с детьми заданных kinds и ставит каждого в очередь — одной транзакцией.
func enqueueRetryFamily(t *testing.T, pool *pgxpool.Pool, r *jobs.River, childKinds []string) (operations.Operation, []operations.Operation) {
	t.Helper()
	ctx := context.Background()
	store := operations.NewStore()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	parent, _, err := store.Create(ctx, tx, operations.CreateParams{
		Kind: "itest.retry-parent", ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if parent, err = store.Transition(ctx, tx, parent.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("parent pending->running: %v", err)
	}
	children := make([]operations.Operation, 0, len(childKinds))
	for _, kind := range childKinds {
		child, _, err := store.Create(ctx, tx, operations.CreateParams{
			Kind: kind, ParentID: &parent.ID, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
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

// TestIntegrationRetryBulkParent — полный цикл ручного retry: parent
// финализируется в partial (один ребёнок failed), POST /retry сбрасывает
// failed-ребёнка в pending, оживляет parent и заново ставит job; после
// успешного повтора parent финализируется в success. Повторный retry на
// уже неретраябельном parent — 409; viewer — 403; audit-событие
// operation.retry_requested записано.
func TestIntegrationRetryBulkParent(t *testing.T) {
	flakyKind := "itest.retry-flaky-" + uniqueSuffix()[:8]
	exec := &retryFlakyExecutor{flakyKind: flakyKind}
	env, r := newRetryWorkerEnv(t, exec)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	store := operations.NewStore()

	parent, children := enqueueRetryFamily(t, env.pool, r, []string{"itest.retry-ok", flakyKind})

	// Первый прогон: flaky-ребёнок падает (MaxAttempts=1 — автоповтора
	// нет), worker финализирует parent в partial.
	waitOperation(t, env, parent.ID, operations.StatusPartial, 30*time.Second)

	// viewer не может ретраить (endpoint operator+).
	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+parent.ID.String()+"/retry", nil, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	// Retry оживляет parent и заново ставит только failed-ребёнка.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+parent.ID.String()+"/retry", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID      uuid.UUID   `json:"operation_id"`
		Retried          []uuid.UUID `json:"retried"`
		SkippedCancelled []uuid.UUID `json:"skipped_cancelled"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode retry response: %v", err)
	}
	var flakyID uuid.UUID
	for _, child := range children {
		if child.Kind == flakyKind {
			flakyID = child.ID
		}
	}
	if len(out.Retried) != 1 || out.Retried[0] != flakyID {
		t.Errorf("retried = %v, want exactly failed child %s", out.Retried, flakyID)
	}
	if len(out.SkippedCancelled) != 0 {
		t.Errorf("skipped_cancelled = %v, want empty", out.SkippedCancelled)
	}

	// Второй прогон успешен — parent финализируется заново, уже в success.
	waitOperation(t, env, parent.ID, operations.StatusSuccess, 30*time.Second)

	// Идемпотентность: retry на уже успешном parent — 409.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+parent.ID.String()+"/retry", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Audit-событие retry с числом повторённых детей записано.
	var auditCount int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from audit_events where action = 'operation.retry_requested' and operation_id = $1`,
		parent.ID,
	).Scan(&auditCount); err != nil {
		t.Fatalf("count retry audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("operation.retry_requested audit events = %d, want 1", auditCount)
	}

	// Ребёнок в терминальном success больше не ретраится, статусы детей
	// финальны.
	for _, child := range children {
		got, err := store.Get(context.Background(), env.pool, child.ID)
		if err != nil {
			t.Fatalf("get child: %v", err)
		}
		if got.Status != operations.StatusSuccess {
			t.Errorf("child %s (%s) status = %q, want success", child.ID, child.Kind, got.Status)
		}
	}
	if got := exec.calls.Load(); got != 3 {
		t.Errorf("executor calls = %d, want 3 (ok + flaky fail + manual retry)", got)
	}
}

// TestIntegrationRetryNonBulkConflicts: retry обычной (не bulk) failed
// операции без детей — 409: механизм предназначен для bulk parent, а
// одиночные failed повторяет River в пределах MaxAttempts.
func TestIntegrationRetryNonBulkConflicts(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	store := operations.NewStore()

	op := createFinished(t, env.pool, store, "itest.retry-single-"+uniqueSuffix()[:8], operations.StatusFailed)
	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+op.ID.String()+"/retry", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Несуществующая операция — 404.
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+uuid.NewString()+"/retry", nil, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
}
