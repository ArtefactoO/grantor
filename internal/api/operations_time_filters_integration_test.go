//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
)

type operationsPage struct {
	Operations []struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
	} `json:"operations"`
	Total        int64 `json:"total"`
	StatusTotals struct {
		Active int64 `json:"active"`
		Errors int64 `json:"errors"`
		All    int64 `json:"all"`
	} `json:"status_totals"`
}

func getOperationsPage(t *testing.T, env *testEnv, viewer *auth.Session, values url.Values) operationsPage {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/operations?"+values.Encode(), nil, viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var page operationsPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode operations page: %v", err)
	}
	return page
}

// TestIntegrationOperationsTodayBoundariesAndExactTotal покрывает полный
// API-контракт календарного дня: RFC3339 instants с offset преобразуются
// PostgreSQL в один timeline, нижняя полночь включена, следующая исключена,
// а total не зависит от limit/offset и использует те же connection/status/kind
// predicates, что и строки страницы.
func TestIntegrationOperationsTodayBoundariesAndExactTotal(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	ctx := t.Context()

	connectionID := uuid.New()
	otherConnectionID := uuid.New()
	if _, err := env.pool.Exec(ctx, `
		insert into connections (id, display_name, engine)
		values ($1, $2, 'fake'), ($3, $4, 'fake')`,
		connectionID, "operations-time-"+connectionID.String(),
		otherConnectionID, "operations-time-"+otherConnectionID.String()); err != nil {
		t.Fatalf("seed connections: %v", err)
	}

	kind := "itest.operations-time-" + uuid.NewString()
	otherKind := kind + "-other"
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := env.pool.Exec(cleanupCtx, `delete from operations where kind = any($1)`, []string{kind, otherKind}); err != nil {
			t.Errorf("cleanup operations: %v", err)
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from connections where id = any($1)`, []uuid.UUID{connectionID, otherConnectionID}); err != nil {
			t.Errorf("cleanup connections: %v", err)
		}
	})

	location := time.FixedZone("UTC+03", 3*60*60)
	createdFrom := time.Date(2026, 7, 20, 0, 0, 0, 0, location)
	createdBefore := createdFrom.Add(24 * time.Hour)

	insertOperation := func(connection uuid.UUID, opKind, status string, createdAt time.Time) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := env.pool.Exec(ctx, `
			insert into operations (id, kind, status, connection_id, actor_type, actor_id, created_at)
			values ($1, $2, $3, $4, 'test', $5, $6)`,
			id, opKind, status, connection, t.Name(), createdAt); err != nil {
			t.Fatalf("seed operation at %s: %v", createdAt.Format(time.RFC3339Nano), err)
		}
		return id
	}

	belowLowerID := insertOperation(connectionID, kind, "success", createdFrom.Add(-time.Microsecond))
	lowerBoundaryID := insertOperation(connectionID, kind, "success", createdFrom)
	for i := 0; i < 101; i++ {
		insertOperation(connectionID, kind, "success", createdFrom.Add(time.Duration(i+1)*time.Minute))
	}
	lastInsideID := insertOperation(connectionID, kind, "success", createdBefore.Add(-time.Microsecond))
	upperBoundaryID := insertOperation(connectionID, kind, "success", createdBefore)
	wrongConnectionID := insertOperation(otherConnectionID, kind, "success", createdFrom.Add(time.Hour))
	wrongKindID := insertOperation(connectionID, otherKind, "success", createdFrom.Add(time.Hour))
	wrongStatusID := insertOperation(connectionID, kind, "pending", createdFrom.Add(time.Hour))

	filters := url.Values{
		"connection_id":  []string{connectionID.String()},
		"status":         []string{"success"},
		"kind":           []string{kind},
		"created_from":   []string{createdFrom.Format(time.RFC3339)},
		"created_before": []string{createdBefore.Format(time.RFC3339)},
		"limit":          []string{"10"},
		"offset":         []string{"7"},
	}
	page := getOperationsPage(t, env, &viewer, filters)
	if page.Total != 103 {
		t.Fatalf("total = %d, want 103", page.Total)
	}
	// status_totals игнорирует current status=success, но сохраняет
	// connection/kind/time: поэтому pending-строка входит в active/all.
	if page.StatusTotals.Active != 1 || page.StatusTotals.Errors != 0 || page.StatusTotals.All != 104 {
		t.Fatalf("status_totals = %+v, want active=1 errors=0 all=104", page.StatusTotals)
	}
	if len(page.Operations) != 10 {
		t.Fatalf("paged rows = %d, want 10", len(page.Operations))
	}
	for _, op := range page.Operations {
		if op.CreatedAt.Before(createdFrom) || !op.CreatedAt.Before(createdBefore) {
			t.Errorf("paged operation %s at %s is outside [%s, %s)",
				op.ID, op.CreatedAt, createdFrom, createdBefore)
		}
	}

	// Даже пустая страница после конца выборки обязана сохранить exact total.
	filters.Set("offset", "999")
	emptyPage := getOperationsPage(t, env, &viewer, filters)
	if emptyPage.Total != 103 || len(emptyPage.Operations) != 0 {
		t.Fatalf("empty page = total %d, rows %d; want total 103, rows 0",
			emptyPage.Total, len(emptyPage.Operations))
	}

	// Полная страница доказывает обе полуоткрытые границы и отсутствие строк,
	// исключённых другими предикатами.
	filters.Set("limit", "500")
	filters.Set("offset", "0")
	fullPage := getOperationsPage(t, env, &viewer, filters)
	found := make(map[uuid.UUID]bool, len(fullPage.Operations))
	for _, op := range fullPage.Operations {
		found[op.ID] = true
	}
	if !found[lowerBoundaryID] {
		t.Error("created_from boundary operation was excluded")
	}
	if !found[lastInsideID] {
		t.Error("last operation before created_before was excluded")
	}
	for label, id := range map[string]uuid.UUID{
		"below lower boundary": belowLowerID,
		"at upper boundary":    upperBoundaryID,
		"wrong connection":     wrongConnectionID,
		"wrong kind":           wrongKindID,
		"wrong status":         wrongStatusID,
	} {
		if found[id] {
			t.Errorf("%s operation %s leaked into filtered page", label, id)
		}
	}

	// actor_type фильтруется сервером до limit: фоновые service-операции не
	// могут вытеснить действия оператора из списка Overview.
	operatorID := uuid.New()
	if _, err := env.pool.Exec(ctx, `
		insert into operations (id, kind, status, connection_id, actor_type, actor_id, created_at)
		values ($1, $2, 'success', $3, 'user', $4, $5)`,
		operatorID, kind, connectionID, t.Name(), createdFrom.Add(2*time.Hour)); err != nil {
		t.Fatalf("seed operator operation: %v", err)
	}
	actorFilters := url.Values{
		"connection_id": []string{connectionID.String()},
		"kind":          []string{kind},
		"actor_type":    []string{"user"},
		"limit":         []string{"1"},
	}
	actorPage := getOperationsPage(t, env, &viewer, actorFilters)
	if actorPage.Total != 1 || len(actorPage.Operations) != 1 || actorPage.Operations[0].ID != operatorID {
		t.Fatalf("actor_type=user page = total %d rows %+v; want operator %s",
			actorPage.Total, actorPage.Operations, operatorID)
	}
	if actorPage.StatusTotals.Active != 0 || actorPage.StatusTotals.Errors != 0 || actorPage.StatusTotals.All != 1 {
		t.Fatalf("actor_type=user status_totals = %+v; want active=0 errors=0 all=1",
			actorPage.StatusTotals)
	}

	childID := uuid.New()
	if _, err := env.pool.Exec(ctx, `
		insert into operations (id, parent_id, kind, status, connection_id, actor_type, actor_id, created_at)
		values ($1, $2, $3, 'success', $4, 'user', $5, $6)`,
		childID, operatorID, kind, connectionID, t.Name(), createdFrom.Add(3*time.Hour)); err != nil {
		t.Fatalf("seed child operation: %v", err)
	}
	actorFilters.Set("top_level_only", "true")
	topLevelPage := getOperationsPage(t, env, &viewer, actorFilters)
	if topLevelPage.Total != 1 || len(topLevelPage.Operations) != 1 || topLevelPage.Operations[0].ID != operatorID {
		t.Fatalf("top_level_only page = total %d rows %+v; want parent %s without child %s",
			topLevelPage.Total, topLevelPage.Operations, operatorID, childID)
	}

	for _, query := range []string{
		"created_from=2026-07-20",
		"created_before=2026-07-21T00%3A00%3A00",
		"created_from=2026-07-20T00%3A00%3A00Z&created_before=2026-07-20T00%3A00%3A00Z",
		"created_from=2026-07-21T00%3A00%3A00Z&created_before=2026-07-20T00%3A00%3A00Z",
		"top_level_only=1",
	} {
		resp := env.do(t, http.MethodGet, "/api/v1/operations?"+query, nil, &viewer, false)
		requireStatus(t, resp, http.StatusBadRequest)
	}
}
