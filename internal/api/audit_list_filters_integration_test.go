//go:build integration

// Фильтры GET /api/v1/audit, на которых стоит объединённая лента «Контроля»:
// standalone (события вне операций), operation_id (след одной операции),
// окно occurred_from/occurred_before и точный total.
package api_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
)

type auditPage struct {
	Events []struct {
		ID          int64      `json:"id"`
		Action      string     `json:"action"`
		OccurredAt  time.Time  `json:"occurred_at"`
		OperationID *uuid.UUID `json:"operation_id"`
		ActorID     string     `json:"actor_id"`
	} `json:"events"`
	Total int64 `json:"total"`
}

func getAuditPage(t *testing.T, env *testEnv, viewer *auth.Session, values url.Values) auditPage {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/audit?"+values.Encode(), nil, viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var page auditPage
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode audit page: %v", err)
	}
	return page
}

func TestIntegrationAuditListFilters(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	ctx := t.Context()

	connectionID := uuid.New()
	if _, err := env.pool.Exec(ctx, `
		insert into connections (id, display_name, engine) values ($1, $2, 'fake')`,
		connectionID, "audit-filters-"+connectionID.String()); err != nil {
		t.Fatalf("seed connection: %v", err)
	}
	operationID := uuid.New()
	if _, err := env.pool.Exec(ctx, `
		insert into operations (id, kind, status, connection_id, actor_type, actor_id)
		values ($1, 'access.grant', 'success', $2, 'user', 'seed@grantor.dev')`,
		operationID, connectionID); err != nil {
		t.Fatalf("seed operation: %v", err)
	}

	base := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	seed := []struct {
		action      string
		actor       string
		operationID *uuid.UUID
		occurredAt  time.Time
	}{
		{"credential.shared", "alice@grantor.dev", nil, base},
		{"account.adopted", "bob@grantor.dev", nil, base.Add(-time.Hour)},
		{"operation.approved", "alice@grantor.dev", &operationID, base.Add(-2 * time.Hour)},
		{"access.granted", "worker", &operationID, base.Add(-3 * time.Hour)},
		{"credential.shared", "alice@grantor.dev", nil, base.Add(-24 * time.Hour)},
	}
	for _, s := range seed {
		if _, err := env.pool.Exec(ctx, `
			insert into audit_events (occurred_at, actor_type, actor_id, action,
				connection_id, operation_id, result, metadata)
			values ($1, 'user', $2, $3, $4, $5, 'success', '{}'::jsonb)`,
			s.occurredAt, s.actor, s.action, connectionID, s.operationID); err != nil {
			t.Fatalf("seed audit event %q: %v", s.action, err)
		}
	}

	conn := connectionID.String()

	// standalone=true оставляет только события вне операций: именно так лента
	// избегает второго показа операции, у которой есть своя строка.
	standalone := getAuditPage(t, env, &viewer, url.Values{
		"connection_id": {conn}, "standalone": {"true"},
	})
	if standalone.Total != 3 || len(standalone.Events) != 3 {
		t.Fatalf("standalone: total=%d events=%d, want 3/3", standalone.Total, len(standalone.Events))
	}
	for _, e := range standalone.Events {
		if e.OperationID != nil {
			t.Errorf("standalone returned event %d bound to operation %s", e.ID, e.OperationID)
		}
	}

	// operation_id собирает след конкретной операции для её детальной панели.
	trail := getAuditPage(t, env, &viewer, url.Values{"operation_id": {operationID.String()}})
	if trail.Total != 2 || len(trail.Events) != 2 {
		t.Fatalf("operation trail: total=%d events=%d, want 2/2", trail.Total, len(trail.Events))
	}
	for _, e := range trail.Events {
		if e.OperationID == nil || *e.OperationID != operationID {
			t.Errorf("operation trail returned foreign event %d", e.ID)
		}
	}

	// Окно: нижняя граница включена, верхняя исключена.
	window := getAuditPage(t, env, &viewer, url.Values{
		"connection_id":   {conn},
		"occurred_from":   {base.Add(-2 * time.Hour).Format(time.RFC3339)},
		"occurred_before": {base.Format(time.RFC3339)},
	})
	if window.Total != 2 {
		t.Fatalf("window total = %d, want 2 (from inclusive, before exclusive)", window.Total)
	}

	// action — CSV, actor_id — точное совпадение.
	actions := getAuditPage(t, env, &viewer, url.Values{
		"connection_id": {conn}, "action": {"credential.shared,account.adopted"},
	})
	if actions.Total != 3 {
		t.Fatalf("action csv total = %d, want 3", actions.Total)
	}
	actor := getAuditPage(t, env, &viewer, url.Values{
		"connection_id": {conn}, "actor_id": {"alice@grantor.dev"},
	})
	if actor.Total != 3 {
		t.Fatalf("actor_id total = %d, want 3", actor.Total)
	}

	// total не зависит от limit/offset: по нему клиент решает, есть ли ещё.
	paged := getAuditPage(t, env, &viewer, url.Values{
		"connection_id": {conn}, "limit": {"2"}, "offset": {"1"},
	})
	if paged.Total != 5 || len(paged.Events) != 2 {
		t.Fatalf("paged: total=%d events=%d, want 5/2", paged.Total, len(paged.Events))
	}

	// Взаимоисключающие фильтры отклоняются, а не дают пустую выборку молча.
	resp := env.do(t, http.MethodGet,
		"/api/v1/audit?standalone=true&operation_id="+operationID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodGet, "/api/v1/audit?standalone=maybe", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodGet, "/api/v1/audit?occurred_from=2026-03-05", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodGet,
		"/api/v1/audit?occurred_from="+url.QueryEscape(base.Format(time.RFC3339))+
			"&occurred_before="+url.QueryEscape(base.Format(time.RFC3339)), nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
}
