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

func TestIntegrationOperationResolutionRemovesActiveErrorWithoutRewritingHistory(t *testing.T) {
	env := newTestEnv(t, nil)
	ctx := t.Context()
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	connectionID := uuid.New()
	kind := "itest.operation-resolution-" + uuid.NewString()
	failedID := uuid.New()
	resolvedID := uuid.New()
	successID := uuid.New()

	if _, err := env.pool.Exec(ctx, `
		insert into connections (id, display_name, engine)
		values ($1, $2, 'fake')`,
		connectionID, "operation-resolution-"+connectionID.String()); err != nil {
		t.Fatalf("seed operation resolution connection: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		insert into operations (
			id, kind, status, connection_id, error, actor_type, actor_id,
			finished_at, resolved_at, resolved_by
		) values
			($2, $3, 'failed', $1, 'first failure', 'user', $6, now(), null, null),
			($4, $3, 'failed', $1, 'old failure', 'user', $6, now(), now(), 'previous@grantor.dev'),
			($5, $3, 'success', $1, '', 'user', $6, now(), null, null)`,
		connectionID, failedID, kind, resolvedID, successID, t.Name()); err != nil {
		t.Fatalf("seed operation resolution: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = env.pool.Exec(cleanupCtx, `delete from audit_events where operation_id = any($1)`, []uuid.UUID{failedID, resolvedID, successID})
		_, _ = env.pool.Exec(cleanupCtx, `delete from operations where kind = $1`, kind)
		_, _ = env.pool.Exec(cleanupCtx, `delete from connections where id = $1`, connectionID)
	})

	filters := url.Values{
		"connection_id":   []string{connectionID.String()},
		"status":          []string{"failed,partial,cancelled"},
		"unresolved_only": []string{"true"},
		"limit":           []string{"100"},
	}
	before := getOperationsPage(t, env, &viewer, filters)
	if before.Total != 1 || len(before.Operations) != 1 || before.Operations[0].ID != failedID {
		t.Fatalf("unresolved before = total %d rows %+v; want only %s", before.Total, before.Operations, failedID)
	}
	if before.StatusTotals.Errors != 1 || before.StatusTotals.All != 3 {
		t.Fatalf("status totals before = %+v; want errors=1 all=3", before.StatusTotals)
	}

	resp := env.do(t, http.MethodPost, "/api/v1/operations/"+failedID.String()+"/resolve", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var resolved struct {
		ID         uuid.UUID  `json:"id"`
		Status     string     `json:"status"`
		Error      string     `json:"error"`
		ResolvedAt *time.Time `json:"resolved_at"`
		ResolvedBy *string    `json:"resolved_by"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&resolved); err != nil {
		t.Fatalf("decode resolved operation: %v", err)
	}
	if resolved.ID != failedID || resolved.Status != "failed" || resolved.Error != "first failure" || resolved.ResolvedAt == nil || resolved.ResolvedBy == nil || *resolved.ResolvedBy != operator.Email {
		t.Fatalf("resolved operation = %+v", resolved)
	}

	after := getOperationsPage(t, env, &viewer, filters)
	if after.Total != 0 || len(after.Operations) != 0 || after.StatusTotals.Errors != 0 || after.StatusTotals.All != 3 {
		t.Fatalf("unresolved after = total %d rows %+v totals %+v", after.Total, after.Operations, after.StatusTotals)
	}

	// Idempotent repeat must not create another audit event.
	repeat := env.do(t, http.MethodPost, "/api/v1/operations/"+failedID.String()+"/resolve", nil, &operator, true)
	requireStatus(t, repeat, http.StatusOK)
	var auditCount int
	if err := env.pool.QueryRow(ctx, `
		select count(*) from audit_events
		where operation_id = $1 and action = 'operation.resolved'`, failedID).Scan(&auditCount); err != nil {
		t.Fatalf("count resolution audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("resolution audit count = %d, want 1", auditCount)
	}

	invalid := env.do(t, http.MethodPost, "/api/v1/operations/"+successID.String()+"/resolve", nil, &operator, true)
	requireStatus(t, invalid, http.StatusConflict)
}
