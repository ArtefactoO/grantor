//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestIntegrationOperationDetailDistinguishesScheduledRetryFromFinishedFailure(t *testing.T) {
	for _, state := range []string{"retryable", "scheduled", "running", "available", "completed", "discarded", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			env := newTestEnv(t, nil)
			_, _, source := failedProvisioningFixture(t, env, "login")
			if _, err := env.pool.Exec(t.Context(), `update river_job set state=$2::river_job_state,finalized_at=case when $2::river_job_state in ('completed','discarded','cancelled') then now() else null end where args->>'operation_id'=$1`, source.ID.String(), state); err != nil {
				t.Fatal(err)
			}
			viewer := session(auth.RoleViewer)
			response := env.do(t, http.MethodGet, "/api/v1/operations/"+source.ID.String(), nil, &viewer, false)
			requireStatus(t, response, http.StatusOK)
			var body struct {
				Status       string `json:"status"`
				RetryPending *bool  `json:"retry_pending"`
			}
			if err := json.Unmarshal(readBody(t, response), &body); err != nil {
				t.Fatal(err)
			}
			want := state != "completed" && state != "discarded" && state != "cancelled"
			if body.RetryPending == nil || *body.RetryPending != want || body.Status != string(operations.StatusFailed) {
				t.Fatalf("attempt outcome or scheduled retry was lost: %+v", body)
			}
		})
	}
}
