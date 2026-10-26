//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func TestIntegrationConnectionDisableEnablePreservesSnapshotAndAudits(t *testing.T) {
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled})
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)

	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/disable", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var disabled patchConnectionBody
	if err := json.NewDecoder(resp.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode disable response: %v", err)
	}
	if disabled.Status != string(connections.StatusDisabled) ||
		disabled.ServerVersion != conn.ServerVersion || disabled.LastDiscoveryAt == nil {
		t.Fatalf("disable changed snapshot or wrong status: %+v", disabled)
	}

	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/enable", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var enabled patchConnectionBody
	if err := json.NewDecoder(resp.Body).Decode(&enabled); err != nil {
		t.Fatalf("decode enable response: %v", err)
	}
	if enabled.Status != string(connections.StatusActive) ||
		enabled.ServerVersion != conn.ServerVersion || enabled.LastDiscoveryAt == nil {
		t.Fatalf("enable changed snapshot or wrong status: %+v", enabled)
	}

	for _, action := range []string{"connection.disabled", "connection.enabled"} {
		events, err := audit.NewWriter().List(t.Context(), env.pool,
			audit.Filter{ConnectionID: &conn.ID, Actions: []string{action}}, 10, 0)
		if err != nil || len(events) != 1 {
			t.Fatalf("%s audit events = %d, err=%v", action, len(events), err)
		}
	}
}

func TestIntegrationConnectionStatusRequiresAdminAndValidTransition(t *testing.T) {
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled})
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn := createPatchConnection(t, env, connections.StatusActive)

	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/enable", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}
