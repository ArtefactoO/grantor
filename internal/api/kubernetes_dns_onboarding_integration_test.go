//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func TestIntegrationKubernetesDNSOnboardingBindsDerivedConnectorGuard(t *testing.T) {
	env := newScopeTestEnv(t, newTestVault(t), policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "kubernetes-dns-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	endpoint := "database.monitor.svc.cluster.local:5432"
	body := map[string]any{"name": "headless-fixture", "owner_type": "service", "owner_id": principalID, "environment": environment,
		"username": "fixture-admin", "password": "synthetic-headless-fixture", "engine": "fake", "endpoints": []string{endpoint},
		"execution_mode": "connector", "tls_config": map[string]string{"mode": "disabled"}}
	response := env.do(t, http.MethodPost, "/api/v1/connection-credential-sources", body, &admin, true)
	requireStatus(t, response, http.StatusCreated)
	var source struct {
		ID     uuid.UUID `json:"id"`
		Target struct {
			NetworkGuard string `json:"network_guard"`
		} `json:"target"`
	}
	if err := json.NewDecoder(response.Body).Decode(&source); err != nil {
		t.Fatal(err)
	}
	if source.Target.NetworkGuard != "private-kubernetes-dns.v1" {
		t.Fatal("approved immutable source lacks derived guard")
	}
	request := onboardingRequest(environment, source.ID)
	request["endpoints"], request["execution_mode"], request["tls_config"] = []string{endpoint}, "connector", map[string]string{"mode": "disabled"}
	response = env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", request, token)
	requireStatus(t, response, http.StatusAccepted)
	receipt := readOnboardingReceipt(t, response)
	connection, err := connections.NewStore().Get(t.Context(), env.pool, receipt.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	if connection.ExecutionMode != "connector" || len(connection.Endpoints) != 1 || connection.Endpoints[0] != endpoint {
		t.Fatal("onboarding redirected the approved DNS target")
	}
	var persisted json.RawMessage
	if err := env.pool.QueryRow(t.Context(), "SELECT spec FROM connection_registrations WHERE id=$1", receipt.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	var comparison struct {
		NetworkGuard string `json:"network_guard"`
	}
	if err := json.Unmarshal(persisted, &comparison); err != nil || comparison.NetworkGuard != source.Target.NetworkGuard {
		t.Fatal("registration omitted immutable transport policy")
	}

	// The source approval cannot be reused in direct mode, even with identical
	// DNS and a fresh request identifier; it must not create a second connection.
	request["registration_key"], request["request_id"], request["execution_mode"] = "direct:"+uuid.NewString(), uuid.NewString(), "direct"
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", request, token), http.StatusForbidden)
	request["network_guard"] = "private-kubernetes-dns.v1"
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", request, token), http.StatusBadRequest)
}
