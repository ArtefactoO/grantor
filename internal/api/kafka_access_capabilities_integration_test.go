//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func TestIntegrationKafkaDisabledAuthorizerRejectsAccessBeforeSideEffects(t *testing.T) {
	// No Vault client: a principal grant reaching credential preparation would
	// return 503. A 409 therefore also proves rejection precedes secret writes.
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := createKafkaPatchConnection(t, env, `{"acl_authorizer":"disabled"}`)
	var err error
	conn, err = connections.NewStore().Update(t.Context(), env.pool, conn.ID, connections.UpdateParams{
		DisplayName: conn.DisplayName, Environment: conn.Environment,
		Tags: conn.Tags, Endpoints: conn.Endpoints, TLSConfig: conn.TLSConfig,
		DiscoveryConfig: json.RawMessage(`{"sasl_mechanism":"plain","security_protocol":"sasl_plaintext"}`),
		Capabilities:    conn.Capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Preserve a stale assignable inventory row to prove the effective
	// connection guard also rejects catalogs produced by older releases.
	seedFakeInventory(t, env.pool, conn.ID)
	account := findAccount(t, env.pool, conn.ID, "svc-a")
	permission := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	principal := createPrincipalRow(t, env.pool, "external-kafka-monitor")
	binding, _, err := inventory.NewStore().EnsureBinding(t.Context(), env.pool, inventory.EnsureBindingParams{
		AccountID: account.ID, PermissionID: permission.ID, DesiredState: inventory.BindingPresent,
		Source: string(inventory.BindingSourceService),
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/bindings", map[string]any{"account_id": account.ID, "permission_id": permission.ID}},
		{http.MethodPost, "/api/v1/principals/" + principal.ID.String() + "/access", map[string]any{"items": []map[string]any{{"connection_id": conn.ID, "permission_id": permission.ID}}}},
		{http.MethodDelete, "/api/v1/bindings/" + binding.ID.String(), nil},
		{http.MethodPost, "/api/v1/accounts/" + account.ID.String() + "/roles", map[string]any{"remove_binding_ids": []string{binding.ID.String()}}},
	}
	for _, test := range tests {
		t.Run(test.method+test.path, func(t *testing.T) {
			requireStatus(t, env.do(t, test.method, test.path, test.body, &operator, true), http.StatusConflict)
		})
	}
	var operations int
	if err := env.pool.QueryRow(t.Context(), "SELECT count(*) FROM operations WHERE connection_id=$1 OR principal_id=$2", conn.ID, principal.ID).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != 0 {
		t.Fatalf("rejected access created %d operations", operations)
	}
	current, err := inventory.NewStore().GetBinding(t.Context(), env.pool, binding.ID)
	if err != nil || current.DesiredState == nil || *current.DesiredState != inventory.BindingPresent {
		t.Fatal("rejected revoke changed desired access")
	}
	accounts, err := inventory.NewStore().ListAccountsByPrincipal(t.Context(), env.pool, principal.ID)
	if err != nil || len(accounts) != 0 {
		t.Fatal("rejected principal grant created an account")
	}
}
