//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	_ "github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

type postgresZeroWriteCounts struct {
	accounts, resources, bindings, policies, operations, jobs int
}

func postgresMutationCounts(t *testing.T, env *testEnv) postgresZeroWriteCounts {
	t.Helper()
	var c postgresZeroWriteCounts
	err := env.pool.QueryRow(t.Context(), `select
		(select count(*) from accounts), (select count(*) from resources),
		(select count(*) from bindings), (select count(*) from role_policies),
		(select count(*) from operations), (select count(*) from river_job)`).Scan(
		&c.accounts, &c.resources, &c.bindings, &c.policies, &c.operations, &c.jobs)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func postgresAuthorityConnection(t *testing.T, env *testEnv,
	status adapter.ProvisioningAuthorityStatus, reason adapter.ProvisioningAuthorityReason,
) connections.Connection {
	t.Helper()
	conn := activeFakeConnection(t, env.pool)
	if _, err := env.pool.Exec(t.Context(), `update connections set engine='postgres',topology='{}',
		discovery_config='{}',capabilities='[]' where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	conn, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	observedAdmin := "grantor"
	if status == adapter.ProvisioningAuthorityUnknown {
		observedAdmin = ""
	}
	topology, err := json.Marshal(map[string]any{
		"system_identifier":                   "123456789",
		"admin_credential_canonical_identity": "grantor",
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
			Status: status, Reason: reason, ObservedAt: observedAt,
			ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: observedAdmin,
			CredentialIncarnation: 9, ConfigIncarnation: connections.ConfigIncarnation(conn),
			TargetIdentity: "postgres:system:123456789",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	caps, _ := json.Marshal([]string{
		string(adapter.CapPostgresSuperuserDirectV1), string(adapter.CapAccountCreate),
		string(adapter.CapAccountRestore), string(adapter.CapRoleCreate),
		string(adapter.ResourceCapability("create", "database")),
		string(adapter.CapRolePolicyApply), string(adapter.CapRolePolicyCreate), string(adapter.CapAccessGrant),
	})
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2,last_discovery_at=$3,
		capabilities=$4,updated_at=now() where id=$1`, conn.ID, topology, observedAt, caps); err != nil {
		t.Fatal(err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestIntegrationPostgresKnownBadAuthorityCreatesNothing(t *testing.T) {
	for _, authority := range []struct {
		name   string
		status adapter.ProvisioningAuthorityStatus
		reason adapter.ProvisioningAuthorityReason
	}{
		{"insufficient", adapter.ProvisioningAuthorityInsufficient, adapter.ProvisioningAuthoritySuperuserRequired},
		{"unknown", adapter.ProvisioningAuthorityUnknown, adapter.ProvisioningAuthorityProbeFailed},
		{"invalid", adapter.ProvisioningAuthorityInvalidCurrentVersion, adapter.ProvisioningAuthorityReadOnlyTarget},
	} {
		t.Run(authority.name, func(t *testing.T) {
			env := newTestEnv(t, nil) // nil Vault proves the guard runs before any credential write.
			conn := postgresAuthorityConnection(t, env, authority.status, authority.reason)
			admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
			store := inventory.NewStore()
			tombstone, err := store.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
				ConnectionID: conn.ID, EngineIdentity: "restore_" + uuid.NewString(), CredentialMode: inventory.CredentialModeGenerated,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.MarkAccountDeleted(t.Context(), env.pool, tombstone.ID, "seed", "authority matrix"); err != nil {
				t.Fatal(err)
			}
			principal := createPrincipalWithSubject(t, env.pool, "authority-"+uniqueSuffix())
			permission := findPermission(t, env.pool, conn.ID, "role:app-readonly")
			requests := []struct {
				name, method, path string
				body               any
				sess               auth.Session
			}{
				{"account", http.MethodPost, "/api/v1/accounts", map[string]any{
					"connection_id": conn.ID, "engine_identity": "new_" + uuid.NewString(),
					"credential": map[string]any{"mode": "generated"}}, operator},
				{"restore", http.MethodPost, "/api/v1/accounts/" + tombstone.ID.String() + "/restore",
					map[string]any{"credential": map[string]any{"mode": "generated"}}, admin},
				{"role", http.MethodPost, "/api/v1/connections/" + conn.ID.String() + "/roles",
					map[string]any{"name": "r_" + uuid.NewString()}, admin},
				{"database", http.MethodPost, "/api/v1/connections/" + conn.ID.String() + "/resources",
					map[string]any{"kind": "database", "name": "db_" + uuid.NewString(), "owner": "app_owner"}, admin},
				{"database_roles", http.MethodPost, "/api/v1/connections/" + conn.ID.String() + "/resources/database-with-roles",
					map[string]any{"name": "db_pair", "owner": "app_owner", "create_default_roles": true,
						"request_id": uuid.NewString(), "updated_at": conn.UpdatedAt,
						"expected_target_identity": "postgres:system:123456789"}, admin},
				{"policy", http.MethodPost, "/api/v1/connections/" + conn.ID.String() + "/role-policies/missing/apply",
					map[string]any{"request_id": uuid.NewString(), "version": 1,
						"observed_fingerprint": "observed", "confirm": true}, admin},
				{"principal", http.MethodPost, "/api/v1/principals/" + principal.ID.String() + "/access",
					map[string]any{"items": []map[string]any{{"connection_id": conn.ID, "permission_id": permission.ID}}}, operator},
				{"manifest", http.MethodPost, "/api/v1/access/apply", map[string]any{
					"version": "v1", "environment": conn.Environment,
					"entries": []map[string]any{{"principal": principal.ExternalSubject,
						"connection": conn.DisplayName, "role": permission.ExternalID}}}, operator},
			}
			for _, request := range requests {
				t.Run(request.name, func(t *testing.T) {
					before := postgresMutationCounts(t, env)
					resp := env.do(t, request.method, request.path, request.body, &request.sess, true)
					requireStatus(t, resp, http.StatusConflict)
					after := postgresMutationCounts(t, env)
					if after != before {
						t.Fatalf("known-bad authority persisted state: before=%+v after=%+v", before, after)
					}
				})
			}
		})
	}
}
