//go:build integration

package api_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func seedPostgresProfilesConnection(t *testing.T, env *testEnv) (connections.Connection, rolepolicies.Policy) {
	t.Helper()
	template := postgresconfig.RolePolicyTemplate{
		Key: "reports-read", Name: "Reports read", Description: "Existing unrelated policy", RoleName: "r_reports", Database: "reports",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_owner"}, Profile: "read",
	}
	config, err := json.Marshal(map[string]any{"database": "postgres", postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{template}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "standard-profiles-" + uuid.NewString(), Engine: "postgres", Environment: "itest",
		Endpoints: []string{"target-postgres:5432"}, DiscoveryConfig: config,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	if _, err := env.pool.Exec(t.Context(), `update connections set status='active', last_discovery_at=$2,
		server_version='17.0',topology='{"system_identifier":"7429012345678901234","postgres_provisioning_authority":{"status":"confirmed"}}' where id=$1`, conn.ID, at); err != nil {
		t.Fatal(err)
	}
	snapshot := &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{Kind: "login", EngineIdentity: "app_owner"}, {Kind: "group", EngineIdentity: "r_reports"}},
		Resources: []adapter.ObservedResource{
			{Kind: "database", ExternalID: "db:app", Name: "app", CanonicalPath: "app", Attributes: map[string]any{"owner": "app_owner", "database_oid": 42, "owner_oid": 17}},
			{Kind: "schema", ExternalID: "schema:app.public", Name: "public", ParentExternalID: "db:app", CanonicalPath: "app.public", Attributes: map[string]any{"owner": "app_owner"}},
		},
		Permissions: []adapter.ObservedPermission{{ExternalID: "role:r_reports", Name: "r_reports"}},
	}
	if _, err := inventory.NewStore().UpsertSnapshot(t.Context(), env.pool, conn.ID, snapshot, at); err != nil {
		t.Fatal(err)
	}
	spec := adapter.RolePolicySpec{Engine: "postgres", Key: template.Key, Name: template.Name, Description: template.Description,
		RoleName: template.RoleName, Database: template.Database, Schemas: template.Schemas, OwnerRoles: template.OwnerRoles, CreatorRoles: template.CreatorRoles, Profile: template.Profile}
	if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID, []adapter.ObservedRolePolicy{{
		ExternalID: "role:r_reports", Spec: spec, ExpectedFingerprint: "reports-exact", ObservedFingerprint: "reports-exact", Exact: true, ApplySupported: true,
		Summary: map[string]any{"role": map[string]any{"exists": true, "safe": true}},
	}}, at); err != nil {
		t.Fatal(err)
	}
	stored, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, template.Key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	return conn, stored
}

func standardProfilesBody() map[string]any {
	return map[string]any{"request_id": uuid.New(), "database": "app", "expected_target_identity": "postgres:system:7429012345678901234"}
}

func issueProfilesPersonalKey(t *testing.T, env *testEnv, issuer string, role auth.Role, environments []string) string {
	t.Helper()
	owner := auth.Session{Issuer: issuer, Subject: uuid.NewString(), Username: "profiles-admin", Email: "profiles@example.test", Role: role,
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	body := map[string]any{"name": "profiles", "role": role, "expires_at": time.Now().Add(30 * time.Minute), "environments": environments}
	response := env.do(t, http.MethodPost, "/api/v1/me/api-keys", body, &owner, true)
	requireStatus(t, response, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil || issued.Token == "" {
		t.Fatalf("issue personal key: %v", err)
	}
	return issued.Token
}

func TestIntegrationPostgresProfilesPersonalKeyPreservesConfigAndPolicies(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	conn, beforePolicy := seedPostgresProfilesConnection(t, env)
	token := issueProfilesPersonalKey(t, env, issuer, auth.RoleAdmin, []string{"itest"})
	path := "/api/v1/connections/" + conn.ID.String()
	requireStatus(t, env.doBearer(t, http.MethodPatch, path, patchBody(conn.UpdatedAt, map[string]any{"discovery_config": json.RawMessage(conn.DiscoveryConfig)}), token), http.StatusForbidden)
	body := standardProfilesBody()
	var first struct {
		OperationID  uuid.UUID `json:"operation_id"`
		Keys         []string  `json:"template_keys"`
		RolesCreated bool      `json:"roles_created"`
	}
	for range 2 {
		response := env.doBearer(t, http.MethodPost, path+"/postgres/access-profiles", body, token)
		requireStatus(t, response, http.StatusAccepted)
		var got struct {
			OperationID  uuid.UUID `json:"operation_id"`
			Keys         []string  `json:"template_keys"`
			RolesCreated bool      `json:"roles_created"`
		}
		if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if first.OperationID != uuid.Nil && got.OperationID != first.OperationID {
			t.Fatal("request replay enqueued a different operation")
		}
		if len(got.Keys) != 2 || got.RolesCreated {
			t.Fatalf("templates unexpectedly created target roles: %+v", got)
		}
		first = got
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != connections.StatusDiscovering || stored.LastDiscoveryAt != nil || stored.ServerVersion != "" || string(stored.Topology) != "{}" {
		t.Fatalf("profile configuration retained stale authority: %+v", stored)
	}
	if !reflect.DeepEqual(conn.Endpoints, stored.Endpoints) || conn.Environment != stored.Environment || conn.VaultAdminPath != stored.VaultAdminPath {
		t.Fatal("profile configuration changed target or credentials")
	}
	var attributes map[string]any
	if err := json.Unmarshal(stored.DiscoveryConfig, &attributes); err != nil || attributes["database"] != "postgres" {
		t.Fatalf("unrelated configuration lost: %s, %v", stored.DiscoveryConfig, err)
	}
	templates, err := postgresconfig.FromAttributes(attributes)
	if err != nil || len(templates) != 3 || templates[0].Key != beforePolicy.TemplateKey || templates[1].RoleName != "r_app" || templates[2].RoleName != "rw_app" {
		t.Fatalf("appended templates = %+v, %v", templates, err)
	}
	policies, err := rolepolicies.NewStore().List(t.Context(), env.pool, conn.ID)
	if err != nil || len(policies) != 1 || !reflect.DeepEqual(policies[0], beforePolicy) {
		t.Fatalf("unrelated role policy changed: %+v, %v", policies, err)
	}
	var operationCount, riverCount, accountCount int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).Scan(&operationCount); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from river_job where args->>'operation_id'=$1`, first.OperationID.String()).Scan(&riverCount); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from accounts where connection_id=$1`, conn.ID).Scan(&accountCount); err != nil {
		t.Fatal(err)
	}
	if operationCount != 1 || riverCount != 1 || accountCount != 2 {
		t.Fatalf("side effects operations=%d river=%d accounts=%d", operationCount, riverCount, accountCount)
	}
	changedBody := standardProfilesBody()
	changedBody["request_id"] = body["request_id"]
	changedBody["profiles"] = []string{"read"}
	requireStatus(t, env.doBearer(t, http.MethodPost, path+"/postgres/access-profiles", changedBody, token), http.StatusConflict)
	if _, err := env.pool.Exec(t.Context(), `update connections set topology='{"system_identifier":"7429012345678901235"}' where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodPost, path+"/postgres/access-profiles", body, token), http.StatusConflict)
	if _, err := env.pool.Exec(t.Context(), `update connections set topology='{}', endpoints='["different-postgres:5432"]' where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodPost, path+"/postgres/access-profiles", body, token), http.StatusConflict)
}

func TestIntegrationPostgresProfilesRejectsScopeAndBroadConfiguration(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	conn, _ := seedPostgresProfilesConnection(t, env)
	path := "/api/v1/connections/" + conn.ID.String() + "/postgres/access-profiles"
	denied := issueProfilesPersonalKey(t, env, issuer, auth.RoleAdmin, []string{"other-environment"})
	requireStatus(t, env.doBearer(t, http.MethodPost, path, standardProfilesBody(), denied), http.StatusForbidden)
	operator := issueProfilesPersonalKey(t, env, issuer, auth.RoleOperator, []string{"itest"})
	requireStatus(t, env.doBearer(t, http.MethodPost, path, standardProfilesBody(), operator), http.StatusForbidden)
	admin := issueProfilesPersonalKey(t, env, issuer, auth.RoleAdmin, []string{"itest"})
	for _, tc := range []struct {
		field  string
		value  any
		status int
	}{
		{"discovery_config", map[string]any{"database": "other"}, http.StatusBadRequest},
		{"sql", "GRANT ALL", http.StatusBadRequest},
		{"admin_credential", map[string]any{"username": "other"}, http.StatusBadRequest},
		{"profiles", []string{"owner"}, http.StatusBadRequest},
		{"database", "missing", http.StatusConflict},
		{"schemas", []string{"missing"}, http.StatusConflict},
		{"owner_roles", []string{"not_an_owner"}, http.StatusConflict},
		{"creator_roles", []string{"not_an_owner"}, http.StatusConflict},
		{"expected_target_identity", "postgres:system:7429012345678901235", http.StatusConflict},
	} {
		t.Run(tc.field, func(t *testing.T) {
			body := standardProfilesBody()
			body[tc.field] = tc.value
			requireStatus(t, env.doBearer(t, http.MethodPost, path, body, admin), tc.status)
		})
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || !stored.UpdatedAt.Equal(conn.UpdatedAt) || !reflect.DeepEqual(stored.DiscoveryConfig, conn.DiscoveryConfig) {
		t.Fatalf("rejected requests changed connection: %+v, %v", stored, err)
	}
}

func TestIntegrationPostgresProfilesProtectsPolicyTransitionsAndRoleCollisions(t *testing.T) {
	for _, mode := range []string{"transition", "collision", "owner_missing", "database_missing", "schema_missing", "schema_outside_database"} {
		t.Run(mode, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, p := seedPostgresProfilesConnection(t, env)
			switch mode {
			case "transition":
				op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{Kind: jobs.KindPostgresRolePolicyAdoptV2, ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := rolepolicies.NewStore().Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{ConnectionID: conn.ID, TemplateKey: p.TemplateKey, Action: rolepolicies.ActionAdopt, OperationID: op.ID, Version: p.Version, ObservedFingerprint: p.ObservedFingerprint}); err != nil {
					t.Fatal(err)
				}
			case "collision":
				if _, err := env.pool.Exec(t.Context(), `update connections set discovery_config=jsonb_set(discovery_config,'{postgres_role_policy_templates,0,role_name}','"r_app"') where id=$1`, conn.ID); err != nil {
					t.Fatal(err)
				}
			case "owner_missing":
				if _, err := env.pool.Exec(t.Context(), `update accounts set status='missing' where connection_id=$1 and engine_identity='app_owner'`, conn.ID); err != nil {
					t.Fatal(err)
				}
			case "database_missing", "schema_missing":
				kind := strings.TrimSuffix(mode, "_missing")
				if _, err := env.pool.Exec(t.Context(), `update resources set status='missing' where connection_id=$1 and kind=$2`, conn.ID, kind); err != nil {
					t.Fatal(err)
				}
			case "schema_outside_database":
				if _, err := env.pool.Exec(t.Context(), `update resources set parent_id=null where connection_id=$1 and kind='schema'`, conn.ID); err != nil {
					t.Fatal(err)
				}
			}
			before, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			admin := session(auth.RoleAdmin)
			requireStatus(t, env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/postgres/access-profiles", standardProfilesBody(), &admin, true), http.StatusConflict)
			after, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("conflict changed connection: %v", err)
			}
		})
	}
}

func TestIntegrationPostgresProfilesEnqueueFailureRollsBackConfiguration(t *testing.T) {
	dispatcher := &countingDispatcher{err: errors.New("synthetic enqueue failure")}
	env := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, dispatcher: dispatcher})
	conn, _ := seedPostgresProfilesConnection(t, env)
	admin := session(auth.RoleAdmin)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/postgres/access-profiles", standardProfilesBody(), &admin, true), http.StatusInternalServerError)
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || !reflect.DeepEqual(conn, stored) {
		t.Fatalf("enqueue failure retained config or snapshot reset: %v", err)
	}
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("enqueue failure retained operation: %d %v", count, err)
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{ConnectionID: &conn.ID, Actions: []string{"postgres.standard_profiles_requested"}}, 10, 0)
	if err != nil || len(events) != 0 {
		t.Fatalf("enqueue failure retained success audit: %d %v", len(events), err)
	}
	if dispatcher.calls.Load() != 1 || !strings.Contains(string(stored.DiscoveryConfig), "reports-read") {
		t.Fatal("rollback test did not exercise the append and enqueue path")
	}
}

func TestIntegrationPostgresProfilesAcceptsPostgresOwnerAndRejectsVirtualCreator(t *testing.T) {
	for _, virtualCreator := range []bool{false, true} {
		t.Run(fmt.Sprintf("virtual_creator=%v", virtualCreator), func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, _ := seedPostgresProfilesConnection(t, env)
			if _, err := env.pool.Exec(t.Context(), `insert into accounts(connection_id,kind,engine_identity,status,ownership,attributes) values ($1,'login','postgres','active','unmanaged','{"superuser":true}')`, conn.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := env.pool.Exec(t.Context(), `update resources set attributes=attributes || '{"owner":"postgres","owner_oid":10}'::jsonb where connection_id=$1 and kind='database'`, conn.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := env.pool.Exec(t.Context(), `update resources set attributes=attributes || '{"owner":"pg_database_owner"}'::jsonb where connection_id=$1 and kind='schema'`, conn.ID); err != nil {
				t.Fatal(err)
			}
			body := standardProfilesBody()
			wantStatus := http.StatusAccepted
			if virtualCreator {
				body["creator_roles"] = []string{"pg_database_owner"}
				wantStatus = http.StatusConflict
			}
			admin := session(auth.RoleAdmin)
			requireStatus(t, env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/postgres/access-profiles", body, &admin, true), wantStatus)
			stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			var attrs map[string]any
			if err := json.Unmarshal(stored.DiscoveryConfig, &attrs); err != nil {
				t.Fatal(err)
			}
			templates, err := postgresconfig.FromAttributes(attrs)
			if err != nil {
				t.Fatal(err)
			}
			if virtualCreator {
				if len(templates) != 1 || stored.Status != connections.StatusActive {
					t.Fatal("virtual creator rejection changed configuration")
				}
				return
			}
			if len(templates) != 3 {
				t.Fatalf("templates = %+v", templates)
			}
			for _, template := range templates[1:] {
				if !reflect.DeepEqual(template.OwnerRoles, []string{"postgres"}) || !reflect.DeepEqual(template.CreatorRoles, []string{"postgres"}) {
					t.Fatalf("database owner was not used as owner/creator: %+v", template)
				}
			}
			var mutatingOperations int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind<>$2`, conn.ID, jobs.KindConnectionDiscover).Scan(&mutatingOperations); err != nil || mutatingOperations != 0 {
				t.Fatalf("profile setup mutated owner identity or grants: %d %v", mutatingOperations, err)
			}
		})
	}
}
