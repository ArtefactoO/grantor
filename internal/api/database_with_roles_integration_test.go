//go:build integration

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	_ "github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func databaseWithRolesConnection(t *testing.T, env *testEnv) connections.Connection {
	t.Helper()
	conn := activeFakeConnection(t, env.pool)
	_, err := env.pool.Exec(t.Context(), `update connections set engine='postgres',
		topology='{}', updated_at=now(), capabilities='[]', discovery_config='{}' where id=$1`, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	topology, err := json.Marshal(map[string]any{
		"system_identifier":                        "123456789",
		"admin_credential_canonical_identity":      "grantor",
		"postgres_role_policy_catalog_fingerprint": postgresconfig.CatalogFingerprint(nil),
		"postgres_role_policy_apply_supported":     true,
		"postgres_role_policy_create_supported":    true,
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
			Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
			ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 1, ConfigIncarnation: connections.ConfigIncarnation(conn),
			TargetIdentity: "postgres:system:123456789",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, _ := json.Marshal([]string{
		string(adapter.CapPostgresSuperuserDirectV1),
		string(adapter.ResourceCapability("create", "database")),
		string(adapter.CapRolePolicyCreate),
	})
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2,last_discovery_at=$3,
		capabilities=$4 where id=$1`, conn.ID, topology, observedAt, capabilities); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `insert into accounts(connection_id,kind,engine_identity,status,ownership,attributes)
		values($1,'group','app_owner','active','unmanaged','{"role_oid":17}') on conflict do nothing`, conn.ID); err != nil {
		t.Fatal(err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func databaseWithRolesBody(conn connections.Connection) map[string]any {
	return map[string]any{
		"name": "itest_" + uniqueSuffix()[:8], "owner": "app_owner", "create_default_roles": true,
		"request_id": uuid.NewString(), "updated_at": conn.UpdatedAt,
		"expected_target_identity": connections.TargetIdentity(conn),
	}
}

type databaseWithRolesResponse struct {
	ResourceID         uuid.UUID `json:"resource_id"`
	OperationID        uuid.UUID `json:"operation_id"`
	CreateDefaultRoles bool      `json:"create_default_roles"`
}

func TestIntegrationDatabaseWithRolesRequestIsDurableAndIdempotent(t *testing.T) {
	env := newTestEnv(t, nil)
	conn := databaseWithRolesConnection(t, env)
	admin := session(auth.RoleAdmin)
	path := "/api/v1/connections/" + conn.ID.String() + "/resources/database-with-roles"
	body := databaseWithRolesBody(conn)
	resp := env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var accepted databaseWithRolesResponse
	if err := json.Unmarshal(readBody(t, resp), &accepted); err != nil || !accepted.CreateDefaultRoles {
		t.Fatalf("response %+v: %v", accepted, err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, accepted.OperationID)
	if err != nil || op.Kind != jobs.KindPostgresDatabaseCreateWithRolesV2 || op.ResourceID == nil || *op.ResourceID != accepted.ResourceID {
		t.Fatalf("not a durable combined workflow: %+v / %v", op, err)
	}
	row, err := databaseprovisioning.NewStore().Get(t.Context(), env.pool, op.ID)
	if err != nil || row.Phase != "pending" || row.DatabaseCreateStarted || row.DatabaseCreated {
		t.Fatalf("API must only enqueue, never manufacture target proof: %+v / %v", row, err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set updated_at=now() where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	// Lost response: the same request wins before its now-stale updated_at.
	resp = env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var replay databaseWithRolesResponse
	if err := json.Unmarshal(readBody(t, resp), &replay); err != nil || replay != accepted {
		t.Fatalf("replay changed workflow identity: %+v / %v", replay, err)
	}
	var jobsCount, audits int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from river_job where args->>'operation_id'=$1`, op.ID.String()).Scan(&jobsCount); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from audit_events where operation_id=$1 and action='database.provisioning_requested'`, op.ID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if jobsCount != 1 || audits != 1 {
		t.Fatalf("duplicate queue/audit: %d/%d", jobsCount, audits)
	}
	body["owner"] = "another_owner"
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
}

func TestIntegrationDatabaseWithRolesRejectsBeforeReservation(t *testing.T) {
	for _, scenario := range []string{"viewer", "operator", "csrf", "non_postgres", "stale_cas", "wrong_target", "no_identity", "long_name", "no_owner", "unknown_field", "false_flag", "catalog_collision"} {
		t.Run(scenario, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn := databaseWithRolesConnection(t, env)
			body := databaseWithRolesBody(conn)
			sess := session(auth.RoleAdmin)
			csrf, want := true, http.StatusConflict
			switch scenario {
			case "viewer":
				sess, want = session(auth.RoleViewer), http.StatusForbidden
			case "operator":
				sess, want = session(auth.RoleOperator), http.StatusForbidden
			case "csrf":
				csrf, want = false, http.StatusForbidden
			case "non_postgres":
				if _, err := env.pool.Exec(t.Context(), `update connections set engine='fake' where id=$1`, conn.ID); err != nil {
					t.Fatal(err)
				}
			case "stale_cas":
				body["updated_at"] = conn.UpdatedAt.Add(-time.Second)
			case "wrong_target":
				body["expected_target_identity"] = "postgres:system:999"
			case "no_identity":
				body["expected_target_identity"], want = "", http.StatusBadRequest
			case "long_name":
				body["name"], want = strings.Repeat("a", 61), http.StatusBadRequest
			case "no_owner":
				delete(body, "owner")
				want = http.StatusBadRequest
			case "unknown_field":
				body["sql"], want = "not accepted", http.StatusBadRequest
			case "false_flag":
				body["create_default_roles"], want = false, http.StatusBadRequest
			case "catalog_collision":
				name := body["name"].(string)
				config, err := json.Marshal(map[string]any{"postgres_role_policy_templates": []postgresconfig.RolePolicyTemplate{{
					Key: "existing", Name: "Existing", Description: "Keep intact", RoleName: "r_" + name,
					Database: "another_db", Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
					CreatorRoles: []string{"app_owner"}, Profile: postgresconfig.ProfileRead,
				}}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := env.pool.Exec(t.Context(), `update connections set discovery_config=$2 where id=$1`, conn.ID, config); err != nil {
					t.Fatal(err)
				}
			}
			resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/resources/database-with-roles", body, &sess, csrf)
			requireStatus(t, resp, want)
			var count int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from database_provisionings where connection_id=$1`, conn.ID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("rejection persisted a workflow: %d / %v", count, err)
			}
		})
	}
}

func TestIntegrationDatabaseWithRolesConcurrentRequest(t *testing.T) {
	env := newTestEnv(t, nil)
	conn := databaseWithRolesConnection(t, env)
	body := databaseWithRolesBody(conn)
	admin := session(auth.RoleAdmin)
	ids := make(chan uuid.UUID, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/resources/database-with-roles", body, &admin, true)
			requireStatus(t, resp, http.StatusAccepted)
			var result databaseWithRolesResponse
			if err := json.Unmarshal(readBody(t, resp), &result); err != nil {
				t.Error(err)
			}
			ids <- result.OperationID
		})
	}
	wg.Wait()
	close(ids)
	first := <-ids
	if second := <-ids; first == uuid.Nil || first != second {
		t.Fatalf("concurrent requests diverged: %s/%s", first, second)
	}
}

// TestIntegrationLegacyDatabaseWithRolesHistoryProjectsJournal proves that
// retiring the helper-era executor does not erase its durable progress. Both
// detail and list endpoints retain the same journal projection while marking
// the old root explicitly non-retryable.
func TestIntegrationLegacyDatabaseWithRolesHistoryProjectsJournal(t *testing.T) {
	env := newTestEnv(t, nil)
	conn := databaseWithRolesConnection(t, env)
	name := "legacy_" + uniqueSuffix()[:8]
	resource, err := inventory.NewStore().CreatePlannedResource(t.Context(), env.pool,
		inventory.CreatePlannedResourceParams{
			ConnectionID:  conn.ID,
			Kind:          "database",
			ExternalID:    "db:" + name,
			Name:          name,
			CanonicalPath: name,
		})
	if err != nil {
		t.Fatalf("create historical planned resource: %v", err)
	}
	payload, err := json.Marshal(jobs.DatabaseCreateWithRolesPayload{
		ResourceID: resource.ID, Name: name, ExpectedTargetIdentity: connections.TargetIdentity(conn),
	})
	if err != nil {
		t.Fatalf("marshal historical payload: %v", err)
	}
	opStore := operations.NewStore()
	op, _, err := opStore.Create(t.Context(), env.pool, operations.CreateParams{
		Kind: jobs.KindDatabaseCreateWithRoles, ConnectionID: &conn.ID, ResourceID: &resource.ID,
		Payload: payload, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create historical operation: %v", err)
	}
	journal := databaseprovisioning.NewStore()
	if err := journal.Create(t.Context(), env.pool, op.ID, resource.ID, conn.ID); err != nil {
		t.Fatalf("create historical journal: %v", err)
	}
	if err := journal.BeginDatabase(t.Context(), env.pool, op.ID); err != nil {
		t.Fatalf("start historical database stage: %v", err)
	}
	// Simulate a pre-v2 confirmed row after migration: its owner OID is
	// intentionally unknown (0) and must remain readable without name-based
	// backfill to a potentially reincarnated role.
	if _, err := env.pool.Exec(t.Context(), `update database_provisionings set
		database_created=true,database_oid=4242,database_owner='legacy_owner',
		target_identity=$2,phase='database_created' where operation_id=$1`, op.ID,
		connections.TargetIdentity(conn)); err != nil {
		t.Fatalf("seed historical database stage: %v", err)
	}
	if err := journal.SetError(t.Context(), env.pool, op.ID, "legacy_executor_retired"); err != nil {
		t.Fatalf("mark historical journal error: %v", err)
	}
	finishOperation(t, env, op.ID, operations.StatusFailed)

	type projection struct {
		ID              uuid.UUID `json:"id"`
		AggregateStatus string    `json:"aggregate_status"`
		Retryable       *bool     `json:"retryable"`
		Progress        *struct {
			Phase            string `json:"phase"`
			DatabaseName     string `json:"database_name"`
			ReadRole         string `json:"read_role"`
			ReadWriteRole    string `json:"read_write_role"`
			DatabaseCreated  bool   `json:"database_created"`
			ReadCreated      bool   `json:"read_created"`
			ReadWriteCreated bool   `json:"read_write_created"`
			ErrorCode        string `json:"error_code"`
		} `json:"database_provisioning"`
	}
	assertProjection := func(where string, got projection, aggregate bool) {
		t.Helper()
		if got.ID != op.ID || got.Retryable == nil || *got.Retryable || got.Progress == nil {
			t.Fatalf("%s projection = %+v, want journal and explicit retryable=false", where, got)
		}
		if aggregate && got.AggregateStatus != string(operations.StatusFailed) {
			t.Errorf("%s aggregate_status = %q, want failed", where, got.AggregateStatus)
		}
		if got.Progress.Phase != "database_created" || got.Progress.DatabaseName != name ||
			got.Progress.ReadRole != "r_"+name || got.Progress.ReadWriteRole != "rw_"+name ||
			!got.Progress.DatabaseCreated || got.Progress.ReadCreated || got.Progress.ReadWriteCreated ||
			got.Progress.ErrorCode != "legacy_executor_retired" {
			t.Errorf("%s database_provisioning = %+v, want exact durable journal", where, got.Progress)
		}
	}

	viewer := session(auth.RoleViewer)
	resp := env.do(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var detail projection
	if err := json.Unmarshal(readBody(t, resp), &detail); err != nil {
		t.Fatalf("decode historical detail: %v", err)
	}
	assertProjection("detail", detail, true)

	resp = env.do(t, http.MethodGet, fmt.Sprintf(
		"/api/v1/operations?connection_id=%s&kind=%s&limit=10", conn.ID, jobs.KindDatabaseCreateWithRoles),
		nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Operations []projection `json:"operations"`
	}
	if err := json.Unmarshal(readBody(t, resp), &list); err != nil {
		t.Fatalf("decode historical list: %v", err)
	}
	if len(list.Operations) != 1 {
		t.Fatalf("historical list rows = %d, want 1", len(list.Operations))
	}
	assertProjection("list", list.Operations[0], false)
}

func TestIntegrationLegacyDatabaseRootStateTableIsTerminal(t *testing.T) {
	for _, state := range []struct {
		name             string
		begin, confirmed bool
		phase            string
	}{
		{name: "not_started", phase: "pending"},
		{name: "outcome_unconfirmed", begin: true, phase: "database_creating"},
		{name: "database_confirmed", begin: true, confirmed: true, phase: "database_created"},
	} {
		t.Run(state.name, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn := databaseWithRolesConnection(t, env)
			name := "legacy_state_" + uniqueSuffix()[:8]
			resource, err := inventory.NewStore().CreatePlannedResource(t.Context(), env.pool,
				inventory.CreatePlannedResourceParams{ConnectionID: conn.ID, Kind: "database",
					ExternalID: "db:" + name, Name: name, CanonicalPath: name})
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(jobs.DatabaseCreateWithRolesPayload{
				ResourceID: resource.ID, Name: name, ExpectedTargetIdentity: connections.TargetIdentity(conn),
			})
			op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
				Kind: jobs.KindDatabaseCreateWithRoles, ConnectionID: &conn.ID, ResourceID: &resource.ID,
				Payload: payload, ActorType: "test", ActorID: t.Name(),
			})
			if err != nil {
				t.Fatal(err)
			}
			journal := databaseprovisioning.NewStore()
			if err := journal.Create(t.Context(), env.pool, op.ID, resource.ID, conn.ID); err != nil {
				t.Fatal(err)
			}
			if state.begin {
				if err := journal.BeginDatabase(t.Context(), env.pool, op.ID); err != nil {
					t.Fatal(err)
				}
			}
			if state.confirmed {
				if err := journal.ConfirmDatabase(t.Context(), env.pool, op.ID, 42, "app_owner", 17,
					connections.TargetIdentity(conn)); err != nil {
					t.Fatal(err)
				}
			}
			if err := journal.SetError(t.Context(), env.pool, op.ID, "legacy_contract_retired"); err != nil {
				t.Fatal(err)
			}
			finishOperation(t, env, op.ID, operations.StatusFailed)
			admin := session(auth.RoleAdmin)
			resp := env.do(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, &admin, false)
			requireStatus(t, resp, http.StatusOK)
			var view struct {
				Retryable bool `json:"retryable"`
				Progress  struct {
					Phase           string `json:"phase"`
					DatabaseCreated bool   `json:"database_created"`
				} `json:"database_provisioning"`
			}
			if err := json.Unmarshal(readBody(t, resp), &view); err != nil || view.Retryable ||
				view.Progress.Phase != state.phase || view.Progress.DatabaseCreated != state.confirmed {
				t.Fatalf("legacy state projection = %+v / %v", view, err)
			}
			requireStatus(t, env.do(t, http.MethodPost,
				"/api/v1/operations/"+op.ID.String()+"/retry", nil, &admin, true), http.StatusConflict)
		})
	}
}

func TestIntegrationDatabaseWithRolesRetryOnlyRoot(t *testing.T) {
	env := newTestEnv(t, nil)
	conn := databaseWithRolesConnection(t, env)
	admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/resources/database-with-roles", databaseWithRolesBody(conn), &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var result databaseWithRolesResponse
	if err := json.Unmarshal(readBody(t, resp), &result); err != nil {
		t.Fatal(err)
	}
	finishOperation(t, env, result.OperationID, operations.StatusFailed)
	if _, err := env.pool.Exec(t.Context(), `update river_job set state='discarded', finalized_at=now() where args->>'operation_id'=$1`, result.OperationID.String()); err != nil {
		t.Fatal(err)
	}
	child, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: jobs.KindPostgresResourceCreateDatabaseForRolesV2, ParentID: &result.OperationID, ConnectionID: &conn.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	finishOperation(t, env, child.ID, operations.StatusFailed)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/operations/"+child.ID.String()+"/retry", nil, &admin, true), http.StatusConflict)
	path := "/api/v1/operations/" + result.OperationID.String() + "/retry"
	requireStatus(t, env.do(t, http.MethodPost, path, nil, &operator, true), http.StatusForbidden)
	if err := databaseprovisioning.NewStore().BeginDatabase(t.Context(), env.pool, result.OperationID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, nil, &admin, true), http.StatusConflict)
	if err := databaseprovisioning.NewStore().ConfirmDatabase(t.Context(), env.pool, result.OperationID, 123, "app_owner", 17, connections.TargetIdentity(conn)); err != nil {
		t.Fatal(err)
	}
	resp = env.do(t, http.MethodGet, "/api/v1/operations/"+result.OperationID.String(), nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)
	var view struct {
		Retryable       bool   `json:"retryable"`
		AggregateStatus string `json:"aggregate_status"`
		Progress        struct {
			DatabaseCreated bool `json:"database_created"`
		} `json:"database_provisioning"`
	}
	if err := json.Unmarshal(readBody(t, resp), &view); err != nil || !view.Retryable || !view.Progress.DatabaseCreated || view.AggregateStatus != "failed" {
		t.Fatalf("incorrect root progress: %+v / %v", view, err)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, nil, &admin, true), http.StatusAccepted)
	requireStatus(t, env.do(t, http.MethodPost, path, nil, &admin, true), http.StatusConflict)
	var childJobs int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from river_job where args->>'operation_id'=$1`, child.ID.String()).Scan(&childJobs); err != nil || childJobs != 0 {
		t.Fatalf("retry queued an inline child: %d / %v", childJobs, err)
	}
}

func TestIntegrationDatabaseRootRetryRearmsPolicyOwnership(t *testing.T) {
	for _, takeover := range []bool{false, true} {
		t.Run(fmt.Sprintf("takeover_%t", takeover), func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, policy := seedRolePolicyAPI(t, env)
			if _, err := env.pool.Exec(t.Context(), `update connections set capabilities=capabilities || $2::jsonb where id=$1`, conn.ID,
				`["resource.create.database"]`); err != nil {
				t.Fatal(err)
			}
			var err error
			conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
			if err != nil {
				t.Fatal(err)
			}
			admin := session(auth.RoleAdmin)
			body := databaseWithRolesBody(conn)
			resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/resources/database-with-roles", body, &admin, true)
			requireStatus(t, resp, http.StatusAccepted)
			var result databaseWithRolesResponse
			if err := json.Unmarshal(readBody(t, resp), &result); err != nil {
				t.Fatal(err)
			}
			finishOperation(t, env, result.OperationID, operations.StatusFailed)
			if _, err := env.pool.Exec(t.Context(), `update river_job set state='discarded',finalized_at=now() where args->>'operation_id'=$1`, result.OperationID.String()); err != nil {
				t.Fatal(err)
			}
			journal := databaseprovisioning.NewStore()
			if err := journal.BeginDatabase(t.Context(), env.pool, result.OperationID); err != nil {
				t.Fatal(err)
			}
			if err := journal.ConfirmDatabase(t.Context(), env.pool, result.OperationID, 123, "app_owner", 17, connections.TargetIdentity(conn)); err != nil {
				t.Fatal(err)
			}
			store := rolepolicies.NewStore()
			if err := store.ReconcileSnapshot(t.Context(), env.pool, conn.ID, []adapter.ObservedRolePolicy{{
				ExternalID: policy.ExternalID, Spec: policy.DesiredSpec, ExpectedFingerprint: policy.ExpectedFingerprint,
				ObservedFingerprint: "missing-role", ApplySupported: true,
				Summary: map[string]any{"role": map[string]any{"exists": false}, "missing": []string{"role:exists"}, "extra": []string{}},
			}}, time.Now()); err != nil {
				t.Fatal(err)
			}
			policy, err = store.Get(t.Context(), env.pool, policy.ID)
			if err != nil {
				t.Fatal(err)
			}
			payload := jobs.RolePolicyPayload{
				RolePolicyID: policy.ID, Action: rolepolicies.ActionCreate, ExpectedVersion: policy.Version + 1,
				ObservedFingerprint: policy.ObservedFingerprint, ExpectedFingerprint: policy.ExpectedFingerprint,
				ExpectedTargetIdentity: connections.TargetIdentity(conn), ExpectedDatabaseOID: 123,
				ExpectedDatabaseOwner: "app_owner", ExpectedDatabaseOwnerOID: 17,
				ExpectedAdminIdentity: "grantor", ExpectedConfigIncarnation: connections.ConfigIncarnation(conn),
				ExpectedCredentialIncarnation: 1,
				ExpectedCatalogFingerprint: postgresconfig.CatalogFingerprint([]postgresconfig.RolePolicyTemplate{{
					Key: policy.DesiredSpec.Key, Name: policy.DesiredSpec.Name, Description: policy.DesiredSpec.Description,
					RoleName: policy.DesiredSpec.RoleName, Database: policy.DesiredSpec.Database,
					Schemas: policy.DesiredSpec.Schemas, OwnerRoles: policy.DesiredSpec.OwnerRoles,
					CreatorRoles: policy.DesiredSpec.CreatorRoles, Profile: policy.DesiredSpec.Profile,
				}}), ExternalID: policy.ExternalID, Spec: policy.DesiredSpec,
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			child, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
				Kind: jobs.KindPostgresRolePolicyCreateDatabaseV2, ParentID: &result.OperationID, ConnectionID: &conn.ID, Payload: raw,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
				ConnectionID: conn.ID, TemplateKey: policy.TemplateKey, Action: rolepolicies.ActionCreate,
				OperationID: child.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
			}); err != nil {
				t.Fatal(err)
			}
			finishOperation(t, env, child.ID, operations.StatusFailed)
			if err := store.MarkRetryExhausted(t.Context(), env.pool, child.ID); err != nil {
				t.Fatal(err)
			}
			// Repair takeover applies to an existing role with incomplete ACLs,
			// not a missing role (which remains owned by the database workflow).
			if _, err := env.pool.Exec(t.Context(), `update role_policies set observed_summary=jsonb_set(observed_summary,'{role,exists}','true') where id=$1`, policy.ID); err != nil {
				t.Fatal(err)
			}
			policy, err = store.Get(t.Context(), env.pool, policy.ID)
			if err != nil {
				t.Fatal(err)
			}
			repairable, active, err := store.Repairability(t.Context(), env.pool, policy)
			if err != nil || !repairable || active {
				t.Fatalf("fixture should allow terminal takeover: %v/%v/%v", repairable, active, err)
			}
			if takeover {
				other, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{Kind: jobs.KindRolePolicyRepair, ConnectionID: &conn.ID})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
					ConnectionID: conn.ID, TemplateKey: policy.TemplateKey, Action: rolepolicies.ActionRepair,
					OperationID: other.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
				}); err != nil {
					t.Fatal(err)
				}
			}
			resp = env.do(t, http.MethodPost, "/api/v1/operations/"+result.OperationID.String()+"/retry", nil, &admin, true)
			if takeover {
				requireStatus(t, resp, http.StatusConflict)
				return
			}
			requireStatus(t, resp, http.StatusAccepted)
			policy, err = store.Get(t.Context(), env.pool, policy.ID)
			if err != nil {
				t.Fatal(err)
			}
			repairable, active, err = store.Repairability(t.Context(), env.pool, policy)
			if err != nil || repairable || !active || !policy.TransitionRetryPending {
				t.Fatalf("queued root must own policy before worker starts: %v/%v/%v marker=%v", repairable, active, err, policy.TransitionRetryPending)
			}
		})
	}
}
