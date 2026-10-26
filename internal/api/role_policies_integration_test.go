//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func seedRolePolicyAPI(t *testing.T, env *testEnv) (connections.Connection, rolepolicies.Policy) {
	t.Helper()
	spec := adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read",
		Description: "Fixed read policy", RoleName: "r_app", Database: "app",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
	template := postgresconfig.RolePolicyTemplate{Key: spec.Key, Name: spec.Name, Description: spec.Description,
		RoleName: spec.RoleName, Database: spec.Database, Schemas: spec.Schemas,
		OwnerRoles: spec.OwnerRoles, CreatorRoles: spec.CreatorRoles, Profile: spec.Profile}
	discoveryConfig, err := json.Marshal(map[string]any{
		postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{template},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "role-policy-api-" + uuid.NewString(), Engine: "postgres",
		Environment: "itest", Endpoints: []string{"target-postgres:5432"},
		DiscoveryConfig: discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	topology, err := json.Marshal(map[string]any{
		"system_identifier": "7429012345678901234", "admin_credential_canonical_identity": "grantor",
		"postgres_role_policy_catalog_fingerprint": postgresconfig.CatalogFingerprint([]postgresconfig.RolePolicyTemplate{template}),
		"postgres_role_policy_apply_supported":     true,
		"postgres_role_policy_create_supported":    true,
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
			Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
			ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 1, ConfigIncarnation: connections.ConfigIncarnation(conn),
			TargetIdentity: "postgres:system:7429012345678901234",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, _ := json.Marshal([]string{string(adapter.CapPostgresSuperuserDirectV1),
		string(adapter.CapRolePolicyApply), string(adapter.CapRolePolicyCreate)})
	if _, err := env.pool.Exec(t.Context(), `update connections set
		status='active', capabilities=$2, topology=$3,last_discovery_at=$4
		where id=$1`, conn.ID, capabilities, topology, observedAt); err != nil {
		t.Fatalf("activate connection: %v", err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload connection: %v", err)
	}
	snapshot := &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{
			{Kind: "group", EngineIdentity: spec.RoleName, Attributes: map[string]any{"role_oid": uint32(19)}},
			{Kind: "group", EngineIdentity: "app_owner", Attributes: map[string]any{"role_oid": uint32(17)}},
			{Kind: "group", EngineIdentity: "app_migrator", Attributes: map[string]any{"role_oid": uint32(18)}},
		},
		Resources: []adapter.ObservedResource{{Kind: "database", ExternalID: "db:app", Name: "app",
			CanonicalPath: "app", Attributes: map[string]any{"database_oid": uint32(42), "owner": "app_owner", "owner_oid": uint32(17)}}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
	}
	if _, err := inventory.NewStore().UpsertSnapshot(t.Context(), env.pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatalf("upsert inventory: %v", err)
	}
	if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID,
		[]adapter.ObservedRolePolicy{{
			ExternalID: "role:" + spec.RoleName, Spec: spec,
			ExpectedFingerprint: "exact-fingerprint", ObservedFingerprint: "exact-fingerprint",
			Exact: true, ApplySupported: true,
			Summary: map[string]any{
				"missing": []string{}, "extra": []string{},
				"role": map[string]any{"exists": true, "safe": true},
			},
		}}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	policy, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	return conn, policy
}

func TestIntegrationRolePolicyCreateIsMissingOnlyAndIdempotent(t *testing.T) {
	env := newTestEnv(t, nil)
	admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
	conn, policy := seedRolePolicyAPI(t, env)
	var badTopology map[string]any
	if err := json.Unmarshal(conn.Topology, &badTopology); err != nil {
		t.Fatal(err)
	}
	badTopology["system_identifier"] = "7429012345678901235"
	badTopologyJSON, _ := json.Marshal(badTopology)
	path := "/api/v1/connections/" + conn.ID.String() + "/role-policies/" + policy.TemplateKey + "/create"
	body := map[string]any{"request_id": uuid.New(), "version": policy.Version, "observed_fingerprint": policy.ObservedFingerprint, "confirm": true,
		"expected_target_identity": "postgres:system:7429012345678901234"}
	requireStatus(t, env.do(t, http.MethodPost, path, body, &operator, true), http.StatusForbidden)
	// An exact unmanaged role must still use the explicit verify-only Adopt.
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
	if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID, []adapter.ObservedRolePolicy{{
		ExternalID: policy.ExternalID, Spec: policy.DesiredSpec, ExpectedFingerprint: policy.ExpectedFingerprint,
		ObservedFingerprint: "missing-role", Exact: false, ApplySupported: true,
		Summary: map[string]any{"role": map[string]any{"exists": false}, "missing": []string{"role:exists"}, "extra": []string{}},
	}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var err error
	policy, err = rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, policy.TemplateKey)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
	body["version"], body["observed_fingerprint"] = policy.Version, policy.ObservedFingerprint
	// Missing roles have a distinct create-only route. Rejected Apply must not
	// reserve a managed/provisioning identity or leave an operation behind.
	applyPath := "/api/v1/connections/" + conn.ID.String() + "/role-policies/" + policy.TemplateKey + "/apply"
	applyBody := map[string]any{"request_id": uuid.New(), "version": policy.Version, "observed_fingerprint": policy.ObservedFingerprint, "confirm": true}
	requireStatus(t, env.do(t, http.MethodPost, applyPath, applyBody, &admin, true), http.StatusConflict)
	var applyCount int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind=$2`, conn.ID, jobs.KindPostgresRolePolicyApplyV2).Scan(&applyCount); err != nil || applyCount != 0 {
		t.Fatalf("missing Apply enqueued operation: %d %v", applyCount, err)
	}
	delete(body, "expected_target_identity")
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusBadRequest)
	body["expected_target_identity"] = "postgres:system:7429012345678901234"
	// A fresh discovery of a different cluster must not silently repin the
	// original preview before reserving or enqueueing either basic role.
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2 where id=$1`, conn.ID, badTopologyJSON); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
	var operationCount int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind=$2`, conn.ID, jobs.KindPostgresRolePolicyCreateV2).Scan(&operationCount); err != nil || operationCount != 0 {
		t.Fatalf("target mismatch enqueued creation: count=%d err=%v", operationCount, err)
	}
	unchanged, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, policy.TemplateKey)
	if err != nil || unchanged.Version != policy.Version || unchanged.Managed {
		t.Fatalf("target mismatch changed policy intent: %+v %v", unchanged, err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2 where id=$1`, conn.ID, conn.Topology); err != nil {
		t.Fatal(err)
	}
	var firstID string
	for range 2 {
		resp := env.do(t, http.MethodPost, path, body, &admin, true)
		requireStatus(t, resp, http.StatusAccepted)
		var result struct {
			OperationID string `json:"operation_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		if firstID != "" && result.OperationID != firstID {
			t.Fatal("same request_id enqueued a second create")
		}
		firstID = result.OperationID
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, uuid.MustParse(firstID))
	if err != nil || op.Kind != jobs.KindPostgresRolePolicyCreateV2 {
		t.Fatalf("operation kind=%q err=%v", op.Kind, err)
	}
	var payload jobs.RolePolicyPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil || payload.Action != rolepolicies.ActionCreate {
		t.Fatalf("immutable create intent lost: %+v %v", payload, err)
	}
	if payload.ExpectedTargetIdentity != body["expected_target_identity"] {
		t.Fatalf("operation did not preserve preview target: %q", payload.ExpectedTargetIdentity)
	}
	// Idempotency must not bypass the target fence after a later rediscovery.
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2 where id=$1`, conn.ID, badTopologyJSON); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1 and kind=$2`, conn.ID, jobs.KindPostgresRolePolicyCreateV2).Scan(&operationCount); err != nil || operationCount != 1 {
		t.Fatalf("mismatched retry changed operation count: count=%d err=%v", operationCount, err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2 where id=$1`, conn.ID, conn.Topology); err != nil {
		t.Fatal(err)
	}
	// A different concurrent request cannot steal the reserved transition.
	body["request_id"] = uuid.New()
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusConflict)
}

func TestIntegrationRolePolicyMutationRequiresCurrentSuperuserAuthority(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "role-policy-no-identity-" + uuid.NewString(), Engine: "postgres",
		Environment: "itest", Endpoints: []string{"target-postgres:5432"},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set
		status='active', capabilities='["role.policy.apply"]', topology='{}'
		where id=$1`, conn.ID); err != nil {
		t.Fatalf("activate connection: %v", err)
	}
	resp := env.do(t, http.MethodPost,
		"/api/v1/connections/"+conn.ID.String()+"/role-policies/missing/apply",
		map[string]any{
			"request_id": uuid.New(), "version": 0,
			"observed_fingerprint": "observed", "confirm": true,
		}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !strings.Contains(body.Error, "PostgreSQL SUPERUSER provisioning authority") {
		t.Fatalf("error = %q, want explicit SUPERUSER authority guidance", body.Error)
	}
}

func TestIntegrationMongoDBRolePolicyDesiredSpecProjection(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "mongodb-role-policy-api-" + uuid.NewString(), Engine: "mongodb",
		Environment: "itest", Endpoints: []string{"mongodb:27017"},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	spec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "app-worker", Name: "Application worker",
		Description: "Typed MongoDB policy", RoleName: "app_worker", Database: "app",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		MongoPrivileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"},
			Actions:  []string{"find", "update"},
		}},
	}
	if err := rolepolicies.NewStore().ReconcileSnapshot(t.Context(), env.pool, conn.ID,
		[]adapter.ObservedRolePolicy{{
			ExternalID: "role:app.app_worker", Spec: spec,
			ExpectedFingerprint: "expected", ObservedFingerprint: "observed",
			Exact: false, ApplySupported: true,
			Summary: map[string]any{"missing": []string{"action:update"}, "extra": []string{}},
		}}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	resp := env.do(t, http.MethodGet,
		"/api/v1/connections/"+conn.ID.String()+"/role-policies", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var listed struct {
		Policies []struct {
			DesiredSpec map[string]any `json:"desired_spec"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Policies) != 1 {
		t.Fatalf("policies = %+v", listed.Policies)
	}
	desired := listed.Policies[0].DesiredSpec
	if len(desired) != 4 || desired["role_name"] != "app_worker" || desired["role_database"] != "app" {
		t.Fatalf("desired_spec = %+v, want typed MongoDB shape", desired)
	}
	if _, exists := desired["database"]; exists {
		t.Fatalf("desired_spec leaks PostgreSQL database field: %+v", desired)
	}
}

func TestIntegrationManagedMongoDBRolePolicyBlocksTemplateRemovalAndIdentityChange(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	template := mongodbconfig.RolePolicyTemplate{
		Key: "app-worker", Name: "Application worker", Description: "Typed MongoDB policy",
		RoleName: "app_worker", RoleDatabase: "app",
		InheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"},
			Actions:  []string{"find", "update"},
		}},
	}
	discoveryConfig, err := json.Marshal(map[string]any{
		"mongodb_role_policy_templates": []mongodbconfig.RolePolicyTemplate{template},
	})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "mongodb-managed-policy-" + uuid.NewString(), Engine: "mongodb",
		Environment: "itest", Endpoints: []string{"target-mongodb:27017"},
		DiscoveryConfig: discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set status='active' where id=$1`, conn.ID); err != nil {
		t.Fatalf("activate connection: %v", err)
	}
	spec := mongodbconfig.Spec(template)
	store := rolepolicies.NewStore()
	if err := store.ReconcileSnapshot(t.Context(), env.pool, conn.ID,
		[]adapter.ObservedRolePolicy{{
			ExternalID: "role:app.app_worker", Spec: spec,
			ExpectedFingerprint: "exact", ObservedFingerprint: "exact",
			Exact: true, ApplySupported: true,
			Summary: map[string]any{"missing": []string{}, "extra": []string{}},
		}}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	policy, err := store.GetByKey(t.Context(), env.pool, conn.ID, template.Key)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	policy = completeRolePolicyAdopt(t, env, conn, policy)
	if !policy.Managed {
		t.Fatal("adopted MongoDB policy is not managed")
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload connection: %v", err)
	}
	changed := template
	changed.RoleName = "other_worker"
	for name, next := range map[string]any{
		"remove": map[string]any{"mongodb_role_policy_templates": []any{}},
		"identity": map[string]any{
			"mongodb_role_policy_templates": []mongodbconfig.RolePolicyTemplate{changed},
		},
	} {
		t.Run(name, func(t *testing.T) {
			resp := env.do(t, http.MethodPatch, "/api/v1/connections/"+conn.ID.String(), map[string]any{
				"updated_at": conn.UpdatedAt, "discovery_config": next,
			}, &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}
}

func TestIntegrationRolePolicyReadAndAdoptContract(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn, policy := seedRolePolicyAPI(t, env)
	base := "/api/v1/connections/" + conn.ID.String() + "/role-policies"

	resp := env.do(t, http.MethodGet, base, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var listed struct {
		Policies []struct {
			TemplateKey     string          `json:"template_key"`
			DesiredSpec     json.RawMessage `json:"desired_spec"`
			ObservedSummary json.RawMessage `json:"observed_summary"`
			BlockedReason   string          `json:"blocked_reason"`
			Repairable      bool            `json:"repairable"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Policies) != 1 || listed.Policies[0].TemplateKey != policy.TemplateKey {
		t.Fatalf("list = %+v", listed.Policies)
	}
	var desired map[string]any
	if err := json.Unmarshal(listed.Policies[0].DesiredSpec, &desired); err != nil {
		t.Fatalf("decode desired_spec: %v", err)
	}
	if len(desired) != 6 || desired["role_name"] != policy.DesiredSpec.RoleName {
		t.Fatalf("desired_spec = %+v, want exact six-field public shape", desired)
	}
	var summary map[string]any
	if err := json.Unmarshal(listed.Policies[0].ObservedSummary, &summary); err != nil {
		t.Fatalf("decode observed_summary: %v", err)
	}
	if _, ok := summary["missing"]; !ok {
		t.Fatal("observed_summary.missing is absent")
	}
	if listed.Policies[0].BlockedReason != "" {
		t.Fatalf("blocked_reason = %q", listed.Policies[0].BlockedReason)
	}

	path := base + "/" + policy.TemplateKey + "/adopt"
	body := map[string]any{
		"request_id": uuid.New(), "version": policy.Version,
		"observed_fingerprint": policy.ObservedFingerprint, "confirm": true,
	}
	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	injected := map[string]any{
		"request_id": uuid.New(), "version": policy.Version,
		"observed_fingerprint": policy.ObservedFingerprint, "confirm": true,
		"raw_sql": "grant all privileges",
	}
	resp = env.do(t, http.MethodPost, path, injected, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var response map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		t.Fatalf("decode mutation: %v", err)
	}
	if len(response) != 1 || response["operation_id"] == nil {
		t.Fatalf("mutation response = %s, want operation_id only", mustJSON(response))
	}
	var operationID uuid.UUID
	if err := json.Unmarshal(response["operation_id"], &operationID); err != nil {
		t.Fatalf("decode operation id: %v", err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, operationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindPostgresRolePolicyAdoptV2 || op.Status != operations.StatusPending {
		t.Fatalf("operation = %+v", op)
	}
	reserved, err := rolepolicies.NewStore().GetByKey(t.Context(), env.pool, conn.ID, policy.TemplateKey)
	if err != nil {
		t.Fatalf("get reserved policy: %v", err)
	}
	if reserved.TransitionOperationID == nil || *reserved.TransitionOperationID != operationID ||
		reserved.Managed || reserved.Status != rolepolicies.StatusPending {
		t.Fatalf("reserved policy = %+v", reserved)
	}

	// Same public request id is durable-idempotent and returns the same
	// operation without advancing policy version a second time.
	resp = env.do(t, http.MethodPost, path, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var repeated struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&repeated); err != nil {
		t.Fatalf("decode repeated: %v", err)
	}
	if repeated.OperationID != operationID {
		t.Fatalf("repeated operation = %s, want %s", repeated.OperationID, operationID)
	}
}

func TestIntegrationManagedRolePolicyBlocksTemplateRemovalAndIdentityChange(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn, policy := seedRolePolicyAPI(t, env)
	store := rolepolicies.NewStore()
	op, created, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: jobs.KindRolePolicyAdopt, ConnectionID: &conn.ID,
		ActorType: "test", ActorID: t.Name(),
	})
	if err != nil || !created {
		t.Fatalf("create adopt operation: created=%v err=%v", created, err)
	}
	reserved, err := store.Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: policy.TemplateKey,
		Action: rolepolicies.ActionAdopt, OperationID: op.ID,
		Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve adopt: %v", err)
	}
	if _, err := store.Complete(t.Context(), env.pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec); err != nil {
		t.Fatalf("complete adopt: %v", err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload connection: %v", err)
	}
	path := "/api/v1/connections/" + conn.ID.String()
	for name, discoveryConfig := range map[string]any{
		"remove": map[string]any{"postgres_role_policy_templates": []any{}},
		"identity": map[string]any{"postgres_role_policy_templates": []map[string]any{{
			"key": policy.TemplateKey, "name": policy.Name,
			"description": policy.Description, "role_name": "r_other",
			"database": policy.DesiredSpec.Database, "schemas": policy.DesiredSpec.Schemas,
			"owner_roles":   policy.DesiredSpec.OwnerRoles,
			"creator_roles": policy.DesiredSpec.CreatorRoles, "profile": policy.DesiredSpec.Profile,
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			resp := env.do(t, http.MethodPatch, path, map[string]any{
				"updated_at": conn.UpdatedAt, "discovery_config": discoveryConfig,
			}, &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("reload after rejected patches: %v", err)
	}
	if !stored.UpdatedAt.Equal(conn.UpdatedAt) || stored.Status != connections.StatusActive {
		t.Fatalf("rejected template change mutated connection: before=%+v after=%+v", conn, stored)
	}
}

func completeRolePolicyAdopt(t *testing.T, env *testEnv, conn connections.Connection, policy rolepolicies.Policy) rolepolicies.Policy {
	t.Helper()
	store := rolepolicies.NewStore()
	op, created, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: jobs.KindRolePolicyAdopt, ConnectionID: &conn.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil || !created {
		t.Fatalf("create adopt operation: created=%v err=%v", created, err)
	}
	reserved, err := store.Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: policy.TemplateKey,
		Action: rolepolicies.ActionAdopt, OperationID: op.ID,
		Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve adopt: %v", err)
	}
	completed, err := store.Complete(t.Context(), env.pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil {
		t.Fatalf("complete adopt: %v", err)
	}
	return completed
}

func TestIntegrationTerminalRolePolicyOwnerIsRepairableAndManualRetryRearmsFence(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn, policy := seedRolePolicyAPI(t, env)
	policy = completeRolePolicyAdopt(t, env, conn, policy)

	drift := adapter.ObservedRolePolicy{
		ExternalID: policy.ExternalID, Spec: policy.DesiredSpec,
		ExpectedFingerprint: policy.ExpectedFingerprint, ObservedFingerprint: "drifted-fingerprint",
		Exact: false, ApplySupported: true,
		Summary: map[string]any{
			"missing": []string{"acl:table:public.orders:SELECT"}, "extra": []string{},
			"role": map[string]any{"exists": true, "safe": true},
		},
	}
	store := rolepolicies.NewStore()
	if err := store.ReconcileSnapshot(t.Context(), env.pool, conn.ID,
		[]adapter.ObservedRolePolicy{drift}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reconcile drift: %v", err)
	}
	policy, _ = store.GetByKey(t.Context(), env.pool, conn.ID, policy.TemplateKey)
	repair, created, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: jobs.KindRolePolicyRepair, ConnectionID: &conn.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil || !created {
		t.Fatalf("create repair operation: created=%v err=%v", created, err)
	}
	reserved, err := store.Reserve(t.Context(), env.pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: policy.TemplateKey,
		Action: rolepolicies.ActionRepair, OperationID: repair.ID,
		Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve repair: %v", err)
	}
	opStore := operations.NewStore()
	if _, err := opStore.Transition(t.Context(), env.pool, repair.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start repair: %v", err)
	}
	if err := store.MarkFailed(t.Context(), env.pool, repair.ID, reserved.ExpectedVersion); err != nil {
		t.Fatalf("mark policy failed: %v", err)
	}
	if _, err := opStore.Transition(t.Context(), env.pool, repair.ID,
		operations.StatusRunning, operations.StatusFailed, operations.TransitionOpts{Error: "exhausted"}); err != nil {
		t.Fatalf("fail repair: %v", err)
	}
	if err := store.MarkRetryExhausted(t.Context(), env.pool, repair.ID); err != nil {
		t.Fatalf("mark exhausted: %v", err)
	}

	base := "/api/v1/connections/" + conn.ID.String() + "/role-policies"
	resp := env.do(t, http.MethodGet, base, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var listed struct {
		Policies []struct {
			Repairable       bool `json:"repairable"`
			TransitionActive bool `json:"transition_active"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode terminal projection: %v", err)
	}
	if len(listed.Policies) != 1 || !listed.Policies[0].Repairable || listed.Policies[0].TransitionActive {
		t.Fatalf("terminal projection = %+v", listed.Policies)
	}

	retryPath := "/api/v1/operations/" + repair.ID.String() + "/retry"
	resp = env.do(t, http.MethodPost, retryPath, nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, retryPath, nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)

	resp = env.do(t, http.MethodGet, base, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	listed.Policies = nil
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatalf("decode retry projection: %v", err)
	}
	if len(listed.Policies) != 1 || listed.Policies[0].Repairable || !listed.Policies[0].TransitionActive {
		t.Fatalf("manual retry projection = %+v", listed.Policies)
	}
}

func TestIntegrationRolePolicyAccountRejectsEveryGrantSurface(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	conn, policy := seedRolePolicyAPI(t, env)
	policy = completeRolePolicyAdopt(t, env, conn, policy)
	if policy.AccountID == nil {
		t.Fatal("managed policy has no dedicated account")
	}

	var permissionID uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `insert into permission_definitions (
		connection_id, engine, external_id, name, assignable, dangerous, attributes, status
	) values ($1,'postgres','role:ordinary','ordinary',true,false,'{}','observed') returning id`,
		conn.ID).Scan(&permissionID); err != nil {
		t.Fatalf("insert ordinary permission: %v", err)
	}

	requests := []struct {
		name string
		path string
		body any
	}{
		{"single", "/api/v1/bindings", map[string]any{
			"account_id": *policy.AccountID, "permission_id": permissionID,
		}},
		{"bulk", "/api/v1/bindings/bulk", map[string]any{"items": []map[string]any{{
			"account_id": *policy.AccountID, "permission_id": permissionID,
		}}}},
		{"account_roles", "/api/v1/accounts/" + policy.AccountID.String() + "/roles", map[string]any{
			"add_permission_ids": []uuid.UUID{permissionID},
		}},
	}
	for _, tc := range requests {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.do(t, http.MethodPost, tc.path, tc.body, &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}

	principal, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeService, DisplayName: policy.DesiredSpec.RoleName,
	})
	if err != nil {
		t.Fatalf("create adversarial principal: %v", err)
	}
	sharedPath := "principals/" + principal.ID.String() + "/environments/itest/credential"
	if _, err := env.pool.Exec(t.Context(), `update accounts set
		principal_id=$2, credential_mode='existing_vault_ref', vault_path=$3
		where id=$1`, *policy.AccountID, principal.ID, sharedPath); err != nil {
		t.Fatalf("link policy identity adversarially: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access",
		map[string]any{
			"engine_identity": policy.DesiredSpec.RoleName,
			"items":           []map[string]any{{"connection_id": conn.ID, "permission_id": permissionID}},
		}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	manifest := map[string]any{
		"version": "v1", "environment": "itest",
		"entries": []map[string]any{{
			"principal": principal.ID.String(), "connection": conn.ID.String(), "role": "role:ordinary",
		}},
	}
	resp = env.do(t, http.MethodPost, "/api/v1/access/apply", manifest, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	var bindings int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from bindings where account_id=$1`,
		*policy.AccountID).Scan(&bindings); err != nil {
		t.Fatalf("count policy account bindings: %v", err)
	}
	if bindings != 0 {
		t.Fatalf("policy account gained %d bindings through rejected surfaces", bindings)
	}
}

func TestIntegrationStructuralRolePolicyDelegationCannotBeRevoked(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn, policy := seedRolePolicyAPI(t, env)
	policy = completeRolePolicyAdopt(t, env, conn, policy)
	permission := permissionByExternalAPI(t, env, conn.ID, policy.ExternalID)

	var adminAccountID, userAccountID, structuralBindingID, userBindingID uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `insert into accounts (
		connection_id, kind, engine_identity, status, ownership, attributes
	) values ($1,'login','grantor_admin','active','unmanaged','{"connection_admin":true}') returning id`,
		conn.ID).Scan(&adminAccountID); err != nil {
		t.Fatalf("insert connection admin: %v", err)
	}
	if err := env.pool.QueryRow(t.Context(), `insert into accounts (
		connection_id, kind, engine_identity, status, ownership, attributes
	) values ($1,'login','ordinary_user','active','managed','{}') returning id`,
		conn.ID).Scan(&userAccountID); err != nil {
		t.Fatalf("insert ordinary user: %v", err)
	}
	var ordinaryPermissionID uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `insert into permission_definitions (
		connection_id, engine, external_id, name, assignable, dangerous, attributes, status
	) values ($1,'postgres','role:ordinary_admin_probe','ordinary_admin_probe',true,false,'{}','observed')
	returning id`, conn.ID).Scan(&ordinaryPermissionID); err != nil {
		t.Fatalf("insert ordinary permission: %v", err)
	}
	if err := env.pool.QueryRow(t.Context(), `insert into bindings (
		account_id, permission_definition_id, source, desired_state,
		observed_state, observed_effective, observed_attributes, status
	) values ($1,$2,'external',null,'present',true,'{"admin_option":true}','drift') returning id`,
		adminAccountID, permission.ID).Scan(&structuralBindingID); err != nil {
		t.Fatalf("insert structural binding: %v", err)
	}
	if err := env.pool.QueryRow(t.Context(), `insert into bindings (
		account_id, permission_definition_id, source, desired_state,
		observed_state, observed_effective, observed_attributes, status
	) values ($1,$2,'service','present','present',true,'{"admin_option":false}','synced') returning id`,
		userAccountID, permission.ID).Scan(&userBindingID); err != nil {
		t.Fatalf("insert ordinary binding: %v", err)
	}

	resp := env.do(t, http.MethodDelete, "/api/v1/bindings/"+structuralBindingID.String(), nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", map[string]any{
		"account_id": adminAccountID, "permission_id": ordinaryPermissionID,
	}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+adminAccountID.String()+"/roles",
		map[string]any{"remove_binding_ids": []uuid.UUID{structuralBindingID}}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	resp = env.do(t, http.MethodDelete, "/api/v1/bindings/"+userBindingID.String(), nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	structural, err := inventory.NewStore().GetBinding(t.Context(), env.pool, structuralBindingID)
	if err != nil {
		t.Fatalf("get structural binding: %v", err)
	}
	if structural.DesiredState != nil {
		t.Fatalf("structural desired state changed to %v", structural.DesiredState)
	}
}

func permissionByExternalAPI(t *testing.T, env *testEnv, connectionID uuid.UUID, externalID string) inventory.Permission {
	t.Helper()
	permissions, err := inventory.NewStore().ListPermissions(t.Context(), env.pool, connectionID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	for _, permission := range permissions {
		if permission.ExternalID == externalID {
			return permission
		}
	}
	t.Fatalf("permission %q not found", externalID)
	return inventory.Permission{}
}

func mustJSON(value any) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
