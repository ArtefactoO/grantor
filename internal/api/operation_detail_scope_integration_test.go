//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func createOperationDetailScopeFixture(t *testing.T, env *testEnv, connectionID, parentID *uuid.UUID, kind, marker string) operations.Operation {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"scope_fixture": marker})
	if err != nil {
		t.Fatalf("marshal operation payload: %v", err)
	}
	op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: kind, ConnectionID: connectionID, ParentID: parentID, Payload: payload,
		ActorType: "service", ActorID: "itest-operation-detail", CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	return op
}

func requireOperationDetailScopeDenied(t *testing.T, resp *http.Response, deniedConnection uuid.UUID) {
	t.Helper()
	requireStatus(t, resp, http.StatusForbidden)
	body := string(readBody(t, resp))
	if strings.Contains(body, deniedConnection.String()) || strings.Contains(body, "foreign-payload") {
		t.Fatalf("forbidden operation detail exposes out-of-scope content: %s", body)
	}
}

func TestIntegrationOperationDetailScopesServiceTokenAndBulkChildren(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	allowedEnvironment := "operation-ci-allowed-" + uuid.NewString()
	foreignEnvironment := "operation-ci-foreign-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, allowedEnvironment)
	foreign := createDraftInEnv(t, env, foreignEnvironment)

	resp := env.do(t, http.MethodPost, "/api/v1/scope-policies", map[string]any{
		"subject_kind": policy.SubjectPrincipal, "subject": principalID, "environment": allowedEnvironment,
	}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principalID+"/tokens", map[string]string{
		"name": "operation-detail-ci",
	}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, resp), &issued); err != nil {
		t.Fatalf("decode service token response: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("service token response is empty")
	}

	// Use the real verification kind to exercise receipt projection after the
	// scope decision, without running a target mutation or a worker.
	own := createOperationDetailScopeFixture(t, env, &allowed.ID, nil, jobs.KindPostgresAccountVerifyCreationV1, "own-payload")
	foreignOp := createOperationDetailScopeFixture(t, env, &foreign.ID, nil, jobs.KindPostgresAccountVerifyCreationV1, "foreign-payload")
	allOwn := createOperationDetailScopeFixture(t, env, nil, nil, "scope.fixture.bulk", "own-parent")
	createOperationDetailScopeFixture(t, env, &allowed.ID, &allOwn.ID, jobs.KindConnectionDiscover, "own-child")
	mixed := createOperationDetailScopeFixture(t, env, nil, nil, "scope.fixture.bulk", "own-parent")
	createOperationDetailScopeFixture(t, env, &allowed.ID, &mixed.ID, jobs.KindConnectionDiscover, "own-child")
	createOperationDetailScopeFixture(t, env, &foreign.ID, &mixed.ID, jobs.KindConnectionDiscover, "foreign-payload")
	mixedWithRootConnection := createOperationDetailScopeFixture(t, env, &allowed.ID, nil, "scope.fixture.bulk", "own-parent")
	createOperationDetailScopeFixture(t, env, &foreign.ID, &mixedWithRootConnection.ID, jobs.KindConnectionDiscover, "foreign-payload")

	for _, op := range []operations.Operation{own, allOwn} {
		resp = env.doBearer(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, issued.Token)
		requireStatus(t, resp, http.StatusOK)
		var receipt struct {
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(readBody(t, resp), &receipt); err != nil || receipt.ID != op.ID {
			t.Fatalf("own receipt does not match requested operation: %v", err)
		}
	}
	for _, op := range []operations.Operation{foreignOp, mixed, mixedWithRootConnection} {
		resp = env.doBearer(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, issued.Token)
		requireOperationDetailScopeDenied(t, resp, foreign.ID)
	}

	// An allowed environment does not grant admin-only onboarding/configuration
	// to the same CI identity that can read and refresh its own connection.
	resp = env.doBearer(t, http.MethodPost, "/api/v1/connections", nil, issued.Token)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.doBearer(t, http.MethodPatch, "/api/v1/connections/"+allowed.ID.String(), map[string]any{
		"updated_at": allowed.UpdatedAt, "display_name": "ci-cannot-configure",
	}, issued.Token)
	requireStatus(t, resp, http.StatusForbidden)
}

func TestIntegrationOperationDetailScopePreservesHumanRoles(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	viewer := session(auth.RoleViewer)
	operator := session(auth.RoleOperator)
	allowedEnvironment := "operation-human-allowed-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, allowedEnvironment)
	foreign := createDraftInEnv(t, env, "operation-human-foreign-"+uuid.NewString())
	createRolePolicy(t, env, admin, allowedEnvironment)
	own := createOperationDetailScopeFixture(t, env, &allowed.ID, nil, jobs.KindConnectionDiscover, "own-payload")
	foreignOp := createOperationDetailScopeFixture(t, env, &foreign.ID, nil, jobs.KindConnectionDiscover, "foreign-payload")
	mixed := createOperationDetailScopeFixture(t, env, nil, nil, "scope.fixture.bulk", "mixed-parent")
	createOperationDetailScopeFixture(t, env, &allowed.ID, &mixed.ID, jobs.KindConnectionDiscover, "own-child")
	createOperationDetailScopeFixture(t, env, &foreign.ID, &mixed.ID, jobs.KindConnectionDiscover, "foreign-payload")

	resp := env.do(t, http.MethodGet, "/api/v1/operations/"+own.ID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	for _, op := range []operations.Operation{foreignOp, mixed} {
		resp = env.do(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, &operator, false)
		requireOperationDetailScopeDenied(t, resp, foreign.ID)
	}
	for _, sess := range []auth.Session{admin, viewer} {
		for _, op := range []operations.Operation{own, foreignOp, mixed} {
			resp = env.do(t, http.MethodGet, "/api/v1/operations/"+op.ID.String(), nil, &sess, false)
			requireStatus(t, resp, http.StatusOK)
		}
	}
}
