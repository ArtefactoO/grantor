//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestScopedPersonalAdminKeyCannotReadOrDecideForeignApprovals(t *testing.T) {
	// The key's explicit restriction must apply even with dev scope enforcement
	// disabled, and the requests use the real personal-key Bearer authenticator.
	env, _, issuer := newPersonalAPIKeyEnv(t)
	allowed := createDraftInEnv(t, env, "approval-allowed-"+uuid.NewString())
	foreign := createDraftInEnv(t, env, "approval-foreign-"+uuid.NewString())
	owner := auth.Session{Issuer: issuer, Subject: uuid.NewString(), Username: "approval-admin", Email: "approval-admin-" + uuid.NewString() + "@example.test",
		Role: auth.RoleAdmin, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	response := env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{
		"name": "restricted-approval-admin", "role": auth.RoleAdmin, "environments": []string{allowed.Environment}, "expires_at": time.Now().Add(30 * time.Minute),
	}, &owner, true)
	requireStatus(t, response, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, response), &issued); err != nil || issued.Token == "" {
		t.Fatalf("decode personal key: %v", err)
	}
	base := time.Now().UTC().Truncate(time.Second)
	create := func(connection, parent *uuid.UUID, status operations.Status, when time.Time) operations.Operation {
		t.Helper()
		op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
			Kind: "scope.approval.fixture", ConnectionID: connection, ParentID: parent,
			ActorType: "user", ActorID: owner.Email, Payload: []byte(`{"scope_marker":"foreign-approval-plan"}`),
		})
		if err != nil {
			t.Fatalf("create approval fixture: %v", err)
		}
		if _, err := env.pool.Exec(t.Context(), "update operations set status=$2,created_at=$3 where id=$1", op.ID, status, when); err != nil {
			t.Fatalf("set approval fixture state: %v", err)
		}
		return op
	}
	ownOld := create(&allowed.ID, nil, operations.StatusPendingApproval, base)
	ownNew := create(&allowed.ID, nil, operations.StatusPendingApproval, base.Add(time.Minute))
	foreignOp := create(&foreign.ID, nil, operations.StatusPendingApproval, base.Add(2*time.Minute))
	mixed := create(&allowed.ID, nil, operations.StatusPendingApproval, base.Add(3*time.Minute))
	mixedAllowed := create(&allowed.ID, &mixed.ID, operations.StatusPendingApproval, base.Add(4*time.Minute))
	mixedForeign := create(&foreign.ID, &mixed.ID, operations.StatusPendingApproval, base.Add(5*time.Minute))
	alreadyApproved := create(&foreign.ID, nil, operations.StatusPending, base.Add(6*time.Minute))
	if _, err := env.pool.Exec(t.Context(), "update operations set approved_by='prior-admin',approved_at=now() where id=$1", alreadyApproved.ID); err != nil {
		t.Fatalf("seed already approved operation: %v", err)
	}

	// An in-scope child may be listed on its own; a mixed parent is hidden.
	for offset, want := range []uuid.UUID{mixedAllowed.ID, ownNew.ID, ownOld.ID} {
		response = env.doBearer(t, http.MethodGet, "/api/v1/approvals?limit=1&offset="+strconv.Itoa(offset), nil, issued.Token)
		requireStatus(t, response, http.StatusOK)
		var page struct {
			Operations []struct {
				ID uuid.UUID `json:"id"`
			} `json:"operations"`
		}
		if err := json.Unmarshal(readBody(t, response), &page); err != nil || len(page.Operations) != 1 || page.Operations[0].ID != want {
			t.Fatalf("approval page %d: %+v, err=%v", offset, page, err)
		}
	}
	for _, suffix := range []string{"approve", "reject"} {
		response = env.doBearer(t, http.MethodPost, "/api/v1/operations/"+foreignOp.ID.String()+"/"+suffix, nil, issued.Token)
		requireStatus(t, response, http.StatusForbidden)
		response = env.doBearer(t, http.MethodPost, "/api/v1/operations/"+mixed.ID.String()+"/"+suffix+"-children", nil, issued.Token)
		requireStatus(t, response, http.StatusForbidden)
		if body := string(readBody(t, response)); strings.Contains(body, mixedForeign.ID.String()) || strings.Contains(body, "foreign-approval-plan") {
			t.Fatalf("denied bulk decision exposes foreign approval: %s", body)
		}
	}
	response = env.doBearer(t, http.MethodPost, "/api/v1/operations/"+alreadyApproved.ID.String()+"/approve", nil, issued.Token)
	requireStatus(t, response, http.StatusForbidden)
	for _, id := range []uuid.UUID{foreignOp.ID, mixedAllowed.ID, mixedForeign.ID} {
		op, err := operations.NewStore().Get(t.Context(), env.pool, id)
		if err != nil || op.Status != operations.StatusPendingApproval {
			t.Fatalf("forbidden approval changed operation %s: %+v, err=%v", id, op, err)
		}
	}
	response = env.doBearer(t, http.MethodPost, "/api/v1/operations/"+ownNew.ID.String()+"/approve", nil, issued.Token)
	requireStatus(t, response, http.StatusOK)
	response = env.doBearer(t, http.MethodPost, "/api/v1/operations/"+ownOld.ID.String()+"/reject", nil, issued.Token)
	requireStatus(t, response, http.StatusOK)
}
