//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestScopedPersonalKeyOperationMutationsDoNotRevealForeignNoopOrSkippedChildren(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	allowed := createDraftInEnv(t, env, "mutation-allowed-"+uuid.NewString())
	foreign := createDraftInEnv(t, env, "mutation-foreign-"+uuid.NewString())
	owner := auth.Session{Issuer: issuer, Subject: uuid.NewString(), Username: "mutation-admin", Email: "mutation-admin-" + uuid.NewString() + "@example.test",
		Role: auth.RoleAdmin, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	response := env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{
		"name": "restricted-operation-admin", "role": auth.RoleAdmin, "environments": []string{allowed.Environment}, "expires_at": time.Now().Add(30 * time.Minute),
	}, &owner, true)
	requireStatus(t, response, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, response), &issued); err != nil || issued.Token == "" {
		t.Fatalf("decode personal key: %v", err)
	}
	base := time.Now().UTC()
	resolved := scopedReadOperation(t, env, "foreign-actor", "scope.mutation.fixture", &foreign.ID, nil, operations.StatusFailed, base)
	if _, err := env.pool.Exec(t.Context(), "update operations set resolved_at=now(),resolved_by='foreign-admin' where id=$1", resolved.ID); err != nil {
		t.Fatalf("seed resolved foreign operation: %v", err)
	}
	mixed := scopedReadOperation(t, env, owner.Email, "scope.mutation.bulk", &allowed.ID, nil, operations.StatusPartial, base)
	ownChild := scopedReadOperation(t, env, owner.Email, "scope.mutation.child", &allowed.ID, &mixed.ID, operations.StatusFailed, base)
	foreignChild := scopedReadOperation(t, env, owner.Email, "scope.mutation.child", &foreign.ID, &mixed.ID, operations.StatusCancelled, base)
	for _, path := range []string{
		"/api/v1/operations/" + resolved.ID.String() + "/resolve",
		"/api/v1/operations/" + mixed.ID.String() + "/resolve",
		"/api/v1/operations/" + mixed.ID.String() + "/retry",
	} {
		response = env.doBearer(t, http.MethodPost, path, nil, issued.Token)
		requireStatus(t, response, http.StatusForbidden)
		body := string(readBody(t, response))
		if strings.Contains(body, "scoped-read-fixture") || strings.Contains(body, foreign.ID.String()) || strings.Contains(body, foreignChild.ID.String()) {
			t.Fatalf("operation mutation denial exposes foreign details: %s", body)
		}
	}
	after, err := operations.NewStore().Get(t.Context(), env.pool, mixed.ID)
	if err != nil || after.ResolvedAt != nil || after.Status != operations.StatusPartial {
		t.Fatalf("forbidden parent resolution changed operation: %+v, err=%v", after, err)
	}
	after, err = operations.NewStore().Get(t.Context(), env.pool, ownChild.ID)
	if err != nil || after.Status != operations.StatusFailed {
		t.Fatalf("forbidden mixed retry changed child: %+v, err=%v", after, err)
	}
	// Interactive admins keep their established global access in dev mode.
	response = env.do(t, http.MethodPost, "/api/v1/operations/"+resolved.ID.String()+"/resolve", nil, &owner, true)
	requireStatus(t, response, http.StatusOK)
	if !strings.Contains(string(readBody(t, response)), "scoped-read-fixture") {
		t.Fatal("interactive admin no longer receives the authorized resolved receipt")
	}
}
