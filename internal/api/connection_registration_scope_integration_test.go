//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationConnectionRegistrationPersonalKeyUsesCurrentEnvironment(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	environment := "key-receipt-" + uuid.NewString()
	foreignEnvironment := "key-receipt-foreign-" + uuid.NewString()
	admin := auth.Session{Issuer: issuer, Subject: "scope-admin-" + uuid.NewString(), Username: "scope-admin", Email: "scope-admin@example.test", Role: auth.RoleAdmin, AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	resp := env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "receipt-scope", "role": "viewer", "expires_at": time.Now().Add(10 * time.Minute), "environments": []string{environment}}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var key struct {
		Token  string `json:"token"`
		APIKey struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(readBody(t, resp), &key); err != nil {
		t.Fatal(err)
	}
	owner := connectionregistration.Owner{Type: "user", ID: key.APIKey.UserID}
	store := connectionregistration.NewStore()
	source, err := store.CreateSource(t.Context(), env.pool, connectionregistration.Source{ID: uuid.New(), Name: "scoped-key", Owner: owner, Environment: environment, TargetSpec: []byte(`{"engine":"fake"}`)})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := env.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	if err := store.LockOwner(t.Context(), tx, owner); err != nil {
		t.Fatal(err)
	}
	reg, _, err := store.Reserve(t.Context(), tx, connectionregistration.ReserveParams{Owner: owner, RequestID: uuid.New(), RegistrationKey: "scoped-key", Environment: environment, Spec: []byte(`{"engine":"fake"}`), CredentialSourceID: source.ID, CredentialSourceVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connections.NewStore().Create(t.Context(), tx, connections.CreateParams{ID: &reg.ConnectionID, DisplayName: "scoped-key", Engine: "fake", Environment: environment, Endpoints: []string{"10.42.0.1:5432"}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := operations.NewStore().Create(t.Context(), tx, operations.CreateParams{ID: &reg.OperationID, Kind: jobs.KindConnectionDiscover, ConnectionID: &reg.ConnectionID, ActorType: "user", ActorID: admin.Email, CorrelationID: uuid.NewString()}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetCanonicalVersion(t.Context(), tx, reg.ID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRegistered(t.Context(), tx, reg.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+reg.ID.String(), nil, key.Token), http.StatusOK)
	if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, reg.ConnectionID, foreignEnvironment); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations/"+reg.ID.String(), nil, key.Token), http.StatusForbidden)
	resp = env.doBearer(t, http.MethodGet, "/api/v1/connection-registrations", nil, key.Token)
	requireStatus(t, resp, http.StatusOK)
	var page struct {
		Registrations []onboardingReceipt `json:"registrations"`
	}
	if err := json.Unmarshal(readBody(t, resp), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Registrations) != 0 {
		t.Fatal("personal key read status through the registration's stale environment")
	}
}
