//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

const favoritesPath = "/api/v1/me/favorite-connections"

func newFavoritesEnv(t *testing.T) (*testEnv, *api.APIKeyIdentityManager, string) {
	t.Helper()
	registerFakeAdapter()
	pool, issuer := pgtest.Pool(t), newFakeOIDC(t).URL
	keys, tokens := apikey.NewStore(), servicetoken.NewStore()
	manager := api.NewAPIKeyIdentityManager(pool, keys, nil, time.Minute)
	manager.SetIssuer(issuer)
	authn, err := auth.New(t.Context(), auth.Config{IssuerURL: issuer, ClientID: "grantor", RedirectURL: "http://localhost/auth/callback",
		SessionSecret: []byte(testSessionSecret), SessionObserver: manager.ObserveSession,
		TokenAuth: api.ChainTokenAuthenticators(api.NewPersonalKeyAuth(pool, keys, issuer), api.NewServiceTokenAuth(pool, tokens))})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := auth.NewCodec([]byte(testSessionSecret))
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.New(api.Config{Pool: pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Operations: operations.NewStore(),
		Audit: audit.NewWriter(), Credentials: credentials.NewService(nil, nil), Dispatcher: dispatcher, Auth: authn,
		APIKeys: keys, APIKeyIdentity: manager, ScopeEnforcement: policy.EnforcementEnforce})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: codec}, manager, issuer
}

func favoriteIDs(t *testing.T, response *http.Response) []uuid.UUID {
	t.Helper()
	requireStatus(t, response, http.StatusOK)
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("identity preferences are cacheable")
	}
	var payload struct {
		IDs []uuid.UUID `json:"connection_ids"`
	}
	if err := json.Unmarshal(readBody(t, response), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.IDs == nil {
		t.Fatal("favorite IDs must always be an array")
	}
	return payload.IDs
}

func favoriteSession(issuer string) auth.Session {
	return auth.Session{Issuer: issuer, Subject: uuid.NewString(), Username: "favorite-user", Email: "same@example.test", Role: auth.RoleViewer,
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
}

func TestIntegrationConnectionFavoritesOwnershipAndCascade(t *testing.T) {
	env, manager, issuer := newFavoritesEnv(t)
	owner, other := favoriteSession(issuer), favoriteSession(issuer)
	conn := createDraft(t, env.pool)
	path := favoritesPath + "/" + conn.ID.String()
	requireStatus(t, env.do(t, http.MethodGet, favoritesPath, nil, nil, false), http.StatusUnauthorized)
	requireStatus(t, env.do(t, http.MethodPut, path, nil, &owner, false), http.StatusForbidden)
	for i := 0; i < 2; i++ {
		requireStatus(t, env.do(t, http.MethodPut, path, nil, &owner, true), http.StatusNoContent)
	}
	ids := favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false))
	if len(ids) != 1 || ids[0] != conn.ID {
		t.Fatalf("idempotent add returned %v", ids)
	}
	if ids := favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath+"?user_id="+owner.Subject, nil, &other, false)); len(ids) != 0 {
		t.Fatalf("different subject with the same email inherited favorites: %v", ids)
	}
	requireStatus(t, env.do(t, http.MethodDelete, path, nil, &other, true), http.StatusNoContent)
	if len(favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false))) != 1 {
		t.Fatal("another user deleted owner's favorite")
	}
	for i := 0; i < 2; i++ {
		requireStatus(t, env.do(t, http.MethodDelete, path, nil, &owner, true), http.StatusNoContent)
	}
	if len(favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false))) != 0 {
		t.Fatal("favorite survived removal")
	}
	requireStatus(t, env.do(t, http.MethodPut, path, nil, &owner, true), http.StatusNoContent)
	if err := connections.NewStore().Delete(t.Context(), env.pool, conn.ID); err != nil {
		t.Fatal(err)
	}
	if len(favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false))) != 0 {
		t.Fatal("deleted connection leaked from favorites")
	}
	requireStatus(t, env.do(t, http.MethodPut, path, nil, &owner, true), http.StatusNotFound)
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from connection_favorites where connection_id=$1`, conn.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("connection FK did not cascade: %d %v", count, err)
	}
	conn = createDraft(t, env.pool)
	requireStatus(t, env.do(t, http.MethodPut, favoritesPath+"/"+conn.ID.String(), nil, &owner, true), http.StatusNoContent)
	u, err := manager.SessionUser(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `delete from api_users where id=$1`, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from connection_favorites where user_id=$1`, u.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("user FK did not cascade: %d %v", count, err)
	}
}

func TestIntegrationConnectionFavoritesPersonalKeyScopeAndRebinding(t *testing.T) {
	env, manager, issuer := newFavoritesEnv(t)
	owner := favoriteSession(issuer)
	allowed, hidden := createDraft(t, env.pool), createDraft(t, env.pool)
	allowedEnv, hiddenEnv := "favorite-"+uuid.NewString(), "hidden-"+uuid.NewString()
	for id, environment := range map[uuid.UUID]string{allowed.ID: allowedEnv, hidden.ID: hiddenEnv} {
		if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, id, environment); err != nil {
			t.Fatal(err)
		}
		requireStatus(t, env.do(t, http.MethodPut, favoritesPath+"/"+id.String(), nil, &owner, true), http.StatusNoContent)
	}
	u, err := manager.SessionUser(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := apikey.NewStore().Create(t.Context(), env.pool, apikey.CreateParams{UserID: u.ID, Name: "scoped", Role: auth.RoleViewer,
		Environments: []string{allowedEnv}, ExpiresAt: time.Now().Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	ids := favoriteIDs(t, env.doBearer(t, http.MethodGet, favoritesPath, nil, token))
	if len(ids) != 1 || ids[0] != allowed.ID {
		t.Fatalf("personal key escaped connection scope: %v", ids)
	}
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		requireStatus(t, env.doBearer(t, method, favoritesPath+"/"+hidden.ID.String(), nil, token), http.StatusForbidden)
	}
	requireStatus(t, env.doBearer(t, http.MethodDelete, favoritesPath+"/"+allowed.ID.String(), nil, token), http.StatusNoContent)
	ids = favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false))
	if len(ids) != 1 || ids[0] != hidden.ID {
		t.Fatalf("browser and personal key do not share owner: %v", ids)
	}
	// A connection moved to a hidden environment must disappear immediately.
	requireStatus(t, env.doBearer(t, http.MethodPut, favoritesPath+"/"+allowed.ID.String(), nil, token), http.StatusNoContent)
	if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, allowed.ID, hiddenEnv); err != nil {
		t.Fatal(err)
	}
	if ids := favoriteIDs(t, env.doBearer(t, http.MethodGet, favoritesPath, nil, token)); len(ids) != 0 {
		t.Fatalf("moved connection leaked through preference: %v", ids)
	}
	// Reusing the same issuer/subject for a new directory identity is not ownership.
	rebound := owner
	rebound.AuthenticatedAt = time.Now().Add(time.Second)
	if _, err := env.pool.Exec(t.Context(), `update api_users set identity_bound_at=$2,authenticated_at=$2 where id=$1`, u.ID, rebound.AuthenticatedAt); err != nil {
		t.Fatal(err)
	}
	if ids := favoriteIDs(t, env.do(t, http.MethodGet, favoritesPath, nil, &rebound, false)); len(ids) != 0 {
		t.Fatalf("rebound identity inherited previous favorites: %v", ids)
	}
	requireStatus(t, env.do(t, http.MethodGet, favoritesPath, nil, &owner, false), http.StatusForbidden)
}

func TestIntegrationConnectionFavoritesServiceOwnerScopeAndCascade(t *testing.T) {
	env, _, _ := newFavoritesEnv(t)
	principal := createPrincipalRow(t, env.pool, "favorite-service")
	other := createPrincipalRow(t, env.pool, "favorite-other")
	environment := "favorites-" + uuid.NewString()
	conn := createDraft(t, env.pool)
	if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, conn.ID, environment); err != nil {
		t.Fatal(err)
	}
	p, err := policy.NewStore().Create(t.Context(), env.pool, policy.CreateParams{SubjectKind: policy.SubjectPrincipal, Subject: principal.ID.String(), Environment: environment})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := servicetoken.NewStore().Create(t.Context(), env.pool, principal.ID, "first")
	if err != nil {
		t.Fatal(err)
	}
	secondToken, _, err := servicetoken.NewStore().Create(t.Context(), env.pool, principal.ID, "second")
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := servicetoken.NewStore().Create(t.Context(), env.pool, other.ID, "other")
	if err != nil {
		t.Fatal(err)
	}
	path := favoritesPath + "/" + conn.ID.String()
	requireStatus(t, env.doBearer(t, http.MethodPut, path, nil, token), http.StatusNoContent)
	if ids := favoriteIDs(t, env.doBearer(t, http.MethodGet, favoritesPath, nil, secondToken)); !slices.Equal(ids, []uuid.UUID{conn.ID}) {
		t.Fatalf("tokens do not share service owner: %v", ids)
	}
	if ids := favoriteIDs(t, env.doBearer(t, http.MethodGet, favoritesPath, nil, otherToken)); len(ids) != 0 {
		t.Fatalf("other service inherited favorites: %v", ids)
	}
	requireStatus(t, env.doBearer(t, http.MethodPut, path, nil, otherToken), http.StatusForbidden)
	if _, err := env.pool.Exec(t.Context(), `delete from scope_policies where id=$1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if ids := favoriteIDs(t, env.doBearer(t, http.MethodGet, favoritesPath, nil, token)); len(ids) != 0 {
		t.Fatalf("revoked scope leaked favorite: %v", ids)
	}
	requireStatus(t, env.doBearer(t, http.MethodDelete, path, nil, token), http.StatusForbidden)
	if _, err := env.pool.Exec(t.Context(), `delete from principals where id=$1`, principal.ID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from connection_favorites where service_principal_id=$1`, principal.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("service FK did not cascade: %d %v", count, err)
	}
}
