//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type apiIdentityFixture struct {
	identity directory.APIIdentity
	err      error
	calls    int
}

func (p *apiIdentityFixture) APIIdentity(_ context.Context, username string) (directory.APIIdentity, error) {
	p.calls++
	if p.err != nil {
		return directory.APIIdentity{}, p.err
	}
	identity := p.identity
	identity.Username = username
	return identity, nil
}

func TestAPIKeyOwnerLeaseRoleAndUIDRefresh(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := apikey.NewStore()
	fixture := &apiIdentityFixture{identity: directory.APIIdentity{UID: "immutable-one", Email: "alice@example.test", Groups: []string{"admin"}, Status: directory.StatusActive}}
	manager := api.NewAPIKeyIdentityManager(pool, store, fixture, time.Minute)
	issuer := "https://idp.test/" + uuid.NewString()
	manager.SetIssuer(issuer)
	manager.SetRoleResolver(func(_ string, groups []string) (auth.Role, bool) {
		if len(groups) == 0 {
			return "", false
		}
		role, err := auth.ParseRole(groups[0])
		return role, err == nil
	})
	sess := auth.Session{Issuer: issuer, Subject: "opaque-subject", Username: "alice", Email: fixture.identity.Email, Role: auth.RoleAdmin,
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := manager.ObserveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	owner, err := manager.SessionUser(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := manager.SessionUser(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.calls != 1 {
		t.Fatalf("unchanged signed cookie renewed owner %d times", fixture.calls)
	}
	if _, err := pool.Exec(ctx, `update api_users set authorized_until=now()-interval '1 second' where id=$1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SessionUser(ctx, sess); err != nil {
		t.Fatalf("valid browser could not renew same identity before first key: %v", err)
	}
	if fixture.calls != 2 {
		t.Fatalf("stale browser authorization refreshed %d times", fixture.calls)
	}
	plaintext, key, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "manager", Role: auth.RoleAdmin, ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := store.Authenticate(ctx, pool, plaintext); err != nil {
			t.Fatal(err)
		}
	}
	if fixture.calls != 2 {
		t.Fatalf("API authentication queried directory %d times", fixture.calls)
	}
	fixture.identity.Groups = []string{"viewer"}
	if err := manager.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Authenticate(ctx, pool, plaintext)
	if err != nil || got.Role != auth.RoleViewer {
		t.Fatalf("current role downgrade: %+v %v", got, err)
	}
	fixture.err = errors.New("dependency unavailable")
	failedLogin := sess
	failedLogin.AuthenticatedAt = time.Now().Add(time.Second)
	if _, err := manager.SessionUser(ctx, failedLogin); err == nil {
		t.Fatal("failed fresh login used an older owner's UID verification")
	}
	before, err := store.GetUserByID(ctx, pool, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Refresh(ctx); err == nil {
		t.Fatal("directory outage was hidden")
	}
	after, err := store.GetUserByID(ctx, pool, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !after.Active || !after.AuthorizedUntil.Equal(before.AuthorizedUntil) {
		t.Fatal("directory outage disabled owner or extended lease")
	}
	if _, err := pool.Exec(ctx, `update api_users set authorized_until=now()-interval '1 second' where id=$1`, owner.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("stale lease accepted: %v", err)
	}
	fixture.err = nil
	fixture.identity.Status = directory.StatusDisabled
	if err := manager.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("disabled owner accepted: %v", err)
	}
	fixture.identity.Status = directory.StatusActive
	fixture.identity.Groups = []string{"admin"}
	fixture.identity.UID = "immutable-two"
	if err := manager.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("reassigned username accepted: %v", err)
	}
	var revoked *time.Time
	if err := pool.QueryRow(ctx, `select revoked_at from personal_api_keys where id=$1`, key.ID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked == nil {
		t.Fatal("reassigned identity did not revoke old key")
	}
	newSess := sess
	newSess.AuthenticatedAt = time.Now().Add(time.Millisecond)
	if err := manager.ObserveSession(ctx, newSess); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.SessionUser(ctx, sess); !errors.Is(err, apikey.ErrOwnerUnavailable) {
		t.Fatalf("old browser cookie could issue keys after identity reassignment: %v", err)
	}
	if _, err := manager.SessionUser(ctx, newSess); err != nil {
		t.Fatalf("fresh login was not allowed to rebind: %v", err)
	}
}

func TestAPIKeySnapshotCannotOutliveOriginalSession(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := apikey.NewStore()
	manager := api.NewAPIKeyIdentityManager(pool, store, nil, time.Minute)
	issuer := "https://snapshot-idp.test/" + uuid.NewString()
	manager.SetIssuer(issuer)
	sess := auth.Session{Issuer: issuer, Subject: uuid.NewString(), Username: "alice", Email: "alice@example.test", Role: auth.RoleOperator,
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(20 * time.Minute)}
	if err := manager.ObserveSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	owner, err := manager.SessionUser(ctx, sess)
	if err != nil {
		t.Fatal(err)
	}
	if maximum := manager.MaxExpiry(sess, time.Now()); !maximum.Equal(sess.ExpiresAt) {
		t.Fatalf("snapshot expiry exceeded original session: %v", maximum)
	}
	if _, _, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "overlong", Role: auth.RoleOperator,
		ExpiresAt: sess.ExpiresAt.Add(time.Minute)}); !errors.Is(err, apikey.ErrOwnerUnavailable) {
		t.Fatalf("store accepted key beyond snapshot lease: %v", err)
	}
	plaintext, _, err := store.Create(ctx, pool, apikey.CreateParams{UserID: owner.ID, Name: "short", Role: auth.RoleOperator, ExpiresAt: time.Now().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	// Enabling safe directory refresh never lends old snapshot keys a new UID.
	owner.DirectoryManaged = true
	owner.DirectoryUID = "newly-verified-uid"
	owner.AuthenticatedAt = time.Now().Add(time.Second)
	if _, err := store.SaveLogin(ctx, pool, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(ctx, pool, plaintext); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("snapshot key inherited refreshed identity: %v", err)
	}
}

func newPersonalAPIKeyEnv(t *testing.T) (*testEnv, *api.APIKeyIdentityManager, string) {
	t.Helper()
	registerFakeAdapter()
	pool := pgtest.Pool(t)
	store := apikey.NewStore()
	issuer := newFakeOIDC(t).URL
	manager := api.NewAPIKeyIdentityManager(pool, store, nil, time.Minute)
	manager.SetIssuer(issuer)
	authn, err := auth.New(t.Context(), auth.Config{IssuerURL: issuer, ClientID: "grantor", RedirectURL: "http://localhost/auth/callback",
		SessionSecret: []byte(testSessionSecret), TokenAuth: api.NewPersonalKeyAuth(pool, store, issuer), SessionObserver: manager.ObserveSession})
	if err != nil {
		t.Fatal(err)
	}
	manager.SetRoleResolver(authn.RoleFor)
	codec, err := auth.NewCodec([]byte(testSessionSecret))
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.New(api.Config{Pool: pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Operations: operations.NewStore(),
		Audit: audit.NewWriter(), Credentials: credentials.NewService(nil, nil), Dispatcher: dispatcher, Auth: authn, APIKeys: store, APIKeyIdentity: manager})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: codec}, manager, issuer
}

func TestPersonalAPIKeyRejectsForeignIssuer(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	store := apikey.NewStore()
	for _, tc := range []struct {
		name, ownerIssuer string
		status            int
	}{
		{"current issuer", issuer, http.StatusOK},
		{"foreign issuer", issuer + "/other-realm", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			owner, err := store.SaveLogin(t.Context(), env.pool, apikey.User{Issuer: tc.ownerIssuer, Subject: "opaque-shared-sub", Username: "alice",
				Email: "alice@example.test", Role: auth.RoleAdmin, Active: true, AuthorizedUntil: now.Add(time.Hour), AuthenticatedAt: now, IdentityBoundAt: now})
			if err != nil {
				t.Fatal(err)
			}
			plaintext, _, err := store.Create(t.Context(), env.pool, apikey.CreateParams{UserID: owner.ID, Name: "realm-scoped", Role: auth.RoleAdmin, ExpiresAt: now.Add(30 * time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.Authenticate(t.Context(), env.pool, plaintext); err != nil {
				t.Fatalf("fixture is not an active fresh credential: %v", err)
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, env.srv.URL+"/api/v1/me", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+plaintext)
			cookie := auth.Session{Issuer: issuer, Subject: "current-admin", Email: "admin@example.test", Role: auth.RoleAdmin, ExpiresAt: now.Add(time.Hour)}
			req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: env.codec.Encode(cookie)})
			response, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			requireStatus(t, response, tc.status)
			response.Body.Close() //nolint:errcheck
			if _, ok := api.NewPersonalKeyAuth(env.pool, store, "").AuthenticateToken(t.Context(), plaintext); ok {
				t.Fatal("missing issuer accepted a personal key")
			}
		})
	}
}

func TestPersonalAPIKeyHTTPBrowserOwnershipAndSecrets(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	owner := auth.Session{Issuer: issuer, Subject: "opaque-" + uuid.NewString(), Username: "alice", Email: "alice@example.test", Role: auth.RoleOperator,
		AuthenticatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour)}
	body := map[string]any{"name": "my-cli", "role": "operator", "expires_at": time.Now().Add(30 * time.Minute)}
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", body, nil, false), http.StatusUnauthorized)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", body, &owner, false), http.StatusForbidden)
	create := env.do(t, http.MethodPost, "/api/v1/me/api-keys", body, &owner, true)
	requireStatus(t, create, http.StatusCreated)
	if create.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("key plaintext response is cacheable")
	}
	var issued struct {
		Token string `json:"token"`
		Key   struct {
			ID     uuid.UUID `json:"id"`
			UserID uuid.UUID `json:"user_id"`
		} `json:"api_key"`
	}
	if err := json.Unmarshal(readBody(t, create), &issued); err != nil {
		t.Fatal(err)
	}
	if !apikey.HasTokenPrefix(issued.Token) || issued.Key.ID == uuid.Nil {
		t.Fatal("missing one-time token")
	}
	listing := env.do(t, http.MethodGet, "/api/v1/me/api-keys", nil, &owner, false)
	requireStatus(t, listing, http.StatusOK)
	raw := readBody(t, listing)
	if strings.Contains(string(raw), issued.Token) || strings.Contains(string(raw), apikey.HashToken(issued.Token)) {
		t.Fatal("list leaked key plaintext or digest")
	}
	var listed struct {
		UserID  uuid.UUID   `json:"user_id"`
		Maximum time.Time   `json:"max_expires_at"`
		Roles   []auth.Role `json:"allowed_roles"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		t.Fatal(err)
	}
	if listed.UserID != issued.Key.UserID || listed.Maximum.After(owner.ExpiresAt) || len(listed.Roles) != 2 {
		t.Fatalf("incorrect owner capabilities: %+v", listed)
	}
	for _, path := range []string{"/api/v1/me/api-keys", "/api/v1/me/api-keys/" + issued.Key.ID.String()} {
		method := http.MethodGet
		if path != "/api/v1/me/api-keys" {
			method = http.MethodDelete
		}
		req, err := http.NewRequestWithContext(t.Context(), method, env.srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		requireStatus(t, resp, http.StatusForbidden)
		resp.Body.Close() //nolint:errcheck
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, env.srv.URL+"/api/v1/me/api-keys", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+issued.Token)
	bearerCreate, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, bearerCreate, http.StatusForbidden)
	bearerCreate.Body.Close() //nolint:errcheck
	other := owner
	other.Subject = "other-" + uuid.NewString()
	other.Username = "bob"
	other.Email = "bob@example.test"
	requireStatus(t, env.do(t, http.MethodDelete, "/api/v1/me/api-keys/"+issued.Key.ID.String(), nil, &other, true), http.StatusNotFound)
	for _, role := range []string{"admin", "invalid"} {
		invalid := map[string]any{"name": "escalate", "role": role, "expires_at": time.Now().Add(30 * time.Minute)}
		requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", invalid, &owner, true), http.StatusForbidden)
	}
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "long", "expires_at": time.Now().Add(2 * time.Hour)}, &owner, true), http.StatusBadRequest)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "no-expiry"}, &owner, true), http.StatusBadRequest)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/me/api-keys", map[string]any{"name": "empty-scope", "expires_at": time.Now().Add(time.Minute), "environments": []string{}}, &owner, true), http.StatusBadRequest)
	var metadata []byte
	rows, err := env.pool.Query(t.Context(), `select metadata from audit_events where action in ('api_key.created','api_key.revoked') and actor_id=$1`, owner.Email)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := rows.Scan(&metadata); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(metadata), issued.Token) || strings.Contains(string(metadata), apikey.HashToken(issued.Token)) {
			t.Fatal("audit leaked token or digest")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodDelete, "/api/v1/me/api-keys/"+issued.Key.ID.String(), nil, &owner, true), http.StatusOK)
	if _, err := apikey.NewStore().Authenticate(t.Context(), env.pool, issued.Token); !errors.Is(err, apikey.ErrInvalidToken) {
		t.Fatalf("HTTP revocation not effective: %v", err)
	}
}
