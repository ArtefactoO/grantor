package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeTokenAuth — тестовая реализация TokenAuthenticator: валиден ровно один
// заранее известный токен, для которого возвращается сессия sess.
type fakeTokenAuth struct {
	token string
	sess  Session
}

func (f fakeTokenAuth) AuthenticateToken(_ context.Context, token string) (Session, bool) {
	if token == f.token {
		return f.sess, true
	}
	return Session{}, false
}

// tokenAuthenticator собирает Authenticator с token-auth и codec.
func tokenAuthenticator(t *testing.T, sess Session) *Authenticator {
	t.Helper()
	return &Authenticator{
		codec:     newTestCodec(t),
		tokenAuth: fakeTokenAuth{token: "grt_valid", sess: sess},
	}
}

func serviceSession(role Role) Session {
	return Session{
		Subject:   "principal-uuid",
		Email:     "svc",
		Role:      role,
		Service:   true,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		name    string
		headers []string
		want    string
		present bool
	}{
		{"valid", []string{"Bearer grt_abc"}, "grt_abc", true},
		{"scheme case", []string{"bearer grt_abc"}, "grt_abc", true},
		{"absent", nil, "", false},
		{"empty", []string{""}, "", true},
		{"unsupported scheme", []string{"Basic dXNlcg=="}, "", true},
		{"missing value", []string{"Bearer"}, "", true},
		{"empty value", []string{"Bearer "}, "", true},
		{"leading whitespace", []string{" Bearer grt_abc"}, "", true},
		{"tab separator", []string{"Bearer\tgrt_abc"}, "", true},
		{"multiple spaces", []string{"Bearer   grt_abc"}, "", true},
		{"trailing whitespace", []string{"Bearer grt_abc "}, "", true},
		{"token whitespace", []string{"Bearer grt_a bc"}, "", true},
		{"unicode whitespace", []string{"Bearer grt_a\u00a0bc"}, "", true},
		{"duplicate", []string{"Bearer grt_abc", "Bearer grt_abc"}, "", true},
		{"comma joined", []string{"Bearer grt_abc, Bearer grt_abc"}, "", true},
		{"comma without space", []string{"Bearer grt_abc,grt_abc"}, "", true},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		for _, header := range tc.headers {
			req.Header.Add("Authorization", header)
		}
		got, ok := bearerToken(req)
		if ok != tc.present || got != tc.want {
			t.Errorf("bearerToken(%s) = (%q, %v), want (%q, %v)", tc.name, got, ok, tc.want, tc.present)
		}
	}
}

func TestAnyAuthorizationHeaderPreventsCookieFallback(t *testing.T) {
	cases := []struct {
		name    string
		headers http.Header
	}{
		{"basic", http.Header{"Authorization": []string{"Basic fixture"}}},
		{"leading whitespace", http.Header{"Authorization": []string{" Bearer grt_valid"}}},
		{"tab separator", http.Header{"Authorization": []string{"Bearer\tgrt_valid"}}},
		{"token whitespace", http.Header{"Authorization": []string{"Bearer grt_ valid"}}},
		{"empty", http.Header{"Authorization": []string{""}}},
		{"empty values", http.Header{"Authorization": nil}},
		{"no token", http.Header{"Authorization": []string{"Bearer"}}},
		{"duplicate", http.Header{"Authorization": []string{"Bearer grt_valid", "Bearer grt_valid"}}},
		{"mixed-case duplicate", http.Header{"Authorization": []string{"Bearer grt_valid"}, "authorization": []string{"Bearer grt_valid"}}},
	}
	for _, tokenAuthConfigured := range []bool{false, true} {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			for _, tc := range cases {
				t.Run(tc.name+"/"+method+"/"+map[bool]string{false: "cookie-only", true: "token-enabled"}[tokenAuthConfigured], func(t *testing.T) {
					a := newTestAuthenticator(t)
					if tokenAuthConfigured {
						a.tokenAuth = fakeTokenAuth{token: "grt_valid", sess: serviceSession(RoleAdmin)}
					}
					endpoint := a.Middleware(a.RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
					req := httptest.NewRequest(method, "/connections", nil)
					req.Header = tc.headers.Clone()
					cookie := sessionCookie(t, a.codec, RoleAdmin)
					req.AddCookie(cookie)
					sess, err := a.codec.Decode(cookie.Value)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set(CSRFHeader, a.codec.CSRFToken(sess))
					rec := httptest.NewRecorder()
					endpoint.ServeHTTP(rec, req)
					if rec.Code != http.StatusUnauthorized {
						t.Fatalf("invalid Authorization authenticated with cookie: %d", rec.Code)
					}
				})
			}
		}
	}
}

func TestMeHandlerRejectsAuthorizationCookieFallback(t *testing.T) {
	a := newTestAuthenticator(t)
	for _, header := range []string{"Basic fixture", "Bearer invalid", "Bearer", ""} {
		req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
		req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
		req.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		a.MeHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("/auth/me Authorization %q fell back to cookie: %d", header, rec.Code)
		}
	}
}

func TestMeHandlerPreservesVerifiedBearerContext(t *testing.T) {
	a := tokenAuthenticator(t, serviceSession(RoleOperator))
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Authorization", "Bearer grt_valid")
	rec := httptest.NewRecorder()
	a.Middleware(a.MeHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verified bearer context no longer accepted by /auth/me: %d", rec.Code)
	}
}

func TestSignedCookieIssuerBindingBeforeAuthorizationAndObservation(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, endpointKind := range []string{"require-role", "me"} {
			for _, tc := range []struct {
				name, issuer string
				status       int
			}{
				{"current", "https://current-idp.test", http.StatusOK},
				{"legacy", "", http.StatusOK},
				{"foreign", "https://foreign-idp.test", http.StatusUnauthorized},
			} {
				t.Run(endpointKind+"/"+method+"/"+tc.name, func(t *testing.T) {
					a := newTestAuthenticator(t)
					a.issuer = "https://current-idp.test"
					observed := 0
					a.SetSessionObserver(func(_ context.Context, _ Session) error { observed++; return nil })
					sess := Session{Issuer: tc.issuer, Subject: "shared-subject", Email: "admin@example.test", Role: RoleAdmin, ExpiresAt: time.Now().Add(time.Hour)}
					cookie := a.codec.Encode(sess)
					if _, err := a.codec.Decode(cookie); err != nil {
						t.Fatalf("fixture signature is not valid: %v", err)
					}
					req := httptest.NewRequest(method, "/private", nil)
					req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
					req.Header.Set(CSRFHeader, a.codec.CSRFToken(sess))
					endpoint := a.MeHandler()
					if endpointKind == "require-role" {
						endpoint = a.Middleware(a.RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
					}
					rec := httptest.NewRecorder()
					endpoint.ServeHTTP(rec, req)
					if rec.Code != tc.status {
						t.Fatalf("valid-MAC %s cookie status=%d want=%d", tc.name, rec.Code, tc.status)
					}
					if tc.name == "foreign" && observed != 0 {
						t.Fatal("foreign cookie reached identity observer")
					}
				})
			}
		}
	}
}

func TestPersonalBearerDoesNotBecomeServiceActor(t *testing.T) {
	sess := Session{Subject: "opaque-sub", Email: "person@example.test", Role: RoleOperator, APIKeyID: "key-id", APIUserID: "user-id"}
	a := tokenAuthenticator(t, sess)
	endpoint := a.Middleware(a.RequireRole(RoleOperator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := FromContext(r.Context())
		if !ok || !IsTokenAuth(r.Context()) || got.Service || got.ActorType() != "user" || got.ActorID() != sess.Email {
			t.Errorf("personal key transport/actor = %+v", got)
		}
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest(http.MethodPost, "/accounts", nil)
	req.Header.Set("Authorization", "Bearer grt_valid")
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("personal key POST without CSRF: %d", rec.Code)
	}
}

func TestBearerNeverFallsBackToCookieWithoutTokenAuthenticator(t *testing.T) {
	a := newTestAuthenticator(t)
	endpoint := a.Middleware(a.RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	for _, header := range []string{"Bearer wrong", "Bearer", "Bearer "} {
		req := httptest.NewRequest(http.MethodGet, "/connections", nil)
		req.Header.Set("Authorization", header)
		req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
		rec := httptest.NewRecorder()
		endpoint.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%q with valid cookie got %d", header, rec.Code)
		}
	}
}

func TestRuntimeCredentialMetadataIsNotSignedIntoCookies(t *testing.T) {
	c := newTestCodec(t)
	sess := Session{Issuer: "https://idp.test/", Subject: "opaque-sub", Username: "alice", AuthenticatedAt: time.Now(),
		Role: RoleAdmin, ExpiresAt: time.Now().Add(time.Hour), APIKeyID: "key-id", APIUserID: "owner-id", OwnerRole: RoleAdmin,
		Environments: []string{"prod"}, Permissions: []string{"connections:create"}}
	decoded, err := c.Decode(c.Encode(sess))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.APIKeyID != "" || decoded.APIUserID != "" || decoded.OwnerRole != "" || decoded.Environments != nil || decoded.Permissions != nil {
		t.Fatalf("runtime credential metadata persisted in cookie: %+v", decoded)
	}
	if decoded.Issuer != sess.Issuer || decoded.Username != sess.Username || decoded.AuthenticatedAt.IsZero() {
		t.Fatal("verified identity was lost")
	}
}

func TestLegacyCookieOwnerObservationNeverRunsForBearer(t *testing.T) {
	a := newTestAuthenticator(t)
	a.issuer = "https://trusted-idp.test"
	observed := 0
	a.SetSessionObserver(func(_ context.Context, s Session) error {
		observed++
		if s.Issuer != a.issuer || !s.AuthenticatedAt.IsZero() {
			t.Errorf("legacy issuer or timestamp rewritten: %+v", s)
		}
		return nil
	})
	endpoint := a.Middleware(a.RequireRole(RoleViewer)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleViewer))
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || observed != 1 {
		t.Fatalf("legacy cookie status=%d observations=%d", rec.Code, observed)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleViewer))
	req.Header.Set("Authorization", "Bearer invalid")
	rec = httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized || observed != 1 {
		t.Fatalf("bearer renewed browser identity status=%d observations=%d", rec.Code, observed)
	}
}

// TestTokenAuthMutatingSkipsCSRF: service-токен аутентифицирует мутирующий
// запрос без CSRF-заголовка (cookie не участвует — нет CSRF-риска).
func TestTokenAuthMutatingSkipsCSRF(t *testing.T) {
	a := tokenAuthenticator(t, serviceSession(RoleOperator))
	endpoint := a.Middleware(a.RequireRole(RoleOperator)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sess, ok := FromContext(r.Context())
			if !ok || !sess.Service {
				t.Error("expected service session in context")
			}
			w.WriteHeader(http.StatusOK)
		})))

	req := httptest.NewRequest(http.MethodPost, "/ops", nil)
	req.Header.Set("Authorization", "Bearer grt_valid")
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid service token: status = %d, want %d; body: %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestTokenAuthInvalidToken: невалидный bearer-токен не откатывается к cookie
// и даёт 401.
func TestTokenAuthInvalidToken(t *testing.T) {
	a := tokenAuthenticator(t, serviceSession(RoleOperator))
	endpoint := a.Middleware(a.RequireRole(RoleViewer)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))

	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	req.Header.Set("Authorization", "Bearer grt_wrong")
	// Наличие валидной cookie не должно спасать запрос с bearer-токеном.
	req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid bearer token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestTokenAuthInsufficientRole: роль service-принципала ниже требуемой → 403.
func TestTokenAuthInsufficientRole(t *testing.T) {
	a := tokenAuthenticator(t, serviceSession(RoleViewer))
	endpoint := a.Middleware(a.RequireRole(RoleOperator)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))

	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	req.Header.Set("Authorization", "Bearer grt_valid")
	rec := httptest.NewRecorder()
	endpoint.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("insufficient service role: status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestSessionActor: actor_type/actor_id зависят от типа сессии.
func TestSessionActor(t *testing.T) {
	human := Session{Subject: "idp-sub", Email: "op@grantor.dev"}
	if human.ActorType() != "user" || human.ActorID() != "op@grantor.dev" {
		t.Errorf("human actor = (%q, %q), want (user, op@grantor.dev)", human.ActorType(), human.ActorID())
	}
	service := Session{Subject: "principal-uuid", Email: "svc", Service: true}
	if service.ActorType() != "service" || service.ActorID() != "principal-uuid" {
		t.Errorf("service actor = (%q, %q), want (service, principal-uuid)", service.ActorType(), service.ActorID())
	}
}
