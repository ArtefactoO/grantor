package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestCodec возвращает Codec с фиксированным тестовым секретом.
func newTestCodec(t *testing.T) Codec {
	t.Helper()
	c, err := NewCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	return c
}

// newTestAuthenticator собирает Authenticator без сетевого OIDC: для
// Middleware/RequireRole достаточно session codec.
func newTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	return &Authenticator{codec: newTestCodec(t)}
}

// operatorEndpoint — фейковый operator-endpoint за Middleware+RequireRole.
func operatorEndpoint(a *Authenticator) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return a.Middleware(a.RequireRole(RoleOperator)(next))
}

// sessionCookie возвращает валидную session cookie с заданной ролью.
func sessionCookie(t *testing.T, c Codec, role Role) *http.Cookie {
	t.Helper()
	return &http.Cookie{
		Name: SessionCookieName,
		Value: c.Encode(Session{
			Subject:   "sub-" + string(role),
			Email:     string(role) + "@grantor.dev",
			Role:      role,
			ExpiresAt: time.Now().Add(time.Hour),
		}),
	}
}

func TestRoleAllows(t *testing.T) {
	cases := []struct {
		role     Role
		required Role
		want     bool
	}{
		{RoleAdmin, RoleViewer, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleAdmin, true},
		{RoleOperator, RoleViewer, true},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleAdmin, false},
		{Role("ghost"), RoleViewer, false},
		{RoleAdmin, Role("ghost"), false},
		{Role(""), Role(""), false},
	}
	for _, tc := range cases {
		if got := tc.role.Allows(tc.required); got != tc.want {
			t.Errorf("%q.Allows(%q) = %v, want %v", tc.role, tc.required, got, tc.want)
		}
	}
}

func TestParseRole(t *testing.T) {
	valid := map[string]Role{
		"viewer":   RoleViewer,
		"OPERATOR": RoleOperator,
		" Admin ":  RoleAdmin, //nolint:gocritic // пробелы намеренно: проверяем trim в ParseRole
	}
	for in, want := range valid {
		got, err := ParseRole(in)
		if err != nil {
			t.Errorf("ParseRole(%q): unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseRole(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"", "root", "admins"} {
		if _, err := ParseRole(in); err == nil {
			t.Errorf("ParseRole(%q): expected error", in)
		}
	}
}

func TestNewCodecEmptySecret(t *testing.T) {
	if _, err := NewCodec(nil); err == nil {
		t.Fatal("NewCodec(nil): expected error")
	}
}

func TestSessionRoundtrip(t *testing.T) {
	c := newTestCodec(t)
	want := Session{
		Subject:   "sub-1",
		Email:     "user@grantor.dev",
		Role:      RoleOperator,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}

	got, err := c.Decode(c.Encode(want))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Subject != want.Subject || got.Email != want.Email || got.Role != want.Role {
		t.Fatalf("roundtrip mismatch: got %+v, want %+v", got, want)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("roundtrip ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}

func TestSessionTamperedPayload(t *testing.T) {
	c := newTestCodec(t)
	token := c.Encode(Session{
		Subject:   "sub-1",
		Role:      RoleViewer,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	// Порча payload при сохранении исходной подписи.
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("unexpected token format: %q", token)
	}
	flipped := byte('A')
	if payload[0] == 'A' {
		flipped = 'B'
	}
	tampered := string(flipped) + payload[1:] + "." + sig

	if _, err := c.Decode(tampered); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Decode(tampered): err = %v, want ErrInvalidToken", err)
	}
}

func TestSessionForgedSignature(t *testing.T) {
	c := newTestCodec(t)
	other, err := NewCodec([]byte("another-secret-value-32-bytes-ok"))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}

	// Токен, подписанный чужим секретом, не проходит проверку.
	forged := other.Encode(Session{
		Subject:   "sub-1",
		Role:      RoleAdmin,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, err := c.Decode(forged); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Decode(forged): err = %v, want ErrInvalidToken", err)
	}
}

func TestSessionExpired(t *testing.T) {
	c := newTestCodec(t)
	token := c.Encode(Session{
		Subject:   "sub-1",
		Role:      RoleViewer,
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if _, err := c.Decode(token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("Decode(expired): err = %v, want ErrTokenExpired", err)
	}
}

func TestMiddlewarePutsSessionIntoContext(t *testing.T) {
	a := newTestAuthenticator(t)

	var got Session
	var ok bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = FromContext(r.Context())
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
	a.Middleware(next).ServeHTTP(httptest.NewRecorder(), req)

	if !ok {
		t.Fatal("session not found in context")
	}
	if got.Role != RoleAdmin || got.Email != "admin@grantor.dev" {
		t.Fatalf("unexpected session in context: %+v", got)
	}
}

func TestRequireRoleNoSession(t *testing.T) {
	a := newTestAuthenticator(t)

	rec := httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ops", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), `"error":"unauthorized"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRequireRoleInsufficientRole(t *testing.T) {
	a := newTestAuthenticator(t)

	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleViewer))
	rec := httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if !strings.Contains(rec.Body.String(), `"error":"forbidden"`) {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestRequireRoleHigherRoleAllowed(t *testing.T) {
	a := newTestAuthenticator(t)

	req := httptest.NewRequest(http.MethodGet, "/ops", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
	rec := httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
}

func TestRequireRoleCSRF(t *testing.T) {
	a := newTestAuthenticator(t)
	sess := Session{
		Subject:   "sub-operator",
		Email:     "operator@grantor.dev",
		Role:      RoleOperator,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	cookie := &http.Cookie{Name: SessionCookieName, Value: a.codec.Encode(sess)}

	newPost := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/ops", nil)
		req.AddCookie(cookie)
		return req
	}

	// Мутирующий запрос без CSRF-заголовка отклоняется.
	rec := httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, newPost())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST without CSRF header: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// Неверный token отклоняется.
	req := newPost()
	req.Header.Set(CSRFHeader, "deadbeef")
	rec = httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST with bad CSRF token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// Валидный token из CSRFToken пропускает запрос.
	req = newPost()
	req.Header.Set(CSRFHeader, a.codec.CSRFToken(sess))
	rec = httptest.NewRecorder()
	operatorEndpoint(a).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST with valid CSRF token: status = %d, want %d; body: %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestURLRewriteApply(t *testing.T) {
	rw := URLRewrite{From: "http://dex:5556", To: "http://localhost:55557"}

	in := "http://dex:5556/dex/auth?client_id=grantor"
	if got, want := rw.Apply(in), "http://localhost:55557/dex/auth?client_id=grantor"; got != want {
		t.Errorf("Apply(%q) = %q, want %q", in, got, want)
	}
	if got := rw.Apply("http://idp.example.com/auth"); got != "http://idp.example.com/auth" {
		t.Errorf("Apply without prefix match changed URL: %q", got)
	}
	if got := (URLRewrite{}).Apply(in); got != in {
		t.Errorf("zero rewrite changed URL: %q", got)
	}
}

func TestSetAndClearCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	SetCookie(rec, "token-value", time.Hour, true)

	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	c := cookies[0]
	if c.Name != SessionCookieName || c.Value != "token-value" {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	if !c.HttpOnly || !c.Secure || c.Path != "/" || c.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unexpected cookie attributes: %+v", c)
	}
	if c.MaxAge != int(time.Hour.Seconds()) {
		t.Fatalf("MaxAge = %d, want %d", c.MaxAge, int(time.Hour.Seconds()))
	}

	rec = httptest.NewRecorder()
	ClearCookie(rec)
	cookies = rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	if cookies[0].MaxAge >= 0 {
		t.Fatalf("ClearCookie MaxAge = %d, want negative", cookies[0].MaxAge)
	}
}

func TestEmailVerificationAllowed(t *testing.T) {
	verifiedTrue := true
	verifiedFalse := false
	cases := []struct {
		name     string
		verified *bool
		want     bool
	}{
		{"claim absent -> allowed", nil, true},
		{"claim true -> allowed", &verifiedTrue, true},
		{"claim false -> denied", &verifiedFalse, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := emailVerificationAllowed(tc.verified); got != tc.want {
				t.Errorf("emailVerificationAllowed(%v) = %v, want %v", tc.verified, got, tc.want)
			}
		})
	}
}

// TestRoleForEmail проверяет назначение роли по спискам, DefaultRole и
// deny-by-default (пустой DefaultRole → роли нет, вход отклоняется).
func TestRoleForEmail(t *testing.T) {
	deny := &Authenticator{
		admins:    emailSet([]string{"Admin@grantor.dev"}),
		operators: emailSet([]string{"op@grantor.dev"}),
		viewers:   emailSet([]string{"view@grantor.dev"}),
		// defaultRole пуст — deny-by-default.
	}
	legacy := &Authenticator{
		admins:      emailSet([]string{"admin@grantor.dev"}),
		defaultRole: RoleViewer,
	}

	cases := []struct {
		name  string
		a     *Authenticator
		email string
		role  Role
		ok    bool
	}{
		{"admin case-insensitive", deny, "admin@grantor.dev", RoleAdmin, true},
		{"operator", deny, "op@grantor.dev", RoleOperator, true},
		{"explicit viewer", deny, "view@grantor.dev", RoleViewer, true},
		{"unknown denied", deny, "stranger@grantor.dev", "", false},
		{"empty email denied", deny, "", "", false},
		{"legacy default viewer", legacy, "stranger@grantor.dev", RoleViewer, true},
		{"legacy admin wins over default", legacy, "admin@grantor.dev", RoleAdmin, true},
	}
	for _, tc := range cases {
		// Без групп: этот тест про маппинг по email, маппинг по группам
		// проверяет TestRoleForGroups.
		role, ok := tc.a.roleFor(tc.email, nil)
		if role != tc.role || ok != tc.ok {
			t.Errorf("%s: roleFor(%q) = (%q, %v), want (%q, %v)",
				tc.name, tc.email, role, ok, tc.role, tc.ok)
		}
	}
}

// Выход уводит на отдельный экран, а не на "/": сессия у IdP жива, и
// возврат на корень немедленно проходил бы вход заново.
func TestLogoutRedirectsToLoggedOutScreen(t *testing.T) {
	a := newTestAuthenticator(t)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/logout", nil)
	req.AddCookie(sessionCookie(t, a.codec, RoleAdmin))
	a.LogoutHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != LoggedOutPath {
		t.Fatalf("Location = %q, want %q", got, LoggedOutPath)
	}

	// Иначе экран сообщал бы о выходе, которого не произошло.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.Value == "" && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatalf("session cookie was not cleared: %v", rec.Result().Cookies())
	}
}
