//go:build integration

// Integration-тесты rate limiting API v1: мутирующий endpoint за лимитом
// отдаёт 429 после исчерпания burst, read-path не лимитируется, per-subject
// вёдра независимы; reveal/share и login лимитируются отдельными вёдрами.
// Разделяют хелперы с api_integration_test.go (session, do, requireStatus).
package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// newRateLimitEnv собирает API-сервер с включённым лимитером и обёрткой
// LimitMutating (как cmd/api). Vault/Yopass не нужны: тесты бьют по путям,
// которые до них не доходят.
func newRateLimitEnv(t *testing.T, limits api.RateLimitConfig) *testEnv {
	t.Helper()
	registerFakeAdapter()
	pool := pgtest.Pool(t)

	// pgtest.Pool разделяет одну БД между тестами пакета, а rate_limit_buckets
	// персистентна: без очистки вёдра (ключи по фиксированному session subject)
	// переносятся между тестами и рушат изоляцию. Начинаем каждый тест с пустой
	// таблицы.
	if _, err := pool.Exec(t.Context(), "truncate rate_limit_buckets"); err != nil {
		t.Fatalf("truncate rate_limit_buckets: %v", err)
	}

	authn, err := auth.New(t.Context(), auth.Config{
		IssuerURL:     newFakeOIDC(t).URL,
		ClientID:      "grantor",
		RedirectURL:   "http://localhost/auth/callback",
		SessionSecret: []byte(testSessionSecret),
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	codec, err := auth.NewCodec([]byte(testSessionSecret))
	if err != nil {
		t.Fatalf("auth.NewCodec: %v", err)
	}
	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatalf("jobs.NewInsertOnly: %v", err)
	}
	server, err := api.New(api.Config{
		Pool:        pool,
		Connections: connections.NewStore(),
		Inventory:   inventory.NewStore(),
		Operations:  operations.NewStore(),
		Audit:       audit.NewWriter(),
		Credentials: credentials.NewService(nil, nil),
		Dispatcher:  dispatcher,
		Auth:        authn,
		RateLimiter: ratelimit.New(pool),
		RateLimits:  limits,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(server.LimitMutating(mux)))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: codec}
}

// slowLimit — медленный refill (Rate ~0), чтобы burst исчерпывался
// детерминированно, а retryAfter был осмысленно большим.
func slowLimit(burst float64) ratelimit.Limit {
	return ratelimit.Limit{Rate: 0.01, Burst: burst}
}

func TestIntegrationMutatingRateLimit(t *testing.T) {
	env := newRateLimitEnv(t, api.RateLimitConfig{
		Login:    slowLimit(5),
		Reveal:   slowLimit(5),
		Mutating: slowLimit(3),
	})
	operator := session(auth.RoleOperator)

	// DELETE несуществующего binding проходит лимитер и отдаёт 404: удобный
	// мутирующий путь без setup (Vault/аккаунтов не нужно).
	path := "/api/v1/bindings/" + uuid.NewString()
	for i := 0; i < 3; i++ {
		resp := env.do(t, http.MethodDelete, path, nil, &operator, true)
		requireStatus(t, resp, http.StatusNotFound)
	}
	// Burst исчерпан — 429 с Retry-After.
	resp := env.do(t, http.MethodDelete, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusTooManyRequests)
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}

	// Read-path не лимитируется даже после исчерпания mutating-ведра.
	resp = env.do(t, http.MethodGet, "/api/v1/connections", nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)

	// Другой subject не затронут: ведро per-subject.
	admin := session(auth.RoleAdmin)
	resp = env.do(t, http.MethodDelete, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationRevealRateLimit(t *testing.T) {
	env := newRateLimitEnv(t, api.RateLimitConfig{
		Login:    slowLimit(5),
		Reveal:   slowLimit(3),
		Mutating: slowLimit(50), // высоко, чтобы reveal-ведро упёрлось первым
	})
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	// Managed account без vault path: share доходит до reveal-лимита, затем
	// отвечает 409 (нет сохранённого credential) — Vault/Yopass не нужны.
	acct := managedAccount(t, env.pool, conn.ID, "")
	path := "/api/v1/accounts/" + acct.ID.String() + "/share"

	for i := 0; i < 3; i++ {
		resp := env.do(t, http.MethodPost, path, nil, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}
	resp := env.do(t, http.MethodPost, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusTooManyRequests)
}

func TestIntegrationLoginRateLimit(t *testing.T) {
	pool := pgtest.Pool(t)
	limiter := ratelimit.New(pool)
	lim := slowLimit(3)

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := api.LimitLoginHandler(limiter, lim, next)

	// Уникальный per-IP ключ на прогон: строки ведра не чистятся между
	// запусками, поэтому фиксированный IP протёк бы между тестами.
	ip := "itest-login-" + uuid.NewString()
	call := func() int {
		req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
		req.Header.Set("X-Forwarded-For", ip)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 3; i++ {
		if code := call(); code != http.StatusOK {
			t.Fatalf("login %d: code = %d, want 200 within burst", i, code)
		}
	}
	if code := call(); code != http.StatusTooManyRequests {
		t.Errorf("login past burst: code = %d, want 429", code)
	}

	// Другой IP не затронут (per-IP ведро).
	otherIP := "itest-login-" + uuid.NewString()
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	req.Header.Set("X-Forwarded-For", otherIP)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("other IP login: code = %d, want 200", rec.Code)
	}
}
