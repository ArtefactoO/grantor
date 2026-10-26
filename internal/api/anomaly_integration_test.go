//go:build integration

// Integration-тесты детекции аномальной частоты credential reveal/share
// (разделы 24/25, ADR-0011): за порогом эмитится ровно одно audit-событие
// security.reveal_rate_anomaly на субъект за окно (throttled), reveal-
// счётчики растут, а /metrics (общий registry) их экспортирует. Детекция не
// блокирует запрос — сам share доходит до 409 (нет сохранённого credential),
// Vault/Yopass не нужны.
package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	dto "github.com/prometheus/client_model/go"

	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// newAnomalyEnv собирает API-сервер с включённой детекцией аномалий и
// щедрыми rate-лимитами (чтобы попытки share доходили до детектора, а не
// упирались в лимитер).
func newAnomalyEnv(t *testing.T, window ratelimit.AnomalyWindow) *testEnv {
	t.Helper()
	registerFakeAdapter()
	pool := pgtest.Pool(t)

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
	// Щедрые лимиты: burst 100 на всех поверхностях, чтобы share проходил
	// лимитер и доходил до детектора.
	generous := ratelimit.Limit{Rate: 100, Burst: 100}
	server, err := api.New(api.Config{
		Pool:            pool,
		Connections:     connections.NewStore(),
		Inventory:       inventory.NewStore(),
		Operations:      operations.NewStore(),
		Audit:           audit.NewWriter(),
		Credentials:     credentials.NewService(nil, nil),
		Dispatcher:      dispatcher,
		Auth:            authn,
		RateLimiter:     ratelimit.New(pool),
		RateLimits:      api.RateLimitConfig{Login: generous, Reveal: generous, Mutating: generous},
		AnomalyDetector: ratelimit.NewAnomalyDetector(pool),
		AnomalyWindow:   window,
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

// uniqueOperator возвращает operator-сессию с уникальными subject/email,
// чтобы окно аномалии и ведро лимитера этого теста не пересекались с чужими.
func uniqueOperator() auth.Session {
	id := "itest-anomaly-" + uuid.NewString()
	return auth.Session{
		Subject:   id,
		Email:     id + "@grantor.dev",
		Role:      auth.RoleOperator,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// anomalyAuditCount считает события security.reveal_rate_anomaly по актору.
func anomalyAuditCount(t *testing.T, env *testEnv, actorID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(t.Context(), `
		select count(*) from audit_events
		where action = 'security.reveal_rate_anomaly' and actor_id = $1`,
		actorID,
	).Scan(&n); err != nil {
		t.Fatalf("count anomaly audit: %v", err)
	}
	return n
}

func TestIntegrationRevealAnomaly(t *testing.T) {
	env := newAnomalyEnv(t, ratelimit.AnomalyWindow{Threshold: 3, Window: time.Hour})
	operator := uniqueOperator()
	conn := activeFakeConnection(t, env.pool)
	// Managed account без vault path: share доходит до guardReveal (метрика +
	// детекция), затем 409 (нет сохранённого credential). Vault/Yopass не нужны.
	acct := managedAccount(t, env.pool, conn.ID, "")
	path := "/api/v1/accounts/" + acct.ID.String() + "/share"

	revealBefore := revealCounter(t, metrics.OperationAccountShare, metrics.ResultAllowed)

	// Ниже порога (2 из 3) — сигнала нет.
	for i := 0; i < 2; i++ {
		resp := env.do(t, http.MethodPost, path, nil, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}
	if got := anomalyAuditCount(t, env, operator.ActorID()); got != 0 {
		t.Fatalf("anomaly audit rows under threshold = %d, want 0", got)
	}

	// Третья попытка достигает порога — ровно один сигнал.
	resp := env.do(t, http.MethodPost, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	if got := anomalyAuditCount(t, env, operator.ActorID()); got != 1 {
		t.Fatalf("anomaly audit rows at threshold = %d, want 1", got)
	}

	// Дальше в том же окне — счётчик растёт, сигнал троттлится (остаётся один).
	for i := 0; i < 3; i++ {
		resp := env.do(t, http.MethodPost, path, nil, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}
	if got := anomalyAuditCount(t, env, operator.ActorID()); got != 1 {
		t.Errorf("anomaly audit rows past threshold = %d, want 1 (throttled)", got)
	}

	// audit-событие несёт actionable metadata (count/threshold/window), без
	// секретов и без ссылки.
	assertAnomalyMetadata(t, env, operator.ActorID())

	// reveal-счётчик вырос ровно на число allowed-попыток (6).
	if got := revealCounter(t, metrics.OperationAccountShare, metrics.ResultAllowed); got < revealBefore+6 {
		t.Errorf("reveal_total allowed = %v, want >= %v", got, revealBefore+6)
	}
	// anomaly-счётчик экспортирован и вырос.
	if got := revealAnomalyCounter(t, metrics.OperationAccountShare); got < 1 {
		t.Errorf("reveal_anomaly_total = %v, want >= 1", got)
	}
}

func TestIntegrationRevealAnomalyDisabled(t *testing.T) {
	// Порог 0 — детекция выключена: share работает, но anomaly-событий нет.
	env := newAnomalyEnv(t, ratelimit.AnomalyWindow{Threshold: 0, Window: time.Hour})
	operator := uniqueOperator()
	conn := activeFakeConnection(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "")
	path := "/api/v1/accounts/" + acct.ID.String() + "/share"

	for i := 0; i < 5; i++ {
		resp := env.do(t, http.MethodPost, path, nil, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}
	if got := anomalyAuditCount(t, env, operator.ActorID()); got != 0 {
		t.Errorf("anomaly audit rows with detection disabled = %d, want 0", got)
	}
}

// assertAnomalyMetadata проверяет форму metadata последнего anomaly-события:
// есть count/threshold/window_seconds, нет полей, похожих на секрет.
func assertAnomalyMetadata(t *testing.T, env *testEnv, actorID string) {
	t.Helper()
	var count, threshold, windowSeconds *int64
	var operation string
	err := env.pool.QueryRow(t.Context(), `
		select (metadata->>'count')::bigint,
		       (metadata->>'threshold')::bigint,
		       (metadata->>'window_seconds')::bigint,
		       metadata->>'operation'
		from audit_events
		where action = 'security.reveal_rate_anomaly' and actor_id = $1
		order by id desc limit 1`,
		actorID,
	).Scan(&count, &threshold, &windowSeconds, &operation)
	if err != nil {
		t.Fatalf("read anomaly metadata: %v", err)
	}
	if count == nil || *count < 3 {
		t.Errorf("metadata count = %v, want >= 3", count)
	}
	if threshold == nil || *threshold != 3 {
		t.Errorf("metadata threshold = %v, want 3", threshold)
	}
	if windowSeconds == nil || *windowSeconds != 3600 {
		t.Errorf("metadata window_seconds = %v, want 3600", windowSeconds)
	}
	if operation != metrics.OperationAccountShare {
		t.Errorf("metadata operation = %q, want %q", operation, metrics.OperationAccountShare)
	}
}

// revealCounter читает значение grantor_credential_reveal_total для
// (operation, result) из общего registry прикладных метрик.
func revealCounter(t *testing.T, operation, result string) float64 {
	t.Helper()
	return counterValue(t, "grantor_credential_reveal_total", map[string]string{
		"operation": operation, "result": result,
	})
}

// revealAnomalyCounter читает grantor_credential_reveal_anomaly_total для
// operation.
func revealAnomalyCounter(t *testing.T, operation string) float64 {
	t.Helper()
	return counterValue(t, "grantor_credential_reveal_anomaly_total", map[string]string{
		"operation": operation,
	})
}

// counterValue суммирует значения counter-метрики name с точным совпадением
// набора лейблов want.
func counterValue(t *testing.T, name string, want map[string]string) float64 {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if metricMatches(m, want) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// metricMatches сообщает, совпадает ли набор лейблов метрики с want.
func metricMatches(m *dto.Metric, want map[string]string) bool {
	if len(m.GetLabel()) != len(want) {
		return false
	}
	for _, l := range m.GetLabel() {
		if want[l.GetName()] != l.GetValue() {
			return false
		}
	}
	return true
}
