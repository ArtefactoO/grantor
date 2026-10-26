// Package serverutil собирает общие для команд grantor (cmd/api,
// cmd/worker) мелочи запуска HTTP-сервера: чтение окружения, /metrics
// handler и конструктор http.Server с общими таймаутами. Логику graceful
// shutdown команды держат у себя: у api и worker разный порядок остановки
// (worker сначала дренирует River, HTTP гасит после), поэтому единый
// run-loop здесь сознательно не вводится.
package serverutil

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

// readHeaderTimeout — общий предел чтения заголовков запроса для HTTP-
// серверов команд (защита от медленных клиентов). Значение совпадает с
// прежним inline-таймаутом cmd/api и cmd/worker.
const readHeaderTimeout = 10 * time.Second

// EnvOr возвращает значение переменной окружения или default, если
// переменная пуста.
func EnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// EnvBool разбирает bool-переменную окружения (strconv.ParseBool: 1/t/true/
// 0/f/false и т.п.). Пустое значение даёт def; нераспознанное — def с
// предупреждением, чтобы опечатка во флаге (в том числе security-флаге) не
// проходила молча.
func EnvBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Warn("serverutil: invalid bool env value; using default", "key", key, "default", def)
		return def
	}
	return b
}

// EnvInt разбирает целочисленную переменную окружения (strconv.Atoi).
// Пустое значение даёт def; нераспознанное — def с предупреждением, чтобы
// опечатка во флаге не проходила молча.
func EnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("serverutil: invalid int env value; using default", "key", key, "default", def)
		return def
	}
	return n
}

// EnvDuration разбирает duration-переменную окружения (time.ParseDuration:
// "1h", "30m", "90s" и т.п.). Пустое значение даёт def; нераспознанное —
// def с предупреждением, чтобы опечатка во флаге не проходила молча.
func EnvDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		slog.Warn("serverutil: invalid duration env value; using default", "key", key, "default", def)
		return def
	}
	return d
}

// SplitCSV разбирает csv-список, отбрасывая пустые элементы и пробелы по
// краям. Общая для cmd/api и cmd/worker идиома разбора env-списков
// (RBAC-emails, endpoint allowlists, IdP static-списки).
func SplitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// EndpointPolicyFromEnv читает единственный контракт endpoint allowlist для
// API pre-check и worker dial-time enforcement. Ошибка конфигурации является
// fatal: молчаливый fallback ослабил бы security boundary.
func EndpointPolicyFromEnv() (netguard.Policy, error) {
	policy, err := netguard.ParsePolicy(
		SplitCSV(os.Getenv("GRANTOR_ENDPOINT_ALLOWED_CIDRS")),
		SplitCSV(os.Getenv("GRANTOR_ENDPOINT_ALLOWED_PORTS")),
		SplitCSV(os.Getenv("GRANTOR_ENDPOINT_ALLOWED_DNS_SUFFIXES")),
	)
	if err != nil {
		return netguard.Policy{}, fmt.Errorf("parse endpoint network policy: %w", err)
	}
	return policy, nil
}

// MetricsHandler возвращает /metrics handler со стандартными Go/process
// collectors и общим registry прикладных метрик grantor (internal/metrics).
// Прикладные метрики нельзя класть в prometheus.DefaultRegisterer — этот
// handler его не собирает; вместо этого registry прикладных метрик
// добавляется отдельным gatherer-ом, поэтому кастомные метрики попадают в
// /metrics и в api, и в worker (оба зовут MetricsHandler).
func MetricsHandler() http.Handler {
	base := prometheus.NewRegistry()
	base.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	gatherer := prometheus.Gatherers{base, metrics.Gatherer()}
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
}

// NewHTTPServer собирает http.Server с общими для команд таймаутами
// (ReadHeaderTimeout). Жизненным циклом (ListenAndServe/Shutdown)
// управляет вызывающий.
func NewHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}
}
