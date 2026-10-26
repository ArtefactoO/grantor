// Package metrics — общий (на процесс) registry прикладных метрик grantor
// и типобезопасные хелперы их обновления (docs/architecture.md, раздел 25;
// docs/adr/0011-security-findings-audit-metrics.md).
//
// # Зачем отдельный registry
//
// serverutil.MetricsHandler отдаёт /metrics и собирает Go/process
// collectors во временный registry на каждый запрос. Кастомные прикладные
// метрики нельзя класть в prometheus.DefaultRegisterer: тот handler его не
// собирает. Поэтому все метрики grantor регистрируются здесь, в
// package-level registry, а MetricsHandler добавляет его gatherer-ом рядом с
// Go/process collectors. Registry общий на процесс, поэтому одни и те же
// метрики появляются и в api, и в worker (оба зовут MetricsHandler).
//
// # Кардинальность лейблов
//
// Лейблы строго ограничены (раздел 24: no unbounded labels). Секреты в
// имена/лейблы метрик не попадают никогда (инвариант раздела 17.2):
//   - reveal/share счётчики лейблятся только operation и result (по 2
//     значения) — не субъектом и не id секрета;
//   - gauge возраста admin credential лейблится connection_id: подключений
//     немного (десятки), это ограниченное множество долгоживущих сущностей.
//     Series удалённых подключений держатся до перезапуска процесса, поэтому
//     эвалуация старения делает Reset перед выставлением текущих значений.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// registry — package-level registry прикладных метрик. Не
// prometheus.DefaultRegisterer: его MetricsHandler не собирает (см. package
// doc).
var registry = prometheus.NewRegistry()

// Gatherer возвращает registry прикладных метрик как prometheus.Gatherer
// для включения в /metrics (serverutil.MetricsHandler) и для проверки в
// тестах.
func Gatherer() prometheus.Gatherer { return registry }

var (
	// credentialRevealTotal — счётчик попыток credential reveal/share по
	// поверхности выдачи (одноразовая ссылка Yopass account/principal).
	// operation: "account_share"|"principal_share"; result: "allowed"
	// (прошёл per-subject лимит) | "limited" (отклонён лимитером, 429).
	// Субъектом НЕ лейблится (unbounded) — аномалия по субъекту уходит в
	// audit security.reveal_rate_anomaly.
	credentialRevealTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grantor_credential_reveal_total",
			Help: "Credential reveal/share attempts by operation and rate-limit result.",
		},
		[]string{"operation", "result"},
	)

	// credentialRevealAnomalyTotal — счётчик сработавших сигналов аномальной
	// частоты reveal/share (по одному на субъект за окно, throttled). Растёт
	// синхронно с audit-событиями security.reveal_rate_anomaly. Лейбл только
	// operation (ограничен).
	credentialRevealAnomalyTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grantor_credential_reveal_anomaly_total",
			Help: "Anomalous credential reveal/share rate alerts emitted, by operation.",
		},
		[]string{"operation"},
	)

	// adminCredentialAgeSeconds — возраст admin credential активного
	// подключения в секундах (now - admin_credential_set_at). Выставляется
	// периодической эвалуацией старения (internal/core/maintenance).
	// Alertmanager сравнивает с порогом сам; series очищаются Reset на каждой
	// эвалуации (см. package doc про кардинальность). В multi-replica worker
	// значение выставляет реплика, держащая maintenance advisory lock;
	// alerting агрегирует по инстансам (max without(instance)).
	adminCredentialAgeSeconds = promauto.With(registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "grantor_connection_admin_credential_age_seconds",
			Help: "Age of a connection admin credential in seconds (now - admin_credential_set_at).",
		},
		[]string{"connection_id"},
	)

	// adminCredentialAged — число активных подключений, чей admin credential
	// на момент последней эвалуации превысил порог старения. Скалярный gauge
	// (не per-connection) — удобная агрегированная метрика для alerting; сам
	// список стареющих виден в audit security.admin_credential_aged.
	adminCredentialAged = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Name: "grantor_connection_admin_credential_aged",
			Help: "Active connections whose admin credential exceeds the configured max age at the last evaluation.",
		},
	)

	// offboardingIncompletePrincipals — число disabled-принципалов, у которых
	// на момент последней эвалуации offboarding остались активные accounts
	// или present/desired bindings (доступ пережил выключение принципала).
	// Скалярный gauge без лейблов (bounded cardinality): сами принципалы
	// видны в audit security.offboarding_incomplete. Выставляется каждым
	// прогоном обслуживания (internal/core/maintenance), в том числе нулём.
	offboardingIncompletePrincipals = promauto.With(registry).NewGauge(
		prometheus.GaugeOpts{
			Name: "grantor_offboarding_incomplete_principals",
			Help: "Disabled principals that still have active accounts or present/desired bindings at the last evaluation.",
		},
	)

	// principalsDisabledTotal — счётчик принципалов, переведённых в disabled
	// IdP-поллом обслуживания. Лейбл reason ограничен двумя значениями
	// (ReasonDirectoryDisabled/ReasonDirectoryMissing); субъект/id принципала
	// в лейблы не попадает (unbounded) — конкретный принципал виден в audit
	// principal.disabled.
	principalsDisabledTotal = promauto.With(registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "grantor_principals_disabled_total",
			Help: "Principals transitioned to disabled by the identity directory poll, by reason.",
		},
		[]string{"reason"},
	)
)

// Значения лейбла result счётчика credentialRevealTotal.
const (
	// ResultAllowed — попытка reveal/share прошла per-subject лимит.
	ResultAllowed = "allowed"
	// ResultLimited — попытка reveal/share отклонена лимитером (429).
	ResultLimited = "limited"
)

// Значения лейбла operation reveal/share метрик.
const (
	// OperationAccountShare — одноразовая выдача credential аккаунта
	// (POST /accounts/{id}/share).
	OperationAccountShare = "account_share"
	// OperationPrincipalShare — одноразовая выдача общего секрета принципала
	// (POST /principals/{id}/share).
	OperationPrincipalShare = "principal_share"
)

// ObserveCredentialReveal инкрементит счётчик попыток reveal/share с
// заданными operation и result (см. константы Operation*/Result*).
func ObserveCredentialReveal(operation, result string) {
	credentialRevealTotal.WithLabelValues(operation, result).Inc()
}

// ObserveCredentialRevealAnomaly инкрементит счётчик сигналов аномальной
// частоты reveal/share для operation (по одному на субъект за окно).
func ObserveCredentialRevealAnomaly(operation string) {
	credentialRevealAnomalyTotal.WithLabelValues(operation).Inc()
}

// SetAdminCredentialAge выставляет возраст admin credential подключения в
// секундах.
func SetAdminCredentialAge(connectionID string, ageSeconds float64) {
	adminCredentialAgeSeconds.WithLabelValues(connectionID).Set(ageSeconds)
}

// ResetAdminCredentialAge очищает все series gauge возраста перед новой
// эвалуацией: убирает подключения, удалённые или переставшие быть active с
// прошлого прогона (см. package doc про кардинальность).
func ResetAdminCredentialAge() {
	adminCredentialAgeSeconds.Reset()
}

// SetAdminCredentialAgedCount выставляет число активных подключений,
// превысивших порог старения на последней эвалуации.
func SetAdminCredentialAgedCount(n int) {
	adminCredentialAged.Set(float64(n))
}

// Значения лейбла reason счётчика principalsDisabledTotal — причина, по
// которой IdP-poll перевёл принципала в disabled.
const (
	// ReasonDirectoryDisabled — субъект найден в каталоге, но выключен
	// (совпал disabled filter).
	ReasonDirectoryDisabled = "disabled"
	// ReasonDirectoryMissing — субъект в каталоге отсутствует (учётка
	// удалена — классический сигнал offboarding).
	ReasonDirectoryMissing = "missing"
)

// SetOffboardingIncompletePrincipals выставляет число disabled-принципалов
// с ещё активными accounts/bindings на последней эвалуации offboarding.
func SetOffboardingIncompletePrincipals(n int) {
	offboardingIncompletePrincipals.Set(float64(n))
}

// ObservePrincipalDisabled инкрементит счётчик принципалов, переведённых в
// disabled IdP-поллом, с причиной reason (см. константы ReasonDirectory*).
func ObservePrincipalDisabled(reason string) {
	principalsDisabledTotal.WithLabelValues(reason).Inc()
}
