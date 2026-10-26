package api

// Детекция аномальной частоты credential reveal/share (docs/threat-model.md,
// разделы 24/25; docs/adr/0011-security-findings-audit-metrics.md). Поверх
// уже существующего per-subject rate limiting (ADR-0007) добавлен слой
// наблюдаемости:
//
//   - Prometheus-счётчик grantor_credential_reveal_total{operation,result}
//     на каждую попытку reveal/share (allowed|limited);
//   - при аномально высокой частоте по одному субъекту — audit-событие
//     security.reveal_rate_anomaly (throttled: один сигнал на субъект за
//     окно, состояние в PostgreSQL — честно между репликами) и счётчик
//     grantor_credential_reveal_anomaly_total.
//
// Детекция НЕ блокирует запрос (это делает rate limiter) — сигнал уходит в
// SIEM через audit-поток. Секреты не пишутся: в метки метрик и metadata
// audit попадают только operation/result/count/threshold/window и субъект-
// актор (его email/id не секрет и нужен, чтобы сигнал был actionable).

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
)

// auditActionRevealRateAnomaly — audit action аномальной частоты reveal/
// share. Размещён рядом с использованием (как прочие auditAction* в api).
const auditActionRevealRateAnomaly = "security.reveal_rate_anomaly"

// guardReveal объединяет проверки поверхности credential reveal/share:
// per-subject rate limit (ADR-0007), метрику попытки и детекцию аномальной
// частоты. Возвращает false, если запрос отклонён лимитером (429 уже записан
// в w) — вызывающий должен прекратить обработку. operation — метка операции
// (metrics.OperationAccountShare|OperationPrincipalShare).
//
// Порядок: сперва лимитер (как раньше), затем — если пропущено — метрика
// allowed и детекция аномалии; при отказе лимитера — метрика limited. Так
// счётчик reveal_total отражает исход лимитера, а аномалия считает реальные
// (не отклонённые) попытки выдачи.
func (s *Server) guardReveal(w http.ResponseWriter, r *http.Request, sess auth.Session, operation string) bool {
	if !s.rateLimitReveal(w, r, sess.Subject) {
		metrics.ObserveCredentialReveal(operation, metrics.ResultLimited)
		return false
	}
	metrics.ObserveCredentialReveal(operation, metrics.ResultAllowed)
	s.detectRevealAnomaly(r.Context(), sess, operation)
	return true
}

// detectRevealAnomaly регистрирует попытку reveal/share субъекта в окне
// частоты и, если субъект впервые за окно превысил порог, эмитит audit
// security.reveal_rate_anomaly и инкрементит anomaly-счётчик. Best-effort:
// детекция выключена (детектор nil / окно не задано) или ошибка счётчика не
// влияют на основной путь выдачи — лишь логируются. Троттлинг («один сигнал
// на субъект за окно») обеспечивает сам AnomalyDetector в PostgreSQL.
func (s *Server) detectRevealAnomaly(ctx context.Context, sess auth.Session, operation string) {
	if s.anomalyDetector == nil || !s.anomalyWindow.Enabled() {
		return
	}
	count, alert, err := s.anomalyDetector.Observe(ctx,
		ratelimit.RevealAnomalyKey(sess.Subject), s.anomalyWindow)
	if err != nil {
		// Ошибка не содержит секретов (ключ — subject, не credential).
		slog.ErrorContext(ctx, "api: reveal anomaly detection failed", "error", err)
		return
	}
	if !alert {
		return
	}
	metrics.ObserveCredentialRevealAnomaly(operation)

	metadata, err := json.Marshal(map[string]any{
		"operation":      operation,
		"count":          count,
		"threshold":      s.anomalyWindow.Threshold,
		"window_seconds": int64(s.anomalyWindow.Window.Seconds()),
		"reason":         "reveal_rate_anomaly",
	})
	if err != nil {
		slog.ErrorContext(ctx, "api: marshal reveal anomaly audit metadata", "error", err)
		return
	}
	// Актор — сам субъект (его id/email не секрет и нужен для реакции).
	// Пишем best-effort вне транзакции выдачи: сигнал наблюдаемости не должен
	// откатывать/блокировать саму выдачу.
	if err := s.audit.Write(ctx, s.pool, audit.Event{
		ActorType: sess.ActorType(),
		ActorID:   sess.ActorID(),
		Action:    auditActionRevealRateAnomaly,
		Result:    "alert",
		Metadata:  metadata,
	}); err != nil {
		slog.ErrorContext(ctx, "api: write reveal anomaly audit", "error", err)
	}
}
