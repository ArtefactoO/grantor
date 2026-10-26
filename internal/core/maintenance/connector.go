package maintenance

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
)

// auditActionConnectorCertificateExpiring — сигнал о том, что сертификат
// connector'а скоро перестанет проходить mTLS.
const auditActionConnectorCertificateExpiring = "security.connector_certificate_expiring"

// evaluateConnectorCertificates эмитит finding по connector'ам, чей
// клиентский сертификат истекает раньше порога, включая уже истёкшие.
//
// Истечение обрывает связь бесповоротно и без предупреждения: агент
// перестаёт проходить mTLS, а операции подключений сегмента начинают
// падать retryable-ошибкой, причина которой видна только в логах пода.
// Порог 0 выключает проверку — как у прочих порогов обслуживания.
func (r *Runner) evaluateConnectorCertificates(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	if r.cfg.ConnectorCertificateWarning <= 0 || r.connectors == nil {
		return 0, nil
	}

	sessions, err := r.connectors.ExpiringSoon(ctx, tx, now, r.cfg.ConnectorCertificateWarning)
	if err != nil {
		return 0, err
	}
	for i := range sessions {
		if err := r.writeConnectorCertificateAudit(ctx, tx, &sessions[i], now); err != nil {
			return i, err
		}
	}
	return len(sessions), nil
}

// writeConnectorCertificateAudit пишет security-событие по одному
// connector'у. Секретов в metadata нет: идентификатор из CN сертификата,
// срок и остаток времени.
func (r *Runner) writeConnectorCertificateAudit(
	ctx context.Context,
	tx pgx.Tx,
	sess *connectorstate.Session,
	now time.Time,
) error {
	if r.audit == nil {
		return nil
	}
	remaining := sess.CertificateNotAfter.Sub(now)
	meta, err := json.Marshal(map[string]any{
		"connector_id":      sess.ConnectorID,
		"not_after":         sess.CertificateNotAfter.UTC().Format(time.RFC3339),
		"remaining_seconds": int64(remaining.Seconds()),
		"threshold_seconds": int64(r.cfg.ConnectorCertificateWarning.Seconds()),
		"expired":           remaining <= 0,
		"last_seen_at":      sess.LastSeenAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf(
			"maintenance: marshal connector certificate audit for %s: %w", sess.ConnectorID, err)
	}
	event := audit.Event{
		ActorType: ActorType,
		ActorID:   ActorID,
		Action:    auditActionConnectorCertificateExpiring,
		Result:    "alert",
		Metadata:  meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf(
			"maintenance: write connector certificate audit for %s: %w", sess.ConnectorID, err)
	}
	return nil
}
