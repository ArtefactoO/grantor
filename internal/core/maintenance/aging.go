package maintenance

// Aging finding admin credential подключения (docs/architecture.md, раздел
// 17.3, R12; docs/threat-model.md, раздел 6 P1; docs/adr/
// 0011-security-findings-audit-metrics.md).
//
// Flow ротации admin credential есть (тот же, что у account), но политики
// старения не было. Здесь периодическая эвалуация: для активных подключений
// с сохранённым admin credential выставляется Prometheus gauge возраста, а
// подключения старше порога отмечаются audit-событием security.admin_
// credential_aged. Механизм — audit + метрики (без нового findings-
// субъекта/UI): alerting живёт в инфраструктуре (SIEM на audit-потоке,
// alertmanager на метриках).
//
// Троттлинг: эвалуация запускается периодически (Runner.Interval, дефолт 1h)
// и эмитит не более одного события на устаревшее подключение за прогон —
// сам период прогона и есть окно троттлинга.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/metrics"
)

// auditActionAdminCredentialAged — audit action security finding старения
// admin credential подключения. Размещён рядом с эвалуацией (как
// "binding.expired"): audit-действия объявляются в точке использования.
const auditActionAdminCredentialAged = "security.admin_credential_aged"

// exceedsMaxAge сообщает, превышает ли возраст admin credential порог
// старения. maxAge <= 0 всегда даёт false (эвалуация выключена). Чистая
// функция — решение старения проверяется юнит-тестом без базы.
func exceedsMaxAge(age, maxAge time.Duration) bool {
	return maxAge > 0 && age > maxAge
}

// agingCandidate — активное подключение с сохранённым admin credential,
// кандидат на эвалуацию старения.
type agingCandidate struct {
	id          uuid.UUID
	environment string
	setAt       time.Time
}

// evaluateAdminCredentialAging выставляет метрики возраста admin credential и
// эмитит audit-события для подключений старше порога. Возвращает число
// устаревших подключений.
//
// При AdminCredentialMaxAge <= 0 эвалуация выключена (no-op, 0): политика
// возраста org-специфична, до её явной установки finding не эмитим и метрики
// не трогаем. Иначе: собираем активные подключения с непустым
// admin_credential_set_at, затем (курсор уже закрыт — pgx не даёт новых
// запросов на том же соединении при открытом rows) выставляем gauge возраста
// каждому и пишем audit устаревшим.
func (r *Runner) evaluateAdminCredentialAging(ctx context.Context, tx pgx.Tx, now time.Time) (int, error) {
	if r.cfg.AdminCredentialMaxAge <= 0 {
		return 0, nil
	}

	rows, err := tx.Query(ctx, `
		select id, environment, admin_credential_set_at
		from connections
		where status = 'active'
		  and vault_admin_path <> ''
		  and admin_credential_set_at is not null
		order by id`)
	if err != nil {
		return 0, fmt.Errorf("maintenance: select aging candidates: %w", err)
	}

	var candidates []agingCandidate
	for rows.Next() {
		var c agingCandidate
		if err := rows.Scan(&c.id, &c.environment, &c.setAt); err != nil {
			rows.Close()
			return 0, fmt.Errorf("maintenance: scan aging candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("maintenance: select aging candidates: %w", err)
	}

	// Reset очищает series подключений, удалённых или переставших быть active
	// с прошлого прогона (кардинальность gauge ограничена текущими активными
	// подключениями; см. package doc internal/metrics).
	metrics.ResetAdminCredentialAge()
	aged := 0
	for i := range candidates {
		c := &candidates[i]
		age := now.Sub(c.setAt)
		metrics.SetAdminCredentialAge(c.id.String(), age.Seconds())
		if !exceedsMaxAge(age, r.cfg.AdminCredentialMaxAge) {
			continue
		}
		aged++
		if err := r.writeAgedAudit(ctx, tx, c, age); err != nil {
			return aged, err
		}
	}
	metrics.SetAdminCredentialAgedCount(aged)
	return aged, nil
}

// writeAgedAudit пишет audit-событие security.admin_credential_aged для
// устаревшего подключения. No-op, если Writer не задан. Секретов в metadata
// нет: только connection_id, environment, возраст и порог.
func (r *Runner) writeAgedAudit(ctx context.Context, tx pgx.Tx, c *agingCandidate, age time.Duration) error {
	if r.audit == nil {
		return nil
	}
	meta, err := json.Marshal(map[string]any{
		"environment":       c.environment,
		"age_seconds":       int64(age.Seconds()),
		"threshold_seconds": int64(r.cfg.AdminCredentialMaxAge.Seconds()),
		"reason":            "admin_credential_aged",
	})
	if err != nil {
		return fmt.Errorf("maintenance: marshal aged audit metadata for connection %s: %w", c.id, err)
	}
	connectionID := c.id
	event := audit.Event{
		ActorType:    ActorType,
		ActorID:      ActorID,
		Action:       auditActionAdminCredentialAged,
		ConnectionID: &connectionID,
		Result:       "alert",
		Metadata:     meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("maintenance: write admin_credential_aged audit for %s: %w", c.id, err)
	}
	return nil
}
