package maintenance

// Offboarding / IdP-sync (docs/threat-model.md, раздел 4.3 R1 и чеклист
// раздела 6; раздел 31 acceptance; docs/adr/0012-idp-poll-offboarding.md).
//
// Две эвалуации одного прогона обслуживания:
//
//   - poll identity directory (когда провайдер подключён, GRANTOR_IDP_MODE):
//     human-принципалы с внешней identity сверяются с каталогом; отдельное
//     зеркало external identity обновляется при каждом успешном poll, а
//     внешний disabled/deleted дополнительно переводит только локальный
//     active principal в disabled c audit principal.disabled
//     (source: idp_poll). Детекция, не отзыв: accounts и bindings принципала
//     НЕ трогаются — отзыв остаётся решением человека/approval flow;
//   - offboarding finding (всегда, независимо от поллинга): disabled-
//     принципал (любого происхождения — IdP-poll или ручное выключение
//     админом), у которого остались активные accounts или present/desired
//     bindings, отмечается audit security.offboarding_incomplete и
//     скалярным gauge grantor_offboarding_incomplete_principals.
//
// Механизм findings — audit + Prometheus (ADR-0011), без нового
// findings-субъекта/UI. Троттлинг — период прогона (Runner.Interval,
// дефолт 1h): не более одного события на принципал за прогон, что и есть
// «finding в течение одного sync-интервала» из acceptance criteria.

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/directoryimport"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/metrics"
)

// Audit actions offboarding-контура. Объявлены в точке использования (как
// security.admin_credential_aged): principal.disabled — то же действие,
// что пишет api при ручном выключении, здесь его эмитит IdP-poll.
const (
	auditActionPrincipalDisabled             = "principal.disabled"
	auditActionExternalIdentityStatusChanged = "principal.external_identity_status_changed"
	auditActionOffboardingIncomplete         = "security.offboarding_incomplete"
)

// DirectoryPoll — настройки поллинга identity directory для Runner.
type DirectoryPoll struct {
	// Provider — источник статусов субъектов. nil = поллинг выключен
	// (offboarding finding при этом продолжает эвалуироваться из
	// локального статуса принципалов).
	Provider directory.Provider
	// ProviderName — значение principals.external_provider, принципалы
	// которого сверяются с каталогом. Пустая строка = все не удалённые
	// human-принципалы с непустым external_subject.
	ProviderName string
	// MissingIsDisabled — считать ли отсутствие субъекта в каталоге
	// сигналом локального offboarding. Зеркало при этом всегда получает
	// external deleted независимо от политики.
	MissingIsDisabled bool
}

// WithDirectoryPoll включает поллинг identity directory и возвращает тот
// же Runner (chained wiring в main, как WithAudit). Poll с nil Provider
// оставляет поллинг выключенным.
func (r *Runner) WithDirectoryPoll(poll DirectoryPoll) *Runner {
	r.dir = poll
	return r
}

// externalIdentityObservation переводит provider-статус в отдельный статус
// зеркала и причину локального disable. Missing всегда означает внешний
// deleted; локальный tombstone при этом не создаётся. Неизвестный статус —
// нарушение Provider-контракта и ошибка всего poll: частичное состояние не
// коммитится.
func externalIdentityObservation(st directory.Status) (principals.ExternalIdentityStatus, string, error) {
	status, err := directoryimport.ExternalIdentityObservation(st)
	if err != nil {
		return "", "", err
	}
	switch st {
	case directory.StatusDisabled:
		return status, metrics.ReasonDirectoryDisabled, nil
	case directory.StatusMissing:
		return status, metrics.ReasonDirectoryMissing, nil
	default:
		return status, "", nil
	}
}

// offboardingIncomplete решает, является ли disabled-принципал незакрытым
// offboarding: у него остались активные accounts или present/desired
// bindings. Чистая функция для юнит-теста решения.
func offboardingIncomplete(accountCount, bindingCount int) bool {
	return accountCount > 0 || bindingCount > 0
}

// pollCandidate — human-принципал с внешней identity, кандидат сверки с
// каталогом. Локальный disabled principal тоже получает актуальный внешний
// статус; локальный deleted tombstone исключён из дальнейшей синхронизации.
type pollCandidate struct {
	id       uuid.UUID
	provider string
	subject  string
}

// pollDirectory сверяет human-принципалов с identity directory, обновляет
// зеркало external identity и переводит локальные active-принципалы при
// внешнем disabled/deleted в disabled (+ audit principal.disabled,
// + счётчик grantor_principals_disabled_total). Возвращает число локальных
// переходов.
//
// Скоуп сверки: только type='human' (service/group-принципалы не живут в
// каталоге людей) с непустым external_subject (локального принципала не по
// чему искать); при непустом ProviderName — только принципалы этого
// провайдера. RecordExternalIdentityStatus атомарно записывает зеркало и
// условный локальный переход: уже-disabled/deleted не трогается и повторного
// audit не получает. Ошибка каталога или неполный/невалидный ответ прерывает
// транзакцию целиком — ни старое зеркало, ни локальный lifecycle не
// искажаются частичным poll; следующий тик повторит сверку.
func (r *Runner) pollDirectory(ctx context.Context, tx pgx.Tx) (int, error) {
	if r.dir.Provider == nil {
		return 0, nil
	}

	sql := `
		select id, external_provider, external_subject
		from principals
		where type = 'human'
		  and status <> 'deleted'
		  and external_subject <> ''`
	args := []any{}
	if r.dir.ProviderName != "" {
		sql += ` and external_provider = $1`
		args = append(args, r.dir.ProviderName)
	}
	sql += ` order by id`

	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return 0, fmt.Errorf("maintenance: select idp poll candidates: %w", err)
	}
	var candidates []pollCandidate
	for rows.Next() {
		var c pollCandidate
		if err := rows.Scan(&c.id, &c.provider, &c.subject); err != nil {
			rows.Close()
			return 0, fmt.Errorf("maintenance: scan idp poll candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("maintenance: select idp poll candidates: %w", err)
	}
	if len(candidates) == 0 {
		return 0, nil
	}

	// Субъекты дедуплицируются: при пустом ProviderName один и тот же
	// subject может принадлежать принципалам разных провайдеров.
	seen := make(map[string]struct{}, len(candidates))
	subjects := make([]string, 0, len(candidates))
	for i := range candidates {
		if _, ok := seen[candidates[i].subject]; ok {
			continue
		}
		seen[candidates[i].subject] = struct{}{}
		subjects = append(subjects, candidates[i].subject)
	}

	statuses, err := r.dir.Provider.Statuses(ctx, subjects)
	if err != nil {
		return 0, fmt.Errorf("maintenance: poll identity directory: %w", err)
	}

	disabled := 0
	for i := range candidates {
		c := &candidates[i]
		st, ok := statuses[c.subject]
		if !ok {
			return disabled, fmt.Errorf(
				"maintenance: poll identity directory: no status for principal %s", c.id)
		}
		externalStatus, reason, err := externalIdentityObservation(st)
		if err != nil {
			return disabled, fmt.Errorf(
				"maintenance: poll identity directory for principal %s: %w", c.id, err)
		}
		disableLocal := st == directory.StatusDisabled ||
			(st == directory.StatusMissing && r.dir.MissingIsDisabled)
		update, err := r.principals.RecordExternalIdentityStatus(
			ctx, tx, c.id, externalStatus, disableLocal)
		if err != nil {
			return disabled, fmt.Errorf(
				"maintenance: record external identity status for principal %s: %w", c.id, err)
		}
		if update.StatusChanged {
			if reason == "" {
				reason = string(st)
			}
			if err := r.writeExternalIdentityStatusChangedAudit(
				ctx, tx, c, update.PreviousStatus, externalStatus, reason,
			); err != nil {
				return disabled, err
			}
		}
		transitioned := update.LocallyDisabled
		if !transitioned {
			continue
		}
		disabled++
		metrics.ObservePrincipalDisabled(reason)
		if err := r.writePrincipalDisabledAudit(ctx, tx, c, reason); err != nil {
			return disabled, err
		}
	}
	return disabled, nil
}

// writeExternalIdentityStatusChangedAudit фиксирует только фактический
// переход зеркала, включая первое наблюдение. Обновление одного checked_at
// события не создаёт. Metadata содержит только несекретные identity metadata;
// previous_status равен null при первом успешном poll.
func (r *Runner) writeExternalIdentityStatusChangedAudit(
	ctx context.Context,
	tx pgx.Tx,
	c *pollCandidate,
	previous *principals.ExternalIdentityStatus,
	status principals.ExternalIdentityStatus,
	reason string,
) error {
	if r.audit == nil {
		return nil
	}
	meta, err := json.Marshal(map[string]any{
		"provider":        c.provider,
		"status":          string(status),
		"previous_status": previous,
		"reason":          reason,
	})
	if err != nil {
		return fmt.Errorf(
			"maintenance: marshal external identity status audit for %s: %w", c.id, err)
	}
	principalID := c.id
	if err := r.audit.Write(ctx, tx, audit.Event{
		ActorType:   ActorType,
		ActorID:     ActorID,
		Action:      auditActionExternalIdentityStatusChanged,
		PrincipalID: &principalID,
		Result:      audit.ResultSuccess,
		Metadata:    meta,
	}); err != nil {
		return fmt.Errorf(
			"maintenance: write external identity status audit for %s: %w", c.id, err)
	}
	return nil
}

// writePrincipalDisabledAudit пишет audit-событие principal.disabled для
// принципала, переведённого в disabled IdP-поллом. No-op, если Writer не
// задан. Секретов в metadata нет: subject — идентификатор каталога
// (email/логин), не credential; он нужен, чтобы сигнал был actionable.
func (r *Runner) writePrincipalDisabledAudit(ctx context.Context, tx pgx.Tx, c *pollCandidate, reason string) error {
	if r.audit == nil {
		return nil
	}
	meta, err := json.Marshal(map[string]any{
		"source":           "idp_poll",
		"reason":           reason,
		"external_subject": c.subject,
	})
	if err != nil {
		return fmt.Errorf("maintenance: marshal principal.disabled metadata for %s: %w", c.id, err)
	}
	principalID := c.id
	event := audit.Event{
		ActorType:   ActorType,
		ActorID:     ActorID,
		Action:      auditActionPrincipalDisabled,
		PrincipalID: &principalID,
		Result:      audit.ResultSuccess,
		Metadata:    meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("maintenance: write principal.disabled audit for %s: %w", c.id, err)
	}
	return nil
}

// offboardingCandidate — disabled-принципал со счётчиками оставшегося
// доступа.
type offboardingCandidate struct {
	id           uuid.UUID
	disabledAt   *time.Time
	accountCount int
	bindingCount int
}

// evaluateOffboarding отмечает disabled-принципалов, сохранивших доступ:
// audit security.offboarding_incomplete на каждого (один за прогон — период
// прогона и есть окно троттлинга) и скалярный gauge
// grantor_offboarding_incomplete_principals. Возвращает число findings.
//
// Эвалуация не зависит от поллинга (работает и при GRANTOR_IDP_MODE="" —
// по принципалам, выключенным админом вручную) и ничего не изменяет:
// детекция без авто-отзыва. Активным считается account в статусе active;
// binding считается оставшимся доступом, если его account не удалён и
// desired_state или observed_state — present (наблюдаемый в целевой
// системе грант учитывается, даже если desired уже absent).
func (r *Runner) evaluateOffboarding(ctx context.Context, tx pgx.Tx) (int, error) {
	rows, err := tx.Query(ctx, `
		select p.id, p.disabled_at,
		       count(distinct a.id) filter (where a.status = 'active'),
		       count(distinct b.id) filter (where a.status <> 'deleted'
		           and (b.desired_state = 'present' or b.observed_state = 'present'))
		from principals p
		left join accounts a on a.principal_id = p.id
		left join bindings b on b.account_id = a.id
		where p.status = 'disabled'
		group by p.id
		order by p.id`)
	if err != nil {
		return 0, fmt.Errorf("maintenance: select offboarding candidates: %w", err)
	}
	var candidates []offboardingCandidate
	for rows.Next() {
		var c offboardingCandidate
		if err := rows.Scan(&c.id, &c.disabledAt, &c.accountCount, &c.bindingCount); err != nil {
			rows.Close()
			return 0, fmt.Errorf("maintenance: scan offboarding candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("maintenance: select offboarding candidates: %w", err)
	}

	findings := 0
	for i := range candidates {
		c := &candidates[i]
		if !offboardingIncomplete(c.accountCount, c.bindingCount) {
			continue
		}
		findings++
		if err := r.writeOffboardingAudit(ctx, tx, c); err != nil {
			return findings, err
		}
	}
	metrics.SetOffboardingIncompletePrincipals(findings)
	return findings, nil
}

// writeOffboardingAudit пишет audit-событие security.offboarding_incomplete
// для disabled-принципала с оставшимся доступом. No-op, если Writer не
// задан. Секретов в metadata нет: только id, счётчики и момент выключения.
func (r *Runner) writeOffboardingAudit(ctx context.Context, tx pgx.Tx, c *offboardingCandidate) error {
	if r.audit == nil {
		return nil
	}
	fields := map[string]any{
		"principal_id":  c.id.String(),
		"account_count": c.accountCount,
		"binding_count": c.bindingCount,
		"reason":        "offboarding_incomplete",
	}
	if c.disabledAt != nil {
		fields["disabled_since"] = c.disabledAt.UTC().Format(time.RFC3339Nano)
	}
	meta, err := json.Marshal(fields)
	if err != nil {
		return fmt.Errorf("maintenance: marshal offboarding metadata for %s: %w", c.id, err)
	}
	principalID := c.id
	event := audit.Event{
		ActorType:   ActorType,
		ActorID:     ActorID,
		Action:      auditActionOffboardingIncomplete,
		PrincipalID: &principalID,
		Result:      "alert",
		Metadata:    meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("maintenance: write offboarding_incomplete audit for %s: %w", c.id, err)
	}
	return nil
}
