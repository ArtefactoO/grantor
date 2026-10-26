// Package operations — доменная модель операций grantor
// (docs/architecture.md, раздел 19). Operation — durable-запись о каждой
// изменяющей (и долгой читающей) работе control plane: grant/revoke,
// создание account, discovery и т.п. Payload/plan/result хранятся
// sanitized: секретные значения в них не попадают.
package operations

import (
	"time"

	"github.com/google/uuid"
)

// Status — состояние операции. Значения совпадают с CHECK-ограничением
// колонки operations.status в схеме (db/migrations/00001_core_schema.sql).
type Status string

const (
	// StatusPendingApproval — операция создана, но требует ручного
	// подтверждения (approved_by/approved_at) до постановки в работу.
	StatusPendingApproval Status = "pending_approval"
	// StatusPending — операция готова к выполнению и ждёт worker.
	StatusPending Status = "pending"
	// StatusRunning — операция выполняется worker прямо сейчас.
	StatusRunning Status = "running"
	// StatusSuccess — операция завершена успешно.
	StatusSuccess Status = "success"
	// StatusPartial — часть дочерних операций завершилась успешно,
	// часть — нет (bulk parent, раздел 19.1 архитектуры).
	StatusPartial Status = "partial"
	// StatusFailed — операция завершена с ошибкой; допускает ручной retry.
	StatusFailed Status = "failed"
	// StatusCancelled — операция отменена и никогда не будет выполнена.
	StatusCancelled Status = "cancelled"
)

// transitions — карта допустимых переходов статусов.
//
// Семантика:
//   - pending_approval -> pending: операция подтверждена (approve);
//   - pending_approval -> cancelled: операция отклонена или отозвана;
//   - pending -> running: worker взял операцию в работу;
//   - pending -> cancelled: операция отменена до начала выполнения;
//   - running -> success | partial | failed: итог выполнения
//     (partial — только для parent bulk-операций);
//   - running -> cancelled: выполнение прервано по запросу отмены;
//   - failed -> pending: ручной retry из UI или автоматический retry
//     диспетчера задач;
//   - failed -> cancelled: оператор безопасно отказывается от lifecycle,
//     который доказанно не дошёл до внешнего side effect;
//   - partial -> pending: retry только failed дочерних операций
//     (раздел 19.1 архитектуры).
//
// success и cancelled — конечные точки без исходящих переходов.
var transitions = map[Status]map[Status]bool{
	StatusPendingApproval: {
		StatusPending:   true,
		StatusCancelled: true,
	},
	StatusPending: {
		StatusRunning:   true,
		StatusCancelled: true,
	},
	StatusRunning: {
		StatusSuccess:   true,
		StatusPartial:   true,
		StatusFailed:    true,
		StatusCancelled: true,
	},
	StatusFailed: {
		StatusPending:   true,
		StatusCancelled: true,
	},
	StatusPartial: {
		StatusPending: true,
	},
}

// CanTransition сообщает, допустим ли переход операции из статуса from
// в статус to. Переход в тот же статус недопустим.
func CanTransition(from, to Status) bool {
	return transitions[from][to]
}

// IsTerminal сообщает, что операция достигла конечного состояния и не
// может измениться никаким переходом: success и cancelled.
//
// failed и partial терминальными не считаются — они допускают retry
// (переход обратно в pending). Для parent-агрегации используйте
// IsFinished: там failed/partial считаются завершёнными, потому что
// worker закончил с операцией и её итог известен.
func (s Status) IsTerminal() bool {
	return s == StatusSuccess || s == StatusCancelled
}

// IsFinished сообщает, что выполнение операции закончилось и её итог
// известен: success, partial, failed или cancelled. Используется для
// агрегации статусов дочерних операций в parent (раздел 19.1
// архитектуры): parent завершён, когда все children finished, даже если
// часть из них failed и может быть повторена вручную.
func (s Status) IsFinished() bool {
	switch s {
	case StatusSuccess, StatusPartial, StatusFailed, StatusCancelled:
		return true
	default:
		return false
	}
}

// AggregateChildren вычисляет сводный статус parent bulk-операции по
// статусам дочерних (раздел 19.1 архитектуры): все success — success;
// все завершились, но часть неуспешно (failed/cancelled/partial) —
// partial при наличии успешных и failed без них; хотя бы один ребёнок
// ещё не finished — running. Пустой список — пустая строка: агрегировать
// нечего.
//
// Одна и та же семантика используется в двух местах: финализацией parent
// в базе (Store.FinalizeParent — durable статус строки operations) и
// aggregate_status в detail-ответе API (совместимость контракта).
func AggregateChildren(children []Status) Status {
	if len(children) == 0 {
		return ""
	}
	anySuccess := false
	anyFailed := false
	for _, st := range children {
		if !st.IsFinished() {
			return StatusRunning
		}
		switch st {
		case StatusSuccess:
			anySuccess = true
		default:
			// failed, cancelled и (теоретически) partial — неуспех.
			anyFailed = true
		}
	}
	switch {
	case anyFailed && anySuccess:
		return StatusPartial
	case anyFailed:
		return StatusFailed
	default:
		return StatusSuccess
	}
}

// Operation зеркалит строку таблицы operations. Payload обязателен
// (jsonb, по умолчанию {}), Plan и Result — nullable jsonb: nil означает
// SQL NULL. Все jsonb-поля sanitized — без секретных значений.
type Operation struct {
	ID             uuid.UUID
	ParentID       *uuid.UUID
	IdempotencyKey *string
	Kind           string
	Status         Status
	ConnectionID   *uuid.UUID
	PrincipalID    *uuid.UUID
	AccountID      *uuid.UUID
	ResourceID     *uuid.UUID
	BindingID      *uuid.UUID
	Payload        []byte
	Plan           []byte
	Result         []byte
	Error          string
	ActorType      string
	ActorID        string
	ApprovedBy     *string
	ApprovedAt     *time.Time
	// DecisionReason — свободный комментарий admin при approve/reject
	// (approval workflow, ADR-0010). Пусто, если решения ещё не было или
	// комментарий не задан. Не содержит секретов.
	DecisionReason string
	CorrelationID  string
	CreatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
	// ResolvedAt/ResolvedBy фиксируют операторское подтверждение, что
	// неуспешный итог обработан. Исходный status/error не меняются и остаются
	// частью истории; resolution влияет только на активные attention-сигналы.
	ResolvedAt *time.Time
	ResolvedBy *string
	UpdatedAt  time.Time
}
