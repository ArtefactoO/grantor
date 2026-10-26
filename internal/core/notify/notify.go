// Package notify — фоновые webhook-уведомления о событиях операций.
//
// Раннер поллит operations вместо хуков в местах создания: pending_approval
// и падения появляются из многих путей API и worker'а, и один поллер ловит
// их все, включая пути, добавленные позже. Watermark в памяти: рестарт
// worker'а начинает с момента старта, события даунтайма не доотправляются —
// уведомления best-effort и дублировать их опаснее, чем потерять.
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/providers/webhook"
)

// DefaultInterval — период опроса операций.
const DefaultInterval = time.Minute

// OperationLister — выборка операций, вошедших в статус после момента.
type OperationLister interface {
	ListEnteredStatusSince(ctx context.Context, q operations.Querier, statuses []string, since time.Time, limit int) ([]operations.Operation, error)
}

// Runner поллит операции и шлёт события в webhook.Client.
type Runner struct {
	Store    OperationLister
	Pool     operations.Querier
	Client   *webhook.Client
	Interval time.Duration
	Log      *slog.Logger
}

// Run блокируется до отмены ctx. Ошибки логируются и не прерывают цикл:
// уведомления не должны ронять worker.
func (r *Runner) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	log := r.Log
	if log == nil {
		log = slog.Default()
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Начинаем с момента старта: не пересылать всю историю при включении.
	watermark := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now()
		ops, err := r.Store.ListEnteredStatusSince(ctx, r.Pool,
			[]string{"pending_approval", "failed", "partial"}, watermark, 100)
		if err != nil {
			log.ErrorContext(ctx, "notify: list operations", "error", err)
			continue
		}
		for i := range ops {
			event := OperationEvent(ops[i])
			if err := r.Client.Send(ctx, event); err != nil {
				log.WarnContext(ctx, "notify: send webhook", "type", event.Type, "error", err)
			}
		}
		// Watermark двигается независимо от ошибок отправки: повторная
		// доставка того же события хуже потерянного (алерты теряют доверие).
		watermark = now
	}
}

// OperationEvent строит несекретное событие по операции. Чистая функция
// для юнит-тестов; значения секретов и payload сюда не попадают.
func OperationEvent(op operations.Operation) webhook.Event {
	eventType := "operation.failed"
	title := "Операция завершилась ошибкой: " + op.Kind
	if op.Status == operations.StatusPendingApproval {
		eventType = "operation.pending_approval"
		title = "Операция ждёт подтверждения: " + op.Kind
	}
	fields := map[string]string{
		"operation_id": op.ID.String(),
		"kind":         op.Kind,
		"status":       string(op.Status),
		"actor":        op.ActorType + ":" + op.ActorID,
	}
	if op.ConnectionID != nil {
		fields["connection_id"] = op.ConnectionID.String()
	}
	if op.Error != "" {
		fields["error"] = op.Error
	}
	occurred := op.CreatedAt
	if op.FinishedAt != nil {
		occurred = *op.FinishedAt
	}
	return webhook.Event{Type: eventType, Title: title, Fields: fields, OccurredAt: occurred}
}
