package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// PrincipalPurger ставит операцию account.delete для учётной записи
// принципала, чей срок хранения после offboard истёк. Реализует
// maintenance.PurgeEnqueuer; устроен как ExpiryRevoker и по той же
// причине: фоновый прогон не имеет ни HTTP-сессии, ни человека-актора.
type PrincipalPurger struct {
	ops        *operations.Store
	inv        *inventory.Store
	dispatcher Dispatcher
	actorType  string
	actorID    string
}

// NewPrincipalPurger собирает purger поверх dispatcher-а worker-а.
func NewPrincipalPurger(dispatcher Dispatcher, actorType, actorID string) *PrincipalPurger {
	return &PrincipalPurger{
		ops:        operations.NewStore(),
		inv:        inventory.NewStore(),
		dispatcher: dispatcher,
		actorType:  actorType,
		actorID:    actorID,
	}
}

// EnqueuePurgeDelete создаёт операцию удаления аккаунта в переданной
// транзакции. Возвращает enqueued=false без ошибки, когда ставить нечего
// или рано: аккаунт уже удалён либо его lifecycle занят другой операцией —
// прогон не падает, кандидата подхватит следующий (как у TTL enforcement).
func (p *PrincipalPurger) EnqueuePurgeDelete(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, reason string) (bool, error) {
	var status inventory.AccountStatus
	if err := tx.QueryRow(ctx,
		`select status from accounts where id = $1 for update`, accountID,
	).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, fmt.Errorf("jobs: purge account %s: %w", accountID, inventory.ErrNotFound)
		}
		return false, fmt.Errorf("jobs: purge account %s: lock: %w", accountID, err)
	}
	if status == inventory.AccountDeleted {
		return false, nil
	}
	var busy bool
	if err := tx.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and status in ('pending_approval', 'pending', 'running')
		)`, accountID).Scan(&busy); err != nil {
		return false, fmt.Errorf("jobs: purge account %s: inspect lifecycle: %w", accountID, err)
	}
	if busy {
		return false, nil
	}

	reserved, err := p.inv.ReserveAccountLifecycle(ctx, tx, accountID, status)
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(AccountPayload{
		AccountID:                reserved.ID,
		ExpectedStatus:           reserved.Status,
		ExpectedLifecycleVersion: reserved.LifecycleVersion,
		Reason:                   reason,
	})
	if err != nil {
		return false, fmt.Errorf("jobs: purge account %s: marshal payload: %w", accountID, err)
	}
	op, _, err := p.ops.Create(ctx, tx, operations.CreateParams{
		Kind:          KindAccountDelete,
		ConnectionID:  &reserved.ConnectionID,
		AccountID:     &reserved.ID,
		PrincipalID:   reserved.PrincipalID,
		Payload:       payload,
		ActorType:     p.actorType,
		ActorID:       p.actorID,
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		return false, err
	}
	if err := p.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return false, err
	}
	return true, nil
}
