package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"

	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// ExpiryRevoker ставит операцию access.revoke для binding, у которого истёк
// срок действия. Реализует maintenance.RevokeEnqueuer.
//
// Зачем отдельный тип, а не вызов api: TTL enforcement выполняет worker в
// фоновом прогоне обслуживания, где нет ни HTTP-сессии, ни actor-а — актор
// здесь сервисный, тот же, что у прочих находок обслуживания. Общая с api
// часть — это сама модель операции (kind, payload, постановка в очередь), а
// не путь запроса.
type ExpiryRevoker struct {
	ops        *operations.Store
	inv        *inventory.Store
	dispatcher Dispatcher
	actorType  string
	actorID    string
}

// NewExpiryRevoker собирает revoker поверх dispatcher-а worker-а. actorType и
// actorID попадают в операцию и её audit-события.
func NewExpiryRevoker(dispatcher Dispatcher, actorType, actorID string) *ExpiryRevoker {
	return &ExpiryRevoker{
		ops:        operations.NewStore(),
		inv:        inventory.NewStore(),
		dispatcher: dispatcher,
		actorType:  actorType,
		actorID:    actorID,
	}
}

// EnqueueExpiredRevoke создаёт операцию отзыва в переданной транзакции.
//
// Занятый lifecycle аккаунта (идёт account.create/disable/rotate) — не ошибка
// прогона: операция отзыва просто не ставится, binding остаётся с
// desired=absent и будет подхвачен следующим прогоном. Падать всем прогоном
// из-за одной параллельной операции нельзя — это остановило бы TTL для
// остальных bindings.
func (e *ExpiryRevoker) EnqueueExpiredRevoke(ctx context.Context, tx pgx.Tx, bindingID uuid.UUID) error {
	binding, err := e.inv.GetBinding(ctx, tx, bindingID)
	if err != nil {
		return err
	}
	if binding.TransitionOperationID != nil {
		return nil
	}
	acct, err := e.inv.GetAccount(ctx, tx, binding.AccountID)
	if err != nil {
		return err
	}

	var status inventory.AccountStatus
	var lifecycleVersion int64
	if err := tx.QueryRow(ctx,
		`select status, lifecycle_version from accounts where id = $1 for update`, acct.ID,
	).Scan(&status, &lifecycleVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("jobs: expire binding %s: account %s: %w", bindingID, acct.ID, inventory.ErrNotFound)
		}
		return fmt.Errorf("jobs: expire binding %s: lock account %s: %w", bindingID, acct.ID, err)
	}
	// Удалённая учётка права уже не несёт: отзывать нечего.
	if status == inventory.AccountDeleted {
		return nil
	}
	var busy bool
	if err := tx.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and status in ('pending_approval', 'pending', 'running')
			  and (kind like 'account.%' or kind = 'credential.rotate' or binding_id = $2)
		)`, acct.ID, bindingID).Scan(&busy); err != nil {
		return fmt.Errorf("jobs: expire binding %s: inspect account lifecycle: %w", bindingID, err)
	}
	if busy {
		// expireBindings уже поставил desired=absent в этой транзакции.
		// Если revoke поставить нельзя, возвращаем прежнее требование present,
		// иначе binding останется снятым только в metadata без target job.
		if _, err := e.inv.SetBindingDesired(ctx, tx, bindingID, inventory.BindingPresent); err != nil {
			return fmt.Errorf("jobs: expire binding %s: restore desired after busy operation: %w", bindingID, err)
		}
		return nil
	}
	permission, err := e.inv.GetPermission(ctx, tx, binding.PermissionDefinitionID)
	if err != nil {
		return err
	}
	var permissionAttributes map[string]any
	if (permission.AssignmentKey != "" || IsPostgresStatsPermission(permission) || IsPostgresObjectPermission(permission)) && len(permission.Attributes) > 0 {
		if err := json.Unmarshal(permission.Attributes, &permissionAttributes); err != nil {
			return fmt.Errorf("jobs: expire binding %s: decode permission attributes: %w", bindingID, err)
		}
	}
	var statsPins *postgres.StatsMembershipPins
	var objectPins *adapter.PostgresObjectACLPins
	operationKind := KindAccessRevoke
	if IsPostgresObjectPermission(permission) {
		operationKind = KindPostgresObjectACLRevokeV1
		conn, err := connections.NewStore().Get(ctx, tx, acct.ConnectionID)
		if err != nil {
			return err
		}
		objectPins, err = BuildObjectACLPins(conn, acct, permission, &binding)
		if err != nil {
			return err
		}
	}
	if IsPostgresStatsPermission(permission) {
		conn, err := connections.NewStore().Get(ctx, tx, acct.ConnectionID)
		if err != nil {
			return err
		}
		statsPins, err = BuildStatsMembershipPins(ctx, tx, conn, acct, permission, uuid.Nil)
		if err != nil {
			return err
		}
		operationKind = KindPostgresStatsRevokeV1
	}

	payload, err := json.Marshal(AccessPayload{
		ObjectACL:                       objectPins,
		StatsMembership:                 statsPins,
		BindingID:                       bindingID,
		ExpectedPermissionDefinitionID:  binding.PermissionDefinitionID,
		ExpectedDesiredState:            string(inventory.BindingAbsent),
		ExpectedAccountLifecycleVersion: lifecycleVersion,
		PermissionAttributes:            permissionAttributes,
	})
	if err != nil {
		return fmt.Errorf("jobs: expire binding %s: marshal payload: %w", bindingID, err)
	}
	op, _, err := e.ops.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		BindingID:     &bindingID,
		Payload:       payload,
		ActorType:     e.actorType,
		ActorID:       e.actorID,
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		return err
	}
	return e.dispatcher.EnqueueOperationTx(ctx, tx, op.ID)
}
