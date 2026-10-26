package api

// Отмена вывода принципала из системы, пока срок хранения не истёк.
//
// Обратный ход offboard: принципал возвращается в active, отозванные права
// выдаются заново (access.grant). Отдельная операция, а не откат
// транзакции: восстановление меняет целевые системы и обязано попасть в
// audit наравне с прямым действием.
//
// Пароль остаётся тем, на который его сменил offboard: вернуть прежний
// нельзя и не нужно — человеку выдаётся текущий обычной одноразовой
// ссылкой, которая после возврата в active снова доступна. Общий пароль
// окружения выдаёт /principals/{id}/share, личный пароль аккаунта —
// /accounts/{id}/share.
//
// Перевыдаются ровно те bindings, которые отозвал последний offboard этого
// принципала (дети access.revoke его parent'а), а не все absent-bindings:
// среди последних могут быть отозванные раньше и осознанно, и возвращать их
// молча нельзя.
//
// Отзывы того же offboard, застрявшие в pending_approval (mass-revoke
// gate), restore отклоняет: восстановление отменяет вывод целиком, и
// оставить его детей ждать approve значит заложить мину — approve-children
// по старому parent снял бы права уже у восстановленного, активного
// человека, не спрашивая никого заново.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// auditActionPrincipalRestored — audit-действие отмены вывода из системы.
const auditActionPrincipalRestored = "principal.restored"

// restoreChild — дочерняя операция перевыдачи права при отмене вывода.
type restoreChild struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	AccountID    uuid.UUID `json:"account_id"`
	BindingID    uuid.UUID `json:"binding_id"`
	OperationID  uuid.UUID `json:"operation_id"`
}

// restorePlan — восстановимое право: binding, отозванный offboard, вместе с
// его аккаунтом и определением права.
type restorePlan struct {
	binding    inventory.Binding
	account    inventory.Account
	permission inventory.Permission
	scope      *inventory.Resource
}

// restorePrincipal — POST /api/v1/principals/{id}/restore (admin): отменяет
// вывод из системы, пока не истёк срок хранения. Принципал возвращается в
// active, purge_after снимается, отозванные offboard права выдаются заново.
// Не в pending_purge — 409: у active отменять нечего, а deleted уже
// уничтожен необратимо.
func (s *Server) restorePrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	p, err := s.principals.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if p.Status != principals.StatusPendingPurge {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"principal is %s: only a principal being offboarded can be restored", p.Status))
		return
	}
	// Истёкший срок — территория purge-фазы обслуживания: восстановление
	// поверх начавшегося уничтожения перевыдавало бы права на аккаунты,
	// которые фоновая задача прямо сейчас удаляет.
	if p.PurgeAfter != nil && time.Now().After(*p.PurgeAfter) {
		respondError(w, http.StatusConflict,
			"retention period has expired: the principal is being purged and cannot be restored")
		return
	}

	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	managed, _ := partitionOffboardAccounts(accounts)
	plans, err := s.restorePlans(ctx, p.ID, managed)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	auditMeta := map[string]any{"restored_bindings": len(plans)}
	if len(plans) == 0 {
		s.restoreMetadataOnly(w, r, sess, p, auditMeta)
		return
	}

	extra := map[string]any{}
	s.runBulkParent(w, r, sess, bulkParent{
		kind:             jobs.KindBulkPrincipalEnable,
		principalID:      &p.ID,
		payload:          map[string]any{"bindings": len(plans)},
		payloadErrPrefix: "api: marshal principal restore payload",
		auditAction:      auditActionPrincipalRestored,
		commitErrPrefix:  "api: commit principal restore",
		extraResponse:    extra,
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		if _, err := s.principals.SetStatus(ctx, tx, p.ID, principals.StatusActive); err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		rejected, err := s.rejectStaleOffboardRevokes(ctx, tx, sess, p.ID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		auditMeta["rejected_stale_revokes"] = rejected
		updated, err := s.principals.SetPurgeAfter(ctx, tx, p.ID, nil)
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		fields, err := principalResponseFields(updated)
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		for k, v := range fields {
			extra[k] = v
		}

		out := make([]restoreChild, 0, len(plans))
		for i := range plans {
			plan := plans[i]
			// Права выдаются как обычный грант: тот же путь, что у ручной
			// выдачи, поэтому desired-состояние и binding остаются теми же.
			child, err := s.createGrant(r, tx, sess, grantTarget{
				account:    plan.account,
				permission: plan.permission,
				scope:      plan.scope,
			}, plan.binding.ExpiresAt, true, &parentID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, restoreChild{
				ConnectionID: plan.account.ConnectionID,
				AccountID:    plan.account.ID,
				BindingID:    child.BindingID,
				OperationID:  child.OperationID,
			})
		}
		return out, auditMeta, true
	})
}

// auditActionOperationRejectedByRestore — audit-действие отклонения
// застрявшего в pending_approval ребёнка offboard при отмене вывода.
// Отдельное действие, а не operation.rejected: решение принял не человек в
// разделе подтверждений, а сама отмена вывода.
const auditActionOperationRejectedByRestore = "operation.rejected_by_restore"

// rejectStaleOffboardRevokes отклоняет access.revoke детей последнего
// offboard принципала, ожидающих approve. Выполняется в транзакции restore:
// либо права перевыданы И зависшие отзывы отклонены, либо ни то ни другое.
// Отсутствие offboard-parent (metadata-only offboard) — не ошибка.
// Возвращает число отклонённых.
func (s *Server) rejectStaleOffboardRevokes(ctx context.Context, tx pgx.Tx,
	sess auth.Session, principalID uuid.UUID) (int, error) {
	parent, err := s.operations.LatestParent(ctx, tx, principalID, jobs.KindBulkPrincipalOffboard)
	if err != nil {
		if errors.Is(err, operations.ErrNotFound) {
			return 0, nil
		}
		return 0, err
	}
	children, err := s.operations.ListByParent(ctx, tx, parent.ID)
	if err != nil {
		return 0, err
	}
	rejected := 0
	for i := range children {
		child := children[i]
		if (child.Kind != jobs.KindAccessRevoke && child.Kind != jobs.KindPostgresStatsRevokeV1) || child.Status != operations.StatusPendingApproval {
			continue
		}
		if _, err := s.operations.Reject(ctx, tx, child.ID, "superseded by principal restore"); err != nil {
			// Гонка с конкурентным решением по этому ребёнку: перечитать и
			// пропустить нельзя — approve успел снять право, которое restore
			// сейчас перевыдаёт. Откат всей транзакции честнее тихой смеси.
			return 0, err
		}
		childID := child.ID
		if err := s.writeAudit(ctx, tx, audit.Event{
			ActorType:    sess.ActorType(),
			ActorID:      sess.ActorID(),
			Action:       auditActionOperationRejectedByRestore,
			ConnectionID: child.ConnectionID,
			AccountID:    child.AccountID,
			PrincipalID:  child.PrincipalID,
			OperationID:  &childID,
			Result:       audit.ResultSuccess,
		}, map[string]any{"reason": "superseded by principal restore"}); err != nil {
			return 0, err
		}
		rejected++
	}
	if rejected > 0 {
		// Отклонение могло закрыть последних незавершённых детей offboard —
		// тогда parent финализируется этой же транзакцией.
		if _, _, err := s.operations.FinalizeParent(ctx, tx, parent.ID); err != nil {
			return 0, err
		}
	}
	return rejected, nil
}

// restorePlans собирает права к перевыдаче: bindings, отозванные последним
// offboard принципала, у которых сохранился аккаунт и определение права.
// Пропадания (binding или аккаунт удалены после offboard) пропускаются
// молча — восстанавливать нечего, а падать на этом нельзя.
func (s *Server) restorePlans(ctx context.Context, principalID uuid.UUID,
	managed []inventory.Account) ([]restorePlan, error) {
	bindingIDs, err := s.operations.LatestParentChildBindings(
		ctx, s.pool, principalID, jobs.KindBulkPrincipalOffboard, jobs.KindAccessRevoke)
	if err != nil {
		return nil, err
	}
	statsBindingIDs, err := s.operations.LatestParentChildBindings(ctx, s.pool, principalID, jobs.KindBulkPrincipalOffboard, jobs.KindPostgresStatsRevokeV1)
	if err != nil {
		return nil, err
	}
	bindingIDs = append(bindingIDs, statsBindingIDs...)
	byAccount := make(map[uuid.UUID]inventory.Account, len(managed))
	for i := range managed {
		byAccount[managed[i].ID] = managed[i]
	}

	out := make([]restorePlan, 0, len(bindingIDs))
	for _, bindingID := range bindingIDs {
		binding, err := s.inventory.GetBinding(ctx, s.pool, bindingID)
		if err != nil {
			if errors.Is(err, inventory.ErrNotFound) {
				continue
			}
			return nil, err
		}
		account, ok := byAccount[binding.AccountID]
		if !ok {
			continue
		}
		permission, err := s.inventory.GetPermission(ctx, s.pool, binding.PermissionDefinitionID)
		if err != nil {
			if errors.Is(err, inventory.ErrNotFound) {
				continue
			}
			return nil, err
		}
		plan := restorePlan{binding: binding, account: account, permission: permission}
		if binding.ScopeResourceID != nil {
			scope, err := s.inventory.GetResource(ctx, s.pool, *binding.ScopeResourceID)
			if err != nil {
				if errors.Is(err, inventory.ErrNotFound) {
					continue
				}
				return nil, err
			}
			plan.scope = &scope
		}
		out = append(out, plan)
	}
	return out, nil
}

// restoreMetadataOnly — отмена вывода принципала, которому нечего
// перевыдавать: одной транзакцией снимаются статус и срок хранения, затем
// best-effort восстанавливаются общие секреты.
func (s *Server) restoreMetadataOnly(w http.ResponseWriter, r *http.Request, sess auth.Session,
	p principals.Principal, auditMeta map[string]any) {
	ctx := r.Context()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := s.principals.SetStatus(ctx, tx, p.ID, principals.StatusActive); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Дети последнего offboard могли зависнуть в pending_approval, даже
	// когда перевыдавать нечего (например, binding удалили после вывода).
	rejected, err := s.rejectStaleOffboardRevokes(ctx, tx, sess, p.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	auditMeta["rejected_stale_revokes"] = rejected
	updated, err := s.principals.SetPurgeAfter(ctx, tx, p.ID, nil)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionPrincipalRestored,
		PrincipalID: &p.ID,
		Result:      audit.ResultSuccess,
	}, auditMeta); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit principal restore: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, toPrincipalJSON(updated))
}
