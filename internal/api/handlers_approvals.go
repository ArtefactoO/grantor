package api

// Approval workflow enforcement (ADR-0010; docs/threat-model.md P1, R3).
// Опасная изменяющая операция (dangerous grant) при включённом gate создаётся
// в статусе pending_approval и не диспатчится воркеру, пока admin явно её не
// подтвердит. Здесь — admin-эндпоинты списка ожидающих, approve и reject
// (одиночные и batch по всем детям parent — approve-children/reject-children).
//
// Это confirmation gate, а НЕ four-eyes: подтвердить операцию может тот же
// admin, что и запросил (self-approval — штатный случай); правило «approver !=
// requester» не применяется, 403 на self-approval нет. Единственное
// требование — роль admin (обеспечивается роутингом). Каждое решение пишет
// audit-событие (operation.approved / operation.rejected) в одной транзакции с
// переходом статуса; approve явно помечает self_approved, если запросивший и
// подтверждающий — один актор. Идемпотентность: повторный approve уже
// подтверждённой, но ещё не выполненной операции — no-op 200; approve/reject
// уже выполненной или отклонённой — 409 conflict.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/approval"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// restoreRejectedDesired возвращает binding отклонённой операции в то
// состояние, в котором он был до её постановки.
//
// И выдача, и отзыв меняют desired ещё до approve (createGrantOperation,
// createRevoke), поэтому без отката отказ admin оставляет binding в вечном
// drift, а повторное применение того же манифеста считает решение уже
// принятым и не проходит gate заново.
//
// Отзыв всегда возвращается в present: pending_approval у него возникает
// только из mass-revoke gate (manifest prune и offboard), а оба отзывают лишь
// managed bindings. У выдачи прежнее состояние произвольно — строка могла
// быть unmanaged или чиниться из absent, — поэтому оно берётся из payload;
// строку, созданную самой выдачей и ни разу не применённую на цели, откат
// удаляет: иначе несуществующее право показывалось бы как «отозванное».
func (s *Server) restoreRejectedDesired(ctx context.Context, tx pgx.Tx, op operations.Operation) error {
	if op.BindingID == nil {
		return nil
	}
	switch op.Kind {
	case jobs.KindAccessRevoke, jobs.KindPostgresStatsRevokeV1:
		return s.rollbackBinding(ctx, tx, func() error {
			_, err := s.inventory.SetBindingDesired(ctx, tx, *op.BindingID, inventory.BindingPresent)
			return err
		})
	case jobs.KindAccessGrant, jobs.KindPostgresStatsGrantV1:
		var payload jobs.AccessPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return fmt.Errorf("api: decode grant payload of %s: %w", op.ID, err)
		}
		return s.rollbackBinding(ctx, tx, func() error {
			if payload.BindingCreated {
				deleted, err := s.inventory.DeleteUnappliedBinding(ctx, tx, *op.BindingID)
				if err != nil || deleted {
					return err
				}
			}
			var prior *inventory.BindingState
			if payload.PriorDesiredState != "" {
				state := inventory.BindingState(payload.PriorDesiredState)
				prior = &state
			}
			_, err := s.inventory.RestoreBindingDesired(ctx, tx, *op.BindingID, prior)
			return err
		})
	case jobs.KindAccessReplace:
		var payload jobs.AccessReplacePayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return fmt.Errorf("api: decode access replacement payload of %s: %w", op.ID, err)
		}
		return s.rollbackBinding(ctx, tx, func() error {
			_, err := s.inventory.RejectAccessReplacement(ctx, tx, inventory.AccessReplacementTransition{
				BindingID:        payload.BindingID,
				OperationID:      op.ID,
				FromPermissionID: payload.FromPermissionDefinitionID,
				ToPermissionID:   payload.ToPermissionDefinitionID,
				AssignmentKey:    payload.AssignmentKey,
				ExpectedVersion:  payload.ExpectedBindingVersion,
			})
			return err
		})
	default:
		return nil
	}
}

// rollbackBinding выполняет откат, прощая исчезнувший binding: его мог унести
// каскад удаления подключения или аккаунта — откатывать нечего, а отказ
// операции остаётся в силе.
func (s *Server) rollbackBinding(ctx context.Context, tx pgx.Tx, rollback func() error) error {
	if err := rollback(); err != nil && !errors.Is(err, inventory.ErrNotFound) {
		return err
	}
	return nil
}

// Audit actions approval workflow.
const (
	auditActionOperationApproved = "operation.approved"
	auditActionOperationRejected = "operation.rejected"
)

// decisionRequest — тело POST approve/reject: необязательный комментарий admin.
type decisionRequest struct {
	Reason string `json:"reason"`
}

// listApprovals — GET /api/v1/approvals (admin): операции в статусе
// pending_approval от новых к старым. Ответ — тот же формат, что и
// listOperations (operationJSON с payload/plan для человекочитаемого плана).
func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit, err := queryLimit(r, "limit", 0)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	readScope, err := s.readScope(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	ops, err := s.operations.List(ctx, s.pool, operations.Filter{
		ReadScope: readScope,
		Status:    operations.StatusPendingApproval,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	out := make([]operationJSON, 0, len(ops))
	for i := range ops {
		out = append(out, toOperationJSON(ops[i]))
	}
	respondJSON(w, http.StatusOK, operationListResponse{Operations: out})
}

// approveOperation — POST /api/v1/operations/{id}/approve (admin): подтверждает
// операцию, ожидающую approval. Подтвердить может тот же admin, что и запросил
// (self-approval разрешён и штатен). Успешный approve переводит операцию в
// pending, и она выполняется обычным путём. Повторный approve уже
// подтверждённой, но не выполненной операции — идемпотентный no-op.
func (s *Server) approveOperation(w http.ResponseWriter, r *http.Request) {
	s.decideOperation(w, r, true)
}

// rejectOperation — POST /api/v1/operations/{id}/reject (admin): отклоняет
// операцию, ожидающую approval; она переходит в терминальный cancelled и
// никогда не выполнится.
func (s *Server) rejectOperation(w http.ResponseWriter, r *http.Request) {
	s.decideOperation(w, r, false)
}

// decideOperation — общая обработка approve (approve=true) и reject
// (approve=false). Загружает операцию, применяет идемпотентность по текущему
// статусу, выполняет переход и пишет audit одной транзакцией. Self-approval не
// блокируется — лишь фиксируется в audit (self_approved).
func (s *Server) decideOperation(w http.ResponseWriter, r *http.Request, approve bool) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	var req decisionRequest
	// Тело необязательно: пустой запрос допустим (approve без комментария).
	if r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	reason := approval.NormalizeReason(req.Reason)

	op, err := s.operations.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkOperationReadScope(ctx, sess, id)) {
		return
	}

	// Идемпотентность до записи: повтор решения по уже разрешённой операции.
	if s.decisionIsNoop(w, op, approve) {
		return
	}
	if op.Status != operations.StatusPendingApproval {
		respondError(w, http.StatusConflict,
			"operation is not pending approval (status "+string(op.Status)+")")
		return
	}

	// Self-approval разрешён (confirmation gate, не four-eyes): не блокируем, а
	// фиксируем в audit — журнал должен явно показывать, что один и тот же admin
	// запросил и подтвердил операцию.
	selfApproved := approval.IsSelf(op.ActorType, op.ActorID, sess.ActorType(), sess.ActorID())

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if s.respondScopeError(ctx, w, s.checkOperationReadScopeWith(ctx, tx, sess, id)) {
		return
	}

	var decided operations.Operation
	action := auditActionOperationRejected
	if approve {
		action = auditActionOperationApproved
		decided, err = s.operations.Approve(ctx, tx, id, sess.ActorID(), reason)
	} else {
		decided, err = s.operations.Reject(ctx, tx, id, reason)
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !approve {
		if err := s.restoreRejectedDesired(ctx, tx, op); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	// Reject переводит ребёнка в терминальный cancelled: если это был
	// последний незавершённый ребёнок bulk-операции, parent финализируется
	// в той же транзакции (идемпотентный no-op, пока есть незавершённые).
	if !approve && op.ParentID != nil {
		if _, _, err := s.operations.FinalizeParent(ctx, tx, *op.ParentID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}

	metadata, err := decisionAuditMetadata(op, reason, selfApproved)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       action,
		ConnectionID: op.ConnectionID,
		AccountID:    op.AccountID,
		PrincipalID:  op.PrincipalID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
		Metadata:     metadata,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, toOperationJSON(decided))
}

// decisionIsNoop обрабатывает идемпотентный повтор решения и сообщает, что
// ответ уже записан. approve повторно по уже подтверждённой (pending с
// approved_by), но ещё не выполненной операции — no-op 200. reject повторно
// по уже отклонённой (cancelled) операции — no-op 200. Прочие статусы (в т.ч.
// уже выполняющаяся/выполненная) не обрабатываются здесь: вызывающий вернёт
// 409 conflict.
func (s *Server) decisionIsNoop(w http.ResponseWriter, op operations.Operation, approve bool) bool {
	switch {
	case approve && op.Status == operations.StatusPending && op.ApprovedBy != nil:
		respondJSON(w, http.StatusOK, toOperationJSON(op))
		return true
	case !approve && op.Status == operations.StatusCancelled:
		respondJSON(w, http.StatusOK, toOperationJSON(op))
		return true
	default:
		return false
	}
}

// decisionAuditMetadata собирает metadata audit-события approve/reject.
// self_approved пишется всегда: для approve — ключевая отметка «тот же admin
// подтвердил свой запрос»; для reject — симметрично фиксирует, отклонил ли
// запросивший свой же запрос. Для batch-решений вычисляется НА КАЖДОГО
// ребёнка отдельно (requester ребёнка сравнивается с общим approver), поэтому
// helper принимает операцию, а не заранее вычисленный флаг сессии.
// Секретов в metadata нет (payload операции не включается).
func decisionAuditMetadata(op operations.Operation, reason string, selfApproved bool) ([]byte, error) {
	return json.Marshal(map[string]any{
		"requester_actor_type": op.ActorType,
		"requester_actor_id":   op.ActorID,
		"operation_kind":       op.Kind,
		"reason":               reason,
		"self_approved":        selfApproved,
	})
}

// maxDecideChildren — защитный предел числа детей одного batch-решения.
// Достижим только теоретически: bulk grant ограничен maxBulkItems (100),
// manifest apply — maxEntries (1000) действий, так что штатно детей у parent
// меньше. Предел совпадает с maxEntries манифеста, чтобы любое штатное
// применение можно было подтвердить одним действием.
const maxDecideChildren = 1000

// childDecisionSkip — ребёнок, пропущенный batch-решением: он уже решён или
// диспатчен (не в pending_approval). Это не ошибка — batch идемпотентен,
// пропущенные отражаются в ответе с их текущим статусом.
type childDecisionSkip struct {
	ID     uuid.UUID         `json:"id"`
	Status operations.Status `json:"status"`
}

// partitionApprovalChildren разбивает детей parent на ожидающих решения
// (pending_approval) и пропускаемых (все остальные статусы — уже решённые
// или уже диспатченные). Чистая функция для юнит-теста формирования batch.
func partitionApprovalChildren(children []operations.Operation) ([]operations.Operation, []childDecisionSkip) {
	var pending []operations.Operation
	var skipped []childDecisionSkip
	for i := range children {
		if children[i].Status == operations.StatusPendingApproval {
			pending = append(pending, children[i])
			continue
		}
		skipped = append(skipped, childDecisionSkip{ID: children[i].ID, Status: children[i].Status})
	}
	return pending, skipped
}

// approveChildrenResponse — тело ответа POST approve-children.
type approveChildrenResponse struct {
	OperationID uuid.UUID           `json:"operation_id"`
	Approved    []uuid.UUID         `json:"approved"`
	Skipped     []childDecisionSkip `json:"skipped"`
}

// rejectChildrenResponse — тело ответа POST reject-children.
type rejectChildrenResponse struct {
	OperationID uuid.UUID           `json:"operation_id"`
	Rejected    []uuid.UUID         `json:"rejected"`
	Skipped     []childDecisionSkip `json:"skipped"`
}

// approveChildren — POST /api/v1/operations/{id}/approve-children (admin):
// подтверждает ВСЕ pending_approval дочерние операции parent {id} одним
// действием (расширение ADR-0010 для bulk/manifest: пачка опасных грантов
// или массовый ревок подтверждается целиком). Семантика по каждому ребёнку —
// ровно как у одиночного approve: тот же guarded UPDATE store.Approve, то же
// audit-событие operation.approved с self_approved, вычисленным по requester
// КАЖДОГО ребёнка против общего approver. Self-approval разрешён и штатен.
func (s *Server) approveChildren(w http.ResponseWriter, r *http.Request) {
	s.decideChildren(w, r, true)
}

// rejectChildren — POST /api/v1/operations/{id}/reject-children (admin):
// отклоняет ВСЕ pending_approval дочерние операции parent {id}; каждая
// переходит в терминальный cancelled и никогда не выполнится.
func (s *Server) rejectChildren(w http.ResponseWriter, r *http.Request) {
	s.decideChildren(w, r, false)
}

// decideChildren — общая обработка approve-children/reject-children. Решения
// по всем pending_approval детям и их audit-события выполняются ОДНОЙ
// транзакцией. Уже решённые/диспатченные дети — не ошибка: они отражаются в
// skipped с текущим статусом (batch идемпотентен; parent без ожидающих детей
// отвечает 200 с пустым результатом). Ребёнок, проигравший гонку
// конкурентному одиночному решению (guarded UPDATE store.decide вернул
// конфликт), тоже уходит в skipped, а не валит batch.
func (s *Server) decideChildren(w http.ResponseWriter, r *http.Request, approve bool) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	var req decisionRequest
	// Тело необязательно: пустой запрос допустим (решение без комментария).
	if r.ContentLength != 0 {
		if !decodeJSON(w, r, &req) {
			return
		}
	}
	reason := approval.NormalizeReason(req.Reason)

	// Parent должен существовать; его собственный статус не важен (bulk parent
	// живёт в running, пока дети не разрешены).
	if _, err := s.operations.Get(ctx, s.pool, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkOperationReadScope(ctx, sess, id)) {
		return
	}
	children, err := s.operations.ListByParent(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	pending, skipped := partitionApprovalChildren(children)
	if len(pending) > maxDecideChildren {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"operation has %d pending children, at most %d can be decided in one batch",
			len(pending), maxDecideChildren))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if s.respondScopeError(ctx, w, s.checkOperationReadScopeWith(ctx, tx, sess, id)) {
		return
	}

	action := auditActionOperationRejected
	if approve {
		action = auditActionOperationApproved
	}
	decided := make([]uuid.UUID, 0, len(pending))
	for i := range pending {
		child := pending[i]
		var decideErr error
		if approve {
			_, decideErr = s.operations.Approve(ctx, tx, child.ID, sess.ActorID(), reason)
		} else {
			_, decideErr = s.operations.Reject(ctx, tx, child.ID, reason)
		}
		switch {
		case errors.Is(decideErr, operations.ErrStatusConflict):
			// Гонка с конкурентным одиночным решением: ребёнок уже не в
			// pending_approval. Перечитываем статус и пропускаем — семантика
			// как у уже решённого ребёнка.
			current, getErr := s.operations.Get(ctx, tx, child.ID)
			if getErr != nil {
				respondStoreError(ctx, w, getErr)
				return
			}
			skipped = append(skipped, childDecisionSkip{ID: child.ID, Status: current.Status})
			continue
		case decideErr != nil:
			respondStoreError(ctx, w, decideErr)
			return
		}
		if !approve {
			if err := s.restoreRejectedDesired(ctx, tx, child); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
		}

		// Audit по каждому ребёнку — как у одиночного решения; self_approved
		// вычисляется по requester этого ребёнка против общего approver.
		selfApproved := approval.IsSelf(child.ActorType, child.ActorID, sess.ActorType(), sess.ActorID())
		metadata, err := decisionAuditMetadata(child, reason, selfApproved)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		childID := child.ID
		if err := s.audit.Write(ctx, tx, audit.Event{
			ActorType:    sess.ActorType(),
			ActorID:      sess.ActorID(),
			Action:       action,
			ConnectionID: child.ConnectionID,
			AccountID:    child.AccountID,
			PrincipalID:  child.PrincipalID,
			OperationID:  &childID,
			Result:       audit.ResultSuccess,
			Metadata:     metadata,
		}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		decided = append(decided, child.ID)
	}
	// Batch reject мог отменить последних незавершённых детей bulk-операции
	// — тогда parent финализируется той же транзакцией (иначе идемпотентный
	// no-op). Approve терминальных статусов не создаёт, финализация не нужна.
	if !approve {
		if _, _, err := s.operations.FinalizeParent(ctx, tx, id); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if skipped == nil {
		skipped = []childDecisionSkip{}
	}
	if approve {
		respondJSON(w, http.StatusOK, approveChildrenResponse{OperationID: id, Approved: decided, Skipped: skipped})
		return
	}
	respondJSON(w, http.StatusOK, rejectChildrenResponse{OperationID: id, Rejected: decided, Skipped: skipped})
}
