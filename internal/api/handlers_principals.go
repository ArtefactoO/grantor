package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

// Audit actions раздела «Пользователи»: принципалы и привязка учётных
// записей. Привязка меняет только метаданные, поэтому события пишутся о
// свершившемся факте, без суффикса _requested.
const (
	auditActionPrincipalCreated  = "principal.created"
	auditActionPrincipalDisabled = "principal.disabled"
	auditActionPrincipalEnabled  = "principal.enabled"
	auditActionPrincipalPurged   = "principal.purged"
	auditActionAccountLinked     = "account.linked"
	auditActionAccountUnlinked   = "account.unlinked"
)

// purgePrincipal — DELETE /api/v1/principals/{id}/purge?confirm=true
// (admin): окончательно удаляет уже offboarded principal без аккаунтов и
// незавершённых операций. Исторический audit остаётся append-only.
func (s *Server) purgePrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.URL.Query().Get("confirm") != "true" {
		respondError(w, http.StatusBadRequest, "principal purge requires confirm=true query parameter")
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	p, purged, err := s.principals.PurgeDeletedOrphan(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !purged {
		respondError(w, http.StatusConflict, "principal can be purged only after offboard and removal of all accounts")
		return
	}
	metadata, _ := json.Marshal(map[string]any{
		"display_name": p.DisplayName,
		"type":         p.Type,
	})
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: auditActionPrincipalPurged,
		PrincipalID: &p.ID, Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"principal_id": p.ID, "purged": true})
}

// principalJSON — представление принципала в ответах API.
type principalJSON struct {
	ID                              uuid.UUID       `json:"id"`
	Type                            string          `json:"type"`
	DisplayName                     string          `json:"display_name"`
	ExternalProvider                string          `json:"external_provider"`
	ExternalSubject                 string          `json:"external_subject"`
	ExternalIdentityStatus          *string         `json:"external_identity_status"`
	ExternalIdentityCheckedAt       *time.Time      `json:"external_identity_checked_at"`
	ExternalIdentityStatusChangedAt *time.Time      `json:"external_identity_status_changed_at"`
	Status                          string          `json:"status"`
	Attributes                      json.RawMessage `json:"attributes"`
	// PurgeAfter — момент необратимого уничтожения выведенного из системы
	// принципала; null у остальных. UI показывает по нему остаток срока.
	PurgeAfter *time.Time `json:"purge_after"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// AccountsCount присутствует только в списковом ответе; в detail
	// вместо счётчика отдаётся сам список accounts.
	AccountsCount *int `json:"accounts_count,omitempty"`
}

// principalListResponse — тело ответа GET /api/v1/principals.
type principalListResponse struct {
	Principals []principalJSON `json:"principals"`
}

// principalDetailResponse — тело ответа GET /api/v1/principals/{id}:
// принципал и его учётные записи по всем connections (каждая несёт
// connection_id).
type principalDetailResponse struct {
	principalJSON
	Accounts []accountJSON `json:"accounts"`
}

// toPrincipalJSON собирает principalJSON из доменной модели.
func toPrincipalJSON(p principals.Principal) principalJSON {
	var externalIdentityStatus *string
	if p.ExternalIdentityStatus != nil {
		value := string(*p.ExternalIdentityStatus)
		externalIdentityStatus = &value
	}
	return principalJSON{
		ID:                              p.ID,
		Type:                            string(p.Type),
		DisplayName:                     p.DisplayName,
		ExternalProvider:                p.ExternalProvider,
		ExternalSubject:                 p.ExternalSubject,
		ExternalIdentityStatus:          externalIdentityStatus,
		ExternalIdentityCheckedAt:       p.ExternalIdentityCheckedAt,
		ExternalIdentityStatusChangedAt: p.ExternalIdentityStatusChangedAt,
		Status:                          string(p.Status),
		Attributes:                      rawOrEmptyObject(p.Attributes),
		PurgeAfter:                      p.PurgeAfter,
		CreatedAt:                       p.CreatedAt,
		UpdatedAt:                       p.UpdatedAt,
	}
}

// listPrincipals — GET /api/v1/principals?limit&offset (viewer): все
// принципалы со счётчиком учётных записей.
func (s *Server) listPrincipals(w http.ResponseWriter, r *http.Request) {
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
	items, err := s.principals.ListScoped(ctx, s.pool, limit, offset, readScope)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]principalJSON, 0, len(items))
	for i := range items {
		pj := toPrincipalJSON(items[i].Principal)
		count := items[i].AccountsCount
		pj.AccountsCount = &count
		out = append(out, pj)
	}
	respondJSON(w, http.StatusOK, principalListResponse{Principals: out})
}

// createPrincipalRequest — тело POST /api/v1/principals.
type createPrincipalRequest struct {
	Type             string `json:"type"`
	DisplayName      string `json:"display_name"`
	ExternalProvider string `json:"external_provider"`
	ExternalSubject  string `json:"external_subject"`
}

// validate проверяет тело создания принципала. Внешняя identity
// необязательна, но задаётся только парой: одиночный provider или
// subject бессмыслен и не покрывается уникальным индексом схемы.
func (req *createPrincipalRequest) validate() error {
	if !principals.Type(req.Type).Valid() {
		return fmt.Errorf("type must be %q, %q or %q",
			principals.TypeHuman, principals.TypeService, principals.TypeGroup)
	}
	if strings.TrimSpace(req.DisplayName) == "" {
		return errors.New("display_name is required")
	}
	if (req.ExternalProvider == "") != (req.ExternalSubject == "") {
		return errors.New("external_provider and external_subject must be set together")
	}
	return nil
}

// createPrincipal — POST /api/v1/principals (operator): создаёт
// принципала; создание и audit-событие коммитятся одной транзакцией.
func (s *Server) createPrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createPrincipalRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	// Пользователи каталога заводятся только импортом: он сверяет subject с
	// каталогом и сразу пишет зеркальный статус, а ручное создание оставляло
	// бы «Not checked» и пропускало опечатки в subject.
	if provider := s.directory.ProviderName(); provider != "" && req.ExternalProvider == provider {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"manual creation is for local principals; add %q users through the directory import", provider))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	p, err := s.principals.Create(ctx, tx, principals.CreateParams{
		Type:             principals.Type(req.Type),
		DisplayName:      req.DisplayName,
		ExternalProvider: req.ExternalProvider,
		ExternalSubject:  req.ExternalSubject,
	})
	if err != nil {
		if errors.Is(err, principals.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, "principal with this external identity already exists")
			return
		}
		respondStoreError(ctx, w, err)
		return
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionPrincipalCreated,
		PrincipalID: &p.ID,
		Result:      audit.ResultSuccess,
	}, map[string]any{
		"type":         string(p.Type),
		"display_name": p.DisplayName,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create principal: %w", err))
		return
	}
	respondJSON(w, http.StatusCreated, toPrincipalJSON(p))
}

// getPrincipal — GET /api/v1/principals/{id} (viewer): принципал и его
// учётные записи по всем connections.
func (s *Server) getPrincipal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	p, err := s.principals.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	visibleConnections, err := s.visibleConnectionIDs(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	out := principalDetailResponse{
		principalJSON: toPrincipalJSON(p),
		Accounts:      make([]accountJSON, 0, len(accounts)),
	}
	for i := range accounts {
		if visibleConnections != nil && !visibleConnections[accounts[i].ConnectionID] {
			continue
		}
		out.Accounts = append(out.Accounts, toAccountJSON(accounts[i]))
	}
	respondJSON(w, http.StatusOK, out)
}

// principalStatusBlocks возвращает текст 409-ошибки для действия над
// принципалом в данном статусе: deleted (tombstone после offboard)
// блокирует всё, disabled — только выдачу секретов (share/rotate), когда
// blockDisabled=true. Пустая строка — действие разрешено. Чистая функция
// для юнит-тестов.
func principalStatusBlocks(status principals.Status, blockDisabled bool) string {
	switch {
	case status == principals.StatusDeleted:
		return "principal is deleted"
	// Человек выводится из системы: новых прав и секретов он получать не
	// должен, пока вывод не отменён восстановлением.
	case status == principals.StatusPendingPurge:
		return "principal is being offboarded"
	case blockDisabled && status == principals.StatusDisabled:
		return "principal is disabled"
	default:
		return ""
	}
}

// cascadeStatusTargets возвращает managed-аккаунты принципала, которым
// каскад disable/enable ставит дочернюю операцию: аккаунты уже в целевом
// статусе пропускаются (лишних детей нет), unmanaged не трогаются (их
// lifecycle принадлежит целевой системе), не-живые исключены — deleted
// (soft delete, строки истории), provisioning (учётки на target ещё нет) и
// missing (её там уже нет). Отключать/включать нечего, а дочерняя
// операция по такой записи гарантированно упала бы и делала каскад
// вечно partial. Никакой engine-специфики: набор целей зависит только от
// метаданных инвентаря, дочерние операции проходят общий adapter/connector
// поток. Чистая функция для юнит-тестов.
func cascadeStatusTargets(accounts []inventory.Account, target inventory.AccountStatus) []inventory.Account {
	out := make([]inventory.Account, 0, len(accounts))
	for i := range accounts {
		acct := accounts[i]
		if acct.Ownership != inventory.OwnershipManaged ||
			!inventory.IsLiveAccountStatus(acct.Status) || acct.Status == target {
			continue
		}
		out = append(out, acct)
	}
	return out
}

// principalResponseFields раскладывает principalJSON в map верхнеуровневых
// полей ответа: каскадный 202-ответ disable/enable сохраняет прежнюю форму
// принципала (backward-compatible) и лишь добавляет operation_id/children.
func principalResponseFields(p principals.Principal) (map[string]any, error) {
	raw, err := json.Marshal(toPrincipalJSON(p))
	if err != nil {
		return nil, fmt.Errorf("api: marshal principal response: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("api: unmarshal principal response: %w", err)
	}
	return out, nil
}

// enqueueAccountChildTx создаёт операцию kind над аккаунтом под parent
// parentID в транзакции tx и ставит её в очередь. requiresApproval создаёт
// операцию в pending_approval (offboard: гейт масс-отзыва накрывает и
// account.delete детей, чтобы удаление аккаунта не обогнало ожидающие
// approve ревоки того же parent). reason — причина удаления для детей
// account.delete каскада offboard; остальные вызовы передают пустую
// строку (omitempty сохраняет их payload побайтово).
func (s *Server) enqueueAccountChildTx(r *http.Request, tx pgx.Tx, sess auth.Session, acct inventory.Account,
	kind string, parentID *uuid.UUID, requiresApproval bool, reason string) (operations.Operation, error) {
	ctx := r.Context()
	if capability, known := accountOperationCapability[kind]; known {
		conn, err := s.connections.Get(ctx, tx, acct.ConnectionID)
		if err != nil {
			return operations.Operation{}, err
		}
		if err := requireConnectionCapability(conn, capability); err != nil {
			return operations.Operation{}, err
		}
	}
	expected := acct.Status
	switch kind {
	case jobs.KindAccountDisable:
		expected = inventory.AccountActive
	case jobs.KindAccountEnable:
		expected = inventory.AccountDisabled
	case jobs.KindAccountDelete:
		// Из deleted переходов нет; provisioning и missing удалять можно —
		// drop на целевой системе идемпотентен (учётки там нет), а
		// tombstone метаданных offboard'у принципала нужен в любом случае.
		if acct.Status == inventory.AccountDeleted {
			return operations.Operation{}, fmt.Errorf("account %s cannot be deleted from status %q: %w",
				acct.ID, acct.Status, inventory.ErrAccountStatusConflict)
		}
	default:
		return operations.Operation{}, fmt.Errorf("api: unsupported account child kind %q", kind)
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, expected)
	if err != nil {
		return operations.Operation{}, err
	}
	return s.enqueueReservedAccountChildTx(r, tx, sess, reserved, expected, kind, parentID, requiresApproval, reason)
}

// enqueueReservedAccountChildTx создаёт child после уже выполненного в этой
// транзакции ReserveAccountLifecycle. Нужен offboard: revoke и delete одного
// account обязаны получить одно поколение, иначе revoke немедленно стал бы
// stale после reservation удаления.
func (s *Server) enqueueReservedAccountChildTx(r *http.Request, tx pgx.Tx, sess auth.Session,
	acct inventory.Account, expected inventory.AccountStatus, kind string, parentID *uuid.UUID,
	requiresApproval bool, reason string) (operations.Operation, error) {
	ctx := r.Context()
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, Reason: reason, ExpectedStatus: expected,
		ExpectedLifecycleVersion: acct.LifecycleVersion,
	})
	if err != nil {
		return operations.Operation{}, fmt.Errorf("api: marshal account payload: %w", err)
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:             kind,
		ParentID:         parentID,
		ConnectionID:     &acct.ConnectionID,
		AccountID:        &acct.ID,
		Payload:          payload,
		ActorType:        sess.ActorType(),
		ActorID:          sess.ActorID(),
		CorrelationID:    uuid.NewString(),
		RequiresApproval: requiresApproval,
	})
	if err != nil {
		return operations.Operation{}, err
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return operations.Operation{}, err
	}
	return op, nil
}

// principalStatusChild — дочерняя операция каскада disable/enable в ответе.
type principalStatusChild struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	AccountID    uuid.UUID `json:"account_id"`
	OperationID  uuid.UUID `json:"operation_id"`
}

// setPrincipalStatusMetadataOnly — прежнее metadata-only поведение
// disable/enable для принципала без каскадных целей: SetStatus и
// audit-событие в одной транзакции, в ответ 200 — обновлённый принципал.
func (s *Server) setPrincipalStatusMetadataOnly(w http.ResponseWriter, r *http.Request, sess auth.Session,
	id uuid.UUID, status principals.Status, auditAction string) {
	ctx := r.Context()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	p, err := s.principals.SetStatus(ctx, tx, id, status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditAction,
		PrincipalID: &p.ID,
		Result:      audit.ResultSuccess,
	}, map[string]any{
		"display_name": p.DisplayName,
		"status":       string(p.Status),
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit principal status: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, toPrincipalJSON(p))
}

// setPrincipalStatus — общий обработчик enable/disable с обратимым
// каскадом по managed-аккаунтам принципала: статус принципала меняется и
// вместе с ним создаётся bulk parent (bulkKind) с дочерними
// account.disable/account.enable для каждого managed-аккаунта не в целевом
// статусе — во всех connections единообразно (children идут через общий
// operation-механизм и одинаково исполняются в direct- и connector-режимах).
// Vault и bindings не затрагиваются: каскад обратим симметричным вызовом.
// Без каскадных целей поведение прежнее (metadata-only, 200); с целями —
// 202 с прежними полями принципала плюс operation_id/children.
func (s *Server) setPrincipalStatus(w http.ResponseWriter, r *http.Request, status principals.Status,
	accountTarget inventory.AccountStatus, bulkKind, accountKind, auditAction string) {
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
	// Deleted-принципал — tombstone: статус не меняется.
	if msg := principalStatusBlocks(p.Status, false); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}

	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	targets := cascadeStatusTargets(accounts, accountTarget)
	// Scope: operator каскадом трогает connections — каждое затронутое
	// должно быть в его окружениях (дедупликация по connection_id, как в
	// bulk grant). Отказ по любому — 403 на весь запрос.
	seen := map[uuid.UUID]bool{}
	for i := range targets {
		connID := targets[i].ConnectionID
		if seen[connID] {
			continue
		}
		seen[connID] = true
		if err := s.checkConnectionScopeByID(ctx, sess, connID); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
	}
	if len(targets) == 0 {
		s.setPrincipalStatusMetadataOnly(w, r, sess, id, status, auditAction)
		return
	}

	// extra заполняется полями обновлённого принципала внутри buildChildren
	// (map — ссылочный тип, runBulkParent читает его после Commit).
	extra := map[string]any{}
	s.runBulkParent(w, r, sess, bulkParent{
		kind:             bulkKind,
		principalID:      &p.ID,
		payload:          map[string]any{"status": string(status), "accounts": len(targets)},
		payloadErrPrefix: "api: marshal principal status payload",
		auditAction:      auditAction,
		commitErrPrefix:  "api: commit principal status",
		extraResponse:    extra,
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		updated, err := s.principals.SetStatus(ctx, tx, id, status)
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

		out := make([]principalStatusChild, 0, len(targets))
		for i := range targets {
			op, err := s.enqueueAccountChildTx(r, tx, sess, targets[i], accountKind, &parentID, false, "")
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, principalStatusChild{
				ConnectionID: targets[i].ConnectionID,
				AccountID:    targets[i].ID,
				OperationID:  op.ID,
			})
		}
		return out, map[string]any{
			"display_name": updated.DisplayName,
			"status":       string(updated.Status),
			"accounts":     len(out),
		}, true
	})
}

// disablePrincipal — POST /api/v1/principals/{id}/disable (operator):
// выключает принципала и каскадно ставит account.disable для каждого его
// managed-аккаунта не в статусе disabled. Vault и bindings не трогаются —
// каскад обратим enable. Без managed-аккаунтов — прежнее metadata-only
// поведение (200).
func (s *Server) disablePrincipal(w http.ResponseWriter, r *http.Request) {
	s.setPrincipalStatus(w, r, principals.StatusDisabled, inventory.AccountDisabled,
		jobs.KindBulkPrincipalDisable, jobs.KindAccountDisable, auditActionPrincipalDisabled)
}

// enablePrincipal — POST /api/v1/principals/{id}/enable (operator):
// симметричный каскад — account.enable для managed-выключенных аккаунтов
// принципала.
func (s *Server) enablePrincipal(w http.ResponseWriter, r *http.Request) {
	s.setPrincipalStatus(w, r, principals.StatusActive, inventory.AccountActive,
		jobs.KindBulkPrincipalEnable, jobs.KindAccountEnable, auditActionPrincipalEnabled)
}

// linkAccountRequest — тело POST /api/v1/accounts/{id}/link.
type linkAccountRequest struct {
	PrincipalID uuid.UUID `json:"principal_id"`
}

// linkAccount — POST /api/v1/accounts/{id}/link (operator): привязка
// учётной записи к принципалу. Работает и для unmanaged-аккаунтов:
// привязка — метаданные control plane, целевая система не меняется.
// Привязка к offboarded-принципалу (tombstone deleted) — 409.
func (s *Server) linkAccount(w http.ResponseWriter, r *http.Request) {
	var req linkAccountRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.PrincipalID == uuid.Nil {
		respondError(w, http.StatusBadRequest, "principal_id is required")
		return
	}
	p, err := s.principals.Get(r.Context(), s.pool, req.PrincipalID)
	if err != nil {
		respondStoreError(r.Context(), w, err)
		return
	}
	if msg := principalStatusBlocks(p.Status, false); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}
	s.setAccountPrincipal(w, r, &req.PrincipalID, auditActionAccountLinked)
}

// unlinkAccount — POST /api/v1/accounts/{id}/unlink (operator): снятие
// привязки учётной записи.
func (s *Server) unlinkAccount(w http.ResponseWriter, r *http.Request) {
	s.setAccountPrincipal(w, r, nil, auditActionAccountUnlinked)
}

// setAccountPrincipal выполняет привязку/отвязку и audit-событие в одной
// транзакции; отвечает обновлённой учётной записью. В audit-событие
// отвязки попадает прежний принципал.
func (s *Server) setAccountPrincipal(w http.ResponseWriter, r *http.Request, principalID *uuid.UUID, auditAction string) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, _, err := lockAccountLifecycleSnapshot(ctx, tx, id, nil, true); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	// Строку читаем всегда (под уже взятым row lock): прежний принципал нужен
	// audit-событию отвязки, а прежний vault_path — чтобы зафиксировать факт
	// сброса указателя на общий секрет.
	current, err := s.inventory.GetAccount(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	auditPrincipalID := principalID
	if auditPrincipalID == nil {
		auditPrincipalID = current.PrincipalID
	}

	acct, err := s.inventory.LinkAccountPrincipal(ctx, tx, id, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	meta := map[string]any{"engine_identity": acct.EngineIdentity}
	if auditPrincipalID != nil {
		meta["principal_id"] = *auditPrincipalID
	}
	// Сброс указателя на общий секрет прежнего принципала — событие, которое
	// обязано быть видно оператору: на целевой системе аккаунт продолжает
	// работать с текущим паролем, но grantor больше не знает его значения,
	// и вернуть контроль можно ротацией. Флаг несекретен (сам путь в audit
	// не пишем).
	if current.VaultPath != "" && acct.VaultPath == "" {
		meta["credential_reference_cleared"] = true
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditAction,
		ConnectionID: &acct.ConnectionID,
		PrincipalID:  auditPrincipalID,
		AccountID:    &acct.ID,
		Result:       audit.ResultSuccess,
	}, meta); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit account principal link: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, toAccountJSON(acct))
}
