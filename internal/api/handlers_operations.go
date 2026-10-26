package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// auditActionOperationRetryRequested — audit-событие ручного retry
// неуспешных детей bulk-операции (POST /operations/{id}/retry).
const auditActionOperationRetryRequested = "operation.retry_requested"

// auditActionOperationResolved records operator acknowledgement of an
// unsuccessful operation. The execution status/error remain unchanged.
const auditActionOperationResolved = "operation.resolved"

// operationJSON — представление операции в ответах API. Payload/plan/
// result хранятся sanitized (см. internal/core/operations) и отдаются
// как есть. Children заполняется только в detail-ответе.
type operationJSON struct {
	RetryPending   *bool           `json:"retry_pending,omitempty"`
	ID             uuid.UUID       `json:"id"`
	ParentID       *uuid.UUID      `json:"parent_id"`
	IdempotencyKey *string         `json:"idempotency_key"`
	Kind           string          `json:"kind"`
	Status         string          `json:"status"`
	ConnectionID   *uuid.UUID      `json:"connection_id"`
	PrincipalID    *uuid.UUID      `json:"principal_id"`
	AccountID      *uuid.UUID      `json:"account_id"`
	ResourceID     *uuid.UUID      `json:"resource_id"`
	BindingID      *uuid.UUID      `json:"binding_id"`
	Payload        json.RawMessage `json:"payload"`
	Plan           json.RawMessage `json:"plan,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	Error          string          `json:"error"`
	ActorType      string          `json:"actor_type"`
	ActorID        string          `json:"actor_id"`
	ApprovedBy     *string         `json:"approved_by"`
	ApprovedAt     *time.Time      `json:"approved_at"`
	DecisionReason string          `json:"decision_reason,omitempty"`
	CorrelationID  string          `json:"correlation_id"`
	CreatedAt      time.Time       `json:"created_at"`
	StartedAt      *time.Time      `json:"started_at"`
	FinishedAt     *time.Time      `json:"finished_at"`
	ResolvedAt     *time.Time      `json:"resolved_at"`
	ResolvedBy     *string         `json:"resolved_by"`
	UpdatedAt      time.Time       `json:"updated_at"`
	Children       []operationJSON `json:"children,omitempty"`
	// AggregateStatus — вычисленный сводный статус bulk parent по
	// статусам дочерних операций (раздел 19.1 архитектуры); заполняется
	// только в detail-ответе операции с children.
	AggregateStatus string `json:"aggregate_status,omitempty"`
	// Retryable is server truth for security-sensitive root operations. Nil
	// preserves the legacy contract for ordinary/bulk kinds.
	Retryable            *bool                     `json:"retryable,omitempty"`
	DatabaseProvisioning *databaseProvisioningJSON `json:"database_provisioning,omitempty"`
}

// aggregateStatus вычисляет сводный статус parent-операции по статусам
// дочерних — семантика operations.AggregateChildren (раздел 19.1
// архитектуры): все success — success; все завершились, но часть неудачно
// (failed/cancelled/partial) — partial при наличии успешных и failed без
// них; иначе выполнение продолжается — running. Пустой список — пустая
// строка: агрегировать нечего.
//
// Тот же итог теперь финализируется и в базе: при завершении последнего
// ребёнка parent транзакционно переходит running -> success | partial |
// failed (operations.Store.FinalizeParent), поэтому список операций
// показывает честный статус из строки. Поле aggregate_status detail-ответа
// сохранено для совместимости контракта и по-прежнему вычисляется на
// чтении.
func aggregateStatus(children []operations.Status) string {
	return string(operations.AggregateChildren(children))
}

// operationListResponse — тело ответа GET /api/v1/operations.
type operationListResponse struct {
	Operations []operationJSON `json:"operations"`
	// Total — точное число строк с теми же фильтрами, но без limit/offset.
	Total *int64 `json:"total,omitempty"`
	// StatusTotals — размеры вкладок с теми же connection/kind/time
	// предикатами, но без status-фильтра текущей вкладки. Как и Total,
	// считает durable operation rows, включая children bulk-операций;
	// группировка family — только представление UI, не сущность пагинации.
	StatusTotals *operationStatusTotalsJSON `json:"status_totals,omitempty"`
}

type operationStatusTotalsJSON struct {
	Active int64 `json:"active"`
	Errors int64 `json:"errors"`
	All    int64 `json:"all"`
}

// toOperationJSON собирает operationJSON из доменной модели.
func toOperationJSON(op operations.Operation) operationJSON {
	return operationJSON{
		ID:             op.ID,
		ParentID:       op.ParentID,
		IdempotencyKey: op.IdempotencyKey,
		Kind:           op.Kind,
		Status:         string(op.Status),
		ConnectionID:   op.ConnectionID,
		PrincipalID:    op.PrincipalID,
		AccountID:      op.AccountID,
		ResourceID:     op.ResourceID,
		BindingID:      op.BindingID,
		Payload:        rawOrEmptyObject(op.Payload),
		Plan:           json.RawMessage(op.Plan),
		Result:         json.RawMessage(op.Result),
		Error:          op.Error,
		ActorType:      op.ActorType,
		ActorID:        op.ActorID,
		ApprovedBy:     op.ApprovedBy,
		ApprovedAt:     op.ApprovedAt,
		DecisionReason: op.DecisionReason,
		CorrelationID:  op.CorrelationID,
		CreatedAt:      op.CreatedAt,
		StartedAt:      op.StartedAt,
		FinishedAt:     op.FinishedAt,
		ResolvedAt:     op.ResolvedAt,
		ResolvedBy:     op.ResolvedBy,
		UpdatedAt:      op.UpdatedAt,
	}
}

func isAdminCredentialOperationKind(kind string) bool {
	return kind == jobs.KindConnectionAdminCredentialSwitch ||
		kind == jobs.KindConnectionAdminCredentialRotate
}

func (s *Server) decorateOperationRetryable(ctx context.Context, out *operationJSON,
	op operations.Operation) error {
	if op.Kind == jobs.KindPostgresAccountProvisionV1 || op.Kind == jobs.KindPostgresAccountVerifyCreationV1 {
		canRetry, err := accountCreationRetryAllowed(ctx, s.pool, op)
		if err != nil {
			return err
		}
		canRetry = canRetry && op.Status == operations.StatusFailed
		out.Retryable = &canRetry
		return nil
	}
	if op.Kind == jobs.KindDatabaseCreateWithRoles || op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 {
		return s.decorateLegacyDatabaseProvisioning(ctx, out, op)
	}
	if !isAdminCredentialOperationKind(op.Kind) {
		return nil
	}
	change, err := s.adminCredentialChanges.Get(ctx, s.pool, op.ID)
	if err != nil {
		return err
	}
	retryable := op.Status == operations.StatusFailed && change.Retryable()
	out.Retryable = &retryable
	return nil
}

// splitCSVParam разбирает CSV query-параметр в список непустых значений
// с обрезкой пробелов. Пустой параметр — nil (условие не задано).
func splitCSVParam(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parseStatusesParam разбирает CSV-значение query-параметра status в
// список статусов операций с валидацией по перечислению
// operations.Status: неизвестный статус — ошибка 400, а не пустая выборка
// (опечатка в фильтре не должна маскироваться под «операций нет»).
func parseStatusesParam(raw string) ([]operations.Status, error) {
	valid := map[operations.Status]bool{
		operations.StatusPendingApproval: true,
		operations.StatusPending:         true,
		operations.StatusRunning:         true,
		operations.StatusSuccess:         true,
		operations.StatusPartial:         true,
		operations.StatusFailed:          true,
		operations.StatusCancelled:       true,
	}
	var statuses []operations.Status
	for _, item := range splitCSVParam(raw) {
		st := operations.Status(item)
		if !valid[st] {
			return nil, fmt.Errorf("invalid status: unknown value %q", item)
		}
		statuses = append(statuses, st)
	}
	return statuses, nil
}

// parseRFC3339Param разбирает необязательную временную границу. Формат
// намеренно строгий: дата без времени, локальное время без offset и строки с
// пробелами не принимаются, чтобы сервер не угадывал timezone клиента.
func parseRFC3339Param(r *http.Request, name string) (*time.Time, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return nil, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: expected RFC3339 timestamp", name)
	}
	return &value, nil
}

func validateOperationsTimeRange(createdFrom, createdBefore *time.Time) error {
	if createdFrom != nil && createdBefore != nil && !createdFrom.Before(*createdBefore) {
		return errors.New("invalid time range: created_before must be after created_from")
	}
	return nil
}

// listOperations — GET
// /api/v1/operations?connection_id&status&kind&actor_type&top_level_only&unresolved_only&created_from&created_before&limit&offset (viewer):
// операции от новых к старым. status и kind — CSV-списки (любой из
// перечисленных): status фильтрует вкладки UI («Активные» —
// pending,pending_approval,running; «Ошибки» — failed,partial,cancelled),
// kind — конкретные виды операций. created_from включителен, created_before
// исключителен; обе границы — RFC3339 с явным timezone. Bulk-parent с выполняющимися детьми
// живёт в running (финализация в базе, см. Store.FinalizeParent), поэтому
// выборка активных статусов включает и таких родителей.
func (s *Server) listOperations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connectionID, err := queryUUID(r, "connection_id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	statuses, err := parseStatusesParam(r.URL.Query().Get("status"))
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	kinds := splitCSVParam(r.URL.Query().Get("kind"))
	actorTypes := splitCSVParam(r.URL.Query().Get("actor_type"))
	topLevelOnly := false
	switch r.URL.Query().Get("top_level_only") {
	case "", "false":
	case "true":
		topLevelOnly = true
	default:
		respondError(w, http.StatusBadRequest, "invalid top_level_only: expected true or false")
		return
	}
	unresolvedOnly := false
	switch r.URL.Query().Get("unresolved_only") {
	case "", "false":
	case "true":
		unresolvedOnly = true
	default:
		respondError(w, http.StatusBadRequest, "invalid unresolved_only: expected true or false")
		return
	}
	createdFrom, err := parseRFC3339Param(r, "created_from")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	createdBefore, err := parseRFC3339Param(r, "created_before")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateOperationsTimeRange(createdFrom, createdBefore); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
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
	if connectionID != nil && s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, *connectionID)) {
		return
	}
	readScope, err := s.readScope(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	// Count и page должны описывать один snapshot: между двумя SELECT может
	// завершиться новая операция, поэтому обычный READ COMMITTED дал бы
	// несогласованные total/rows. Read-only REPEATABLE READ фиксирует snapshot
	// первым SELECT и не блокирует writers.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("operations: begin list snapshot: %w", err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	ops, total, err := s.operations.ListPage(ctx, tx, operations.Filter{
		ReadScope:      readScope,
		ConnectionID:   connectionID,
		TopLevelOnly:   topLevelOnly,
		Statuses:       statuses,
		Kinds:          kinds,
		ActorTypes:     actorTypes,
		CreatedFrom:    createdFrom,
		CreatedBefore:  createdBefore,
		UnresolvedOnly: unresolvedOnly,
		Limit:          limit,
		Offset:         offset,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	statusTotals, err := s.operations.CountStatusTotals(ctx, tx, operations.Filter{
		ReadScope:     readScope,
		ConnectionID:  connectionID,
		TopLevelOnly:  topLevelOnly,
		Kinds:         kinds,
		ActorTypes:    actorTypes,
		CreatedFrom:   createdFrom,
		CreatedBefore: createdBefore,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("operations: commit list snapshot: %w", err))
		return
	}

	out := make([]operationJSON, 0, len(ops))
	for i := range ops {
		item := toOperationJSON(ops[i])
		if err := s.decorateOperationRetryable(ctx, &item, ops[i]); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		out = append(out, item)
	}
	respondJSON(w, http.StatusOK, operationListResponse{
		Operations: out,
		Total:      &total,
		StatusTotals: &operationStatusTotalsJSON{
			Active: statusTotals.Active,
			Errors: statusTotals.Errors,
			All:    statusTotals.All,
		},
	})
}

// resolveOperation — POST /api/v1/operations/{id}/resolve (operator): marks
// a failed/partial/cancelled incident as handled. It does not mutate the
// execution outcome and therefore remains visible in the complete history.
func (s *Server) resolveOperation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	op, err := s.operations.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkOperationReadScope(ctx, sess, id)) {
		return
	}
	if op.ResolvedAt != nil {
		respondJSON(w, http.StatusOK, toOperationJSON(op))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	resolved, resolvedNow, err := s.operations.Resolve(ctx, tx, id, sess.ActorID())
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if resolvedNow {
		if err := s.writeAudit(ctx, tx, audit.Event{
			ActorType:    sess.ActorType(),
			ActorID:      sess.ActorID(),
			Action:       auditActionOperationResolved,
			ConnectionID: op.ConnectionID,
			PrincipalID:  op.PrincipalID,
			AccountID:    op.AccountID,
			OperationID:  &op.ID,
			Result:       audit.ResultSuccess,
		}, map[string]any{
			"operation_kind":   op.Kind,
			"operation_status": op.Status,
		}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, toOperationJSON(resolved))
}

// getOperation — GET /api/v1/operations/{id} (viewer): операция с
// дочерними операциями (bulk parent, раздел 19.1 архитектуры).
func (s *Server) getOperation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	op, err := s.operations.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	children, err := s.operations.ListByParent(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if err := s.checkOperationReadScope(ctx, sess, id); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	retryPending, err := operationRetryPending(ctx, s.pool, op, children)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := toOperationJSON(op)
	out.RetryPending = &retryPending
	if err := s.decorateOperationRetryable(ctx, &out, op); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	statuses := make([]operations.Status, 0, len(children))
	for i := range children {
		out.Children = append(out.Children, toOperationJSON(children[i]))
		statuses = append(statuses, children[i].Status)
	}
	out.AggregateStatus = aggregateStatus(statuses)
	if op.Kind == jobs.KindDatabaseCreateWithRoles || op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 {
		// Inline child completion is stage progress, not completion of the
		// whole workflow. Only the root's durable status is authoritative.
		out.AggregateStatus = string(op.Status)
		for i := range out.Children {
			retryable := false
			out.Children[i].Retryable = &retryable
		}
	}
	respondJSON(w, http.StatusOK, out)
}

// retryableChildren отбирает детей, подлежащих ручному retry: только
// failed. cancelled ретраю не подлежит — статус терминален по state
// machine (перехода cancelled -> pending нет), а отклонённый admin'ом
// (reject) ребёнок не должен вернуться в работу в обход approval-гейта.
// Чистая функция для юнит-тестов.
func retryableChildren(children []operations.Operation) []operations.Operation {
	var failed []operations.Operation
	for i := range children {
		if children[i].Status == operations.StatusFailed {
			failed = append(failed, children[i])
		}
	}
	return failed
}

func isRolePolicyOperationKind(kind string) bool {
	switch kind {
	case jobs.KindRolePolicyApply, jobs.KindRolePolicyAdopt, jobs.KindRolePolicyRepair, jobs.KindRolePolicyCreate,
		jobs.KindPostgresRolePolicyApplyV2, jobs.KindPostgresRolePolicyAdoptV2,
		jobs.KindPostgresRolePolicyRepairV2, jobs.KindPostgresRolePolicyCreateV2,
		jobs.KindPostgresRolePolicyCreateDatabaseV2:
		return true
	default:
		return false
	}
}

func isAccountCreationOperationKind(kind string) bool {
	switch kind {
	case jobs.KindAccountCreate, jobs.KindRoleCreate,
		jobs.KindPostgresAccountCreateV2, jobs.KindPostgresAccountProvisionV1, jobs.KindPostgresAccountVerifyCreationV1, jobs.KindPostgresRoleCreateV2:
		return true
	default:
		return false
	}
}

func isPostgresV2RetryOperationKind(kind string) bool {
	switch kind {
	case jobs.KindPostgresAccountCreateV2, jobs.KindPostgresAccountProvisionV1, jobs.KindPostgresAccountVerifyCreationV1, jobs.KindPostgresRoleCreateV2,
		jobs.KindPostgresDatabaseCreateWithRolesV2,
		jobs.KindPostgresRolePolicyApplyV2, jobs.KindPostgresRolePolicyAdoptV2,
		jobs.KindPostgresRolePolicyRepairV2, jobs.KindPostgresRolePolicyCreateV2:
		return true
	default:
		return false
	}
}

func validatePostgresV2RetryIntent(conn connections.Connection, op operations.Operation,
	databaseCreated, databaseCatalogFrozen bool,
) error {
	var expectedAdmin, expectedTarget, expectedConfig, expectedCatalog string
	var expectedCredential int
	var required []adapter.Capability
	switch op.Kind {
	case jobs.KindPostgresAccountCreateV2, jobs.KindPostgresAccountProvisionV1, jobs.KindPostgresAccountVerifyCreationV1:
		var payload jobs.AccountPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return err
		}
		expectedAdmin, expectedTarget = payload.ExpectedAdminIdentity, payload.ExpectedTargetIdentity
		expectedConfig, expectedCredential = payload.ExpectedConfigIncarnation, payload.ExpectedCredentialIncarnation
		required = []adapter.Capability{adapter.CapAccountCreate}
	case jobs.KindPostgresRoleCreateV2:
		var payload jobs.AccountPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return err
		}
		expectedAdmin, expectedTarget = payload.ExpectedAdminIdentity, payload.ExpectedTargetIdentity
		expectedConfig, expectedCredential = payload.ExpectedConfigIncarnation, payload.ExpectedCredentialIncarnation
		required = []adapter.Capability{adapter.CapRoleCreate}
	case jobs.KindPostgresDatabaseCreateWithRolesV2:
		var payload jobs.DatabaseCreateWithRolesPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return err
		}
		expectedAdmin, expectedTarget = payload.ExpectedAdminIdentity, payload.ExpectedTargetIdentity
		expectedConfig, expectedCredential = payload.ExpectedConfigIncarnation, payload.ExpectedCredentialIncarnation
		expectedCatalog = payload.ExpectedCatalogFingerprint
		required = []adapter.Capability{adapter.ResourceCapability("create", resourceKindDatabase), adapter.CapRolePolicyCreate}
		if databaseCreated && databaseCatalogFrozen {
			// The workflow itself appends the frozen pair to discovery_config
			// after CREATE; child policies carry the new config/catalog pins.
			expectedConfig, expectedCatalog = "", ""
			required = []adapter.Capability{adapter.CapRolePolicyCreate}
		}
	default:
		var payload jobs.RolePolicyPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return err
		}
		expectedAdmin, expectedTarget = payload.ExpectedAdminIdentity, payload.ExpectedTargetIdentity
		expectedConfig, expectedCredential = payload.ExpectedConfigIncarnation, payload.ExpectedCredentialIncarnation
		expectedCatalog = payload.ExpectedCatalogFingerprint
		capability := adapter.CapRolePolicyApply
		if op.Kind == jobs.KindPostgresRolePolicyCreateV2 {
			capability = adapter.CapRolePolicyCreate
		}
		required = []adapter.Capability{capability}
	}
	pins, err := requirePostgresProvisioningAuthority(conn, required...)
	if err != nil || expectedAdmin != pins.AdminIdentity || expectedTarget != pins.TargetIdentity ||
		(expectedConfig != "" && expectedConfig != pins.ConfigIncarnation) || expectedCredential != pins.CredentialIncarnation ||
		(expectedCatalog != "" && expectedCatalog != pins.CatalogFingerprint) {
		return errors.New("PostgreSQL provisioning authority or pinned target changed; start a fresh operation")
	}
	return nil
}

func (s *Server) legacyPostgresOperationForRetry(ctx context.Context, op operations.Operation) (bool, error) {
	switch op.Kind {
	case jobs.KindResourceCreatePreparedDatabase, jobs.KindDatabaseCreateWithRoles,
		jobs.KindRolePolicyCreateDatabase:
		return true, nil
	case jobs.KindRolePolicyApply, jobs.KindRolePolicyAdopt, jobs.KindRolePolicyRepair, jobs.KindRolePolicyCreate:
		var payload jobs.RolePolicyPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return false, nil // established decoder owns malformed historical rows
		}
		return payload.Spec.Engine == "postgres", nil
	case jobs.KindAccountCreate, jobs.KindAccountRestore, jobs.KindRoleCreate, jobs.KindResourceCreateDatabase:
		if op.ConnectionID == nil {
			return false, nil
		}
		conn, err := s.connections.Get(ctx, s.pool, *op.ConnectionID)
		if err != nil {
			return false, err
		}
		return conn.Engine == "postgres", nil
	default:
		return false, nil
	}
}

// retryOperationResponse — тело ответа POST /operations/{id}/retry.
type retryOperationResponse struct {
	OperationID uuid.UUID `json:"operation_id"`
	// Retried — id детей, сброшенных в pending и поставленных в очередь.
	Retried []uuid.UUID `json:"retried"`
	// SkippedCancelled — id детей в cancelled, пропущенных retry (статус
	// терминален; отклонённые admin'ом не возвращаются в работу).
	SkippedCancelled []uuid.UUID `json:"skipped_cancelled"`
}

// retryOperation — POST /api/v1/operations/{id}/retry (operator): повторяет
// неуспешных детей bulk parent в статусе partial или failed. Каждый failed
// ребёнок сбрасывается failed -> pending (текст прошлой ошибки очищается) и
// заново ставится в очередь worker (свежий job — прежний исчерпал attempts
// River), затем parent оживает partial|failed -> pending -> running
// (Store.ReviveParent) — всё одной транзакцией. При завершении последнего
// ребёнка worker финализирует parent заново (Store.FinalizeParent).
//
// Гейты не обходятся: retryable — только failed дети (они уже прошли
// approval перед первым запуском), cancelled (в т.ч. отклонённые reject)
// пропускаются, pending_approval у финализированного parent существовать не
// может (все дети finished). Идемпотентность: повторный вызов на уже
// оживлённом (running) parent — 409 conflict; порядок «сначала переходы
// детей, затем parent» повторяет порядок блокировок worker (строка ребёнка
// -> строка parent), исключая взаимоблокировку с конкурентной финализацией.
func (s *Server) retryOperation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	op, err := s.operations.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if s.respondScopeError(ctx, w, s.checkOperationReadScope(ctx, sess, id)) {
		return
	}
	legacyPostgres, err := s.legacyPostgresOperationForRetry(ctx, op)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if legacyPostgres {
		respondError(w, http.StatusConflict,
			"legacy PostgreSQL operation is history-only; start a new SUPERUSER-direct operation")
		return
	}
	if op.ParentID != nil {
		parent, err := s.operations.Get(ctx, s.pool, *op.ParentID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if parent.Kind == jobs.KindDatabaseCreateWithRoles {
			respondError(w, http.StatusConflict,
				"legacy PostgreSQL database workflow is history-only; start a new SUPERUSER-direct operation")
			return
		}
		if parent.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 {
			respondError(w, http.StatusConflict,
				"retry the PostgreSQL database workflow root; inline child operations cannot run independently")
			return
		}
	}
	if op.Status != operations.StatusPartial && op.Status != operations.StatusFailed {
		respondError(w, http.StatusConflict,
			"operation is not retryable (status "+string(op.Status)+"; want partial or failed)")
		return
	}
	children, err := s.operations.ListByParent(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	rootRetry := op.Status == operations.StatusFailed &&
		(isRolePolicyOperationKind(op.Kind) || isAdminCredentialOperationKind(op.Kind) ||
			isAccountCreationOperationKind(op.Kind) || op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2)
	if len(children) == 0 && !rootRetry {
		respondError(w, http.StatusConflict, "operation has no children to retry")
		return
	}
	failed := retryableChildren(children)
	if rootRetry {
		failed = []operations.Operation{op}
	}
	if len(failed) == 0 {
		respondError(w, http.StatusConflict, "operation has no failed children to retry")
		return
	}
	if op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden, "retrying PostgreSQL database provisioning requires admin role")
		return
	}
	for i := range failed {
		if (isRolePolicyOperationKind(failed[i].Kind) || isAdminCredentialOperationKind(failed[i].Kind)) &&
			!sess.Role.Allows(auth.RoleAdmin) {
			respondError(w, http.StatusForbidden, "retrying this operation requires admin role")
			return
		}
	}
	var credentialChange *admincredentials.Change
	if rootRetry && isAdminCredentialOperationKind(op.Kind) {
		change, err := s.adminCredentialChanges.Get(ctx, s.pool, op.ID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if !change.Retryable() {
			respondError(w, http.StatusConflict, "admin credential operation is not safely retryable")
			return
		}
		credentialChange = &change
	}

	// Scope-проверки — как у соседних мутаций: operator должен иметь доступ
	// ко всем окружениям connections ретраящихся детей (у самого parent
	// connection_id обычно нет).
	checkedConns := map[uuid.UUID]bool{}
	for i := range failed {
		connID := failed[i].ConnectionID
		if connID == nil || checkedConns[*connID] {
			continue
		}
		if err := s.checkConnectionScopeByID(ctx, sess, *connID); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
		checkedConns[*connID] = true
	}

	skippedCancelled := make([]uuid.UUID, 0, len(children))
	for i := range children {
		if children[i].Status == operations.StatusCancelled {
			skippedCancelled = append(skippedCancelled, children[i].ID)
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Creation retries and metadata-only recovery share the same lock order:
	// connection(s), account, operation. A failed CREATE must not be revived
	// while a recovery snapshot is about to release its reservation.
	creationConnections := make([]uuid.UUID, 0)
	for i := range failed {
		if !isAccountCreationOperationKind(failed[i].Kind) &&
			!isPostgresV2RetryOperationKind(failed[i].Kind) {
			continue
		}
		if failed[i].ConnectionID == nil {
			respondError(w, http.StatusConflict, "creation operation has no connection")
			return
		}
		if !slices.Contains(creationConnections, *failed[i].ConnectionID) {
			creationConnections = append(creationConnections, *failed[i].ConnectionID)
		}
	}
	slices.SortFunc(creationConnections, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	for _, connID := range creationConnections {
		locked, err := locks.TryAcquireTx(ctx, tx, connID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if !locked {
			respondError(w, http.StatusConflict, "connection operation is running; retry after it finishes")
			return
		}
		conn, err := s.connections.Get(ctx, tx, connID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if conn.Status != connections.StatusActive {
			respondError(w, http.StatusConflict, "creation retry requires an active connection")
			return
		}
		for _, candidate := range failed {
			if candidate.ConnectionID == nil || *candidate.ConnectionID != connID ||
				!isPostgresV2RetryOperationKind(candidate.Kind) {
				continue
			}
			databaseCreated, databaseCatalogFrozen := false, false
			if candidate.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 {
				journal, err := databaseprovisioning.NewStore().Get(ctx, tx, candidate.ID)
				if err != nil {
					respondStoreError(ctx, w, err)
					return
				}
				if journal.DatabaseCreateStarted && !journal.DatabaseCreated {
					respondError(w, http.StatusConflict,
						"database creation outcome is unconfirmed; automatic retry is disabled")
					return
				}
				var payload jobs.DatabaseCreateWithRolesPayload
				if err := json.Unmarshal(candidate.Payload, &payload); err != nil ||
					(journal.DatabaseCreated && (journal.DatabaseOwner != payload.ExpectedDatabaseOwner ||
						journal.DatabaseOwnerOID != payload.ExpectedDatabaseOwnerOID ||
						journal.TargetIdentity != payload.ExpectedTargetIdentity)) {
					respondError(w, http.StatusConflict, "database provisioning receipt no longer matches its pinned intent")
					return
				}
				databaseCreated = journal.DatabaseCreated
				databaseCatalogFrozen = journal.Phase != "database_created"
			}
			if err := validatePostgresV2RetryIntent(conn, candidate, databaseCreated, databaseCatalogFrozen); err != nil {
				respondError(w, http.StatusConflict, err.Error())
				return
			}
		}
		for _, candidate := range failed {
			if candidate.ConnectionID != nil && *candidate.ConnectionID == connID &&
				(candidate.Kind == jobs.KindRoleCreate || candidate.Kind == jobs.KindPostgresRoleCreateV2) &&
				roleCreationRequiresAdmin(conn.Engine) && !sess.Role.Allows(auth.RoleAdmin) {
				respondError(w, http.StatusForbidden, "creating bare database roles requires admin; operators may only assign managed roles")
				return
			}
		}
	}
	if credentialChange != nil {
		if err := locks.AcquireTx(ctx, tx, credentialChange.ConnectionID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		current, err := s.adminCredentialChanges.Get(ctx, tx, credentialChange.OperationID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if !current.Retryable() {
			respondError(w, http.StatusConflict, "admin credential operation changed concurrently; reload current state")
			return
		}
		if _, err := s.adminCredentialChanges.SetPhase(ctx, tx, current.OperationID,
			current.Phase, current.TargetSideEffectPossible, ""); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}
	if rootRetry && op.Kind == jobs.KindPostgresDatabaseCreateWithRolesV2 {
		for i := range children {
			if children[i].Status != operations.StatusFailed ||
				children[i].Kind != jobs.KindPostgresRolePolicyCreateDatabaseV2 {
				continue
			}
			// Inline children are not enqueued independently, but an exhausted
			// River attempt released their role-policy transition. Re-arm that
			// exact owner before the root is made pending; a concurrent takeover
			// fails closed here and rolls the whole retry back.
			if err := rolepolicies.NewStore().MarkRetryPending(ctx, tx, children[i].ID); err != nil {
				s.respondRolePolicyError(ctx, w, err)
				return
			}
		}
	}

	retried := make([]uuid.UUID, 0, len(failed))
	for i := range failed {
		// Recovery can release a failed CREATE reservation without deleting
		// its history. Lock the account before the operation, as recovery
		// does, and reject retries from that abandoned lifecycle generation.
		if isAccountCreationOperationKind(failed[i].Kind) {
			var payload jobs.AccountPayload
			if err := json.Unmarshal(failed[i].Payload, &payload); err != nil || payload.AccountID == uuid.Nil {
				respondError(w, http.StatusConflict, "creation operation has an invalid account lifecycle")
				return
			}
			var current inventory.Account
			if err := tx.QueryRow(ctx, `select status, lifecycle_version from accounts where id=$1 for update`, payload.AccountID).
				Scan(&current.Status, &current.LifecycleVersion); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
			current.ID = payload.AccountID
			if err := inventory.CheckAccountLifecycle(current, "", payload.ExpectedLifecycleVersion); err != nil {
				respondError(w, http.StatusConflict, "creation was superseded by account recovery or another lifecycle; it cannot be retried")
				return
			}
			var busy bool
			if err := tx.QueryRow(ctx, `select exists (
				select 1 from operations where account_id=$1 and status in ('pending_approval','pending','running')
			) or exists (
				select 1 from river_job j join operations o on
					j.args->>'operation_id'=o.id::text or (j.args->'next_operation_ids') ? o.id::text
				where o.account_id=$1 and j.state not in ('completed','cancelled','discarded')
			)`, payload.AccountID).Scan(&busy); err != nil {
				respondStoreError(ctx, w, err)
				return
			}
			if busy {
				respondError(w, http.StatusConflict, "account operation or automatic retry is still running")
				return
			}
		}
		if failed[i].Kind == jobs.KindPostgresAccountProvisionV1 || failed[i].Kind == jobs.KindPostgresAccountVerifyCreationV1 {
			allowed, err := accountCreationRetryAllowed(ctx, tx, failed[i])
			if err != nil {
				respondStoreError(ctx, w, err)
				return
			}
			if !allowed {
				respondError(w, http.StatusConflict, "account creation has no confirmed result to resume")
				return
			}
		}
		// Guard `status = failed` закрывает гонки: если ребёнка уже сбросил
		// конкурентный retry (или redelivery job в worker), придёт
		// ErrStatusConflict -> 409, транзакция откатится целиком.
		if _, err := s.operations.Transition(ctx, tx, failed[i].ID,
			operations.StatusFailed, operations.StatusPending, operations.TransitionOpts{}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if isRolePolicyOperationKind(failed[i].Kind) {
			if err := rolepolicies.NewStore().MarkRetryPending(ctx, tx, failed[i].ID); err != nil {
				s.respondRolePolicyError(ctx, w, err)
				return
			}
		}
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, failed[i].ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		retried = append(retried, failed[i].ID)
	}

	// Parent оживает после переходов детей (см. порядок блокировок в
	// doc-комментарии). revived=false — конкурентный retry успел первым;
	// вся транзакция откатывается, вызывающий перечитает состояние.
	if !rootRetry {
		if _, revived, err := s.operations.ReviveParent(ctx, tx, id); err != nil {
			respondStoreError(ctx, w, err)
			return
		} else if !revived {
			respondError(w, http.StatusConflict,
				"operation was retried concurrently; reload current state")
			return
		}
	}

	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionOperationRetryRequested,
		PrincipalID: op.PrincipalID,
		OperationID: &op.ID,
		Result:      audit.ResultSuccess,
	}, map[string]any{
		"operation_kind":    op.Kind,
		"children_total":    len(children),
		"retried_count":     len(retried),
		"skipped_cancelled": len(skippedCancelled),
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, retryOperationResponse{
		OperationID:      id,
		Retried:          retried,
		SkippedCancelled: skippedCancelled,
	})
}
