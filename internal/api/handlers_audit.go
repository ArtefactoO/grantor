package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/audit"
)

// auditEventJSON — представление audit-события в ответах API. Metadata
// sanitized по контракту audit.Writer.
type auditEventJSON struct {
	ID           int64           `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ActorType    string          `json:"actor_type"`
	ActorID      string          `json:"actor_id"`
	Action       string          `json:"action"`
	ConnectionID *uuid.UUID      `json:"connection_id"`
	ResourceID   *uuid.UUID      `json:"resource_id"`
	PrincipalID  *uuid.UUID      `json:"principal_id"`
	AccountID    *uuid.UUID      `json:"account_id"`
	OperationID  *uuid.UUID      `json:"operation_id"`
	Result       string          `json:"result"`
	Metadata     json.RawMessage `json:"metadata"`
}

// auditListResponse — тело ответа GET /api/v1/audit. Total считается по
// фильтру без limit/offset: клиент по нему решает, есть ли ещё страница.
type auditListResponse struct {
	Events []auditEventJSON `json:"events"`
	Total  int64            `json:"total"`
}

// validateAuditRange проверяет границы окна событий; семантика та же, что у
// операций: occurred_from включителен, occurred_before исключителен.
func validateAuditRange(occurredFrom, occurredBefore *time.Time) error {
	if occurredFrom != nil && occurredBefore != nil && !occurredFrom.Before(*occurredBefore) {
		return errors.New("invalid time range: occurred_before must be after occurred_from")
	}
	return nil
}

// listAudit — GET
// /api/v1/audit?connection_id&operation_id&standalone&action&actor_id&occurred_from&occurred_before&limit&offset
// (viewer): audit trail от новых событий к старым. standalone=true оставляет
// только события вне операций — этим объединённая лента «Контроля» избегает
// показа одной операции дважды; operation_id, наоборот, собирает след
// конкретной операции для её детальной панели. Оба параметра вместе
// бессмысленны и отклоняются, чтобы фильтр не давал молча пустую выборку.
func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	connectionID, err := queryUUID(r, "connection_id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	operationID, err := queryUUID(r, "operation_id")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	standalone := false
	switch r.URL.Query().Get("standalone") {
	case "", "false":
	case "true":
		standalone = true
	default:
		respondError(w, http.StatusBadRequest, "invalid standalone: expected true or false")
		return
	}
	if standalone && operationID != nil {
		respondError(w, http.StatusBadRequest,
			"invalid filter: standalone and operation_id are mutually exclusive")
		return
	}
	occurredFrom, err := parseRFC3339Param(r, "occurred_from")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	occurredBefore, err := parseRFC3339Param(r, "occurred_before")
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateAuditRange(occurredFrom, occurredBefore); err != nil {
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
	if operationID != nil && s.respondScopeError(ctx, w, s.checkOperationReadScope(ctx, sess, *operationID)) {
		return
	}
	readScope, err := s.readScope(ctx, sess)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	filter := audit.Filter{
		ReadScope:      readScope,
		ConnectionID:   connectionID,
		OperationID:    operationID,
		Standalone:     standalone,
		Actions:        splitCSVParam(r.URL.Query().Get("action")),
		ActorID:        r.URL.Query().Get("actor_id"),
		OccurredFrom:   occurredFrom,
		OccurredBefore: occurredBefore,
	}

	// Страница и её total обязаны описывать один snapshot: между двумя SELECT
	// пишутся новые события, и обычный READ COMMITTED дал бы клиенту
	// несогласованную пару (как в listOperations).
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("audit: begin list snapshot: %w", err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	events, err := s.audit.List(ctx, tx, filter, limit, offset)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	total, err := s.audit.Count(ctx, tx, filter)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("audit: commit list snapshot: %w", err))
		return
	}

	out := make([]auditEventJSON, 0, len(events))
	for i := range events {
		e := &events[i]
		out = append(out, auditEventJSON{
			ID:           e.ID,
			OccurredAt:   e.OccurredAt,
			ActorType:    e.ActorType,
			ActorID:      e.ActorID,
			Action:       e.Action,
			ConnectionID: e.ConnectionID,
			ResourceID:   e.ResourceID,
			PrincipalID:  e.PrincipalID,
			AccountID:    e.AccountID,
			OperationID:  e.OperationID,
			Result:       e.Result,
			Metadata:     rawOrEmptyObject(e.Metadata),
		})
	}
	respondJSON(w, http.StatusOK, auditListResponse{Events: out, Total: total})
}
