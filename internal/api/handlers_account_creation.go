package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

var errAccountCreationUnresolved = fmt.Errorf("account creation is awaiting verification or result review; continue the existing creation: %w", inventory.ErrAccountLifecycleBusy)

func respondAccountCreationGuardError(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, errAccountCreationUnresolved) {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	respondStoreError(ctx, w, err)
}

// A repeated grant/manifest is a new request, not permission to replace an
// unresolved CREATE. Check before credential work or lifecycle reservation.
func guardAccountCreationReceipt(ctx context.Context, q inventory.Querier, id uuid.UUID) error {
	var unresolved bool
	if err := q.QueryRow(ctx, `select exists (select 1 from account_creation_receipts
  where account_id=$1 and phase in ('creating','created'))`, id).Scan(&unresolved); err != nil {
		return err
	}
	if unresolved {
		return errAccountCreationUnresolved
	}
	return nil
}

// A generic retry must not turn a lost CREATE acknowledgement into another
// CREATE. This check is repeated under the connection/account locks on POST.
func accountCreationRetryAllowed(ctx context.Context, q inventory.Querier, op operations.Operation) (bool, error) {
	var p jobs.AccountPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil {
		return false, nil
	}
	id := op.ID
	if op.Kind == jobs.KindPostgresAccountVerifyCreationV1 {
		id = p.CreationOperationID
		if id == uuid.Nil {
			return false, nil
		}
	}
	r, err := accountcreation.NewStore().Get(ctx, q, id)
	if errors.Is(err, accountcreation.ErrNotFound) {
		return op.Kind == jobs.KindPostgresAccountProvisionV1, nil
	}
	if err != nil {
		return false, err
	}
	if op.AccountID == nil || *op.AccountID != p.AccountID || r.AccountID != p.AccountID ||
		op.ConnectionID == nil || *op.ConnectionID != r.ConnectionID {
		return false, nil
	}
	return r.Phase == "created" || r.Phase == "verified" ||
		(r.Phase == "planned" && op.Kind == jobs.KindPostgresAccountProvisionV1), nil
}

// verifyAccountCreation queues read-only verification of the original
// receipt. It keeps the original CREATE operation and its audit immutable.
func (s *Server) verifyAccountCreation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req recoverAccountProvisioningRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if req.RequestID == uuid.Nil || req.OperationID == uuid.Nil || req.UpdatedAt.IsZero() {
		respondError(w, http.StatusBadRequest, "request_id, operation_id and updated_at are required")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	before, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	locked, err := locks.TryAcquireTx(ctx, tx, before.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !locked {
		respondError(w, http.StatusConflict, "connection operation is running; retry after it finishes")
		return
	}
	conn, err := s.connections.Get(ctx, tx, before.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	key := fmt.Sprintf("account.creation.verify:%s:%s:%s", id, req.OperationID, req.RequestID)
	respond := func(op operations.Operation, dedup bool) {
		respondJSON(w, http.StatusAccepted, map[string]any{"account_id": id, "operation_id": op.ID,
			"status": op.Status, "verification_only": true, "deduplicated": dedup})
	}
	if op, err := s.operations.GetByIdempotencyKey(ctx, tx, key); err == nil {
		respond(op, true)
		return
	} else if !errors.Is(err, operations.ErrNotFound) {
		respondStoreError(ctx, w, err)
		return
	}
	var version int64
	if err := tx.QueryRow(ctx, `select lifecycle_version from accounts where id=$1 for update`, id).Scan(&version); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	acct, err := s.inventory.GetAccount(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !acct.UpdatedAt.Equal(req.UpdatedAt) {
		respondError(w, http.StatusConflict, "account changed; reload before verification")
		return
	}
	info, err := inspectAccountProvisioning(ctx, tx, acct, conn)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !info.VerificationReady || info.OperationID == nil || *info.OperationID != req.OperationID ||
		info.OperationKind != jobs.KindPostgresAccountProvisionV1 {
		respondError(w, http.StatusConflict, "account creation cannot be verified: "+info.BlockedReason)
		return
	}
	source, err := s.operations.Get(ctx, tx, req.OperationID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	var payload jobs.AccountPayload
	if err := json.Unmarshal(source.Payload, &payload); err != nil || payload.AccountID != acct.ID || payload.ExpectedLifecycleVersion != version {
		respondError(w, http.StatusConflict, "account creation intent changed")
		return
	}
	// Copy only the original, immutable account intent. No new lifecycle or
	// credential version is reserved and no account password is read here.
	payload.CreationOperationID = source.ID
	raw, err := json.Marshal(payload)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{Kind: jobs.KindPostgresAccountVerifyCreationV1,
		IdempotencyKey: &key, ConnectionID: &conn.ID, AccountID: &acct.ID, Payload: raw,
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: uuid.NewString()})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		Action: "account.creation_verification_requested", ConnectionID: &conn.ID, AccountID: &acct.ID,
		OperationID: &op.ID, Result: audit.ResultSuccess}, map[string]any{"source_operation_id": source.ID,
		"engine_identity": acct.EngineIdentity, "target_modified": false}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respond(op, false)
}
