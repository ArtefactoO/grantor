package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// Failed operations can still have an automatic River retry. Do not present
// them as finished, or allow abandoning their reservation, until every job
// (including a queued sequence predecessor) has stopped.
type accountProvisioningJSON struct {
	VerificationReady bool       `json:"verification_ready"`
	CreationPhase     string     `json:"creation_phase,omitempty"`
	AccountID         uuid.UUID  `json:"account_id"`
	UpdatedAt         time.Time  `json:"updated_at"`
	State             string     `json:"state"`
	OperationID       *uuid.UUID `json:"operation_id,omitempty"`
	OperationKind     string     `json:"operation_kind,omitempty"`
	OperationStatus   string     `json:"operation_status,omitempty"`
	OperationError    string     `json:"operation_error,omitempty"`
	Recoverable       bool       `json:"recoverable"`
	Retryable         bool       `json:"retryable"`
	BlockedReason     string     `json:"blocked_reason,omitempty"`
}

func inspectAccountProvisioning(ctx context.Context, q inventory.Querier, acct inventory.Account,
	conn connections.Connection,
) (accountProvisioningJSON, error) {
	out := accountProvisioningJSON{AccountID: acct.ID, UpdatedAt: acct.UpdatedAt, State: "unavailable"}
	if acct.Status != inventory.AccountProvisioning || acct.Ownership != inventory.OwnershipManaged {
		out.BlockedReason = "not_provisioning"
		return out, nil
	}
	var rawPayload []byte
	err := q.QueryRow(ctx, `
		select id, kind, status, coalesce(error, ''), payload from operations
		where account_id = $1 and kind in (
			'account.create', 'role.create',
			'postgres.account.create.v2', 'postgres.account.provision.v1', 'postgres.role.create.v2'
		)
		order by created_at desc, id desc limit 1`, acct.ID).
		Scan(&out.OperationID, &out.OperationKind, &out.OperationStatus, &out.OperationError, &rawPayload)
	if errors.Is(err, pgx.ErrNoRows) {
		out.BlockedReason = "no_failed_creation"
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("api: inspect account provisioning operation: %w", err)
	}
	var busy, managedBindings, policyAccount bool
	if err := q.QueryRow(ctx, `
		select exists (
			select 1 from operations where account_id = $1
			and status in ('pending_approval', 'pending', 'running', 'partial')
		) or exists (
			select 1 from river_job j join operations o on
				j.args->>'operation_id' = o.id::text
				or (j.args->'next_operation_ids') ? o.id::text
			where o.account_id = $1
			and j.state not in ('completed', 'cancelled', 'discarded')
		), exists (
			select 1 from bindings where account_id = $1
			and (desired_state is not null or transition_operation_id is not null)
		), exists (
			select 1 from role_policies where account_id = $1
		)`, acct.ID).Scan(&busy, &managedBindings, &policyAccount); err != nil {
		return out, fmt.Errorf("api: inspect account provisioning dependencies: %w", err)
	}
	if busy {
		out.State, out.BlockedReason = "running", "busy"
		return out, nil
	}
	if out.OperationStatus != string(operations.StatusFailed) {
		out.BlockedReason = "no_failed_creation"
		return out, nil
	}
	out.State = "failed"
	var source jobs.AccountPayload
	if err := json.Unmarshal(rawPayload, &source); err != nil || source.AccountID != acct.ID ||
		source.ExpectedStatus != inventory.AccountProvisioning || source.ExpectedLifecycleVersion != acct.LifecycleVersion {
		out.BlockedReason = "no_failed_creation"
		return out, nil
	}
	if acct.PrincipalID != nil {
		var principalActive bool
		if err := q.QueryRow(ctx, `select status='active' and coalesce(external_identity_status='active',true) from principals where id=$1`, *acct.PrincipalID).Scan(&principalActive); err != nil {
			return out, err
		}
		if !principalActive {
			out.BlockedReason = "principal_not_active"
			return out, nil
		}
	}
	if out.OperationKind == jobs.KindPostgresAccountProvisionV1 {
		receipt, receiptErr := accountcreation.NewStore().Get(ctx, q, *out.OperationID)
		if receiptErr != nil && !errors.Is(receiptErr, accountcreation.ErrNotFound) {
			return out, receiptErr
		}
		if receiptErr == nil {
			out.CreationPhase = receipt.Phase
			switch receipt.Phase {
			case "creating":
				out.BlockedReason = "creation_outcome_unknown"
				return out, nil
			case "created":
				pins, pinsErr := requirePostgresProvisioningAuthority(conn, adapter.CapAccountCreate)
				if !policyAccount && pinsErr == nil && jobs.AccountCreationReceiptMatches(receipt, acct, source) &&
					source.ExpectedAdminIdentity == pins.AdminIdentity && source.ExpectedTargetIdentity == pins.TargetIdentity &&
					source.ExpectedConfigIncarnation == pins.ConfigIncarnation && source.ExpectedCredentialIncarnation == pins.CredentialIncarnation {
					out.VerificationReady = true
				} else {
					out.BlockedReason = "creation_intent_changed"
				}
				return out, nil
			case "verified":
				out.BlockedReason = "creation_intent_changed"
				return out, nil
			}
		}
	}
	switch {
	case policyAccount:
		out.BlockedReason = "role_policy"
	case managedBindings:
		out.BlockedReason = "managed_bindings"
	case adapter.AttrBool(decodeAttributes(acct.Attributes), adapter.AttrConnectionAdmin):
		out.BlockedReason = "connection_admin"
	case conn.Status != connections.StatusActive || !slices.Contains(conn.Capabilities, string(adapter.CapInventoryAccounts)):
		out.BlockedReason = "connection_unavailable"
	default:
		out.Recoverable = true
		required := adapter.CapAccountCreate
		if out.OperationKind == jobs.KindRoleCreate || out.OperationKind == jobs.KindPostgresRoleCreateV2 {
			required = adapter.CapRoleCreate
		}
		out.Retryable = slices.Contains(connectionCapabilitiesForProjection(conn), string(required))
		if conn.Engine == "postgres" {
			pins, authorityErr := requirePostgresProvisioningAuthority(conn, required)
			out.Retryable = authorityErr == nil &&
				(out.OperationKind == jobs.KindPostgresAccountCreateV2 || out.OperationKind == jobs.KindPostgresAccountProvisionV1 || out.OperationKind == jobs.KindPostgresRoleCreateV2) &&
				source.ExpectedAdminIdentity == pins.AdminIdentity &&
				source.ExpectedTargetIdentity == pins.TargetIdentity &&
				source.ExpectedConfigIncarnation == pins.ConfigIncarnation &&
				source.ExpectedCredentialIncarnation == pins.CredentialIncarnation
		}
	}
	return out, nil
}

func (s *Server) getAccountProvisioning(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	out, err := inspectAccountProvisioning(ctx, s.pool, acct, conn)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if (out.OperationKind == jobs.KindRoleCreate || out.OperationKind == jobs.KindPostgresRoleCreateV2) &&
		roleCreationRequiresAdmin(conn.Engine) && !sess.Role.Allows(auth.RoleAdmin) {
		out.Retryable = false
	}
	respondJSON(w, http.StatusOK, out)
}

type recoverAccountProvisioningRequest struct {
	RequestID   uuid.UUID `json:"request_id"`
	OperationID uuid.UUID `json:"operation_id"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// This is a metadata-only release, not adopt, delete, or a retry of CREATE.
// Fresh discovery must first prove the identity exists. Only then will the
// worker release its reservation/reference and fence old jobs in the same
// metadata transaction as the observed snapshot. No account password is read.
func (s *Server) recoverAccountProvisioning(w http.ResponseWriter, r *http.Request) {
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
	key := fmt.Sprintf("account.provisioning.recover:%s:%s:%s", id, req.OperationID, req.RequestID)
	// A lost HTTP response must replay successfully even after discovery has
	// changed the account status/updated_at. Scope is checked before dedup.
	if existing, err := s.operations.GetByIdempotencyKey(ctx, tx, key); err == nil {
		respondJSON(w, http.StatusAccepted, map[string]any{
			"account_id": id, "operation_id": existing.ID, "status": existing.Status, "deduplicated": true,
		})
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
		respondError(w, http.StatusConflict, "account changed concurrently; reload before recovery")
		return
	}
	info, err := inspectAccountProvisioning(ctx, tx, acct, conn)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !info.Recoverable || info.OperationID == nil || *info.OperationID != req.OperationID {
		respondError(w, http.StatusConflict, "account provisioning cannot be recovered: "+info.BlockedReason)
		return
	}
	payload, err := json.Marshal(map[string]any{
		"recovered_account_id": acct.ID, "source_operation_id": req.OperationID,
		"expected_lifecycle_version": version,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindAccountRecoverProvisioning, IdempotencyKey: &key, ConnectionID: &conn.ID,
		AccountID: &acct.ID, Payload: payload, ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: "account.provisioning_recovery_requested",
		ConnectionID: &conn.ID, AccountID: &acct.ID, OperationID: &op.ID, Result: audit.ResultSuccess,
	}, map[string]any{
		"source_operation_id": req.OperationID, "engine_identity": acct.EngineIdentity,
		"expected_lifecycle_version": version,
		"target_modified":            false,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit account provisioning recovery: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id": acct.ID, "operation_id": op.ID, "status": op.Status,
	})
}
