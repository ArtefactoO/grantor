package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

type verifyManagedCredentialRequest struct {
	RequestID            uuid.UUID `json:"request_id"`
	Mode                 string    `json:"mode"`
	Password             string    `json:"password"`
	ExpectedVaultVersion *int      `json:"expected_vault_version,omitempty"`
}

func (s *Server) verifyManagedCredential(w http.ResponseWriter, r *http.Request) {
	var req verifyManagedCredentialRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if req.Mode == "" {
		req.Mode = "verify"
	}
	if req.RequestID == uuid.Nil || (req.Mode != "verify" && req.Mode != "reconcile") || (req.Mode == "verify" && req.Password != "") ||
		(req.Mode == "reconcile" && (req.Password == "" || len(req.Password) > 4096 || strings.ContainsRune(req.Password, 0))) ||
		(req.ExpectedVaultVersion != nil && *req.ExpectedVaultVersion < 0) {
		respondError(w, http.StatusBadRequest, "request_id and verify/reconcile mode are required; only reconcile accepts a bounded password")
		return
	}
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	a, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, a.ConnectionID)) {
		return
	}
	key := "credential-verify:" + a.ID.String() + ":" + req.RequestID.String()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Replay does not depend on current lifecycle or Vault availability; scope
	// is still checked against the account's current connection above.
	if old, err := s.operations.GetByIdempotencyKey(ctx, tx, key); err == nil {
		s.respondCredentialVerificationReplay(w, old, req)
		return
	} else if !errors.Is(err, operations.ErrNotFound) {
		respondStoreError(ctx, w, err)
		return
	}
	c, ok := s.lockCredentialConnection(w, r, tx, a.ConnectionID, adapter.CapCredentialProve)
	if !ok {
		return
	}
	if old, err := s.operations.GetByIdempotencyKey(ctx, tx, key); err == nil {
		s.respondCredentialVerificationReplay(w, old, req)
		return
	} else if !errors.Is(err, operations.ErrNotFound) {
		respondStoreError(ctx, w, err)
		return
	}
	if c.Status != connections.StatusActive || connections.TargetIdentity(c) == "" || !engineProvesCredential(c.Engine) {
		respondError(w, http.StatusConflict, "an active connection with a discovered target identity is required")
		return
	}
	a, err = s.inventory.GetAccount(ctx, tx, a.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if a.Status != inventory.AccountActive || a.Ownership != inventory.OwnershipManaged || a.Kind != "login" || a.VaultPath == "" {
		respondError(w, http.StatusConflict, "an active managed login with a canonical credential path is required")
		return
	}
	if req.Mode == "reconcile" && a.VaultPath != "accounts/"+a.ID.String()+"/credential" {
		respondError(w, http.StatusConflict, "shared credentials cannot be reconciled per account")
		return
	}
	if !credentials.VerificationPathAllowed(a.ID, a.PrincipalID, c.Environment, a.VaultPath, req.Mode == "reconcile") {
		respondError(w, http.StatusConflict, "credential reference is outside account scope")
		return
	}
	current, present, err := s.credentials.CredentialMetadata(ctx, a.VaultPath)
	if err != nil {
		respondError(w, http.StatusServiceUnavailable, "canonical credential metadata is unavailable")
		return
	}
	if req.ExpectedVaultVersion != nil && *req.ExpectedVaultVersion != current {
		respondError(w, http.StatusConflict, "canonical credential version changed")
		return
	}
	if req.Mode == "verify" && !present {
		respondError(w, http.StatusConflict, "canonical credential is absent")
		return
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, a.ID, a.Status)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	p := jobs.CredentialVerifyPayload{AccountID: a.ID, RequestID: req.RequestID, Status: a.Status, LifecycleVersion: reserved.LifecycleVersion,
		CanonicalVersion: current, Reconcile: req.Mode == "reconcile", ConfigIncarnation: connections.ConfigIncarnation(c), TargetIdentity: connections.TargetIdentity(c),
		EngineIdentity: a.EngineIdentity, CredentialPath: a.VaultPath, AuthenticationScope: a.AuthenticationScope}
	if a.PrincipalID != nil {
		p.PrincipalID = *a.PrincipalID
	}
	// Deterministic, non-secret identity lets a retry recover its stage after
	// the API lost Vault/metadata acknowledgement before committing the row.
	opID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(key))
	commitAttempted := false
	staged := false
	defer func() {
		if staged && !commitAttempted {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = s.credentials.DeleteVerificationProof(cleanupCtx, a.ID, opID)
		}
	}()
	if p.Reconcile {
		password := []byte(req.Password)
		req.Password = ""
		p.ProofVersion, err = s.credentials.PutVerificationProof(ctx, a.ID, opID, a.EngineIdentity, password)
		clear(password)
		if err != nil {
			respondError(w, http.StatusBadGateway, "could not stage verification proof")
			return
		}
		staged = true
	}
	payload, err := json.Marshal(p)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{ID: &opID, Kind: jobs.KindCredentialVerify, IdempotencyKey: &key,
		ConnectionID: &a.ConnectionID, AccountID: &a.ID, Payload: payload, ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: uuid.NewString()})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err = s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err = s.writeAudit(ctx, tx, audit.Event{Action: "credential.verify_requested", ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		ConnectionID: &a.ConnectionID, AccountID: &a.ID, OperationID: &op.ID, Result: audit.ResultSuccess}, map[string]any{"mode": req.Mode, "vault_version": current}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	commitAttempted = true
	if err = tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{"operation_id": op.ID, "canonical_vault_version": current})
}

func (s *Server) respondCredentialVerificationReplay(w http.ResponseWriter, old operations.Operation, req verifyManagedCredentialRequest) {
	var p jobs.CredentialVerifyPayload
	if old.Kind != jobs.KindCredentialVerify || json.Unmarshal(old.Payload, &p) != nil || p.Reconcile != (req.Mode == "reconcile") ||
		(req.ExpectedVaultVersion != nil && *req.ExpectedVaultVersion != p.CanonicalVersion) {
		respondError(w, http.StatusConflict, "request_id belongs to a different verification intent")
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{"operation_id": old.ID, "canonical_vault_version": p.CanonicalVersion})
}

func (s *Server) getCredentialVerification(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	ctx := r.Context()
	a, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScopeByID(ctx, sess, a.ConnectionID)) {
		return
	}
	c, err := s.connections.Get(ctx, s.pool, a.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	version, present := 0, false
	if a.VaultPath != "" {
		if !credentials.VerificationPathAllowed(a.ID, a.PrincipalID, c.Environment, a.VaultPath, false) {
			respondError(w, http.StatusConflict, "credential reference is outside account scope")
			return
		}
		version, present, err = s.credentials.CredentialMetadata(ctx, a.VaultPath)
		if err != nil {
			respondError(w, http.StatusServiceUnavailable, "canonical credential metadata unavailable")
			return
		}
	}
	receipts, err := s.audit.List(ctx, s.pool, audit.Filter{AccountID: &a.ID, Actions: []string{"credential.verified"}}, 1, 0)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := map[string]any{"current_vault_version": version, "canonical_credential_present": present, "matches_current_vault_version": false,
		"application_access_ready": false, "last_verification": nil}
	if len(receipts) > 0 {
		var receipt jobs.CredentialVerificationReceipt
		if json.Unmarshal(receipts[0].Metadata, &receipt) == nil {
			principalID := uuid.Nil
			if a.PrincipalID != nil {
				principalID = *a.PrincipalID
			}
			out["last_verification"] = receipt
			out["matches_current_vault_version"] = receipt.CredentialProved && present && a.Status == inventory.AccountActive && a.Ownership == inventory.OwnershipManaged &&
				receipt.VaultVersion == version && receipt.LifecycleVersion == a.LifecycleVersion &&
				receipt.ConfigIncarnation == connections.ConfigIncarnation(c) && receipt.TargetIdentity == connections.TargetIdentity(c) &&
				receipt.EngineIdentity == a.EngineIdentity && receipt.AuthenticationScope == a.AuthenticationScope && receipt.PrincipalID == principalID && receipt.CredentialPath == a.VaultPath
		}
	}
	respondJSON(w, http.StatusOK, out)
}
