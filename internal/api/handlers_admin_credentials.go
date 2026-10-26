package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const (
	auditActionAdminCredentialSwitchRequested = "connection.admin_credential_switch_requested"
	auditActionAdminCredentialRotateRequested = "connection.admin_credential_rotate_requested"
	auditActionAdminCredentialCancelled       = "connection.admin_credential_change_cancelled"
	auditActionAdminCredentialRejected        = "connection.admin_credential_change_failed"
)

type switchAdminCredentialRequest struct {
	RequestID uuid.UUID `json:"request_id"`
	UpdatedAt time.Time `json:"updated_at"`
	AuthMode  string    `json:"auth_mode"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
}

type rotateAdminCredentialRequest struct {
	RequestID uuid.UUID `json:"request_id"`
	UpdatedAt time.Time `json:"updated_at"`
	Mode      string    `json:"mode"`
	Password  string    `json:"password,omitempty"`
}

type cancelAdminCredentialRequest struct {
	RequestID uuid.UUID `json:"request_id"`
	UpdatedAt time.Time `json:"updated_at"`
}

type adminCredentialOperationResponse struct {
	OperationID uuid.UUID `json:"operation_id"`
}

type stagedAdminCredentialInput struct {
	GenerationMode string
	Username       string
	Password       string
}

type adminCredentialRequestError struct {
	status  int
	message string
}

func (e *adminCredentialRequestError) Error() string { return e.message }

func requestError(status int, message string) error {
	return &adminCredentialRequestError{status: status, message: message}
}

func (s *Server) switchConnectionAdminCredential(w http.ResponseWriter, r *http.Request) {
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req switchAdminCredentialRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if req.RequestID == uuid.Nil || req.UpdatedAt.IsZero() {
		respondError(w, http.StatusBadRequest, "request_id and updated_at are required")
		return
	}
	if req.AuthMode != "" && req.AuthMode != "password" && req.AuthMode != "none" {
		respondError(w, http.StatusBadRequest, "auth_mode must be password or none")
		return
	}
	if req.AuthMode == "none" && (req.Username != "" || req.Password != "") {
		respondError(w, http.StatusBadRequest, "username and password must be omitted in no-auth mode")
		return
	}
	if req.AuthMode != "none" {
		if err := validateAdminCredentialValue(req.Username, req.Password); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	generationMode := "provided"
	if req.AuthMode == "none" {
		generationMode = "none"
	}
	opID, err := s.startConnectionAdminCredentialChange(r.Context(), sess, connectionID,
		req.RequestID, req.UpdatedAt, admincredentials.ModeSwitch, stagedAdminCredentialInput{
			GenerationMode: generationMode,
			Username:       req.Username,
			Password:       req.Password,
		})
	if err != nil {
		s.respondAdminCredentialRequestError(r.Context(), w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, adminCredentialOperationResponse{OperationID: opID})
}

func (s *Server) rotateConnectionAdminCredential(w http.ResponseWriter, r *http.Request) {
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req rotateAdminCredentialRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if req.RequestID == uuid.Nil || req.UpdatedAt.IsZero() {
		respondError(w, http.StatusBadRequest, "request_id and updated_at are required")
		return
	}
	if req.Mode != "generated" && req.Mode != "provided" {
		respondError(w, http.StatusBadRequest, "mode must be generated or provided")
		return
	}
	if req.Mode == "generated" && req.Password != "" {
		respondError(w, http.StatusBadRequest, "password must be omitted in generated mode")
		return
	}
	if req.Mode == "provided" {
		if err := validateAdminCredentialPassword(req.Password); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	opID, err := s.startConnectionAdminCredentialChange(r.Context(), sess, connectionID,
		req.RequestID, req.UpdatedAt, admincredentials.ModeRotate, stagedAdminCredentialInput{
			GenerationMode: req.Mode,
			Password:       req.Password,
		})
	if err != nil {
		s.respondAdminCredentialRequestError(r.Context(), w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, adminCredentialOperationResponse{OperationID: opID})
}

func validateAdminCredentialValue(username, password string) error {
	if strings.TrimSpace(username) == "" || len(username) > 512 {
		return errors.New("username must be between 1 and 512 bytes")
	}
	for _, r := range username {
		if unicode.IsControl(r) {
			return errors.New("username must not contain control characters")
		}
	}
	return validateAdminCredentialPassword(password)
}

func validateAdminCredentialPassword(password string) error {
	if password == "" || len(password) > 8192 {
		return errors.New("password must be between 1 and 8192 bytes")
	}
	if strings.IndexByte(password, 0) >= 0 {
		return errors.New("password must not contain NUL")
	}
	return nil
}

func (s *Server) startConnectionAdminCredentialChange(ctx context.Context, sess auth.Session,
	connectionID, requestID uuid.UUID, expectedUpdatedAt time.Time, mode admincredentials.Mode,
	input stagedAdminCredentialInput) (uuid.UUID, error) {
	if input.GenerationMode != "none" && s.vault == nil {
		return uuid.Nil, requestError(http.StatusServiceUnavailable, "vault is not configured")
	}
	if existing, err := s.adminCredentialChanges.GetByRequest(ctx, s.pool, connectionID, requestID); err == nil {
		if existing.Mode != mode || existing.CandidateMode != input.GenerationMode {
			return uuid.Nil, requestError(http.StatusConflict, "request_id already belongs to another credential change")
		}
		if existing.Phase == admincredentials.PhasePreparing {
			return s.finalizePreparedAdminCredentialChange(ctx, existing, input)
		}
		return existing.OperationID, nil
	} else if !errors.Is(err, admincredentials.ErrNotFound) {
		return uuid.Nil, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, connectionID); err != nil {
		return uuid.Nil, err
	}
	if existing, err := s.adminCredentialChanges.GetByRequest(ctx, tx, connectionID, requestID); err == nil {
		if existing.Mode != mode || existing.CandidateMode != input.GenerationMode {
			return uuid.Nil, requestError(http.StatusConflict, "request_id already belongs to another credential change")
		}
		if err := tx.Rollback(ctx); err != nil {
			return uuid.Nil, err
		}
		if existing.Phase == admincredentials.PhasePreparing {
			return s.finalizePreparedAdminCredentialChange(ctx, existing, input)
		}
		return existing.OperationID, nil
	} else if !errors.Is(err, admincredentials.ErrNotFound) {
		return uuid.Nil, err
	}

	conn, err := s.connections.Get(ctx, tx, connectionID)
	if err != nil {
		return uuid.Nil, err
	}
	if input.GenerationMode == "none" && (conn.Engine != "redis" || mode != admincredentials.ModeSwitch) {
		return uuid.Nil, requestError(http.StatusBadRequest, "no-auth is supported only for Redis switch")
	}
	if !conn.UpdatedAt.Equal(expectedUpdatedAt) {
		return uuid.Nil, connections.ErrVersionConflict
	}
	switch conn.Status {
	case connections.StatusActive, connections.StatusDegraded,
		connections.StatusConnectionFailed, connections.StatusDiscoveryFailed:
	default:
		return uuid.Nil, requestError(http.StatusConflict,
			"connection status does not allow an admin credential change")
	}
	if _, activeErr := s.adminCredentialChanges.Active(ctx, tx, connectionID); activeErr == nil {
		return uuid.Nil, requestError(http.StatusConflict, "another admin credential change is active")
	} else if !errors.Is(activeErr, admincredentials.ErrNotFound) {
		return uuid.Nil, activeErr
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		return uuid.Nil, requestError(http.StatusConflict, "connection engine is unavailable in this control plane")
	}
	if _, ok := ad.(adapter.ConnectionAdminCredentialManager); !ok ||
		!ad.Manifest().HasCapability(adapter.CapConnectionAdminCredentialSwitch) {
		return uuid.Nil, requestError(http.StatusConflict, "connection admin credential switch is unsupported")
	}
	if mode == admincredentials.ModeRotate &&
		!slices.Contains(conn.Capabilities, string(adapter.CapConnectionAdminCredentialRotate)) {
		return uuid.Nil, requestError(http.StatusConflict, "connection admin credential rotation is unavailable for the discovered topology")
	}

	canonicalPath, err := vault.ConnectionAdminPath(connectionID.String())
	if err != nil {
		return uuid.Nil, err
	}
	if mode == admincredentials.ModeRotate && conn.VaultAdminPath != canonicalPath {
		return uuid.Nil, requestError(http.StatusConflict,
			"rotation requires the canonical connection admin Vault path; use switch to recover or canonicalize it")
	}
	canonicalVersion := 0
	if input.GenerationMode != "none" {
		canonicalMeta, canonicalErr := s.vault.Metadata(ctx, canonicalPath)
		if canonicalErr != nil && !errors.Is(canonicalErr, vault.ErrNotFound) {
			return uuid.Nil, requestError(http.StatusBadGateway, "failed to read canonical admin credential metadata from vault")
		}
		if canonicalErr == nil {
			canonicalVersion = canonicalMeta.CurrentVersion
		}
	}

	var current adapter.Credential
	if input.GenerationMode != "none" && conn.VaultAdminPath != "" {
		currentData, _, readErr := s.vault.Get(ctx, conn.VaultAdminPath)
		if readErr != nil {
			if mode == admincredentials.ModeRotate {
				return uuid.Nil, requestError(http.StatusBadGateway, "failed to read current admin credential from vault")
			}
			currentData = nil
		}
		if currentData != nil {
			current, err = adminCredentialFromVault(currentData)
			if err != nil && mode == admincredentials.ModeRotate {
				return uuid.Nil, requestError(http.StatusConflict, "current admin credential in vault is incomplete")
			}
		}
	} else if mode == admincredentials.ModeRotate {
		return uuid.Nil, requestError(http.StatusConflict, "rotation requires an existing canonical admin credential")
	}
	defer clear(current.Secret)

	stagePath := ""
	if input.GenerationMode != "none" {
		stagePath, err = vault.ConnectionAdminChangeStagePath(connectionID.String(), requestID.String())
		if err != nil {
			return uuid.Nil, err
		}

	}
	epoch, err := s.adminCredentialChanges.NextEpoch(ctx, tx, connectionID)
	if err != nil {
		return uuid.Nil, err
	}
	payload, err := jobs.MarshalAdminCredentialOperationPayload(mode, epoch)
	if err != nil {
		return uuid.Nil, err
	}
	operationID := requestID
	idempotencyKey := fmt.Sprintf("connection-admin-credential:%s:%s", connectionID, requestID)
	kind := jobs.KindConnectionAdminCredentialSwitch
	auditAction := auditActionAdminCredentialSwitchRequested
	if mode == admincredentials.ModeRotate {
		kind = jobs.KindConnectionAdminCredentialRotate
		auditAction = auditActionAdminCredentialRotateRequested
	}
	op, created, err := s.operations.Create(ctx, tx, operations.CreateParams{
		ID:             &operationID,
		Kind:           kind,
		IdempotencyKey: &idempotencyKey,
		ConnectionID:   &connectionID,
		Payload:        payload,
		ActorType:      sess.ActorType(),
		ActorID:        sess.ActorID(),
		CorrelationID:  uuid.NewString(),
	})
	if err != nil {
		return uuid.Nil, requestError(http.StatusConflict, "request_id conflicts with an existing operation")
	}
	if !created {
		return uuid.Nil, requestError(http.StatusConflict,
			"request_id already belongs to an operation without a credential lifecycle")
	}
	change, err := s.adminCredentialChanges.Create(ctx, tx, admincredentials.CreateParams{
		OperationID:              op.ID,
		ConnectionID:             connectionID,
		RequestID:                requestID,
		Mode:                     mode,
		CandidateMode:            input.GenerationMode,
		Epoch:                    epoch,
		StageVaultPath:           stagePath,
		StagedVaultVersion:       0,
		ExpectedCanonicalVersion: canonicalVersion,
		PreviousStatus:           conn.Status,
		ExpectedUpdatedAt:        expectedUpdatedAt,
	})
	if err != nil {
		if errors.Is(err, admincredentials.ErrActiveChange) {
			return uuid.Nil, requestError(http.StatusConflict, "another admin credential change is active")
		}
		return uuid.Nil, err
	}
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditAction,
		ConnectionID: &connectionID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
		Metadata: mustJSON(map[string]any{
			"mode":                       mode,
			"epoch":                      change.Epoch,
			"expected_canonical_version": canonicalVersion,
			"phase":                      admincredentials.PhasePreparing,
		}),
	}); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return s.finalizePreparedAdminCredentialChange(ctx, change, input)
}

func (s *Server) finalizePreparedAdminCredentialChange(ctx context.Context,
	change admincredentials.Change, input stagedAdminCredentialInput) (uuid.UUID, error) {
	if change.Phase != admincredentials.PhasePreparing {
		if change.Phase.Terminal() {
			return uuid.Nil, requestError(http.StatusConflict, "credential request is already terminal")
		}
		return change.OperationID, nil
	}
	if change.CandidateMode != input.GenerationMode {
		return uuid.Nil, requestError(http.StatusConflict, "request_id already belongs to another candidate mode")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, change.ConnectionID); err != nil {
		return uuid.Nil, err
	}
	currentChange, err := s.adminCredentialChanges.Get(ctx, tx, change.OperationID)
	if err != nil {
		return uuid.Nil, err
	}
	if currentChange.Phase != admincredentials.PhasePreparing {
		if currentChange.Phase.Terminal() {
			return uuid.Nil, requestError(http.StatusConflict, "credential request became terminal")
		}
		return currentChange.OperationID, nil
	}
	change = currentChange
	conn, err := s.connections.Get(ctx, tx, change.ConnectionID)
	if err != nil {
		return uuid.Nil, err
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		return uuid.Nil, requestError(http.StatusConflict, "connection engine is unavailable in this control plane")
	}
	if change.CandidateMode == "none" {
		if conn.Engine != "redis" || change.Mode != admincredentials.ModeSwitch {
			return uuid.Nil, requestError(http.StatusConflict, "invalid no-auth change")
		}
		if _, err := s.adminCredentialChanges.FinalizeStage(ctx, tx, change.OperationID, 0); err != nil {
			return uuid.Nil, err
		}
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, change.OperationID); err != nil {
			return uuid.Nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, err
		}
		return change.OperationID, nil
	}
	var current adapter.Credential
	if conn.VaultAdminPath != "" {
		currentData, _, readErr := s.vault.Get(ctx, conn.VaultAdminPath)
		if readErr != nil && change.Mode == admincredentials.ModeRotate {
			return uuid.Nil, requestError(http.StatusBadGateway, "failed to read current admin credential from vault")
		}
		if readErr == nil {
			current, err = adminCredentialFromVault(currentData)
			if err != nil && change.Mode == admincredentials.ModeRotate {
				return uuid.Nil, requestError(http.StatusConflict, "current admin credential in vault is incomplete")
			}
		}
	} else if change.Mode == admincredentials.ModeRotate {
		return uuid.Nil, requestError(http.StatusConflict, "rotation requires an existing canonical admin credential")
	}
	defer clear(current.Secret)
	if s.beforeAdminCredentialStage != nil {
		if err := s.beforeAdminCredentialStage(ctx, change.OperationID); err != nil {
			return uuid.Nil, err
		}
	}
	candidate, stagedVersion, err := s.ensureAdminCredentialStage(ctx, ad,
		change.StageVaultPath, change.Mode, input, current)
	if err != nil {
		return uuid.Nil, err
	}
	defer clear(candidate.Secret)
	if candidate.Username == current.Username && current.Username != "" &&
		subtle.ConstantTimeCompare(candidate.Secret, current.Secret) == 1 {
		if err := s.vault.DeleteMetadata(ctx, change.StageVaultPath); err != nil &&
			!errors.Is(err, vault.ErrNotFound) {
			return uuid.Nil, requestError(http.StatusBadGateway,
				"staged Vault value could not be cleaned; retry the same request_id")
		}
		op, err := s.operations.Get(ctx, tx, change.OperationID)
		if err != nil {
			return uuid.Nil, err
		}
		if op.Status == operations.StatusPending {
			if _, err := s.operations.Transition(ctx, tx, op.ID, op.Status,
				operations.StatusCancelled, operations.TransitionOpts{}); err != nil {
				return uuid.Nil, err
			}
		}
		closed, err := s.adminCredentialChanges.RestoreTerminal(ctx, tx, change.OperationID,
			admincredentials.PhaseFailed, "invalid_candidate", nil)
		if err != nil {
			return uuid.Nil, err
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			ActorType: op.ActorType, ActorID: op.ActorID,
			Action:       auditActionAdminCredentialRejected,
			ConnectionID: &closed.ConnectionID, OperationID: &closed.OperationID,
			Result: audit.ResultFailure,
			Metadata: mustJSON(map[string]any{
				"mode": closed.Mode, "epoch": closed.Epoch, "error_code": "invalid_candidate",
			}),
		}); err != nil {
			return uuid.Nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return uuid.Nil, err
		}
		if err := s.adminCredentialChanges.MarkStageCleaned(ctx, s.pool, closed.OperationID); err != nil {
			slog.WarnContext(ctx, "api: mark rejected prepared stage cleaned deferred",
				"connection_id", closed.ConnectionID, "operation_id", closed.OperationID, "error", err)
		}
		return uuid.Nil, requestError(http.StatusBadRequest,
			"candidate credential is identical to the current credential")
	}
	if change.Mode == admincredentials.ModeRotate && candidate.Username != current.Username {
		return uuid.Nil, requestError(http.StatusConflict,
			"staged rotation identity differs from the current admin identity")
	}

	if _, err := s.adminCredentialChanges.FinalizeStage(ctx, tx,
		change.OperationID, stagedVersion); err != nil {
		return uuid.Nil, err
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, change.OperationID); err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	return change.OperationID, nil
}

func (s *Server) ensureAdminCredentialStage(ctx context.Context, ad adapter.Adapter, stagePath string,
	mode admincredentials.Mode, input stagedAdminCredentialInput, current adapter.Credential) (adapter.Credential, int, error) {
	if data, version, err := s.vault.Get(ctx, stagePath); err == nil {
		candidate, parseErr := adminCredentialFromVault(data)
		if parseErr != nil {
			return adapter.Credential{}, 0, requestError(http.StatusConflict, "existing staged credential is incomplete")
		}
		if input.GenerationMode == "provided" && !sameProvidedCredential(candidate, input, mode, current) {
			clear(candidate.Secret)
			return adapter.Credential{}, 0, requestError(http.StatusConflict, "request_id already staged different credential material")
		}
		return candidate, version, nil
	} else if !errors.Is(err, vault.ErrNotFound) {
		return adapter.Credential{}, 0, requestError(http.StatusBadGateway, "failed to read staged admin credential from vault")
	}

	candidate := adapter.Credential{Kind: "password", Username: input.Username}
	if mode == admincredentials.ModeRotate {
		candidate.Username = current.Username
	}
	if input.GenerationMode == "generated" {
		generated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{Length: 32})
		if err != nil {
			return adapter.Credential{}, 0, requestError(http.StatusConflict, "engine cannot generate an admin credential")
		}
		candidate.Secret = slices.Clone(generated.Secret)
		clear(generated.Secret)
	} else {
		candidate.Secret = []byte(input.Password)
	}
	if candidate.Username == "" || len(candidate.Secret) == 0 {
		clear(candidate.Secret)
		return adapter.Credential{}, 0, requestError(http.StatusConflict,
			"engine generated an incomplete admin credential")
	}
	data := map[string]any{"username": candidate.Username, "password": string(candidate.Secret)}
	version, putErr := s.vault.PutCAS(ctx, stagePath, data, 0)
	delete(data, "password")
	delete(data, "username")
	if putErr == nil {
		return candidate, version, nil
	}
	// The Vault response may be lost after a committed write. Resolve by exact
	// read-back in memory; never persist or log either value.
	readData, readVersion, readErr := s.vault.Get(ctx, stagePath)
	if readErr != nil {
		clear(candidate.Secret)
		return adapter.Credential{}, 0, requestError(http.StatusBadGateway, "failed to stage admin credential in vault")
	}
	staged, parseErr := adminCredentialFromVault(readData)
	if parseErr != nil {
		clear(candidate.Secret)
		return adapter.Credential{}, 0, requestError(http.StatusConflict, "staged admin credential is incomplete")
	}
	if candidate.Username != staged.Username || subtle.ConstantTimeCompare(candidate.Secret, staged.Secret) != 1 {
		clear(candidate.Secret)
		clear(staged.Secret)
		return adapter.Credential{}, 0, requestError(http.StatusConflict, "request_id already owns a different staged credential")
	}
	clear(candidate.Secret)
	return staged, readVersion, nil
}

func adminCredentialFromVault(data map[string]any) (adapter.Credential, error) {
	username, ok := data["username"].(string)
	if !ok || username == "" {
		return adapter.Credential{}, errors.New("admin credential username is missing")
	}
	password, ok := data["password"].(string)
	if !ok || password == "" {
		return adapter.Credential{}, errors.New("admin credential password is missing")
	}
	return adapter.Credential{Kind: "password", Username: username, Secret: []byte(password)}, nil
}

func sameProvidedCredential(candidate adapter.Credential, input stagedAdminCredentialInput,
	mode admincredentials.Mode, current adapter.Credential) bool {
	wantUsername := input.Username
	if mode == admincredentials.ModeRotate {
		wantUsername = current.Username
	}
	return candidate.Username == wantUsername &&
		subtle.ConstantTimeCompare(candidate.Secret, []byte(input.Password)) == 1
}

func (s *Server) respondAdminCredentialRequestError(ctx context.Context, w http.ResponseWriter, err error) {
	var reqErr *adminCredentialRequestError
	if errors.As(err, &reqErr) {
		respondError(w, reqErr.status, reqErr.message)
		return
	}
	respondStoreError(ctx, w, err)
}

func (s *Server) cancelConnectionAdminCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req cancelAdminCredentialRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if req.RequestID == uuid.Nil || req.UpdatedAt.IsZero() {
		respondError(w, http.StatusBadRequest, "request_id and updated_at are required")
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
	if err := locks.AcquireTx(ctx, tx, connectionID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	conn, err := s.connections.Get(ctx, tx, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	change, err := s.adminCredentialChanges.Active(ctx, tx, connectionID)
	if errors.Is(err, admincredentials.ErrNotFound) {
		latest, latestErr := s.adminCredentialChanges.Latest(ctx, tx, connectionID)
		if latestErr == nil && latest.Phase == admincredentials.PhaseCancelled &&
			latest.CancelRequestID != nil && *latest.CancelRequestID == req.RequestID {
			if cleanupErr := s.cleanupTerminalAdminCredentialStage(ctx, latest); cleanupErr != nil {
				slog.WarnContext(ctx, "api: cleanup cancelled admin credential stage deferred",
					"connection_id", connectionID, "operation_id", latest.OperationID, "error", cleanupErr)
			}
			respondJSON(w, http.StatusAccepted, adminCredentialOperationResponse{OperationID: latest.OperationID})
			return
		}
		respondError(w, http.StatusConflict, "there is no active admin credential change")
		return
	}
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !conn.UpdatedAt.Equal(req.UpdatedAt) {
		respondStoreError(ctx, w, connections.ErrVersionConflict)
		return
	}
	if !change.CancelAllowed() {
		respondError(w, http.StatusConflict, "admin credential change can no longer be cancelled safely")
		return
	}
	op, err := s.operations.Get(ctx, tx, change.OperationID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	switch op.Status {
	case operations.StatusPending, operations.StatusPendingApproval, operations.StatusRunning, operations.StatusFailed:
		if _, err := s.operations.Transition(ctx, tx, op.ID, op.Status, operations.StatusCancelled, operations.TransitionOpts{}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	default:
		respondError(w, http.StatusConflict, "credential operation is already finished")
		return
	}
	change, err = s.adminCredentialChanges.RestoreTerminal(ctx, tx, change.OperationID,
		admincredentials.PhaseCancelled, "", &req.RequestID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionAdminCredentialCancelled,
		ConnectionID: &connectionID,
		OperationID:  &change.OperationID,
		Result:       audit.ResultSuccess,
		Metadata: mustJSON(map[string]any{
			"mode":  change.Mode,
			"epoch": change.Epoch,
			"phase": change.Phase,
		}),
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if cleanupErr := s.cleanupTerminalAdminCredentialStage(ctx, change); cleanupErr != nil {
		slog.WarnContext(ctx, "api: cleanup cancelled admin credential stage deferred",
			"connection_id", connectionID, "operation_id", change.OperationID, "error", cleanupErr)
	}
	respondJSON(w, http.StatusAccepted, adminCredentialOperationResponse{OperationID: change.OperationID})
}

func (s *Server) cleanupTerminalAdminCredentialStage(ctx context.Context,
	change admincredentials.Change) error {
	if !change.StageCleanupPending {
		return nil
	}
	if s.vault == nil {
		return errors.New("vault is not configured")
	}
	if err := s.vault.DeleteMetadata(ctx, change.StageVaultPath); err != nil &&
		!errors.Is(err, vault.ErrNotFound) {
		return err
	}
	return s.adminCredentialChanges.MarkStageCleaned(ctx, s.pool, change.OperationID)
}

func mustJSON(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}
