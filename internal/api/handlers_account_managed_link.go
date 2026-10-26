package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

const auditActionAccountManagedLinkRequested = "account.managed_link_requested"

var errManagedLinkCredentialChoiceRequired = errors.New("credential is required when principal has no credential in this environment")

type linkAndManageAccountRequest struct {
	PrincipalID uuid.UUID                 `json:"principal_id"`
	Credential  *restoreCredentialRequest `json:"credential"`
}

func (req *linkAndManageAccountRequest) validate() error {
	if req.PrincipalID == uuid.Nil {
		return errors.New("principal_id is required")
	}
	if req.Credential == nil {
		return nil
	}
	return (&restoreAccountRequest{Credential: req.Credential}).validate()
}

func managedLinkIdempotencyKey(accountID, principalID uuid.UUID, version int64) string {
	return fmt.Sprintf("account-managed-link:%s:%s:v%d", accountID, principalID, version)
}

// linkAndManageAccount сохраняет shared credential (если это первая учётка
// principal в environment) и ставит credential.rotate. Password provided-
// режима существует только в памяти этого handler и Vault callback.
func (s *Server) linkAndManageAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req linkAndManageAccountRequest
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

	acct, err := s.inventory.GetAccount(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	p, err := s.principals.Get(ctx, s.pool, req.PrincipalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if msg := principalStatusBlocks(p.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Повтор уже принятого HTTP-запроса возвращает ту же durable operation,
	// включая retry после terminal success, когда account уже managed.
	key := managedLinkIdempotencyKey(acct.ID, req.PrincipalID, acct.LifecycleVersion)
	if existing, getErr := s.operations.GetByIdempotencyKey(ctx, s.pool, key); getErr == nil && existing.Status != operations.StatusFailed && existing.Status != operations.StatusCancelled {
		respondJSON(w, http.StatusAccepted, map[string]any{
			"account_id": acct.ID, "principal_id": req.PrincipalID,
			"environment": conn.Environment, "operation_id": existing.ID,
		})
		return
	}
	if acct.Status != inventory.AccountActive || acct.Kind != "login" {
		respondError(w, http.StatusConflict, "only an active login account can be linked and managed")
		return
	}
	if acct.Ownership != inventory.OwnershipUnmanaged && acct.Ownership != inventory.OwnershipManaged {
		respondError(w, http.StatusConflict, "account ownership does not allow link-and-manage")
		return
	}
	if acct.PrincipalID != nil && *acct.PrincipalID != req.PrincipalID {
		respondError(w, http.StatusConflict, "account is linked to another principal")
		return
	}
	// Тот же запрет, что у adopt: под этой учёткой grantor управляет самим
	// подключением, и link-and-manage сменил бы ей пароль, не обновив admin
	// credential — управление подключением сломалось бы целиком. Без гейта
	// здесь скрытие кнопки в UI обходится прямым вызовом API.
	if adapter.AttrBool(decodeAttributes(acct.Attributes), adapter.AttrConnectionAdmin) {
		respondError(w, http.StatusConflict,
			"account is the admin credential of its connection and cannot be managed: "+
				"managing it would break grantor's own access to the connection")
		return
	}
	// Граница с rotate {"attach":true}: link-and-manage — путь принятия ещё
	// не управляемой учётки (связать с принципалом и посадить на его общий
	// пароль). Возврат УЖЕ управляемого и уже связанного аккаунта на общий
	// пароль делает ротация с намерением attach: она не трогает ownership,
	// не заводит новый общий секрет и проходит те же гарды принципала.
	// Держать два механизма одного действия — гарантированное расхождение
	// поведения, поэтому здесь путь один.
	if acct.Ownership == inventory.OwnershipManaged && acct.PrincipalID != nil {
		respondError(w, http.StatusConflict,
			"account is already managed and linked to this principal; "+
				`put it back on the shared credential with POST /api/v1/accounts/{id}/rotate {"attach": true}`)
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, "connection must be active")
		return
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil || !ad.Manifest().HasCapability(adapter.CapCredentialRotate) || !adapter.SupportsCredentialProof(ad) {
		respondError(w, http.StatusConflict, "credential rotation with proof is unsupported for this connection engine")
		return
	}
	if !adapter.HasManagedCredentialCapabilities(conn.Capabilities) {
		respondError(w, http.StatusConflict, "credential rotation with proof is not enabled for this connection")
		return
	}
	if conn.ExecutionMode != connections.ExecutionModeConnector {
		if _, ok := ad.(adapter.CredentialProver); !ok {
			respondError(w, http.StatusConflict, "credential proof is unsupported for this connection engine")
			return
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	conn, ok = s.lockCredentialConnection(w, r, tx, acct.ConnectionID, adapter.CapCredentialRotate)
	if !ok {
		return
	}
	if err := requireConnectionCapability(conn, adapter.CapCredentialProve); err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	var provided []byte
	if req.Credential != nil && req.Credential.Mode == credentialModeProvided {
		provided = []byte(req.Credential.Password)
		defer clear(provided)
	}
	sharedPath, credentialCreated, err := s.credentials.EnsurePrincipalCredential(ctx, req.PrincipalID, conn.Environment, func() ([]byte, error) {
		if req.Credential == nil {
			return nil, errManagedLinkCredentialChoiceRequired
		}
		if req.Credential.Mode == credentialModeProvided {
			out := append([]byte(nil), provided...)
			return out, nil
		}
		return credentials.GeneratePassword(credentials.DefaultPasswordLength)
	})
	if err != nil {
		if errors.Is(err, errManagedLinkCredentialChoiceRequired) {
			respondError(w, http.StatusBadRequest, errManagedLinkCredentialChoiceRequired.Error())
			return
		}
		if errors.Is(err, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable, "vault is not configured: cannot store principal credential")
			return
		}
		slog.ErrorContext(ctx, "api: ensure managed link credential", "account_id", acct.ID, "principal_id", req.PrincipalID, "error", err)
		respondError(w, http.StatusBadGateway, "failed to prepare principal credential in vault")
		return
	}
	credentialSource := "existing"
	if credentialCreated {
		credentialSource = req.Credential.Mode
	}

	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, inventory.AccountActive)
	if err != nil {
		// Конкурентный identical request мог уже зарезервировать следующее
		// поколение и создать operation, пока этот запрос готовил Vault. После
		// ожидания row lock возвращаем победителя вместо ложного 409.
		if current, getErr := s.inventory.GetAccount(ctx, s.pool, acct.ID); getErr == nil {
			concurrentKey := managedLinkIdempotencyKey(acct.ID, req.PrincipalID, current.LifecycleVersion)
			if existing, opErr := s.operations.GetByIdempotencyKey(ctx, s.pool, concurrentKey); opErr == nil && existing.Status != operations.StatusFailed && existing.Status != operations.StatusCancelled {
				respondJSON(w, http.StatusAccepted, map[string]any{
					"account_id": acct.ID, "principal_id": req.PrincipalID,
					"environment": conn.Environment, "operation_id": existing.ID,
				})
				return
			}
		}
		respondStoreError(ctx, w, err)
		return
	}
	key = managedLinkIdempotencyKey(acct.ID, req.PrincipalID, reserved.LifecycleVersion)
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, ExpectedStatus: inventory.AccountActive,
		ExpectedLifecycleVersion: reserved.LifecycleVersion, SharedCredentialPath: sharedPath,
		ManagedLinkPrincipalID: &req.PrincipalID,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindCredentialRotate, IdempotencyKey: &key,
		ConnectionID: &acct.ConnectionID, PrincipalID: &req.PrincipalID, AccountID: &acct.ID,
		Payload: payload, ActorType: sess.ActorType(), ActorID: sess.ActorID(), CorrelationID: uuid.NewString(),
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
		ActorType: sess.ActorType(), ActorID: sess.ActorID(), Action: auditActionAccountManagedLinkRequested,
		ConnectionID: &acct.ConnectionID, PrincipalID: &req.PrincipalID, AccountID: &acct.ID,
		OperationID: &op.ID, Result: audit.ResultSuccess,
	}, map[string]any{
		"engine_identity": acct.EngineIdentity, "environment": conn.Environment,
		"credential_source": credentialSource, "principal_display_name": p.DisplayName,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"account_id": acct.ID, "principal_id": req.PrincipalID, "environment": conn.Environment, "operation_id": op.ID,
	})
}
