package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

const KindCredentialVerify = "credential.verify"

type CredentialVerifyPayload struct {
	AccountID           uuid.UUID               `json:"account_id"`
	RequestID           uuid.UUID               `json:"request_id"`
	Status              inventory.AccountStatus `json:"expected_status"`
	LifecycleVersion    int64                   `json:"expected_lifecycle_version"`
	CanonicalVersion    int                     `json:"canonical_version"`
	ProofVersion        int                     `json:"proof_version"`
	Reconcile           bool                    `json:"reconcile"`
	ConfigIncarnation   string                  `json:"config_incarnation"`
	TargetIdentity      string                  `json:"target_identity"`
	EngineIdentity      string                  `json:"engine_identity"`
	AuthenticationScope string                  `json:"authentication_scope"`
	CredentialPath      string                  `json:"credential_path"`
	PrincipalID         uuid.UUID               `json:"principal_id"`
}

type CredentialVerificationReceipt struct {
	CredentialProved       bool      `json:"credential_proved"`
	Reconciled             bool      `json:"reconciled"`
	VaultVersion           int       `json:"vault_version"`
	LifecycleVersion       int64     `json:"lifecycle_version"`
	VerifiedAt             time.Time `json:"verified_at"`
	ConfigIncarnation      string    `json:"config_incarnation"`
	TargetIdentity         string    `json:"target_identity"`
	EngineIdentity         string    `json:"engine_identity"`
	PrincipalID            uuid.UUID `json:"principal_id"`
	AuthenticationScope    string    `json:"authentication_scope"`
	CredentialPath         string    `json:"credential_path"`
	ApplicationAccessReady bool      `json:"application_access_ready"`
}

func (p CredentialVerifyPayload) valid() bool {
	return p.RequestID != uuid.Nil && p.AccountID != uuid.Nil && p.Status == inventory.AccountActive &&
		p.LifecycleVersion > 0 && p.CanonicalVersion >= 0 && p.ConfigIncarnation != "" && p.TargetIdentity != "" &&
		p.EngineIdentity != "" && p.CredentialPath != "" && ((p.Reconcile && p.ProofVersion == 1) || (!p.Reconcile && p.ProofVersion == 0 && p.CanonicalVersion > 0))
}

func (p CredentialVerifyPayload) checkAccount(a inventory.Account) error {
	if err := inventory.CheckAccountLifecycle(a, p.Status, p.LifecycleVersion); err != nil {
		return err
	}
	principal := uuid.Nil
	if a.PrincipalID != nil {
		principal = *a.PrincipalID
	}
	if a.ID != p.AccountID || a.Ownership != inventory.OwnershipManaged || a.Kind != "login" || a.Status != inventory.AccountActive ||
		a.VaultPath != p.CredentialPath || a.EngineIdentity != p.EngineIdentity || a.AuthenticationScope != p.AuthenticationScope || principal != p.PrincipalID {
		return errors.New("credential verification: account intent changed")
	}
	if p.Reconcile && a.VaultPath != "accounts/"+a.ID.String()+"/credential" {
		return errors.New("credential verification: shared credential cannot be reconciled per account")
	}
	return nil
}

func (p CredentialVerifyPayload) checkConnection(c connections.Connection) error {
	var principal *uuid.UUID
	if p.PrincipalID != uuid.Nil {
		principal = &p.PrincipalID
	}
	if !credentials.VerificationPathAllowed(p.AccountID, principal, c.Environment, p.CredentialPath, p.Reconcile) {
		return errors.New("credential verification: credential reference is outside account scope")
	}
	if connections.ConfigIncarnation(c) != p.ConfigIncarnation || connections.TargetIdentity(c) != p.TargetIdentity {
		return errors.New("credential verification: connection incarnation changed")
	}
	if c.Status != connections.StatusActive || c.AuthMode == "none" ||
		!slices.Contains(connections.EffectiveCapabilities(c, c.Capabilities), string(adapter.CapCredentialProve)) {
		return errors.New("credential verification: connection does not admit credential proof")
	}
	return nil
}

func (e *MainExecutor) executeCredentialVerify(ctx context.Context, op operations.Operation) error {
	var p CredentialVerifyPayload
	if json.Unmarshal(op.Payload, &p) != nil || !p.valid() || op.ID == uuid.Nil || op.AccountID == nil || *op.AccountID != p.AccountID || op.ConnectionID == nil {
		return terminal(errors.New("credential verification: invalid payload"))
	}
	if e.deps.Pool == nil || e.deps.Inventory == nil || e.deps.Connections == nil || e.deps.Audit == nil || e.mut.Credentials == nil {
		return errors.New("credential verification: dependencies unavailable")
	}
	cleanup := func() error {
		if p.Reconcile {
			return e.mut.Credentials.DeleteVerificationProof(ctx, p.AccountID, op.ID)
		}
		return nil
	}
	reject := func(cause error) error {
		if err := cleanup(); err != nil {
			return err
		}
		return terminal(cause)
	}
	// The audit receipt is committed before operation-engine acknowledgement.
	// Replay it even if a later lifecycle/configuration change superseded it.
	receipts, err := e.deps.Audit.List(ctx, e.deps.Pool, audit.Filter{OperationID: &op.ID, Actions: []string{"credential.verified"}}, 1, 0)
	if err != nil {
		return err
	}
	if len(receipts) != 0 {
		if err := cleanup(); err != nil {
			return err
		}
		e.setResultArtifact(op.ID, receipts[0].Metadata)
		return nil
	}
	a, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, p.AccountID)
	if err != nil {
		return err
	}
	if *op.ConnectionID != a.ConnectionID {
		return reject(errors.New("credential verification: account connection changed"))
	}
	if err := p.checkAccount(a); err != nil {
		return reject(err)
	}
	c, err := e.deps.Connections.Get(ctx, e.deps.Pool, a.ConnectionID)
	if err != nil {
		return err
	}
	if err := p.checkConnection(c); err != nil {
		return reject(err)
	}
	if c.ExecutionMode == connections.ExecutionModeConnector {
		if err := e.requireActiveConnectorCapability(connector.CapCredentialProofV1); err != nil {
			return errors.New("credential verification: compatible connector unavailable")
		}
	}
	conn, cfg, ad, via, err := e.mutationTarget(ctx, op.Kind, a.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return errors.New("credential verification: target unavailable")
	}
	if err := p.checkConnection(conn); err != nil {
		return reject(err)
	}
	prover, err := managedLinkProofAdapter(c.Engine, ad, via)
	if err != nil || !adapter.SupportsCredentialProof(prover) {
		return reject(adapter.ErrCredentialProofUnsupported)
	}
	var username string
	var password []byte
	version := p.CanonicalVersion
	if p.Reconcile {
		username, password, err = e.mut.Credentials.GetVerificationProof(ctx, a.ID, op.ID, p.ProofVersion)
		version = p.ProofVersion
	} else {
		username, password, err = e.mut.Credentials.GetAccountCredentialVersion(ctx, a.VaultPath, a.EngineIdentity, p.CanonicalVersion)
	}
	defer clear(password)
	if err != nil {
		return errors.New("credential verification: pinned credential unavailable")
	}
	if username != a.EngineIdentity {
		return reject(errors.New("credential verification: credential identity mismatch"))
	}
	cred := adapter.Credential{Kind: "password", Username: username, Secret: password}
	if via {
		err = e.connectorProveCredential(ctx, op, conn, cfg, a, cred, version)
	} else {
		err = prover.(adapter.CredentialProver).ProveCredential(ctx, cfg, adapterAccount(a), cred)
	}
	if err != nil {
		if errors.Is(err, adapter.ErrExternalIdentityConflict) || errors.Is(err, adapter.ErrCredentialProofAccessDenied) || errors.Is(err, adapter.ErrCredentialProofUnsupported) {
			return reject(errors.New("credential verification: password or login admission rejected"))
		}
		return errors.New("credential verification: target unavailable")
	}

	// Hold the account row through the Vault CAS and audit commit so that an
	// offboard/ownership change during proof cannot promote the candidate.
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `select id from connections where id=$1 for share`, a.ConnectionID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `select id from accounts where id=$1 for update`, a.ID); err != nil {
		return err
	}
	latest, err := e.deps.Inventory.GetAccount(ctx, tx, a.ID)
	if err != nil {
		return err
	}
	if err := p.checkAccount(latest); err != nil {
		return reject(err)
	}
	latestConnection, err := e.deps.Connections.Get(ctx, tx, a.ConnectionID)
	if err != nil {
		return err
	}
	if err := p.checkConnection(latestConnection); err != nil {
		return reject(err)
	}
	if p.Reconcile {
		version, err = e.mut.Credentials.ReconcileAccountCredentialCAS(ctx, a.ID, op.ID, username, password, p.CanonicalVersion)
		if errors.Is(err, credentials.ErrCredentialVersionConflict) {
			return reject(err)
		}
		if err != nil {
			return err
		}
	} else {
		current, present, getErr := e.mut.Credentials.CredentialMetadata(ctx, a.VaultPath)
		if getErr != nil {
			return errors.New("credential verification: canonical credential unavailable")
		}
		if !present || current != p.CanonicalVersion {
			return reject(credentials.ErrCredentialVersionConflict)
		}
		version = current
	}
	metadata, err := json.Marshal(CredentialVerificationReceipt{CredentialProved: true, Reconciled: p.Reconcile,
		VaultVersion: version, LifecycleVersion: p.LifecycleVersion, VerifiedAt: time.Now().UTC(), ConfigIncarnation: p.ConfigIncarnation,
		TargetIdentity: p.TargetIdentity, EngineIdentity: p.EngineIdentity, PrincipalID: p.PrincipalID, AuthenticationScope: p.AuthenticationScope,
		CredentialPath: p.CredentialPath, ApplicationAccessReady: false})
	if err != nil {
		return err
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{ActorType: op.ActorType, ActorID: op.ActorID, Action: "credential.verified",
		ConnectionID: &a.ConnectionID, AccountID: &a.ID, OperationID: &op.ID, Result: audit.ResultSuccess, Metadata: metadata}); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	if err := cleanup(); err != nil {
		return err
	}
	e.setResultArtifact(op.ID, metadata)
	return nil
}
