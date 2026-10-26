package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

const KindPostgresAccountProvisionV1 = "postgres.account.provision.v1"
const KindPostgresAccountVerifyCreationV1 = "postgres.account.verify_creation.v1"

var ErrAccountCreationUnknown = errors.New("account creation outcome is unknown; automatic creation and verification are blocked")

// AccountCreationReceiptMatches checks the immutable intent without target or Vault access.
func AccountCreationReceiptMatches(r accountcreation.Receipt, acct inventory.Account, p AccountPayload) bool {
	path := p.SharedCredentialPath
	if path == "" {
		path = acct.VaultPath
	}
	return p.AccountID == acct.ID && r.AccountID == acct.ID && r.ConnectionID == acct.ConnectionID &&
		r.EngineIdentity == acct.EngineIdentity && r.LifecycleVersion == p.ExpectedLifecycleVersion &&
		r.AdminIdentity == p.ExpectedAdminIdentity && r.TargetIdentity == p.ExpectedTargetIdentity &&
		r.ConfigIncarnation == p.ExpectedConfigIncarnation && r.AdminCredentialIncarnation == p.ExpectedCredentialIncarnation &&
		r.CredentialPath == path && acct.VaultPath == path && r.CredentialVersion > 0 &&
		(p.CredentialVaultVersion == 0 || p.CredentialVaultVersion == r.CredentialVersion)
}

// The outer worker owns the connection lock. Receipt phases survive a lost
// worker commit, but a role lookup can never advance "creating" to "created".
func (e *MainExecutor) executePostgresAccountProvisioning(ctx context.Context, op operations.Operation, verifyOnly bool) (resultErr error) {
	p, err := decodeAccountPayload(op.Payload)
	if err != nil {
		return err
	}
	if op.AccountID == nil || op.ConnectionID == nil || *op.AccountID != p.AccountID ||
		p.ExpectedStatus != inventory.AccountProvisioning ||
		(verifyOnly && p.CreationOperationID == uuid.Nil) || (!verifyOnly && p.CreationOperationID != uuid.Nil) {
		return terminal(errors.New("invalid account creation identity or source operation"))
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, p.AccountID)
	if err != nil {
		return err
	}
	if acct.ConnectionID != *op.ConnectionID || acct.Kind != inventory.AccountKindLogin || acct.Ownership != inventory.OwnershipManaged {
		return terminal(errors.New("account creation reservation identity changed"))
	}
	sourceID := op.ID
	if verifyOnly {
		sourceID = p.CreationOperationID
	}
	store := accountcreation.NewStore()
	r, receiptErr := store.Get(ctx, e.deps.Pool, sourceID)
	if receiptErr != nil && !errors.Is(receiptErr, accountcreation.ErrNotFound) {
		return receiptErr
	}
	if receiptErr == nil && !AccountCreationReceiptMatches(r, acct, p) {
		return terminal(errors.New("account creation receipt does not match the reserved intent"))
	}
	if verifyOnly {
		source, sourceErr := operations.NewStore().Get(ctx, e.deps.Pool, sourceID)
		if sourceErr != nil {
			return terminal(errors.New("original creation operation is unavailable"))
		}
		var original AccountPayload
		requested := p
		requested.CreationOperationID = uuid.Nil
		if source.Kind != KindPostgresAccountProvisionV1 || source.Status != operations.StatusFailed ||
			source.AccountID == nil || *source.AccountID != acct.ID || source.ConnectionID == nil || *source.ConnectionID != acct.ConnectionID ||
			json.Unmarshal(source.Payload, &original) != nil || !reflect.DeepEqual(original, requested) {
			return terminal(errors.New("original creation intent changed; verification is blocked"))
		}
		var busy bool
		if err := e.deps.Pool.QueryRow(ctx, `select exists (
   select 1 from operations where account_id=$1 and id<>$2 and status in ('pending_approval','pending','running','partial')
  ) or exists (
   select 1 from river_job j join operations o on
    j.args->>'operation_id'=o.id::text or (j.args->'next_operation_ids') ? o.id::text
   where o.account_id=$1 and o.id<>$2 and j.state not in ('completed','cancelled','discarded')
  )`, acct.ID, op.ID).Scan(&busy); err != nil {
			return err
		}
		if busy {
			return terminal(errors.New("another account operation is still running"))
		}
	}
	if receiptErr == nil && r.Phase == "verified" && acct.Status == inventory.AccountActive && acct.LifecycleVersion == r.LifecycleVersion {
		return nil // Account activation, receipt and audit committed together.
	}
	if err := inventory.CheckAccountLifecycle(acct, p.ExpectedStatus, p.ExpectedLifecycleVersion); err != nil {
		return terminal(err)
	}
	if verifyOnly && (receiptErr != nil || r.Phase != "created") {
		return terminal(errors.New("account creation has no confirmed receipt to verify"))
	}
	if receiptErr == nil && r.Phase == "creating" {
		return terminal(ErrAccountCreationUnknown)
	}
	if receiptErr == nil && r.Phase != "planned" && r.Phase != "created" {
		return terminal(accountcreation.ErrConflict)
	}
	if acct.PrincipalID != nil {
		var active bool
		if err := e.deps.Pool.QueryRow(ctx, `select status='active' and coalesce(external_identity_status='active',true) from principals where id=$1`, *acct.PrincipalID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return terminal(errors.New("account principal is not active"))
		}
	}
	// The exact connector session is checked again by Dispatch. Do this first,
	// before resolving either admin or account credentials.
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, acct.ConnectionID)
	if err != nil {
		return err
	}
	viaConnector, err := connectorRoute(conn.ExecutionMode, op.Kind, e.conn.Dispatcher != nil)
	if err != nil {
		return err
	}
	if viaConnector {
		if err := e.requireActiveConnectorCapability(adapter.CapPostgresAccountCreationV1); err != nil {
			return err
		}
		if err := e.requireActiveConnectorCapability(adapter.CapPostgresSuperuserDirectV1); err != nil {
			return err
		}
	}
	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return err
	}
	if err := validatePostgresRuntimePins(conn, cfg, p.ExpectedAdminIdentity, p.ExpectedTargetIdentity,
		p.ExpectedConfigIncarnation, p.ExpectedCredentialIncarnation); err != nil {
		return err
	}
	if e.mut.Credentials == nil {
		return errors.New("credentials service is not configured")
	}
	path := p.SharedCredentialPath
	if path == "" {
		path = acct.VaultPath
	}
	username, password, version, err := e.mut.Credentials.GetAccountCredentialSnapshot(ctx, path, acct.EngineIdentity)
	defer clear(password)
	if err != nil {
		return err
	}
	if username != acct.EngineIdentity || (receiptErr == nil && version != r.CredentialVersion) ||
		(p.CredentialVaultVersion > 0 && version != p.CredentialVaultVersion) {
		return terminal(errors.New("account credential incarnation changed; verification is blocked"))
	}
	if receiptErr != nil {
		r = accountcreation.Receipt{OperationID: sourceID, AccountID: acct.ID, ConnectionID: acct.ConnectionID,
			EngineIdentity: acct.EngineIdentity, TargetIdentity: p.ExpectedTargetIdentity, AdminIdentity: p.ExpectedAdminIdentity,
			ConfigIncarnation: p.ExpectedConfigIncarnation, AdminCredentialIncarnation: p.ExpectedCredentialIncarnation,
			LifecycleVersion: p.ExpectedLifecycleVersion, CredentialPath: path, CredentialVersion: version, Phase: "planned"}
		if err := store.Create(ctx, e.deps.Pool, r); err != nil {
			return err
		}
	}
	// Snapshot returned bytes and KV version atomically. The version checks
	// above pin these owned bytes; fetching the same version again adds no proof.
	credential := adapter.Credential{Kind: "password", Username: username, Secret: password}
	change := adapter.DesiredChange{Kind: adapter.ChangePostgresAccountCreateV2, Connection: cfg,
		Account: adapterAccount(acct), Credential: &credential, ExpectedAdminIdentity: p.ExpectedAdminIdentity,
		ExpectedTargetIdentity: p.ExpectedTargetIdentity}
	defer func() {
		if resultErr != nil {
			if auditErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, auditActionAccountCreateFailed, resultErr); auditErr != nil {
				resultErr = errors.Join(resultErr, auditErr)
			}
		}
	}()
	stage := func(stage string, proof *adapter.AccountCreationProof) (*adapter.AccountCreationProof, error) {
		if viaConnector {
			return e.connectorAccountCreationStage(ctx, op, conn, cfg, acct, change, stage, proof, r.CredentialVersion)
		}
		provisioner, ok := ad.(adapter.AccountCreationProvisioner)
		if !ok || !ad.Manifest().HasCapability(adapter.CapPostgresAccountCreationV1) {
			return nil, terminal(errors.New("proof-carrying account creation is unsupported"))
		}
		switch stage {
		case "preflight":
			return nil, provisioner.PreflightAccountCreation(ctx, change)
		case "create":
			return provisioner.CreateAccountWithProof(ctx, change)
		case "verify":
			return proof, provisioner.VerifyCreatedAccount(ctx, change, *proof)
		default:
			return nil, terminal(errors.New("unknown account creation stage"))
		}
	}
	if r.Phase == "planned" {
		if _, err := stage("preflight", nil); err != nil {
			return accountCreationStageError(err)
		}
		if err := store.Begin(ctx, e.deps.Pool, sourceID); err != nil {
			return err
		}
		proof, err := stage("create", nil)
		if err != nil || proof == nil || proof.RoleOID == 0 || proof.EngineIdentity != acct.EngineIdentity || proof.TargetIdentity != r.TargetIdentity {
			return terminal(ErrAccountCreationUnknown)
		}
		if err := store.Confirm(ctx, e.deps.Pool, sourceID, proof.RoleOID); err != nil {
			return err
		}
		r.RoleOID, r.Phase = proof.RoleOID, "created"
	}
	proof := adapter.AccountCreationProof{EngineIdentity: r.EngineIdentity, RoleOID: r.RoleOID, TargetIdentity: r.TargetIdentity}
	if _, err := stage("verify", &proof); err != nil {
		return accountCreationStageError(err)
	}
	// A canonical credential change during the proof also blocks promotion.
	_, latestPassword, latestVersion, err := e.mut.Credentials.GetAccountCredentialSnapshot(ctx, path, acct.EngineIdentity)
	clear(latestPassword)
	if err != nil {
		return err
	}
	if latestVersion != r.CredentialVersion {
		return terminal(errors.New("account credential incarnation changed during verification"))
	}
	metadata, err := json.Marshal(map[string]any{"account": acct.EngineIdentity, "role_oid": r.RoleOID,
		"source_operation_id": sourceID, "credential_proved": true, "verification_only": verifyOnly})
	if err != nil {
		return err
	}
	wrap := func(err error) error { return fmt.Errorf("jobs: account provisioning operation %s: %w", op.ID, err) }
	return e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, auditActionAccountCreated, metadata, wrap, func(tx pgx.Tx) error {
		var lockedID uuid.UUID
		if err := tx.QueryRow(ctx, `select id from accounts where id=$1 for update`, acct.ID).Scan(&lockedID); err != nil {
			return err
		}
		current, err := e.deps.Inventory.GetAccount(ctx, tx, acct.ID)
		if err != nil {
			return err
		}
		if current.Ownership != inventory.OwnershipManaged || current.Kind != inventory.AccountKindLogin ||
			!AccountCreationReceiptMatches(r, current, p) || !reflect.DeepEqual(current.PrincipalID, acct.PrincipalID) {
			return terminal(errors.New("account creation reservation changed during verification"))
		}
		if current.PrincipalID != nil {
			var active bool
			if err := tx.QueryRow(ctx, `select status='active' and coalesce(external_identity_status='active',true)
    from principals where id=$1 for share`, *current.PrincipalID).Scan(&active); err != nil {
				return err
			}
			if !active {
				return terminal(errors.New("account principal changed during verification"))
			}
		}
		if err := e.deps.Inventory.SetAccountStatusGuarded(ctx, tx, acct.ID, inventory.AccountProvisioning, inventory.AccountActive, r.LifecycleVersion); err != nil {
			return err
		}
		if err := e.deps.Inventory.SetAccountCredentialVersion(ctx, tx, acct.ID, r.CredentialVersion); err != nil {
			return err
		}
		return store.Complete(ctx, tx, sourceID, op.ID)
	})
}

func accountCreationStageError(err error) error {
	if errors.Is(err, adapter.ErrCredentialProofAccessDenied) || errors.Is(err, adapter.ErrCredentialProofUnsupported) ||
		errors.Is(err, adapter.ErrExternalIdentityConflict) || errors.Is(err, adapter.ErrTargetIdentityConflict) {
		return terminal(err)
	}
	return err
}

func (e *MainExecutor) connectorAccountCreationStage(ctx context.Context, op operations.Operation, conn connections.Connection,
	cfg adapter.Connection, acct inventory.Account, change adapter.DesiredChange, stage string, proof *adapter.AccountCreationProof, version int) (*adapter.AccountCreationProof, error) {
	ref, tls, attrs := connectorConnectionParts(conn, cfg)
	payload, err := json.Marshal(connector.AccountCreationPayload{Stage: stage, AccountID: acct.ID.String(), Proof: proof,
		Request: connector.MutationPayload{Connection: ref, TLS: tls, Attributes: attrs,
			Change: connector.ChangeRef{Kind: string(change.Kind), Account: connectorAccountRef(acct),
				ExpectedAdminIdentity: change.ExpectedAdminIdentity, ExpectedTargetIdentity: change.ExpectedTargetIdentity}}})
	if err != nil {
		return nil, err
	}
	idem := fmt.Sprintf("op:%s:account-create:%s", op.ID, stage)
	if stage != "create" {
		idem += ":" + uuid.NewString()
	}
	job := connectorJobBase(op, conn, connector.JobAccountCreation, idem, payload, time.Now())
	creds := connectorJobCredentials(cfg)
	credential := *change.Credential
	credential.Secret = append([]byte(nil), credential.Secret...)
	creds.Account, creds.AccountVaultVersion = &credential, version
	res, err := e.connectorDispatch(ctx, job, creds)
	if err != nil || res.JobID != job.ID {
		return nil, errors.New("account provisioning connector is unavailable")
	}
	if res.Status != connector.JobSuccess {
		switch res.ErrorCode {
		case "credential_access_denied":
			return nil, adapter.ErrCredentialProofAccessDenied
		case "credential_proof_unsupported", "account_creation_unsupported":
			return nil, adapter.ErrCredentialProofUnsupported
		case "credential_identity_conflict", "credential_identity_mismatch":
			return nil, adapter.ErrExternalIdentityConflict
		case "target_identity_changed":
			return nil, adapter.ErrTargetIdentityConflict
		default:
			return nil, errors.New("account provisioning target is unavailable")
		}
	}
	out, err := connector.ParseAccountCreationOutcome(res.Result)
	if err != nil || out.Stage != stage || out.AccountID != acct.ID.String() || out.VaultVersion != version ||
		(stage != "preflight" && (out.Proof == nil || out.Proof.RoleOID == 0 || out.Proof.EngineIdentity != acct.EngineIdentity ||
			out.Proof.TargetIdentity != change.ExpectedTargetIdentity || (proof != nil && *out.Proof != *proof))) ||
		(stage == "preflight" && out.Proof != nil) {
		return nil, errors.New("account provisioning result does not match the reserved intent")
	}
	return out.Proof, nil
}
