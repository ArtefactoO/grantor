package jobs

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const (
	auditActionAdminCredentialSwitched = "connection.admin_credential_switched"
	auditActionAdminCredentialRotated  = "connection.admin_credential_rotated"
	auditActionAdminCredentialFailed   = "connection.admin_credential_change_failed"
)

type adminCredentialVault interface {
	VaultReader
	GetVersion(ctx context.Context, path string, version int) (map[string]any, error)
	PutCAS(ctx context.Context, path string, data map[string]any, expectedVersion int) (int, error)
	DeleteMetadata(ctx context.Context, path string) error
}

type adminCredentialTargetOutcome struct {
	Proof          adapter.AdminCredentialProof
	AlreadyApplied bool
	Snapshot       *adapter.Snapshot
}

type adminCredentialResultArtifact struct {
	Mode                  admincredentials.Mode        `json:"mode"`
	Epoch                 int64                        `json:"epoch"`
	CanonicalVaultVersion int                          `json:"canonical_vault_version"`
	AlreadyApplied        bool                         `json:"already_applied,omitempty"`
	Proof                 adapter.AdminCredentialProof `json:"proof,omitempty"`
}

func (e *MainExecutor) executeConnectionAdminCredentialChange(ctx context.Context, op operations.Operation) error {
	if op.ConnectionID == nil {
		return terminal(fmt.Errorf("jobs: admin credential operation %s has no connection id", op.ID))
	}
	payload, err := ParseAdminCredentialOperationPayload(op.Payload)
	if err != nil {
		return terminal(err)
	}
	wantMode := admincredentials.ModeSwitch
	if op.Kind == KindConnectionAdminCredentialRotate {
		wantMode = admincredentials.ModeRotate
	}
	if payload.Mode != wantMode {
		return terminal(fmt.Errorf("jobs: admin credential operation kind/mode mismatch"))
	}

	store := admincredentials.NewStore()
	change, err := store.Get(ctx, e.deps.Pool, op.ID)
	if err != nil {
		return fmt.Errorf("jobs: load admin credential change: %w", err)
	}
	if change.ConnectionID != *op.ConnectionID || change.Mode != payload.Mode || change.Epoch != payload.Epoch {
		return terminal(fmt.Errorf("jobs: admin credential operation is stale: %w", admincredentials.ErrStaleOperation))
	}
	switch change.Phase {
	case admincredentials.PhaseCompleted:
		return e.restoreAdminCredentialCompletionArtifact(ctx, op.ID, change)
	case admincredentials.PhaseFailed, admincredentials.PhaseCancelled:
		return terminal(fmt.Errorf("jobs: admin credential change is already %s", change.Phase))
	}

	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, change.ConnectionID)
	if err != nil {
		return fmt.Errorf("jobs: load admin credential connection: %w", err)
	}
	if conn.Status != connections.StatusCredentialUpdating {
		return terminal(fmt.Errorf("jobs: admin credential connection status %q is stale: %w",
			conn.Status, admincredentials.ErrStaleOperation))
	}
	viaConnector, err := connectorRoute(conn.ExecutionMode, op.Kind, e.conn.Dispatcher != nil)
	if err != nil {
		return e.recordAdminCredentialRetryableError(ctx, change, "connector_unavailable", err)
	}

	if change.CandidateMode == "none" && (conn.Engine != "redis" || change.Mode != admincredentials.ModeSwitch || change.StagedVaultVersion != 0 || change.StageVaultPath != "") {
		return e.closeAdminCredentialBeforeEffect(ctx, op, change, "invalid_candidate", terminal(errors.New("invalid no-auth lifecycle descriptor")))
	}
	vaultClient, vaultOK := e.deps.Vault.(adminCredentialVault)
	candidate := adapter.Credential{Kind: "none", Username: "default"}
	if change.CandidateMode != "none" {
		if !vaultOK || vaultClient == nil {
			return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable",
				errors.New("jobs: admin credential lifecycle requires a CAS-capable Vault client"))
		}
		stageData, err := vaultClient.GetVersion(ctx, change.StageVaultPath, change.StagedVaultVersion)
		if err != nil {
			if change.CanonicalVaultVersion == nil {
				return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable",
					fmt.Errorf("jobs: read exact staged admin credential version: %w", err))
			}
			// Stage cleanup is required before terminal success. If metadata commit
			// then fails, the promoted canonical value is the exact durable candidate
			// and is safe to use for the receipt retry.
			canonicalPath, pathErr := vault.ConnectionAdminPath(change.ConnectionID.String())
			if pathErr != nil {
				return pathErr
			}
			var canonicalVersion int
			stageData, canonicalVersion, err = vaultClient.Get(ctx, canonicalPath)
			if err != nil || canonicalVersion != *change.CanonicalVaultVersion {
				return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable",
					errors.New("jobs: staged credential is absent and promoted canonical recovery failed"))
			}
		}
		candidate, err = credentialFromVault(stageData)
		if err != nil {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, "invalid_candidate",
				terminal(fmt.Errorf("jobs: staged admin credential is incomplete")))
		}
	}
	defer clear(candidate.Secret)

	cfg, err := adapterConnection(conn)
	if err != nil {
		return terminal(err)
	}
	if change.CandidateMode != "none" && (conn.VaultAdminPath != "" || conn.AuthMode == "none") {
		if err := e.applyAdminCredential(ctx, conn, &cfg); err != nil {
			if change.Mode == admincredentials.ModeRotate {
				return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable", err)
			}
			// Switch is the recovery path and does not require a working old
			// credential, but a configured path must still be read safely for
			// connector framing and equality diagnostics.
			cfg.AdminCredential = adapter.Credential{}
		}
	}
	defer clear(cfg.AdminCredential.Secret)
	candidateAlreadyCanonical := sameAdminCredential(candidate, cfg.AdminCredential)
	if change.Mode == admincredentials.ModeRotate &&
		(candidate.Username == "" || candidate.Username != cfg.AdminCredential.Username) {
		return e.closeAdminCredentialBeforeEffect(ctx, op, change, "invalid_candidate",
			terminal(errors.New("jobs: staged rotation identity differs from canonical admin identity")))
	}
	if change.Mode == admincredentials.ModeRotate && candidateAlreadyCanonical &&
		!change.TargetSideEffectPossible {
		return e.closeAdminCredentialBeforeEffect(ctx, op, change, "invalid_candidate",
			terminal(errors.New("jobs: staged rotation credential already equals canonical before target mutation")))
	}
	if change.Mode == admincredentials.ModeRotate && !change.TargetSideEffectPossible {
		canonicalPath, pathErr := vault.ConnectionAdminPath(change.ConnectionID.String())
		if pathErr != nil {
			return pathErr
		}
		if conn.VaultAdminPath != canonicalPath {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, "canonical_version_changed",
				terminal(errors.New("jobs: rotation current credential path is no longer canonical")))
		}
		_, currentVersion, versionErr := vaultClient.Get(ctx, canonicalPath)
		if versionErr != nil {
			return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable", versionErr)
		}
		if currentVersion != change.ExpectedCanonicalVersion {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, "canonical_version_changed",
				terminal(errors.New("jobs: canonical admin credential changed before target mutation")))
		}
	}

	var ad adapter.Adapter
	var manager adapter.ConnectionAdminCredentialManager
	if !viaConnector {
		ad, err = adapter.New(conn.Engine)
		if err != nil {
			return terminal(err)
		}
		var managerOK bool
		manager, managerOK = ad.(adapter.ConnectionAdminCredentialManager)
		if !managerOK {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, "rotation_unsupported",
				terminal(adapter.ErrAdminCredentialRotationUnsupported))
		}
	}

	if change.Mode == admincredentials.ModeRotate &&
		(change.ExpectedAuthorityFingerprint == "" || !change.TargetSideEffectPossible) {
		assessment, assessErr := e.assessAdminCredentialBeforeRotation(ctx, conn, cfg, manager, viaConnector)
		if assessErr != nil {
			if errors.Is(assessErr, adapter.ErrAdminCredentialRotationUnsupported) {
				return e.closeAdminCredentialBeforeEffect(ctx, op, change, "rotation_unsupported", terminal(assessErr))
			}
			if errors.Is(assessErr, adapter.ErrTargetIdentityConflict) ||
				errors.Is(assessErr, adapter.ErrAdminCredentialAuthorityChanged) ||
				errors.Is(assessErr, adapter.ErrAdminCredentialRejected) {
				return e.closeAdminCredentialBeforeEffect(ctx, op, change,
					adminCredentialErrorCode(assessErr), terminal(assessErr))
			}
			return e.recordAdminCredentialRetryableError(ctx, change, "internal_error", assessErr)
		}
		if !assessment.RotateSupported {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, "rotation_unsupported",
				terminal(adapter.ErrAdminCredentialRotationUnsupported))
		}
		if change.ExpectedAuthorityFingerprint == "" {
			if err := store.SetExpectedProof(ctx, e.deps.Pool, op.ID,
				assessment.CanonicalIdentity, assessment.AuthorityFingerprint, assessment.TargetIdentity); err != nil {
				return fmt.Errorf("jobs: persist admin credential proof fence: %w", err)
			}
			change, err = store.Get(ctx, e.deps.Pool, op.ID)
			if err != nil {
				return err
			}
		} else {
			expected := adapter.AdminCredentialProof{
				CanonicalIdentity:    change.ExpectedCanonicalIdentity,
				AuthorityFingerprint: change.ExpectedAuthorityFingerprint,
				TargetIdentity:       change.ExpectedTargetIdentity,
			}
			if assessment.TargetIdentity == "" || assessment.TargetIdentity != expected.TargetIdentity {
				return e.closeAdminCredentialBeforeEffect(ctx, op, change, "target_identity_changed",
					terminal(adapter.ErrTargetIdentityConflict))
			}
			if assessment.CanonicalIdentity != expected.CanonicalIdentity ||
				assessment.AuthorityFingerprint != expected.AuthorityFingerprint {
				return e.closeAdminCredentialBeforeEffect(ctx, op, change, "admin_authority_changed",
					terminal(adapter.ErrAdminCredentialAuthorityChanged))
			}
		}
	}

	phase := admincredentials.PhaseCandidateProving
	externalEffect := false
	if change.Mode == admincredentials.ModeRotate {
		phase = admincredentials.PhaseTargetApplying
		externalEffect = true
	}
	if change, err = e.advanceAdminCredentialPhase(ctx, change, phase, externalEffect, ""); err != nil {
		return err
	}
	var outcome adminCredentialTargetOutcome
	var targetErr error
	if change.Mode == admincredentials.ModeRotate && candidateAlreadyCanonical {
		outcome, targetErr = e.runAdminCredentialCandidateProof(ctx, op, conn, cfg, ad, manager,
			viaConnector, change, candidate)
	} else {
		outcome, targetErr = e.runAdminCredentialTarget(ctx, op, conn, cfg, ad, manager,
			viaConnector, change, candidate)
	}
	if targetErr != nil {
		code := adminCredentialErrorCode(targetErr)
		if change.Mode == admincredentials.ModeSwitch && code == "invalid_candidate" &&
			!change.TargetSideEffectPossible {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, code, terminal(targetErr))
		}
		if code == "rotation_unsupported" && !change.TargetSideEffectPossible {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, code, terminal(targetErr))
		}
		return e.recordAdminCredentialRetryableError(ctx, change, code, targetErr)
	}
	if err := e.verifyAdminCredentialOutcomeFence(conn, change, outcome); err != nil {
		code := adminCredentialErrorCode(err)
		if !change.TargetSideEffectPossible {
			return e.closeAdminCredentialBeforeEffect(ctx, op, change, code, terminal(err))
		}
		return e.recordAdminCredentialRetryableError(ctx, change, code, err)
	}
	if change, err = e.advanceAdminCredentialPhase(ctx, change,
		admincredentials.PhaseTargetApplied, change.TargetSideEffectPossible, ""); err != nil {
		return err
	}

	canonicalVersion, err := e.promoteAdminCredentialCandidate(ctx, vaultClient, change, candidate)
	if err != nil {
		return e.recordAdminCredentialRetryableError(ctx, change, "vault_unavailable", err)
	}
	change, err = store.Get(ctx, e.deps.Pool, op.ID)
	if err != nil {
		return err
	}
	if change, err = e.advanceAdminCredentialPhase(ctx, change,
		admincredentials.PhaseMetadataCommitting, true, ""); err != nil {
		return err
	}
	if err := e.recordAdminCredentialSuccess(ctx, op, conn, change, candidate, outcome, canonicalVersion); err != nil {
		_, _ = store.SetPhase(ctx, e.deps.Pool, op.ID, change.Phase, true, "metadata_commit_failed")
		return fmt.Errorf("jobs: commit admin credential metadata: %w", err)
	}
	e.setAdminCredentialResultArtifact(op.ID, change, canonicalVersion, outcome)
	if err := e.cleanupTerminalAdminCredentialStage(ctx, change); err != nil {
		slog.WarnContext(ctx, "jobs: cleanup completed admin credential stage deferred",
			"connection_id", change.ConnectionID, "operation_id", change.OperationID, "error", err)
	}
	return nil
}

func (e *MainExecutor) assessAdminCredentialBeforeRotation(ctx context.Context,
	conn connections.Connection, cfg adapter.Connection, manager adapter.ConnectionAdminCredentialManager,
	viaConnector bool) (adapter.AdminCredentialAssessment, error) {
	if !viaConnector {
		live, err := manager.AssessConnectionAdminCredential(ctx, cfg)
		if err != nil {
			return adapter.AdminCredentialAssessment{}, err
		}
		var topology map[string]any
		if err := json.Unmarshal(conn.Topology, &topology); err != nil {
			return adapter.AdminCredentialAssessment{}, fmt.Errorf("jobs: parse stored admin credential assessment: %w", err)
		}
		stored, ok := adapter.AdminCredentialAssessmentFromTopology(topology)
		if ok {
			if live.CanonicalIdentity != stored.CanonicalIdentity ||
				live.AuthorityFingerprint != stored.AuthorityFingerprint {
				return adapter.AdminCredentialAssessment{}, adapter.ErrAdminCredentialAuthorityChanged
			}
			if stored.TargetIdentity == "" || live.TargetIdentity != stored.TargetIdentity {
				return adapter.AdminCredentialAssessment{}, adapter.ErrTargetIdentityConflict
			}
		} else if expected := connections.TargetIdentity(conn); expected != "" &&
			live.TargetIdentity != expected {
			return adapter.AdminCredentialAssessment{}, adapter.ErrTargetIdentityConflict
		}
		return live, nil
	}
	var topology struct {
		SwitchSupported      bool   `json:"admin_credential_switch_supported"`
		RotateSupported      bool   `json:"admin_credential_rotate_supported"`
		CanonicalIdentity    string `json:"admin_credential_canonical_identity"`
		AuthorityFingerprint string `json:"admin_credential_authority_fingerprint"`
		TargetIdentity       string `json:"admin_credential_target_identity"`
	}
	if err := json.Unmarshal(conn.Topology, &topology); err != nil {
		return adapter.AdminCredentialAssessment{}, fmt.Errorf("jobs: parse stored admin credential assessment: %w", err)
	}
	if !topology.RotateSupported || topology.CanonicalIdentity == "" || topology.AuthorityFingerprint == "" {
		return adapter.AdminCredentialAssessment{}, adapter.ErrAdminCredentialRotationUnsupported
	}
	return adapter.AdminCredentialAssessment{
		SwitchSupported:      topology.SwitchSupported,
		RotateSupported:      topology.RotateSupported,
		CanonicalIdentity:    topology.CanonicalIdentity,
		AuthorityFingerprint: topology.AuthorityFingerprint,
		TargetIdentity:       topology.TargetIdentity,
	}, nil
}

func (e *MainExecutor) runAdminCredentialTarget(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, ad adapter.Adapter,
	manager adapter.ConnectionAdminCredentialManager, viaConnector bool,
	change admincredentials.Change, candidate adapter.Credential) (adminCredentialTargetOutcome, error) {
	if viaConnector {
		connectorMode := connector.AdminCredentialModeSwitch
		if change.Mode == admincredentials.ModeRotate {
			connectorMode = connector.AdminCredentialModeRotate
		}
		out, err := e.connectorAdminCredentialChange(ctx, op, conn, cfg, connectorMode,
			candidate, change.Epoch, change.StagedVaultVersion, adapter.AdminCredentialProof{
				CanonicalIdentity:    change.ExpectedCanonicalIdentity,
				AuthorityFingerprint: change.ExpectedAuthorityFingerprint,
				TargetIdentity:       change.ExpectedTargetIdentity,
			})
		if err != nil {
			return adminCredentialTargetOutcome{}, err
		}
		return adminCredentialTargetOutcome{
			Proof: out.Proof, AlreadyApplied: out.AlreadyApplied, Snapshot: out.Snapshot,
		}, nil
	}

	candidateCfg := cfg
	candidateCfg.AdminCredential = candidate
	candidateCfg.AuthMode = candidateAuthenticationMode(candidate)
	candidateCfg.AdminCredentialIncarnation = change.StagedVaultVersion
	var proof adapter.AdminCredentialProof
	alreadyApplied := false
	if change.Mode == admincredentials.ModeSwitch {
		var err error
		proof, err = manager.ProveConnectionAdminCredential(ctx, cfg, candidate)
		if err != nil {
			return adminCredentialTargetOutcome{}, fmt.Errorf("prove staged admin credential: %w", err)
		}
		if err := ad.ValidateConnection(ctx, candidateCfg); err != nil {
			return adminCredentialTargetOutcome{}, fmt.Errorf("validate staged admin credential: %w", err)
		}
	} else {
		rotation, err := manager.RotateConnectionAdminCredential(ctx, cfg, candidate,
			adapter.AdminCredentialProof{
				CanonicalIdentity:    change.ExpectedCanonicalIdentity,
				AuthorityFingerprint: change.ExpectedAuthorityFingerprint,
				TargetIdentity:       change.ExpectedTargetIdentity,
			})
		if err != nil {
			return adminCredentialTargetOutcome{}, fmt.Errorf("rotate connection admin credential: %w", err)
		}
		proof = rotation.Proof
		alreadyApplied = rotation.AlreadyApplied
	}
	snapshot, err := ad.Discover(ctx, candidateCfg)
	if err != nil {
		return adminCredentialTargetOutcome{}, fmt.Errorf("discover with staged admin credential: %w", err)
	}
	if snapshot == nil {
		return adminCredentialTargetOutcome{}, errors.New("discover with staged admin credential returned no snapshot")
	}
	return adminCredentialTargetOutcome{Proof: proof, AlreadyApplied: alreadyApplied, Snapshot: snapshot}, nil
}

func (e *MainExecutor) runAdminCredentialCandidateProof(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, ad adapter.Adapter,
	manager adapter.ConnectionAdminCredentialManager, viaConnector bool,
	change admincredentials.Change, candidate adapter.Credential) (adminCredentialTargetOutcome, error) {
	if viaConnector {
		out, err := e.connectorAdminCredentialChange(ctx, op, conn, cfg,
			connector.AdminCredentialModeSwitch, candidate, change.Epoch, change.StagedVaultVersion,
			adapter.AdminCredentialProof{})
		if err != nil {
			return adminCredentialTargetOutcome{}, err
		}
		return adminCredentialTargetOutcome{
			Proof: out.Proof, AlreadyApplied: true, Snapshot: out.Snapshot,
		}, nil
	}
	candidateCfg := cfg
	candidateCfg.AdminCredential = candidate
	candidateCfg.AuthMode = candidateAuthenticationMode(candidate)
	candidateCfg.AdminCredentialIncarnation = change.StagedVaultVersion
	proof, err := manager.ProveConnectionAdminCredential(ctx, cfg, candidate)
	if err != nil {
		return adminCredentialTargetOutcome{}, fmt.Errorf("prove promoted admin credential: %w", err)
	}
	if err := ad.ValidateConnection(ctx, candidateCfg); err != nil {
		return adminCredentialTargetOutcome{}, fmt.Errorf("validate promoted admin credential: %w", err)
	}
	snapshot, err := ad.Discover(ctx, candidateCfg)
	if err != nil {
		return adminCredentialTargetOutcome{}, fmt.Errorf("discover with promoted admin credential: %w", err)
	}
	return adminCredentialTargetOutcome{Proof: proof, AlreadyApplied: true, Snapshot: snapshot}, nil
}

func (e *MainExecutor) verifyAdminCredentialOutcomeFence(conn connections.Connection,
	change admincredentials.Change, outcome adminCredentialTargetOutcome) error {
	if outcome.Snapshot == nil || outcome.Proof.CanonicalIdentity == "" ||
		outcome.Proof.AuthorityFingerprint == "" {
		return adapter.ErrAdminCredentialProofAmbiguous
	}
	snapshotAssessment, observed := adapter.AdminCredentialAssessmentFromTopology(outcome.Snapshot.Topology)
	if !observed || snapshotAssessment.CanonicalIdentity != outcome.Proof.CanonicalIdentity ||
		snapshotAssessment.AuthorityFingerprint != outcome.Proof.AuthorityFingerprint {
		return adapter.ErrAdminCredentialAuthorityChanged
	}
	expectedTarget := connections.TargetIdentity(conn)
	if expectedTarget == "" {
		var topology struct {
			TargetIdentity string `json:"admin_credential_target_identity"`
		}
		_ = json.Unmarshal(conn.Topology, &topology)
		expectedTarget = topology.TargetIdentity
	}
	proofTarget := outcome.Proof.TargetIdentity
	topology, err := json.Marshal(outcome.Snapshot.Topology)
	if err != nil {
		return fmt.Errorf("marshal candidate topology: %w", err)
	}
	candidateConn := conn
	candidateConn.Topology = topology
	snapshotTarget := connections.TargetIdentity(candidateConn)
	if snapshotTarget == "" {
		snapshotTarget = snapshotAssessment.TargetIdentity
	}
	if proofTarget != "" && snapshotTarget != "" && proofTarget != snapshotTarget {
		return fmt.Errorf("admin proof and discovery resolved to different targets: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if expectedTarget != "" && (proofTarget != expectedTarget || snapshotTarget != expectedTarget) {
		return fmt.Errorf("candidate resolved to a different target: %w", adapter.ErrTargetIdentityConflict)
	}
	if change.Mode == admincredentials.ModeRotate {
		if outcome.Proof.CanonicalIdentity != change.ExpectedCanonicalIdentity ||
			outcome.Proof.AuthorityFingerprint != change.ExpectedAuthorityFingerprint ||
			(change.ExpectedTargetIdentity != "" && outcome.Proof.TargetIdentity != change.ExpectedTargetIdentity) {
			return adapter.ErrAdminCredentialAuthorityChanged
		}
	}
	return nil
}

func (e *MainExecutor) promoteAdminCredentialCandidate(ctx context.Context, client adminCredentialVault,
	change admincredentials.Change, candidate adapter.Credential) (int, error) {
	store := admincredentials.NewStore()
	canonicalPath, err := vault.ConnectionAdminPath(change.ConnectionID.String())
	if err != nil {
		return 0, err
	}
	if !change.Phase.AtLeast(admincredentials.PhasePromoting) {
		if _, err := store.SetPhase(ctx, e.deps.Pool, change.OperationID,
			admincredentials.PhasePromoting, true, ""); err != nil {
			return 0, err
		}
	}
	if candidate.Kind == "none" {
		if change.CanonicalVaultVersion != nil {
			if *change.CanonicalVaultVersion != 0 {
				return 0, errors.New("invalid no-auth canonical version")
			}
			return 0, nil
		}
		if err := store.SetCanonicalVersion(ctx, e.deps.Pool, change.OperationID, 0); err != nil {
			return 0, err
		}
		return 0, nil
	}
	if change.CanonicalVaultVersion != nil {
		data, version, err := client.Get(ctx, canonicalPath)
		if err != nil {
			return 0, err
		}
		canonical, err := credentialFromVault(data)
		if err != nil {
			return 0, errors.New("canonical admin credential is incomplete after promotion")
		}
		defer clear(canonical.Secret)
		if !sameAdminCredential(candidate, canonical) || version != *change.CanonicalVaultVersion {
			return 0, errors.New("canonical admin credential differs from the promoted candidate")
		}
		return version, nil
	}

	data := map[string]any{"username": candidate.Username, "password": string(candidate.Secret)}
	version, putErr := client.PutCAS(ctx, canonicalPath, data, change.ExpectedCanonicalVersion)
	delete(data, "password")
	delete(data, "username")
	if putErr != nil {
		// Lost CAS response: compare only in memory. Exact equality proves the
		// candidate was promoted; no value or derivative enters metadata/logs.
		canonicalData, actualVersion, readErr := client.Get(ctx, canonicalPath)
		if readErr != nil {
			return 0, fmt.Errorf("promote canonical admin credential: %w", putErr)
		}
		canonical, parseErr := credentialFromVault(canonicalData)
		if parseErr != nil {
			return 0, fmt.Errorf("promote canonical admin credential: %w", putErr)
		}
		defer clear(canonical.Secret)
		if !sameAdminCredential(candidate, canonical) {
			return 0, fmt.Errorf("canonical admin credential CAS did not converge: %w", putErr)
		}
		version = actualVersion
	}
	if err := store.SetCanonicalVersion(ctx, e.deps.Pool, change.OperationID, version); err != nil {
		return 0, err
	}
	return version, nil
}

func sameAdminCredential(a, b adapter.Credential) bool {
	return a.Kind == b.Kind && a.Username == b.Username && subtle.ConstantTimeCompare(a.Secret, b.Secret) == 1
}

func deleteAdminCredentialStage(ctx context.Context, client adminCredentialVault, path string) error {
	err := client.DeleteMetadata(ctx, path)
	if errors.Is(err, vault.ErrNotFound) {
		return nil
	}
	return err
}

func (e *MainExecutor) recordAdminCredentialSuccess(ctx context.Context, op operations.Operation,
	conn connections.Connection, change admincredentials.Change, candidate adapter.Credential,
	outcome adminCredentialTargetOutcome, canonicalVersion int) error {
	snapshot := outcome.Snapshot
	if candidate.Kind != "none" {
		if err := rebindProvisioningAuthorityCredentialIncarnation(snapshot, canonicalVersion); err != nil {
			return err
		}
	}
	observedAt := snapshot.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	candidateCfg, err := adapterConnection(conn)
	if err != nil {
		return err
	}
	candidateCfg.AdminCredential = candidate
	candidateCfg.AuthMode = candidateAuthenticationMode(candidate)
	candidateCfg.AdminCredentialIncarnation = canonicalVersion
	markConnectionAdminAccount(conn, candidateCfg, snapshot)
	topology, err := json.Marshal(snapshot.Topology)
	if err != nil {
		return err
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	stats, err := e.deps.Inventory.UpsertSnapshot(ctx, tx, conn.ID, snapshot, observedAt)
	if err != nil {
		return err
	}
	if err := rolepolicies.NewStore().ReconcileSnapshot(ctx, tx, conn.ID, snapshot.RolePolicies, observedAt); err != nil {
		return err
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		return err
	}
	canonicalPath, err := vault.ConnectionAdminPath(conn.ID.String())
	if err != nil {
		return err
	}
	if candidate.Kind == "none" {
		canonicalPath = ""
	}
	candidateMode := change.CandidateMode
	if candidateMode == "none" {
		candidateMode = "provided"
	}
	tag, err := tx.Exec(ctx, `
		update connections
		set status = 'active', vault_admin_path = $2,
			admin_credential_mode = $3, auth_mode = $4, admin_credential_set_at = case when $4 = 'none' then null else now() end, updated_at = now()
		where id = $1 and status = 'credential_updating'`,
		conn.ID, canonicalPath, candidateMode, candidateAuthenticationMode(candidate))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return connections.ErrStatusConflict
	}
	if err := e.deps.Connections.SetDiscoveryResult(ctx, tx, conn.ID, snapshot.ServerVersion,
		topology, ad.Manifest().CapabilityNames(), observedAt); err != nil {
		return err
	}
	completionResult, err := marshalAdminCredentialResult(change, canonicalVersion, outcome)
	if err != nil {
		return err
	}
	if _, err := admincredentials.NewStore().Complete(ctx, tx, op.ID, completionResult); err != nil {
		return err
	}
	action := auditActionAdminCredentialSwitched
	if change.Mode == admincredentials.ModeRotate {
		action = auditActionAdminCredentialRotated
	}
	metadata, err := json.Marshal(map[string]any{
		"mode":                    change.Mode,
		"epoch":                   change.Epoch,
		"canonical_vault_version": canonicalVersion,
		"already_applied":         outcome.AlreadyApplied,
		"resources":               stats.Resources,
		"accounts":                stats.Accounts,
		"permissions":             stats.Permissions,
		"bindings":                stats.Bindings,
	})
	if err != nil {
		return err
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID, Action: action,
		ConnectionID: &conn.ID, OperationID: &op.ID,
		Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		return err
	}
	if e.mut.BeforeAdminCredentialMetadataCommit != nil {
		if err := e.mut.BeforeAdminCredentialMetadataCommit(ctx, op); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// rebindProvisioningAuthorityCredentialIncarnation closes the promotion
// window for credential changes. Discovery runs with the staged candidate
// before Vault CAS promotion, so its authority attestation initially carries
// the old canonical credential version. Persisting that snapshot would make a
// just-completed switch/rotation immediately stale (or, worse, make an API
// compare the stale value with itself). Rebind only the typed, secret-free
// attestation after CAS returned the exact new canonical version.
func rebindProvisioningAuthorityCredentialIncarnation(snapshot *adapter.Snapshot,
	canonicalVersion int,
) error {
	if snapshot == nil {
		return errors.New("admin credential success has no discovery snapshot")
	}
	if canonicalVersion <= 0 {
		return errors.New("admin credential success has no canonical Vault version")
	}
	if snapshot.Topology == nil {
		return nil
	}
	if _, present := snapshot.Topology[adapter.PostgresProvisioningAuthorityTopologyKey]; !present {
		return nil
	}
	assessment, ok := adapter.ProvisioningAuthorityFromTopology(
		snapshot.Topology, adapter.PostgresProvisioningAuthorityTopologyKey,
	)
	if !ok {
		return errors.New("admin credential discovery returned malformed PostgreSQL authority assessment")
	}
	assessment.CredentialIncarnation = canonicalVersion
	snapshot.Topology[adapter.PostgresProvisioningAuthorityTopologyKey] = assessment
	return nil
}

func (e *MainExecutor) closeAdminCredentialBeforeEffect(ctx context.Context, op operations.Operation,
	change admincredentials.Change, code string, cause error) error {
	current, err := admincredentials.NewStore().Get(ctx, e.deps.Pool, op.ID)
	if err != nil {
		return errors.Join(cause, err)
	}
	if current.TargetSideEffectPossible {
		return e.recordAdminCredentialRetryableError(ctx, current, code, retryableAdminCredentialCause(cause))
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return errors.Join(cause, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	closed, err := admincredentials.NewStore().RestoreTerminal(ctx, tx, op.ID,
		admincredentials.PhaseFailed, code, nil)
	if err != nil {
		return errors.Join(cause, err)
	}
	metadata, err := json.Marshal(map[string]any{
		"mode": closed.Mode, "epoch": closed.Epoch, "error_code": code,
	})
	if err != nil {
		return errors.Join(cause, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID, Action: auditActionAdminCredentialFailed,
		ConnectionID: &closed.ConnectionID, OperationID: &op.ID,
		Result: audit.ResultFailure, Metadata: metadata,
	}); err != nil {
		return errors.Join(cause, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(cause, err)
	}
	if err := e.cleanupTerminalAdminCredentialStage(ctx, closed); err != nil {
		slog.WarnContext(ctx, "jobs: cleanup rejected admin credential stage deferred",
			"connection_id", closed.ConnectionID, "operation_id", closed.OperationID, "error", err)
	}
	return cause
}

func retryableAdminCredentialCause(err error) error {
	var marked *terminalError
	if errors.As(err, &marked) {
		return marked.cause
	}
	return err
}

func (e *MainExecutor) advanceAdminCredentialPhase(ctx context.Context, change admincredentials.Change,
	phase admincredentials.Phase, externalEffect bool, errorCode string) (admincredentials.Change, error) {
	if change.Phase.AtLeast(phase) {
		if errorCode == "" || change.ErrorCode == errorCode {
			return change, nil
		}
		phase = change.Phase
	}
	return admincredentials.NewStore().SetPhase(ctx, e.deps.Pool, change.OperationID,
		phase, externalEffect, errorCode)
}

func (e *MainExecutor) recordAdminCredentialRetryableError(ctx context.Context,
	change admincredentials.Change, code string, cause error) error {
	if code == "" {
		code = "internal_error"
	}
	store := admincredentials.NewStore()
	current, loadErr := store.Get(ctx, e.deps.Pool, change.OperationID)
	if loadErr != nil {
		return errors.Join(cause, loadErr)
	}
	_, phaseErr := store.SetPhase(ctx, e.deps.Pool, change.OperationID,
		current.Phase, current.TargetSideEffectPossible, code)
	if phaseErr != nil {
		return errors.Join(cause, phaseErr)
	}
	return cause
}

func adminCredentialErrorCode(err error) string {
	var remote *connectorAdminCredentialError
	if errors.As(err, &remote) && remote.code != "" {
		return remote.code
	}
	switch {
	case errors.Is(err, adapter.ErrAdminCredentialRejected):
		return "invalid_candidate"
	case errors.Is(err, adapter.ErrAdminCredentialRotationUnsupported):
		return "rotation_unsupported"
	case errors.Is(err, adapter.ErrAdminCredentialAuthorityChanged):
		return "admin_authority_changed"
	case errors.Is(err, adapter.ErrAdminCredentialOldStillValid):
		return "old_credential_still_valid"
	case errors.Is(err, adapter.ErrTargetIdentityConflict):
		return "target_identity_changed"
	default:
		return "internal_error"
	}
}

func (e *MainExecutor) setAdminCredentialResultArtifact(opID uuid.UUID, change admincredentials.Change,
	canonicalVersion int, outcome adminCredentialTargetOutcome) {
	data, err := marshalAdminCredentialResult(change, canonicalVersion, outcome)
	if err == nil {
		e.setResultArtifact(opID, data)
	}
}

func marshalAdminCredentialResult(change admincredentials.Change, canonicalVersion int,
	outcome adminCredentialTargetOutcome) ([]byte, error) {
	return json.Marshal(adminCredentialResultArtifact{
		Mode: change.Mode, Epoch: change.Epoch, CanonicalVaultVersion: canonicalVersion,
		AlreadyApplied: outcome.AlreadyApplied, Proof: outcome.Proof,
	})
}

func (e *MainExecutor) restoreAdminCredentialCompletionArtifact(ctx context.Context, opID uuid.UUID,
	change admincredentials.Change) error {
	if change.CanonicalVaultVersion == nil {
		return fmt.Errorf("jobs: completed admin credential change has no canonical Vault version")
	}
	if len(change.CompletionResult) == 0 {
		return fmt.Errorf("jobs: completed admin credential change has no completion result")
	}
	e.setResultArtifact(opID, change.CompletionResult)
	if err := e.cleanupTerminalAdminCredentialStage(ctx, change); err != nil {
		slog.WarnContext(ctx, "jobs: cleanup receipt admin credential stage deferred",
			"connection_id", change.ConnectionID, "operation_id", change.OperationID, "error", err)
	}
	return nil
}

func (e *MainExecutor) cleanupTerminalAdminCredentialStage(ctx context.Context,
	change admincredentials.Change) error {
	if !change.StageCleanupPending {
		return nil
	}
	client, ok := e.deps.Vault.(adminCredentialVault)
	if !ok || client == nil {
		return errors.New("CAS-capable Vault client is unavailable")
	}
	if err := deleteAdminCredentialStage(ctx, client, change.StageVaultPath); err != nil {
		return err
	}
	return admincredentials.NewStore().MarkStageCleaned(ctx, e.deps.Pool, change.OperationID)
}

func candidateAuthenticationMode(candidate adapter.Credential) string {
	if candidate.Kind == "none" {
		return "none"
	}
	return "password"
}
