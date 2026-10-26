package jobs

// Connector transport for connection administrator credential lifecycle.
// These helpers intentionally do not reuse connectorRotateJob: ordinary
// account rotation lacks candidate-first recovery, old-secret invalidation and
// administrative authority proof. Dedicated JobKind values make old agents
// fail before target mutation and prohibit a generic credential-job fallback.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

type connectorAdminCredentialError struct {
	code string
	msg  string
}

func (e *connectorAdminCredentialError) Error() string { return e.msg }

func connectorAdminCredentialJob(
	op operations.Operation,
	conn connections.Connection,
	cfg adapter.Connection,
	mode connector.AdminCredentialMode,
	candidateUsername string,
	epoch int64,
	stagedVaultVersion int,
	expectedProof adapter.AdminCredentialProof,
	now time.Time,
) (connector.Job, error) {
	if stagedVaultVersion < 0 || (stagedVaultVersion == 0 && (conn.Engine != "redis" || mode != connector.AdminCredentialModeSwitch || candidateUsername != "default")) {
		return connector.Job{}, errors.New("admin credential connector job requires a positive staged Vault version")
	}
	connRef, tlsRef, attrs := connectorConnectionParts(conn, cfg)
	payloadDescriptor := connector.AdminCredentialPayload{
		Connection: connRef, TLS: tlsRef, Attributes: attrs,
		CandidateUsername: candidateUsername, Epoch: epoch, Mode: mode,
		ExpectedCanonicalIdentity:    expectedProof.CanonicalIdentity,
		ExpectedAuthorityFingerprint: expectedProof.AuthorityFingerprint,
		ExpectedTargetIdentity:       expectedProof.TargetIdentity,
	}
	if stagedVaultVersion == 0 {
		payloadDescriptor.CandidateAuthMode = "none"
	}
	payload, err := payloadDescriptor.Marshal()
	if err != nil {
		return connector.Job{}, err
	}
	jobKind, err := payloadDescriptor.JobKind()
	if err != nil {
		return connector.Job{}, err
	}
	intent := fmt.Sprintf("%s\x1f%s\x1f%d\x1f%d\x1f%s\x1f%s\x1f%s",
		mode, candidateUsername, epoch, stagedVaultVersion,
		expectedProof.CanonicalIdentity, expectedProof.AuthorityFingerprint, expectedProof.TargetIdentity)
	sum := sha256.Sum256([]byte(intent))
	idem := fmt.Sprintf("op:%s:admin-credential:%s", op.ID, hex.EncodeToString(sum[:])[:16])
	return connectorJobBase(op, conn, jobKind, idem, payload, now), nil
}

// connectorAdminCredentialChange sends the old canonical credential only in
// CredentialsFrame.Admin and the staged candidate only in Account. The exact
// staged Vault version is echoed by the agent and checked before the caller is
// allowed to promote the canonical secret.
func (e *MainExecutor) connectorAdminCredentialChange(
	ctx context.Context,
	op operations.Operation,
	conn connections.Connection,
	cfg adapter.Connection,
	mode connector.AdminCredentialMode,
	candidate adapter.Credential,
	epoch int64,
	stagedVaultVersion int,
	expectedProof adapter.AdminCredentialProof,
) (connector.AdminCredentialOutcome, error) {
	job, err := connectorAdminCredentialJob(op, conn, cfg, mode, candidate.Username,
		epoch, stagedVaultVersion, expectedProof, time.Now())
	if err != nil {
		return connector.AdminCredentialOutcome{}, err
	}
	if candidate.Username == "" || (candidate.Kind != "none" && len(candidate.Secret) == 0) {
		return connector.AdminCredentialOutcome{}, errors.New("admin credential connector job requires a staged candidate")
	}
	frameCandidate := candidate
	frameCandidate.Secret = append([]byte(nil), candidate.Secret...)
	creds := connector.JobCredentials{
		Account:                    &frameCandidate,
		AccountVaultVersion:        stagedVaultVersion,
		AdminCredentialIncarnation: cfg.AdminCredentialIncarnation,
	}
	if candidate.Kind == "none" {
		creds.Account = nil
	}
	if cfg.AuthMode != "none" && (cfg.AdminCredential.Username != "" || len(cfg.AdminCredential.Secret) > 0) {
		current := cfg.AdminCredential
		current.Secret = append([]byte(nil), cfg.AdminCredential.Secret...)
		creds.Admin = &current
	}
	if mode == connector.AdminCredentialModeRotate && creds.Admin == nil {
		return connector.AdminCredentialOutcome{}, errors.New("admin credential rotation requires the old canonical credential")
	}
	res, err := e.connectorDispatch(ctx, job, creds)
	if err != nil {
		return connector.AdminCredentialOutcome{}, err
	}
	if res.Status != connector.JobSuccess {
		return connector.AdminCredentialOutcome{}, &connectorAdminCredentialError{
			code: res.ErrorCode,
			msg:  fmt.Sprintf("connector job %s: status %q: %s", job.ID, res.Status, res.Error),
		}
	}
	outcome, err := connector.ParseAdminCredentialOutcome(res.Result)
	if err != nil {
		return connector.AdminCredentialOutcome{}, fmt.Errorf(
			"connector job %s: parse admin credential outcome: %w", job.ID, err)
	}
	if outcome.Mode != mode || outcome.Epoch != epoch ||
		outcome.CandidateUsername != candidate.Username ||
		outcome.StagedVaultVersion != stagedVaultVersion || (candidate.Kind == "none" && outcome.CandidateAuthMode != "none") {
		return connector.AdminCredentialOutcome{}, fmt.Errorf(
			"connector job %s returned mismatched admin credential intent", job.ID)
	}
	return outcome, nil
}
