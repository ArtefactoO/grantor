package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

// proveCredential only authenticates. No Plan, Apply or Rotate path is reachable.
// All failures use closed codes: adapter errors may contain credential material.
func (a *Agent) proveCredential(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	fail := func(code string) connector.JobResult {
		res.Status = connector.JobFailed
		res.ErrorCode, res.Error = code, "credential verification failed: "+code
		return res
	}
	p, err := connector.ParseCredentialProofPayload(job.Payload)
	if err != nil || job.ConnectionID != p.Connection.ID || job.Engine != p.Connection.Engine {
		return fail("invalid_proof_job")
	}
	if creds.Account == nil || creds.AccountVaultVersion <= 0 {
		return fail("invalid_proof_credential")
	}
	cred := creds.Account.Credential()
	if cred.Kind != "password" || cred.Username != p.Account.EngineIdentity || len(cred.Secret) == 0 {
		return fail("credential_identity_mismatch")
	}
	ad, cfg, err := a.target(job.Engine, p.Connection, p.TLS, p.Attributes, creds.Admin, creds.AdminCredentialIncarnation)
	if err != nil {
		return fail("target_unavailable")
	}
	if !adapter.SupportsCredentialProof(ad) {
		return fail("credential_proof_unsupported")
	}
	if err := ad.(adapter.CredentialProver).ProveCredential(ctx, cfg, adapterAccount(p.Account), cred); err != nil {
		switch {
		case errors.Is(err, adapter.ErrCredentialProofAccessDenied):
			return fail("credential_access_denied")
		case errors.Is(err, adapter.ErrExternalIdentityConflict):
			return fail("password_rejected")
		case errors.Is(err, adapter.ErrCredentialProofUnsupported):
			return fail("credential_proof_unsupported")
		default:
			return fail("target_unavailable")
		}
	}
	out, err := json.Marshal(connector.CredentialProofOutcome{
		Verified: true, AccountID: p.AccountID, EngineIdentity: p.Account.EngineIdentity,
		VaultVersion: creds.AccountVaultVersion,
	})
	if err != nil {
		return fail("proof_result_invalid")
	}
	res.Status, res.Result = connector.JobSuccess, out
	return res
}
