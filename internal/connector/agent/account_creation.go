package agent

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

func (a *Agent) accountCreation(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	fail := func(code string) connector.JobResult {
		res.Status = connector.JobFailed
		res.ErrorCode, res.Error = code, "account provisioning stage failed: "+code
		return res
	}
	p, err := connector.ParseAccountCreationPayload(job.Payload)
	if err != nil || job.ConnectionID != p.Request.Connection.ID || job.Engine != "postgres" ||
		creds.Account == nil || creds.AccountVaultVersion <= 0 || creds.AdminCredentialIncarnation <= 0 {
		return fail("invalid_account_creation_job")
	}
	// Reuse the existing closed v2 mapping and all connection/credential pins.
	mutation := job
	mutation.Kind = connector.JobPlan
	mutation.Payload, err = json.Marshal(p.Request)
	if err != nil {
		return fail("invalid_account_creation_job")
	}
	ad, change, err := a.mutationChange(mutation, creds)
	if err != nil {
		return fail("target_unavailable")
	}
	if change.Connection.AdminCredential.Username != change.ExpectedAdminIdentity {
		return fail("target_identity_changed")
	}
	provisioner, ok := ad.(adapter.AccountCreationProvisioner)
	if !ok || !ad.Manifest().HasCapability(adapter.CapPostgresAccountCreationV1) {
		return fail("account_creation_unsupported")
	}
	if change.Credential == nil || change.Credential.Kind != "password" || len(change.Credential.Secret) == 0 || change.Credential.Username != change.Account.EngineIdentity {
		return fail("credential_identity_mismatch")
	}
	var proof *adapter.AccountCreationProof
	switch p.Stage {
	case "preflight":
		err = provisioner.PreflightAccountCreation(ctx, change)
	case "create":
		proof, err = provisioner.CreateAccountWithProof(ctx, change)
	case "verify":
		proof = p.Proof
		err = provisioner.VerifyCreatedAccount(ctx, change, *proof)
	}
	if err != nil {
		switch {
		case errors.Is(err, adapter.ErrCredentialProofAccessDenied):
			return fail("credential_access_denied")
		case errors.Is(err, adapter.ErrCredentialProofUnsupported):
			return fail("credential_proof_unsupported")
		case errors.Is(err, adapter.ErrExternalIdentityConflict):
			return fail("credential_identity_conflict")
		case errors.Is(err, adapter.ErrTargetIdentityConflict):
			return fail("target_identity_changed")
		default:
			return fail("target_unavailable")
		}
	}
	if p.Stage != "preflight" && (proof == nil || proof.RoleOID == 0 ||
		proof.EngineIdentity != change.Account.EngineIdentity || proof.TargetIdentity != change.ExpectedTargetIdentity) {
		return fail("invalid_creation_receipt")
	}
	out := connector.AccountCreationOutcome{Stage: p.Stage, AccountID: p.AccountID,
		VaultVersion: creds.AccountVaultVersion, Confirmed: true, Proof: proof}
	res.Result, err = json.Marshal(out)
	if err != nil {
		return fail("invalid_creation_receipt")
	}
	res.Status = connector.JobSuccess
	return res
}
