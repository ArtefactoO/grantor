package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func connectorProofJob(op operations.Operation, conn connections.Connection, cfg adapter.Connection, acct inventory.Account) (connector.Job, error) {
	ref, tls, attrs := connectorConnectionParts(conn, cfg)
	payload, err := json.Marshal(connector.CredentialProofPayload{
		Connection: ref, TLS: tls, Attributes: attrs,
		Account: connectorAccountRef(acct), AccountID: acct.ID.String(),
	})
	if err != nil {
		return connector.Job{}, err
	}
	// A retry must prove the password now, even if a previous proof succeeded
	// before the metadata commit failed. Wire redelivery keeps this same key.
	idem := fmt.Sprintf("op:%s:proof:%s", op.ID, uuid.NewString())
	return connectorJobBase(op, conn, connector.JobProveCredential, idem, payload, time.Now()), nil
}

func (e *MainExecutor) connectorProveCredential(ctx context.Context, op operations.Operation, conn connections.Connection,
	cfg adapter.Connection, acct inventory.Account, credential adapter.Credential, version int) error {
	job, err := connectorProofJob(op, conn, cfg, acct)
	if err != nil {
		return errors.New("credential proof job is unavailable")
	}
	creds := connectorJobCredentials(cfg)
	// Dispatch zeroes its owned bytes; preserve the staged password for the
	// subsequent canonical Vault write after a successfully verified response.
	credential.Secret = append([]byte(nil), credential.Secret...)
	creds.Account, creds.AccountVaultVersion = &credential, version
	res, err := e.connectorDispatch(ctx, job, creds)
	if err != nil || res.JobID != job.ID {
		return errors.New("credential proof connector is unavailable")
	}
	if res.Status != connector.JobSuccess {
		switch res.ErrorCode {
		case "credential_access_denied":
			return adapter.ErrCredentialProofAccessDenied
		case "password_rejected", "credential_identity_mismatch":
			return adapter.ErrExternalIdentityConflict
		case "credential_proof_unsupported":
			return adapter.ErrCredentialProofUnsupported
		default:
			return errors.New("credential proof target is unavailable")
		}
	}
	out, err := connector.ParseCredentialProofOutcome(res.Result)
	if err != nil || out.AccountID != acct.ID.String() || out.EngineIdentity != acct.EngineIdentity || out.VaultVersion != version {
		return errors.New("credential proof result does not match the staged credential")
	}
	return nil
}
