package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

type proofDispatcher func(connector.Job, connector.JobCredentials) (connector.JobResult, error)

func (f proofDispatcher) Dispatch(_ context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	return f(job, creds)
}

func TestConnectorProofChecksAcknowledgementAndOwnsSecrets(t *testing.T) {
	acct := inventory.Account{ID: uuid.New(), Kind: "login", EngineIdentity: "legacy_app"}
	conn := connections.Connection{ID: uuid.New(), Engine: "postgres"}
	op := operations.Operation{ID: uuid.New(), Kind: KindAccountAdoptVerify}
	for _, mode := range []string{"success", "wrong_job", "wrong_account", "wrong_identity", "wrong_version", "unverified", "unknown_field", "rejected", "transport"} {
		t.Run(mode, func(t *testing.T) {
			var owned []byte
			d := proofDispatcher(func(job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
				owned = creds.Account.Secret
				if bytes.Contains(job.Payload, owned) {
					t.Fatal("job contains secret")
				}
				out := connector.CredentialProofOutcome{Verified: true, AccountID: acct.ID.String(), EngineIdentity: acct.EngineIdentity, VaultVersion: 3}
				switch mode {
				case "wrong_account":
					out.AccountID = uuid.NewString()
				case "wrong_identity":
					out.EngineIdentity = "someone_else"
				case "wrong_version":
					out.VaultVersion = 4
				case "unverified":
					out.Verified = false
				case "transport":
					return connector.JobResult{}, errors.New("proof-canary")
				}
				raw, _ := json.Marshal(out)
				if mode == "unknown_field" {
					raw = append(raw[:len(raw)-1], []byte(`,"extra":"proof-canary"}`)...)
				}
				res := connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}
				if mode == "wrong_job" {
					res.JobID = uuid.NewString()
				}
				if mode == "rejected" {
					res.Status = connector.JobFailed
					res.ErrorCode = "password_rejected"
					res.Error = "proof-canary"
				}
				return res, nil
			})
			executor := (&MainExecutor{}).WithConnector(ConnectorDeps{Dispatcher: d})
			candidate := []byte("proof-canary")
			err := executor.connectorProveCredential(t.Context(), op, conn, adapter.Connection{}, acct,
				adapter.Credential{Kind: "password", Username: acct.EngineIdentity, Secret: candidate}, 3)
			if (err == nil) != (mode == "success") {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if err != nil && bytes.Contains([]byte(err.Error()), candidate) {
				t.Fatal("worker leaked secret")
			}
			if mode == "rejected" && !errors.Is(err, adapter.ErrExternalIdentityConflict) {
				t.Fatal("rejection lost terminal identity")
			}
			if string(candidate) != "proof-canary" {
				t.Fatal("dispatch erased staged candidate before promotion")
			}
			if !bytes.Equal(owned, make([]byte, len(owned))) {
				t.Fatal("worker retained dispatched credential")
			}
		})
	}
	first, _ := connectorProofJob(op, conn, adapter.Connection{}, acct)
	second, _ := connectorProofJob(op, conn, adapter.Connection{}, acct)
	if first.IdempotencyKey == second.IdempotencyKey {
		t.Fatal("new attempt could reuse stale proof")
	}
	via, err := connectorRoute(connections.ExecutionModeConnector, KindAccountAdoptVerify, true)
	if err != nil || !via {
		t.Fatal("proof must route to connector")
	}
}
