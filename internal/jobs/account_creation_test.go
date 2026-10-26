package jobs

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestAccountCreationReceiptMatchesEveryReservedIdentity(t *testing.T) {
	acct := inventory.Account{ID: uuid.New(), ConnectionID: uuid.New(), EngineIdentity: "created_login", VaultPath: "accounts/fixture/credential", LifecycleVersion: 7}
	p := AccountPayload{AccountID: acct.ID, ExpectedLifecycleVersion: 7, ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42",
		ExpectedConfigIncarnation: "config-1", ExpectedCredentialIncarnation: 3, CredentialVaultVersion: 1}
	r := accountcreation.Receipt{OperationID: uuid.New(), AccountID: acct.ID, ConnectionID: acct.ConnectionID, EngineIdentity: acct.EngineIdentity,
		LifecycleVersion: 7, AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "config-1",
		AdminCredentialIncarnation: 3, CredentialPath: acct.VaultPath, CredentialVersion: 1}
	if !AccountCreationReceiptMatches(r, acct, p) {
		t.Fatal("matching creation intent was rejected")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*accountcreation.Receipt)
	}{
		{"account", func(r *accountcreation.Receipt) { r.AccountID = uuid.New() }},
		{"connection", func(r *accountcreation.Receipt) { r.ConnectionID = uuid.New() }},
		{"identity", func(r *accountcreation.Receipt) { r.EngineIdentity = "foreign_login" }},
		{"lifecycle", func(r *accountcreation.Receipt) { r.LifecycleVersion++ }},
		{"admin", func(r *accountcreation.Receipt) { r.AdminIdentity = "foreign_admin" }},
		{"target", func(r *accountcreation.Receipt) { r.TargetIdentity = "postgres:system:43" }},
		{"config", func(r *accountcreation.Receipt) { r.ConfigIncarnation = "config-2" }},
		{"admin credential", func(r *accountcreation.Receipt) { r.AdminCredentialIncarnation++ }},
		{"credential path", func(r *accountcreation.Receipt) { r.CredentialPath = "accounts/foreign/credential" }},
		{"missing credential version", func(r *accountcreation.Receipt) { r.CredentialVersion = 0 }},
		{"changed credential version", func(r *accountcreation.Receipt) { r.CredentialVersion++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := r
			tc.mutate(&bad)
			if AccountCreationReceiptMatches(bad, acct, p) {
				t.Fatal("creation receipt accepted a changed reserved identity")
			}
		})
	}
	p.SharedCredentialPath = "principals/fixture/environments/test/credential"
	if AccountCreationReceiptMatches(r, acct, p) {
		t.Fatal("shared credential path was not independently pinned")
	}
	r.CredentialPath = p.SharedCredentialPath
	acct.VaultPath = p.SharedCredentialPath
	if !AccountCreationReceiptMatches(r, acct, p) {
		t.Fatal("matching shared credential path was rejected")
	}
}

func TestConnectorAccountCreationStageRequiresMatchedOutcomeAndOwnsSecrets(t *testing.T) {
	conn := connections.Connection{ID: uuid.New(), Engine: "postgres"}
	acct := inventory.Account{ID: uuid.New(), ConnectionID: conn.ID, Kind: "login", EngineIdentity: "created_login"}
	op := operations.Operation{ID: uuid.New(), Kind: KindPostgresAccountProvisionV1}
	proof := adapter.AccountCreationProof{EngineIdentity: acct.EngineIdentity, RoleOID: 123, TargetIdentity: "postgres:system:42"}
	for _, stage := range []string{"preflight", "create", "verify"} {
		for _, mode := range []string{"success", "wrong_job", "wrong_stage", "wrong_account", "wrong_version", "unconfirmed", "missing_proof", "foreign_identity", "foreign_target", "foreign_oid", "unknown_field", "typed_denied", "transport"} {
			t.Run(stage+"/"+mode, func(t *testing.T) {
				var owned []byte
				dispatcher := proofDispatcher(func(job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
					owned = creds.Account.Secret
					if bytes.Contains(job.Payload, owned) || job.Kind != connector.JobAccountCreation || creds.AccountVaultVersion != 7 || creds.Account.Username != acct.EngineIdentity {
						t.Fatal("worker changed stage routing, version, identity or serialized a secret")
					}
					payload, err := connector.ParseAccountCreationPayload(job.Payload)
					if err != nil || payload.Stage != stage || payload.AccountID != acct.ID.String() {
						t.Fatal("worker did not issue the closed stage payload")
					}
					out := connector.AccountCreationOutcome{Stage: stage, AccountID: acct.ID.String(), VaultVersion: 7, Confirmed: true}
					if stage != "preflight" {
						copyProof := proof
						out.Proof = &copyProof
					}
					switch mode {
					case "wrong_stage":
						out.Stage = "unknown"
					case "wrong_account":
						out.AccountID = uuid.NewString()
					case "wrong_version":
						out.VaultVersion++
					case "unconfirmed":
						out.Confirmed = false
					case "missing_proof":
						if stage == "preflight" {
							out.Proof = &proof
							break
						}
						out.Proof = nil
					case "foreign_identity", "foreign_target", "foreign_oid":
						if out.Proof == nil {
							copyProof := proof
							out.Proof = &copyProof
						}
						switch mode {
						case "foreign_identity":
							out.Proof.EngineIdentity = "foreign_login"
						case "foreign_target":
							out.Proof.TargetIdentity = "postgres:system:999"
						case "foreign_oid":
							out.Proof.RoleOID = 0
							if stage == "verify" {
								out.Proof.RoleOID = proof.RoleOID + 1
							}
						}
					case "transport":
						return connector.JobResult{}, errors.New("creation-worker-canary")
					}
					raw, err := json.Marshal(out)
					if err != nil {
						t.Fatal(err)
					}
					if mode == "unknown_field" {
						raw = append(raw[:len(raw)-1], []byte(`,"sql":"creation-worker-canary"}`)...)
					}
					res := connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}
					if mode == "wrong_job" {
						res.JobID = uuid.NewString()
					}
					if mode == "typed_denied" {
						res.Status, res.ErrorCode, res.Error = connector.JobFailed, "credential_access_denied", "creation-worker-canary"
					}
					return res, nil
				})
				executor := (&MainExecutor{}).WithConnector(ConnectorDeps{Dispatcher: dispatcher})
				candidate := []byte("creation-worker-canary")
				cfg := adapter.Connection{Engine: "postgres", ConfigIncarnation: "config-1", AdminCredentialIncarnation: 3,
					AdminCredential: adapter.Credential{Kind: "password", Username: "grantor"}}
				change := adapter.DesiredChange{Kind: adapter.ChangePostgresAccountCreateV2, Account: adapter.Account{Kind: "login", EngineIdentity: acct.EngineIdentity},
					ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: proof.TargetIdentity,
					Credential: &adapter.Credential{Kind: "password", Username: acct.EngineIdentity, Secret: candidate}}
				var input *adapter.AccountCreationProof
				if stage == "verify" {
					input = &proof
				}
				_, err := executor.connectorAccountCreationStage(t.Context(), op, conn, cfg, acct, change, stage, input, 7)
				if (err == nil) != (mode == "success") {
					t.Fatalf("stage outcome validation = %v", err)
				}
				if err != nil && bytes.Contains([]byte(err.Error()), candidate) {
					t.Fatal("worker retained connector error or credential contents")
				}
				if mode == "typed_denied" && !errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
					t.Fatal("closed connector error lost admission-denied classification")
				}
				if string(candidate) != "creation-worker-canary" || !bytes.Equal(owned, make([]byte, len(owned))) {
					t.Fatal("worker erased the staged secret or retained its dispatched copy")
				}
			})
		}
	}
}

func TestAccountCreationStageErrorsPreserveTerminalAndUnavailableSemantics(t *testing.T) {
	for _, err := range []error{adapter.ErrCredentialProofAccessDenied, adapter.ErrCredentialProofUnsupported, adapter.ErrExternalIdentityConflict, adapter.ErrTargetIdentityConflict} {
		if !isTerminal(accountCreationStageError(err)) {
			t.Fatalf("deterministic creation-stage refusal remains retryable: %v", err)
		}
	}
	if isTerminal(accountCreationStageError(errors.New("temporary target failure"))) {
		t.Fatal("temporary dependency failure became a terminal target refusal")
	}
}
