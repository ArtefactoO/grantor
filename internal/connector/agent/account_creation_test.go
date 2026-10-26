package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
)

type creationContractAdapter struct {
	adapter.Adapter
	preflights atomic.Int64
	creates    atomic.Int64
	verifies   atomic.Int64
	mutations  atomic.Int64
	seen       chan adapter.DesiredChange
	seenProof  chan adapter.AccountCreationProof
	returned   *adapter.AccountCreationProof
	err        error
	noMarker   bool
}

func (a *creationContractAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	m.Engine = "postgres"
	m.Capabilities = append(m.Capabilities, adapter.CapPostgresSuperuserDirectV1)
	if !a.noMarker {
		m.Capabilities = append(m.Capabilities, adapter.CapPostgresAccountCreationV1)
	}
	return m
}

func (a *creationContractAdapter) PreflightAccountCreation(_ context.Context, change adapter.DesiredChange) error {
	a.preflights.Add(1)
	a.seen <- change
	return a.err
}

func (a *creationContractAdapter) CreateAccountWithProof(_ context.Context, change adapter.DesiredChange) (*adapter.AccountCreationProof, error) {
	a.creates.Add(1)
	a.seen <- change
	return a.returned, a.err
}

func (a *creationContractAdapter) VerifyCreatedAccount(_ context.Context, change adapter.DesiredChange, proof adapter.AccountCreationProof) error {
	a.verifies.Add(1)
	a.seen <- change
	a.seenProof <- proof
	return a.err
}

func (a *creationContractAdapter) Plan(context.Context, adapter.DesiredChange) (*adapter.Plan, error) {
	a.mutations.Add(1)
	return nil, errors.New("generic mutation is forbidden")
}

func (a *creationContractAdapter) Apply(context.Context, adapter.Plan) (*adapter.Result, error) {
	a.mutations.Add(1)
	return nil, errors.New("generic mutation is forbidden")
}

func (a *creationContractAdapter) Verify(context.Context, adapter.Plan) (*adapter.Verification, error) {
	a.mutations.Add(1)
	return nil, errors.New("generic mutation is forbidden")
}

func (a *creationContractAdapter) RotateCredential(context.Context, adapter.Connection, adapter.Account, adapter.Credential) error {
	a.mutations.Add(1)
	return errors.New("credential rotation is forbidden")
}

func creationAgentFixture(t *testing.T, caps []adapter.Capability, ad adapter.Adapter) (*Agent, connector.Signer, *atomic.Int64) {
	t.Helper()
	key := []byte("account-creation-signing-key")
	resolutions := &atomic.Int64{}
	a, err := New(Config{GatewayAddr: "unused.invalid:443", TLS: &tls.Config{MinVersion: tls.VersionTLS12},
		Verifier: connector.NewHMACVerifier("creation", key), CredentialsTimeout: 2 * time.Second,
		Capabilities: caps, NewAdapter: func(string) (adapter.Adapter, error) {
			resolutions.Add(1)
			return ad, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	return a, connector.NewHMACSigner("creation", key), resolutions
}

func creationStageJob(t *testing.T, stage string) connector.Job {
	t.Helper()
	p := connector.AccountCreationPayload{Stage: stage, AccountID: "account-id", Request: connector.MutationPayload{
		Connection: connector.ConnectionRef{ID: "connection-id", Engine: "postgres", Endpoints: []string{"db.test:5432"}, ConfigIncarnation: "config-1"},
		Attributes: map[string]any{"database": "postgres"},
		Change: connector.ChangeRef{Kind: string(adapter.ChangePostgresAccountCreateV2),
			Account:               connector.AccountRef{Kind: "login", EngineIdentity: "created_login"},
			ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42"},
	}}
	if stage == "verify" {
		p.Proof = &adapter.AccountCreationProof{EngineIdentity: "created_login", RoleOID: 123, TargetIdentity: "postgres:system:42"}
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return connector.Job{ID: "creation-" + stage, Kind: connector.JobAccountCreation,
		ConnectionID: "connection-id", Engine: "postgres", ProtocolVersion: connector.ProtocolVersion,
		IssuedAt: time.Now().Unix(), IdempotencyKey: "creation-" + stage, Nonce: "nonce-" + stage, Payload: raw}
}

func creationStageFrame(job connector.Job) connector.CredentialsFrame {
	return connector.CredentialsFrame{JobID: job.ID, Nonce: job.Nonce,
		Admin:                      &connector.FrameCredential{Kind: "password", Username: "grantor", Secret: []byte("creation-admin-canary")},
		AdminCredentialIncarnation: 3,
		Account:                    &connector.FrameCredential{Kind: "password", Username: "created_login", Secret: []byte("creation-account-canary")}, AccountVaultVersion: 7}
}

func executeCreationStage(t *testing.T, a *Agent, signer connector.Signer, job connector.Job, frame connector.CredentialsFrame) connector.JobResult {
	t.Helper()
	envelope, err := connector.SignJob(signer, job)
	if err != nil {
		t.Fatal(err)
	}
	frames := make(chan connector.CredentialsFrame, 1)
	frames <- frame
	return a.handleJob(t.Context(), envelope, frames)
}

func newCreationContractAdapter() *creationContractAdapter {
	return &creationContractAdapter{Adapter: fake.New(), seen: make(chan adapter.DesiredChange, 1), seenProof: make(chan adapter.AccountCreationProof, 1),
		returned: &adapter.AccountCreationProof{EngineIdentity: "created_login", RoleOID: 123, TargetIdentity: "postgres:system:42"}}
}

func TestAccountCreationAgentStagesDoNotUseGenericMutations(t *testing.T) {
	for _, stage := range []string{"preflight", "create", "verify"} {
		t.Run(stage, func(t *testing.T) {
			ad := newCreationContractAdapter()
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}, ad)
			job := creationStageJob(t, stage)
			frame := creationStageFrame(job)
			res := executeCreationStage(t, a, signer, job, frame)
			out, err := connector.ParseAccountCreationOutcome(res.Result)
			if err != nil || res.Status != connector.JobSuccess || out.Stage != stage || out.AccountID != "account-id" || out.VaultVersion != 7 {
				t.Fatalf("stage acknowledgement = %+v, parse error %v", res, err)
			}
			if ad.mutations.Load() != 0 || ad.preflights.Load()+ad.creates.Load()+ad.verifies.Load() != 1 {
				t.Fatal("stage used a generic mutation or executed more than one target step")
			}
			if (stage == "preflight" && ad.preflights.Load() != 1) || (stage == "create" && ad.creates.Load() != 1) || (stage == "verify" && ad.verifies.Load() != 1) {
				t.Fatal("stage was routed to another target operation")
			}
			change := <-ad.seen
			if change.Kind != adapter.ChangePostgresAccountCreateV2 || change.ExpectedAdminIdentity != "grantor" ||
				change.ExpectedTargetIdentity != "postgres:system:42" || change.Connection.ConfigIncarnation != "config-1" ||
				change.Connection.AdminCredentialIncarnation != 3 || change.Connection.AdminCredential.Username != "grantor" ||
				change.Connection.ID != "connection-id" || change.Connection.Engine != "postgres" ||
				change.Account.EngineIdentity != "created_login" || change.Credential == nil || change.Credential.Username != "created_login" {
				t.Fatal("connector changed an identity, incarnation or target pin")
			}
			if stage == "preflight" && out.Proof != nil {
				t.Fatal("preflight returned a creation receipt")
			}
			if stage != "preflight" && (out.Proof == nil || *out.Proof != *ad.returned) {
				t.Fatal("acknowledgement changed creation evidence")
			}
			if stage == "verify" && <-ad.seenProof != *ad.returned {
				t.Fatal("verification did not receive the signed creation receipt")
			}
			if !bytes.Equal(frame.Admin.Secret, make([]byte, len(frame.Admin.Secret))) ||
				!bytes.Equal(frame.Account.Secret, make([]byte, len(frame.Account.Secret))) {
				t.Fatal("connector retained credential bytes after the stage")
			}
		})
	}
}

func TestAccountCreationAgentPreflightRejectsBeforeCredentials(t *testing.T) {
	for _, tc := range []struct {
		name   string
		caps   []adapter.Capability
		mutate func(*connector.Job)
	}{
		{name: "legacy V2 only", caps: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1}},
		{name: "new marker without authority", caps: []adapter.Capability{adapter.CapPostgresAccountCreationV1}},
		{name: "unknown stage", mutate: func(j *connector.Job) {
			j.Payload = bytes.Replace(j.Payload, []byte(`"stage":"create"`), []byte(`"stage":"sql"`), 1)
		}},
		{name: "foreign connection", mutate: func(j *connector.Job) { j.ConnectionID = "foreign-connection" }},
		{name: "foreign engine", mutate: func(j *connector.Job) { j.Engine = "mysql" }},
		{name: "unknown SQL command", mutate: func(j *connector.Job) { j.Payload = append([]byte(`{"sql":"preflight-canary",`), j.Payload[1:]...) }},
		{name: "receipt on create", mutate: func(j *connector.Job) {
			j.Payload = append([]byte(`{"proof":{"engine_identity":"created_login","role_oid":123,"target_identity":"postgres:system:42"},`), j.Payload[1:]...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caps := tc.caps
			if caps == nil {
				caps = []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}
			}
			ad := newCreationContractAdapter()
			a, signer, resolutions := creationAgentFixture(t, caps, ad)
			job := creationStageJob(t, "create")
			if tc.mutate != nil {
				tc.mutate(&job)
			}
			envelope, err := connector.SignJob(signer, job)
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan connector.JobResult, 1)
			go func() { result <- a.handleJob(t.Context(), envelope, make(chan connector.CredentialsFrame)) }()
			select {
			case res := <-result:
				if res.Status != connector.JobFailed || strings.Contains(res.Error, "preflight-canary") {
					t.Fatal("invalid creation job was accepted or leaked unknown command contents")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("invalid creation job waited for credentials")
			}
			frames := make(chan connector.CredentialsFrame, 1)
			frames <- creationStageFrame(job)
			res := a.handleJob(t.Context(), envelope, frames)
			if res.Status != connector.JobFailed || len(frames) != 1 || resolutions.Load() != 0 {
				t.Fatal("invalid creation preflight consumed credentials or resolved a target adapter")
			}
			frame := <-frames
			frame.Zero()
		})
	}
}

func TestAccountCreationAgentRejectsMalformedCredentialFrames(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*connector.CredentialsFrame)
	}{
		{"foreign job ID", func(f *connector.CredentialsFrame) { f.JobID = "foreign-job" }},
		{"foreign nonce", func(f *connector.CredentialsFrame) { f.Nonce = "foreign-nonce" }},
		{"missing account", func(f *connector.CredentialsFrame) { f.Account = nil }},
		{"foreign username", func(f *connector.CredentialsFrame) { f.Account.Username = "foreign_login" }},
		{"wrong credential kind", func(f *connector.CredentialsFrame) { f.Account.Kind = "token" }},
		{"empty password", func(f *connector.CredentialsFrame) { f.Account.Secret = nil }},
		{"missing account version", func(f *connector.CredentialsFrame) { f.AccountVaultVersion = 0 }},
		{"negative account version", func(f *connector.CredentialsFrame) { f.AccountVaultVersion = -1 }},
		{"missing admin incarnation", func(f *connector.CredentialsFrame) { f.AdminCredentialIncarnation = 0 }},
		{"missing admin", func(f *connector.CredentialsFrame) { f.Admin = nil }},
		{"foreign admin username", func(f *connector.CredentialsFrame) { f.Admin.Username = "foreign_admin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := newCreationContractAdapter()
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}, ad)
			job := creationStageJob(t, "verify")
			frame := creationStageFrame(job)
			tc.mutate(&frame)
			res := executeCreationStage(t, a, signer, job, frame)
			if res.Status != connector.JobFailed || ad.preflights.Load()+ad.creates.Load()+ad.verifies.Load()+ad.mutations.Load() != 0 {
				t.Fatal("invalid credentials reached target account provisioning")
			}
		})
	}
}

func TestAccountCreationAgentRequiresAdapterMarkerAndContract(t *testing.T) {
	for _, withContract := range []bool{true, false} {
		t.Run(fmt.Sprintf("contract-%t", withContract), func(t *testing.T) {
			ad := newCreationContractAdapter()
			ad.noMarker = true
			var target adapter.Adapter = ad
			if !withContract {
				// Embedding only Adapter intentionally hides the optional contract.
				target = struct{ adapter.Adapter }{ad}
			}
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}, target)
			job := creationStageJob(t, "create")
			res := executeCreationStage(t, a, signer, job, creationStageFrame(job))
			if res.Status != connector.JobFailed || ad.preflights.Load()+ad.creates.Load()+ad.verifies.Load()+ad.mutations.Load() != 0 {
				t.Fatal("unadvertised or unimplemented creation contract reached the target")
			}
		})
	}
}

func TestAccountCreationAgentReturnsOnlyMatchedCreationProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*creationContractAdapter)
	}{
		{"nil receipt", func(a *creationContractAdapter) { a.returned = nil }},
		{"zero OID", func(a *creationContractAdapter) { a.returned.RoleOID = 0 }},
		{"foreign identity", func(a *creationContractAdapter) { a.returned.EngineIdentity = "creation-proof-canary" }},
		{"foreign target", func(a *creationContractAdapter) { a.returned.TargetIdentity = "creation-proof-canary" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := newCreationContractAdapter()
			tc.mutate(ad)
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}, ad)
			job := creationStageJob(t, "create")
			res := executeCreationStage(t, a, signer, job, creationStageFrame(job))
			raw, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			if res.Status != connector.JobFailed || res.ErrorCode != "invalid_creation_receipt" || len(res.Result) != 0 || bytes.Contains(raw, []byte("creation-proof-canary")) {
				t.Fatal("mismatched adapter receipt was returned as creation evidence")
			}
		})
	}
}

func TestAccountCreationAgentErrorsUseClosedRedactedCodes(t *testing.T) {
	for _, stage := range []string{"preflight", "create", "verify"} {
		for _, tc := range []struct {
			name string
			err  error
			code string
		}{
			{"HBA", fmt.Errorf("adapter-error-canary: %w", adapter.ErrCredentialProofAccessDenied), "credential_access_denied"},
			{"unsupported authentication", fmt.Errorf("adapter-error-canary: %w", adapter.ErrCredentialProofUnsupported), "credential_proof_unsupported"},
			{"foreign identity", fmt.Errorf("adapter-error-canary: %w", adapter.ErrExternalIdentityConflict), "credential_identity_conflict"},
			{"changed target", fmt.Errorf("adapter-error-canary: %w", adapter.ErrTargetIdentityConflict), "target_identity_changed"},
			{"unavailable", errors.New("adapter-error-canary"), "target_unavailable"},
		} {
			t.Run(stage+"/"+tc.name, func(t *testing.T) {
				ad := newCreationContractAdapter()
				ad.err = tc.err
				a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresAccountCreationV1}, ad)
				job := creationStageJob(t, stage)
				frame := creationStageFrame(job)
				res := executeCreationStage(t, a, signer, job, frame)
				raw, err := json.Marshal(res)
				if err != nil {
					t.Fatal(err)
				}
				if res.Status != connector.JobFailed || res.ErrorCode != tc.code || len(res.Result) != 0 {
					t.Fatalf("closed stage error = %+v, want %s", res, tc.code)
				}
				for _, canary := range []string{"adapter-error-canary", "creation-admin-canary", "creation-account-canary"} {
					if bytes.Contains(raw, []byte(canary)) {
						t.Fatal("stage result exposed adapter error or credentials")
					}
				}
				if !bytes.Equal(frame.Admin.Secret, make([]byte, len(frame.Admin.Secret))) || !bytes.Equal(frame.Account.Secret, make([]byte, len(frame.Account.Secret))) {
					t.Fatal("failed stage retained credentials")
				}
			})
		}
	}
}
