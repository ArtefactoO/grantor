package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
)

type statsContractAdapter struct {
	adapter.Adapter
	seen     []adapter.DesiredChange
	noMarker bool
	verify   bool
	err      error
}

func (a *statsContractAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	m.Engine = "postgres"
	m.Capabilities = append(m.Capabilities, adapter.CapPostgresSuperuserDirectV1)
	if !a.noMarker {
		m.Capabilities = append(m.Capabilities, adapter.CapPostgresStatsMembershipV1)
	}
	return m
}
func (a *statsContractAdapter) Plan(_ context.Context, c adapter.DesiredChange) (*adapter.Plan, error) {
	a.seen = append(a.seen, c)
	return &adapter.Plan{Change: c, Steps: []adapter.PlanStep{{Kind: "stats-membership"}}}, a.err
}
func (a *statsContractAdapter) Apply(_ context.Context, p adapter.Plan) (*adapter.Result, error) {
	return &adapter.Result{Steps: []adapter.StepResult{{Step: p.Steps[0], Status: adapter.StepApplied}}}, a.err
}
func (a *statsContractAdapter) Verify(context.Context, adapter.Plan) (*adapter.Verification, error) {
	return &adapter.Verification{Verified: a.verify}, a.err
}

func statsAgentJob(t *testing.T, kind adapter.ChangeKind) connector.Job {
	t.Helper()
	p := connector.MutationPayload{Connection: connector.ConnectionRef{ID: "stats-connection", Engine: "postgres", ConfigIncarnation: "stats-config", Endpoints: []string{"db.test:5432"}},
		Change: connector.ChangeRef{Kind: string(kind), Account: connector.AccountRef{Kind: "login", EngineIdentity: "monitor"}, Permission: "role:pg_read_all_stats",
			ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42", StatsMembership: &adapter.PostgresStatsMembershipPins{
				AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "stats-config", CredentialIncarnation: 3, BuiltinOID: 3375, SubjectOID: 17001}}}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return connector.Job{ID: "stats-job", Kind: connector.JobApply, ConnectionID: p.Connection.ID, Engine: "postgres", ProtocolVersion: connector.ProtocolVersion,
		IssuedAt: time.Now().Unix(), IdempotencyKey: "stats-job", Nonce: "stats-nonce", Payload: raw}
}
func statsAgentFrame(job connector.Job) connector.CredentialsFrame {
	return connector.CredentialsFrame{JobID: job.ID, Nonce: job.Nonce, Admin: &connector.FrameCredential{Kind: "password", Username: "grantor", Secret: []byte("stats-frame-canary")}, AdminCredentialIncarnation: 3}
}

func TestStatsMembershipAgentCapabilityAndSignatureRejectBeforeCredentials(t *testing.T) {
	for _, caps := range [][]adapter.Capability{{adapter.CapPostgresSuperuserDirectV1}, {adapter.CapPostgresStatsMembershipV1}} {
		ad := &statsContractAdapter{Adapter: fake.New(), verify: true}
		a, signer, resolutions := creationAgentFixture(t, caps, ad)
		job := statsAgentJob(t, adapter.ChangePostgresStatsMembershipGrantV1)
		env, err := connector.SignJob(signer, job)
		if err != nil {
			t.Fatal(err)
		}
		frames := make(chan connector.CredentialsFrame, 1)
		frames <- statsAgentFrame(job)
		result := a.handleJob(t.Context(), env, frames)
		if result.Status != connector.JobFailed || len(frames) != 1 || resolutions.Load() != 0 || len(ad.seen) != 0 {
			t.Fatal("unsupported runtime consumed credentials or reached adapter")
		}
		frame := <-frames
		frame.Zero()
	}
	ad := &statsContractAdapter{Adapter: fake.New(), verify: true}
	a, signer, resolutions := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresStatsMembershipV1}, ad)
	job := statsAgentJob(t, adapter.ChangePostgresStatsMembershipGrantV1)
	env, err := connector.SignJob(signer, job)
	if err != nil {
		t.Fatal(err)
	}
	env.Job.Payload = bytes.ReplaceAll(env.Job.Payload, []byte("17001"), []byte("17002"))
	frames := make(chan connector.CredentialsFrame, 1)
	frames <- statsAgentFrame(job)
	if res := a.handleJob(t.Context(), env, frames); res.Status != connector.JobFailed || len(frames) != 1 || resolutions.Load() != 0 {
		t.Fatal("tampered signed pins reached credentials or adapter")
	}
	frame := <-frames
	frame.Zero()
}

func TestStatsMembershipAgentCredentialBindingBeforeTargetPlan(t *testing.T) {
	for name, mutate := range map[string]func(*connector.CredentialsFrame){
		"admin version": func(f *connector.CredentialsFrame) { f.AdminCredentialIncarnation++ },
		"admin name":    func(f *connector.CredentialsFrame) { f.Admin.Username = "other_admin" },
		"no admin":      func(f *connector.CredentialsFrame) { f.Admin = nil },
		"account secret": func(f *connector.CredentialsFrame) {
			f.Account = &connector.FrameCredential{Username: "monitor", Secret: []byte("stats-account-canary")}
		},
		"account version": func(f *connector.CredentialsFrame) { f.AccountVaultVersion = 1 },
		"wrong nonce":     func(f *connector.CredentialsFrame) { f.Nonce = "different" },
	} {
		t.Run(name, func(t *testing.T) {
			ad := &statsContractAdapter{Adapter: fake.New(), verify: true}
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresStatsMembershipV1}, ad)
			job := statsAgentJob(t, adapter.ChangePostgresStatsMembershipGrantV1)
			frame := statsAgentFrame(job)
			mutate(&frame)
			res := executeCreationStage(t, a, signer, job, frame)
			if res.Status != connector.JobFailed || len(ad.seen) != 0 {
				t.Fatal("mismatched credential frame reached target plan")
			}
		})
	}
}

func TestStatsMembershipAgentForwardsOnlyTypedPinsAndFailsUnprovenApply(t *testing.T) {
	for _, tc := range []struct {
		name               string
		noMarker, verified bool
		err                error
		success            bool
	}{
		{name: "supported", verified: true, success: true},
		{name: "adapter missing marker", noMarker: true, verified: true},
		{name: "dependency unavailable", err: errors.New("target unavailable")},
		{name: "unsatisfied read back"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := &statsContractAdapter{Adapter: fake.New(), verify: tc.verified, noMarker: tc.noMarker, err: tc.err}
			a, signer, _ := creationAgentFixture(t, []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresStatsMembershipV1}, ad)
			job := statsAgentJob(t, adapter.ChangePostgresStatsMembershipGrantV1)
			res := executeCreationStage(t, a, signer, job, statsAgentFrame(job))
			if (res.Status == connector.JobSuccess) != tc.success {
				t.Fatalf("incorrect stats result: %s %s", res.Status, res.Error)
			}
			if tc.success {
				if len(ad.seen) != 1 || ad.seen[0].StatsMembership == nil || ad.seen[0].StatsMembership.SubjectOID != 17001 || ad.seen[0].Credential != nil || len(ad.seen[0].Attributes) != 0 || ad.seen[0].Connection.AdminCredentialIncarnation != 3 {
					t.Fatal("typed stats change lost pins or received account credential")
				}
			}
			encoded, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("stats-frame-canary")) {
				t.Fatal("stats outcome leaked credential")
			}
		})
	}
}
