package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

type adminCredentialManagerAdapter struct {
	adapter.Adapter
	mu sync.Mutex
	// username -> exact active secret. Rotation replaces the entry for one
	// username, switch can prove an independently provisioned identity.
	active map[string]string

	proveCalls                    atomic.Int64
	rotateCalls                   atomic.Int64
	applyCalls                    atomic.Int64
	validateCalls                 atomic.Int64
	discoverCalls                 atomic.Int64
	discoverCredentialIncarnation atomic.Int64
	ambiguous                     atomic.Bool
}

func newAdminCredentialManagerAdapter(active map[string]string) *adminCredentialManagerAdapter {
	copyActive := make(map[string]string, len(active))
	for username, password := range active {
		copyActive[username] = password
	}
	return &adminCredentialManagerAdapter{Adapter: fake.New(), active: copyActive}
}

func (a *adminCredentialManagerAdapter) assessment() adapter.AdminCredentialAssessment {
	a.mu.Lock()
	canonical := ""
	for username := range a.active {
		canonical = username
		break
	}
	a.mu.Unlock()
	return adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true,
		CanonicalIdentity: canonical, AuthorityFingerprint: "authority-v1",
		TargetIdentity: "fake:target:1",
	}
}

func (a *adminCredentialManagerAdapter) proof(credential adapter.Credential) (adapter.AdminCredentialProof, error) {
	a.proveCalls.Add(1)
	if a.ambiguous.Load() {
		return adapter.AdminCredentialProof{}, adapter.ErrAdminCredentialProofAmbiguous
	}
	a.mu.Lock()
	active := a.active[credential.Username]
	a.mu.Unlock()
	if active == "" || active != string(credential.Secret) {
		return adapter.AdminCredentialProof{}, adapter.ErrAdminCredentialRejected
	}
	return adapter.AdminCredentialProof{
		CanonicalIdentity:    credential.Username,
		AuthorityFingerprint: "authority-v1",
		TargetIdentity:       "fake:target:1",
	}, nil
}

func (a *adminCredentialManagerAdapter) AssessConnectionAdminCredential(
	context.Context,
	adapter.Connection,
) (adapter.AdminCredentialAssessment, error) {
	return a.assessment(), nil
}

func (a *adminCredentialManagerAdapter) ProveConnectionAdminCredential(
	_ context.Context,
	_ adapter.Connection,
	candidate adapter.Credential,
) (adapter.AdminCredentialProof, error) {
	return a.proof(candidate)
}

func (a *adminCredentialManagerAdapter) RotateConnectionAdminCredential(
	ctx context.Context,
	cfg adapter.Connection,
	candidate adapter.Credential,
	expected adapter.AdminCredentialProof,
) (adapter.AdminCredentialRotationResult, error) {
	a.rotateCalls.Add(1)
	return adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(_ context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.proof(credential)
			},
			Apply: func(_ context.Context, credential adapter.Credential, _ adapter.AdminCredentialProof) error {
				a.applyCalls.Add(1)
				a.mu.Lock()
				a.active[credential.Username] = string(credential.Secret)
				a.mu.Unlock()
				return nil
			},
		})
}

func (a *adminCredentialManagerAdapter) ValidateConnection(
	_ context.Context,
	cfg adapter.Connection,
) error {
	a.validateCalls.Add(1)
	_, err := a.proof(cfg.AdminCredential)
	return err
}

func (a *adminCredentialManagerAdapter) Discover(
	_ context.Context,
	cfg adapter.Connection,
) (*adapter.Snapshot, error) {
	a.discoverCalls.Add(1)
	a.discoverCredentialIncarnation.Store(int64(cfg.AdminCredentialIncarnation))
	if _, err := a.proof(cfg.AdminCredential); err != nil {
		return nil, err
	}
	return &adapter.Snapshot{
		ServerVersion: "test-1",
		Topology: map[string]any{
			"target_identity": "fake:target:1",
		},
		ObservedAt: time.Now(),
	}, nil
}

func adminCredentialJob(
	t *testing.T,
	id string,
	idempotencyKey string,
	mode connector.AdminCredentialMode,
	candidateUsername string,
	epoch int64,
) connector.Job {
	t.Helper()
	payload := connector.AdminCredentialPayload{
		Connection: connector.ConnectionRef{
			ID: "conn-admin", Engine: fake.Engine, Endpoints: []string{"fake:1"},
		},
		CandidateUsername: candidateUsername,
		Epoch:             epoch,
		Mode:              mode,
	}
	if mode == connector.AdminCredentialModeRotate {
		payload.ExpectedCanonicalIdentity = candidateUsername
		payload.ExpectedAuthorityFingerprint = "authority-v1"
		payload.ExpectedTargetIdentity = "fake:target:1"
	}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatalf("marshal admin credential payload: %v", err)
	}
	kind, err := payload.JobKind()
	if err != nil {
		t.Fatalf("admin credential job kind: %v", err)
	}
	return connector.Job{
		ID: id, Kind: kind, ConnectionID: payload.Connection.ID, Engine: fake.Engine,
		ProtocolVersion: connector.ProtocolVersion, IssuedAt: time.Now().Unix(),
		IdempotencyKey: idempotencyKey, Nonce: id + "-nonce", Payload: raw,
	}
}

func adminCredentialFrame(oldUsername, oldPassword, candidateUsername, candidatePassword string, version int) connector.JobCredentials {
	out := connector.JobCredentials{
		Account: &adapter.Credential{
			Kind: "password", Username: candidateUsername, Secret: []byte(candidatePassword),
		},
		AccountVaultVersion: version,
	}
	if oldUsername != "" {
		out.Admin = &adapter.Credential{
			Kind: "password", Username: oldUsername, Secret: []byte(oldPassword),
		}
	}
	return out
}

func TestAdminCredentialSwitchUsesProofValidationAndFullDiscovery(t *testing.T) {
	sv := pairs(t)[0]
	manager := newAdminCredentialManagerAdapter(map[string]string{"replacement": "candidate-password"})
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})

	job := adminCredentialJob(t, "admin-switch-1", "idem-admin-switch-1",
		connector.AdminCredentialModeSwitch, "replacement", 3)
	res, err := rt.srv.Dispatch(t.Context(), job,
		adminCredentialFrame("", "", "replacement", "candidate-password", 6))
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("switch result = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	outcome, err := connector.ParseAdminCredentialOutcome(res.Result)
	if err != nil {
		t.Fatalf("ParseAdminCredentialOutcome: %v", err)
	}
	if outcome.Mode != connector.AdminCredentialModeSwitch || outcome.Epoch != 3 ||
		outcome.StagedVaultVersion != 6 || outcome.CandidateUsername != "replacement" ||
		outcome.Snapshot == nil || outcome.Proof.CanonicalIdentity != "replacement" || outcome.AlreadyApplied {
		t.Fatalf("switch outcome = %+v", outcome)
	}
	if manager.validateCalls.Load() != 1 || manager.discoverCalls.Load() != 1 || manager.applyCalls.Load() != 0 {
		t.Fatalf("switch calls validate/discover/apply = %d/%d/%d, want 1/1/0",
			manager.validateCalls.Load(), manager.discoverCalls.Load(), manager.applyCalls.Load())
	}
	if manager.discoverCredentialIncarnation.Load() != 6 {
		t.Fatalf("candidate discovery credential incarnation = %d, want staged version 6",
			manager.discoverCredentialIncarnation.Load())
	}
}

func TestAdminCredentialRotateRecoversResultLossAndGatewayDeduplicates(t *testing.T) {
	sv := pairs(t)[0]
	manager := newAdminCredentialManagerAdapter(map[string]string{"grantor": "old-password"})
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	ctx := t.Context()

	firstJob := adminCredentialJob(t, "admin-rotate-1", "idem-admin-rotate-1",
		connector.AdminCredentialModeRotate, "grantor", 4)
	first, err := rt.srv.Dispatch(ctx, firstJob,
		adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 9))
	if err != nil || first.Status != connector.JobSuccess {
		t.Fatalf("first rotate = status:%q error:%q dispatch:%v", first.Status, first.Error, err)
	}
	firstOutcome, err := connector.ParseAdminCredentialOutcome(first.Result)
	if err != nil || firstOutcome.AlreadyApplied {
		t.Fatalf("first outcome = %+v, err=%v", firstOutcome, err)
	}
	if manager.applyCalls.Load() != 1 || manager.rotateCalls.Load() != 1 || manager.discoverCalls.Load() != 1 {
		t.Fatalf("first calls apply/rotate/discover = %d/%d/%d",
			manager.applyCalls.Load(), manager.rotateCalls.Load(), manager.discoverCalls.Load())
	}

	// Same durable idempotency key returns cached success without invoking the
	// manager or sending a second credentials frame.
	duplicateJob := adminCredentialJob(t, "admin-rotate-duplicate", "idem-admin-rotate-1",
		connector.AdminCredentialModeRotate, "grantor", 4)
	duplicate, err := rt.srv.Dispatch(ctx, duplicateJob,
		adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 9))
	if err != nil || duplicate.Status != connector.JobSuccess {
		t.Fatalf("dedup rotate = status:%q error:%q dispatch:%v", duplicate.Status, duplicate.Error, err)
	}
	if manager.rotateCalls.Load() != 1 || manager.discoverCalls.Load() != 1 {
		t.Fatalf("cached result re-executed target: rotate/discover=%d/%d",
			manager.rotateCalls.Load(), manager.discoverCalls.Load())
	}

	// A fresh gateway has no durable success receipt, modeling loss of both
	// the wire result and its dedup record. The same immutable idempotency key is
	// therefore executed again; candidate-first proof sees that target already
	// uses the candidate and returns success without a second Apply.
	rtAfterLoss := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	retryJob := adminCredentialJob(t, "admin-rotate-retry", "idem-admin-rotate-1",
		connector.AdminCredentialModeRotate, "grantor", 4)
	retry, err := rtAfterLoss.srv.Dispatch(ctx, retryJob,
		adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 9))
	if err != nil || retry.Status != connector.JobSuccess {
		t.Fatalf("retry rotate = status:%q error:%q dispatch:%v", retry.Status, retry.Error, err)
	}
	retryOutcome, err := connector.ParseAdminCredentialOutcome(retry.Result)
	if err != nil || !retryOutcome.AlreadyApplied {
		t.Fatalf("retry outcome = %+v, err=%v", retryOutcome, err)
	}
	if manager.applyCalls.Load() != 1 || manager.rotateCalls.Load() != 2 || manager.discoverCalls.Load() != 2 {
		t.Fatalf("recovery calls apply/rotate/discover = %d/%d/%d, want 1/2/2",
			manager.applyCalls.Load(), manager.rotateCalls.Load(), manager.discoverCalls.Load())
	}
}

type unsupportedAdminManagerAdapter struct {
	adapter.Adapter
	validateCalls atomic.Int64
	discoverCalls atomic.Int64
	rotateCalls   atomic.Int64
}

func (a *unsupportedAdminManagerAdapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	a.validateCalls.Add(1)
	return a.Adapter.ValidateConnection(ctx, cfg)
}

func (a *unsupportedAdminManagerAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	a.discoverCalls.Add(1)
	return a.Adapter.Discover(ctx, cfg)
}

func (a *unsupportedAdminManagerAdapter) RotateCredential(
	ctx context.Context,
	cfg adapter.Connection,
	account adapter.Account,
	credential adapter.Credential,
) error {
	a.rotateCalls.Add(1)
	return a.Adapter.RotateCredential(ctx, cfg, account, credential)
}

func TestAdminCredentialUnsupportedManagerAndUnknownKindFailBeforeTarget(t *testing.T) {
	sv := pairs(t)[0]
	unsupported := &unsupportedAdminManagerAdapter{Adapter: fake.New()}
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return unsupported, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	creds := func() connector.JobCredentials {
		return adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 2)
	}

	job := adminCredentialJob(t, "admin-unsupported", "idem-admin-unsupported",
		connector.AdminCredentialModeRotate, "grantor", 1)
	res, err := rt.srv.Dispatch(t.Context(), job, creds())
	if err != nil {
		t.Fatalf("Dispatch unsupported manager: %v", err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "manager is unsupported") {
		t.Fatalf("unsupported result = {%q %q}", res.Status, res.Error)
	}

	unknown := adminCredentialJob(t, "admin-unknown", "idem-admin-unknown",
		connector.AdminCredentialModeRotate, "grantor", 1)
	unknown.Kind = connector.JobKind("job.admin_credential_rotate.v2")
	res, err = rt.srv.Dispatch(t.Context(), unknown, creds())
	if err != nil {
		t.Fatalf("Dispatch unknown admin kind: %v", err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "unknown job kind") {
		t.Fatalf("unknown result = {%q %q}", res.Status, res.Error)
	}
	if unsupported.validateCalls.Load() != 0 || unsupported.discoverCalls.Load() != 0 ||
		unsupported.rotateCalls.Load() != 0 {
		t.Fatalf("unsupported/unknown kind reached target: validate/discover/generic-rotate=%d/%d/%d",
			unsupported.validateCalls.Load(), unsupported.discoverCalls.Load(), unsupported.rotateCalls.Load())
	}
}

func TestAdminCredentialWireCoordinatesFailBeforeManagerOrTarget(t *testing.T) {
	sv := pairs(t)[0]
	manager := newAdminCredentialManagerAdapter(map[string]string{"replacement": "candidate-password"})
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})

	baseJob := func(id string) connector.Job {
		return adminCredentialJob(t, id, "idem-"+id,
			connector.AdminCredentialModeSwitch, "replacement", 3)
	}
	baseCreds := func() connector.JobCredentials {
		return adminCredentialFrame("", "", "replacement", "candidate-password", 6)
	}
	type wireCase struct {
		name  string
		job   connector.Job
		creds connector.JobCredentials
	}
	modeMismatch := baseJob("admin-mode-mismatch")
	modeMismatch.Kind = connector.JobAdminCredentialRotate
	missingVersion := baseCreds()
	missingVersion.AccountVaultVersion = 0
	candidateMismatch := baseCreds()
	candidateMismatch.Account.Username = "other"
	connectionMismatch := baseJob("admin-connection-mismatch")
	connectionMismatch.ConnectionID = "other-connection"
	cases := []wireCase{
		{"mode mismatch", modeMismatch, baseCreds()},
		{"missing exact version", baseJob("admin-no-version"), missingVersion},
		{"candidate mismatch", baseJob("admin-candidate-mismatch"), candidateMismatch},
		{"connection mismatch", connectionMismatch, baseCreds()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := rt.srv.Dispatch(t.Context(), tc.job, tc.creds)
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if res.Status != connector.JobFailed {
				t.Fatalf("result = {%q %q}, want failed", res.Status, res.Error)
			}
		})
	}
	if manager.proveCalls.Load() != 0 || manager.rotateCalls.Load() != 0 ||
		manager.validateCalls.Load() != 0 || manager.discoverCalls.Load() != 0 ||
		manager.applyCalls.Load() != 0 {
		t.Fatalf("invalid wire coordinates reached manager/target: prove/rotate/validate/discover/apply=%d/%d/%d/%d/%d",
			manager.proveCalls.Load(), manager.rotateCalls.Load(), manager.validateCalls.Load(),
			manager.discoverCalls.Load(), manager.applyCalls.Load())
	}
}

func TestAdminCredentialAmbiguousCandidateNeverMutates(t *testing.T) {
	sv := pairs(t)[0]
	manager := newAdminCredentialManagerAdapter(map[string]string{"grantor": "old-password"})
	manager.ambiguous.Store(true)
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	job := adminCredentialJob(t, "admin-ambiguous", "idem-admin-ambiguous",
		connector.AdminCredentialModeRotate, "grantor", 1)
	res, err := rt.srv.Dispatch(t.Context(), job,
		adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 2))
	if err != nil {
		t.Fatalf("Dispatch ambiguous candidate: %v", err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, adapter.ErrAdminCredentialProofAmbiguous.Error()) {
		t.Fatalf("ambiguous result = {%q %q}", res.Status, res.Error)
	}
	if manager.applyCalls.Load() != 0 || manager.discoverCalls.Load() != 0 {
		t.Fatalf("ambiguous proof mutated/discovered target: apply/discover=%d/%d",
			manager.applyCalls.Load(), manager.discoverCalls.Load())
	}
}

func TestAdminCredentialRotateRejectsStoredTargetFenceBeforeManagerMutation(t *testing.T) {
	sv := pairs(t)[0]
	manager := newAdminCredentialManagerAdapter(map[string]string{"grantor": "old-password"})
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	job := adminCredentialJob(t, "admin-target-fence", "idem-admin-target-fence",
		connector.AdminCredentialModeRotate, "grantor", 1)
	payload, err := connector.ParseAdminCredentialPayload(job.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.ExpectedTargetIdentity = "fake:target:other"
	job.Payload, err = payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	res, err := rt.srv.Dispatch(t.Context(), job,
		adminCredentialFrame("grantor", "old-password", "grantor", "candidate-password", 2))
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != connector.JobFailed || res.ErrorCode != "target_identity_changed" {
		t.Fatalf("target fence result = status:%q code:%q error:%q", res.Status, res.ErrorCode, res.Error)
	}
	if manager.rotateCalls.Load() != 0 || manager.applyCalls.Load() != 0 || manager.discoverCalls.Load() != 0 {
		t.Fatalf("target fence touched target mutation: rotate/apply/discover=%d/%d/%d",
			manager.rotateCalls.Load(), manager.applyCalls.Load(), manager.discoverCalls.Load())
	}
}

func TestAdminCredentialSecretsNeverEnterResultLogsOrDedup(t *testing.T) {
	sv := pairs(t)[0]
	const oldCanary = "SECRET-CANARY-admin-old-55d1"
	const candidateCanary = "SECRET-CANARY-admin-candidate-21e4"
	manager := newAdminCredentialManagerAdapter(map[string]string{"grantor": oldCanary})
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dedup := newRecordingDedup()
	rt := newRuntimeWith(t, sv,
		gateway.Config{Logger: logger, Dedup: dedup}, agent.Config{Logger: logger},
		func(string) (adapter.Adapter, error) { return manager, nil },
		runtime{calls: &atomic.Int64{}, fake: fake.New()})
	job := adminCredentialJob(t, "admin-secret-scan", "idem-admin-secret-scan",
		connector.AdminCredentialModeRotate, "grantor", 8)
	res, err := rt.srv.Dispatch(t.Context(), job,
		adminCredentialFrame("grantor", oldCanary, "grantor", candidateCanary, 17))
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("secret-scan rotate = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	resultBlob, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	for _, canary := range []string{oldCanary, candidateCanary} {
		if bytes.Contains(resultBlob, []byte(canary)) ||
			bytes.Contains(dedup.allBlobs(), []byte(canary)) ||
			strings.Contains(logs.String(), canary) {
			t.Fatalf("admin credential canary %q leaked into result, dedup or logs", canary)
		}
	}
	if len(dedup.allBlobs()) == 0 {
		t.Fatal("dedup secret scan is vacuous")
	}
}

var _ adapter.ConnectionAdminCredentialManager = (*adminCredentialManagerAdapter)(nil)
