package agent_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

// adminCreds — credentials задания с admin credential подключения (ADR-0014:
// секреты приходят кадром TypeCredentials, а не из Vault connector'а).
// Свежие слайсы на каждый вызов: агент зануляет материал после исполнения.
func adminCreds() connector.JobCredentials {
	return connector.JobCredentials{
		Admin:                      &adapter.Credential{Kind: "password", Username: "admin", Secret: []byte("admin-pw")},
		AdminCredentialIncarnation: 1,
	}
}

// countingAdapter считает вызовы Discover, чтобы проверить дедупликацию
// (задание не исполняется дважды).
type countingAdapter struct {
	adapter.Adapter
	calls *atomic.Int64
}

type connectionIncarnationCaptureAdapter struct {
	adapter.Adapter
	seen chan adapter.Connection
}

func (a connectionIncarnationCaptureAdapter) Discover(_ context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	a.seen <- cfg
	return &adapter.Snapshot{}, nil
}

func (c countingAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	c.calls.Add(1)
	return c.Adapter.Discover(ctx, cfg)
}

// noProofRotatingAdapter реализует обязательный adapter.Adapter, но намеренно
// не реализует CredentialProver и не объявляет credential.prove. Счётчик
// фиксирует, коснулся ли agent target до capability guard.
type noProofRotatingAdapter struct {
	adapter.Adapter
	rotateCalls *atomic.Int64
}

type rolePolicyRoundTripAdapter struct {
	adapter.Adapter
	planCalls   *atomic.Int64
	applyCalls  *atomic.Int64
	verifyCalls *atomic.Int64
	seenSpecs   chan adapter.RolePolicySpec
}

func (a rolePolicyRoundTripAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	m.Capabilities = append(m.Capabilities, adapter.CapRolePolicyApply, adapter.CapRolePolicyCreate)
	return m
}

func (a rolePolicyRoundTripAdapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	if change.Kind != adapter.ChangeRolePolicyApply && change.Kind != adapter.ChangeRolePolicyVerify &&
		change.Kind != adapter.ChangeRolePolicyCreate {
		return a.Adapter.Plan(ctx, change)
	}
	a.planCalls.Add(1)
	if a.seenSpecs != nil && change.RolePolicySpec != nil {
		a.seenSpecs <- *change.RolePolicySpec
	}
	return &adapter.Plan{Change: change, Steps: []adapter.PlanStep{{
		Kind: "role-policy-round-trip", Description: "apply or verify fixed role policy",
	}}}, nil
}

func (a rolePolicyRoundTripAdapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if plan.Change.Kind != adapter.ChangeRolePolicyApply && plan.Change.Kind != adapter.ChangeRolePolicyCreate {
		return a.Adapter.Apply(ctx, plan)
	}
	a.applyCalls.Add(1)
	return &adapter.Result{Steps: []adapter.StepResult{{
		Step: plan.Steps[0], Status: adapter.StepApplied,
	}}}, nil
}

func (a rolePolicyRoundTripAdapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	if plan.Change.Kind != adapter.ChangeRolePolicyApply && plan.Change.Kind != adapter.ChangeRolePolicyVerify &&
		plan.Change.Kind != adapter.ChangeRolePolicyCreate {
		return a.Adapter.Verify(ctx, plan)
	}
	a.verifyCalls.Add(1)
	return &adapter.Verification{Verified: true, Details: "exact role policy"}, nil
}

func (a noProofRotatingAdapter) Manifest() adapter.Manifest {
	m := a.Adapter.Manifest()
	caps := make([]adapter.Capability, 0, len(m.Capabilities))
	for _, capability := range m.Capabilities {
		if capability != adapter.CapCredentialProve {
			caps = append(caps, capability)
		}
	}
	m.Capabilities = caps
	return m
}

func (a noProofRotatingAdapter) RotateCredential(ctx context.Context, cfg adapter.Connection,
	account adapter.Account, credential adapter.Credential) error {
	a.rotateCalls.Add(1)
	return a.Adapter.RotateCredential(ctx, cfg, account, credential)
}

// signerVerifier — согласованная пара для подписи (gateway) и проверки
// (connector) заданий.
type signerVerifier struct {
	name     string
	signer   connector.Signer
	verifier connector.Verifier
}

func pairs(t *testing.T) []signerVerifier {
	t.Helper()
	secret := []byte("dev-shared-secret")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return []signerVerifier{
		{"hmac", connector.NewHMACSigner("k", secret), connector.NewHMACVerifier("k", secret)},
		{"ed25519", connector.NewED25519Signer("g", priv), connector.NewED25519Verifier("g", pub)},
	}
}

// runtime связывает gateway и agent через реальный mTLS-loopback с ОБЩИМ fake
// adapter (мутации между заданиями видны через Discover); credentials заданий
// передаются кадром TypeCredentials из Dispatch.
type runtime struct {
	srv   *gateway.Server
	calls *atomic.Int64
	fake  *fake.Fake
}

func newRuntime(t *testing.T, sv signerVerifier) runtime {
	t.Helper()
	shared := fake.New()
	calls := &atomic.Int64{}
	return newRuntimeWith(t, sv, gateway.Config{}, agent.Config{}, func(string) (adapter.Adapter, error) {
		return countingAdapter{Adapter: shared, calls: calls}, nil
	}, runtime{calls: calls, fake: shared})
}

// newRuntimeWith поднимает gateway+agent с переопределениями конфигурации
// (базовые поля — TLS, подпись, verifier — заполняются здесь).
func newRuntimeWith(t *testing.T, sv signerVerifier, gwCfg gateway.Config, agCfg agent.Config,
	newAdapter func(string) (adapter.Adapter, error), rt runtime) runtime {
	t.Helper()
	pair := conntest.GenTLS(t, "localhost", "connector-test")

	gwCfg.TLS = pair.ServerTLS
	gwCfg.Signer = sv.signer
	srv, err := gateway.New(gwCfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	agCfg.ConnectorID = "connector-test"
	agCfg.GatewayAddr = ln.Addr().String()
	agCfg.TLS = pair.ClientTLS
	agCfg.Verifier = sv.verifier
	agCfg.NewAdapter = newAdapter
	ag, err := agent.New(agCfg)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = srv.Close()
		<-runErr
	})

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	rt.srv = srv
	return rt
}

// discoverJob строит подписываемое задание JobDiscover для fake engine.
// Payload секрет-free и не несёт даже ссылок на credentials (ADR-0014).
func discoverJob(t *testing.T, id, idem string) connector.Job {
	return discoverJobForConnection(t, id, idem, "conn-fake")
}

func discoverJobForConnection(t *testing.T, id, idem, connectionID string) connector.Job {
	t.Helper()
	payload, err := connector.DiscoverPayload{
		Connection: connector.ConnectionRef{
			ID:        connectionID,
			Engine:    fake.Engine,
			Endpoints: []string{"fake:1"},
		},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return connector.Job{
		ID:              id,
		Kind:            connector.JobDiscover,
		ConnectionID:    connectionID,
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  idem,
		Nonce:           id + "-nonce",
		Payload:         payload,
	}
}

func TestDiscoverRoundTrip(t *testing.T) {
	for _, sv := range pairs(t) {
		t.Run(sv.name, func(t *testing.T) {
			rt := newRuntime(t, sv)
			res, err := rt.srv.Dispatch(context.Background(), discoverJob(t, "job-1", "idem-1"), adminCreds())
			if err != nil {
				t.Fatalf("Dispatch: %v", err)
			}
			if res.Status != connector.JobSuccess {
				t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
			}
			var snap adapter.Snapshot
			if err := json.Unmarshal(res.Result, &snap); err != nil {
				t.Fatalf("unmarshal snapshot: %v", err)
			}

			// connector-executed discover == direct discover через тот же adapter.
			direct, err := fake.New().Discover(context.Background(), adapter.Connection{})
			if err != nil {
				t.Fatalf("direct Discover: %v", err)
			}
			if snap.ServerVersion != direct.ServerVersion {
				t.Errorf("server version = %q, want %q", snap.ServerVersion, direct.ServerVersion)
			}
			if len(snap.Resources) != len(direct.Resources) {
				t.Errorf("resources = %d, want %d", len(snap.Resources), len(direct.Resources))
			}
			if len(snap.Accounts) != len(direct.Accounts) {
				t.Errorf("accounts = %d, want %d", len(snap.Accounts), len(direct.Accounts))
			}
			if rt.calls.Load() != 1 {
				t.Errorf("Discover calls = %d, want 1", rt.calls.Load())
			}
		})
	}
}

func TestConnectorAgentPropagatesConfigAndAdminCredentialIncarnations(t *testing.T) {
	shared := fake.New()
	seen := make(chan adapter.Connection, 1)
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) {
			return connectionIncarnationCaptureAdapter{Adapter: shared, seen: seen}, nil
		}, runtime{fake: shared})

	job := discoverJob(t, "incarnation-job", "incarnation-idem")
	payload, err := connector.ParseDiscoverPayload(job.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload.Connection.ConfigIncarnation = strings.Repeat("d", 64)
	job.Payload, err = payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	creds := adminCreds()
	creds.AdminCredentialIncarnation = 41
	res, err := rt.srv.Dispatch(t.Context(), job, creds)
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("dispatch = %+v, %v", res, err)
	}
	cfg := <-seen
	if cfg.ConfigIncarnation != payload.Connection.ConfigIncarnation ||
		cfg.AdminCredentialIncarnation != 41 || cfg.AdminCredential.Username != "admin" {
		t.Fatalf("connector target lost an incarnation fence: %+v", cfg)
	}
}

func TestDedupNotExecutedTwice(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	first, err := rt.srv.Dispatch(ctx, discoverJob(t, "job-1", "idem-shared"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch #1: %v", err)
	}
	// Повтор с тем же IdempotencyKey: gateway обязан вернуть кешированный
	// результат и НЕ исполнять задание второй раз.
	second, err := rt.srv.Dispatch(ctx, discoverJob(t, "job-2", "idem-shared"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch #2: %v", err)
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("Discover calls = %d, want 1 (duplicate must not execute twice)", rt.calls.Load())
	}
	if first.Status != connector.JobSuccess || second.Status != connector.JobSuccess {
		t.Fatalf("statuses = %q/%q, want success", first.Status, second.Status)
	}
	if second.JobID != first.JobID {
		t.Errorf("cached result JobID = %q, want %q", second.JobID, first.JobID)
	}
}

// TestFailedResultNotCached — политика дедупликации кеширует только успешные
// результаты: после failed-результата задание с тем же IdempotencyKey
// исполняется заново (иначе retry операции навсегда получал бы старую ошибку).
func TestFailedResultNotCached(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	bad := discoverJob(t, "job-1", "idem-retry")
	bad.Kind = connector.JobKind("job.bogus") // неизвестный вид → failed-результат
	res, err := rt.srv.Dispatch(ctx, bad, adminCreds())
	if err != nil {
		t.Fatalf("Dispatch failed job: %v", err)
	}
	if res.Status != connector.JobFailed {
		t.Fatalf("status = %q, want failed", res.Status)
	}

	good, err := rt.srv.Dispatch(ctx, discoverJob(t, "job-2", "idem-retry"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch retry: %v", err)
	}
	if good.Status != connector.JobSuccess {
		t.Fatalf("retry status = %q, error = %q, want success (failed result must not be cached)",
			good.Status, good.Error)
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("Discover calls = %d, want 1 (retry after failure must execute)", rt.calls.Load())
	}
}

func TestRejectTamperedSignature(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])

	env, err := connector.SignJob(pairs(t)[0].signer, discoverJob(t, "job-1", "idem-tamper"))
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	env.Signature[0] ^= 0xFF // порча подписи после подписания

	res, err := rt.srv.DispatchEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("DispatchEnvelope: %v", err)
	}
	if res.Status != connector.JobFailed {
		t.Errorf("status = %q, want failed for tampered signature", res.Status)
	}
	if rt.calls.Load() != 0 {
		t.Errorf("Discover calls = %d, want 0 (tampered job must not execute)", rt.calls.Load())
	}
}

func TestRejectWrongProtocolVersion(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])

	job := discoverJob(t, "job-1", "idem-version")
	job.ProtocolVersion = "v2"
	env, err := connector.SignJob(pairs(t)[0].signer, job)
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	res, err := rt.srv.DispatchEnvelope(context.Background(), env)
	if err != nil {
		t.Fatalf("DispatchEnvelope: %v", err)
	}
	if res.Status != connector.JobFailed {
		t.Errorf("status = %q, want failed for wrong protocol version", res.Status)
	}
	if rt.calls.Load() != 0 {
		t.Errorf("Discover calls = %d, want 0 (wrong-version job must not execute)", rt.calls.Load())
	}
}

func TestUnknownJobKind(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])

	job := discoverJob(t, "job-1", "idem-bogus")
	job.Kind = connector.JobKind("job.bogus")
	res, err := rt.srv.Dispatch(context.Background(), job, adminCreds())
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.Status != connector.JobFailed {
		t.Errorf("status = %q, want failed for unknown kind", res.Status)
	}
	if rt.calls.Load() != 0 {
		t.Errorf("Discover calls = %d, want 0", rt.calls.Load())
	}
}

// --- Этап 3: мутирующие задания, параллельная выдача и heartbeat ---

// mutationJob строит подписываемое задание JobApply для fake engine.
func mutationJob(t *testing.T, id, idem string, change connector.ChangeRef) connector.Job {
	t.Helper()
	payload, err := connector.MutationPayload{
		Connection: connector.ConnectionRef{
			ID:        "conn-fake",
			Engine:    fake.Engine,
			Endpoints: []string{"fake:1"},
		},
		Change: change,
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal mutation payload: %v", err)
	}
	return connector.Job{
		ID:              id,
		Kind:            connector.JobApply,
		ConnectionID:    "conn-fake",
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  idem,
		Nonce:           id + "-nonce",
		Payload:         payload,
	}
}

// fakeHasBinding проверяет наличие binding в общем fake adapter через Discover
// (внутреннее состояние fake не экспортируется).
func fakeHasBinding(t *testing.T, f *fake.Fake, account, permission string) bool {
	t.Helper()
	snap, err := f.Discover(context.Background(), adapter.Connection{})
	if err != nil {
		t.Fatalf("fake Discover: %v", err)
	}
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == account && b.PermissionExternalID == permission {
			return true
		}
	}
	return false
}

// TestApplyRoundTrip — JobApply исполняет полный поток plan -> apply -> verify
// на стороне connector: результат несёт sanitized plan и result с
// verification, а изменение реально применено (наблюдаемо через Discover).
func TestApplyRoundTrip(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	job := mutationJob(t, "apply-1", "idem-apply-1", connector.ChangeRef{
		Kind:       string(adapter.ChangeGrant),
		Account:    connector.AccountRef{Kind: "login", EngineIdentity: "svc-a"},
		Permission: "role:app-readonly",
	})
	res, err := rt.srv.Dispatch(ctx, job, adminCreds())
	if err != nil {
		t.Fatalf("Dispatch apply: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
	}

	var plan connector.SanitizedPlan
	if err := json.Unmarshal(res.Plan, &plan); err != nil {
		t.Fatalf("unmarshal sanitized plan: %v", err)
	}
	if plan.Change.Kind != string(adapter.ChangeGrant) || plan.Change.Account != "svc-a" {
		t.Errorf("sanitized plan change = %+v, want grant for svc-a", plan.Change)
	}
	if len(plan.Steps) == 0 {
		t.Error("sanitized plan has no steps")
	}

	parsed, err := connector.ParseSanitizedResult(res.Result)
	if err != nil {
		t.Fatalf("ParseSanitizedResult: %v", err)
	}
	if parsed.Verification == nil || !parsed.Verification.Verified {
		t.Errorf("result verification = %+v, want verified", parsed.Verification)
	}
	if len(parsed.Steps) == 0 || parsed.Steps[0].Status != string(adapter.StepApplied) {
		t.Errorf("result steps = %+v, want applied", parsed.Steps)
	}

	if !fakeHasBinding(t, rt.fake, "svc-a", "role:app-readonly") {
		t.Error("grant was not applied to the fake target")
	}
}

func TestRolePolicyApplyAndAdoptRoundTripAndUnknownKindFailClosed(t *testing.T) {
	shared := fake.New()
	planCalls := &atomic.Int64{}
	applyCalls := &atomic.Int64{}
	verifyCalls := &atomic.Int64{}
	seenSpecs := make(chan adapter.RolePolicySpec, 3)
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) {
			return rolePolicyRoundTripAdapter{
				Adapter: shared, planCalls: planCalls,
				applyCalls: applyCalls, verifyCalls: verifyCalls, seenSpecs: seenSpecs,
			}, nil
		}, runtime{fake: shared})
	spec := adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read",
		RoleName: "r_app", Database: "app", Schemas: []string{"public"},
		OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_migrator"},
		Profile: "read",
	}
	change := connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyApply), Permission: "role:r_app",
		RolePolicySpec: &spec, ExpectedTargetIdentity: "postgres:system:42",
	}
	apply := mutationJob(t, "policy-apply", "idem-policy-apply", change)
	res, err := rt.srv.Dispatch(context.Background(), apply, adminCreds())
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("role policy apply = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	parsed, err := connector.ParseSanitizedResult(res.Result)
	if err != nil || parsed.Verification == nil || !parsed.Verification.Verified {
		t.Fatalf("role policy apply result = %+v, %v", parsed, err)
	}

	change.Kind = string(adapter.ChangeRolePolicyVerify)
	adopt := mutationJob(t, "policy-adopt", "idem-policy-adopt", change)
	adopt.Kind = connector.JobVerify
	res, err = rt.srv.Dispatch(context.Background(), adopt, adminCreds())
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("role policy adopt = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	if got := applyCalls.Load(); got != 1 {
		t.Fatalf("Apply calls = %d, want one apply and zero for verify-only adopt", got)
	}
	if got := planCalls.Load(); got != 2 {
		t.Fatalf("Plan calls = %d, want apply+adopt", got)
	}
	if got := verifyCalls.Load(); got != 2 {
		t.Fatalf("Verify calls = %d, want apply+adopt", got)
	}
	for range 2 {
		<-seenSpecs
	}

	mongoSpec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "cluster-observer", Name: "Cluster observer",
		RoleName: "clusterObserver", Database: "admin",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		MongoPrivileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"serverStatus"},
		}},
	}
	mongoApply := mutationJob(t, "mongo-policy-apply", "idem-mongo-policy-apply", connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyApply), Permission: "role:admin.clusterObserver",
		RolePolicySpec:         &mongoSpec,
		ExpectedTargetIdentity: "mongodb:replica-set:65f15f1276d3f744be6c0711",
	})
	res, err = rt.srv.Dispatch(context.Background(), mongoApply, adminCreds())
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("MongoDB role policy apply = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	forwarded := <-seenSpecs
	if forwarded.Engine != "mongodb" || len(forwarded.MongoInheritedRoles) != 1 ||
		len(forwarded.MongoPrivileges) != 1 || !forwarded.MongoPrivileges[0].Resource.Cluster {
		t.Fatalf("forwarded MongoDB role policy spec = %+v", forwarded)
	}

	unknown := mutationJob(t, "policy-unknown", "idem-policy-unknown", connector.ChangeRef{
		Kind: "role.policy.apply.v2", Permission: "role:r_app",
	})
	res, err = rt.srv.Dispatch(context.Background(), unknown, adminCreds())
	if err == nil || res.Status != "" || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unknown change crossed gateway allowlist = status:%q error:%q dispatch:%v", res.Status, res.Error, err)
	}
	if got := applyCalls.Load(); got != 2 {
		t.Fatalf("unknown change reached adapter Apply; calls=%d", got)
	}
}

func TestRolePolicyOldAdapterFailsBeforeTargetMutation(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	spec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "app-reader", Name: "Application reader",
		RoleName: "appReader", Database: "app",
		MongoPrivileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"},
			Actions:  []string{"find"},
		}},
	}
	job := mutationJob(t, "old-agent-policy", "idem-old-agent-policy", connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyApply), Permission: "role:app.appReader",
		RolePolicySpec:         &spec,
		ExpectedTargetIdentity: "mongodb:replica-set:65f15f1276d3f744be6c0711",
	})
	res, err := rt.srv.Dispatch(context.Background(), job, adminCreds())
	if err != nil {
		t.Fatalf("dispatch role policy to old adapter: %v", err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "unsupported") {
		t.Fatalf("old adapter result = status:%q error:%q", res.Status, res.Error)
	}
}

func TestLegacyPostgresRolePolicyCreateIsHistoryOnly(t *testing.T) {
	shared := fake.New()
	planCalls, applyCalls, verifyCalls := &atomic.Int64{}, &atomic.Int64{}, &atomic.Int64{}
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) {
			return rolePolicyRoundTripAdapter{Adapter: shared,
				planCalls: planCalls, applyCalls: applyCalls, verifyCalls: verifyCalls}, nil
		}, runtime{fake: shared})
	spec := adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read", RoleName: "r_app",
		Database: "app", Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_owner"}, Profile: "read",
	}
	job := databaseMutationJob(t, "create-policy", connector.ChangeRef{
		Kind: string(adapter.ChangeRolePolicyCreate), Permission: "role:r_app",
		RolePolicySpec: &spec, ExpectedTargetIdentity: "postgres:system:42",
	})
	res, err := rt.srv.Dispatch(t.Context(), job, adminCreds())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "history-only") ||
		planCalls.Load() != 0 || applyCalls.Load() != 0 || verifyCalls.Load() != 0 {
		t.Fatalf("legacy PostgreSQL create crossed target boundary: %+v plan=%d apply=%d verify=%d",
			res, planCalls.Load(), applyCalls.Load(), verifyCalls.Load())
	}
}

// TestApplyIdempotentRetry — повторный JobApply того же изменения (новый
// IdempotencyKey, имитация retry после потери результата) безопасен: шаг
// отдаёт skipped, verify проходит, итоговое состояние то же (exactly-once
// observable effect за счёт идемпотентности Apply).
func TestApplyIdempotentRetry(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	change := connector.ChangeRef{
		Kind:       string(adapter.ChangeGrant),
		Account:    connector.AccountRef{Kind: "login", EngineIdentity: "svc-a"},
		Permission: "role:app-readonly",
	}
	first, err := rt.srv.Dispatch(ctx, mutationJob(t, "apply-1", "idem-a1", change), adminCreds())
	if err != nil || first.Status != connector.JobSuccess {
		t.Fatalf("first apply = (%v, %q %q), want success", err, first.Status, first.Error)
	}
	second, err := rt.srv.Dispatch(ctx, mutationJob(t, "apply-2", "idem-a2", change), adminCreds())
	if err != nil || second.Status != connector.JobSuccess {
		t.Fatalf("second apply = (%v, %q %q), want success", err, second.Status, second.Error)
	}
	parsed, err := connector.ParseSanitizedResult(second.Result)
	if err != nil {
		t.Fatalf("ParseSanitizedResult: %v", err)
	}
	if len(parsed.Steps) == 0 || parsed.Steps[0].Status != string(adapter.StepSkipped) {
		t.Errorf("retry steps = %+v, want skipped (idempotent re-apply)", parsed.Steps)
	}
	if !fakeHasBinding(t, rt.fake, "svc-a", "role:app-readonly") {
		t.Error("binding lost after idempotent retry")
	}
}

// TestApplyAccountCreateUsesFrameCredential — account.create получает
// начальный credential из кадра TypeCredentials (control plane прочитал его
// из Vault), а не из payload; учётная запись появляется в целевой системе.
func TestApplyAccountCreateUsesFrameCredential(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	job := mutationJob(t, "create-1", "idem-create-1", connector.ChangeRef{
		Kind: string(adapter.ChangeAccountCreate),
		Account: connector.AccountRef{
			Kind:           "login",
			EngineIdentity: "svc-new",
		},
	})
	creds := adminCreds()
	creds.Account = &adapter.Credential{Kind: "password", Username: "svc-new", Secret: []byte("frame-account-pw")}
	res, err := rt.srv.Dispatch(ctx, job, creds)
	if err != nil {
		t.Fatalf("Dispatch account.create: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
	}
	snap, err := rt.fake.Discover(ctx, adapter.Connection{})
	if err != nil {
		t.Fatalf("fake Discover: %v", err)
	}
	found := false
	for _, a := range snap.Accounts {
		if a.EngineIdentity == "svc-new" {
			found = true
		}
	}
	if !found {
		t.Error("created account not observed in the fake target")
	}
}

// TestRotateCredentialRoundTrip — JobRotateCredential применяет НОВУЮ версию
// секрета из кадра TypeCredentials; результат несёт несекретное
// подтверждение с версией Vault из того же кадра.
func TestRotateCredentialRoundTrip(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	payload, err := connector.RotatePayload{
		Connection: connector.ConnectionRef{
			ID:        "conn-fake",
			Engine:    fake.Engine,
			Endpoints: []string{"fake:1"},
		},
		Account: connector.AccountRef{
			Kind:           "login",
			EngineIdentity: "svc-a",
		},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal rotate payload: %v", err)
	}
	creds := adminCreds()
	creds.Account = &adapter.Credential{Kind: "password", Username: "svc-a", Secret: []byte("rotated-pw")}
	creds.AccountVaultVersion = 7
	res, err := rt.srv.Dispatch(ctx, connector.Job{
		ID:              "rotate-1",
		Kind:            connector.JobRotateCredential,
		ConnectionID:    "conn-fake",
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "idem-rotate-1",
		Nonce:           "rotate-1-nonce",
		Payload:         payload,
	}, creds)
	if err != nil {
		t.Fatalf("Dispatch rotate: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
	}
	outcome, err := connector.ParseRotateOutcome(res.Result)
	if err != nil {
		t.Fatalf("ParseRotateOutcome: %v", err)
	}
	if !outcome.Rotated || outcome.VaultVersion != 7 {
		t.Errorf("rotate outcome = %+v, want rotated with vault version 7 from the frame", outcome)
	}
}

// TestRotateWithUnsupportedProofDoesNotMutate фиксирует fail-closed порядок
// managed-link на connector: отсутствие CredentialProver обнаруживается до
// RotateCredential, поэтому failed job не меняет пароль target.
func TestRotateWithUnsupportedProofDoesNotMutate(t *testing.T) {
	sv := pairs(t)[0]
	shared := fake.New()
	rotateCalls := &atomic.Int64{}
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) {
			return noProofRotatingAdapter{Adapter: shared, rotateCalls: rotateCalls}, nil
		}, runtime{calls: &atomic.Int64{}, fake: shared})

	payload, err := connector.RotatePayload{
		Connection: connector.ConnectionRef{
			ID:        "conn-fake",
			Engine:    fake.Engine,
			Endpoints: []string{"fake:1"},
		},
		Account: connector.AccountRef{
			Kind:           "login",
			EngineIdentity: "svc-a",
		},
		VerifyCredential: true,
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal rotate payload: %v", err)
	}
	creds := adminCreds()
	creds.Account = &adapter.Credential{
		Kind: "password", Username: "svc-a", Secret: []byte("must-not-be-applied"),
	}
	creds.AccountVaultVersion = 9
	res, err := rt.srv.Dispatch(context.Background(), connector.Job{
		ID:              "rotate-no-proof",
		Kind:            connector.JobRotateCredential,
		ConnectionID:    "conn-fake",
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "idem-rotate-no-proof",
		Nonce:           "rotate-no-proof-nonce",
		Payload:         payload,
	}, creds)
	if err != nil {
		t.Fatalf("Dispatch rotate: %v", err)
	}
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "credential proof is unsupported") {
		t.Fatalf("result = {%q %q}, want proof-unsupported failure", res.Status, res.Error)
	}
	if got := rotateCalls.Load(); got != 0 {
		t.Fatalf("RotateCredential calls = %d, want 0", got)
	}
}

// TestRotateWithoutFrameAccountFailsTyped — ротация без credential учётной
// записи в кадре — типизированный failed-результат, задание не применяется.
func TestRotateWithoutFrameAccountFailsTyped(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	payload, err := connector.RotatePayload{
		Connection: connector.ConnectionRef{ID: "conn-fake", Engine: fake.Engine},
		Account:    connector.AccountRef{Kind: "login", EngineIdentity: "svc-a"},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal rotate payload: %v", err)
	}
	res, err := rt.srv.Dispatch(context.Background(), connector.Job{
		ID:              "rotate-nofr",
		Kind:            connector.JobRotateCredential,
		ConnectionID:    "conn-fake",
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "idem-rotate-nofr",
		Nonce:           "rotate-nofr-nonce",
		Payload:         payload,
	}, adminCreds())
	if err != nil {
		t.Fatalf("Dispatch rotate: %v", err)
	}
	if res.Status != connector.JobFailed ||
		!strings.Contains(res.Error, "no account credential") {
		t.Errorf("result = {%q %q}, want typed failure about missing account credential", res.Status, res.Error)
	}
}

// TestPlanOnlyDoesNotMutate — JobPlan строит план, не меняя целевую систему.
func TestPlanOnlyDoesNotMutate(t *testing.T) {
	rt := newRuntime(t, pairs(t)[0])
	ctx := context.Background()

	job := mutationJob(t, "plan-1", "idem-plan-1", connector.ChangeRef{
		Kind:       string(adapter.ChangeGrant),
		Account:    connector.AccountRef{Kind: "login", EngineIdentity: "svc-a"},
		Permission: "role:app-readwrite",
	})
	job.Kind = connector.JobPlan
	res, err := rt.srv.Dispatch(ctx, job, adminCreds())
	if err != nil {
		t.Fatalf("Dispatch plan: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
	}
	var plan connector.SanitizedPlan
	if err := json.Unmarshal(res.Plan, &plan); err != nil {
		t.Fatalf("unmarshal sanitized plan: %v", err)
	}
	if len(plan.Steps) == 0 {
		t.Error("plan-only job returned no steps")
	}
	if fakeHasBinding(t, rt.fake, "svc-a", "role:app-readwrite") {
		t.Error("plan-only job mutated the target")
	}
}

// gateAdapter блокирует первый Discover до сигнала release, чтобы доказать
// параллельную выдачу заданий (второе задание завершается, пока первое
// исполняется).
type gateAdapter struct {
	adapter.Adapter
	first   *atomic.Bool
	calls   *atomic.Int64
	started chan struct{}
	release chan struct{}
}

func (g gateAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	g.calls.Add(1)
	if g.first.CompareAndSwap(false, true) {
		close(g.started)
		<-g.release
	}
	return g.Adapter.Discover(ctx, cfg)
}

// TestParallelDispatch — gateway/agent исполняют задания разных connections
// одновременно: быстрое задание завершается, пока медленное ещё in-flight.
func TestParallelDispatch(t *testing.T) {
	sv := pairs(t)[0]
	shared := fake.New()
	started := make(chan struct{})
	release := make(chan struct{})
	calls := &atomic.Int64{}
	ga := gateAdapter{Adapter: shared, first: &atomic.Bool{}, calls: calls, started: started, release: release}
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return ga, nil },
		runtime{calls: &atomic.Int64{}, fake: shared})

	slowDone := make(chan error, 1)
	go func() {
		_, err := rt.srv.Dispatch(context.Background(),
			discoverJobForConnection(t, "slow-1", "idem-slow-1", "conn-slow"), adminCreds())
		slowDone <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("slow job did not start")
	}

	// Быстрое задание завершается, пока медленное блокировано.
	fastCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := rt.srv.Dispatch(fastCtx,
		discoverJobForConnection(t, "fast-1", "idem-fast-1", "conn-fast"), adminCreds())
	if err != nil {
		t.Fatalf("fast Dispatch while slow in flight: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("fast status = %q, error = %q, want success", res.Status, res.Error)
	}

	close(release)
	if err := <-slowDone; err != nil {
		t.Fatalf("slow Dispatch: %v", err)
	}
}

// TestSameConnectionJobsNeverOverlap — локальный connector gate остаётся
// обязательным даже при MaxInFlight > 1: второй target-вызов того же
// connection не начинается, пока первый не завершился.
func TestSameConnectionJobsNeverOverlap(t *testing.T) {
	sv := pairs(t)[0]
	shared := fake.New()
	started := make(chan struct{})
	release := make(chan struct{})
	calls := &atomic.Int64{}
	ga := gateAdapter{Adapter: shared, first: &atomic.Bool{}, calls: calls, started: started, release: release}
	rt := newRuntimeWith(t, sv, gateway.Config{MaxInFlight: 4}, agent.Config{MaxInFlight: 4},
		func(string) (adapter.Adapter, error) { return ga, nil },
		runtime{calls: &atomic.Int64{}, fake: shared})

	done := make(chan error, 2)
	for _, id := range []string{"serial-1", "serial-2"} {
		id := id
		go func() {
			_, err := rt.srv.Dispatch(context.Background(),
				discoverJobForConnection(t, id, "idem-"+id, "conn-serial"), adminCreds())
			done <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first same-connection job did not start")
	}

	// Gateway уже мог выдать второй job, но connector не должен впустить его
	// в adapter до освобождения gate первым job.
	time.Sleep(200 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("adapter calls while first job is blocked = %d, want 1", got)
	}
	close(release)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("same-connection Dispatch: %v", err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("adapter calls after release = %d, want 2", got)
	}
}

// stubbornLeaseAdapter моделирует самый опасный lost-response window: target
// вызов замечает отмену lease, но не возвращается сразу. Agent обязан дождаться
// его фактического возврата перед reconnect, иначе новый job мог бы пересечься
// со старым на target.
type stubbornLeaseAdapter struct {
	adapter.Adapter
	calls         atomic.Int64
	started       chan struct{}
	canceled      chan struct{}
	release       chan struct{}
	secondStarted chan struct{}
}

func (a *stubbornLeaseAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	if a.calls.Add(1) == 1 {
		close(a.started)
		<-ctx.Done()
		close(a.canceled)
		<-a.release // намеренно игнорируем ctx до явного завершения target call
		return nil, ctx.Err()
	}
	close(a.secondStarted)
	return a.Adapter.Discover(ctx, cfg)
}

// TestLeaseDropWaitsForOldTargetBeforeReconnect доказывает полный fencing
// контур: gateway по lease закрывает сессию, agent отменяет context старого
// target call, но reconnect не происходит, пока тот реально не вернулся.
func TestLeaseDropWaitsForOldTargetBeforeReconnect(t *testing.T) {
	sv := pairs(t)[0]
	pair := conntest.GenTLS(t, "localhost", "connector-test")
	srv, err := gateway.New(gateway.Config{
		TLS:            pair.ServerTLS,
		Signer:         sv.signer,
		IOTimeout:      1500 * time.Millisecond,
		LivenessWindow: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	blocked := &stubbornLeaseAdapter{
		Adapter:       fake.New(),
		started:       make(chan struct{}),
		canceled:      make(chan struct{}),
		release:       make(chan struct{}),
		secondStarted: make(chan struct{}),
	}
	ag, err := agent.New(agent.Config{
		ConnectorID:       "connector-test",
		GatewayAddr:       ln.Addr().String(),
		TLS:               pair.ClientTLS,
		Verifier:          sv.verifier,
		HeartbeatInterval: 100 * time.Millisecond,
		MaxInFlight:       2,
		NewAdapter: func(string) (adapter.Adapter, error) {
			return blocked, nil
		},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	var attempts atomic.Int64
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		for ctx.Err() == nil {
			attempts.Add(1)
			_ = ag.Run(ctx)
		}
	}()
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(blocked.release) })
		cancel()
		_ = ln.Close()
		_ = srv.Close()
		<-runDone
	})

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("initial WaitReady: %v", err)
	}

	dispatchDone := make(chan error, 1)
	go func() {
		_, err := srv.Dispatch(context.Background(),
			discoverJobForConnection(t, "lease-old", "idem-lease-old", "conn-lease"), adminCreds())
		dispatchDone <- err
	}()
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("old target call did not start")
	}
	select {
	case <-blocked.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not cancel the old target context at job deadline")
	}
	if err := <-dispatchDone; !errors.Is(err, gateway.ErrLeaseExpired) {
		t.Fatalf("old Dispatch = %v, want ErrLeaseExpired", err)
	}
	if _, _, ok := srv.ConnectedConnector(); ok {
		t.Fatal("gateway retained the expired wire session")
	}

	// Старый adapter всё ещё не вернулся. Тот же agent не имеет права начать
	// вторую Run/reconnect попытку до освобождения target call.
	time.Sleep(250 * time.Millisecond)
	if got := attempts.Load(); got != 1 {
		t.Fatalf("agent Run attempts before old target returned = %d, want 1", got)
	}
	select {
	case <-blocked.secondStarted:
		t.Fatal("new target call started before the old one returned")
	default:
	}

	releaseOnce.Do(func() { close(blocked.release) })
	reconnectCtx, reconnectCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reconnectCancel()
	if err := srv.WaitReady(reconnectCtx); err != nil {
		t.Fatalf("WaitReady after old target returned: %v", err)
	}
	if got := attempts.Load(); got < 2 {
		t.Fatalf("agent Run attempts after release = %d, want at least 2", got)
	}

	res, err := srv.Dispatch(reconnectCtx,
		discoverJobForConnection(t, "lease-new", "idem-lease-new", "conn-lease"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch after quiescent reconnect: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("new status = %q, error = %q, want success", res.Status, res.Error)
	}
}

// TestHeartbeatKeepsSessionAlive — agent с частым heartbeat переживает
// короткое liveness-окно gateway: сессия жива и задания исполняются даже
// после паузы, превышающей окно.
func TestHeartbeatKeepsSessionAlive(t *testing.T) {
	sv := pairs(t)[0]
	shared := fake.New()
	calls := &atomic.Int64{}
	rt := newRuntimeWith(t, sv,
		gateway.Config{LivenessWindow: 700 * time.Millisecond},
		agent.Config{HeartbeatInterval: 100 * time.Millisecond},
		func(string) (adapter.Adapter, error) {
			return countingAdapter{Adapter: shared, calls: calls}, nil
		},
		runtime{calls: calls, fake: shared})

	// Пауза заметно дольше liveness-окна: без heartbeat сессия была бы снята.
	time.Sleep(1500 * time.Millisecond)
	if !rt.srv.ConnectorAlive() {
		t.Fatal("connector is not alive despite heartbeats")
	}
	res, err := rt.srv.Dispatch(context.Background(), discoverJob(t, "hb-1", "idem-hb-1"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch after idle period: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, error = %q, want success", res.Status, res.Error)
	}
}

// --- ADR-0014: инварианты кадра credentials ---

// recordingDedup — DedupStore, записывающий всё сохраняемое: доказывает, что
// в durable-хранилище не попадает ничего, кроме JobResult (и в нём нет
// секретов задания). Store принимает ТОЛЬКО connector.JobResult по сигнатуре
// интерфейса — кадру credentials в него попасть некуда структурно; тест
// дополнительно ищет canary в фактически сохранённых байтах.
type recordingDedup struct {
	mu     sync.Mutex
	stored map[string]connector.JobResult
	blobs  [][]byte
}

func newRecordingDedup() *recordingDedup {
	return &recordingDedup{stored: map[string]connector.JobResult{}}
}

func (d *recordingDedup) Lookup(_ context.Context, key string) (connector.JobResult, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, ok := d.stored[key]
	return res, ok, nil
}

func (d *recordingDedup) Store(_ context.Context, key string, res connector.JobResult) error {
	blob, err := json.Marshal(res)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.stored[key]; !ok {
		d.stored[key] = res
	}
	d.blobs = append(d.blobs, blob)
	return nil
}

func (d *recordingDedup) allBlobs() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return bytes.Join(d.blobs, []byte("\n"))
}

// syncBuffer — потокобезопасный буфер для захвата логов gateway и agent.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestCredentialsNotLoggedOrPersisted — canary-секреты, переданные кадром
// credentials, не попадают ни в логи gateway/agent (включая debug-уровень),
// ни в dedup store, ни в JobResult. Единственный носитель — кадр
// TypeCredentials в mTLS-канале.
func TestCredentialsNotLoggedOrPersisted(t *testing.T) {
	sv := pairs(t)[0]
	logs := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	dedup := newRecordingDedup()
	shared := fake.New()
	calls := &atomic.Int64{}
	rt := newRuntimeWith(t, sv,
		gateway.Config{Logger: logger, Dedup: dedup},
		agent.Config{Logger: logger},
		func(string) (adapter.Adapter, error) {
			return countingAdapter{Adapter: shared, calls: calls}, nil
		},
		runtime{calls: calls, fake: shared})
	ctx := context.Background()

	const adminCanary = "SECRET-CANARY-admin-3f9c"
	const accountCanary = "SECRET-CANARY-account-8a1d"

	creds := connector.JobCredentials{
		Admin: &adapter.Credential{Kind: "password", Username: "admin", Secret: []byte(adminCanary)},
	}
	res, err := rt.srv.Dispatch(ctx, discoverJob(t, "canary-1", "idem-canary-1"), creds)
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("discover = (%v, %q %q), want success", err, res.Status, res.Error)
	}

	createJob := mutationJob(t, "canary-2", "idem-canary-2", connector.ChangeRef{
		Kind:    string(adapter.ChangeAccountCreate),
		Account: connector.AccountRef{Kind: "login", EngineIdentity: "svc-canary"},
	})
	createCreds := connector.JobCredentials{
		Admin:   &adapter.Credential{Kind: "password", Username: "admin", Secret: []byte(adminCanary)},
		Account: &adapter.Credential{Kind: "password", Username: "svc-canary", Secret: []byte(accountCanary)},
	}
	createRes, err := rt.srv.Dispatch(ctx, createJob, createCreds)
	if err != nil || createRes.Status != connector.JobSuccess {
		t.Fatalf("account.create = (%v, %q %q), want success", err, createRes.Status, createRes.Error)
	}

	// Позитивный контроль представительности: dedup реально что-то сохранил.
	if len(dedup.allBlobs()) == 0 {
		t.Fatal("dedup store recorded nothing; the no-secrets check is vacuous")
	}
	for _, canary := range []string{adminCanary, accountCanary} {
		if strings.Contains(logs.String(), canary) {
			t.Errorf("credential canary %q leaked into gateway/agent logs", canary)
		}
		if bytes.Contains(dedup.allBlobs(), []byte(canary)) {
			t.Errorf("credential canary %q leaked into the dedup store", canary)
		}
		for _, res := range []connector.JobResult{res, createRes} {
			blob, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("marshal result: %v", err)
			}
			if bytes.Contains(blob, []byte(canary)) {
				t.Errorf("credential canary %q leaked into a job result", canary)
			}
		}
	}
}

// capturingAdapter записывает слайсы секретов, реально переданные adapter,
// чтобы проверить их зануление агентом после исполнения задания.
type capturingAdapter struct {
	adapter.Adapter
	mu       sync.Mutex
	secrets  [][]byte
	failNext bool
}

func (c *capturingAdapter) capture(bs ...[]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range bs {
		if len(b) > 0 {
			c.secrets = append(c.secrets, b)
		}
	}
}

func (c *capturingAdapter) captured() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.secrets
}

func (c *capturingAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	c.capture(cfg.AdminCredential.Secret)
	return c.Adapter.Discover(ctx, cfg)
}

func (c *capturingAdapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	c.capture(change.Connection.AdminCredential.Secret)
	if change.Credential != nil {
		c.capture(change.Credential.Secret)
	}
	return c.Adapter.Plan(ctx, change)
}

func (c *capturingAdapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	c.capture(cfg.AdminCredential.Secret, credential.Secret)
	c.mu.Lock()
	fail := c.failNext
	c.mu.Unlock()
	if fail {
		return errors.New("simulated rotate failure")
	}
	return c.Adapter.RotateCredential(ctx, cfg, account, credential)
}

// assertZeroed проверяет, что все захваченные слайсы секретов занулены.
func assertZeroed(t *testing.T, secrets [][]byte) {
	t.Helper()
	if len(secrets) == 0 {
		t.Fatal("no secrets captured; the zeroing check is vacuous")
	}
	for i, b := range secrets {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("captured secret #%d is not zeroed after job completion", i)
		}
	}
}

// TestCredentialsZeroedAfterUse — agent зануляет секретный материал кадра
// после исполнения задания: слайсы, реально переданные adapter (admin и
// account credential), обнулены к моменту получения результата — и для
// успешного задания, и для упавшего (failed jobs не удерживают секреты).
func TestCredentialsZeroedAfterUse(t *testing.T) {
	sv := pairs(t)[0]
	shared := fake.New()
	capt := &capturingAdapter{Adapter: shared}
	rt := newRuntimeWith(t, sv, gateway.Config{}, agent.Config{},
		func(string) (adapter.Adapter, error) { return capt, nil },
		runtime{calls: &atomic.Int64{}, fake: shared})
	ctx := context.Background()

	// Успешное задание: discover с admin credential.
	res, err := rt.srv.Dispatch(ctx, discoverJob(t, "zero-1", "idem-zero-1"), adminCreds())
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("discover = (%v, %q %q), want success", err, res.Status, res.Error)
	}
	assertZeroed(t, capt.captured())

	// Упавшее задание: rotate с ошибкой adapter — секреты всё равно занулены.
	capt.mu.Lock()
	capt.failNext = true
	capt.mu.Unlock()
	payload, err := connector.RotatePayload{
		Connection: connector.ConnectionRef{ID: "conn-fake", Engine: fake.Engine},
		Account:    connector.AccountRef{Kind: "login", EngineIdentity: "svc-a"},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal rotate payload: %v", err)
	}
	creds := adminCreds()
	creds.Account = &adapter.Credential{Kind: "password", Username: "svc-a", Secret: []byte("doomed-pw")}
	failRes, err := rt.srv.Dispatch(ctx, connector.Job{
		ID:              "zero-2",
		Kind:            connector.JobRotateCredential,
		ConnectionID:    "conn-fake",
		Engine:          fake.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "idem-zero-2",
		Nonce:           "zero-2-nonce",
		Payload:         payload,
	}, creds)
	if err != nil {
		t.Fatalf("Dispatch failing rotate: %v", err)
	}
	if failRes.Status != connector.JobFailed {
		t.Fatalf("status = %q, want failed", failRes.Status)
	}
	assertZeroed(t, capt.captured())
}

// rawGatewaySession — «сырое» gateway-соединение: реальный agent подключён к
// тестовому TLS-серверу, кадры пишет сам тест. Нужен для сценариев нарушения
// протокола credentials, которые настоящий gateway не воспроизводит
// (отсутствующий кадр, чужая привязка).
type rawGatewaySession struct {
	conn *tls.Conn
}

// startRawGatewaySession поднимает TLS-listener, подключает к нему agent с
// коротким CredentialsTimeout и проходит handshake вручную.
func startRawGatewaySession(t *testing.T, sv signerVerifier) *rawGatewaySession {
	return startRawGatewaySessionWithAdapter(t, sv,
		func(string) (adapter.Adapter, error) { return fake.New(), nil })
}

func startRawGatewaySessionWithAdapter(t *testing.T, sv signerVerifier,
	newAdapter func(string) (adapter.Adapter, error)) *rawGatewaySession {
	t.Helper()
	pair := conntest.GenTLS(t, "localhost", "connector-test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", pair.ServerTLS)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	ag, err := agent.New(agent.Config{
		ConnectorID:        "connector-test",
		GatewayAddr:        ln.Addr().String(),
		TLS:                pair.ClientTLS,
		Verifier:           sv.verifier,
		CredentialsTimeout: 300 * time.Millisecond,
		NewAdapter:         newAdapter,
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-runErr
	})

	var conn net.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not connect to the raw gateway")
	}
	tlsConn := conn.(*tls.Conn)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	var hello connector.Hello
	if err := wire.ReadJSON(tlsConn, wire.TypeHello, &hello); err != nil {
		t.Fatalf("read hello: %v", err)
	}
	if err := wire.WriteJSON(tlsConn, wire.TypeHelloAck,
		wire.HelloAck{ProtocolVersion: connector.ProtocolVersion}); err != nil {
		t.Fatalf("write hello ack: %v", err)
	}
	t.Cleanup(func() { _ = tlsConn.Close() })
	return &rawGatewaySession{conn: tlsConn}
}

// awaitResult читает кадры до TypeResult (heartbeat игнорируется).
func (s *rawGatewaySession) awaitResult(t *testing.T) connector.JobResult {
	t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		typ, payload, err := wire.ReadFrame(s.conn)
		if err != nil {
			t.Fatalf("read frame: %v", err)
		}
		if typ != wire.TypeResult {
			continue
		}
		var res connector.JobResult
		if err := json.Unmarshal(payload, &res); err != nil {
			t.Fatalf("unmarshal result: %v", err)
		}
		return res
	}
}

type deadlineContextAdapter struct {
	adapter.Adapter
	seen chan time.Time
}

func (a deadlineContextAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("job execution context has no deadline")
	}
	a.seen <- deadline
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestJobDeadlineBoundsTargetContext — signed Job.Deadline ограничивает не
// только pre-start check: ровно этот deadline видит выполняющийся adapter, и
// долгий target call отменяется без разрыва живой wire-сессии.
func TestJobDeadlineBoundsTargetContext(t *testing.T) {
	sv := pairs(t)[0]
	seen := make(chan time.Time, 1)
	s := startRawGatewaySessionWithAdapter(t, sv, func(string) (adapter.Adapter, error) {
		return deadlineContextAdapter{Adapter: fake.New(), seen: seen}, nil
	})

	job := discoverJob(t, "deadline-1", "idem-deadline-1")
	job.Deadline = time.Now().Add(2 * time.Second).Unix()
	env, err := connector.SignJob(sv.signer, job)
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	if err := wire.WriteJSON(s.conn, wire.TypeJob, env); err != nil {
		t.Fatalf("write job: %v", err)
	}
	if err := wire.WriteJSON(s.conn, wire.TypeCredentials, adminCreds().Frame(job)); err != nil {
		t.Fatalf("write credentials: %v", err)
	}

	select {
	case got := <-seen:
		want := time.Unix(job.Deadline, 0)
		if !got.Equal(want) {
			t.Fatalf("adapter context deadline = %s, want %s", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("adapter did not receive the job")
	}
	res := s.awaitResult(t)
	if res.Status != connector.JobFailed || !strings.Contains(res.Error, "context deadline exceeded") {
		t.Fatalf("result = {%q %q}, want deadline failure", res.Status, res.Error)
	}
}

// TestMissingCredentialsFrameFailsTyped — control plane, не приславший кадр
// TypeCredentials (прежний контракт), получает типизированный failed-результат
// по таймауту ожидания кадра; задание не исполняется и agent не зависает.
func TestMissingCredentialsFrameFailsTyped(t *testing.T) {
	sv := pairs(t)[0]
	s := startRawGatewaySession(t, sv)

	env, err := connector.SignJob(sv.signer, discoverJob(t, "nofr-1", "idem-nofr-1"))
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	if err := wire.WriteJSON(s.conn, wire.TypeJob, env); err != nil {
		t.Fatalf("write job: %v", err)
	}
	// Кадр credentials сознательно не отправляется.
	res := s.awaitResult(t)
	if res.JobID != env.Job.ID || res.Status != connector.JobFailed ||
		!strings.Contains(res.Error, "credentials frame was not received") {
		t.Errorf("result = %+v, want typed failure about the missing credentials frame", res)
	}
}

// TestCredentialsFrameNonceMismatchRejected — кадр credentials с чужой
// привязкой (правильный JobID, чужой Nonce) отклоняется типизированным
// failed-результатом; задание не исполняется.
func TestCredentialsFrameNonceMismatchRejected(t *testing.T) {
	sv := pairs(t)[0]
	s := startRawGatewaySession(t, sv)

	job := discoverJob(t, "badnonce-1", "idem-badnonce-1")
	env, err := connector.SignJob(sv.signer, job)
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	if err := wire.WriteJSON(s.conn, wire.TypeJob, env); err != nil {
		t.Fatalf("write job: %v", err)
	}
	frame := adminCreds().Frame(job)
	frame.Nonce = "spoofed-nonce"
	if err := wire.WriteJSON(s.conn, wire.TypeCredentials, frame); err != nil {
		t.Fatalf("write credentials frame: %v", err)
	}
	res := s.awaitResult(t)
	if res.JobID != job.ID || res.Status != connector.JobFailed ||
		!strings.Contains(res.Error, "not bound to the job") {
		t.Errorf("result = %+v, want typed failure about the frame binding", res)
	}
}
