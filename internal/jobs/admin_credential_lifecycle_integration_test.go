//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const adminCredentialLifecycleEngine = "admin-credential-lifecycle-test"

var (
	registerAdminCredentialLifecycleOnce sync.Once
	adminCredentialLifecycleTargetMu     sync.Mutex
	adminCredentialLifecycleTarget       *lifecycleTarget
)

type lifecycleTarget struct {
	mu                sync.Mutex
	passwords         map[string]string
	authority         string
	targetIdentity    string
	applyCount        int
	proofCount        int
	loseApplyResponse bool
}

func (t *lifecycleTarget) prove(credential adapter.Credential) (adapter.AdminCredentialProof, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.proofCount++
	password, exists := t.passwords[credential.Username]
	if !exists || password != string(credential.Secret) {
		return adapter.AdminCredentialProof{}, fmt.Errorf("target authentication rejected: %w",
			adapter.ErrAdminCredentialRejected)
	}
	return adapter.AdminCredentialProof{
		CanonicalIdentity: credential.Username, AuthorityFingerprint: t.authority,
		TargetIdentity: t.targetIdentity,
	}, nil
}

func (t *lifecycleTarget) rotate(candidate adapter.Credential) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.passwords[candidate.Username] = string(candidate.Secret)
	t.applyCount++
	if t.loseApplyResponse {
		t.loseApplyResponse = false
		return errors.New("simulated lost target response")
	}
	return nil
}

func (t *lifecycleTarget) applies() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.applyCount
}

func (t *lifecycleTarget) proofs() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.proofCount
}

type lifecycleAdapter struct {
	adapter.Adapter
	target *lifecycleTarget
}

func newLifecycleAdapter() adapter.Adapter {
	adminCredentialLifecycleTargetMu.Lock()
	target := adminCredentialLifecycleTarget
	adminCredentialLifecycleTargetMu.Unlock()
	return &lifecycleAdapter{Adapter: fake.New(), target: target}
}

func (a *lifecycleAdapter) Manifest() adapter.Manifest {
	manifest := a.Adapter.Manifest()
	manifest.Engine = adminCredentialLifecycleEngine
	manifest.Capabilities = append(manifest.Capabilities,
		adapter.CapConnectionAdminCredentialSwitch,
		adapter.CapConnectionAdminCredentialRotate)
	return manifest
}

func (a *lifecycleAdapter) ValidateConnection(_ context.Context, cfg adapter.Connection) error {
	_, err := a.target.prove(cfg.AdminCredential)
	return err
}

func (a *lifecycleAdapter) Discover(_ context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	proof, err := a.target.prove(cfg.AdminCredential)
	if err != nil {
		return nil, err
	}
	topology := map[string]any{}
	adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true,
		CanonicalIdentity: proof.CanonicalIdentity, AuthorityFingerprint: proof.AuthorityFingerprint,
		TargetIdentity: proof.TargetIdentity,
	})
	return &adapter.Snapshot{
		ServerVersion: "test", Topology: topology, ObservedAt: time.Now(),
		Accounts: []adapter.ObservedAccount{{Kind: "login", EngineIdentity: cfg.AdminCredential.Username}},
	}, nil
}

func (a *lifecycleAdapter) AssessConnectionAdminCredential(_ context.Context,
	cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	proof, err := a.target.prove(cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	return adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true,
		CanonicalIdentity: proof.CanonicalIdentity, AuthorityFingerprint: proof.AuthorityFingerprint,
		TargetIdentity: proof.TargetIdentity,
	}, nil
}

func (a *lifecycleAdapter) ProveConnectionAdminCredential(_ context.Context,
	_ adapter.Connection, candidate adapter.Credential) (adapter.AdminCredentialProof, error) {
	return a.target.prove(candidate)
}

func (a *lifecycleAdapter) RotateConnectionAdminCredential(ctx context.Context,
	cfg adapter.Connection, candidate adapter.Credential,
	expected adapter.AdminCredentialProof) (adapter.AdminCredentialRotationResult, error) {
	return adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(_ context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.target.prove(credential)
			},
			Apply: func(_ context.Context, credential adapter.Credential, _ adapter.AdminCredentialProof) error {
				return a.target.rotate(credential)
			},
		})
}

type lifecycleVaultValue struct {
	version int
	data    map[string]any
	history map[int]map[string]any
}

type lifecycleVault struct {
	mu              sync.Mutex
	values          map[string]*lifecycleVaultValue
	loseCASResponse bool
}

func newLifecycleVault() *lifecycleVault {
	return &lifecycleVault{values: map[string]*lifecycleVaultValue{}}
}

func cloneVaultData(data map[string]any) map[string]any {
	out := make(map[string]any, len(data))
	for key, value := range data {
		out[key] = value
	}
	return out
}

func (v *lifecycleVault) Get(_ context.Context, path string) (map[string]any, int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	value := v.values[path]
	if value == nil {
		return nil, 0, vault.ErrNotFound
	}
	return cloneVaultData(value.data), value.version, nil
}

func (v *lifecycleVault) GetVersion(_ context.Context, path string, version int) (map[string]any, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	value := v.values[path]
	if value == nil || value.history[version] == nil {
		return nil, vault.ErrNotFound
	}
	return cloneVaultData(value.history[version]), nil
}

func (v *lifecycleVault) PutCAS(_ context.Context, path string, data map[string]any,
	expectedVersion int) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	value := v.values[path]
	current := 0
	if value != nil {
		current = value.version
	}
	if current != expectedVersion {
		return 0, errors.New("vault CAS conflict")
	}
	if value == nil {
		value = &lifecycleVaultValue{history: map[int]map[string]any{}}
		v.values[path] = value
	}
	value.version++
	value.data = cloneVaultData(data)
	value.history[value.version] = cloneVaultData(data)
	if v.loseCASResponse {
		v.loseCASResponse = false
		return 0, errors.New("simulated lost Vault CAS response")
	}
	return value.version, nil
}

func (v *lifecycleVault) DeleteMetadata(_ context.Context, path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.values, path)
	return nil
}

type lifecycleFixture struct {
	executor   *MainExecutor
	operation  operations.Operation
	change     admincredentials.Change
	connection connections.Connection
	vault      *lifecycleVault
	target     *lifecycleTarget
	pool       *pgxpool.Pool
}

func newLifecycleFixture(t *testing.T, mode admincredentials.Mode, candidateUser,
	candidatePassword string) lifecycleFixture {
	t.Helper()
	registerAdminCredentialLifecycleOnce.Do(func() {
		adapter.Register(adminCredentialLifecycleEngine, newLifecycleAdapter)
	})
	target := &lifecycleTarget{
		passwords: map[string]string{"grantor": "old-password"},
		authority: "authority-v1", targetIdentity: "target-v1",
	}
	adminCredentialLifecycleTargetMu.Lock()
	adminCredentialLifecycleTarget = target
	adminCredentialLifecycleTargetMu.Unlock()

	ctx := t.Context()
	pool := accessLifecycleGuardPool(t)
	connStore := connections.NewStore()
	ad := newLifecycleAdapter()
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName: "admin-lifecycle-" + uuid.NewString(), Engine: adminCredentialLifecycleEngine,
		Capabilities: ad.Manifest().CapabilityNames(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]connections.Status{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	} {
		conn, err = connStore.Transition(ctx, pool, conn.ID, step[0], step[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	topology := map[string]any{}
	adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: true, CanonicalIdentity: "grantor",
		AuthorityFingerprint: "authority-v1", TargetIdentity: "target-v1",
	})
	topologyJSON, _ := json.Marshal(topology)
	if err := connStore.SetDiscoveryResult(ctx, pool, conn.ID, "test", topologyJSON,
		ad.Manifest().CapabilityNames(), time.Now()); err != nil {
		t.Fatal(err)
	}

	vaultClient := newLifecycleVault()
	canonicalPath, _ := vault.ConnectionAdminPath(conn.ID.String())
	canonicalVersion, err := vaultClient.PutCAS(ctx, canonicalPath,
		map[string]any{"username": "grantor", "password": "old-password"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		update connections set vault_admin_path = $2, admin_credential_set_at = now(), updated_at = now()
		where id = $1`, conn.ID, canonicalPath); err != nil {
		t.Fatal(err)
	}
	conn, err = connStore.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}

	opID := uuid.New()
	payload, _ := MarshalAdminCredentialOperationPayload(mode, 1)
	kind := KindConnectionAdminCredentialSwitch
	if mode == admincredentials.ModeRotate {
		kind = KindConnectionAdminCredentialRotate
	}
	op, created, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
		ID: &opID, Kind: kind, ConnectionID: &conn.ID, Payload: payload,
		ActorType: "test", ActorID: t.Name(),
	})
	if err != nil || !created {
		t.Fatalf("create operation: created=%v err=%v", created, err)
	}
	stagePath, _ := vault.ConnectionAdminChangeStagePath(conn.ID.String(), op.ID.String())
	stageVersion, err := vaultClient.PutCAS(ctx, stagePath,
		map[string]any{"username": candidateUser, "password": candidatePassword}, 0)
	if err != nil {
		t.Fatal(err)
	}
	change, err := admincredentials.NewStore().Create(ctx, pool, admincredentials.CreateParams{
		OperationID: op.ID, ConnectionID: conn.ID, RequestID: op.ID,
		Mode: mode, CandidateMode: "generated", Epoch: 1,
		StageVaultPath: stagePath, StagedVaultVersion: stageVersion,
		ExpectedCanonicalVersion: canonicalVersion,
		PreviousStatus:           conn.Status, ExpectedUpdatedAt: conn.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	executor := NewMainExecutor(DiscoveryDeps{
		Connections: connStore, Inventory: inventory.NewStore(), Audit: audit.NewWriter(),
		Vault: vaultClient, Pool: pool,
	}).WithMutations(MutationDeps{})
	return lifecycleFixture{
		executor: executor, operation: op, change: change, connection: conn,
		vault: vaultClient, target: target, pool: pool,
	}
}

func TestIntegrationAdminCredentialRotateRecoversLostTargetResponse(t *testing.T) {
	fixture := newLifecycleFixture(t, admincredentials.ModeRotate, "grantor", "new-password")
	fixture.target.loseApplyResponse = true
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err == nil {
		t.Fatal("first execution should observe lost target response")
	}
	change, err := admincredentials.NewStore().Get(t.Context(), fixture.pool, fixture.operation.ID)
	if err != nil || !change.TargetSideEffectPossible || change.Phase != admincredentials.PhaseTargetApplying {
		t.Fatalf("change after lost response = %+v err=%v", change, err)
	}
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err != nil {
		t.Fatalf("candidate-first retry: %v", err)
	}
	if fixture.target.applies() != 1 {
		t.Fatalf("rotation applied %d times", fixture.target.applies())
	}
	assertLifecycleCompleted(t, fixture)
}

func TestIntegrationAdminCredentialLostCASResponseAndMetadataCrashConverge(t *testing.T) {
	fixture := newLifecycleFixture(t, admincredentials.ModeRotate, "grantor", "new-password")
	fixture.vault.loseCASResponse = true
	failMetadataOnce := true
	fixture.executor.mut.BeforeAdminCredentialMetadataCommit = func(context.Context, operations.Operation) error {
		if failMetadataOnce {
			failMetadataOnce = false
			return errors.New("simulated metadata commit failure")
		}
		return nil
	}
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err == nil {
		t.Fatal("first metadata commit should fail")
	}
	change, err := admincredentials.NewStore().Get(t.Context(), fixture.pool, fixture.operation.ID)
	if err != nil || change.CanonicalVaultVersion == nil ||
		change.Phase != admincredentials.PhaseMetadataCommitting {
		t.Fatalf("durable promoted change = %+v err=%v", change, err)
	}
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err != nil {
		t.Fatalf("metadata recovery: %v", err)
	}
	if fixture.target.applies() != 1 {
		t.Fatalf("rotation applied %d times", fixture.target.applies())
	}
	assertLifecycleCompleted(t, fixture)
	// Simulate loss of the outer operation commit: completed lifecycle is the
	// durable receipt and must restore the sanitized artifact without target IO.
	fixture.executor.TakeOperationArtifacts(fixture.operation.ID)
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err != nil {
		t.Fatalf("completion receipt retry: %v", err)
	}
	if len(fixture.executor.TakeOperationArtifacts(fixture.operation.ID).Result) == 0 {
		t.Fatal("completion receipt did not restore operation result")
	}
	if fixture.target.applies() != 1 {
		t.Fatal("completion receipt touched target")
	}
}

func TestIntegrationInvalidSwitchRestoresCanonicalAndSnapshot(t *testing.T) {
	fixture := newLifecycleFixture(t, admincredentials.ModeSwitch, "replacement", "wrong-password")
	err := fixture.executor.Execute(t.Context(), fixture.operation)
	if err == nil || !isTerminal(err) {
		t.Fatalf("invalid switch error=%v terminal=%v", err, isTerminal(err))
	}
	change, loadErr := admincredentials.NewStore().Get(t.Context(), fixture.pool, fixture.operation.ID)
	if loadErr != nil || change.Phase != admincredentials.PhaseFailed ||
		change.ErrorCode != "invalid_candidate" {
		t.Fatalf("failed switch change=%+v err=%v", change, loadErr)
	}
	conn, loadErr := connections.NewStore().Get(t.Context(), fixture.pool, fixture.connection.ID)
	if loadErr != nil || conn.Status != connections.StatusActive {
		t.Fatalf("connection after invalid switch status=%q err=%v", conn.Status, loadErr)
	}
	canonicalPath, _ := vault.ConnectionAdminPath(conn.ID.String())
	data, version, loadErr := fixture.vault.Get(t.Context(), canonicalPath)
	if loadErr != nil || version != 1 || data["password"] != "old-password" {
		t.Fatalf("canonical changed after invalid switch: version=%d value_matches=%v err=%v",
			version, data["password"] == "old-password", loadErr)
	}
}

func TestIntegrationStaleAdminCredentialIntentFailsBeforeTargetCall(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*operations.Operation)
	}{
		{
			name: "epoch",
			mutate: func(op *operations.Operation) {
				op.Payload, _ = MarshalAdminCredentialOperationPayload(admincredentials.ModeRotate, 99)
			},
		},
		{
			name: "mode",
			mutate: func(op *operations.Operation) {
				op.Payload, _ = MarshalAdminCredentialOperationPayload(admincredentials.ModeSwitch, 1)
			},
		},
		{
			name: "connection",
			mutate: func(op *operations.Operation) {
				other := uuid.New()
				op.ConnectionID = &other
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := newLifecycleFixture(t, admincredentials.ModeRotate, "grantor", "new-password")
			op := fixture.operation
			tt.mutate(&op)
			err := fixture.executor.Execute(t.Context(), op)
			if err == nil || !isTerminal(err) {
				t.Fatalf("stale intent error=%v terminal=%v", err, isTerminal(err))
			}
			if fixture.target.proofs() != 0 || fixture.target.applies() != 0 {
				t.Fatalf("stale intent touched target: proofs=%d applies=%d",
					fixture.target.proofs(), fixture.target.applies())
			}
		})
	}
}

func TestIntegrationAdminCredentialRotateRejectsChangedTargetBeforeMutation(t *testing.T) {
	fixture := newLifecycleFixture(t, admincredentials.ModeRotate, "grantor", "new-password")
	fixture.target.mu.Lock()
	fixture.target.targetIdentity = "target:other"
	fixture.target.mu.Unlock()
	err := fixture.executor.Execute(t.Context(), fixture.operation)
	if err == nil || !isTerminal(err) {
		t.Fatalf("changed target error=%v terminal=%v", err, isTerminal(err))
	}
	if fixture.target.applies() != 0 {
		t.Fatalf("changed target was mutated %d times", fixture.target.applies())
	}
	change, loadErr := admincredentials.NewStore().Get(t.Context(), fixture.pool, fixture.operation.ID)
	if loadErr != nil || change.Phase != admincredentials.PhaseFailed ||
		change.ErrorCode != "target_identity_changed" {
		t.Fatalf("changed-target lifecycle=%+v err=%v", change, loadErr)
	}
}

func TestIntegrationAdminCredentialRetryUsesPersistedFenceInsideManager(t *testing.T) {
	fixture := newLifecycleFixture(t, admincredentials.ModeRotate, "grantor", "new-password")
	store := admincredentials.NewStore()
	if err := store.SetExpectedProof(t.Context(), fixture.pool, fixture.operation.ID,
		"grantor", "authority-v1", "target-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPhase(t.Context(), fixture.pool, fixture.operation.ID,
		admincredentials.PhaseTargetApplying, true, "connector_unavailable"); err != nil {
		t.Fatal(err)
	}
	fixture.target.mu.Lock()
	fixture.target.targetIdentity = "target:other"
	fixture.target.mu.Unlock()
	if err := fixture.executor.Execute(t.Context(), fixture.operation); err == nil {
		t.Fatal("persisted target fence mismatch unexpectedly succeeded")
	}
	if fixture.target.applies() != 0 {
		t.Fatalf("persisted target fence retry mutated target %d times", fixture.target.applies())
	}
	change, err := store.Get(t.Context(), fixture.pool, fixture.operation.ID)
	if err != nil || change.Phase != admincredentials.PhaseTargetApplying ||
		!change.TargetSideEffectPossible || change.ErrorCode != "admin_authority_changed" {
		t.Fatalf("persisted-fence lifecycle=%+v err=%v", change, err)
	}
}

func assertLifecycleCompleted(t *testing.T, fixture lifecycleFixture) {
	t.Helper()
	change, err := admincredentials.NewStore().Get(t.Context(), fixture.pool, fixture.operation.ID)
	if err != nil || change.Phase != admincredentials.PhaseCompleted ||
		change.CanonicalVaultVersion == nil || len(change.CompletionResult) == 0 ||
		change.StageCleanupPending {
		t.Fatalf("completed change=%+v err=%v", change, err)
	}
	conn, err := connections.NewStore().Get(t.Context(), fixture.pool, fixture.connection.ID)
	if err != nil || conn.Status != connections.StatusActive {
		t.Fatalf("completed connection status=%q err=%v", conn.Status, err)
	}
	canonicalPath, _ := vault.ConnectionAdminPath(conn.ID.String())
	data, _, err := fixture.vault.Get(t.Context(), canonicalPath)
	if err != nil || data["password"] != "new-password" {
		t.Fatalf("canonical candidate mismatch: value_matches=%v err=%v",
			data["password"] == "new-password", err)
	}
}

var _ adapter.ConnectionAdminCredentialManager = (*lifecycleAdapter)(nil)
var _ adminCredentialVault = (*lifecycleVault)(nil)
