//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type provisioningRecoveryTarget struct {
	adapter.Adapter
	snapshot     *adapter.Snapshot
	calls        atomic.Int64
	err          error
	beforeReturn func() error
}

func (a *provisioningRecoveryTarget) Discover(context.Context, adapter.Connection) (*adapter.Snapshot, error) {
	a.calls.Add(1)
	if a.err != nil {
		return nil, a.err
	}
	raw, err := json.Marshal(a.snapshot)
	if err != nil {
		return nil, err
	}
	var snapshot adapter.Snapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, err
	}
	if a.beforeReturn != nil {
		if err := a.beforeReturn(); err != nil {
			return nil, err
		}
	}
	return &snapshot, nil
}

type provisioningRecoveryDispatcher struct{ target *provisioningRecoveryTarget }

func (d provisioningRecoveryDispatcher) Dispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	if job.Kind != connector.JobDiscover || creds.Account != nil ||
		strings.Contains(string(job.Payload), "recovered_account_id") {
		return connector.JobResult{}, errors.New("recovery crossed the read-only connector boundary")
	}
	snapshot, err := d.target.Discover(ctx, adapter.Connection{})
	if err != nil {
		return connector.JobResult{}, err
	}
	raw, err := json.Marshal(snapshot)
	return connector.JobResult{JobID: job.ID, Status: connector.JobSuccess, Result: raw}, err
}

type provisioningRecoveryVault struct{ calls atomic.Int64 }

func (v *provisioningRecoveryVault) Get(context.Context, string) (map[string]any, int, error) {
	v.calls.Add(1)
	return map[string]any{"username": "connection_admin", "password": "recovery-admin-canary"}, 1, nil
}

type provisioningRecoveryFixture struct {
	pool      *pgxpool.Pool
	inv       *inventory.Store
	ops       *operations.Store
	conns     *connections.Store
	account   inventory.Account
	source    operations.Operation
	operation operations.Operation
	target    *provisioningRecoveryTarget
	vault     *provisioningRecoveryVault
	deps      jobs.DiscoveryDeps
	mode      string
}

func newProvisioningRecoveryFixture(t *testing.T, mode, kind string, observed bool) *provisioningRecoveryFixture {
	t.Helper()
	ctx := context.Background()
	f := &provisioningRecoveryFixture{
		pool: pgtest.Pool(t), inv: inventory.NewStore(), ops: operations.NewStore(),
		conns: connections.NewStore(), vault: &provisioningRecoveryVault{}, mode: mode,
	}
	engine := "recovery-" + uuid.NewString()
	f.target = &provisioningRecoveryTarget{Adapter: fake.New(), snapshot: &adapter.Snapshot{ServerVersion: "test", ObservedAt: time.Now()}}
	if observed {
		f.target.snapshot.Accounts = []adapter.ObservedAccount{{Kind: kind, EngineIdentity: "existing_identity", Attributes: map[string]any{"can_login": kind == "login"}}}
	}
	adapter.Register(engine, func() adapter.Adapter { return f.target })
	conn, err := f.conns.Create(ctx, f.pool, connections.CreateParams{
		DisplayName: engine, Engine: engine, ExecutionMode: mode, VaultAdminPath: "connection/admin",
		Capabilities: f.target.Manifest().CapabilityNames(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `update connections set status='discovering' where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	credentialMode, vaultPath := "", ""
	if kind == "login" {
		credentialMode, vaultPath = "provided", "accounts/unproven/credential"
	}
	account, err := f.inv.CreateProvisioningAccount(ctx, f.pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "existing_identity", Kind: kind,
		CredentialMode: credentialMode, VaultPath: vaultPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	f.account, err = f.inv.ReserveAccountLifecycle(ctx, tx, account.ID, inventory.AccountProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	createKind := jobs.KindAccountCreate
	if kind == "group" {
		createKind = jobs.KindRoleCreate
	}
	payload, err := json.Marshal(jobs.AccountPayload{AccountID: account.ID,
		ExpectedStatus: inventory.AccountProvisioning, ExpectedLifecycleVersion: f.account.LifecycleVersion})
	if err != nil {
		t.Fatal(err)
	}
	f.source, _, err = f.ops.Create(ctx, tx, operations.CreateParams{
		Kind: createKind, AccountID: &account.ID, ConnectionID: &conn.ID, Payload: payload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.ops.Transition(ctx, tx, f.source.ID, operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatal(err)
	}
	f.source, err = f.ops.Transition(ctx, tx, f.source.ID, operations.StatusRunning, operations.StatusFailed,
		operations.TransitionOpts{Error: "original creation failure"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err = json.Marshal(jobs.ProvisioningRecoveryPayload{RecoveryAccountID: account.ID,
		SourceOperationID: f.source.ID, ExpectedLifecycleVersion: f.account.LifecycleVersion})
	if err != nil {
		t.Fatal(err)
	}
	f.operation, _, err = f.ops.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindAccountRecoverProvisioning, AccountID: &account.ID, ConnectionID: &conn.ID, Payload: payload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	f.deps = jobs.DiscoveryDeps{Connections: f.conns, Inventory: f.inv, Audit: audit.NewWriter(), Vault: f.vault, Pool: f.pool}
	return f
}

func (f *provisioningRecoveryFixture) executor() *jobs.MainExecutor {
	return jobs.NewMainExecutor(f.deps).WithConnector(jobs.ConnectorDeps{Dispatcher: provisioningRecoveryDispatcher{target: f.target}})
}

func (f *provisioningRecoveryFixture) accountNow(t *testing.T) inventory.Account {
	t.Helper()
	account, err := f.inv.GetAccount(context.Background(), f.pool, f.account.ID)
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func (f *provisioningRecoveryFixture) auditCount(t *testing.T, action string) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(context.Background(), `select count(*) from audit_events where operation_id=$1 and action=$2`, f.operation.ID, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestProvisioningRecoveryRequiresFreshObservedIdentity(t *testing.T) {
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		for _, kind := range []string{"login", "group"} {
			t.Run(mode+"/"+kind, func(t *testing.T) {
				f := newProvisioningRecoveryFixture(t, mode, kind, true)
				if err := f.executor().Execute(t.Context(), f.operation); err != nil {
					t.Fatal(err)
				}
				account := f.accountNow(t)
				if account.Status != inventory.AccountActive || account.Ownership != inventory.OwnershipUnmanaged ||
					account.Kind != kind || account.VaultPath != "" || account.CredentialMode != nil ||
					account.LifecycleVersion != f.account.LifecycleVersion+1 {
					t.Fatalf("recovered account is not the observed credential-free incarnation: %+v", account)
				}
				if f.target.calls.Load() != 1 || f.vault.calls.Load() != 1 || f.auditCount(t, "account.provisioning_recovered") != 1 {
					t.Fatal("recovery did not perform exactly one read and one durable metadata transition")
				}
				source, err := f.ops.Get(t.Context(), f.pool, f.source.ID)
				if err != nil || source.Status != operations.StatusFailed || source.Error != f.source.Error {
					t.Fatalf("source failure history changed: status=%s error=%v", source.Status, err)
				}
				if err := f.executor().Execute(t.Context(), f.source); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
					t.Fatalf("stale creation after recovery was not fenced: %v", err)
				}
				if err := f.executor().Execute(t.Context(), f.operation); err != nil {
					t.Fatalf("completed recovery replay: %v", err)
				}
				if f.target.calls.Load() != 1 || f.vault.calls.Load() != 1 {
					t.Fatal("stale creation or completed recovery replay reached Vault or target")
				}
			})
		}
	}
}

func TestProvisioningRecoveryAbsentRetainsCreationReservation(t *testing.T) {
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		t.Run(mode, func(t *testing.T) {
			f := newProvisioningRecoveryFixture(t, mode, "group", false)
			if err := f.executor().Execute(t.Context(), f.operation); !errors.Is(err, jobs.ErrProvisioningRecoveryAccountAbsent) {
				t.Fatalf("recovery error=%v, want absent refusal", err)
			}
			account := f.accountNow(t)
			if account.Status != inventory.AccountProvisioning || account.Ownership != inventory.OwnershipManaged ||
				account.LifecycleVersion != f.account.LifecycleVersion || account.VaultPath != f.account.VaultPath {
				t.Fatal("absent recovery abandoned the original creation reservation")
			}
			conn, err := f.conns.Get(t.Context(), f.pool, account.ConnectionID)
			if err != nil || conn.Status != connections.StatusActive || conn.LastDiscoveryAt == nil {
				t.Fatalf("successful absent snapshot left connection unhealthy: status=%s error=%v", conn.Status, err)
			}
			if f.auditCount(t, "connection.discovered") != 1 || f.auditCount(t, "account.provisioning_recovered") != 0 {
				t.Fatal("absent recovery failed to retain its successful read without a release receipt")
			}
		})
	}
}

func TestProvisioningRecoveryStaleJobStopsBeforeVaultAndTarget(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "login", true)
	if _, err := f.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.executor().Execute(t.Context(), f.operation); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
		t.Fatalf("stale recovery error=%v", err)
	}
	if f.target.calls.Load() != 0 || f.vault.calls.Load() != 0 {
		t.Fatal("stale recovery touched Vault or target")
	}
}

func TestProvisioningRecoveryRejectsOrdinaryDiscoveryIntentBeforeVaultAndTarget(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "login", true)
	legacy := f.operation
	legacy.Kind = jobs.KindConnectionDiscover
	if err := f.executor().Execute(t.Context(), legacy); err == nil || !strings.Contains(err.Error(), "requires account.recover_provisioning") {
		t.Fatalf("ordinary discovery accepted recovery intent: %v", err)
	}
	if f.target.calls.Load() != 0 || f.vault.calls.Load() != 0 {
		t.Fatal("recovery attached to ordinary discovery reached Vault or target")
	}
	if f.accountNow(t).Status != inventory.AccountProvisioning || f.auditCount(t, "account.provisioning_recovered") != 0 {
		t.Fatal("invalid recovery intent changed the original reservation")
	}
}

func TestProvisioningRecoveryRechecksFenceAfterDiscovery(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "login", true)
	f.target.beforeReturn = func() error {
		_, err := f.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, f.account.ID)
		return err
	}
	if err := f.executor().Execute(t.Context(), f.operation); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
		t.Fatalf("post-discovery lifecycle race error=%v", err)
	}
	if f.accountNow(t).Status != inventory.AccountProvisioning || f.auditCount(t, "account.provisioning_recovered") != 0 {
		t.Fatal("stale read released a newer account incarnation")
	}
}

func TestProvisioningRecoverySourceRetryStopsBeforeVaultAndTarget(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "login", true)
	if _, err := f.ops.Transition(t.Context(), f.pool, f.source.ID, operations.StatusFailed, operations.StatusPending, operations.TransitionOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := f.executor().Execute(t.Context(), f.operation); err == nil {
		t.Fatal("recovery accepted a source that had already been retried")
	}
	if f.target.calls.Load() != 0 || f.vault.calls.Load() != 0 {
		t.Fatal("concurrent source retry did not stop recovery before Vault and target")
	}
}

func TestProvisioningRecoverySnapshotFailureDoesNotReleaseAccount(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeDirect, "login", true)
	f.target.snapshot.Bindings = []adapter.ObservedBinding{{
		AccountEngineIdentity: f.account.EngineIdentity, PermissionExternalID: "role:unknown", ScopeExternalID: "",
	}}
	if err := f.executor().Execute(t.Context(), f.operation); err == nil {
		t.Fatal("inconsistent snapshot unexpectedly committed")
	}
	if account := f.accountNow(t); account.Status != inventory.AccountProvisioning || account.LifecycleVersion != f.account.LifecycleVersion || account.VaultPath != f.account.VaultPath {
		t.Fatal("failed snapshot left a partially released account")
	}
	if f.auditCount(t, "account.provisioning_recovered") != 0 {
		t.Fatal("failed snapshot left a durable success receipt")
	}
}

func TestProvisioningRecoveryMetadataCommitIsAtomic(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "login", true)
	var fail atomic.Bool
	fail.Store(true)
	f.deps.BeforeProvisioningRecoveryMetadataCommit = func(context.Context, operations.Operation) error {
		if fail.CompareAndSwap(true, false) {
			return errors.New("forced recovery metadata commit failure")
		}
		return nil
	}
	executor := f.executor()
	if err := executor.Execute(t.Context(), f.operation); err == nil {
		t.Fatal("metadata fault did not fail recovery")
	}
	if account := f.accountNow(t); account.Status != inventory.AccountProvisioning || account.VaultPath != f.account.VaultPath || account.LifecycleVersion != f.account.LifecycleVersion {
		t.Fatal("failed metadata transaction left a partial recovery")
	}
	if f.auditCount(t, "account.provisioning_recovered") != 0 || f.auditCount(t, "connection.discovered") != 0 {
		t.Fatal("rolled-back recovery left a durable receipt or snapshot audit")
	}
	if err := executor.Execute(t.Context(), f.operation); err != nil {
		t.Fatalf("retry after metadata fault: %v", err)
	}
	if f.accountNow(t).Status != inventory.AccountActive || f.auditCount(t, "account.provisioning_recovered") != 1 {
		t.Fatal("metadata retry did not converge")
	}
}

func TestProvisioningRecoveryReceiptSurvivesLostOuterCommit(t *testing.T) {
	f := newProvisioningRecoveryFixture(t, connections.ExecutionModeConnector, "group", true)
	var fail atomic.Bool
	fail.Store(true)
	f.deps.BeforeProvisioningRecoveryOperationCommit = func(context.Context, operations.Operation) error {
		if fail.CompareAndSwap(true, false) {
			return errors.New("forced recovery outer operation commit failure")
		}
		return nil
	}
	river, err := jobs.New(f.pool, f.ops, f.executor(), jobs.Config{
		Queue: testQueue(), WorkerCount: 1, MaxAttempts: 3, SnoozeOnLock: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	if err := river.EnqueueOperationTx(t.Context(), tx, f.operation.ID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	startRiver(t, river)
	waitForStatus(t, f.pool, f.ops, f.operation.ID, operations.StatusSuccess, 30*time.Second)
	if f.target.calls.Load() != 1 || f.vault.calls.Load() != 1 ||
		f.auditCount(t, "account.provisioning_recovered") != 1 || f.accountNow(t).LifecycleVersion != f.account.LifecycleVersion+1 {
		t.Fatal("outer commit recovery repeated discovery, credential access or the metadata transition")
	}
	if states := jobStates(t, f.pool, f.operation.ID); len(states) != 1 || !strings.Contains(states[0], ":2") {
		t.Fatalf("outer commit fault was not exercised: %v", states)
	}
}
