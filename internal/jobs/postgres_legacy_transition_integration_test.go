//go:build integration

package jobs_test

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type legacyRejectCountingVault struct{ calls atomic.Int32 }

func (v *legacyRejectCountingVault) Get(context.Context, string) (map[string]any, int, error) {
	v.calls.Add(1)
	return nil, 0, fmt.Errorf("legacy operation unexpectedly read Vault")
}

func TestLegacyPostgresCreationKindsRejectBeforeVaultOrAdapter(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "legacy-zero-target-" + uuid.NewString(), Engine: "postgres",
		VaultAdminPath: "connections/test/admin",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	vault := &legacyRejectCountingVault{}
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connections.NewStore(), Pool: pool, Vault: vault,
	})
	for _, kind := range []string{
		jobs.KindAccountCreate,
		jobs.KindAccountRestore,
		jobs.KindRoleCreate,
		jobs.KindResourceCreateDatabase,
	} {
		t.Run(kind, func(t *testing.T) {
			err := executor.Execute(ctx, operations.Operation{
				ID: uuid.New(), Kind: kind, ConnectionID: &conn.ID,
			})
			if err == nil || !strings.Contains(err.Error(), "history-only") {
				t.Fatalf("legacy Execute(%q) = %v", kind, err)
			}
		})
	}
	if calls := vault.calls.Load(); calls != 0 {
		t.Fatalf("legacy operations read Vault %d times", calls)
	}
}

// TestLegacyPostgresPolicyRiverReleasesTransition proves the complete durable
// boundary, not merely the operation-kind classifier. A helper-era policy
// operation is terminated on its first River attempt and the policy ceases to
// be owned by an automatic retry, so a new v2 intent can take over explicitly.
func TestLegacyPostgresPolicyRiverReleasesTransition(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "legacy-policy-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	spec := adapter.RolePolicySpec{
		Engine: "postgres", Key: "legacy-read", Name: "Legacy read",
		RoleName: "r_legacy", Database: "app", Schemas: []string{"public"},
		OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_owner"}, Profile: "read",
	}
	roleStore := rolepolicies.NewStore()
	if err := roleStore.ReconcileSnapshot(ctx, pool, conn.ID, []adapter.ObservedRolePolicy{{
		ExternalID: "role:" + spec.RoleName, Spec: spec,
		ExpectedFingerprint: "expected", ObservedFingerprint: "drifted",
		ApplySupported: true,
		Summary: map[string]any{
			"missing": []string{"acl:table:public.orders:SELECT"},
			"extra":   []string{},
			"role":    map[string]any{"exists": true, "safe": true},
		},
	}}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	policy, err := roleStore.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}

	opStore := operations.NewStore()
	exec := &selectiveExecutor{behavior: func(operations.Operation) error {
		return fmt.Errorf("legacy PostgreSQL policy executor retired: %w", adapter.ErrUnsupportedChange)
	}}
	runner, err := jobs.New(pool, opStore, exec, jobs.Config{
		Queue: testQueue(), WorkerCount: 1, MaxAttempts: 5, SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create River runner: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin enqueue: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindRolePolicyApply, ConnectionID: &conn.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create legacy operation: %v", err)
	}
	if _, err := roleStore.Reserve(ctx, tx, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: policy.TemplateKey,
		Action: rolepolicies.ActionApply, OperationID: op.ID,
		Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
	}); err != nil {
		t.Fatalf("reserve policy transition: %v", err)
	}
	if err := runner.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue legacy operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enqueue: %v", err)
	}

	startRiver(t, runner)
	failed := waitForStatus(t, pool, opStore, op.ID, operations.StatusFailed, 30*time.Second)
	if !strings.HasPrefix(failed.Error, terminalErrorMarker) {
		t.Fatalf("legacy failure = %q, want terminal marker", failed.Error)
	}
	waitForJobStates(t, pool, op.ID, []string{"cancelled:1"}, 30*time.Second)
	policy, err = roleStore.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("reload policy: %v", err)
	}
	if policy.Status != rolepolicies.StatusFailed || policy.TransitionRetryPending {
		t.Fatalf("released policy = status:%s retry_pending:%v", policy.Status, policy.TransitionRetryPending)
	}
	if repairable, active, err := roleStore.Repairability(ctx, pool, policy); err != nil || !repairable || active {
		t.Fatalf("released transition = repairable:%v active:%v err:%v", repairable, active, err)
	}
}
