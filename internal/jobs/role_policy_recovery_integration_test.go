//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type rolePolicySuccessDispatcher struct{ calls atomic.Int32 }

func (*rolePolicySuccessDispatcher) ActiveConnectorSupports(capability adapter.Capability) bool {
	return capability == adapter.CapPostgresSuperuserDirectV1
}

func (d *rolePolicySuccessDispatcher) Dispatch(_ context.Context, job connector.Job,
	_ connector.JobCredentials,
) (connector.JobResult, error) {
	d.calls.Add(1)
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		return connector.JobResult{}, err
	}
	plan, err := connector.MarshalSanitizedPlan(&adapter.Plan{
		Change: adapter.DesiredChange{
			Kind: adapter.ChangeKind(payload.Change.Kind), Permission: payload.Change.Permission,
		},
		Steps: []adapter.PlanStep{{Kind: "role-policy-apply", Description: "apply fixed policy"}},
	})
	if err != nil {
		return connector.JobResult{}, err
	}
	result, err := connector.MarshalSanitizedResult(&adapter.Result{Steps: []adapter.StepResult{{
		Step:   adapter.PlanStep{Kind: "role-policy-apply", Description: "apply fixed policy"},
		Status: adapter.StepApplied,
	}}}, &adapter.Verification{Verified: true, Details: "exact"})
	if err != nil {
		return connector.JobResult{}, err
	}
	return connector.JobResult{
		JobID: job.ID, Status: connector.JobSuccess, Plan: plan, Result: result,
		ObservedAt: time.Now().Unix(),
	}, nil
}

type rolePolicyOuterCommitFault struct {
	*jobs.MainExecutor
	fail atomic.Bool
}

func (e *rolePolicyOuterCommitFault) BeforeOperationCommit(_ context.Context, op operations.Operation) error {
	if (op.Kind == jobs.KindPostgresRolePolicyApplyV2 || op.Kind == jobs.KindPostgresRolePolicyCreateV2) && e.fail.CompareAndSwap(true, false) {
		return errors.New("forced role-policy post-metadata pre-operation-commit fault")
	}
	return nil
}

func TestRolePolicyCompletionReceiptRecoversLostOuterCommit(t *testing.T) {
	t.Run("apply", func(t *testing.T) {
		rolePolicyCompletionReceiptRecoversLostOuterCommit(t, jobs.KindPostgresRolePolicyApplyV2, rolepolicies.ActionApply, "role_policy.applied")
	})
	t.Run("create", func(t *testing.T) {
		rolePolicyCompletionReceiptRecoversLostOuterCommit(t, jobs.KindPostgresRolePolicyCreateV2, rolepolicies.ActionCreate, "role_policy.created")
	})
}

func rolePolicyCompletionReceiptRecoversLostOuterCommit(t *testing.T, kind string, action rolepolicies.Action, auditAction string) {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	registerPostgresOnce.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})

	connStore := connections.NewStore()
	invStore := inventory.NewStore()
	opStore := operations.NewStore()
	roleStore := rolepolicies.NewStore()
	auditWriter := audit.NewWriter()
	spec := adapter.RolePolicySpec{
		Engine: postgres.Engine, Key: "app-read", Name: "Application read",
		Description: "Receipt recovery policy",
		RoleName:    "r_receipt", Database: "app", Schemas: []string{"public"},
		OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
	template := postgresconfig.RolePolicyTemplate{Key: spec.Key, Name: spec.Name, Description: spec.Description,
		RoleName: spec.RoleName, Database: spec.Database, Schemas: spec.Schemas,
		OwnerRoles: spec.OwnerRoles, CreatorRoles: spec.CreatorRoles, Profile: spec.Profile}
	discoveryConfig, _ := json.Marshal(map[string]any{
		postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{template},
	})
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName: "role-policy-recovery-" + uuid.NewString(), Engine: postgres.Engine,
		Environment: "itest", Endpoints: []string{"isolated-postgres:5432"},
		ExecutionMode: connections.ExecutionModeConnector, DiscoveryConfig: discoveryConfig,
		AdminCredentialMode: "existing_vault_ref", VaultAdminPath: testVaultPath,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	topology, _ := json.Marshal(map[string]any{
		"system_identifier": "7429012345678901234", "admin_credential_canonical_identity": "grantor",
		"postgres_role_policy_catalog_fingerprint": postgresconfig.CatalogFingerprint([]postgresconfig.RolePolicyTemplate{template}),
		adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
			Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
			ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 1, ConfigIncarnation: connections.ConfigIncarnation(conn),
			TargetIdentity: "postgres:system:7429012345678901234",
		},
	})
	if _, err := pool.Exec(ctx, `update connections set status='active',
		capabilities='["postgres.superuser_direct.v1","role.policy.apply","role.policy.create"]',
		topology=$2,last_discovery_at=$3 where id=$1`, conn.ID, topology, observedAt); err != nil {
		t.Fatalf("activate connection: %v", err)
	}

	if _, err := invStore.UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{}, time.Now()); err != nil {
		t.Fatalf("seed inventory: %v", err)
	}
	if err := roleStore.ReconcileSnapshot(ctx, pool, conn.ID, []adapter.ObservedRolePolicy{{
		ExternalID: "role:" + spec.RoleName, Spec: spec,
		ExpectedFingerprint: "expected-role-policy", ObservedFingerprint: "absent-role-policy",
		Exact: false, ApplySupported: true,
		Summary: map[string]any{
			"missing": []string{"role:exists"}, "extra": []string{},
			"role": map[string]any{"exists": action == rolepolicies.ActionApply, "safe": true},
		},
	}}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	policy, err := roleStore.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	payload, err := json.Marshal(jobs.RolePolicyPayload{
		RolePolicyID: policy.ID, Action: action,
		ExpectedVersion: policy.Version + 1, ObservedFingerprint: policy.ObservedFingerprint,
		ExpectedFingerprint:    policy.ExpectedFingerprint,
		ExpectedTargetIdentity: "postgres:system:7429012345678901234",
		ExpectedDatabaseOID:    42, ExpectedDatabaseOwner: "app_owner", ExpectedDatabaseOwnerOID: 17,
		ExpectedAdminIdentity: "grantor", ExpectedConfigIncarnation: connections.ConfigIncarnation(conn),
		ExpectedCredentialIncarnation: 1,
		ExpectedCatalogFingerprint:    postgresconfig.CatalogFingerprint([]postgresconfig.RolePolicyTemplate{template}),
		ExternalID:                    policy.ExternalID, Spec: policy.DesiredSpec,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	dispatcher := &rolePolicySuccessDispatcher{}
	mainExecutor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore, Inventory: invStore, Audit: auditWriter, Pool: pool,
		Vault: fakeVaultReader{username: "grantor", password: "secret"},
	}).WithConnector(jobs.ConnectorDeps{Dispatcher: dispatcher})
	executor := &rolePolicyOuterCommitFault{MainExecutor: mainExecutor}
	executor.fail.Store(true)
	river, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue: testQueue(), WorkerCount: 1, MaxAttempts: 3, SnoozeOnLock: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin enqueue: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: kind, ConnectionID: &conn.ID, Payload: payload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if _, err := roleStore.Reserve(ctx, tx, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: policy.TemplateKey,
		Action: action, OperationID: op.ID,
		Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint,
	}); err != nil {
		t.Fatalf("reserve policy: %v", err)
	}
	if err := river.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enqueue: %v", err)
	}
	startRiver(t, river)
	done := waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 60*time.Second)
	if executor.fail.Load() {
		t.Fatal("outer commit fault was not exercised")
	}
	if dispatcher.calls.Load() != 1 {
		t.Fatalf("connector dispatch calls = %d, want exactly one target mutation", dispatcher.calls.Load())
	}
	if len(done.Plan) == 0 || len(done.Result) == 0 {
		t.Fatalf("recovered operation artifacts are empty: plan=%d result=%d", len(done.Plan), len(done.Result))
	}
	var receiptCount, auditCount, permissionCount int
	if err := pool.QueryRow(ctx, `select count(*) from role_policy_operation_completions where operation_id=$1`,
		op.ID).Scan(&receiptCount); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if err := pool.QueryRow(ctx, `select count(*) from audit_events
		where operation_id=$1 and action=$2`, op.ID, auditAction).Scan(&auditCount); err != nil {
		t.Fatalf("count audits: %v", err)
	}
	if err := pool.QueryRow(ctx, `select count(*) from permission_definitions
		where connection_id=$1 and external_id=$2`, conn.ID, policy.ExternalID).Scan(&permissionCount); err != nil {
		t.Fatalf("count permissions: %v", err)
	}
	if receiptCount != 1 || auditCount != 1 || permissionCount != 1 {
		t.Fatalf("recovery duplicates: receipts=%d audits=%d permissions=%d", receiptCount, auditCount, permissionCount)
	}
}
