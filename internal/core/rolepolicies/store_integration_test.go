//go:build integration

package rolepolicies_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func policyConnection(t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(t.Context(), pool, connections.CreateParams{
		DisplayName: "role-policy-" + uuid.NewString(), Engine: "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return conn
}

func policySpec(role string) adapter.RolePolicySpec {
	return adapter.RolePolicySpec{
		Engine: "postgres", Key: "app-read", Name: "Application read",
		Description: "Fixed read policy", RoleName: role, Database: "app",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
}

func observation(spec adapter.RolePolicySpec, exact, exists bool, actual string) adapter.ObservedRolePolicy {
	return adapter.ObservedRolePolicy{
		ExternalID: "role:" + spec.RoleName, Spec: spec,
		ExpectedFingerprint: "expected-fingerprint", ObservedFingerprint: actual,
		Exact: exact, ApplySupported: true,
		Summary: map[string]any{
			"missing": []string{}, "extra": []string{},
			"role": map[string]any{"exists": exists, "safe": true},
		},
	}
}

func operation(t *testing.T, pool *pgxpool.Pool, connectionID uuid.UUID, kind string) operations.Operation {
	t.Helper()
	op, created, err := operations.NewStore().Create(t.Context(), pool, operations.CreateParams{
		Kind: kind, ConnectionID: &connectionID, ActorType: "test", ActorID: t.Name(),
	})
	if err != nil || !created {
		t.Fatalf("create operation: created=%v err=%v", created, err)
	}
	return op
}

func permissionByExternal(t *testing.T, pool *pgxpool.Pool, connectionID uuid.UUID, external string) inventory.Permission {
	t.Helper()
	permissions, err := inventory.NewStore().ListPermissions(t.Context(), pool, connectionID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	for _, permission := range permissions {
		if permission.ExternalID == external {
			return permission
		}
	}
	t.Fatalf("permission %q not found", external)
	return inventory.Permission{}
}

func TestAdoptExactPolicyGatesPermissionAndDriftBlocksNewAssignments(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	spec := policySpec("r_app")

	// Ordinary inventory sees the existing role as assignable. Role-policy
	// reconciliation must override it until exact state is explicitly adopted.
	snapshot := &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{Kind: "group", EngineIdentity: spec.RoleName}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
	}
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatalf("upsert inventory: %v", err)
	}
	store := rolepolicies.NewStore()
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{observation(spec, true, true, "expected-fingerprint")}, time.Now()); err != nil {
		t.Fatalf("reconcile exact unmanaged: %v", err)
	}
	policy, err := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if policy.Managed || policy.Status != rolepolicies.StatusObserved {
		t.Fatalf("unmanaged exact policy = %+v", policy)
	}
	if permissionByExternal(t, pool, conn.ID, "role:"+spec.RoleName).Assignable {
		t.Fatal("unmanaged policy role must not be assignable")
	}

	op := operation(t, pool, conn.ID, "role.policy.adopt")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionAdopt,
		OperationID: op.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve adopt: %v", err)
	}
	completed, err := store.Complete(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil {
		t.Fatalf("complete adopt: %v", err)
	}
	if !completed.Managed || !completed.Exact || completed.Status != rolepolicies.StatusSynced {
		t.Fatalf("completed policy = %+v", completed)
	}
	if !permissionByExternal(t, pool, conn.ID, completed.ExternalID).Assignable {
		t.Fatal("exact managed policy role must be assignable")
	}

	drift := observation(spec, false, true, "actual-drift-fingerprint")
	drift.Summary["missing"] = []string{"table:public.orders:SELECT"}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{drift}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reconcile drift: %v", err)
	}
	drifted, err := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get drifted: %v", err)
	}
	if drifted.Status != rolepolicies.StatusDrift || !drifted.Repairable() {
		t.Fatalf("drifted policy = %+v", drifted)
	}
	if permissionByExternal(t, pool, conn.ID, drifted.ExternalID).Assignable {
		t.Fatal("drifted policy role must block new assignments")
	}
}

func TestCreateMissingPolicyReservesRoleIdentityAndCompletesAtomically(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_missing")
	missing := observation(spec, false, false, "absent-fingerprint")
	missing.Dangerous = true // generic lifecycle must preserve adapter-computed risk.
	missing.Summary["missing_count"] = 3
	missing.Summary["extra_count"] = 2
	missing.Summary["truncated"] = true
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{missing}, time.Now()); err != nil {
		t.Fatalf("reconcile missing: %v", err)
	}
	policy, err := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get missing: %v", err)
	}
	if policy.Status != rolepolicies.StatusMissing || policy.AccountID != nil {
		t.Fatalf("missing policy = %+v", policy)
	}
	op := operation(t, pool, conn.ID, "role.policy.create")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionCreate,
		OperationID: op.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve apply: %v", err)
	}
	if reserved.Policy.AccountID == nil {
		t.Fatal("apply did not reserve accounts identity")
	}
	account, err := inventory.NewStore().GetAccount(ctx, pool, *reserved.Policy.AccountID)
	if err != nil {
		t.Fatalf("get reserved account: %v", err)
	}
	if account.Status != inventory.AccountProvisioning || account.Ownership != inventory.OwnershipManaged {
		t.Fatalf("reserved account = %+v", account)
	}
	completed, err := store.Complete(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil {
		t.Fatalf("complete apply: %v", err)
	}
	account, err = inventory.NewStore().GetAccount(ctx, pool, *completed.AccountID)
	if err != nil {
		t.Fatalf("get completed account: %v", err)
	}
	if account.Status != inventory.AccountActive || account.Ownership != inventory.OwnershipManaged || account.Kind != "group" {
		t.Fatalf("completed account = %+v", account)
	}
	permission := permissionByExternal(t, pool, conn.ID, completed.ExternalID)
	if !permission.Assignable {
		t.Fatal("completed policy permission is not assignable")
	}
	if !completed.Dangerous || !permission.Dangerous {
		t.Fatalf("dangerous policy/permission = %v/%v, want true/true", completed.Dangerous, permission.Dangerous)
	}
	var summary map[string]any
	if err := json.Unmarshal(completed.ObservedSummary, &summary); err != nil {
		t.Fatalf("decode completed summary: %v", err)
	}
	if summary["missing_count"] != float64(0) || summary["extra_count"] != float64(0) || summary["truncated"] != false {
		t.Fatalf("completed summary retained stale preview counters: %+v", summary)
	}
}

func TestRolePolicyStaleAndTemplateIdentityGuards(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_guarded")
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{observation(spec, false, false, "absent")}, time.Now()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	policy, _ := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	op := operation(t, pool, conn.ID, "role.policy.create")
	_, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionCreate,
		OperationID: op.ID, Version: policy.Version + 1,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if !errors.Is(err, rolepolicies.ErrStale) {
		t.Fatalf("stale reserve error = %v", err)
	}

	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionCreate,
		OperationID: op.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	changed := spec
	changed.RoleName = "r_other"
	if err := store.ValidateTemplateChange(ctx, pool, conn.ID, []adapter.RolePolicySpec{changed}); !errors.Is(err, rolepolicies.ErrConflict) && !errors.Is(err, rolepolicies.ErrUnsafeTemplateChange) {
		t.Fatalf("active identity change error = %v", err)
	}
	if err := store.MarkFailed(ctx, pool, op.ID, reserved.ExpectedVersion+1); !errors.Is(err, rolepolicies.ErrStale) {
		t.Fatalf("stale MarkFailed error = %v", err)
	}
}

func TestTargetStartedRetryConvergesAfterLostResponseAndFreshDiscovery(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_forward")
	initial := observation(spec, false, false, "absent-before-apply")
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{initial}, time.Now()); err != nil {
		t.Fatalf("reconcile initial: %v", err)
	}
	policy, _ := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	op := operation(t, pool, conn.ID, "role.policy.create")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionCreate,
		OperationID: op.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	started, err := store.BeginTarget(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil || !started.TargetStarted {
		t.Fatalf("begin target: started=%v err=%v", started.TargetStarted, err)
	}

	// Simulate Apply reaching target, its response being lost, and a later
	// discovery observing the exact target state before retrying this operation.
	exact := observation(spec, true, true, policy.ExpectedFingerprint)
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{exact}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reconcile exact after lost response: %v", err)
	}
	if _, err := store.ValidateTransition(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec, false); err != nil {
		t.Fatalf("retry after target_started must accept changed observation: %v", err)
	}
	if _, err := store.ValidateTransition(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec, true); !errors.Is(err, rolepolicies.ErrStale) {
		t.Fatalf("verify-only stale check error = %v", err)
	}
	completed, err := store.Complete(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil {
		t.Fatalf("complete retry: %v", err)
	}
	if !completed.Exact || completed.Status != rolepolicies.StatusSynced || completed.TargetStarted {
		t.Fatalf("completed retry = %+v", completed)
	}
}

func TestCompletedOperationReceiptRecognizesOnlyPinnedIntent(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_receipt")
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{Kind: "group", EngineIdentity: spec.RoleName}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
	}, time.Now()); err != nil {
		t.Fatalf("seed role inventory: %v", err)
	}
	initial := observation(spec, true, true, "expected-fingerprint")
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{initial}, time.Now()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	policy, _ := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	op := operation(t, pool, conn.ID, "role.policy.adopt")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionAdopt,
		OperationID: op.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.Complete(ctx, pool, op.ID, reserved.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec); err != nil {
		t.Fatalf("complete: %v", err)
	}
	recognized, err := store.RecognizeCompletion(ctx, pool, op.ID, policy.ID,
		reserved.ExpectedVersion, policy.ObservedFingerprint,
		policy.ExpectedFingerprint, policy.DesiredSpec)
	if err != nil || !recognized {
		t.Fatalf("recognize completion = %v, %v", recognized, err)
	}
	changed := policy.DesiredSpec
	changed.Profile = "read_write"
	if _, err := store.RecognizeCompletion(ctx, pool, op.ID, policy.ID,
		reserved.ExpectedVersion, policy.ObservedFingerprint,
		policy.ExpectedFingerprint, changed); !errors.Is(err, rolepolicies.ErrStale) {
		t.Fatalf("changed completion intent error = %v, want ErrStale", err)
	}
}

func TestRepairabilityFencesAutomaticRetryAndAllowsTerminalTakeover(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_repair_retry")
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{Kind: "group", EngineIdentity: spec.RoleName}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
	}, time.Now()); err != nil {
		t.Fatalf("seed role inventory: %v", err)
	}
	initial := observation(spec, true, true, "expected-fingerprint")
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{initial}, time.Now()); err != nil {
		t.Fatalf("reconcile exact: %v", err)
	}
	policy, _ := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	adopt := operation(t, pool, conn.ID, "role.policy.adopt")
	adopted, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionAdopt,
		OperationID: adopt.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve adopt: %v", err)
	}
	if _, err := store.Complete(ctx, pool, adopt.ID, adopted.ExpectedVersion,
		policy.ObservedFingerprint, policy.ExpectedFingerprint, policy.DesiredSpec); err != nil {
		t.Fatalf("complete adopt: %v", err)
	}
	drift := observation(spec, false, true, "drifted")
	drift.Summary["missing"] = []string{"acl:table:public.orders:SELECT"}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{drift}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reconcile drift: %v", err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	repair := operation(t, pool, conn.ID, "role.policy.repair")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: spec.Key, Action: rolepolicies.ActionRepair,
		OperationID: repair.ID, Version: policy.Version,
		ObservedFingerprint: policy.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve repair: %v", err)
	}
	opStore := operations.NewStore()
	if _, err := opStore.Transition(ctx, pool, repair.ID, operations.StatusPending,
		operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start repair operation: %v", err)
	}
	if err := store.MarkFailed(ctx, pool, repair.ID, reserved.ExpectedVersion); err != nil {
		t.Fatalf("mark policy failed: %v", err)
	}
	if _, err := opStore.Transition(ctx, pool, repair.ID, operations.StatusRunning,
		operations.StatusFailed, operations.TransitionOpts{Error: "transient"}); err != nil {
		t.Fatalf("fail repair operation: %v", err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if repairable, active, err := store.Repairability(ctx, pool, policy); err != nil || repairable || !active {
		t.Fatalf("transient repairability = repairable:%v active:%v err:%v", repairable, active, err)
	}
	if err := store.MarkRetryExhausted(ctx, pool, repair.ID); err != nil {
		t.Fatalf("mark retries exhausted: %v", err)
	}
	// A fresh discovery may already observe the target exact while the
	// metadata/audit attempt failed. Reserve explicitly allows Repair from
	// status=failed in this state; the GET projection must offer it too.
	if _, err := pool.Exec(ctx, `update role_policies set exact=true where id=$1`, reserved.Policy.ID); err != nil {
		t.Fatalf("observe exact target after metadata failure: %v", err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if repairable, active, err := store.Repairability(ctx, pool, policy); err != nil || !repairable || active {
		t.Fatalf("terminal repairability = repairable:%v active:%v err:%v", repairable, active, err)
	}
	if err := store.MarkRetryPending(ctx, pool, repair.ID); err != nil {
		t.Fatalf("mark manual retry pending: %v", err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if repairable, active, err := store.Repairability(ctx, pool, policy); err != nil || repairable || !active {
		t.Fatalf("manual retry repairability = repairable:%v active:%v err:%v", repairable, active, err)
	}
	// A terminal failure can happen before executeRolePolicy reaches
	// failRolePolicy (for example, a stale verify-only payload). The outer
	// worker still has to release retry ownership and project a failed policy.
	if _, err := pool.Exec(ctx, `update role_policies set status='pending' where id=$1`, policy.ID); err != nil {
		t.Fatalf("reset pending state for early terminal failure: %v", err)
	}
	if err := store.MarkRetryExhausted(ctx, pool, repair.ID); err != nil {
		t.Fatalf("mark early terminal retry exhausted: %v", err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if policy.Status != rolepolicies.StatusFailed || policy.TransitionRetryPending {
		t.Fatalf("early terminal policy = status:%s retry_pending:%v", policy.Status, policy.TransitionRetryPending)
	}
}

func TestStructuralAndRevokedBindingsDoNotCountAsPolicyUse(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	spec := policySpec("r_structural")
	snapshot := &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{
			Kind: "login", EngineIdentity: "grantor_admin",
			Attributes: map[string]any{adapter.AttrConnectionAdmin: true},
		}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
		Bindings: []adapter.ObservedBinding{{
			AccountEngineIdentity: "grantor_admin", PermissionExternalID: "role:" + spec.RoleName,
			Attributes: map[string]any{"admin_option": true},
		}},
	}
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatalf("upsert structural inventory: %v", err)
	}
	store := rolepolicies.NewStore()
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{observation(spec, true, true, "expected-fingerprint")}, time.Now()); err != nil {
		t.Fatalf("reconcile policy: %v", err)
	}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID, nil, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("remove policy catalog: %v", err)
	}
	if _, err := store.GetByKey(ctx, pool, conn.ID, spec.Key); !errors.Is(err, rolepolicies.ErrNotFound) {
		t.Fatalf("structural binding kept unmanaged policy in use: %v", err)
	}

	conn = policyConnection(t, pool)
	spec = policySpec("r_revoked")
	snapshot = &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{{Kind: "login", EngineIdentity: "ordinary_user"}},
		Permissions: []adapter.ObservedPermission{{
			ExternalID: "role:" + spec.RoleName, Name: spec.RoleName, Assignable: true,
		}},
		Bindings: []adapter.ObservedBinding{{
			AccountEngineIdentity: "ordinary_user", PermissionExternalID: "role:" + spec.RoleName,
		}},
	}
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatalf("upsert active user binding: %v", err)
	}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{observation(spec, true, true, "expected-fingerprint")}, time.Now()); err != nil {
		t.Fatalf("reconcile revoked fixture policy: %v", err)
	}
	account, err := inventory.NewStore().FindAccountByIdentity(ctx, pool, conn.ID, "ordinary_user")
	if err != nil {
		t.Fatalf("find ordinary account: %v", err)
	}
	bindings, err := inventory.NewStore().ListBindingsByAccount(ctx, pool, account.ID)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("list active binding = %d, %v", len(bindings), err)
	}
	if _, err := inventory.NewStore().SetBindingDesired(ctx, pool, bindings[0].ID, inventory.BindingAbsent); err != nil {
		t.Fatalf("set binding absent: %v", err)
	}
	snapshot.Bindings = nil
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("observe revoked binding absent: %v", err)
	}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID, nil, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("remove policy with revoked tombstone: %v", err)
	}
	if _, err := store.GetByKey(ctx, pool, conn.ID, spec.Key); !errors.Is(err, rolepolicies.ErrNotFound) {
		t.Fatalf("revoked absent binding kept unmanaged policy in use: %v", err)
	}
}

func TestMongoInheritedPolicyRequiresManagedSyncedDependency(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "mongo-policy-dependencies-" + uuid.NewString(), Engine: "mongodb",
	})
	if err != nil {
		t.Fatalf("create MongoDB connection: %v", err)
	}
	baseSpec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "base-read", Name: "Base read",
		RoleName: "baseRead", Database: "app",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
	}
	dependentSpec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "composite-read", Name: "Composite read",
		RoleName: "compositeRead", Database: "app",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "baseRead", DB: "app"}},
	}
	observed := func(spec adapter.RolePolicySpec, expected, actual string, exact bool) adapter.ObservedRolePolicy {
		return adapter.ObservedRolePolicy{
			ExternalID: "role:" + spec.Database + "." + spec.RoleName,
			Spec:       spec, ExpectedFingerprint: expected, ObservedFingerprint: actual,
			Exact: exact, ApplySupported: true,
			Summary: map[string]any{
				"missing": []string{}, "extra": []string{}, "exists": true,
			},
		}
	}
	baseObservation := observed(baseSpec, "base-expected", "base-expected", true)
	dependentObservation := observed(dependentSpec, "dependent-expected", "dependent-expected", true)
	snapshot := &adapter.Snapshot{Permissions: []adapter.ObservedPermission{
		{ExternalID: baseObservation.ExternalID, Name: baseSpec.RoleName, Assignable: true},
		{ExternalID: dependentObservation.ExternalID, Name: dependentSpec.RoleName, Assignable: true},
	}}
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatalf("seed MongoDB permissions: %v", err)
	}
	store := rolepolicies.NewStore()
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{baseObservation, dependentObservation}, time.Now()); err != nil {
		t.Fatalf("reconcile unmanaged dependency graph: %v", err)
	}
	dependent, err := store.GetByKey(ctx, pool, conn.ID, dependentSpec.Key)
	if err != nil {
		t.Fatalf("get dependent policy: %v", err)
	}
	if dependent.ApplySupported || dependent.BlockedReason != "inherited_policy_not_ready" ||
		dependent.Status != rolepolicies.StatusBlocked {
		t.Fatalf("unmanaged dependency policy = %+v", dependent)
	}
	if permissionByExternal(t, pool, conn.ID, dependent.ExternalID).Assignable {
		t.Fatal("dependent permission became assignable before its dependency was managed")
	}

	base, err := store.GetByKey(ctx, pool, conn.ID, baseSpec.Key)
	if err != nil {
		t.Fatalf("get base policy: %v", err)
	}
	baseOp := operation(t, pool, conn.ID, "role.policy.adopt")
	baseReserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: base.TemplateKey, Action: rolepolicies.ActionAdopt,
		OperationID: baseOp.ID, Version: base.Version, ObservedFingerprint: base.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve base adopt: %v", err)
	}
	if _, err := store.Complete(ctx, pool, baseOp.ID, baseReserved.ExpectedVersion,
		base.ObservedFingerprint, base.ExpectedFingerprint, base.DesiredSpec); err != nil {
		t.Fatalf("complete base adopt: %v", err)
	}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{baseObservation, dependentObservation}, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("reconcile ready dependency graph: %v", err)
	}
	dependent, err = store.GetByKey(ctx, pool, conn.ID, dependentSpec.Key)
	if err != nil {
		t.Fatalf("reload dependent policy: %v", err)
	}
	if !dependent.ApplySupported || dependent.BlockedReason != "" || dependent.Status != rolepolicies.StatusObserved {
		t.Fatalf("ready dependent policy = %+v", dependent)
	}
	dependentOp := operation(t, pool, conn.ID, "role.policy.adopt")
	dependentReserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{
		ConnectionID: conn.ID, TemplateKey: dependent.TemplateKey, Action: rolepolicies.ActionAdopt,
		OperationID: dependentOp.ID, Version: dependent.Version,
		ObservedFingerprint: dependent.ObservedFingerprint,
	})
	if err != nil {
		t.Fatalf("reserve dependent adopt: %v", err)
	}
	completedDependent, err := store.Complete(ctx, pool, dependentOp.ID, dependentReserved.ExpectedVersion,
		dependent.ObservedFingerprint, dependent.ExpectedFingerprint, dependent.DesiredSpec)
	if err != nil {
		t.Fatalf("complete dependent adopt: %v", err)
	}
	var exactSummary map[string]any
	if err := json.Unmarshal(completedDependent.ObservedSummary, &exactSummary); err != nil {
		t.Fatalf("decode completed MongoDB summary: %v", err)
	}
	if exactSummary["exists"] != true || exactSummary["missing_count"] != float64(0) ||
		exactSummary["direct_inherited_roles_count"] != float64(1) {
		t.Fatalf("completed MongoDB summary = %+v", exactSummary)
	}

	baseDrift := observed(baseSpec, "base-expected", "base-drift", false)
	baseDrift.Summary["missing"] = []string{"role:app.read"}
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{baseDrift, dependentObservation}, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("reconcile dependency drift: %v", err)
	}
	dependent, err = store.GetByKey(ctx, pool, conn.ID, dependentSpec.Key)
	if err != nil {
		t.Fatalf("get dependency-blocked managed policy: %v", err)
	}
	if dependent.BlockedReason != "inherited_policy_not_ready" || dependent.Status != rolepolicies.StatusBlocked {
		t.Fatalf("dependent policy after base drift = %+v", dependent)
	}
	if permissionByExternal(t, pool, conn.ID, dependent.ExternalID).Assignable {
		t.Fatal("dependent permission remained assignable after dependency drift")
	}
}

func TestMongoTopLevelExistsProjectsMissingStatus(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "mongo-missing-policy-" + uuid.NewString(), Engine: "mongodb",
	})
	if err != nil {
		t.Fatalf("create MongoDB connection: %v", err)
	}
	spec := adapter.RolePolicySpec{
		Engine: "mongodb", Key: "missing-role", Name: "Missing role",
		RoleName: "missingRole", Database: "app",
	}
	observation := adapter.ObservedRolePolicy{
		ExternalID: "role:app.missingRole", Spec: spec,
		ExpectedFingerprint: "expected", ObservedFingerprint: "missing",
		ApplySupported: true,
		Summary: map[string]any{
			"missing": []string{"role:exists"}, "extra": []string{}, "exists": false,
		},
	}
	if err := rolepolicies.NewStore().ReconcileSnapshot(ctx, pool, conn.ID,
		[]adapter.ObservedRolePolicy{observation}, time.Now()); err != nil {
		t.Fatalf("reconcile missing MongoDB role: %v", err)
	}
	policy, err := rolepolicies.NewStore().GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatalf("get missing MongoDB policy: %v", err)
	}
	if policy.Status != rolepolicies.StatusMissing {
		t.Fatalf("missing MongoDB policy status = %q, want %q", policy.Status, rolepolicies.StatusMissing)
	}
}
