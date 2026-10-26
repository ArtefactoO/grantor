//go:build integration

package rolepolicies_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestMissingPolicyRequiresCreateAndRecoversTerminalPlaceholder(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	conn := policyConnection(t, pool)
	store := rolepolicies.NewStore()
	spec := policySpec("r_recover")
	if err := store.ReconcileSnapshot(ctx, pool, conn.ID, []adapter.ObservedRolePolicy{observation(spec, false, false, "missing")}, time.Now()); err != nil {
		t.Fatal(err)
	}
	policy, err := store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if err != nil {
		t.Fatal(err)
	}
	bad := operation(t, pool, conn.ID, "postgres.role.policy.apply.v2")
	_, err = store.Reserve(ctx, pool, rolepolicies.ReserveParams{ConnectionID: conn.ID, TemplateKey: spec.Key,
		Action: rolepolicies.ActionApply, OperationID: bad.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint})
	if !errors.Is(err, rolepolicies.ErrConflict) {
		t.Fatalf("missing Apply accepted: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, `select count(*) from accounts where connection_id=$1`, conn.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rejected Apply reserved an account: %d %v", n, err)
	}
	first := operation(t, pool, conn.ID, "postgres.role.policy.create.v2")
	reserved, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{ConnectionID: conn.ID, TemplateKey: spec.Key,
		Action: rolepolicies.ActionCreate, OperationID: first.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	// Same persisted shape as the old erroneous Apply: no target role, only a
	// managed/provisioning placeholder and a failed transition with retries.
	if _, err := pool.Exec(ctx, `update operations set status='failed',kind='postgres.role.policy.apply.v2' where id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkFailed(ctx, pool, first.ID, reserved.ExpectedVersion); err != nil {
		t.Fatal(err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if allowed, err := store.Creatability(ctx, pool, policy); err != nil || allowed {
		t.Fatal("creation stole an active retry")
	}
	if err := store.MarkRetryExhausted(ctx, pool, first.ID); err != nil {
		t.Fatal(err)
	}
	policy, _ = store.GetByKey(ctx, pool, conn.ID, spec.Key)
	if allowed, err := store.Creatability(ctx, pool, policy); err != nil || !allowed {
		t.Fatalf("terminal placeholder cannot recover: %v", err)
	}
	if repairable, active, err := store.Repairability(ctx, pool, policy); err != nil || repairable || active {
		t.Fatal("missing role offered repair")
	}
	// A previously real managed role that was deleted is not this recovery case.
	if _, err := pool.Exec(ctx, `update accounts set status='missing' where id=$1`, *policy.AccountID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := store.Creatability(ctx, pool, policy); err != nil || allowed {
		t.Fatal("externally deleted managed identity was treated as an empty reservation")
	}
	if _, err := pool.Exec(ctx, `update accounts set status='provisioning' where id=$1`, *policy.AccountID); err != nil {
		t.Fatal(err)
	}
	next := operation(t, pool, conn.ID, "postgres.role.policy.create.v2")
	recovered, err := store.Reserve(ctx, pool, rolepolicies.ReserveParams{ConnectionID: conn.ID, TemplateKey: spec.Key,
		Action: rolepolicies.ActionCreate, OperationID: next.ID, Version: policy.Version, ObservedFingerprint: policy.ObservedFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	if *recovered.Policy.AccountID != *policy.AccountID {
		t.Fatal("recovery created a duplicate account identity")
	}
}
