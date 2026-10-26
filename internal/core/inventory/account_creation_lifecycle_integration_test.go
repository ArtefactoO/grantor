//go:build integration

package inventory_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestAccountCreationLifecycleRejectsPendingTypedOperations(t *testing.T) {
	// Representative namespaces, not a list of all production operation kinds.
	// A new version in the same namespace must preserve the busy boundary.
	for _, kind := range []string{
		jobs.KindPostgresAccountProvisionV1,
		jobs.KindPostgresAccountVerifyCreationV1,
		"postgres.role.create.future.v3",
	} {
		t.Run(kind, func(t *testing.T) {
			pool := pgtest.Pool(t)
			inv, ops := inventory.NewStore(), operations.NewStore()
			conn := newTestConnection(t.Context(), t, pool)
			acct, err := inv.CreateProvisioningAccount(t.Context(), pool, inventory.CreateManagedAccountParams{
				ConnectionID: conn.ID, EngineIdentity: "pending_" + uuid.NewString(),
				CredentialMode: inventory.CredentialModeProvided,
			})
			if err != nil {
				t.Fatal(err)
			}
			op, _, err := ops.Create(t.Context(), pool, operations.CreateParams{
				Kind: kind, ConnectionID: &conn.ID, AccountID: &acct.ID, ActorType: "test", ActorID: t.Name(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inv.ReserveAccountLifecycle(t.Context(), pool, acct.ID, acct.Status); !errors.Is(err, inventory.ErrAccountLifecycleBusy) {
				t.Fatalf("pending typed operation did not fence the reservation: %v", err)
			}
			after, err := inv.GetAccount(t.Context(), pool, acct.ID)
			if err != nil || after.LifecycleVersion != acct.LifecycleVersion || after.Status != acct.Status {
				t.Fatal("busy typed operation changed the account lifecycle")
			}
			if _, err := ops.Transition(t.Context(), pool, op.ID, operations.StatusPending, operations.StatusCancelled, operations.TransitionOpts{}); err != nil {
				t.Fatal(err)
			}
			reserved, err := inv.ReserveAccountLifecycle(t.Context(), pool, acct.ID, acct.Status)
			if err != nil || reserved.LifecycleVersion != acct.LifecycleVersion+1 {
				t.Fatalf("finished typed operation left a permanent reservation barrier: %v", err)
			}
		})
	}
}

func TestAccountCreationLifecycleRejectsScheduledRetryAndSequencePredecessor(t *testing.T) {
	for _, predecessor := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct retry", true: "sequence predecessor"}[predecessor], func(t *testing.T) {
			pool := pgtest.Pool(t)
			inv, ops := inventory.NewStore(), operations.NewStore()
			conn := newTestConnection(t.Context(), t, pool)
			acct, err := inv.CreateProvisioningAccount(t.Context(), pool, inventory.CreateManagedAccountParams{
				ConnectionID: conn.ID, EngineIdentity: "scheduled_" + uuid.NewString(),
				CredentialMode: inventory.CredentialModeProvided,
			})
			if err != nil {
				t.Fatal(err)
			}
			source, _, err := ops.Create(t.Context(), pool, operations.CreateParams{
				Kind: jobs.KindPostgresAccountProvisionV1, ConnectionID: &conn.ID, AccountID: &acct.ID,
				ActorType: "test", ActorID: t.Name(),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ops.Transition(t.Context(), pool, source.ID, operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
				t.Fatal(err)
			}
			if _, err := ops.Transition(t.Context(), pool, source.ID, operations.StatusRunning, operations.StatusFailed, operations.TransitionOpts{Error: "scheduled retry fixture"}); err != nil {
				t.Fatal(err)
			}
			river, err := jobs.NewInsertOnly(pool)
			if err != nil {
				t.Fatal(err)
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(t.Context()) //nolint:errcheck
			queuedID := source.ID
			if predecessor {
				head, _, err := ops.Create(t.Context(), tx, operations.CreateParams{
					Kind: "unrelated.workflow", ConnectionID: &conn.ID, ActorType: "test", ActorID: t.Name(),
				})
				if err != nil {
					t.Fatal(err)
				}
				queuedID = head.ID
				err = river.EnqueueOperationSequenceTx(t.Context(), tx, head.ID, source.ID)
			} else {
				err = river.EnqueueOperationTx(t.Context(), tx, source.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `update river_job set state='scheduled',scheduled_at=now()+interval '1 hour'
				where args->>'operation_id'=$1`, queuedID.String()); err != nil {
				t.Fatal(err)
			}
			if _, err := inv.ReserveAccountLifecycle(t.Context(), pool, acct.ID, acct.Status); !errors.Is(err, inventory.ErrAccountLifecycleBusy) {
				t.Fatalf("failed operation with a live scheduled retry did not fence the reservation: %v", err)
			}
			after, err := inv.GetAccount(t.Context(), pool, acct.ID)
			if err != nil || after.LifecycleVersion != acct.LifecycleVersion || after.Status != acct.Status {
				t.Fatal("scheduled retry changed the account reservation")
			}
			if _, err := pool.Exec(t.Context(), `update river_job set state='discarded',finalized_at=now()
				where args->>'operation_id'=$1`, queuedID.String()); err != nil {
				t.Fatal(err)
			}
			reserved, err := inv.ReserveAccountLifecycle(t.Context(), pool, acct.ID, acct.Status)
			if err != nil || reserved.LifecycleVersion != acct.LifecycleVersion+1 {
				t.Fatalf("stopped retry left a permanent account reservation barrier: %v", err)
			}
		})
	}
}
