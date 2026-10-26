//go:build integration

package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type replacementTestFixture struct {
	connectionID uuid.UUID
	account      inventory.Account
	permissionA  uuid.UUID
	permissionB  uuid.UUID
	permissionC  uuid.UUID
	binding      inventory.Binding
	assignment   string
}

func newReplacementTestFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	store *inventory.Store,
) replacementTestFixture {
	t.Helper()
	conn := newTestConnection(ctx, t, pool)
	account, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "replace-fixture-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create replacement fixture account: %v", err)
	}
	assignmentKey := "rabbitmq:vhost:" + uuid.NewString()
	ids := make([]uuid.UUID, 3)
	for i, name := range []string{"a", "b", "c"} {
		if err := pool.QueryRow(ctx, `
			insert into permission_definitions
				(connection_id, engine, external_id, name, assignment_key, assignable, attributes)
			values ($1, 'rabbitmq', $2, $3, $4, true, jsonb_build_object('template_key', $3::text))
			returning id`, conn.ID, "template:"+name+":"+uuid.NewString(), name, assignmentKey).Scan(&ids[i]); err != nil {
			t.Fatalf("insert replacement fixture permission %s: %v", name, err)
		}
	}
	binding, _, err := store.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID: account.ID, PermissionID: ids[0], DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure replacement fixture binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		update bindings set
			observed_state = 'present', observed_effective = true, status = 'synced',
			observed_permission_definition_id = $2,
			observed_attributes = (select attributes from permission_definitions where id = $2)
		where id = $1`, binding.ID, ids[0]); err != nil {
		t.Fatalf("seed replacement fixture observation: %v", err)
	}
	binding, err = store.GetBinding(ctx, pool, binding.ID)
	if err != nil {
		t.Fatalf("reload replacement fixture binding: %v", err)
	}
	return replacementTestFixture{
		connectionID: conn.ID,
		account:      account,
		permissionA:  ids[0],
		permissionB:  ids[1],
		permissionC:  ids[2],
		binding:      binding,
		assignment:   assignmentKey,
	}
}

func TestAccessReplacementTransitionKeepsOneBindingAndIsVersionGuarded(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	account, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "replace-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}

	assignmentKey := "rabbitmq:vhost:etl"
	var fromID, toID, driftID uuid.UUID
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions
			(connection_id, engine, external_id, name, assignment_key, assignable, attributes)
		values ($1, 'rabbitmq', $2, 'old', $3, true, '{"configure":"old"}'::jsonb)
		returning id`, conn.ID, "old-"+uuid.NewString(), assignmentKey).Scan(&fromID); err != nil {
		t.Fatalf("insert from permission: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions
			(connection_id, engine, external_id, name, assignment_key, assignable, attributes)
		values ($1, 'rabbitmq', $2, 'new', $3, true, '{"configure":"new"}'::jsonb)
		returning id`, conn.ID, "new-"+uuid.NewString(), assignmentKey).Scan(&toID); err != nil {
		t.Fatalf("insert to permission: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions
			(connection_id, engine, external_id, name, assignment_key, assignable, attributes)
		values ($1, 'rabbitmq', $2, 'drift', $3, true, '{"configure":"drift"}'::jsonb)
		returning id`, conn.ID, "drift-"+uuid.NewString(), assignmentKey).Scan(&driftID); err != nil {
		t.Fatalf("insert drift permission: %v", err)
	}
	binding, _, err := store.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID: account.ID, PermissionID: fromID, DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure source binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		update bindings set
			observed_state = 'present', observed_effective = true, status = 'synced',
			observed_permission_definition_id = $2,
			observed_attributes = '{"configure":"old"}'::jsonb
		where id = $1`, binding.ID, fromID); err != nil {
		t.Fatalf("seed observed source: %v", err)
	}
	binding, err = store.GetBinding(ctx, pool, binding.ID)
	if err != nil {
		t.Fatalf("reload source binding: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reserve: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, _, err := operations.NewStore().Create(ctx, tx, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &conn.ID, AccountID: &account.ID,
		BindingID: &binding.ID, ActorType: "test", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatalf("create replace operation: %v", err)
	}
	transition := inventory.AccessReplacementTransition{
		BindingID: binding.ID, OperationID: op.ID,
		FromPermissionID: fromID, ToPermissionID: toID,
		AssignmentKey: assignmentKey, ExpectedVersion: binding.Version + 1,
	}
	reserved, err := store.ReserveAccessReplacement(ctx, tx, transition)
	if err != nil {
		t.Fatalf("reserve replacement: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit reserve: %v", err)
	}
	if _, err := operations.NewStore().Transition(ctx, pool, op.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start replacement operation: %v", err)
	}
	if reserved.ID != binding.ID || reserved.PermissionDefinitionID != toID ||
		reserved.ObservedPermissionDefinitionID == nil || *reserved.ObservedPermissionDefinitionID != fromID ||
		reserved.Version != transition.ExpectedVersion || reserved.TransitionOperationID == nil ||
		*reserved.TransitionOperationID != op.ID {
		t.Fatalf("reserved binding = %+v", reserved)
	}
	if string(reserved.ObservedAttributes) != `{"configure": "old"}` &&
		string(reserved.ObservedAttributes) != `{"configure":"old"}` {
		t.Fatalf("reserve changed observed attributes: %s", reserved.ObservedAttributes)
	}
	// Discovery вправе увидеть actual C, пока operation всё ещё владеет desired
	// transition A -> B. Это drift, а не stale job: exact Verify B должен иметь
	// возможность завершить переход и переписать observed на B.
	if _, err := pool.Exec(ctx, `
		update bindings set observed_permission_definition_id = $2,
			observed_attributes = '{"configure":"drift"}'::jsonb, status = 'drift'
		where id = $1`, binding.ID, driftID); err != nil {
		t.Fatalf("seed observed drift during replacement: %v", err)
	}

	stale := transition
	stale.OperationID = uuid.New()
	if _, err := store.CompleteAccessReplacement(ctx, pool, stale); !errors.Is(err, inventory.ErrBindingTransitionConflict) {
		t.Fatalf("stale complete error = %v", err)
	}
	completed, err := store.CompleteAccessReplacement(ctx, pool, transition)
	if err != nil {
		t.Fatalf("complete replacement: %v", err)
	}
	if completed.PermissionDefinitionID != toID || completed.ObservedPermissionDefinitionID == nil ||
		*completed.ObservedPermissionDefinitionID != toID || completed.TransitionOperationID != nil ||
		completed.Version != transition.ExpectedVersion+1 || completed.Status != inventory.BindingStatusSynced {
		t.Fatalf("completed binding = %+v", completed)
	}
	if _, err := operations.NewStore().Transition(ctx, pool, op.ID,
		operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
		t.Fatalf("finish replacement operation: %v", err)
	}

	// Approval reject до Apply возвращает desired B и делает выданный payload
	// B -> A stale отдельным увеличением версии.
	rejectTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin reject reserve: %v", err)
	}
	defer rejectTx.Rollback(ctx) //nolint:errcheck
	rejectOp, _, err := operations.NewStore().Create(ctx, rejectTx, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &conn.ID, AccountID: &account.ID,
		BindingID: &binding.ID, ActorType: "test", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatalf("create rejected operation: %v", err)
	}
	rejectedTransition := inventory.AccessReplacementTransition{
		BindingID: binding.ID, OperationID: rejectOp.ID,
		FromPermissionID: toID, ToPermissionID: fromID,
		AssignmentKey: assignmentKey, ExpectedVersion: completed.Version + 1,
	}
	if _, err := store.ReserveAccessReplacement(ctx, rejectTx, rejectedTransition); err != nil {
		t.Fatalf("reserve rejected replacement: %v", err)
	}
	if err := rejectTx.Commit(ctx); err != nil {
		t.Fatalf("commit rejected reserve: %v", err)
	}
	rejected, err := store.RejectAccessReplacement(ctx, pool, rejectedTransition)
	if err != nil {
		t.Fatalf("reject replacement: %v", err)
	}
	if rejected.PermissionDefinitionID != toID || rejected.ObservedPermissionDefinitionID == nil ||
		*rejected.ObservedPermissionDefinitionID != toID || rejected.TransitionOperationID != nil ||
		rejected.Version != rejectedTransition.ExpectedVersion+1 || rejected.Status != inventory.BindingStatusSynced {
		t.Fatalf("rejected binding = %+v", rejected)
	}

	var count int
	if err := pool.QueryRow(ctx,
		`select count(*) from bindings where account_id = $1 and assignment_key = $2`,
		account.ID, assignmentKey).Scan(&count); err != nil {
		t.Fatalf("count slot bindings: %v", err)
	}
	if count != 1 {
		t.Fatalf("slot binding rows = %d, want 1", count)
	}
}

func TestTransitionOwnedBindingRejectsGenericMutators(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	fixture := newReplacementTestFixture(t, ctx, pool, store)
	op, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &fixture.connectionID,
		AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create replacement operation: %v", err)
	}
	transition := inventory.AccessReplacementTransition{
		BindingID: fixture.binding.ID, OperationID: op.ID,
		FromPermissionID: fixture.permissionA, ToPermissionID: fixture.permissionB,
		AssignmentKey: fixture.assignment, ExpectedVersion: fixture.binding.Version + 1,
	}
	reserved, err := store.ReserveAccessReplacement(ctx, pool, transition)
	if err != nil {
		t.Fatalf("reserve replacement: %v", err)
	}

	mutators := []struct {
		name string
		run  func() error
	}{
		{"ensure", func() error {
			_, _, err := store.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
				AccountID: fixture.account.ID, PermissionID: fixture.permissionB,
				DesiredState: inventory.BindingPresent,
			})
			return err
		}},
		{"set desired", func() error {
			_, err := store.SetBindingDesired(ctx, pool, fixture.binding.ID, inventory.BindingAbsent)
			return err
		}},
		{"set result", func() error {
			_, err := store.SetBindingResult(ctx, pool, fixture.binding.ID, inventory.BindingPresent)
			return err
		}},
		{"set expected result", func() error {
			_, err := store.SetBindingResultExpected(ctx, pool, fixture.binding.ID, fixture.permissionB,
				inventory.BindingPresent, inventory.BindingPresent, nil)
			return err
		}},
		{"mark expected failed", func() error {
			return store.MarkBindingFailedExpected(ctx, pool, fixture.binding.ID, fixture.permissionB,
				inventory.BindingPresent)
		}},
		{"mark failed", func() error {
			return store.MarkBindingFailed(ctx, pool, fixture.binding.ID)
		}},
		{"restore unmanaged", func() error {
			_, err := store.RestoreBindingDesired(ctx, pool, fixture.binding.ID, nil)
			return err
		}},
		{"delete unapplied", func() error {
			_, err := store.DeleteUnappliedBinding(ctx, pool, fixture.binding.ID)
			return err
		}},
	}
	for _, test := range mutators {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, inventory.ErrBindingTransitionConflict) {
				t.Fatalf("error = %v, want ErrBindingTransitionConflict", err)
			}
			current, err := store.GetBinding(ctx, pool, fixture.binding.ID)
			if err != nil {
				t.Fatalf("reload transition-owned binding: %v", err)
			}
			if current.PermissionDefinitionID != fixture.permissionB ||
				current.TransitionOperationID == nil || *current.TransitionOperationID != op.ID ||
				current.Version != reserved.Version || current.Status != inventory.BindingStatusPending {
				t.Fatalf("mutator changed transition-owned binding: %+v", current)
			}
		})
	}
}

func TestReserveAccessReplacementBlocksActiveGrantAndRevoke(t *testing.T) {
	for _, kind := range []string{"access.grant", "access.revoke"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pool := pgtest.Pool(t)
			store := inventory.NewStore()
			fixture := newReplacementTestFixture(t, ctx, pool, store)
			if _, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
				Kind: kind, ConnectionID: &fixture.connectionID,
				AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
				ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
			}); err != nil {
				t.Fatalf("create active %s operation: %v", kind, err)
			}
			replaceOp, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
				Kind: "access.replace", ConnectionID: &fixture.connectionID,
				AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
				ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
			})
			if err != nil {
				t.Fatalf("create replacement operation: %v", err)
			}
			_, err = store.ReserveAccessReplacement(ctx, pool, inventory.AccessReplacementTransition{
				BindingID: fixture.binding.ID, OperationID: replaceOp.ID,
				FromPermissionID: fixture.permissionA, ToPermissionID: fixture.permissionB,
				AssignmentKey: fixture.assignment, ExpectedVersion: fixture.binding.Version + 1,
			})
			if !errors.Is(err, inventory.ErrBindingTransitionConflict) {
				t.Fatalf("reserve with active %s error = %v, want ErrBindingTransitionConflict", kind, err)
			}
			current, getErr := store.GetBinding(ctx, pool, fixture.binding.ID)
			if getErr != nil {
				t.Fatalf("reload binding: %v", getErr)
			}
			if current.PermissionDefinitionID != fixture.permissionA ||
				current.TransitionOperationID != nil || current.Version != fixture.binding.Version {
				t.Fatalf("blocked reservation changed binding: %+v", current)
			}
		})
	}
}

func TestEnsureBindingRetiresSyncedExclusiveRevokeTombstone(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	fixture := newReplacementTestFixture(t, ctx, pool, store)

	if _, err := store.SetBindingDesired(ctx, pool, fixture.binding.ID, inventory.BindingAbsent); err != nil {
		t.Fatalf("set exclusive binding absent: %v", err)
	}
	tombstone, err := store.SetBindingResultExpected(ctx, pool, fixture.binding.ID, fixture.permissionA,
		inventory.BindingAbsent, inventory.BindingAbsent, nil)
	if err != nil {
		t.Fatalf("complete exclusive revoke: %v", err)
	}
	if tombstone.Status != inventory.BindingStatusSynced || tombstone.ObservedState != inventory.BindingAbsent {
		t.Fatalf("exclusive revoke tombstone = %+v, want absent/synced", tombstone)
	}
	opStore := operations.NewStore()
	pendingOp, _, err := opStore.Create(ctx, pool, operations.CreateParams{
		Kind: "access.revoke", ConnectionID: &fixture.connectionID,
		AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create pending revoke operation: %v", err)
	}
	blockedTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin blocked tombstone retire: %v", err)
	}
	_, _, blockedErr := store.EnsureBinding(ctx, blockedTx, inventory.EnsureBindingParams{
		AccountID: fixture.account.ID, PermissionID: fixture.permissionB,
		DesiredState: inventory.BindingPresent,
	})
	if !errors.Is(blockedErr, inventory.ErrBindingTransitionConflict) {
		blockedTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("retire with pending operation error = %v, want ErrBindingTransitionConflict", blockedErr)
	}
	if err := blockedTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback blocked tombstone retire: %v", err)
	}
	if _, err := store.GetBinding(ctx, pool, fixture.binding.ID); err != nil {
		t.Fatalf("pending operation retire removed tombstone: %v", err)
	}
	if _, err := opStore.Transition(ctx, pool, pendingOp.ID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start revoke operation: %v", err)
	}
	if _, err := opStore.Transition(ctx, pool, pendingOp.ID,
		operations.StatusRunning, operations.StatusSuccess, operations.TransitionOpts{}); err != nil {
		t.Fatalf("finish revoke operation: %v", err)
	}

	retireCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	retireTx, err := pool.Begin(retireCtx)
	if err != nil {
		t.Fatalf("begin terminal tombstone retire: %v", err)
	}
	defer retireTx.Rollback(ctx) //nolint:errcheck
	created, fresh, err := store.EnsureBinding(retireCtx, retireTx, inventory.EnsureBindingParams{
		AccountID: fixture.account.ID, PermissionID: fixture.permissionB,
		DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure new exclusive permission: %v", err)
	}
	if err := retireTx.Commit(retireCtx); err != nil {
		t.Fatalf("commit terminal tombstone retire: %v", err)
	}
	if !fresh || created.ID == fixture.binding.ID || created.PermissionDefinitionID != fixture.permissionB ||
		created.AssignmentKey != fixture.assignment {
		t.Fatalf("new exclusive binding = %+v fresh=%v; want new UUID for permission B", created, fresh)
	}
	if _, err := store.GetBinding(ctx, pool, fixture.binding.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("retired tombstone lookup error = %v, want ErrNotFound", err)
	}
	bindings, err := store.ListBindingsByAccount(ctx, pool, fixture.account.ID)
	if err != nil || len(bindings) != 1 || bindings[0].ID != created.ID {
		t.Fatalf("exclusive slot rows after regrant = %+v, %v; want only new binding", bindings, err)
	}
	finished, err := opStore.Get(ctx, pool, pendingOp.ID)
	if err != nil {
		t.Fatalf("reload terminal revoke operation: %v", err)
	}
	if finished.Status != operations.StatusSuccess || finished.BindingID != nil {
		t.Fatalf("terminal revoke after tombstone retire = status %q binding %v, want success/nil",
			finished.Status, finished.BindingID)
	}
}

func TestFailedAccessReplacementAllowsOnlyExactReverseTakeover(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	fixture := newReplacementTestFixture(t, ctx, pool, store)
	oldPayload, err := json.Marshal(map[string]any{
		"binding_id": fixture.binding.ID, "from_permission_definition_id": fixture.permissionA,
		"to_permission_definition_id": fixture.permissionB, "assignment_key": fixture.assignment,
		"expected_binding_version": fixture.binding.Version + 1,
	})
	if err != nil {
		t.Fatalf("marshal old replacement payload: %v", err)
	}
	oldOp, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &fixture.connectionID,
		AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID, Payload: oldPayload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create old replacement operation: %v", err)
	}
	oldTransition := inventory.AccessReplacementTransition{
		BindingID: fixture.binding.ID, OperationID: oldOp.ID,
		FromPermissionID: fixture.permissionA, ToPermissionID: fixture.permissionB,
		AssignmentKey: fixture.assignment, ExpectedVersion: fixture.binding.Version + 1,
	}
	if _, err := store.ReserveAccessReplacement(ctx, pool, oldTransition); err != nil {
		t.Fatalf("reserve old replacement: %v", err)
	}
	if err := store.MarkAccessReplacementFailed(ctx, pool, oldTransition); err != nil {
		t.Fatalf("mark old replacement failed: %v", err)
	}
	if _, err := pool.Exec(ctx, `update operations set status = 'failed', finished_at = now() where id = $1`, oldOp.ID); err != nil {
		t.Fatalf("mark old operation failed: %v", err)
	}

	// B -> C is not the exact inverse of the pinned A -> B intent and cannot
	// steal its durable transition owner. Roll back the rejected operation so
	// it does not itself remain an active blocker for the valid reverse.
	badTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin arbitrary takeover: %v", err)
	}
	badOp, _, err := operations.NewStore().Create(ctx, badTx, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &fixture.connectionID,
		AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		badTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("create arbitrary replacement operation: %v", err)
	}
	_, badErr := store.ReserveAccessReplacement(ctx, badTx, inventory.AccessReplacementTransition{
		BindingID: fixture.binding.ID, OperationID: badOp.ID,
		FromPermissionID: fixture.permissionB, ToPermissionID: fixture.permissionC,
		AssignmentKey: fixture.assignment, ExpectedVersion: oldTransition.ExpectedVersion + 1,
	})
	if !errors.Is(badErr, inventory.ErrBindingTransitionConflict) {
		badTx.Rollback(ctx) //nolint:errcheck
		t.Fatalf("arbitrary B -> C takeover error = %v, want ErrBindingTransitionConflict", badErr)
	}
	if err := badTx.Rollback(ctx); err != nil {
		t.Fatalf("rollback arbitrary takeover: %v", err)
	}

	reverseTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin exact reverse takeover: %v", err)
	}
	defer reverseTx.Rollback(ctx) //nolint:errcheck
	reverseOp, _, err := operations.NewStore().Create(ctx, reverseTx, operations.CreateParams{
		Kind: "access.replace", ConnectionID: &fixture.connectionID,
		AccountID: &fixture.account.ID, BindingID: &fixture.binding.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create reverse replacement operation: %v", err)
	}
	reverseTransition := inventory.AccessReplacementTransition{
		BindingID: fixture.binding.ID, OperationID: reverseOp.ID,
		FromPermissionID: fixture.permissionB, ToPermissionID: fixture.permissionA,
		AssignmentKey: fixture.assignment, ExpectedVersion: oldTransition.ExpectedVersion + 1,
	}
	reversed, err := store.ReserveAccessReplacement(ctx, reverseTx, reverseTransition)
	if err != nil {
		t.Fatalf("reserve exact B -> A reverse: %v", err)
	}
	if err := reverseTx.Commit(ctx); err != nil {
		t.Fatalf("commit exact reverse takeover: %v", err)
	}
	if reversed.PermissionDefinitionID != fixture.permissionA || reversed.Version != reverseTransition.ExpectedVersion ||
		reversed.TransitionOperationID == nil || *reversed.TransitionOperationID != reverseOp.ID {
		t.Fatalf("reversed binding = %+v, want A owned by reverse operation", reversed)
	}
	if _, err := store.CompleteAccessReplacement(ctx, pool, oldTransition); !errors.Is(err, inventory.ErrBindingTransitionConflict) {
		t.Fatalf("old replacement payload after takeover error = %v, want ErrBindingTransitionConflict", err)
	}
}
