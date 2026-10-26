//go:build integration

package inventory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

const assignmentSlot = "rabbitmq:vhost:app"

func assignmentSnapshot(identity, observedPermission string) *adapter.Snapshot {
	return &adapter.Snapshot{
		Accounts: []adapter.ObservedAccount{
			{Kind: "login", EngineIdentity: identity},
		},
		Permissions: []adapter.ObservedPermission{
			{ExternalID: "template:a", Name: "Template A", AssignmentKey: assignmentSlot, Assignable: true},
			{ExternalID: "template:b", Name: "Template B", AssignmentKey: assignmentSlot, Assignable: true},
		},
		Bindings: []adapter.ObservedBinding{
			{
				AccountEngineIdentity: identity,
				PermissionExternalID:  observedPermission,
				AssignmentKey:         assignmentSlot,
				Attributes: map[string]any{
					"actual_template":            observedPermission,
					adapter.AttrBindingEffective: true,
				},
			},
		},
		ObservedAt: time.Now(),
	}
}

func unknownAssignmentSnapshot(identity string) *adapter.Snapshot {
	snap := assignmentSnapshot(identity, "template:unknown")
	snap.Permissions = append(snap.Permissions, adapter.ObservedPermission{
		ExternalID: "template:unknown", Name: "Unknown narrow regex", AssignmentKey: assignmentSlot,
	})
	snap.Bindings[0].Attributes = map[string]any{
		"configure":                  "^status_changes$",
		"write":                      "^etl_updates$",
		"read":                       "^(status_changes|etl_updates)$",
		adapter.AttrBindingEffective: false,
	}
	return snap
}

func assignmentPermissionByExternalID(t *testing.T, permissions []inventory.Permission, externalID string) inventory.Permission {
	t.Helper()
	for i := range permissions {
		if permissions[i].ExternalID == externalID {
			return permissions[i]
		}
	}
	t.Fatalf("permission %q not found", externalID)
	return inventory.Permission{}
}

func observedAttrs(t *testing.T, binding inventory.Binding) map[string]any {
	t.Helper()
	var attrs map[string]any
	if err := json.Unmarshal(binding.ObservedAttributes, &attrs); err != nil {
		t.Fatalf("decode observed attributes: %v", err)
	}
	return attrs
}

func TestExclusiveAssignmentManagedKeepsDesiredAndTracksObserved(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-managed"

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now()); err != nil {
		t.Fatalf("upsert template A: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	templateA := assignmentPermissionByExternalID(t, permissions, "template:a")
	templateB := assignmentPermissionByExternalID(t, permissions, "template:b")
	bindings, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("initial bindings = %d, %v; want one", len(bindings), err)
	}
	bindingID := bindings[0].ID
	if _, err := store.AdoptBinding(ctx, pool, bindingID); err != nil {
		t.Fatalf("adopt template A: %v", err)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:b"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("upsert observed template B: %v", err)
	}
	bindings, err = store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("bindings after mismatch = %d, %v; want one", len(bindings), err)
	}
	mismatch := bindings[0]
	if mismatch.ID != bindingID || mismatch.PermissionDefinitionID != templateA.ID {
		t.Errorf("desired binding changed: id=%s permission=%s, want %s/%s",
			mismatch.ID, mismatch.PermissionDefinitionID, bindingID, templateA.ID)
	}
	if mismatch.ObservedPermissionDefinitionID == nil || *mismatch.ObservedPermissionDefinitionID != templateB.ID {
		t.Errorf("observed permission = %v, want template B %s", mismatch.ObservedPermissionDefinitionID, templateB.ID)
	}
	if mismatch.AssignmentKey != assignmentSlot || !mismatch.ObservedEffective || mismatch.Status != inventory.BindingStatusDrift {
		t.Errorf("mismatch binding = %+v, want exact actual template with desired/actual drift", mismatch)
	}
	if got := observedAttrs(t, mismatch)["actual_template"]; got != "template:b" {
		t.Errorf("observed actual_template = %v, want template:b", got)
	}

	unchangedAt := mismatch.UpdatedAt
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:b"), time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("repeat observed template B: %v", err)
	}
	repeated, err := store.GetBinding(ctx, pool, bindingID)
	if err != nil {
		t.Fatalf("get repeated binding: %v", err)
	}
	if !repeated.UpdatedAt.Equal(unchangedAt) {
		t.Errorf("exclusive binding updated_at changed on identical snapshot: %v -> %v", unchangedAt, repeated.UpdatedAt)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now().Add(3*time.Minute)); err != nil {
		t.Fatalf("restore observed template A: %v", err)
	}
	synced, err := store.GetBinding(ctx, pool, bindingID)
	if err != nil {
		t.Fatalf("get synced binding: %v", err)
	}
	if synced.ObservedPermissionDefinitionID == nil || *synced.ObservedPermissionDefinitionID != templateA.ID ||
		!synced.ObservedEffective || synced.Status != inventory.BindingStatusSynced {
		t.Errorf("synced binding = %+v, want exact template A/synced", synced)
	}
}

func TestExclusiveAssignmentUnmanagedMovesExactBindingWithoutTwin(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-unmanaged"

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now()); err != nil {
		t.Fatalf("upsert template A: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	initial, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(initial) != 1 {
		t.Fatalf("initial bindings = %d, %v; want one", len(initial), err)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:b"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("upsert template B: %v", err)
	}
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	templateB := assignmentPermissionByExternalID(t, permissions, "template:b")
	current, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(current) != 1 {
		t.Fatalf("current bindings = %d, %v; want one", len(current), err)
	}
	if current[0].ID != initial[0].ID || current[0].PermissionDefinitionID != templateB.ID ||
		current[0].ObservedPermissionDefinitionID == nil || *current[0].ObservedPermissionDefinitionID != templateB.ID ||
		current[0].DesiredState != nil || current[0].Status != inventory.BindingStatusObserved {
		t.Errorf("unmanaged slot = %+v, want same row moved exactly to template B", current[0])
	}
}

func TestExclusiveAssignmentUnknownActualKeepsOneManagedSlot(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-unknown"

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now()); err != nil {
		t.Fatalf("upsert template A: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	bindings, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("initial bindings = %d, %v; want one", len(bindings), err)
	}
	if _, err := store.AdoptBinding(ctx, pool, bindings[0].ID); err != nil {
		t.Fatalf("adopt template A: %v", err)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, unknownAssignmentSnapshot(identity), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("upsert unknown actual: %v", err)
	}
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	unknown := assignmentPermissionByExternalID(t, permissions, "template:unknown")
	current, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(current) != 1 {
		t.Fatalf("bindings after unknown actual = %d, %v; want one slot row", len(current), err)
	}
	b := current[0]
	if b.ID != bindings[0].ID || b.ObservedPermissionDefinitionID == nil ||
		*b.ObservedPermissionDefinitionID != unknown.ID || b.ObservedEffective ||
		b.Status != inventory.BindingStatusDrift {
		t.Errorf("unknown actual binding = %+v, want same managed row with observed unknown/drift", b)
	}
	attrs := observedAttrs(t, b)
	if attrs["configure"] != "^status_changes$" || attrs["write"] != "^etl_updates$" {
		t.Errorf("unknown actual attributes = %#v, want exact regex triple", attrs)
	}
}

func TestExclusiveAssignmentRejectsInexactAdoptAndBulkIsAtomic(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-adopt-mismatch"

	snap := unknownAssignmentSnapshot(identity)
	snap.Permissions = append(snap.Permissions, adapter.ObservedPermission{
		ExternalID: "role:readers", Name: "Readers", Assignable: true,
	})
	snap.Bindings = append(snap.Bindings, adapter.ObservedBinding{
		AccountEngineIdentity: identity, PermissionExternalID: "role:readers",
	})
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("upsert unknown + non-exclusive bindings: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	bindings, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 2 {
		t.Fatalf("bindings = %d, %v; want exclusive mismatch + non-exclusive", len(bindings), err)
	}
	var exclusive inventory.Binding
	for i := range bindings {
		if bindings[i].AssignmentKey != "" {
			exclusive = bindings[i]
		}
	}
	if exclusive.ID == uuid.Nil {
		t.Fatal("exclusive mismatch binding not found")
	}
	if _, err := store.AdoptBinding(ctx, pool, exclusive.ID); !errors.Is(err, inventory.ErrBindingObservationMismatch) {
		t.Errorf("AdoptBinding mismatch error = %v, want ErrBindingObservationMismatch", err)
	}
	if _, err := store.AdoptAccountBindings(ctx, pool, account); !errors.Is(err, inventory.ErrBindingObservationMismatch) {
		t.Errorf("AdoptAccountBindings mismatch error = %v, want ErrBindingObservationMismatch", err)
	}
	bindings, err = store.ListBindingsByAccount(ctx, pool, account)
	if err != nil {
		t.Fatalf("reload bindings: %v", err)
	}
	for i := range bindings {
		if bindings[i].DesiredState != nil {
			t.Errorf("bulk adopt partially managed binding %+v", bindings[i])
		}
	}
}

func TestExclusiveAssignmentDiscoveryPreservesActiveTransition(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-transition"

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now()); err != nil {
		t.Fatalf("upsert template A: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	templateA := assignmentPermissionByExternalID(t, permissions, "template:a")
	templateB := assignmentPermissionByExternalID(t, permissions, "template:b")
	bindings, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 1 {
		t.Fatalf("initial bindings = %d, %v; want one", len(bindings), err)
	}
	managed, err := store.AdoptBinding(ctx, pool, bindings[0].ID)
	if err != nil {
		t.Fatalf("adopt template A: %v", err)
	}
	operationID := uuid.New()
	if _, err := pool.Exec(ctx, `
		insert into operations (id, kind, connection_id, account_id, binding_id, actor_type, actor_id)
		values ($1, 'access.replace', $2, $3, $4, 'test', 'assignment-transition')`,
		operationID, conn.ID, account, managed.ID,
	); err != nil {
		t.Fatalf("insert transition operation: %v", err)
	}
	reserved, err := store.ReserveAccessReplacement(ctx, pool, inventory.AccessReplacementTransition{
		BindingID: managed.ID, OperationID: operationID,
		FromPermissionID: templateA.ID, ToPermissionID: templateB.ID,
		AssignmentKey: assignmentSlot, ExpectedVersion: managed.Version + 1,
	})
	if err != nil {
		t.Fatalf("reserve replacement: %v", err)
	}
	if reserved.Status != inventory.BindingStatusPending || reserved.TransitionOperationID == nil {
		t.Fatalf("reserved binding = %+v, want pending transition", reserved)
	}

	// Target всё ещё на A, пока child operation не выполнил PUT B. Discovery
	// обновляет actual observation, но не имеет права завершать transition.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, assignmentSnapshot(identity, "template:a"), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("discovery during replacement: %v", err)
	}
	current, err := store.GetBinding(ctx, pool, managed.ID)
	if err != nil {
		t.Fatalf("get binding after discovery: %v", err)
	}
	if current.PermissionDefinitionID != templateB.ID || current.ObservedPermissionDefinitionID == nil ||
		*current.ObservedPermissionDefinitionID != templateA.ID || current.Status != inventory.BindingStatusPending ||
		current.TransitionOperationID == nil || *current.TransitionOperationID != operationID ||
		current.Version != reserved.Version || !current.ObservedEffective {
		t.Errorf("binding after concurrent discovery = %+v, want desired B/actual exact A with pending owner", current)
	}

	// Approval reject is still a metadata-only rollback because Apply has not
	// started. The fresh exact observation of A must immediately make the slot
	// synced again rather than leaving a false pending/drift state.
	rejected, err := store.RejectAccessReplacement(ctx, pool, inventory.AccessReplacementTransition{
		BindingID: managed.ID, OperationID: operationID,
		FromPermissionID: templateA.ID, ToPermissionID: templateB.ID,
		AssignmentKey: assignmentSlot, ExpectedVersion: reserved.Version,
	})
	if err != nil {
		t.Fatalf("reject replacement after discovery observed A: %v", err)
	}
	if rejected.PermissionDefinitionID != templateA.ID || rejected.ObservedPermissionDefinitionID == nil ||
		*rejected.ObservedPermissionDefinitionID != templateA.ID || rejected.Status != inventory.BindingStatusSynced ||
		rejected.TransitionOperationID != nil || rejected.Version != reserved.Version+1 || !rejected.ObservedEffective {
		t.Fatalf("rejected binding = %+v, want desired/actual A synced with retired owner", rejected)
	}
}

func TestEnsureBindingCopiesAssignmentKeyAndRejectsOccupiedSlot(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	const identity = "exclusive-ensure"

	snap := assignmentSnapshot(identity, "template:a")
	snap.Bindings = nil
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("upsert catalog: %v", err)
	}
	account := accountID(ctx, t, pool, store, conn.ID, identity)
	permissions, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	templateA := assignmentPermissionByExternalID(t, permissions, "template:a")
	templateB := assignmentPermissionByExternalID(t, permissions, "template:b")

	created, fresh, err := store.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID: account, PermissionID: templateA.ID, DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure template A: %v", err)
	}
	if !fresh || created.AssignmentKey != assignmentSlot {
		t.Errorf("created binding = %+v fresh=%v, want assignment key/fresh", created, fresh)
	}
	if _, _, err := store.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID: account, PermissionID: templateB.ID, DesiredState: inventory.BindingPresent,
	}); !errors.Is(err, inventory.ErrAssignmentOccupied) {
		t.Errorf("ensure template B error = %v, want ErrAssignmentOccupied", err)
	}
	bindings, err := store.ListBindingsByAccount(ctx, pool, account)
	if err != nil || len(bindings) != 1 || bindings[0].ID != created.ID {
		t.Errorf("bindings after conflict = %+v, %v; want original row only", bindings, err)
	}

	// A later replacement operation will reuse this exact row and bump version;
	// foundation defaults remain stable until that state machine is added.
	if created.Version != 0 || created.TransitionOperationID != nil {
		t.Errorf("fresh binding transition fields = version %d operation %v, want zero/nil",
			created.Version, created.TransitionOperationID)
	}
}
