package api

import (
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func managedPresentBinding(accountID, permissionID uuid.UUID, assignmentKey string) inventory.Binding {
	desired := inventory.BindingPresent
	return inventory.Binding{
		ID: uuid.New(), AccountID: accountID, PermissionDefinitionID: permissionID,
		AssignmentKey: assignmentKey, DesiredState: &desired,
	}
}

func TestPartitionAccountRoleChangesCanonicalizesExplicitReplacement(t *testing.T) {
	accountID := uuid.New()
	fromPermission := inventory.Permission{ID: uuid.New(), AssignmentKey: "rabbitmq:vhost:etl"}
	toPermission := inventory.Permission{ID: uuid.New(), AssignmentKey: fromPermission.AssignmentKey}
	fromBinding := managedPresentBinding(accountID, fromPermission.ID, fromPermission.AssignmentKey)
	account := inventory.Account{ID: accountID}

	adds, removes, replacements, err := partitionAccountRoleChanges(
		[]inventory.Binding{fromBinding},
		[]grantTarget{{account: account, permission: toPermission}},
		[]accountRoleRemoval{{binding: fromBinding, permission: fromPermission}},
	)
	if err != nil {
		t.Fatalf("partitionAccountRoleChanges: %v", err)
	}
	if len(adds) != 0 || len(removes) != 0 || len(replacements) != 1 {
		t.Fatalf("partition = %d adds, %d removes, %d replacements", len(adds), len(removes), len(replacements))
	}
	if replacements[0].from.binding.ID != fromBinding.ID ||
		replacements[0].to.permission.ID != toPermission.ID {
		t.Fatalf("replacement = %+v, want binding %s -> permission %s",
			replacements[0], fromBinding.ID, toPermission.ID)
	}
}

func TestPartitionAccountRoleChangesRejectsImplicitAndAmbiguousReplacement(t *testing.T) {
	accountID := uuid.New()
	assignmentKey := "rabbitmq:vhost:etl"
	fromPermission := inventory.Permission{ID: uuid.New(), AssignmentKey: assignmentKey}
	toPermission := inventory.Permission{ID: uuid.New(), AssignmentKey: assignmentKey}
	otherPermission := inventory.Permission{ID: uuid.New(), AssignmentKey: assignmentKey}
	fromBinding := managedPresentBinding(accountID, fromPermission.ID, assignmentKey)
	account := inventory.Account{ID: accountID}

	if _, _, _, err := partitionAccountRoleChanges(
		[]inventory.Binding{fromBinding},
		[]grantTarget{{account: account, permission: toPermission}}, nil,
	); err == nil {
		t.Fatal("implicit replacement: err = nil")
	}
	if _, _, _, err := partitionAccountRoleChanges(
		[]inventory.Binding{fromBinding},
		[]grantTarget{
			{account: account, permission: toPermission},
			{account: account, permission: otherPermission},
		},
		[]accountRoleRemoval{{binding: fromBinding, permission: fromPermission}},
	); err == nil {
		t.Fatal("ambiguous replacement: err = nil")
	}
}

func TestPartitionAccountRoleChangesKeepsReplacementInputOrderAcrossSlots(t *testing.T) {
	accountID := uuid.New()
	account := inventory.Account{ID: accountID}
	firstKey := "rabbitmq:vhost:first"
	secondKey := "rabbitmq:vhost:second"
	firstFrom := inventory.Permission{ID: uuid.New(), AssignmentKey: firstKey}
	firstTo := inventory.Permission{ID: uuid.New(), AssignmentKey: firstKey}
	secondFrom := inventory.Permission{ID: uuid.New(), AssignmentKey: secondKey}
	secondTo := inventory.Permission{ID: uuid.New(), AssignmentKey: secondKey}
	firstBinding := managedPresentBinding(accountID, firstFrom.ID, firstKey)
	secondBinding := managedPresentBinding(accountID, secondFrom.ID, secondKey)

	// Current inventory and removals deliberately use the opposite order. The
	// output must follow the caller's additions order so child operation order
	// is deterministic and does not depend on map iteration or DB row order.
	adds, removes, replacements, err := partitionAccountRoleChanges(
		[]inventory.Binding{firstBinding, secondBinding},
		[]grantTarget{
			{account: account, permission: secondTo},
			{account: account, permission: firstTo},
		},
		[]accountRoleRemoval{
			{binding: firstBinding, permission: firstFrom},
			{binding: secondBinding, permission: secondFrom},
		},
	)
	if err != nil {
		t.Fatalf("partitionAccountRoleChanges: %v", err)
	}
	if len(adds) != 0 || len(removes) != 0 || len(replacements) != 2 {
		t.Fatalf("partition = %d adds, %d removes, %d replacements", len(adds), len(removes), len(replacements))
	}
	if replacements[0].from.binding.ID != secondBinding.ID ||
		replacements[0].to.permission.ID != secondTo.ID ||
		replacements[1].from.binding.ID != firstBinding.ID ||
		replacements[1].to.permission.ID != firstTo.ID {
		t.Fatalf("replacement order = [%s -> %s, %s -> %s], want second slot then first slot",
			replacements[0].from.binding.ID, replacements[0].to.permission.ID,
			replacements[1].from.binding.ID, replacements[1].to.permission.ID)
	}
}
