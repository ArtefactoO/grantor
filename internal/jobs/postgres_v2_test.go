package jobs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

func TestPostgresV2WorkerVocabularyIsDistinctAndClosed(t *testing.T) {
	want := map[string]adapter.ChangeKind{
		KindPostgresAccountCreateV2:                  adapter.ChangePostgresAccountCreateV2,
		KindPostgresAccountRestoreV2:                 adapter.ChangePostgresAccountRestoreV2,
		KindPostgresRoleCreateV2:                     adapter.ChangePostgresRoleCreateV2,
		KindPostgresResourceCreateDatabaseV2:         adapter.ChangePostgresDatabaseCreateV2,
		KindPostgresResourceCreateDatabaseForRolesV2: adapter.ChangePostgresDatabaseCreateV2,
		KindPostgresRolePolicyApplyV2:                adapter.ChangePostgresRolePolicyApplyV2,
		KindPostgresRolePolicyAdoptV2:                adapter.ChangePostgresRolePolicyAdoptV2,
		KindPostgresRolePolicyRepairV2:               adapter.ChangePostgresRolePolicyRepairV2,
		KindPostgresRolePolicyCreateV2:               adapter.ChangePostgresRolePolicyCreateV2,
		KindPostgresRolePolicyCreateDatabaseV2:       adapter.ChangePostgresRolePolicyCreateDatabaseV2,
	}
	if len(postgresV2OperationChangeKind) != len(want) {
		t.Fatalf("v2 operation mapping has %d entries, want %d", len(postgresV2OperationChangeKind), len(want))
	}
	for operationKind, changeKind := range want {
		if !isPostgresV2OperationKind(operationKind) || postgresV2OperationChangeKind[operationKind] != changeKind {
			t.Fatalf("operation %q maps to %q, want %q", operationKind,
				postgresV2OperationChangeKind[operationKind], changeKind)
		}
	}
	if !isPostgresV2OperationKind(KindPostgresDatabaseCreateWithRolesV2) {
		t.Fatal("versioned database-with-roles root is outside the worker vocabulary")
	}
	for _, legacy := range []string{
		KindAccountCreate, KindAccountRestore, KindRoleCreate,
		KindResourceCreateDatabase, KindDatabaseCreateWithRoles,
		KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair,
		KindRolePolicyCreate, KindRolePolicyCreateDatabase,
	} {
		if isPostgresV2OperationKind(legacy) {
			t.Fatalf("legacy operation kind %q collided with v2", legacy)
		}
	}
}

func TestPostgresV2OperationsReachTheirRegisteredExecutors(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	for _, kind := range []string{
		KindPostgresAccountCreateV2, KindPostgresAccountRestoreV2,
		KindPostgresRoleCreateV2, KindPostgresResourceCreateDatabaseV2,
		KindPostgresDatabaseCreateWithRolesV2,
		KindPostgresResourceCreateDatabaseForRolesV2,
		KindPostgresRolePolicyApplyV2, KindPostgresRolePolicyAdoptV2,
		KindPostgresRolePolicyRepairV2, KindPostgresRolePolicyCreateV2,
		KindPostgresRolePolicyCreateDatabaseV2,
	} {
		t.Run(kind, func(t *testing.T) {
			err := e.Execute(t.Context(), operations.Operation{ID: uuid.New(), Kind: kind})
			if err == nil || strings.Contains(err.Error(), "disabled") {
				t.Fatalf("Execute(%q) = %v; v2 kind did not reach its executor", kind, err)
			}
		})
	}
}

func TestLegacyPostgresPolicyAndRootAreTerminalHistoryOnly(t *testing.T) {
	e := NewMainExecutor(DiscoveryDeps{})
	payload, err := json.Marshal(RolePolicyPayload{Spec: adapter.RolePolicySpec{Engine: "postgres"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{
		KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair,
		KindRolePolicyCreate, KindRolePolicyCreateDatabase,
		KindResourceCreatePreparedDatabase, KindDatabaseCreateWithRoles,
	} {
		t.Run(kind, func(t *testing.T) {
			err := e.Execute(t.Context(), operations.Operation{ID: uuid.New(), Kind: kind, Payload: payload})
			if err == nil || !isTerminal(err) || !strings.Contains(err.Error(), "history-only") {
				t.Fatalf("legacy Execute(%q) = %v, terminal=%v", kind, err, isTerminal(err))
			}
		})
	}

	for kind, action := range map[string]rolepolicies.Action{
		KindRolePolicyApply:                    rolepolicies.ActionApply,
		KindRolePolicyAdopt:                    rolepolicies.ActionAdopt,
		KindRolePolicyRepair:                   rolepolicies.ActionRepair,
		KindRolePolicyCreate:                   rolepolicies.ActionCreate,
		KindRolePolicyCreateDatabase:           rolepolicies.ActionCreate,
		KindPostgresRolePolicyApplyV2:          rolepolicies.ActionApply,
		KindPostgresRolePolicyAdoptV2:          rolepolicies.ActionAdopt,
		KindPostgresRolePolicyRepairV2:         rolepolicies.ActionRepair,
		KindPostgresRolePolicyCreateV2:         rolepolicies.ActionCreate,
		KindPostgresRolePolicyCreateDatabaseV2: rolepolicies.ActionCreate,
	} {
		if got := rolePolicyTransitionActionForKind(kind); got != action {
			t.Fatalf("transition action for %q = %q, want %q", kind, got, action)
		}
	}
}
