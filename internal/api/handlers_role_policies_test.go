package api

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

func TestRolePolicyCreateRequiresExplicitTargetIdentity(t *testing.T) {
	req := rolePolicyMutationRequest{RequestID: uuid.New(), Version: 1, ObservedFingerprint: "observed", Confirm: true}
	if err := req.validate(rolepolicies.ActionCreate); err == nil {
		t.Fatal("create accepted an unpinned target")
	}
	for _, action := range []rolepolicies.Action{rolepolicies.ActionApply, rolepolicies.ActionAdopt, rolepolicies.ActionRepair} {
		if err := req.validate(action); err != nil {
			t.Fatalf("legacy %s requires a create-only field: %v", action, err)
		}
	}
	for _, identity := range []string{"", "  ", "postgres:system:42"} {
		req.ExpectedTargetIdentity = patchField[string]{Set: true, Value: identity}
		if err := req.validate(rolepolicies.ActionCreate); (err == nil) != (identity == "postgres:system:42") {
			t.Fatalf("create target %q validation=%v", identity, err)
		}
		for _, action := range []rolepolicies.Action{rolepolicies.ActionApply, rolepolicies.ActionAdopt, rolepolicies.ActionRepair} {
			if err := req.validate(action); err == nil {
				t.Fatalf("%s accepted a provided create-only field", action)
			}
		}
	}
	for _, raw := range []string{`{"expected_target_identity":null}`, `{"expected_target_identity":42}`} {
		if err := json.Unmarshal([]byte(raw), &req); err == nil {
			t.Fatalf("invalid target type accepted: %s", raw)
		}
	}
}
