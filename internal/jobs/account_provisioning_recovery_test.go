package jobs

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func TestProvisioningRecoveryPayloadIsExplicitAndFenced(t *testing.T) {
	accountID, connectionID, sourceID := uuid.New(), uuid.New(), uuid.New()
	op := operations.Operation{Kind: KindConnectionDiscover, AccountID: &accountID, ConnectionID: &connectionID}
	for _, raw := range []string{"", `{}`, `{"refresh":true}`} {
		op.Payload = []byte(raw)
		payload, err := parseProvisioningRecoveryPayload(op)
		if err != nil || payload != nil {
			t.Fatalf("ordinary discovery %q interpreted as recovery: %v, %v", raw, payload, err)
		}
	}
	op.Kind = KindAccountRecoverProvisioning
	for _, raw := range []string{"", `{}`, `null`, `{"refresh":true}`} {
		op.Payload = []byte(raw)
		if _, err := parseProvisioningRecoveryPayload(op); err == nil || !isTerminal(err) {
			t.Fatalf("recovery with no pinned payload %q must fail terminal: %v", raw, err)
		}
	}
	valid := map[string]any{
		"recovered_account_id": accountID, "source_operation_id": sourceID, "expected_lifecycle_version": 3,
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"valid", func(map[string]any) {}},
		{"missing account", func(p map[string]any) { delete(p, "recovered_account_id") }},
		{"mismatched account", func(p map[string]any) { p["recovered_account_id"] = uuid.New() }},
		{"missing source", func(p map[string]any) { delete(p, "source_operation_id") }},
		{"missing version", func(p map[string]any) { delete(p, "expected_lifecycle_version") }},
		{"null version", func(p map[string]any) { p["expected_lifecycle_version"] = nil }},
		{"negative version", func(p map[string]any) { p["expected_lifecycle_version"] = -1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := make(map[string]any, len(valid))
			for key, value := range valid {
				fields[key] = value
			}
			tc.mutate(fields)
			var err error
			op.Payload, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := parseProvisioningRecoveryPayload(op)
			if tc.name == "valid" {
				if err != nil || payload == nil || payload.ExpectedLifecycleVersion != 3 {
					t.Fatalf("valid recovery payload = %v, %v", payload, err)
				}
			} else if err == nil || !isTerminal(err) {
				t.Fatalf("invalid recovery payload must be terminal: %v", err)
			}
		})
	}
}
