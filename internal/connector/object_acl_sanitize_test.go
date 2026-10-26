package connector_test

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

func TestObjectACLReadbackHasAClosedSanitizedShape(t *testing.T) {
	v := &adapter.Verification{Verified: true, Observed: map[string]any{"direct_privilege": true, "grantors": []adapter.PostgresACLGrantor{{OID: 13, Name: "owner"}}}}
	raw, err := connector.MarshalSanitizedResult(&adapter.Result{}, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector.ParseSanitizedResult(raw); err != nil {
		t.Fatal(err)
	}
	for _, observed := range []map[string]any{
		{"direct_privilege": true, "grantors": []any{}, "password": "canary"},
		{"direct_privilege": true, "grantors": []map[string]any{{"oid": 13, "name": "owner", "raw_sql": "arbitrary"}}},
		{"direct_privilege": true, "grantors": []adapter.PostgresACLGrantor{{OID: 13, Name: "owner", GrantOption: true}}},
	} {
		v.Observed = observed
		if _, err := connector.MarshalSanitizedResult(&adapter.Result{}, v); err == nil {
			t.Fatal("unknown or delegating readback accepted")
		}
	}
}
