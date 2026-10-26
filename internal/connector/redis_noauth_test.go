package connector_test

import (
	"encoding/json"
	"testing"

	"github.com/ArtefactoO/grantor/internal/connector"
)

func TestRedisNoAuthSignedDescriptorRequiresClosedContract(t *testing.T) {
	for _, tc := range []struct {
		engine, auth, candidate string
		kind                    connector.JobKind
		want, invalid           bool
	}{
		{"redis", "none", "", connector.JobDiscover, true, false},
		{"redis", "password", "none", connector.JobAdminCredentialSwitch, true, false},
		{"redis", "none", "password", connector.JobAdminCredentialSwitch, true, false},
		{"redis", "none", "", connector.JobApply, false, true},
		{"postgres", "none", "", connector.JobDiscover, false, true},
		{"redis", "password", "", connector.JobDiscover, false, false},
		{"redis", "unknown", "", connector.JobDiscover, false, true},
	} {
		raw, _ := json.Marshal(map[string]any{"connection": connector.ConnectionRef{ID: "c", Engine: tc.engine, AuthMode: tc.auth}, "candidate_auth_mode": tc.candidate})
		got, err := connector.JobUsesRedisNoAuth(connector.Job{Engine: tc.engine, Kind: tc.kind, Payload: raw})
		if got != tc.want || (err != nil) != tc.invalid {
			t.Fatalf("%+v => %v/%v", tc, got, err)
		}
	}
}
