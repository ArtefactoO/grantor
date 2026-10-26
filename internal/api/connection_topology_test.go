package api

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/connections"
)

func TestConnectionTopologyRedactsLegacyHBASnapshots(t *testing.T) {
	rules := json.RawMessage(`[{"number":1,"type":"host","databases":["app"],"users":["alice"],"auth_method":"ldap","options":["ldapbindpasswd=fixture-sensitive-value"],"error":"invalid fixture-sensitive-value"}]`)
	raw, _ := json.Marshal(map[string]any{"system_identifier": "42", "postgres_object_acl_version": 1, "hba_rules": rules, "postgres_default_privileges": []any{}, "postgres_access_evidence": map[string]any{"version": 1, "endpoints": []any{map[string]any{"endpoint": "db:5432", "available": true, "rules": rules}}}})
	before := bytes.Clone(raw)
	out := connectionResponseTopology(connections.Connection{Engine: "postgres", Topology: raw})
	if bytes.Contains(out, []byte("fixture-sensitive-value")) || !bytes.Contains(out, []byte("configured")) || !bytes.Contains(out, []byte("invalid_hba_rule")) {
		t.Fatalf("legacy HBA response was not sanitized: %s", out)
	}
	if bytes.Contains(out, []byte(`"postgres_access_evidence"`)) {
		t.Fatal("internal evidence catalog escaped connection response")
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("read projection mutated stored topology")
	}
	compact := compactPostgresTopology(out)
	for _, key := range []string{"hba_rules", "postgres_default_privileges", "postgres_access_evidence"} {
		if bytes.Contains(compact, []byte(`"`+key+`"`)) {
			t.Fatalf("heavy %s escaped summary", key)
		}
	}
	if !bytes.Contains(compact, []byte(`"postgres_object_acl_version":1`)) || !bytes.Contains(compact, []byte(`"system_identifier":"42"`)) {
		t.Fatal("summary lost authority/inventory markers")
	}
}
