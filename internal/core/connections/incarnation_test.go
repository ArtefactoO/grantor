package connections

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConfigIncarnationCanonicalAndScoped(t *testing.T) {
	base := Connection{
		ID: uuid.New(), Engine: "postgres", Endpoints: []string{"db:5432"},
		ExecutionMode: "connector", TLSConfig: json.RawMessage(`{"mode":"verify-full","ca_cert_pem":"ca"}`),
		DiscoveryConfig:     json.RawMessage(`{"database":"postgres","future":{"b":2,"a":1}}`),
		AdminCredentialMode: "provided", VaultAdminPath: "connections/c/admin",
	}
	want := ConfigIncarnation(base)
	reordered := base
	reordered.TLSConfig = json.RawMessage(`{"ca_cert_pem":"ca","mode":"verify-full"}`)
	reordered.DiscoveryConfig = json.RawMessage(`{"future":{"a":1,"b":2},"database":"postgres"}`)
	if got := ConfigIncarnation(reordered); got != want {
		t.Fatalf("JSON key order changed incarnation: %s != %s", got, want)
	}

	for name, mutate := range map[string]func(*Connection){
		"id":              func(c *Connection) { c.ID = uuid.New() },
		"engine":          func(c *Connection) { c.Engine = "mysql" },
		"endpoints":       func(c *Connection) { c.Endpoints = []string{"other:5432"} },
		"execution mode":  func(c *Connection) { c.ExecutionMode = "direct" },
		"tls":             func(c *Connection) { c.TLSConfig = json.RawMessage(`{"mode":"disabled"}`) },
		"discovery":       func(c *Connection) { c.DiscoveryConfig = json.RawMessage(`{"database":"other"}`) },
		"credential mode": func(c *Connection) { c.AdminCredentialMode = "existing_vault_ref" },
		"vault path":      func(c *Connection) { c.VaultAdminPath = "connections/other/admin" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			if got := ConfigIncarnation(changed); got == want {
				t.Fatalf("mutation did not change incarnation: %s", got)
			}
		})
	}

	nonTarget := base
	nonTarget.DisplayName = "renamed"
	nonTarget.Environment = "prod"
	nonTarget.Status = StatusActive
	nonTarget.Capabilities = []string{"future"}
	nonTarget.Topology = json.RawMessage(`{"changed":true}`)
	nonTarget.UpdatedAt = time.Now()
	if got := ConfigIncarnation(nonTarget); got != want {
		t.Fatalf("presentation/runtime metadata changed incarnation: %s != %s", got, want)
	}
}
