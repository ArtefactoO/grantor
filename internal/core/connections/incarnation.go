package connections

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// ConfigIncarnation fingerprints only the immutable target/admin routing
// projection proved by discovery. Status, topology, capabilities and display
// metadata are excluded because discovery itself updates them.
func ConfigIncarnation(c Connection) string {
	payload := struct {
		ID                  string   `json:"id"`
		Engine              string   `json:"engine"`
		AuthMode            string   `json:"auth_mode,omitempty"`
		Endpoints           []string `json:"endpoints"`
		ExecutionMode       string   `json:"execution_mode"`
		TLSConfig           any      `json:"tls_config"`
		DiscoveryConfig     any      `json:"discovery_config"`
		AdminCredentialMode string   `json:"admin_credential_mode"`
		VaultAdminPath      string   `json:"vault_admin_path"`
	}{
		ID: c.ID.String(), Engine: c.Engine, AuthMode: authModeIncarnation(c.AuthMode), Endpoints: c.Endpoints,
		ExecutionMode: c.ExecutionMode, TLSConfig: canonicalIncarnationJSON(c.TLSConfig),
		DiscoveryConfig:     canonicalIncarnationJSON(c.DiscoveryConfig),
		AdminCredentialMode: c.AdminCredentialMode, VaultAdminPath: c.VaultAdminPath,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err) // fixed struct + JSON-compatible canonical values
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func canonicalIncarnationJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return map[string]any{}
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		// AdapterConfig rejects malformed JSON before any operation; retaining
		// the exact bytes here keeps the fingerprint deterministic meanwhile.
		return string(raw)
	}
	return value
}

func authModeIncarnation(mode string) string {
	if mode == "none" {
		return mode
	}
	return ""
}
