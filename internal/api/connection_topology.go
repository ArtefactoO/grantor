package api

import (
	"encoding/json"

	"github.com/ArtefactoO/grantor/internal/core/connections"
)

// Old snapshots can predate HBA redaction. Sanitize the response as well as
// discovery so an upgrade cannot expose stored authentication options.
func connectionResponseTopology(c connections.Connection) json.RawMessage {
	raw := rawOrEmptyObject(c.Topology)
	if c.Engine != "postgres" {
		return raw
	}
	var topology map[string]json.RawMessage
	if json.Unmarshal(raw, &topology) != nil || topology == nil {
		return json.RawMessage(`{}`)
	}
	if rules, exists := topology["hba_rules"]; exists {
		if safe, ok := safeTopologyHBARules(rules); ok {
			topology["hba_rules"] = safe
		} else {
			delete(topology, "hba_rules")
		}
	}
	// The large evidence catalog is internal; diagnostics returns a bounded projection.
	delete(topology, "postgres_access_evidence")
	out, err := json.Marshal(topology)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}

func safeTopologyHBARules(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	wrapper, err := json.Marshal(map[string]json.RawMessage{"hba_rules": raw})
	if err != nil {
		return nil, false
	}
	rules, _, supported := hbaRulesFromTopology(wrapper)
	if !supported {
		return nil, false
	}
	out, err := json.Marshal(rules)
	return out, err == nil
}
