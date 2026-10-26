package connections

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TargetIdentity returns a stable, non-secret identity proven by discovery.
// It is intentionally narrower than the whole topology: node lists and
// versions legitimately change, while RabbitMQ cluster_name, PostgreSQL
// system_identifier and the topology-specific MongoDB identifiers below
// identify the administrative target across endpoint/TLS recovery.
func TargetIdentity(connection Connection) string {
	if len(connection.Topology) == 0 {
		return ""
	}
	switch connection.Engine {
	case "rabbitmq":
		var topology struct {
			ClusterName string `json:"cluster_name"`
		}
		if err := json.Unmarshal(connection.Topology, &topology); err != nil {
			return ""
		}
		name := strings.TrimSpace(topology.ClusterName)
		if name == "" {
			return ""
		}
		return "rabbitmq:cluster:" + name
	case "postgres":
		// PostgreSQL system_identifier is uint64 and may exceed JavaScript's
		// exact integer range. Discovery writes it as a string, but accepting a
		// legacy JSON number here makes the metadata projection migration-safe.
		var topology map[string]json.RawMessage
		if err := json.Unmarshal(connection.Topology, &topology); err != nil {
			return ""
		}
		raw := topology["system_identifier"]
		if len(raw) == 0 {
			return ""
		}
		var identifier string
		if err := json.Unmarshal(raw, &identifier); err != nil {
			var number json.Number
			if err := json.Unmarshal(raw, &number); err != nil {
				return ""
			}
			identifier = fmt.Sprint(number)
		}
		identifier = strings.TrimSpace(identifier)
		if identifier == "" {
			return ""
		}
		return "postgres:system:" + identifier
	case "mongodb":
		var topology struct {
			Kind         string `json:"topology"`
			ReplicaSetID string `json:"replica_set_id"`
			ClusterID    string `json:"cluster_id"`
			ProcessID    string `json:"process_id"`
		}
		if err := json.Unmarshal(connection.Topology, &topology); err != nil {
			return ""
		}
		switch strings.TrimSpace(topology.Kind) {
		case "replica_set":
			if id := strings.TrimSpace(topology.ReplicaSetID); id != "" {
				return "mongodb:replica-set:" + id
			}
		case "sharded":
			if id := strings.TrimSpace(topology.ClusterID); id != "" {
				return "mongodb:sharded-cluster:" + id
			}
		case "standalone":
			if id := strings.TrimSpace(topology.ProcessID); id != "" {
				return "mongodb:standalone-process:" + id
			}
		}
		return ""
	default:
		return ""
	}
}
