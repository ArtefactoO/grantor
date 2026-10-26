package connections

import (
	"encoding/json"
	"testing"
)

func TestTargetIdentityUsesStableRabbitMQClusterName(t *testing.T) {
	first := Connection{Engine: "rabbitmq", Topology: json.RawMessage(`{
		"cluster_name":"rabbit@prod","nodes":["rabbit@a"],"node_count":1
	}`)}
	changedNodes := Connection{Engine: "rabbitmq", Topology: json.RawMessage(`{
		"cluster_name":"rabbit@prod","nodes":["rabbit@b","rabbit@c"],"node_count":2
	}`)}
	other := Connection{Engine: "rabbitmq", Topology: json.RawMessage(`{"cluster_name":"rabbit@other"}`)}
	if got := TargetIdentity(first); got != "rabbitmq:cluster:rabbit@prod" {
		t.Fatalf("TargetIdentity(first) = %q", got)
	}
	if TargetIdentity(changedNodes) != TargetIdentity(first) {
		t.Fatal("node churn changed stable RabbitMQ target identity")
	}
	if TargetIdentity(other) == TargetIdentity(first) {
		t.Fatal("different RabbitMQ cluster_name has the same target identity")
	}
	if got := TargetIdentity(Connection{Engine: "postgres", Topology: first.Topology}); got != "" {
		t.Fatalf("Postgres without system identifier = %q, want empty", got)
	}
}

func TestTargetIdentityUsesPostgresSystemIdentifier(t *testing.T) {
	first := Connection{Engine: "postgres", Topology: json.RawMessage(`{
		"system_identifier":"7429012345678901234","in_recovery":false
	}`)}
	recoveredEndpoint := Connection{Engine: "postgres", Topology: json.RawMessage(`{
		"system_identifier":"7429012345678901234","in_recovery":false,"nodes":["new"]
	}`)}
	other := Connection{Engine: "postgres", Topology: json.RawMessage(`{
		"system_identifier":"7429012345678909999"
	}`)}
	if got := TargetIdentity(first); got != "postgres:system:7429012345678901234" {
		t.Fatalf("TargetIdentity(first) = %q", got)
	}
	if TargetIdentity(recoveredEndpoint) != TargetIdentity(first) {
		t.Fatal("endpoint/topology recovery changed PostgreSQL target identity")
	}
	if TargetIdentity(other) == TargetIdentity(first) {
		t.Fatal("different PostgreSQL system_identifier has the same target identity")
	}
	legacyNumber := Connection{Engine: "postgres", Topology: json.RawMessage(`{
		"system_identifier":7429012345678901234
	}`)}
	if TargetIdentity(legacyNumber) != TargetIdentity(first) {
		t.Fatalf("numeric legacy target identity = %q, want %q",
			TargetIdentity(legacyNumber), TargetIdentity(first))
	}
}

func TestTargetIdentityUsesTopologySpecificMongoDBIdentity(t *testing.T) {
	tests := []struct {
		name     string
		topology string
		want     string
	}{
		{
			name: "replica set",
			topology: `{"topology":"replica_set","replica_set_id":"65f15f1276d3f744be6c0711",` +
				`"set_name":"rs0","hosts":["mongo-1:27017"]}`,
			want: "mongodb:replica-set:65f15f1276d3f744be6c0711",
		},
		{
			name:     "sharded cluster",
			topology: `{"topology":"sharded","cluster_id":"65f15f1276d3f744be6c0712"}`,
			want:     "mongodb:sharded-cluster:65f15f1276d3f744be6c0712",
		},
		{
			name:     "standalone process",
			topology: `{"topology":"standalone","process_id":"65f15f1276d3f744be6c0713"}`,
			want:     "mongodb:standalone-process:65f15f1276d3f744be6c0713",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := Connection{Engine: "mongodb", Topology: []byte(tt.topology)}
			if got := TargetIdentity(conn); got != tt.want {
				t.Fatalf("TargetIdentity = %q, want %q", got, tt.want)
			}
		})
	}

	for _, topology := range []string{
		`{"topology":"replica_set","set_name":"rs0"}`,
		`{"topology":"sharded","process_id":"node-not-cluster"}`,
		`{"topology":"standalone","cluster_id":"cluster-not-process"}`,
		`{"topology":"unknown","process_id":"65f15f1276d3f744be6c0713"}`,
	} {
		if got := TargetIdentity(Connection{Engine: "mongodb", Topology: []byte(topology)}); got != "" {
			t.Errorf("TargetIdentity(%s) = %q, want empty", topology, got)
		}
	}

	first := Connection{Engine: "mongodb", Topology: json.RawMessage(
		`{"topology":"replica_set","replica_set_id":"65f15f1276d3f744be6c0711",` +
			`"hosts":["mongo-1:27017"]}`)}
	changedMembers := Connection{Engine: "mongodb", Topology: json.RawMessage(
		`{"topology":"replica_set","replica_set_id":"65f15f1276d3f744be6c0711",` +
			`"hosts":["mongo-2:27017","mongo-3:27017"]}`)}
	other := Connection{Engine: "mongodb", Topology: json.RawMessage(
		`{"topology":"replica_set","replica_set_id":"65f15f1276d3f744be6c0799"}`)}
	if TargetIdentity(first) != TargetIdentity(changedMembers) {
		t.Fatal("replica-set member churn changed stable MongoDB target identity")
	}
	if TargetIdentity(first) == TargetIdentity(other) {
		t.Fatal("different MongoDB replicaSetId has the same target identity")
	}
}
