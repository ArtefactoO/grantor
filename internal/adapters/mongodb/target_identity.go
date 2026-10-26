package mongodb

import (
	"context"
	"errors"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// MongoDB does not expose one portable cluster identifier for every
// topology. The policy lifecycle therefore accepts only the documented,
// topology-specific proofs below and fails closed when the administrative
// account cannot read them:
//   - replica set: immutable settings.replicaSetId from replSetGetConfig;
//   - sharded cluster: clusterId from the config.version document;
//   - standalone: topologyVersion.processId from hello (restart-scoped).
//
// config.version and topologyVersion are server-internal interfaces and Atlas
// does not support updateRole. An unavailable/unknown proof never falls back
// to setName, hosts or an endpoint: CapRolePolicyApply remains disabled.
const (
	mongoIdentityReplicaSetPrefix = "mongodb:replica-set:"
	mongoIdentityShardedPrefix    = "mongodb:sharded-cluster:"
	mongoIdentityStandalonePrefix = "mongodb:standalone-process:"
)

func discoverMongoTargetIdentity(
	ctx context.Context,
	client *mongo.Client,
	hello bson.M,
) (string, map[string]any, error) {
	topology := topologyFromHello(hello)
	kind, _ := topology["topology"].(string)
	switch kind {
	case "replica_set":
		id, err := replicaSetID(ctx, client)
		if err != nil {
			return "", topology, err
		}
		topology["replica_set_id"] = id
		return mongoIdentityReplicaSetPrefix + id, topology, nil
	case "sharded":
		id, err := shardedClusterID(ctx, client)
		if err != nil {
			return "", topology, err
		}
		topology["cluster_id"] = id
		return mongoIdentityShardedPrefix + id, topology, nil
	case "standalone":
		id := standaloneProcessID(hello)
		if id == "" {
			return "", topology, errors.New("standalone topologyVersion.processId is unavailable")
		}
		topology["process_id"] = id
		return mongoIdentityStandalonePrefix + id, topology, nil
	default:
		return "", topology, fmt.Errorf("unsupported topology %q", kind)
	}
}

func replicaSetID(ctx context.Context, client *mongo.Client) (string, error) {
	var result bson.M
	if err := client.Database(adminDatabase).RunCommand(ctx,
		bson.D{{Key: "replSetGetConfig", Value: 1}}).Decode(&result); err != nil {
		return "", fmt.Errorf("read replica set identity: %w", err)
	}
	config, ok := documentField(result, "config")
	if !ok {
		return "", errors.New("read replica set identity: config is absent")
	}
	settings, ok := documentField(config, "settings")
	if !ok {
		return "", errors.New("read replica set identity: settings are absent")
	}
	id := stableObjectID(settings["replicaSetId"])
	if id == "" {
		return "", errors.New("read replica set identity: replicaSetId is absent")
	}
	return id, nil
}

func shardedClusterID(ctx context.Context, client *mongo.Client) (string, error) {
	var version bson.M
	if err := client.Database("config").Collection("version").
		FindOne(ctx, bson.D{}).Decode(&version); err != nil {
		return "", fmt.Errorf("read sharded cluster identity: %w", err)
	}
	id := stableObjectID(version["clusterId"])
	if id == "" {
		return "", errors.New("read sharded cluster identity: clusterId is absent")
	}
	return id, nil
}

func standaloneProcessID(hello bson.M) string {
	topologyVersion, ok := documentField(hello, "topologyVersion")
	if !ok {
		return ""
	}
	return stableObjectID(topologyVersion["processId"])
}

func documentField(document bson.M, key string) (bson.M, bool) {
	switch value := document[key].(type) {
	case bson.M:
		return value, true
	case bson.D:
		out := make(bson.M, len(value))
		for _, element := range value {
			out[element.Key] = element.Value
		}
		return out, true
	case map[string]any:
		return bson.M(value), true
	default:
		return nil, false
	}
}

func stableObjectID(value any) string {
	switch id := value.(type) {
	case primitive.ObjectID:
		if id.IsZero() {
			return ""
		}
		return id.Hex()
	case string:
		parsed, err := primitive.ObjectIDFromHex(id)
		if err != nil || parsed.IsZero() {
			return ""
		}
		return parsed.Hex()
	default:
		return ""
	}
}

func requireMongoTargetIdentity(
	ctx context.Context,
	client *mongo.Client,
	expected string,
) error {
	if expected == "" {
		return fmt.Errorf("mongodb: expected target identity is empty: %w", adapter.ErrTargetIdentityConflict)
	}
	hello, err := runHello(ctx, client)
	if err != nil {
		return fmt.Errorf("mongodb: prove target identity: %w", err)
	}
	writablePrimary, _ := hello["isWritablePrimary"].(bool)
	if !writablePrimary {
		return fmt.Errorf("mongodb: target is not writable primary: %w", adapter.ErrUnsupportedChange)
	}
	actual, _, err := discoverMongoTargetIdentity(ctx, client, hello)
	if err != nil {
		return fmt.Errorf("mongodb: prove target identity: %w: %w", err, adapter.ErrTargetIdentityConflict)
	}
	if actual != expected {
		return fmt.Errorf("mongodb: target identity changed from %q to %q: %w",
			expected, actual, adapter.ErrTargetIdentityConflict)
	}
	return nil
}
