package mongodb

import (
	"encoding/json"
	"slices"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func decodeObservedResource(t *testing.T, document bson.D) (roleResource, error) {
	t.Helper()
	raw, err := bson.Marshal(document)
	if err != nil {
		t.Fatalf("bson.Marshal resource: %v", err)
	}
	var resource roleResource
	err = bson.Unmarshal(raw, &resource)
	return resource, err
}

func TestMongo83ClusterMonitorBucketResourceIsObservedAndAssignable(t *testing.T) {
	// MongoDB r8.3.8 builtin_roles.yml gives clusterMonitor these five actions
	// on any_system_buckets. privilege.cpp serializes that resource without db.
	raw, err := bson.Marshal(bson.D{
		{Key: "role", Value: "clusterMonitor"}, {Key: "db", Value: "admin"}, {Key: "isBuiltin", Value: true},
		{Key: "privileges", Value: bson.A{
			bson.D{{Key: "resource", Value: bson.D{{Key: "system_buckets", Value: ""}}},
				{Key: "actions", Value: bson.A{"collStats", "dbStats", "getDatabaseVersion", "getShardVersion", "indexStats"}}},
			bson.D{{Key: "resource", Value: bson.D{{Key: "cluster", Value: true}}},
				{Key: "actions", Value: bson.A{"serverStatus"}}},
		}},
	})
	if err != nil {
		t.Fatalf("bson.Marshal role: %v", err)
	}
	var role customRole
	if err := bson.Unmarshal(raw, &role); err != nil {
		t.Fatalf("bson.Unmarshal role: %v", err)
	}
	role.ObservationComplete = true
	role = normalizeObservedRole(role)
	if roleHasUnsupportedResource(role) || unsupportedResourceCount(role) != 0 {
		t.Fatal("exact MongoDB 8.3 bucket resource must be understood")
	}
	permission := buildPermissions([]customRole{role}, nil, map[string]bool{"admin": true})[0]
	if !permission.Assignable || !permission.Dangerous || permission.ExternalID != "role:admin.clusterMonitor" {
		t.Fatalf("complete clusterMonitor permission = %+v", permission)
	}
	role.ObservationComplete = false
	if permission := buildPermissions([]customRole{role}, nil, map[string]bool{"admin": true})[0]; permission.Assignable {
		t.Fatal("recognizing buckets must not bypass observation completeness")
	}
}

func TestObservedSystemBucketResourceKeepsEmptySuffixPresence(t *testing.T) {
	for _, document := range []bson.D{
		{{Key: "system_buckets", Value: ""}},
		{{Key: "db", Value: "appdb"}, {Key: "system_buckets", Value: ""}},
	} {
		resource, err := decodeObservedResource(t, document)
		if err != nil || resource.SystemBuckets == nil || *resource.SystemBuckets != "" || !validObservedRoleResource(resource) {
			t.Fatalf("supported bucket shape %v decoded as %+v: %v", document, resource, err)
		}
	}
	normal, err := decodeObservedResource(t, bson.D{{Key: "db", Value: ""}, {Key: "collection", Value: ""}})
	if err != nil || normal.hasSystemBuckets() {
		t.Fatal("normal resource must retain an absent bucket suffix")
	}
	if _, err := decodeObservedResource(t, bson.D{{Key: "system_buckets", Value: nil}}); err == nil {
		t.Fatal("null bucket field must not collapse to absent or empty string")
	}
}

func TestObservedSystemBucketsRequireRawBSONStrings(t *testing.T) {
	// Symbol and Binary are accepted by the driver's generic string codec;
	// accepting them here would alias a different BSON value to an empty suffix.
	for _, value := range []any{
		primitive.Symbol(""),
		primitive.Binary{Subtype: 0, Data: []byte{}},
		primitive.Binary{Subtype: 2, Data: []byte{}},
		primitive.NilObjectID,
	} {
		if _, err := decodeObservedResource(t, bson.D{{Key: "system_buckets", Value: value}}); err == nil {
			t.Fatalf("non-string bucket suffix type %T was accepted", value)
		}
	}
	for _, value := range []any{
		primitive.Symbol("appdb"),
		primitive.Binary{Subtype: 0, Data: []byte("appdb")},
		primitive.Binary{Subtype: 2, Data: []byte("appdb")},
		primitive.NilObjectID,
	} {
		if _, err := decodeObservedResource(t, bson.D{{Key: "db", Value: value}, {Key: "system_buckets", Value: ""}}); err == nil {
			t.Fatalf("non-string bucket database type %T was accepted", value)
		}
	}
}

func TestObservedSystemBucketMixedUnknownAndInvalidTypesFailClosed(t *testing.T) {
	for _, document := range []bson.D{
		{{Key: "system_buckets", Value: ""}, {Key: "collection", Value: ""}},
		{{Key: "system_buckets", Value: ""}, {Key: "cluster", Value: false}},
		{{Key: "system_buckets", Value: ""}, {Key: "cluster", Value: true}},
		{{Key: "system_buckets", Value: ""}, {Key: "anyResource", Value: false}},
		{{Key: "system_buckets", Value: ""}, {Key: "anyResource", Value: true}},
		{{Key: "system_buckets", Value: ""}, {Key: "futureResource", Value: true}},
		{{Key: "system_buckets", Value: ""}, {Key: "db", Value: ""}},
		{{Key: "system_buckets", Value: ""}, {Key: "db", Value: nil}},
		{{Key: "system_buckets", Value: ""}, {Key: "db", Value: true}},
		{{Key: "system_buckets", Value: 1}},
		{{Key: "system_buckets", Value: bson.A{}}},
		{{Key: "system_buckets", Value: "specific_suffix"}},
		{{Key: "system_buckets", Value: ""}, {Key: "system_buckets", Value: ""}},
	} {
		resource, err := decodeObservedResource(t, document)
		if err != nil {
			continue // A decode error prevents a complete role observation.
		}
		role := customRole{Role: "clusterMonitor", DB: "admin", IsBuiltin: true, ObservationComplete: true,
			DirectPrivileges: []rolePrivilege{{Resource: resource, Actions: []string{"collStats"}}}}
		permission := buildPermissions([]customRole{role}, nil, map[string]bool{"admin": true})[0]
		if validObservedRoleResource(resource) || permission.Assignable {
			t.Fatalf("invalid shape %v became assignable: %+v", document, permission)
		}
	}
}

func TestBucketFingerprintsNeverCollideWithNormalOrInvalidScopes(t *testing.T) {
	documents := []bson.D{
		{{Key: "system_buckets", Value: ""}},
		{{Key: "db", Value: "appdb"}, {Key: "system_buckets", Value: ""}},
		{{Key: "db", Value: ""}, {Key: "collection", Value: ""}},
		{{Key: "db", Value: "appdb"}, {Key: "collection", Value: ""}},
		{{Key: "db", Value: "appdb"}, {Key: "collection", Value: "system.buckets.events"}},
		{{Key: "system_buckets", Value: ""}, {Key: "collection", Value: ""}},
		{{Key: "system_buckets", Value: ""}, {Key: "db", Value: ""}},
	}
	keys, fingerprints := map[string]bool{}, map[string]bool{}
	var privileges []rolePrivilege
	for _, document := range documents {
		resource, err := decodeObservedResource(t, document)
		if err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		key := observedResourceKey(resource)
		if keys[key] {
			t.Fatalf("resource normalization collision for %v", document)
		}
		keys[key] = true
		state := newMongoRolePolicyState(testMongoRolePolicyTemplate())
		addObservedPrivilegeTokens(state, state.actual, rolePrivilege{Resource: resource, Actions: []string{"collStats"}}, true)
		fingerprint := policyFingerprint(state.actual)
		if fingerprints[fingerprint] {
			t.Fatalf("effective privilege collision for %v", document)
		}
		fingerprints[fingerprint] = true
		privileges = append(privileges, rolePrivilege{Resource: resource, Actions: []string{"collStats"}})
	}
	if normalized := normalizeObservedPrivileges(privileges); len(normalized) != len(documents) {
		t.Fatalf("normalization merged distinct scopes: %d resources", len(normalized))
	}
	legacy := roleResource{DB: "appdb", Collection: "events"}
	if got := observedResourceKey(legacy); got != `any=false|cluster=false|db="appdb"|collection="events"|unknown=[]` {
		t.Fatalf("legacy observation key changed: %q", got)
	}
}

func TestBucketsRemainObservationOnlyAndDoNotAuthorizeRoleManagement(t *testing.T) {
	resource, err := decodeObservedResource(t, bson.D{{Key: "system_buckets", Value: ""}})
	if err != nil {
		t.Fatalf("decode bucket: %v", err)
	}
	privilege := rolePrivilege{Resource: resource, Actions: []string{"collStats"}}
	preview, truncated := previewTypedPrivileges([]rolePrivilege{privilege})
	if len(preview) != 0 || !truncated {
		t.Fatal("bucket privilege must not be projected as a normal desired namespace")
	}
	var desired adapter.MongoRoleResource
	if json.Unmarshal([]byte(`{"system_buckets":""}`), &desired) == nil {
		t.Fatal("observed grammar must not extend desired API role-document grammar")
	}
	state := newMongoRolePolicyState(testMongoRolePolicyTemplate())
	addActualMongoRoleState(state, customRole{Role: "custom_monitor", DB: "admin", ObservationComplete: true,
		DirectPrivileges: []rolePrivilege{privilege}})
	if state.blockedReason != "observed_role_resource_not_representable" {
		t.Fatalf("lossy custom role repair was not blocked: %q", state.blockedReason)
	}
	for _, document := range []bson.D{
		{{Key: "system_buckets", Value: ""}},
		{{Key: "db", Value: "appdb"}, {Key: "system_buckets", Value: ""}},
	} {
		bucket, err := decodeObservedResource(t, document)
		if err != nil {
			t.Fatalf("decode authority fixture: %v", err)
		}
		privileges := []rolePrivilege{{Resource: bucket, Actions: []string{"createRole", "grantRole", "revokeRole"}}}
		if mongoAuthorizationCoversDatabase(privileges, "createRole", "appdb") ||
			mongoAuthorizationCoversAllDatabases(privileges, "revokeRole") {
			t.Fatal("bucket-only privilege must not become database-wide management authority")
		}
	}
	if !slices.Contains(roleDangerReasons(customRole{ObservationComplete: true, DirectPrivileges: []rolePrivilege{privilege}}),
		"direct:broad_resource:"+printableObservedResourceKey(resource)) {
		t.Fatal("global bucket scope must retain conservative danger classification")
	}
}
