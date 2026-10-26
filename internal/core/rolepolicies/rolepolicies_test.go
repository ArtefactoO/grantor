package rolepolicies

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestTechnicalSpecPreservesPostgresWireContract(t *testing.T) {
	spec := adapter.RolePolicySpec{
		Engine: "postgres", RoleName: "r_app", Database: "app",
		Schemas: []string{"public"}, OwnerRoles: []string{"app_owner"},
		CreatorRoles: []string{"app_migrator"}, Profile: "read",
	}
	raw, err := json.Marshal(TechnicalSpec(spec))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 6 || got["database"] != "app" || got["profile"] != "read" {
		t.Fatalf("PostgreSQL desired_spec = %s, want established six-field shape", raw)
	}
	if _, exists := got["role_database"]; exists {
		t.Fatalf("PostgreSQL desired_spec leaked MongoDB fields: %s", raw)
	}
}

func TestExactObservedSummaryBoundsMongoDBDirectDefinition(t *testing.T) {
	spec := adapter.RolePolicySpec{Engine: "mongodb", RoleName: "large", Database: "admin"}
	for privilegeIndex := 0; privilegeIndex < 128; privilegeIndex++ {
		privilege := adapter.MongoRolePrivilege{
			Resource: adapter.MongoRoleResource{
				DB: "app", Collection: "collection_" + strings.Repeat("x", 180),
			},
		}
		for actionIndex := 0; actionIndex < 116; actionIndex++ {
			privilege.Actions = append(privilege.Actions, "action_"+strings.Repeat("y", 80))
		}
		spec.MongoPrivileges = append(spec.MongoPrivileges, privilege)
	}
	for index := 0; index < 64; index++ {
		spec.MongoInheritedRoles = append(spec.MongoInheritedRoles,
			adapter.MongoRoleRef{Role: "role_" + strings.Repeat("r", 100), DB: "admin"})
	}
	raw, err := exactObservedSummary(json.RawMessage(`{
		"missing":["old"],"extra":["old"],"truncated":true,
		"inherited_privileges":[{"resource":{"cluster":true},"actions":["old"]}]
	}`), spec)
	if err != nil {
		t.Fatalf("exactObservedSummary: %v", err)
	}
	if len(raw) >= 64*1024 {
		t.Fatalf("completed summary size = %d, want < 65536", len(raw))
	}
	var summary map[string]any
	if err := json.Unmarshal(raw, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	if summary["truncated"] != true || summary["direct_privileges_count"] != float64(128) ||
		summary["direct_inherited_roles_count"] != float64(64) {
		t.Fatalf("completed summary = %+v", summary)
	}
	if _, exists := summary["inherited_privileges"]; exists {
		t.Fatal("completed summary retained stale inherited privileges")
	}

	empty, err := exactObservedSummary(nil, adapter.RolePolicySpec{
		Engine: "mongodb", RoleName: "empty", Database: "app",
	})
	if err != nil {
		t.Fatalf("empty exactObservedSummary: %v", err)
	}
	if strings.Contains(string(empty), `"direct_privileges":null`) ||
		strings.Contains(string(empty), `"direct_inherited_roles":null`) {
		t.Fatalf("empty completed summary uses null arrays: %s", empty)
	}
}

func TestTechnicalSpecProjectsTypedMongoDBWireContract(t *testing.T) {
	spec := adapter.RolePolicySpec{
		Engine: "mongodb", RoleName: "app_worker", Database: "app",
		MongoInheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		MongoPrivileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"},
			Actions:  []string{"find"},
		}},
	}
	projected := TechnicalSpec(spec)
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got) != 4 || got["role_database"] != "app" || got["role_name"] != "app_worker" {
		t.Fatalf("MongoDB desired_spec = %s, want four-field typed shape", raw)
	}
	for _, postgresField := range []string{"database", "schemas", "owner_roles", "creator_roles", "profile"} {
		if _, exists := got[postgresField]; exists {
			t.Fatalf("MongoDB desired_spec contains PostgreSQL field %q: %s", postgresField, raw)
		}
	}

	// Public projection must not alias the durable spec; UI serialization or
	// tests may mutate it without changing immutable operation intent.
	projected.InheritedRoles[0].Role = "changed"
	projected.Privileges[0].Actions[0] = "update"
	if spec.MongoInheritedRoles[0].Role != "read" || spec.MongoPrivileges[0].Actions[0] != "find" {
		t.Fatal("TechnicalSpec aliases adapter.RolePolicySpec slices")
	}
}

func TestTechnicalSpecMongoDBUsesEmptyArraysNotNull(t *testing.T) {
	raw, err := json.Marshal(TechnicalSpec(adapter.RolePolicySpec{
		Engine: "mongodb", RoleName: "empty", Database: "app",
	}))
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(raw) != `{"role_name":"empty","role_database":"app","inherited_roles":[],"privileges":[]}` {
		t.Fatalf("empty MongoDB desired_spec = %s", raw)
	}
}
