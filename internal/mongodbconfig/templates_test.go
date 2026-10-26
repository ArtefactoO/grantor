package mongodbconfig

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func validTemplate() RolePolicyTemplate {
	return RolePolicyTemplate{
		Key: "app-worker", Name: "Application worker", Description: "Application data access",
		RoleName: "app_worker", RoleDatabase: "app",
		InheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "app"}},
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"},
			Actions:  []string{"find", "insert", "update"},
		}},
	}
}

func TestValidateRolePolicyTemplates(t *testing.T) {
	if err := Validate([]RolePolicyTemplate{validTemplate()}); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*RolePolicyTemplate)
	}{
		{"empty key", func(v *RolePolicyTemplate) { v.Key = "" }},
		{"unsafe key", func(v *RolePolicyTemplate) { v.Key = "app/worker" }},
		{"built-in role identity", func(v *RolePolicyTemplate) { v.RoleName = "read" }},
		{"unsafe role", func(v *RolePolicyTemplate) { v.RoleName = `x\"; db.dropDatabase()` }},
		{"empty role database", func(v *RolePolicyTemplate) { v.RoleDatabase = "" }},
		{"unknown action", func(v *RolePolicyTemplate) { v.Privileges[0].Actions = []string{"runArbitraryCommand"} }},
		{"empty actions", func(v *RolePolicyTemplate) { v.Privileges[0].Actions = nil }},
		{"any resource", func(v *RolePolicyTemplate) {
			v.RoleDatabase = "admin"
			v.Privileges[0].Resource = adapter.MongoRoleResource{AnyResource: true}
		}},
		{"cluster non-admin", func(v *RolePolicyTemplate) {
			v.Privileges[0] = adapter.MongoRolePrivilege{Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"replSetGetConfig"}}
		}},
		{"cross database non-admin", func(v *RolePolicyTemplate) { v.Privileges[0].Resource.DB = "other" }},
		{"cluster action on namespace", func(v *RolePolicyTemplate) { v.Privileges[0].Actions = []string{"replSetGetConfig"} }},
		{"namespace action on cluster", func(v *RolePolicyTemplate) {
			v.RoleDatabase = "admin"
			v.Privileges[0] = adapter.MongoRolePrivilege{Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"find"}}
		}},
		{"database action on collection", func(v *RolePolicyTemplate) { v.Privileges[0].Actions = []string{"createRole"} }},
		{"collection action on database", func(v *RolePolicyTemplate) {
			v.Privileges[0].Resource.Collection = ""
			v.Privileges[0].Actions = []string{"killAnyCursor"}
		}},
		{"plan cache filter on database", func(v *RolePolicyTemplate) {
			v.Privileges[0].Resource.Collection = ""
			v.Privileges[0].Actions = []string{"planCacheIndexFilter"}
		}},
		{"unsafe built-in inheritance", func(v *RolePolicyTemplate) { v.InheritedRoles[0].Role = "root" }},
		{"cross database inheritance", func(v *RolePolicyTemplate) { v.InheritedRoles[0].DB = "other" }},
		{"new built-in role identity", func(v *RolePolicyTemplate) {
			v.RoleDatabase = "admin"
			v.RoleName = "searchCoordinator"
			v.InheritedRoles = nil
			v.Privileges = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := validTemplate()
			tc.edit(&value)
			if err := Validate([]RolePolicyTemplate{value}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestValidateActionResourceMatrix(t *testing.T) {
	template := validTemplate()
	template.RoleDatabase = "admin"
	template.InheritedRoles = nil
	template.Privileges = []adapter.MongoRolePrivilege{
		{Resource: adapter.MongoRoleResource{DB: "admin"}, Actions: []string{"createRole"}},
		{Resource: adapter.MongoRoleResource{DB: "app", Collection: "events"}, Actions: []string{"find", "validate", "compact"}},
		{Resource: adapter.MongoRoleResource{Cluster: true}, Actions: []string{"replSetGetConfig", "compact"}},
	}
	if err := Validate([]RolePolicyTemplate{template}); err != nil {
		t.Fatalf("Validate(representative matrix): %v", err)
	}
}

func TestValidateCatalogDependenciesAndCycles(t *testing.T) {
	base := validTemplate()
	child := validTemplate()
	child.Key, child.Name, child.RoleName = "app-child", "Application child", "app_child"
	child.InheritedRoles = []adapter.MongoRoleRef{{Role: base.RoleName, DB: base.RoleDatabase}}
	if err := Validate([]RolePolicyTemplate{base, child}); err != nil {
		t.Fatalf("Validate(catalog dependency): %v", err)
	}

	missing := child
	missing.InheritedRoles = []adapter.MongoRoleRef{{Role: "unmanaged_custom_role", DB: "app"}}
	if err := Validate([]RolePolicyTemplate{base, missing}); err == nil || !strings.Contains(err.Error(), "unmanaged role") {
		t.Fatalf("Validate(unmanaged dependency) = %v", err)
	}

	child.InheritedRoles = []adapter.MongoRoleRef{{Role: "app_worker", DB: "app"}}
	base.InheritedRoles = []adapter.MongoRoleRef{{Role: child.RoleName, DB: child.RoleDatabase}}
	if err := Validate([]RolePolicyTemplate{base, child}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("Validate(cycle) = %v", err)
	}
}

func TestValidateUniqueRoleIdentityIncludesDatabase(t *testing.T) {
	first, second := validTemplate(), validTemplate()
	second.Key, second.Name, second.RoleDatabase = "other-worker", "Other worker", "other"
	second.InheritedRoles[0].DB = "other"
	second.Privileges[0].Resource.DB = "other"
	if err := Validate([]RolePolicyTemplate{first, second}); err != nil {
		t.Fatalf("same role name in separate databases must be distinct: %v", err)
	}
	second.RoleDatabase = first.RoleDatabase
	second.InheritedRoles[0].DB = first.RoleDatabase
	second.Privileges[0].Resource.DB = first.RoleDatabase
	if err := Validate([]RolePolicyTemplate{first, second}); err == nil {
		t.Fatal("same role identity must be rejected")
	}
}

func TestNormalizeMergesPrivilegesAndIgnoresOrder(t *testing.T) {
	first := validTemplate()
	first.InheritedRoles = append(first.InheritedRoles, first.InheritedRoles[0])
	first.Privileges = append(first.Privileges,
		adapter.MongoRolePrivilege{
			Resource: first.Privileges[0].Resource,
			Actions:  []string{"remove", "find"},
		},
		adapter.MongoRolePrivilege{
			Resource: adapter.MongoRoleResource{DB: "app"},
			Actions:  []string{"listCollections"},
		},
	)
	normalized := Normalize(first)
	if len(normalized.InheritedRoles) != 1 || len(normalized.Privileges) != 2 {
		t.Fatalf("Normalize = %+v", normalized)
	}
	wantActions := []string{"find", "insert", "remove", "update"}
	var gotActions []string
	for _, privilege := range normalized.Privileges {
		if privilege.Resource.Collection == "events" {
			gotActions = privilege.Actions
		}
	}
	if !reflect.DeepEqual(gotActions, wantActions) {
		t.Fatalf("merged actions = %v, want %v", gotActions, wantActions)
	}

	second := validTemplate()
	second.Privileges[0].Actions = []string{"update", "find", "insert"}
	if Fingerprint(second) != Fingerprint(validTemplate()) {
		t.Fatal("fingerprint must ignore action order")
	}
}

func TestSpecAndPublicJSONRemainTyped(t *testing.T) {
	spec := Spec(validTemplate())
	if spec.Engine != "mongodb" || spec.RoleName != "app_worker" || spec.Database != "app" ||
		len(spec.MongoInheritedRoles) != 1 || len(spec.MongoPrivileges) != 1 {
		t.Fatalf("Spec = %+v", spec)
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(raw), "bson") || strings.Contains(string(raw), "command") {
		t.Fatalf("spec contains untyped target fields: %s", raw)
	}
}

func TestSpecCanonicalEmptyMongoSlicesSurviveJSONRoundTrip(t *testing.T) {
	template := validTemplate()
	template.InheritedRoles = nil
	template.Privileges = nil
	want := Spec(template)
	if want.MongoInheritedRoles != nil || want.MongoPrivileges != nil {
		t.Fatalf("Spec empty slices = inherited:%#v privileges:%#v, want canonical nil",
			want.MongoInheritedRoles, want.MongoPrivileges)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got adapter.RolePolicySpec
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip spec = %#v, want %#v", got, want)
	}
}

func TestFromAttributesSurvivesConnectorJSONShape(t *testing.T) {
	attrs := map[string]any{AttributeRolePolicyTemplates: []any{map[string]any{
		"key": "app-worker", "name": "Application worker", "description": "Application data access",
		"role_name": "app_worker", "role_database": "app",
		"inherited_roles": []any{map[string]any{"role": "read", "db": "app"}},
		"privileges": []any{map[string]any{
			"resource": map[string]any{"db": "app", "collection": "events"},
			"actions":  []any{"find", "update"},
		}},
	}}}
	got, err := FromAttributes(attrs)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(got) != 1 || got[0].RoleDatabase != "app" || got[0].Privileges[0].Actions[0] != "find" {
		t.Fatalf("templates = %+v", got)
	}
}

func TestFromAttributesRejectsUnknownFields(t *testing.T) {
	for name, attrs := range map[string]map[string]any{
		"template raw BSON": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "app",
			"inherited_roles": []any{}, "privileges": []any{}, "raw_bson": map[string]any{},
		}}},
		"resource raw field": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "app", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{"db": "app", "collection": "", "server": true},
				"actions":  []any{"find"},
			}},
		}}},
		"empty resource becomes implicit broad scope": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "admin", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{}, "actions": []any{"find"},
			}},
		}}},
		"namespace resource missing collection": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "app", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{"db": "app"}, "actions": []any{"find"},
			}},
		}}},
		"namespace resource missing database": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "app", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{"collection": "events"}, "actions": []any{"find"},
			}},
		}}},
		"namespace resource null database": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "admin", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{"db": nil, "collection": ""}, "actions": []any{"find"},
			}},
		}}},
		"namespace resource null collection": {AttributeRolePolicyTemplates: []any{map[string]any{
			"key": "app-worker", "name": "Application worker", "description": "Application data access",
			"role_name": "app_worker", "role_database": "admin", "inherited_roles": []any{},
			"privileges": []any{map[string]any{
				"resource": map[string]any{"db": "", "collection": nil}, "actions": []any{"find"},
			}},
		}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := FromAttributes(attrs); err == nil {
				t.Fatal("unknown/raw BSON field must be rejected")
			}
		})
	}
}

func TestAllowedActionsExcludesInternalEscapeHatches(t *testing.T) {
	allowed := AllowedActions()
	if len(allowed) != 116 {
		t.Fatalf("allowed action catalog has %d entries, want versioned v1 count 116", len(allowed))
	}
	for _, action := range []string{"find", "insert", "createIndex", "viewRole", "shutdown"} {
		if !slices.Contains(allowed, action) {
			t.Fatalf("allowed actions missing %q", action)
		}
	}
	for _, action := range []string{"anyAction", "internal", "applyOps"} {
		if slices.Contains(allowed, action) {
			t.Fatalf("internal action %q must not be allowed", action)
		}
	}
}
