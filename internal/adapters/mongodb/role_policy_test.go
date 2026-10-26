package mongodb

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
)

func testMongoRolePolicyTemplate() mongodbconfig.RolePolicyTemplate {
	return mongodbconfig.Normalize(mongodbconfig.RolePolicyTemplate{
		Key: "app-writer", Name: "Application writer", Description: "Scoped writer",
		RoleName: "app_writer", RoleDatabase: "appdb",
		InheritedRoles: []adapter.MongoRoleRef{{Role: "read", DB: "appdb"}},
		Privileges: []adapter.MongoRolePrivilege{{
			Resource: adapter.MongoRoleResource{DB: "appdb", Collection: "events"},
			Actions:  []string{"insert", "update"},
		}},
	})
}

func mongoRolePolicyConnection(template mongodbconfig.RolePolicyTemplate) adapter.Connection {
	return adapter.Connection{
		Engine: Engine,
		Attributes: map[string]any{
			mongodbconfig.AttributeRolePolicyTemplates: []mongodbconfig.RolePolicyTemplate{template},
		},
	}
}

func TestMongoRolePolicyTemplateRequiresPinnedCatalogEntry(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	spec := mongodbconfig.Spec(template)
	change := adapter.DesiredChange{
		Connection: mongoRolePolicyConnection(template), RolePolicySpec: &spec,
		Permission: rolePermissionID(template.RoleDatabase, template.RoleName),
	}
	got, err := mongoRolePolicyTemplate(change)
	if err != nil {
		t.Fatalf("mongoRolePolicyTemplate: %v", err)
	}
	if mongodbconfig.Fingerprint(got) != mongodbconfig.Fingerprint(template) {
		t.Fatalf("template = %+v, want %+v", got, template)
	}

	tampered := spec
	tampered.MongoPrivileges = cloneMongoPrivileges(spec.MongoPrivileges)
	tampered.MongoPrivileges[0].Actions = append(tampered.MongoPrivileges[0].Actions, "remove")
	change.RolePolicySpec = &tampered
	if _, err := mongoRolePolicyTemplate(change); err == nil {
		t.Fatal("tampered pinned spec must be rejected")
	}

	foreign := spec
	foreign.Profile = "read_write"
	change.RolePolicySpec = &foreign
	if _, err := mongoRolePolicyTemplate(change); err == nil {
		t.Fatal("foreign engine fields must be rejected")
	}

	wrongPermission := spec
	change.RolePolicySpec = &wrongPermission
	change.Permission = "role:appdb.someone_else"
	if _, err := mongoRolePolicyTemplate(change); err == nil {
		t.Fatal("mismatched permission identity must be rejected")
	}
}

func TestMongoRolePolicyCapabilitiesRequireObservedExactCatalog(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	conn := mongoRolePolicyConnection(template)
	ad := New()
	if slices.Contains(ad.CapabilitiesFor(conn, nil), adapter.CapRolePolicyApply) {
		t.Fatal("role policy capability must be off before discovery")
	}
	topology := map[string]any{
		mongoRolePolicyCatalogFingerprintKey: mongodbconfig.CatalogFingerprint([]mongodbconfig.RolePolicyTemplate{template}),
		mongoRolePolicyApplySupportedKey:     true,
	}
	if !slices.Contains(ad.CapabilitiesFor(conn, topology), adapter.CapRolePolicyApply) {
		t.Fatal("role policy capability must be enabled for the observed exact catalog")
	}
	changed := template
	changed.Description = "Changed after discovery"
	conn.Attributes[mongodbconfig.AttributeRolePolicyTemplates] = []mongodbconfig.RolePolicyTemplate{changed}
	if slices.Contains(ad.CapabilitiesFor(conn, topology), adapter.CapRolePolicyApply) {
		t.Fatal("catalog change after discovery must disable role policy capability")
	}
}

func TestMongoRoleDangerIsDerivedFromObservedPrivileges(t *testing.T) {
	safe := customRole{
		Role: "app_reader", DB: "appdb", ObservationComplete: true,
		DirectPrivileges: []rolePrivilege{{
			Resource: roleResource{DB: "appdb", Collection: "events"},
			Actions:  []string{"find"},
		}},
	}
	if reasons := roleDangerReasons(safe); len(reasons) != 0 {
		t.Fatalf("safe role danger reasons = %v", reasons)
	}
	cluster := safe
	cluster.InheritedPrivileges = []rolePrivilege{{
		Resource: roleResource{Cluster: true}, Actions: []string{"serverStatus"},
	}}
	reasons := roleDangerReasons(cluster)
	if !slices.Contains(reasons, "inherited:broad_resource:cluster") ||
		!slices.Contains(reasons, "inherited:dangerous_action:serverStatus") {
		t.Fatalf("cluster danger reasons = %v", reasons)
	}
	incomplete := safe
	incomplete.ObservationComplete = false
	if !slices.Contains(roleDangerReasons(incomplete), "privilege_observation_incomplete") {
		t.Fatal("incomplete role observation must be dangerous")
	}
	ddl := safe
	ddl.DirectPrivileges[0].Actions = []string{"dropCollection"}
	if !slices.Contains(roleDangerReasons(ddl), "direct:dangerous_action:dropCollection") {
		t.Fatal("destructive custom-role action must be dangerous")
	}
}

func TestUnknownMongoResourceShapeFailsClosed(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "resource", Value: bson.D{{Key: "futureResource", Value: true}}},
		{Key: "actions", Value: bson.A{"find"}},
	})
	if err != nil {
		t.Fatalf("bson.Marshal: %v", err)
	}
	var decoded rolePrivilege
	if err := bson.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("bson.Unmarshal: %v", err)
	}
	resource := decoded.Resource
	if resource.Unknown["futureResource"] != true {
		t.Fatalf("unknown resource keys were dropped: %+v", resource)
	}
	if validObservedRoleResource(resource) {
		t.Fatal("unknown MongoDB resource shape must be rejected")
	}
	role := customRole{
		Role: "future_role", DB: "appdb", ObservationComplete: true,
		DirectPrivileges: []rolePrivilege{{Resource: resource, Actions: []string{"find"}}},
	}
	if !roleHasUnsupportedResource(role) ||
		!slices.Contains(roleDangerReasons(role), "unsupported_resource_shape") {
		t.Fatalf("unknown resource role was not blocked: %v", roleDangerReasons(role))
	}
	preview, truncated := previewTypedPrivileges(role.DirectPrivileges)
	if len(preview) != 0 || !truncated {
		t.Fatalf("unknown resource preview = %+v/%v, want omitted/truncated", preview, truncated)
	}
}

func TestMongoRoleManagementAuthorizationIsScopeAware(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	authorization := mongoRoleManagementAuthorization{
		Authenticated: true,
		Privileges: []rolePrivilege{
			{Resource: roleResource{DB: "appdb"}, Actions: []string{"viewRole", "createRole", "grantRole"}},
			{Resource: roleResource{}, Actions: []string{"revokeRole"}},
		},
	}
	if status := mongoRoleManagementForTemplate(authorization, template); !status.Supported {
		t.Fatalf("appdb-scoped authorization = %+v, want supported", status)
	}
	other := template
	other.RoleDatabase = "otherdb"
	other.InheritedRoles = nil
	other.Privileges = []adapter.MongoRolePrivilege{{
		Resource: adapter.MongoRoleResource{DB: "otherdb", Collection: "events"},
		Actions:  []string{"find"},
	}}
	if status := mongoRoleManagementForTemplate(authorization, other); status.Supported {
		t.Fatal("db A role-management privileges must not authorize db B")
	}
	withoutAllDBRevoke := authorization
	withoutAllDBRevoke.Privileges = slices.Clone(authorization.Privileges)
	withoutAllDBRevoke.Privileges[1] = rolePrivilege{
		Resource: roleResource{DB: "appdb"}, Actions: []string{"revokeRole"},
	}
	if status := mongoRoleManagementForTemplate(withoutAllDBRevoke, template); status.Supported {
		t.Fatal("repair without all-database revokeRole must be rejected")
	}
	selfAuthority := authorization
	selfAuthority.AuthorityRoles = map[string]struct{}{
		mongodbconfig.RoleIdentity(template.RoleDatabase, template.RoleName): {},
	}
	status := mongoRoleManagementForTemplate(selfAuthority, template)
	if status.Supported || status.Reason != "role_is_connection_admin_dependency" {
		t.Fatalf("self-authority status = %+v, want fail-closed dependency blocker", status)
	}
}

func TestObservedSafeCustomRoleAndBuiltinsStayCompatible(t *testing.T) {
	roles := []customRole{
		{Role: "custom_reader", DB: "appdb", ObservationComplete: true},
		{Role: "read", DB: "appdb", IsBuiltin: true, ObservationComplete: true,
			InheritedPrivileges: []rolePrivilege{{
				Resource: roleResource{DB: "appdb"}, Actions: []string{"find", "killCursors"},
			}}},
		{Role: "readWrite", DB: "appdb", IsBuiltin: true, ObservationComplete: true,
			InheritedPrivileges: []rolePrivilege{{
				Resource: roleResource{DB: "appdb"}, Actions: []string{"find", "insert", "update"},
			}}},
	}
	permissions := buildPermissions(roles,
		map[roleRef]bool{{Role: "unobserved_custom", DB: "appdb"}: true},
		map[string]bool{"appdb": true})
	byID := make(map[string]adapter.ObservedPermission)
	for _, permission := range permissions {
		byID[permission.ExternalID] = permission
	}
	if permission := byID["role:appdb.custom_reader"]; permission.Dangerous || !permission.Assignable {
		t.Fatalf("fully observed safe custom role = %+v", permission)
	}
	for _, id := range []string{"role:appdb.read", "role:appdb.readWrite"} {
		if permission := byID[id]; permission.Dangerous || !permission.Assignable {
			t.Fatalf("built-in %s = %+v, want assignable non-dangerous", id, permission)
		}
	}
	if permission := byID["role:appdb.unobserved_custom"]; !permission.Dangerous || permission.Assignable || permission.Attributes["observation_incomplete"] != true {
		t.Fatalf("unobserved custom fallback = %+v, want dangerous nonassignable", permission)
	}
}

func TestConfiguredMissingMongoRoleIsVisibleAndNonAssignable(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	state := newMongoRolePolicyState(template)
	state.finish()
	policy := observedMongoRolePolicy(template, state, true, "")
	permissions := annotateMongoRolePolicyPermissions(nil,
		[]adapter.ObservedRolePolicy{policy}, map[string]bool{"appdb": true})
	if len(permissions) != 1 {
		t.Fatalf("permissions = %+v", permissions)
	}
	permission := permissions[0]
	if permission.Assignable || permission.ExternalID != "role:appdb.app_writer" ||
		permission.Attributes["role_policy_role_missing"] != true {
		t.Fatalf("missing configured role permission = %+v", permission)
	}
}

func TestMongoRolePolicyCommandUsesTypedReplacementArrays(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	for _, tc := range []struct {
		exists bool
		key    string
	}{
		{exists: false, key: "createRole"},
		{exists: true, key: "updateRole"},
	} {
		cmd := mongoRolePolicyCommand(template, tc.exists)
		counts := map[string]int{}
		for _, element := range cmd {
			counts[element.Key]++
		}
		for _, key := range []string{tc.key, "privileges", "roles", "writeConcern"} {
			if counts[key] != 1 {
				t.Fatalf("command key %q count = %d, want 1: %+v", key, counts[key], cmd)
			}
		}
		raw, err := bson.Marshal(cmd)
		if err != nil {
			t.Fatalf("bson.Marshal: %v", err)
		}
		var decoded bson.M
		if err := bson.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("bson.Unmarshal: %v", err)
		}
		if decoded[tc.key] != template.RoleName {
			t.Fatalf("command = %+v, want %s=%q", decoded, tc.key, template.RoleName)
		}
		if _, ok := decoded["privileges"]; !ok {
			t.Fatal("command must fully replace privileges")
		}
		if _, ok := decoded["roles"]; !ok {
			t.Fatal("command must fully replace inherited roles")
		}
		if _, ok := decoded["authenticationRestrictions"]; ok {
			t.Fatal("typed policy command must not carry raw authentication restrictions")
		}
		writeConcern, ok := decoded["writeConcern"].(bson.M)
		if !ok || writeConcern["w"] != "majority" {
			t.Fatalf("writeConcern = %#v, want majority", decoded["writeConcern"])
		}
	}
}

func TestMongoRolePolicyPreviewIsBounded(t *testing.T) {
	values := make([]rolePrivilege, mongoRolePolicyPreviewLimit+7)
	for index := range values {
		values[index] = rolePrivilege{
			Resource: roleResource{DB: "appdb", Collection: "events"},
			Actions:  []string{"find"},
		}
	}
	preview, truncated := previewTypedPrivileges(values)
	if len(preview) != mongoPrivilegePreviewLimit || !truncated {
		t.Fatalf("preview len/truncated = %d/%v", len(preview), truncated)
	}
}

func TestMongoRolePolicySummaryStaysBelowMetadataLimit(t *testing.T) {
	template := testMongoRolePolicyTemplate()
	state := newMongoRolePolicyState(template)
	state.exists = true
	state.role = customRole{Role: template.RoleName, DB: template.RoleDatabase, ObservationComplete: true}
	for privilegeIndex := 0; privilegeIndex < 128; privilegeIndex++ {
		privilege := rolePrivilege{
			Resource: roleResource{DB: "appdb", Collection: fmt.Sprintf("collection_%03d", privilegeIndex)},
		}
		for actionIndex := 0; actionIndex < 128; actionIndex++ {
			privilege.Actions = append(privilege.Actions,
				fmt.Sprintf("unknown_action_%03d_%s", actionIndex, strings.Repeat("x", 80)))
		}
		state.role.DirectPrivileges = append(state.role.DirectPrivileges, privilege)
		state.role.InheritedPrivileges = append(state.role.InheritedPrivileges, privilege)
	}
	for index := 0; index < 1000; index++ {
		state.actual[fmt.Sprintf("extra:%04d:%s", index, strings.Repeat("y", 120))] = struct{}{}
	}
	state.dangerReasons = roleDangerReasons(state.role)
	state.finish()
	policy := observedMongoRolePolicy(template, state, false, "role_management_privileges_missing")
	raw, err := json.Marshal(policy.Summary)
	if err != nil {
		t.Fatalf("json.Marshal summary: %v", err)
	}
	if len(raw) >= 64*1024 {
		t.Fatalf("summary size = %d bytes, want < 65536", len(raw))
	}
	if policy.Summary["truncated"] != true {
		t.Fatal("max-shaped summary must advertise truncation")
	}
}

func TestMongoTargetIdentityEmptyIsTypedConflict(t *testing.T) {
	err := requireMongoTargetIdentity(t.Context(), nil, "")
	if !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("error = %v, want ErrTargetIdentityConflict", err)
	}
}
