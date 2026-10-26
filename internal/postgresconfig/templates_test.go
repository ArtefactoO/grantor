package postgresconfig

import (
	"strings"
	"testing"
)

func validTemplate() RolePolicyTemplate {
	return RolePolicyTemplate{
		Key: "app-read", Name: "Application read", Description: "Read application data",
		RoleName: "r_app", Database: "app", Schemas: []string{"audit", "public"},
		OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_migrator", "app_owner"},
		Profile: ProfileRead,
	}
}

func TestValidateRolePolicyTemplates(t *testing.T) {
	if err := Validate([]RolePolicyTemplate{validTemplate()}); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	formerHelperSchema := validTemplate()
	formerHelperSchema.Schemas = []string{"grantor"}
	if err := Validate([]RolePolicyTemplate{formerHelperSchema}); err != nil {
		t.Fatalf("the former helper schema must no longer be reserved: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*RolePolicyTemplate)
	}{
		{"empty key", func(v *RolePolicyTemplate) { v.Key = "" }},
		{"unsafe key", func(v *RolePolicyTemplate) { v.Key = "app/read" }},
		{"uppercase key", func(v *RolePolicyTemplate) { v.Key = "APP" }},
		{"invalid role", func(v *RolePolicyTemplate) { v.RoleName = `r_app"; drop role x` }},
		{"reserved role", func(v *RolePolicyTemplate) { v.RoleName = "pg_read_all_data" }},
		{"empty schemas", func(v *RolePolicyTemplate) { v.Schemas = nil }},
		{"system schema", func(v *RolePolicyTemplate) { v.Schemas = []string{"pg_catalog"} }},
		{"empty owner roles", func(v *RolePolicyTemplate) { v.OwnerRoles = nil }},
		{"empty creator roles", func(v *RolePolicyTemplate) { v.CreatorRoles = nil }},
		{"policy owns objects", func(v *RolePolicyTemplate) { v.OwnerRoles = []string{"r_app"} }},
		{"policy creates objects", func(v *RolePolicyTemplate) { v.CreatorRoles = []string{"r_app"} }},
		{"duplicate schemas", func(v *RolePolicyTemplate) { v.Schemas = []string{"public", "public"} }},
		{"unknown profile", func(v *RolePolicyTemplate) { v.Profile = "admin" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := validTemplate()
			tc.edit(&value)
			if err := Validate([]RolePolicyTemplate{value}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	for _, field := range []string{"key", "name", "role"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			first, second := validTemplate(), validTemplate()
			second.Key, second.Name, second.RoleName = "app-rw", "Application write", "rw_app"
			switch field {
			case "key":
				second.Key = first.Key
			case "name":
				second.Name = first.Name
			case "role":
				second.RoleName = first.RoleName
			}
			if err := Validate([]RolePolicyTemplate{first, second}); err == nil || !strings.Contains(err.Error(), "duplicat") && !strings.Contains(err.Error(), "more than one") {
				t.Fatalf("Validate duplicate %s = %v", field, err)
			}
		})
	}
}

func TestNormalizeAndFingerprintIgnoreListOrder(t *testing.T) {
	first := validTemplate()
	second := validTemplate()
	second.Schemas = []string{"public", "audit"}
	second.CreatorRoles = []string{"app_owner", "app_migrator"}
	if Fingerprint(first) != Fingerprint(second) {
		t.Fatal("semantically equal templates must have the same fingerprint")
	}
	normalized := Normalize(second)
	if strings.Join(normalized.Schemas, ",") != "audit,public" ||
		strings.Join(normalized.CreatorRoles, ",") != "app_migrator,app_owner" {
		t.Fatalf("Normalize = %+v", normalized)
	}
}

func TestCatalogFingerprintIgnoresTemplateOrder(t *testing.T) {
	first := validTemplate()
	second := validTemplate()
	second.Key, second.Name, second.RoleName = "app-rw", "Application write", "rw_app"
	second.Profile = ProfileReadWrite
	if CatalogFingerprint([]RolePolicyTemplate{first, second}) !=
		CatalogFingerprint([]RolePolicyTemplate{second, first}) {
		t.Fatal("catalog fingerprint must not depend on template order")
	}
}

func TestFromAttributesSurvivesConnectorJSONShape(t *testing.T) {
	attrs := map[string]any{AttributeRolePolicyTemplates: []any{map[string]any{
		"key": "app-read", "name": "Application read", "description": "Read application data",
		"role_name": "r_app", "database": "app", "schemas": []any{"public"},
		"owner_roles": []any{"app_owner"}, "creator_roles": []any{"app_migrator"}, "profile": "read",
	}}}
	got, err := FromAttributes(attrs)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(got) != 1 || got[0].RoleName != "r_app" || got[0].Database != "app" {
		t.Fatalf("templates = %+v", got)
	}
}

func TestFromAttributesRejectsUnknownFields(t *testing.T) {
	attrs := map[string]any{AttributeRolePolicyTemplates: []any{map[string]any{
		"key": "app-read", "name": "Application read", "description": "Read application data",
		"role_name": "r_app", "database": "app", "schemas": []any{"public"},
		"owner_roles": []any{"app_owner"}, "creator_roles": []any{"app_migrator"},
		"profile": "read", "raw_sql": "grant all",
	}}}
	if _, err := FromAttributes(attrs); err == nil {
		t.Fatal("unknown field must be rejected")
	}
}
