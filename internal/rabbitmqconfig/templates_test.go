package rabbitmqconfig

import (
	"strings"
	"testing"
)

func validTemplate() PermissionTemplate {
	return PermissionTemplate{
		Key: "etl-worker", Name: "ETL worker", Description: "ETL queues only",
		Vhost: "sl-project", Configure: `^(status_changes|project_etl_match_state_updates)$`,
		Write: `^project_etl_match_state_updates$`, Read: `^(status_changes|project_etl_match_state_updates)$`,
	}
}

func TestValidatePermissionTemplates(t *testing.T) {
	if err := Validate([]PermissionTemplate{validTemplate()}); err != nil {
		t.Fatalf("Validate(valid): %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*PermissionTemplate)
	}{
		{"empty key", func(v *PermissionTemplate) { v.Key = "" }},
		{"unsafe key", func(v *PermissionTemplate) { v.Key = "bad/key" }},
		{"uppercase key", func(v *PermissionTemplate) { v.Key = "ETL" }},
		{"dotted key", func(v *PermissionTemplate) { v.Key = "etl.worker" }},
		{"invalid regex", func(v *PermissionTemplate) { v.Read = "(" }},
		{"legacy full tuple", func(v *PermissionTemplate) { v.Configure, v.Write, v.Read = ".*", ".*", ".*" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := validTemplate()
			tc.edit(&value)
			if err := Validate([]PermissionTemplate{value}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	for _, field := range []string{"key", "name", "tuple"} {
		t.Run("duplicate "+field, func(t *testing.T) {
			first, second := validTemplate(), validTemplate()
			switch field {
			case "key":
				second.Name, second.Read = "Another", "^other$"
			case "name":
				second.Key, second.Read = "other", "^other$"
			case "tuple":
				second.Key, second.Name = "other", "Another"
			}
			if err := Validate([]PermissionTemplate{first, second}); err == nil || !strings.Contains(err.Error(), "duplicated") {
				t.Fatalf("Validate duplicate %s = %v, want duplicated error", field, err)
			}
		})
	}
}

func TestValidatePermissionRegexSafeSubset(t *testing.T) {
	for _, expression := range []string{
		`.*`,
		`^$`,
		`^queue$`,
		`^queue/name:status-v1$`,
		`^amq\.gen-.*$`,
		`^literal\(group\)\|pipe$`,
		`^literal\)$`,
		`^\.\*$`,
		`^(status_changes|project_etl_match_state_updates)$`,
		`^(foo|amq\.gen-.*|bar/baz:qux)$`,
		`^(.*)$`,
	} {
		t.Run(expression, func(t *testing.T) {
			if err := ValidatePermissionRegex(expression); err != nil {
				t.Fatalf("ValidatePermissionRegex(%q): %v", expression, err)
			}
		})
	}
}

func TestValidatePermissionRegexRejectsOutsideSubset(t *testing.T) {
	for _, expression := range []string{
		`queue`,
		`^queue`,
		`queue$`,
		`^foo|bar$`,
		`^(foo|)$`,
		`^(|foo)$`,
		`^(foo||bar)$`,
		`^[a-z]+$`,
		`^foo+$`,
		`^foo?$`,
		`^foo{1,3}$`,
		`^(foo)$`,
		`^((foo|bar))$`,
		`^(?=foo)foo$`,
		`^(foo)\1$`,
		`^foo\$`,
		`^(a+)+$`,
		`^(a|aa)+$`,
		`^(.*)*$`,
	} {
		t.Run(expression, func(t *testing.T) {
			if err := ValidatePermissionRegex(expression); err == nil {
				t.Fatalf("ValidatePermissionRegex(%q) unexpectedly succeeded", expression)
			}
		})
	}
}

func TestFromAttributesSurvivesConnectorJSONShape(t *testing.T) {
	attrs := map[string]any{AttributePermissionTemplates: []any{map[string]any{
		"key": "etl-worker", "name": "ETL worker", "description": "ETL queues only",
		"vhost": "sl-project", "configure": "^status$", "write": "^write$", "read": "^read$", "dangerous": false,
	}}}
	got, err := FromAttributes(attrs)
	if err != nil {
		t.Fatalf("FromAttributes: %v", err)
	}
	if len(got) != 1 || got[0].Key != "etl-worker" || got[0].Vhost != "sl-project" {
		t.Fatalf("templates = %+v", got)
	}
}

func TestIsBroadUsesAnyUnrestrictedRegex(t *testing.T) {
	value := validTemplate()
	if IsBroad(value) {
		t.Fatal("narrow template must not be broad")
	}
	for _, expression := range []string{
		`.*`,
		`^.*$`,
		`^(.*)$`,
		`^(status|.*)$`,
		`^.*.*$`,
	} {
		value.Write = expression
		if !IsBroad(value) {
			t.Fatalf("unrestricted write %q must mark the template broad", expression)
		}
	}
	for _, expression := range []string{`^prefix.*$`, `^(status|events)$`, `^\.\*$`} {
		value.Write = expression
		if IsBroad(value) {
			t.Fatalf("narrow write %q must not mark the template broad", expression)
		}
	}
}

func TestValidateRejectsSemanticLegacyFullTuple(t *testing.T) {
	for _, tuple := range [][3]string{
		{`^.*$`, `^(.*)$`, `.*`},
		{`^(queue|.*)$`, `^.*.*$`, `^(.*|exchange)$`},
	} {
		value := validTemplate()
		value.Configure, value.Write, value.Read = tuple[0], tuple[1], tuple[2]
		if err := Validate([]PermissionTemplate{value}); err == nil || !strings.Contains(err.Error(), "duplicates legacy full") {
			t.Fatalf("Validate(%q/%q/%q) = %v, want legacy duplicate error", tuple[0], tuple[1], tuple[2], err)
		}
	}
}
