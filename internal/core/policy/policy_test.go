package policy

import (
	"slices"
	"testing"
)

func TestResolveAllowed(t *testing.T) {
	cases := []struct {
		name         string
		environments []string
		wantAllowed  []string
		wantAll      bool
	}{
		{"empty -> deny by default", nil, nil, false},
		{"single env", []string{"prod"}, []string{"prod"}, false},
		{"star -> allow all", []string{"*"}, nil, true},
		{"star among others -> allow all, concrete kept", []string{"dev", "*", "prod"}, []string{"dev", "prod"}, true},
		{"multiple concrete", []string{"dev", "test"}, []string{"dev", "test"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed, allowAll := resolveAllowed(tc.environments)
			if allowAll != tc.wantAll {
				t.Errorf("resolveAllowed(%v) allowAll = %v, want %v", tc.environments, allowAll, tc.wantAll)
			}
			if !slices.Equal(allowed, tc.wantAllowed) {
				t.Errorf("resolveAllowed(%v) allowed = %v, want %v", tc.environments, allowed, tc.wantAllowed)
			}
		})
	}
}

func TestEnforcementModeEnforcing(t *testing.T) {
	cases := []struct {
		mode EnforcementMode
		want bool
	}{
		{EnforcementEnforce, true},
		{EnforcementDisabled, false},
		{EnforcementMode(""), false},
	}
	for _, tc := range cases {
		if got := tc.mode.Enforcing(); got != tc.want {
			t.Errorf("%q.Enforcing() = %v, want %v", tc.mode, got, tc.want)
		}
	}
}

func TestParseEnforcementMode(t *testing.T) {
	valid := map[string]EnforcementMode{
		"":          EnforcementDisabled,
		"disabled":  EnforcementDisabled,
		"enforce":   EnforcementEnforce,
		" ENFORCE ": EnforcementEnforce, //nolint:gocritic // пробелы намеренно: проверяем trim в ParseEnforcementMode
		"Disabled":  EnforcementDisabled,
	}
	for in, want := range valid {
		got, err := ParseEnforcementMode(in)
		if err != nil {
			t.Errorf("ParseEnforcementMode(%q): unexpected error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseEnforcementMode(%q) = %q, want %q", in, got, want)
		}
	}

	for _, in := range []string{"on", "true", "strict"} {
		if _, err := ParseEnforcementMode(in); err == nil {
			t.Errorf("ParseEnforcementMode(%q): expected error", in)
		}
	}
}

func TestValidSubjectKind(t *testing.T) {
	for _, kind := range []string{SubjectRole, SubjectPrincipal} {
		if !ValidSubjectKind(kind) {
			t.Errorf("ValidSubjectKind(%q) = false, want true", kind)
		}
	}
	for _, kind := range []string{"", "user", "group"} {
		if ValidSubjectKind(kind) {
			t.Errorf("ValidSubjectKind(%q) = true, want false", kind)
		}
	}
}
