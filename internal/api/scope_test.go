package api

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func TestScopeAppliesTo(t *testing.T) {
	cases := []struct {
		name string
		mode policy.EnforcementMode
		role auth.Role
		want bool
	}{
		{"disabled admin", policy.EnforcementDisabled, auth.RoleAdmin, false},
		{"disabled operator", policy.EnforcementDisabled, auth.RoleOperator, false},
		{"disabled viewer", policy.EnforcementDisabled, auth.RoleViewer, false},
		{"enforce admin", policy.EnforcementEnforce, auth.RoleAdmin, false},
		{"enforce operator", policy.EnforcementEnforce, auth.RoleOperator, true},
		{"enforce viewer", policy.EnforcementEnforce, auth.RoleViewer, false},
		{"enforce unknown role", policy.EnforcementEnforce, auth.Role("ghost"), false},
		{"empty mode operator", policy.EnforcementMode(""), auth.RoleOperator, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopeAppliesTo(tc.mode, tc.role); got != tc.want {
				t.Errorf("scopeAppliesTo(%q, %q) = %v, want %v", tc.mode, tc.role, got, tc.want)
			}
		})
	}
}

func TestEnvironmentAllowed(t *testing.T) {
	cases := []struct {
		name     string
		allowed  []string
		allowAll bool
		env      string
		want     bool
	}{
		{"deny by default", nil, false, "prod", false},
		{"allow all", nil, true, "prod", true},
		{"in list", []string{"dev", "prod"}, false, "prod", true},
		{"not in list", []string{"dev"}, false, "prod", false},
		{"empty env not in list", []string{"dev"}, false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := environmentAllowed(tc.allowed, tc.allowAll, tc.env); got != tc.want {
				t.Errorf("environmentAllowed(%v, %v, %q) = %v, want %v",
					tc.allowed, tc.allowAll, tc.env, got, tc.want)
			}
		})
	}
}

func TestServicePrincipalID(t *testing.T) {
	human := auth.Session{Subject: "idp-sub", Email: "op@grantor.dev", Role: auth.RoleOperator}
	if got := servicePrincipalID(human); got != "" {
		t.Errorf("servicePrincipalID(human) = %q, want empty", got)
	}
	service := auth.Session{Subject: "principal-uuid", Role: auth.RoleOperator, Service: true}
	if got := servicePrincipalID(service); got != "principal-uuid" {
		t.Errorf("servicePrincipalID(service) = %q, want principal-uuid", got)
	}
}
