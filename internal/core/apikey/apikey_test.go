package apikey

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/auth"
)

func TestGenerateTokenAndRoleCeiling(t *testing.T) {
	one, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	two, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if one == two || !HasTokenPrefix(one) || len(one) != 47 || HashToken(one) == one || len(HashToken(one)) != 64 {
		t.Fatal("token entropy, prefix or hash contract failed")
	}
	for _, tc := range []struct{ owner, cap, want auth.Role }{
		{auth.RoleAdmin, auth.RoleViewer, auth.RoleViewer},
		{auth.RoleOperator, auth.RoleAdmin, auth.RoleOperator},
		{auth.RoleViewer, auth.RoleOperator, auth.RoleViewer},
		{"", auth.RoleAdmin, ""},
		{auth.RoleAdmin, "invalid", ""},
	} {
		if got := EffectiveRole(tc.owner, tc.cap); got != tc.want {
			t.Errorf("EffectiveRole(%q,%q)=%q", tc.owner, tc.cap, got)
		}
	}
}
