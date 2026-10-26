package api

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
)

func TestRegistrationDelegationIsSeparateFromRole(t *testing.T) {
	s := &Server{}
	for _, test := range []struct {
		name    string
		session auth.Session
		want    bool
	}{
		{"service without delegation", auth.Session{Service: true, Subject: uuid.NewString(), Role: auth.RoleOperator}, false},
		{"delegated service", auth.Session{Service: true, Role: auth.RoleOperator, Permissions: []string{servicetoken.PermissionCreateConnections}}, true},
		{"personal viewer", auth.Session{APIKeyID: uuid.NewString(), Role: auth.RoleViewer, OwnerRole: auth.RoleAdmin}, false},
		{"personal admin", auth.Session{APIKeyID: uuid.NewString(), Role: auth.RoleAdmin}, true},
		{"cookie uses existing admin create workflow", auth.Session{Role: auth.RoleAdmin}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := s.canRegisterConnections(context.Background(), test.session)
			if err != nil || got != test.want {
				t.Fatalf("got %v/%v, want %v", got, err, test.want)
			}
		})
	}
}

func TestPersonalReadOnlyKeyRetainsOperatorOwnerScope(t *testing.T) {
	s := &Server{scopeEnforcement: policy.EnforcementDisabled}
	if !s.scopeApplies(auth.Session{APIKeyID: uuid.NewString(), Role: auth.RoleViewer, OwnerRole: auth.RoleOperator}) {
		t.Fatal("read-only delegation must not widen owner scope")
	}
	if !s.scopeApplies(auth.Session{APIKeyID: uuid.NewString(), Role: auth.RoleAdmin, OwnerRole: auth.RoleAdmin, Environments: []string{"test"}}) {
		t.Fatal("admin key environment restriction must still apply")
	}
	if s.scopeApplies(auth.Session{Role: auth.RoleViewer}) {
		t.Fatal("legacy human viewer policy changed")
	}
}

func TestCredentialOwnerDoesNotTreatHumanSubjectAsPrincipal(t *testing.T) {
	subject := uuid.NewString()
	if _, _, ok := SessionCredentialOwner(auth.Session{Subject: subject, Role: auth.RoleAdmin}); ok {
		t.Fatal("browser OIDC subject is not a service principal")
	}
	kind, id, ok := SessionCredentialOwner(auth.Session{Subject: subject, Service: true})
	if !ok || kind != "service" || id != subject {
		t.Fatal("service owner not retained")
	}
	userID := uuid.NewString()
	kind, id, ok = SessionCredentialOwner(auth.Session{APIKeyID: uuid.NewString(), APIUserID: userID, Subject: subject})
	if !ok || kind != "user" || id != userID {
		t.Fatal("personal owner must use control-plane user ID")
	}
}
