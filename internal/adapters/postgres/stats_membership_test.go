package postgres

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestStatsBuiltinIsPermissionOnlyAndOtherSystemRolesRemainHidden(t *testing.T) {
	accounts, permissions := rolesToObserved([]roleInfo{{name: StatsRole, oid: 3375}, {name: "pg_monitor", oid: 3373},
		{name: "ordinary_login", oid: 17000, canLogin: true}}, time.Now())
	if len(accounts) != 1 || accounts[0].EngineIdentity != "ordinary_login" {
		t.Fatal("system role became an account lifecycle target")
	}
	if len(permissions) != 2 {
		t.Fatal("system catalog widened beyond the statistics builtin")
	}
	for _, p := range permissions {
		if p.Name == StatsRole && (!p.Assignable || p.AccountEngineIdentity != "" || p.Attributes["protected_builtin"] != true) {
			t.Fatal("statistics builtin is not a protected permission-only entry")
		}
	}
}

func TestProtectedSystemRoleLifecycleFailsBeforeTransport(t *testing.T) {
	a := NewWithDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("protected lifecycle touched transport")
		return nil, nil
	})
	for _, kind := range []adapter.ChangeKind{adapter.ChangeAccountCreate, adapter.ChangeAccountDelete, adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountRestore, adapter.ChangeRoleCreate, adapter.ChangeGrant} {
		if _, err := a.Plan(t.Context(), adapter.DesiredChange{Kind: kind, Account: adapter.Account{Kind: "login", EngineIdentity: StatsRole}}); !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Fatalf("system role mutation %s accepted: %v", kind, err)
		}
	}
	if _, err := a.Plan(t.Context(), adapter.DesiredChange{Kind: adapter.ChangeGrant, Account: adapter.Account{Kind: "login", EngineIdentity: "monitor"}, Permission: StatsPermission}); !errors.Is(err, ErrStatsMembershipUnsupported) {
		t.Fatal("legacy unpinned statistics grant accepted")
	}
}

func TestStatsMembershipUnavailableTransportNeverVerifiesOrSkips(t *testing.T) {
	a := NewWithDialer(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("fixture unavailable") })
	cfg := testConnection("disabled")
	cfg.ConfigIncarnation, cfg.AdminCredentialIncarnation = "stats-config", 1
	pins := StatsMembershipPins{AdminIdentity: cfg.AdminCredential.Username, TargetIdentity: "postgres:system:42", ConfigIncarnation: cfg.ConfigIncarnation,
		CredentialIncarnation: 1, BuiltinOID: 3375, SubjectOID: 17001}
	for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresStatsMembershipGrantV1, adapter.ChangePostgresStatsMembershipRevokeV1} {
		change := adapter.DesiredChange{Kind: kind, Connection: cfg, Account: adapter.Account{Kind: "login", EngineIdentity: "monitor"}, Permission: StatsPermission,
			StatsMembership: &pins, ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity}
		if _, err := a.Plan(t.Context(), change); err == nil {
			t.Fatal("offline target accepted a plan")
		}
		plan := adapter.Plan{Change: change, Steps: []adapter.PlanStep{{Kind: stepGrant}}}
		if _, err := a.Apply(t.Context(), plan); err == nil {
			t.Fatal("offline target returned successful apply")
		}
		if _, err := a.Verify(t.Context(), plan); err == nil {
			t.Fatal("offline target returned successful read-back")
		}
	}
}

func TestLegacyStatsAttributesCannotAuthorizeProtectedMembership(t *testing.T) {
	a := NewWithDialer(func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("legacy protected membership touched transport")
		return nil, nil
	})
	pins := StatsMembershipPins{AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "config",
		CredentialIncarnation: 1, BuiltinOID: 3375, SubjectOID: 17001}
	for _, kind := range []adapter.ChangeKind{adapter.ChangeGrant, adapter.ChangeRevoke} {
		change := adapter.DesiredChange{Kind: kind, Account: adapter.Account{Kind: "login", EngineIdentity: "monitor"}, Permission: StatsPermission, Attributes: pins.Attributes()}
		if _, err := a.Plan(t.Context(), change); !errors.Is(err, ErrStatsMembershipUnsupported) {
			t.Fatalf("legacy protected membership accepted: %v", err)
		}
		if _, err := a.Apply(t.Context(), adapter.Plan{Change: change, Steps: []adapter.PlanStep{{Kind: stepGrant}}}); !errors.Is(err, ErrStatsMembershipUnsupported) {
			t.Fatalf("legacy protected membership apply accepted: %v", err)
		}
	}
}
