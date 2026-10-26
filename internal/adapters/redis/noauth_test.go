package redis

import (
	"context"
	"slices"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestNoAuthIsExplicitAndNeverCarriesPassword(t *testing.T) {
	for _, cfg := range []adapter.Connection{
		{AuthMode: "none", AdminCredential: adapter.Credential{Secret: []byte("fixture")}},
		{AuthMode: "none", AdminCredential: adapter.Credential{Username: "another"}},
		{AuthMode: "password", AdminCredential: adapter.Credential{Kind: "none"}},
		{AuthMode: "unknown"},
	} {
		cfg.Endpoints = []string{"127.0.0.1:6379"}
		if _, err := newClient(cfg); err == nil {
			t.Fatal("invalid authentication configuration accepted")
		}
	}
	cfg := adapter.Connection{Endpoints: []string{"127.0.0.1:6379"}, AuthMode: "none", AdminCredential: adapter.Credential{Kind: "none", Username: "default"}}
	client, err := newClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	if client.rdb.Options().Username != "" || client.rdb.Options().Password != "" {
		t.Fatal("no-auth client would send credentials")
	}
}

func TestNoAuthAllowsInventoryAndRecoverySwitchOnly(t *testing.T) {
	a := New()
	cfg := adapter.Connection{AuthMode: "none", AdminCredential: adapter.Credential{Kind: "none", Username: "default"}}
	caps := a.CapabilitiesFor(cfg, map[string]any{adapter.TopologyAdminCredentialSwitchSupported: true, adapter.TopologyAdminCredentialRotateSupported: true})
	if len(caps) != 4 || !slices.Contains(caps, adapter.CapConnectionAdminCredentialSwitch) {
		t.Fatalf("unsafe no-auth capabilities: %v", caps)
	}
	for _, capability := range caps {
		if capability != adapter.CapConnectionAdminCredentialSwitch && capability != adapter.CapInventoryAccounts && capability != adapter.CapInventoryPermissions && capability != adapter.CapInventoryBindings {
			t.Fatalf("unexpected mutation %s", capability)
		}
	}
	change := adapter.DesiredChange{Kind: adapter.ChangeAccountCreate, Connection: cfg}
	if _, err := a.Plan(context.Background(), change); err == nil {
		t.Fatal("no-auth plan accepted")
	}
	if _, err := a.Apply(context.Background(), adapter.Plan{Change: change}); err == nil {
		t.Fatal("no-auth apply accepted")
	}
	if err := a.RotateCredential(context.Background(), cfg, adapter.Account{}, adapter.Credential{}); err == nil {
		t.Fatal("no-auth account rotation accepted")
	}
	if err := a.ProveCredential(context.Background(), cfg, adapter.Account{}, adapter.Credential{}); err == nil {
		t.Fatal("no-auth account proof accepted")
	}
	if _, err := a.RotateConnectionAdminCredential(context.Background(), cfg, adapter.Credential{}, adapter.AdminCredentialProof{}); err == nil {
		t.Fatal("no-auth admin rotation accepted")
	}
}
