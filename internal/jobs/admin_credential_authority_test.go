package jobs

import (
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

func TestRebindProvisioningAuthorityCredentialIncarnation(t *testing.T) {
	assessment := adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: time.Now(), ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
		CredentialIncarnation: 7, ConfigIncarnation: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		TargetIdentity: "postgres:system:42",
	}
	snapshot := &adapter.Snapshot{Topology: map[string]any{
		adapter.PostgresProvisioningAuthorityTopologyKey: assessment,
	}}
	if err := rebindProvisioningAuthorityCredentialIncarnation(snapshot, 8); err != nil {
		t.Fatalf("rebind: %v", err)
	}
	got, ok := adapter.ProvisioningAuthorityFromTopology(
		snapshot.Topology, adapter.PostgresProvisioningAuthorityTopologyKey,
	)
	if !ok || got.CredentialIncarnation != 8 {
		t.Fatalf("rebound assessment = %+v, ok=%v", got, ok)
	}
	if assessment.CredentialIncarnation != 7 {
		t.Fatal("rebind mutated caller-owned assessment")
	}
}

func TestRebindProvisioningAuthorityCredentialIncarnationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snapshot *adapter.Snapshot
		version  int
	}{
		{name: "missing snapshot", version: 2},
		{name: "missing version", snapshot: &adapter.Snapshot{}},
		{name: "malformed authority", version: 2, snapshot: &adapter.Snapshot{Topology: map[string]any{
			adapter.PostgresProvisioningAuthorityTopologyKey: map[string]any{"status": "confirmed"},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := rebindProvisioningAuthorityCredentialIncarnation(tc.snapshot, tc.version); err == nil {
				t.Fatal("rebind unexpectedly succeeded")
			}
		})
	}
}

func TestRebindProvisioningAuthorityCredentialIncarnationIgnoresOtherEngines(t *testing.T) {
	snapshot := &adapter.Snapshot{Topology: map[string]any{"engine": "mongodb"}}
	if err := rebindProvisioningAuthorityCredentialIncarnation(snapshot, 2); err != nil {
		t.Fatalf("other engine topology: %v", err)
	}
}

func TestRedisNoAuthSwitchRequiresMatchingTargetAndIndependentSnapshot(t *testing.T) {
	conn := connections.Connection{Engine: "redis", AuthMode: "password", Topology: []byte(`{"admin_credential_target_identity":"redis:run:expected-node"}`)}
	proof := adapter.AdminCredentialProof{CanonicalIdentity: "default", AuthorityFingerprint: "none-authority", TargetIdentity: "redis:run:other-node"}
	topology := map[string]any{"run_id": "other-node", "authentication_enabled": false}
	adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{SwitchSupported: true, CanonicalIdentity: proof.CanonicalIdentity, AuthorityFingerprint: proof.AuthorityFingerprint, TargetIdentity: proof.TargetIdentity})
	outcome := adminCredentialTargetOutcome{Proof: proof, Snapshot: &adapter.Snapshot{Topology: topology}}
	e := &MainExecutor{}
	if err := e.verifyAdminCredentialOutcomeFence(conn, admincredentials.Change{Mode: admincredentials.ModeSwitch}, outcome); !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("target mismatch accepted: %v", err)
	}
	outcome.Proof.TargetIdentity = "redis:run:expected-node"
	outcome.Snapshot.Topology["run_id"] = "expected-node"
	outcome.Snapshot.Topology[adapter.TopologyAdminCredentialTargetIdentity] = "redis:run:expected-node"
	outcome.Snapshot.Topology[adapter.TopologyAdminCredentialCanonicalIdentity] = "another-user"
	if err := e.verifyAdminCredentialOutcomeFence(conn, admincredentials.Change{Mode: admincredentials.ModeSwitch}, outcome); !errors.Is(err, adapter.ErrAdminCredentialAuthorityChanged) {
		t.Fatalf("independent identity mismatch accepted: %v", err)
	}
}
