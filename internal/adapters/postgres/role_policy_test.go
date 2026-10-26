package postgres

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

func testRolePolicyTemplate() postgresconfig.RolePolicyTemplate {
	return postgresconfig.RolePolicyTemplate{
		Key: "app-read", Name: "Application read", Description: "Read application data",
		RoleName: "r_app", Database: "app", Schemas: []string{"public"},
		OwnerRoles: []string{"app_owner"}, CreatorRoles: []string{"app_creator"},
		Profile: postgresconfig.ProfileRead,
	}
}

func TestRolePolicySpecRoundTrip(t *testing.T) {
	want := postgresconfig.Normalize(testRolePolicyTemplate())
	got, err := rolePolicyTemplate(ptr(rolePolicySpec(want)))
	if err != nil {
		t.Fatalf("rolePolicyTemplate: %v", err)
	}
	if postgresconfig.Fingerprint(got) != postgresconfig.Fingerprint(want) {
		t.Fatalf("round trip = %+v, want %+v", got, want)
	}
}

func TestRolePolicyFingerprintSameCanonicalDomain(t *testing.T) {
	template := testRolePolicyTemplate()
	state := newRolePolicyState(template)
	addStaticExpectedState(state, template)
	state.expected["role:admin_not_member:grantor_admin"] = struct{}{}
	for value := range state.expected {
		state.actual[value] = struct{}{}
	}
	if fingerprintPolicyTokens(state.expected) != fingerprintPolicyTokens(state.actual) {
		t.Fatal("exact expected/actual sets must have byte-identical fingerprints")
	}
	state.actual["acl:unexpected"] = struct{}{}
	if fingerprintPolicyTokens(state.expected) == fingerprintPolicyTokens(state.actual) {
		t.Fatal("extra ACL must change the observed fingerprint")
	}
}

func TestRolePolicyDiffPreviewIsBounded(t *testing.T) {
	values := make([]string, rolePolicyPreviewLimit+7)
	for i := range values {
		values[i] = strings.Repeat("x", i+1)
	}
	preview, truncated := previewPolicyTokens(values)
	if len(preview) != rolePolicyPreviewLimit || !truncated {
		t.Fatalf("preview len/truncated = %d/%v, want %d/true", len(preview), truncated, rolePolicyPreviewLimit)
	}
}

func TestConfiguredPolicyPermissionStartsNonassignable(t *testing.T) {
	policy := adapter.ObservedRolePolicy{
		ExternalID: "role:r_app",
		Spec:       adapter.RolePolicySpec{Key: "app-read", RoleName: "r_app"},
		Exact:      true, ApplySupported: true,
	}
	permissions := annotateRolePolicyPermissions([]adapter.ObservedPermission{{
		ExternalID: "role:r_app", Name: "r_app", Assignable: true,
		Attributes: map[string]any{"can_login": false},
	}}, []adapter.ObservedRolePolicy{policy})
	if len(permissions) != 1 || permissions[0].Assignable {
		t.Fatalf("permissions = %+v, configured policy role must await managed+synced core state", permissions)
	}
	if permissions[0].Attributes["role_policy_exact"] != true {
		t.Fatalf("permission attributes = %v", permissions[0].Attributes)
	}
}

func TestMissingConfiguredPolicyPublishesNonassignablePermission(t *testing.T) {
	permissions := annotateRolePolicyPermissions(nil, []adapter.ObservedRolePolicy{{
		ExternalID:    "role:r_missing",
		Spec:          adapter.RolePolicySpec{Key: "missing", RoleName: "r_missing"},
		BlockedReason: "superuser_required",
	}})
	if len(permissions) != 1 || permissions[0].ExternalID != "role:r_missing" || permissions[0].Assignable {
		t.Fatalf("permissions = %+v", permissions)
	}
}

func TestStructuralAdminMembershipIsVisibleDrift(t *testing.T) {
	template := testRolePolicyTemplate()
	state := newRolePolicyState(template)
	addStaticExpectedState(state, template)
	state.expected["role:admin_not_member:grantor_admin"] = struct{}{}
	for token := range state.expected {
		state.actual[token] = struct{}{}
	}
	delete(state.actual, "role:admin_not_member:grantor_admin")
	state.actual["role:admin_membership:grantor_admin:grantor:spostgres:admin:true:inherit:false:set:false"] = struct{}{}
	state.finish()
	if len(state.missing) != 1 || len(state.extra) != 1 ||
		fingerprintPolicyTokens(state.expected) == fingerprintPolicyTokens(state.actual) {
		t.Fatalf("membership drift missing=%v extra=%v", state.missing, state.extra)
	}
}

func TestRolePolicyCapabilityRequiresMatchingDiscoveredCatalog(t *testing.T) {
	template := testRolePolicyTemplate()
	cfg := adapter.Connection{Engine: Engine, ConfigIncarnation: strings.Repeat("a", 64), Attributes: map[string]any{
		postgresconfig.AttributeRolePolicyTemplates: []postgresconfig.RolePolicyTemplate{template},
	}}
	ad := New()
	withoutTopology := ad.CapabilitiesFor(cfg, nil)
	for _, forbidden := range []adapter.Capability{
		adapter.CapAccountCreate, adapter.CapAccountRestore, adapter.CapRoleCreate,
		adapter.ResourceCapability("create", resourceKindDatabase),
		adapter.CapPostgresSuperuserDirectV1,
	} {
		if slices.Contains(withoutTopology, forbidden) {
			t.Errorf("phase-1 capabilities unexpectedly contain %q", forbidden)
		}
	}
	for _, preserved := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
	} {
		if !slices.Contains(withoutTopology, preserved) {
			t.Errorf("phase-1 capabilities lost %q", preserved)
		}
	}
	if slices.Contains(withoutTopology, adapter.CapRolePolicyApply) {
		t.Fatal("role.policy.apply must be absent before SUPERUSER-direct executor delivery")
	}
	if slices.Contains(withoutTopology, adapter.CapRolePolicyCreate) {
		t.Fatal("role.policy.create must be absent before SUPERUSER-direct executor delivery")
	}
	topology := map[string]any{
		rolePolicyCatalogFingerprintKey: postgresconfig.CatalogFingerprint([]postgresconfig.RolePolicyTemplate{template}),
		rolePolicyApplySupportedKey:     true,
	}
	if slices.Contains(ad.CapabilitiesFor(cfg, topology), adapter.CapRolePolicyApply) {
		t.Fatal("stale helper-era topology must not enable role.policy.apply")
	}
	topology[rolePolicyCreateSupportedKey] = true
	if slices.Contains(ad.CapabilitiesFor(cfg, topology), adapter.CapRolePolicyCreate) {
		t.Fatal("helper-era create attestation must remain fail-closed")
	}
	topology[adapter.PostgresProvisioningAuthorityTopologyKey] = adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: time.Now(), ExpectedAdminIdentity: "grantor_admin", ObservedAdminIdentity: "grantor_admin",
		CredentialIncarnation: 7, ConfigIncarnation: cfg.ConfigIncarnation,
		TargetIdentity: "postgres:system:42",
	}
	confirmed := ad.CapabilitiesFor(cfg, topology)
	for _, capability := range []adapter.Capability{
		adapter.CapPostgresSuperuserDirectV1, adapter.CapAccountCreate, adapter.CapAccountRestore,
		adapter.CapRoleCreate, adapter.ResourceCapability("create", resourceKindDatabase),
		adapter.CapRolePolicyApply, adapter.CapRolePolicyCreate,
	} {
		if !slices.Contains(confirmed, capability) {
			t.Errorf("confirmed SUPERUSER capabilities lost %q: %v", capability, confirmed)
		}
	}
	template.Profile = postgresconfig.ProfileReadWrite
	cfg.Attributes[postgresconfig.AttributeRolePolicyTemplates] = []postgresconfig.RolePolicyTemplate{template}
	if slices.Contains(ad.CapabilitiesFor(cfg, topology), adapter.CapRolePolicyApply) {
		t.Fatal("stale topology must not authorize a patched catalog")
	}
	if slices.Contains(ad.CapabilitiesFor(cfg, topology), adapter.CapRolePolicyCreate) {
		t.Fatal("stale topology must not enable create-only")
	}
}

func ptr[T any](value T) *T { return &value }
