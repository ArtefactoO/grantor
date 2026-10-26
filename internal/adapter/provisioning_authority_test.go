package adapter

import (
	"strings"
	"testing"
	"time"
)

func TestProvisioningAuthorityRoundTripAndCurrentValidation(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	configV1 := strings.Repeat("a", 64)
	configV2 := strings.Repeat("b", 64)
	want := ProvisioningAuthorityAssessment{
		Status: ProvisioningAuthorityConfirmed, Reason: ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
		CredentialIncarnation: 7, ConfigIncarnation: configV1,
		TargetIdentity: "postgres:system:123",
	}
	topology := map[string]any{PostgresProvisioningAuthorityTopologyKey: want}
	got, ok := ProvisioningAuthorityFromTopology(topology, PostgresProvisioningAuthorityTopologyKey)
	if !ok || got != want {
		t.Fatalf("assessment = %+v, %v; want %+v, true", got, ok, want)
	}
	if got = got.ValidateCurrent("grantor", 7, configV1); got != want {
		t.Fatalf("current assessment changed: %+v", got)
	}
	if got = got.ValidateSnapshot("grantor", configV1, &now); got != want {
		t.Fatalf("current snapshot assessment changed: %+v", got)
	}
	for name, got := range map[string]ProvisioningAuthorityReason{
		"identity":   want.ValidateCurrent("other", 7, configV1).Reason,
		"credential": want.ValidateCurrent("grantor", 8, configV1).Reason,
		"config":     want.ValidateCurrent("grantor", 7, configV2).Reason,
		"snapshot":   want.ValidateSnapshot("grantor", configV1, nil).Reason,
	} {
		if got == "" || got == ProvisioningAuthoritySuperuserConfirmed {
			t.Fatalf("%s mismatch stayed confirmed: %q", name, got)
		}
	}
}

func TestProvisioningAuthorityMalformedFailsClosed(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	valid := map[string]any{
		"status": "confirmed", "reason": "superuser_confirmed",
		"observed_at":             now.Format(time.RFC3339Nano),
		"expected_admin_identity": "grantor", "observed_admin_identity": "grantor",
		"credential_incarnation": 7, "config_incarnation": strings.Repeat("a", 64),
		"target_identity": "postgres:system:123",
	}
	with := func(key string, value any) map[string]any {
		copyValue := make(map[string]any, len(valid)+1)
		for field, fieldValue := range valid {
			copyValue[field] = fieldValue
		}
		copyValue[key] = value
		return map[string]any{PostgresProvisioningAuthorityTopologyKey: copyValue}
	}
	for name, topology := range map[string]map[string]any{
		"nil":                 nil,
		"scalar":              {PostgresProvisioningAuthorityTopologyKey: "confirmed"},
		"unknown status":      with("status", "future"),
		"unknown reason":      with("reason", "future"),
		"unknown field":       with("raw_sql", "select 1"),
		"zero observed at":    with("observed_at", time.Time{}.Format(time.RFC3339Nano)),
		"zero credential":     with("credential_incarnation", 0),
		"negative credential": with("credential_incarnation", -1),
		"malformed config":    with("config_incarnation", "not-a-sha256"),
		"uppercase config":    with("config_incarnation", strings.Repeat("A", 64)),
		"confirmed mismatch":  with("observed_admin_identity", "other"),
		"confirmed no target": with("target_identity", ""),
		"status reason clash": with("reason", "superuser_required"),
	} {
		t.Run(name, func(t *testing.T) {
			if got, ok := ProvisioningAuthorityFromTopology(topology, PostgresProvisioningAuthorityTopologyKey); ok {
				t.Fatalf("malformed assessment parsed: %+v", got)
			}
		})
	}
}

func TestProvisioningAuthorityClosedStatusReasonMatrix(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	config := strings.Repeat("a", 64)
	valid := []ProvisioningAuthorityAssessment{
		{Status: ProvisioningAuthorityConfirmed, Reason: ProvisioningAuthoritySuperuserConfirmed,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 7, ConfigIncarnation: config, TargetIdentity: "postgres:system:123"},
		{Status: ProvisioningAuthorityInsufficient, Reason: ProvisioningAuthoritySuperuserRequired,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 7, ConfigIncarnation: config},
		{Status: ProvisioningAuthorityUnknown, Reason: ProvisioningAuthorityProbeFailed,
			ObservedAt: now, ExpectedAdminIdentity: "grantor",
			CredentialIncarnation: 7, ConfigIncarnation: config},
		{Status: ProvisioningAuthorityUnknown, Reason: ProvisioningAuthorityAdminCredentialMissing,
			ObservedAt: now, ConfigIncarnation: config},
		{Status: ProvisioningAuthorityUnknown, Reason: ProvisioningAuthorityCredentialIncarnationMissing,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ConfigIncarnation: config},
		{Status: ProvisioningAuthorityUnknown, Reason: ProvisioningAuthorityConfigIncarnationMissing,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", CredentialIncarnation: 7},
		{Status: ProvisioningAuthorityUnknown, Reason: ProvisioningAuthorityTargetIdentityUnavailable,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 7, ConfigIncarnation: config},
		{Status: ProvisioningAuthorityInvalidCurrentVersion, Reason: ProvisioningAuthorityAdminIdentityMismatch,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "other",
			CredentialIncarnation: 7, ConfigIncarnation: config},
		{Status: ProvisioningAuthorityInvalidCurrentVersion, Reason: ProvisioningAuthorityReadOnlyTarget,
			ObservedAt: now, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
			CredentialIncarnation: 7, ConfigIncarnation: config, TargetIdentity: "postgres:system:123"},
	}
	for _, assessment := range valid {
		topology := map[string]any{PostgresProvisioningAuthorityTopologyKey: assessment}
		if got, ok := ProvisioningAuthorityFromTopology(topology, PostgresProvisioningAuthorityTopologyKey); !ok || got != assessment {
			t.Fatalf("valid assessment rejected: %+v/%v, want %+v", got, ok, assessment)
		}
	}
}

func TestProvisioningAuthoritySnapshotAllowsPostgresTimestampPrecision(t *testing.T) {
	observed := time.Date(2026, 8, 27, 10, 0, 0, 499, time.UTC)
	stored := observed.Add(-499 * time.Nanosecond)
	assessment := ProvisioningAuthorityAssessment{
		Status: ProvisioningAuthorityConfirmed, Reason: ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: observed, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor",
		CredentialIncarnation: 7, ConfigIncarnation: strings.Repeat("a", 64),
		TargetIdentity: "postgres:system:123",
	}
	if got := assessment.ValidateSnapshot("grantor", assessment.ConfigIncarnation, &stored); got != assessment {
		t.Fatalf("PostgreSQL timestamp precision invalidated snapshot: %+v", got)
	}
	tooOld := observed.Add(-time.Microsecond)
	if got := assessment.ValidateSnapshot("grantor", assessment.ConfigIncarnation, &tooOld); got.Reason != ProvisioningAuthorityConnectionSnapshotNotActive {
		t.Fatalf("different snapshot remained current: %+v", got)
	}
}
