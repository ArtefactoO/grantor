package postgres

import (
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestClassifyPostgresAdminAuthority(t *testing.T) {
	now := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	configIncarnation := strings.Repeat("a", 64)
	base := adapter.Connection{
		AdminCredential:            adapter.Credential{Username: "grantor"},
		AdminCredentialIncarnation: 7, ConfigIncarnation: configIncarnation,
	}
	confirmed := postgresAdminAuthorityProbe{
		sessionUser: "grantor", currentUser: "grantor", superuser: true, ok: true,
	}
	for _, tc := range []struct {
		name   string
		cfg    adapter.Connection
		system string
		probe  postgresAdminAuthorityProbe
		status adapter.ProvisioningAuthorityStatus
		reason adapter.ProvisioningAuthorityReason
	}{
		{name: "confirmed", cfg: base, system: "123", probe: confirmed,
			status: adapter.ProvisioningAuthorityConfirmed, reason: adapter.ProvisioningAuthoritySuperuserConfirmed},
		{name: "non superuser", cfg: base, system: "123", probe: postgresAdminAuthorityProbe{sessionUser: "grantor", currentUser: "grantor", ok: true},
			status: adapter.ProvisioningAuthorityInsufficient, reason: adapter.ProvisioningAuthoritySuperuserRequired},
		{name: "identity mismatch", cfg: base, system: "123", probe: postgresAdminAuthorityProbe{sessionUser: "other", currentUser: "other", superuser: true, ok: true},
			status: adapter.ProvisioningAuthorityInvalidCurrentVersion, reason: adapter.ProvisioningAuthorityAdminIdentityMismatch},
		{name: "probe failed", cfg: base, system: "123", probe: postgresAdminAuthorityProbe{},
			status: adapter.ProvisioningAuthorityUnknown, reason: adapter.ProvisioningAuthorityProbeFailed},
		{name: "target identity missing", cfg: base, probe: confirmed,
			status: adapter.ProvisioningAuthorityUnknown, reason: adapter.ProvisioningAuthorityTargetIdentityUnavailable},
		{name: "read only", cfg: base, system: "123", probe: postgresAdminAuthorityProbe{sessionUser: "grantor", currentUser: "grantor", superuser: true, readOnly: true, ok: true},
			status: adapter.ProvisioningAuthorityInvalidCurrentVersion, reason: adapter.ProvisioningAuthorityReadOnlyTarget},
		{name: "credential missing", cfg: adapter.Connection{ConfigIncarnation: configIncarnation}, system: "123", probe: confirmed,
			status: adapter.ProvisioningAuthorityUnknown, reason: adapter.ProvisioningAuthorityAdminCredentialMissing},
		{name: "credential incarnation missing", cfg: adapter.Connection{AdminCredential: adapter.Credential{Username: "grantor"}, ConfigIncarnation: configIncarnation}, system: "123", probe: confirmed,
			status: adapter.ProvisioningAuthorityUnknown, reason: adapter.ProvisioningAuthorityCredentialIncarnationMissing},
		{name: "config incarnation missing", cfg: adapter.Connection{AdminCredential: adapter.Credential{Username: "grantor"}, AdminCredentialIncarnation: 7}, system: "123", probe: confirmed,
			status: adapter.ProvisioningAuthorityUnknown, reason: adapter.ProvisioningAuthorityConfigIncarnationMissing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPostgresAdminAuthority(tc.cfg, now, tc.system, tc.probe)
			if got.Status != tc.status || got.Reason != tc.reason || !got.ObservedAt.Equal(now) {
				t.Fatalf("assessment = %+v, want status=%q reason=%q", got, tc.status, tc.reason)
			}
		})
	}
}
