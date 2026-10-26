package adapter

import (
	"bytes"
	"encoding/json"
	"io"
	"time"
)

const PostgresProvisioningAuthorityTopologyKey = "postgres_provisioning_authority"

type ProvisioningAuthorityStatus string

const (
	ProvisioningAuthorityConfirmed             ProvisioningAuthorityStatus = "confirmed"
	ProvisioningAuthorityInsufficient          ProvisioningAuthorityStatus = "insufficient"
	ProvisioningAuthorityUnknown               ProvisioningAuthorityStatus = "unknown"
	ProvisioningAuthorityInvalidCurrentVersion ProvisioningAuthorityStatus = "invalid_current_version"
)

type ProvisioningAuthorityReason string

const (
	ProvisioningAuthoritySuperuserConfirmed           ProvisioningAuthorityReason = "superuser_confirmed"
	ProvisioningAuthoritySuperuserRequired            ProvisioningAuthorityReason = "superuser_required"
	ProvisioningAuthorityAdminIdentityMismatch        ProvisioningAuthorityReason = "admin_identity_mismatch"
	ProvisioningAuthorityProbeFailed                  ProvisioningAuthorityReason = "authority_probe_failed"
	ProvisioningAuthorityAdminCredentialMissing       ProvisioningAuthorityReason = "admin_credential_missing"
	ProvisioningAuthorityCredentialIncarnationMissing ProvisioningAuthorityReason = "credential_incarnation_missing"
	ProvisioningAuthorityConfigIncarnationMissing     ProvisioningAuthorityReason = "config_incarnation_missing"
	ProvisioningAuthorityCredentialIncarnationChanged ProvisioningAuthorityReason = "credential_incarnation_changed"
	ProvisioningAuthorityConfigIncarnationChanged     ProvisioningAuthorityReason = "config_incarnation_changed"
	ProvisioningAuthorityConnectionSnapshotNotActive  ProvisioningAuthorityReason = "connection_snapshot_not_active"
	ProvisioningAuthorityTargetIdentityUnavailable    ProvisioningAuthorityReason = "target_identity_unavailable"
	ProvisioningAuthorityReadOnlyTarget               ProvisioningAuthorityReason = "read_only_target"
)

// ProvisioningAuthorityAssessment is the shared backend/API contract for a
// discovery-time authority proof. It is an early fail-closed preflight, never
// a substitute for the adapter's live proof immediately before mutation.
type ProvisioningAuthorityAssessment struct {
	Status                ProvisioningAuthorityStatus `json:"status"`
	Reason                ProvisioningAuthorityReason `json:"reason"`
	ObservedAt            time.Time                   `json:"observed_at"`
	ExpectedAdminIdentity string                      `json:"expected_admin_identity"`
	ObservedAdminIdentity string                      `json:"observed_admin_identity"`
	CredentialIncarnation int                         `json:"credential_incarnation"`
	ConfigIncarnation     string                      `json:"config_incarnation"`
	TargetIdentity        string                      `json:"target_identity"`
}

func (a ProvisioningAuthorityAssessment) ValidStatus() bool {
	switch a.Status {
	case ProvisioningAuthorityConfirmed, ProvisioningAuthorityInsufficient,
		ProvisioningAuthorityUnknown, ProvisioningAuthorityInvalidCurrentVersion:
		return true
	default:
		return false
	}
}

func (a ProvisioningAuthorityAssessment) validReason() bool {
	switch a.Reason {
	case ProvisioningAuthoritySuperuserConfirmed,
		ProvisioningAuthoritySuperuserRequired,
		ProvisioningAuthorityAdminIdentityMismatch,
		ProvisioningAuthorityProbeFailed,
		ProvisioningAuthorityAdminCredentialMissing,
		ProvisioningAuthorityCredentialIncarnationMissing,
		ProvisioningAuthorityConfigIncarnationMissing,
		ProvisioningAuthorityCredentialIncarnationChanged,
		ProvisioningAuthorityConfigIncarnationChanged,
		ProvisioningAuthorityConnectionSnapshotNotActive,
		ProvisioningAuthorityTargetIdentityUnavailable,
		ProvisioningAuthorityReadOnlyTarget:
		return true
	default:
		return false
	}
}

// validTopology enforces the closed discovery-time wire contract. Reasons
// produced only while projecting a stored snapshot against current metadata
// are deliberately not accepted back from topology.
func (a ProvisioningAuthorityAssessment) validTopology() bool {
	if !a.ValidStatus() || !a.validReason() || a.ObservedAt.IsZero() ||
		a.CredentialIncarnation < 0 || !validProvisioningConfigIncarnation(a.ConfigIncarnation) {
		return false
	}

	credentialMissing := a.Reason == ProvisioningAuthorityAdminCredentialMissing ||
		a.Reason == ProvisioningAuthorityCredentialIncarnationMissing
	if credentialMissing != (a.CredentialIncarnation == 0) {
		return false
	}
	configMissing := a.Reason == ProvisioningAuthorityConfigIncarnationMissing
	if configMissing != (a.ConfigIncarnation == "") {
		return false
	}

	sameKnownIdentity := a.ExpectedAdminIdentity != "" &&
		a.ObservedAdminIdentity == a.ExpectedAdminIdentity
	switch a.Status {
	case ProvisioningAuthorityConfirmed:
		return a.Reason == ProvisioningAuthoritySuperuserConfirmed &&
			sameKnownIdentity && a.TargetIdentity != ""
	case ProvisioningAuthorityInsufficient:
		return a.Reason == ProvisioningAuthoritySuperuserRequired && sameKnownIdentity
	case ProvisioningAuthorityUnknown:
		switch a.Reason {
		case ProvisioningAuthorityAdminCredentialMissing:
			return a.ExpectedAdminIdentity == ""
		case ProvisioningAuthorityCredentialIncarnationMissing,
			ProvisioningAuthorityConfigIncarnationMissing,
			ProvisioningAuthorityProbeFailed:
			return a.ExpectedAdminIdentity != ""
		case ProvisioningAuthorityTargetIdentityUnavailable:
			return sameKnownIdentity && a.TargetIdentity == ""
		default:
			return false
		}
	case ProvisioningAuthorityInvalidCurrentVersion:
		switch a.Reason {
		case ProvisioningAuthorityAdminIdentityMismatch:
			// current_user can differ from session_user; only session_user is
			// exposed by this safe projection, so equality cannot disprove the
			// mismatch observed by the live two-identity probe.
			return a.ExpectedAdminIdentity != "" && a.ObservedAdminIdentity != ""
		case ProvisioningAuthorityReadOnlyTarget:
			return sameKnownIdentity && a.TargetIdentity != ""
		default:
			return false
		}
	default:
		return false
	}
}

func validProvisioningConfigIncarnation(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// ProvisioningAuthorityFromTopology parses a topology value through JSON so
// it accepts both the typed struct written by an in-process adapter and the
// map[string]any obtained after metadata JSONB round-trip.
func ProvisioningAuthorityFromTopology(topology map[string]any, key string) (ProvisioningAuthorityAssessment, bool) {
	if topology == nil {
		return ProvisioningAuthorityAssessment{}, false
	}
	raw, ok := topology[key]
	if !ok {
		return ProvisioningAuthorityAssessment{}, false
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return ProvisioningAuthorityAssessment{}, false
	}
	var out ProvisioningAuthorityAssessment
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil || !out.validTopology() {
		return ProvisioningAuthorityAssessment{}, false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ProvisioningAuthorityAssessment{}, false
	}
	return out, true
}

// ValidateSnapshot checks that the discovery proof belongs to the connection
// snapshot currently exposed by metadata. It intentionally does not compare a
// Vault version: Connection has no canonical Vault-version marker. Mutating
// paths must load the current credential and perform their independent live
// proof before a target side effect.
func (a ProvisioningAuthorityAssessment) ValidateSnapshot(
	expectedAdminIdentity string,
	configIncarnation string,
	lastDiscoveryAt *time.Time,
) ProvisioningAuthorityAssessment {
	out := a
	switch {
	case out.ExpectedAdminIdentity != expectedAdminIdentity:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityAdminIdentityMismatch
	case configIncarnation == "":
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityConfigIncarnationMissing
	case !validProvisioningConfigIncarnation(configIncarnation) ||
		out.ConfigIncarnation != configIncarnation:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityConfigIncarnationChanged
	case lastDiscoveryAt == nil || !sameDiscoveryInstant(out.ObservedAt, *lastDiscoveryAt):
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityConnectionSnapshotNotActive
	}
	return out
}

func sameDiscoveryInstant(a, b time.Time) bool {
	delta := a.Sub(b)
	if delta < 0 {
		delta = -delta
	}
	// PostgreSQL timestamptz has microsecond precision while the same instant
	// embedded in topology JSON may retain Go nanoseconds.
	return delta < time.Microsecond
}

func (a ProvisioningAuthorityAssessment) ValidateCurrent(
	expectedAdminIdentity string,
	credentialIncarnation int,
	configIncarnation string,
) ProvisioningAuthorityAssessment {
	out := a
	switch {
	case expectedAdminIdentity == "" || out.ExpectedAdminIdentity == "" ||
		out.ExpectedAdminIdentity != expectedAdminIdentity:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityAdminIdentityMismatch
	case credentialIncarnation <= 0 || out.CredentialIncarnation <= 0:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityCredentialIncarnationMissing
	case out.CredentialIncarnation != credentialIncarnation:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityCredentialIncarnationChanged
	case configIncarnation == "" || out.ConfigIncarnation == "":
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityConfigIncarnationMissing
	case !validProvisioningConfigIncarnation(configIncarnation) ||
		out.ConfigIncarnation != configIncarnation:
		out.Status = ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = ProvisioningAuthorityConfigIncarnationChanged
	}
	return out
}
