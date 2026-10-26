package postgres

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

type postgresAdminAuthorityProbe struct {
	sessionUser string
	currentUser string
	superuser   bool
	inRecovery  bool
	readOnly    bool
	ok          bool
}

// observePostgresAdminAuthority publishes a typed, secret-free attestation of
// the exact administrator identity and credential/config incarnation used by
// this discovery. It is advisory for API/UI preflight only: mutating paths
// repeat the live proof immediately before their first target side effect.
func observePostgresAdminAuthority(
	ctx context.Context,
	conn *pgx.Conn,
	cfg adapter.Connection,
	observedAt time.Time,
	systemIdentifier string,
) adapter.ProvisioningAuthorityAssessment {
	var probe postgresAdminAuthorityProbe
	if err := conn.QueryRow(ctx, `
		select session_user, current_user, coalesce((
			select rolsuper from pg_catalog.pg_roles where rolname = session_user
		), false), pg_is_in_recovery(), current_setting('transaction_read_only')::boolean`).
		Scan(&probe.sessionUser, &probe.currentUser, &probe.superuser, &probe.inRecovery, &probe.readOnly); err == nil {
		probe.ok = true
	}
	return classifyPostgresAdminAuthority(cfg, observedAt, systemIdentifier, probe)
}

func classifyPostgresAdminAuthority(
	cfg adapter.Connection,
	observedAt time.Time,
	systemIdentifier string,
	probe postgresAdminAuthorityProbe,
) adapter.ProvisioningAuthorityAssessment {
	expected := cfg.AdminCredential.Username
	out := adapter.ProvisioningAuthorityAssessment{
		Status:     adapter.ProvisioningAuthorityUnknown,
		Reason:     adapter.ProvisioningAuthorityAdminCredentialMissing,
		ObservedAt: observedAt.UTC(), ExpectedAdminIdentity: expected,
		ObservedAdminIdentity: probe.sessionUser,
		CredentialIncarnation: cfg.AdminCredentialIncarnation,
		ConfigIncarnation:     cfg.ConfigIncarnation,
	}
	if systemIdentifier != "" {
		out.TargetIdentity = "postgres:system:" + systemIdentifier
	}
	switch {
	case expected == "":
		return out
	case cfg.AdminCredentialIncarnation <= 0:
		out.Reason = adapter.ProvisioningAuthorityCredentialIncarnationMissing
		return out
	case cfg.ConfigIncarnation == "":
		out.Reason = adapter.ProvisioningAuthorityConfigIncarnationMissing
		return out
	case !probe.ok:
		out.Reason = adapter.ProvisioningAuthorityProbeFailed
		return out
	case probe.sessionUser != expected || probe.currentUser != expected:
		out.Status = adapter.ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = adapter.ProvisioningAuthorityAdminIdentityMismatch
		return out
	case !probe.superuser:
		out.Status = adapter.ProvisioningAuthorityInsufficient
		out.Reason = adapter.ProvisioningAuthoritySuperuserRequired
		return out
	case systemIdentifier == "":
		out.Reason = adapter.ProvisioningAuthorityTargetIdentityUnavailable
		return out
	case probe.inRecovery || probe.readOnly:
		out.Status = adapter.ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = adapter.ProvisioningAuthorityReadOnlyTarget
		return out
	default:
		out.Status = adapter.ProvisioningAuthorityConfirmed
		out.Reason = adapter.ProvisioningAuthoritySuperuserConfirmed
		return out
	}
}
