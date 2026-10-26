package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

var _ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)

func (a *Adapter) AssessConnectionAdminCredential(
	ctx context.Context,
	cfg adapter.Connection,
) (adapter.AdminCredentialAssessment, error) {
	proof, inRecovery, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	assessment := adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: !inRecovery && proof.TargetIdentity != "",
		CanonicalIdentity:    proof.CanonicalIdentity,
		AuthorityFingerprint: proof.AuthorityFingerprint,
		TargetIdentity:       proof.TargetIdentity,
	}
	if inRecovery {
		assessment.BlockedReason = "read_only_replica"
	} else if proof.TargetIdentity == "" {
		assessment.BlockedReason = "target_identity_unavailable"
	}
	return assessment, nil
}

func (a *Adapter) ProveConnectionAdminCredential(
	ctx context.Context,
	cfg adapter.Connection,
	candidate adapter.Credential,
) (adapter.AdminCredentialProof, error) {
	proof, _, err := a.proveConnectionAdminCredential(ctx, cfg, candidate)
	return proof, err
}

func (a *Adapter) RotateConnectionAdminCredential(
	ctx context.Context,
	cfg adapter.Connection,
	candidate adapter.Credential,
	expected adapter.AdminCredentialProof,
) (adapter.AdminCredentialRotationResult, error) {
	return adapter.RunCandidateFirstAdminCredentialRotation(ctx, cfg.AdminCredential, candidate, expected,
		adapter.AdminCredentialRotationHooks{
			Prove: func(ctx context.Context, credential adapter.Credential) (adapter.AdminCredentialProof, error) {
				return a.ProveConnectionAdminCredential(ctx, cfg, credential)
			},
			Apply: func(ctx context.Context, credential adapter.Credential, oldProof adapter.AdminCredentialProof) error {
				oldCfg := cfg
				conn, err := a.connect(ctx, oldCfg, maintenanceDatabase(oldCfg))
				if err != nil {
					return fmt.Errorf("postgres: rotate connection admin credential: target unavailable")
				}
				defer closeQuietly(ctx, conn)
				var current string
				var inRecovery bool
				if err := conn.QueryRow(ctx, `select current_user, pg_is_in_recovery()`).Scan(&current, &inRecovery); err != nil {
					return fmt.Errorf("postgres: rotate connection admin credential: verify target state: %w", err)
				}
				if current != cfg.AdminCredential.Username || inRecovery {
					return fmt.Errorf("postgres: rotate connection admin credential: identity/topology changed: %w",
						adapter.ErrAdminCredentialRotationUnsupported)
				}
				if systemIdentifier, ok := discoverSystemIdentifier(ctx, conn); !ok ||
					"postgres:system:"+systemIdentifier != oldProof.TargetIdentity {
					return fmt.Errorf("postgres: rotate connection admin credential: target identity changed: %w",
						adapter.ErrTargetIdentityConflict)
				}
				if err := setRolePassword(ctx, conn, current, credential.Secret); err != nil {
					return fmt.Errorf("postgres: rotate connection admin credential: %w", err)
				}
				return nil
			},
		})
}

func (a *Adapter) proveConnectionAdminCredential(
	ctx context.Context,
	cfg adapter.Connection,
	credential adapter.Credential,
) (adapter.AdminCredentialProof, bool, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return adapter.AdminCredentialProof{}, false, errors.New("postgres: admin username and password are required")
	}
	probe := cfg
	probe.AdminCredential = credential
	conn, err := a.connect(ctx, probe, maintenanceDatabase(cfg))
	if err != nil {
		if isAuthenticationFailure(err) {
			return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return adapter.AdminCredentialProof{}, false, errors.New("postgres: prove admin credential: target unavailable")
	}
	defer closeQuietly(ctx, conn)

	var current string
	var inRecovery, isSuper, canCreateRole, canCreateDB, replication, bypassRLS bool
	err = conn.QueryRow(ctx, `
		select current_user, pg_is_in_recovery(),
		       r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls
		from pg_roles r where r.rolname = current_user`).Scan(
		&current, &inRecovery, &isSuper, &canCreateRole, &canCreateDB, &replication, &bypassRLS,
	)
	if err != nil {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: prove admin credential metadata: %w", err)
	}
	if current != credential.Username {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: authenticated as another identity: %w",
			adapter.ErrAdminCredentialRejected)
	}
	if !isSuper && !canCreateRole {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: admin authority is insufficient: %w",
			adapter.ErrAdminCredentialAuthorityChanged)
	}
	facts := []string{
		"super=" + strconv.FormatBool(isSuper),
		"create_role=" + strconv.FormatBool(canCreateRole),
		"create_db=" + strconv.FormatBool(canCreateDB),
		"replication=" + strconv.FormatBool(replication),
		"bypass_rls=" + strconv.FormatBool(bypassRLS),
	}
	rows, err := conn.Query(ctx, `
		select parent.rolname, am.admin_option
		from pg_auth_members am
		join pg_roles parent on parent.oid=am.roleid
		join pg_roles member on member.oid=am.member
		where member.rolname=current_user
		order by parent.rolname, am.admin_option`)
	if err != nil {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: read admin memberships: %w", err)
	}
	for rows.Next() {
		var role string
		var adminOption bool
		if err := rows.Scan(&role, &adminOption); err != nil {
			rows.Close()
			return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: scan admin memberships: %w", err)
		}
		facts = append(facts, "membership="+role+":admin="+strconv.FormatBool(adminOption))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: read admin memberships: %w", err)
	}
	rows.Close()

	wrong, err := randomProbePassword()
	if err != nil {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	negative := probe
	negative.AdminCredential.Secret = wrong
	wrongConn, wrongErr := a.connect(ctx, negative, maintenanceDatabase(cfg))
	if wrongErr == nil {
		closeQuietly(ctx, wrongConn)
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	if !isAuthenticationFailure(wrongErr) {
		return adapter.AdminCredentialProof{}, false, fmt.Errorf("postgres: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	targetIdentity := ""
	if systemIdentifier, ok := discoverSystemIdentifier(ctx, conn); ok {
		targetIdentity = "postgres:system:" + systemIdentifier
	}
	return adapter.AdminCredentialProof{
		CanonicalIdentity:    current,
		AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
		TargetIdentity:       targetIdentity,
	}, inRecovery, nil
}

func publishAdminCredentialAssessment(ctx context.Context, a *Adapter, cfg adapter.Connection, topology map[string]any) {
	assessment, err := a.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{
			BlockedReason: "assessment_failed",
		})
		return
	}
	adapter.PublishAdminCredentialAssessment(topology, assessment)
}
