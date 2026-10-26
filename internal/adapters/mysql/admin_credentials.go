package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

var (
	_ adapter.ConnectionAdminCredentialManager = (*Adapter)(nil)
	_ adapter.ConnectionCapabilityScoper       = (*Adapter)(nil)
)

type mysqlAdminCredentialState struct {
	proof             adapter.AdminCredentialProof
	version           string
	versionComment    string
	plugin            string
	writable          bool
	oracleMySQL8      bool
	secondaryPassword bool
}

type mysqlAdminQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (a *Adapter) AssessConnectionAdminCredential(ctx context.Context, cfg adapter.Connection) (adapter.AdminCredentialAssessment, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialAssessment{}, err
	}
	rotate := state.oracleMySQL8 && state.writable && supportedAdminAuthPlugin(state.plugin) &&
		state.proof.TargetIdentity != ""
	reason := ""
	switch {
	case !state.oracleMySQL8:
		reason = "requires_oracle_mysql_8"
	case !state.writable:
		reason = "read_only_server"
	case !supportedAdminAuthPlugin(state.plugin):
		reason = "unsupported_auth_plugin"
	case state.proof.TargetIdentity == "":
		reason = "target_identity_unavailable"
	}
	return adapter.AdminCredentialAssessment{
		SwitchSupported: true, RotateSupported: rotate, BlockedReason: reason,
		CanonicalIdentity:    state.proof.CanonicalIdentity,
		AuthorityFingerprint: state.proof.AuthorityFingerprint,
		TargetIdentity:       state.proof.TargetIdentity,
	}, nil
}

func (a *Adapter) ProveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential,
) (adapter.AdminCredentialProof, error) {
	state, err := a.proveConnectionAdminCredential(ctx, cfg, candidate)
	return state.proof, err
}

func (a *Adapter) RotateConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential, expected adapter.AdminCredentialProof,
) (adapter.AdminCredentialRotationResult, error) {
	if candidate.Kind != "password" || candidate.Username == "" || len(candidate.Secret) == 0 ||
		candidate.Username != cfg.AdminCredential.Username {
		return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialRotationUnsupported
	}
	candidateProof, candidateErr := a.ProveConnectionAdminCredential(ctx, cfg, candidate)
	if candidateErr == nil {
		if !sameMySQLAdminProof(candidateProof, expected) {
			return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialAuthorityChanged
		}
		oldProof, oldErr := a.ProveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
		if oldErr == nil && !sameMySQLAdminProof(candidateProof, oldProof) {
			return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialAuthorityChanged
		}
		if oldErr != nil && !errors.Is(oldErr, adapter.ErrAdminCredentialRejected) {
			return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove old admin credential during recovery: %w", oldErr)
		}
		// Candidate-authenticated cleanup must happen before requiring old
		// rejection: an existing secondary password otherwise keeps old valid
		// and the generic helper can never reach DISCARD OLD PASSWORD.
		if err := a.discardSecondaryAdminPassword(ctx, cfg, candidate, candidateProof); err != nil {
			return adapter.AdminCredentialRotationResult{}, err
		}
		if _, err := a.ProveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential); err == nil {
			return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialOldStillValid
		} else if !errors.Is(err, adapter.ErrAdminCredentialRejected) {
			return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove old admin credential invalidation: %w", err)
		}
		return adapter.AdminCredentialRotationResult{AlreadyApplied: true, Proof: candidateProof}, nil
	}
	if !errors.Is(candidateErr, adapter.ErrAdminCredentialRejected) {
		return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove candidate admin credential: %w", candidateErr)
	}
	oldProof, err := a.ProveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	if err != nil {
		return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove current admin credential: %w", err)
	}
	if !sameMySQLAdminProof(oldProof, expected) {
		return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialAuthorityChanged
	}
	if err := a.applyAdminPassword(ctx, cfg, candidate, oldProof); err != nil {
		return adapter.AdminCredentialRotationResult{}, err
	}
	finalProof, err := a.ProveConnectionAdminCredential(ctx, cfg, candidate)
	if err != nil {
		return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove rotated admin credential: %w", err)
	}
	if !sameMySQLAdminProof(finalProof, oldProof) {
		return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialAuthorityChanged
	}
	if err := a.discardSecondaryAdminPassword(ctx, cfg, candidate, finalProof); err != nil {
		return adapter.AdminCredentialRotationResult{}, err
	}
	if _, err := a.ProveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential); err == nil {
		return adapter.AdminCredentialRotationResult{}, adapter.ErrAdminCredentialOldStillValid
	} else if !errors.Is(err, adapter.ErrAdminCredentialRejected) {
		return adapter.AdminCredentialRotationResult{}, fmt.Errorf("mysql: prove old admin credential invalidation: %w", err)
	}
	return adapter.AdminCredentialRotationResult{Proof: finalProof}, nil
}

func sameMySQLAdminProof(a, b adapter.AdminCredentialProof) bool {
	return a.CanonicalIdentity == b.CanonicalIdentity &&
		a.AuthorityFingerprint == b.AuthorityFingerprint && a.TargetIdentity == b.TargetIdentity
}

func (a *Adapter) applyAdminPassword(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential, oldProof adapter.AdminCredentialProof) error {
	db, err := a.open(ctx, cfg, "")
	if err != nil {
		return errors.New("mysql: rotate connection admin credential: target unavailable")
	}
	defer closeQuietly(db)
	conn, err := db.Conn(ctx)
	if err != nil {
		return errors.New("mysql: rotate connection admin credential: target unavailable")
	}
	defer conn.Close() //nolint:errcheck
	state, err := readMySQLAdminCredentialState(ctx, conn, cfg.AdminCredential.Username)
	if err != nil {
		return fmt.Errorf("mysql: rotate connection admin credential: %w", err)
	}
	if !state.oracleMySQL8 || !state.writable || !supportedAdminAuthPlugin(state.plugin) {
		return fmt.Errorf("mysql: rotate connection admin credential: target state changed: %w",
			adapter.ErrAdminCredentialRotationUnsupported)
	}
	if state.proof.TargetIdentity == "" || state.proof.TargetIdentity != oldProof.TargetIdentity {
		return fmt.Errorf("mysql: rotate connection admin credential: target identity changed: %w",
			adapter.ErrTargetIdentityConflict)
	}
	restoreMode, err := pinMySQLLiteralMode(ctx, conn)
	if err != nil {
		return fmt.Errorf("mysql: rotate connection admin credential: %w", err)
	}
	defer restoreMode()
	lit, err := quoteLiteral(string(candidate.Secret))
	if err != nil {
		return fmt.Errorf("mysql: rotate connection admin credential: %w", err)
	}
	identity, err := parseUserHost(state.proof.CanonicalIdentity)
	if err != nil {
		return fmt.Errorf("mysql: rotate connection admin credential: canonical identity changed: %w",
			adapter.ErrAdminCredentialRotationUnsupported)
	}
	if _, err := conn.ExecContext(ctx, "ALTER USER "+identity.quoted()+" IDENTIFIED BY "+lit); err != nil {
		return fmt.Errorf("mysql: rotate connection admin credential: %s", redactExecError(err))
	}
	return nil
}

func (a *Adapter) discardSecondaryAdminPassword(ctx context.Context, cfg adapter.Connection,
	candidate adapter.Credential, expected adapter.AdminCredentialProof,
) error {
	probe := cfg
	probe.AdminCredential = candidate
	db, err := a.open(ctx, probe, "")
	if err != nil {
		return errors.New("mysql: discard secondary admin password: target unavailable")
	}
	defer closeQuietly(db)
	conn, err := db.Conn(ctx)
	if err != nil {
		return errors.New("mysql: discard secondary admin password: target unavailable")
	}
	defer conn.Close() //nolint:errcheck
	state, err := readMySQLAdminCredentialState(ctx, conn, candidate.Username)
	if err != nil {
		return fmt.Errorf("mysql: discard secondary admin password: %w", err)
	}
	if state.proof.TargetIdentity == "" || state.proof.TargetIdentity != expected.TargetIdentity {
		return fmt.Errorf("mysql: discard secondary admin password: target identity changed: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if !state.secondaryPassword {
		return nil
	}
	identity, err := parseUserHost(state.proof.CanonicalIdentity)
	if err != nil {
		return fmt.Errorf("mysql: discard secondary admin password: identity changed: %w",
			adapter.ErrAdminCredentialRotationUnsupported)
	}
	restoreMode, err := pinMySQLLiteralMode(ctx, conn)
	if err != nil {
		return fmt.Errorf("mysql: discard secondary admin password: %w", err)
	}
	defer restoreMode()
	if _, err := conn.ExecContext(ctx, "ALTER USER "+identity.quoted()+" DISCARD OLD PASSWORD"); err != nil {
		return fmt.Errorf("mysql: discard secondary admin password: %s", redactExecError(err))
	}
	return nil
}

func pinMySQLLiteralMode(ctx context.Context, conn *sql.Conn) (func(), error) {
	var originalSQLMode string
	if err := conn.QueryRowContext(ctx, `SELECT @@SESSION.sql_mode`).Scan(&originalSQLMode); err != nil {
		return nil, fmt.Errorf("read sql_mode: %w", err)
	}
	if _, err := conn.ExecContext(ctx,
		`SET SESSION sql_mode = TRIM(BOTH ',' FROM REPLACE(CONCAT(',', @@SESSION.sql_mode, ','), ',NO_BACKSLASH_ESCAPES,', ','))`); err != nil {
		return nil, fmt.Errorf("pin sql_mode: %w", err)
	}
	return func() {
		mode := quoteString(originalSQLMode)
		restoreCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = conn.ExecContext(restoreCtx, "SET SESSION sql_mode = "+mode)
	}, nil
}

func (a *Adapter) proveConnectionAdminCredential(ctx context.Context, cfg adapter.Connection,
	credential adapter.Credential,
) (mysqlAdminCredentialState, error) {
	if credential.Kind != "password" || credential.Username == "" || len(credential.Secret) == 0 {
		return mysqlAdminCredentialState{}, errors.New("mysql: admin username and password are required")
	}
	probe := cfg
	probe.AdminCredential = credential
	db, err := a.open(ctx, probe, "")
	if err != nil {
		if isAuthenticationFailure(err) {
			return mysqlAdminCredentialState{}, fmt.Errorf("mysql: admin credential rejected: %w",
				adapter.ErrAdminCredentialRejected)
		}
		return mysqlAdminCredentialState{}, errors.New("mysql: prove admin credential: target unavailable")
	}
	defer closeQuietly(db)
	state, err := readMySQLAdminCredentialState(ctx, db, credential.Username)
	if err != nil {
		return mysqlAdminCredentialState{}, err
	}
	current, err := parseUserHost(state.proof.CanonicalIdentity)
	if err != nil || current.user != credential.Username {
		return mysqlAdminCredentialState{}, fmt.Errorf("mysql: authenticated as another identity: %w",
			adapter.ErrAdminCredentialRejected)
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return mysqlAdminCredentialState{}, fmt.Errorf("mysql: generate negative admin proof: %w", err)
	}
	defer clear(wrong)
	if _, err := a.probeIdentity(ctx, cfg, credential.Username, wrong); err == nil {
		return mysqlAdminCredentialState{}, fmt.Errorf("mysql: password authentication is not enforced: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	} else if !isAuthenticationFailure(err) {
		return mysqlAdminCredentialState{}, fmt.Errorf("mysql: negative admin proof is ambiguous: %w",
			adapter.ErrAdminCredentialProofAmbiguous)
	}
	return state, nil
}

func readMySQLAdminCredentialState(ctx context.Context, db mysqlAdminQueryer, configuredUser string) (mysqlAdminCredentialState, error) {
	var state mysqlAdminCredentialState
	var current string
	var readOnly int
	if err := db.QueryRowContext(ctx,
		`SELECT VERSION(), @@version_comment, CURRENT_USER(), @@global.read_only`).
		Scan(&state.version, &state.versionComment, &current, &readOnly); err != nil {
		return state, fmt.Errorf("mysql: read admin target state: %w", err)
	}
	identity, err := parseUserHost(current)
	if err != nil || identity.user != configuredUser {
		return state, fmt.Errorf("mysql: current user mismatch: %w", adapter.ErrAdminCredentialRejected)
	}
	comment := strings.ToLower(state.versionComment)
	state.oracleMySQL8 = supportsRoles(state.version) && strings.Contains(comment, "mysql") &&
		!strings.Contains(comment, "percona") && !strings.Contains(comment, "aurora")
	serverUUID := ""
	superReadOnly := 1
	secondary := 0
	if state.oracleMySQL8 {
		// These variables/columns are Oracle-MySQL-8-specific. Failure disables
		// self-rotation but must not remove switch proof on MariaDB/older MySQL
		// or on an admin lacking mysql.user metadata visibility.
		_ = db.QueryRowContext(ctx, `SELECT @@global.server_uuid, @@global.super_read_only`).
			Scan(&serverUUID, &superReadOnly)
		_ = db.QueryRowContext(ctx, `
			SELECT plugin,
			       CASE WHEN JSON_EXTRACT(COALESCE(User_attributes, JSON_OBJECT()), '$.additional_password') IS NULL THEN 0 ELSE 1 END
			FROM mysql.user WHERE User=? AND Host=?`, identity.user, identity.host).
			Scan(&state.plugin, &secondary)
	} else {
		_ = db.QueryRowContext(ctx, `SELECT plugin FROM mysql.user WHERE User=? AND Host=?`,
			identity.user, identity.host).Scan(&state.plugin)
	}
	grantLines, err := mysqlAdminGrantLines(ctx, db)
	if err != nil {
		return state, err
	}
	caps := adminGrantCapabilities(grantLines)
	if !caps.canCreateUser || !caps.hasGrantOption {
		return state, fmt.Errorf("mysql: admin authority is insufficient: %w", adapter.ErrAdminCredentialAuthorityChanged)
	}
	facts := append([]string{
		"plugin=" + state.plugin,
		"create_user=true", "grant_option=true",
	}, grantLines...)
	targetIdentity := ""
	if serverUUID != "" {
		targetIdentity = "mysql:server:" + serverUUID
	}
	state.proof = adapter.AdminCredentialProof{
		CanonicalIdentity:    current,
		AuthorityFingerprint: adapter.AdminCredentialAuthorityFingerprint(facts...),
		TargetIdentity:       targetIdentity,
	}
	state.writable = readOnly == 0 && (!state.oracleMySQL8 || superReadOnly == 0)
	state.secondaryPassword = secondary != 0
	return state, nil
}

func mysqlAdminGrantLines(ctx context.Context, db mysqlAdminQueryer) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SHOW GRANTS FOR CURRENT_USER()`)
	if err != nil {
		return nil, fmt.Errorf("mysql: read admin grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return nil, fmt.Errorf("mysql: scan admin grants: %w", err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: read admin grants: %w", err)
	}
	slices.Sort(lines)
	return lines, nil
}

func supportedAdminAuthPlugin(plugin string) bool {
	return plugin == "caching_sha2_password" || plugin == "mysql_native_password"
}

func (a *Adapter) CapabilitiesFor(_ adapter.Connection, topology map[string]any) []adapter.Capability {
	return adapter.ScopeAdminCredentialCapabilities(a.Manifest().Capabilities, topology)
}

func publishAdminCredentialAssessment(ctx context.Context, a *Adapter, cfg adapter.Connection, topology map[string]any) {
	assessment, err := a.AssessConnectionAdminCredential(ctx, cfg)
	if err != nil {
		adapter.PublishAdminCredentialAssessment(topology, adapter.AdminCredentialAssessment{BlockedReason: "assessment_failed"})
		return
	}
	adapter.PublishAdminCredentialAssessment(topology, assessment)
}
