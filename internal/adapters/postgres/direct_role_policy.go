package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

const stepDirectRolePolicy = "postgres-role-policy-direct"

type directPolicyAuthority struct {
	admin            string
	targetIdentity   string
	database         string
	databaseOID      uint32
	databaseOwner    string
	databaseOwnerOID uint32
	serverVersion    int
}

type directPolicyStatement struct {
	kind string
	sql  string
}

func isDirectRolePolicyChange(kind adapter.ChangeKind) bool {
	switch kind {
	case adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		return true
	default:
		return false
	}
}

func isDirectRolePolicyMutation(kind adapter.ChangeKind) bool {
	switch kind {
	case adapter.ChangePostgresRolePolicyApplyV2,
		adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2,
		adapter.ChangePostgresRolePolicyCreateDatabaseV2:
		return true
	default:
		return false
	}
}

func isDirectRolePolicyCreate(kind adapter.ChangeKind) bool {
	return kind == adapter.ChangePostgresRolePolicyCreateV2 ||
		kind == adapter.ChangePostgresRolePolicyCreateDatabaseV2
}

func isDirectRolePolicyReadOnly(kind adapter.ChangeKind) bool {
	return kind == adapter.ChangePostgresRolePolicyVerifyV2 ||
		kind == adapter.ChangePostgresRolePolicyAdoptV2
}

func validateDirectRolePolicyChange(change adapter.DesiredChange) (postgresconfig.RolePolicyTemplate, error) {
	if !isDirectRolePolicyChange(change.Kind) {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf("postgres: direct role policy kind %q: %w",
			change.Kind, adapter.ErrUnsupportedChange)
	}
	if change.Connection.Engine != "" && change.Connection.Engine != Engine {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf("postgres: direct role policy engine %q: %w",
			change.Connection.Engine, adapter.ErrUnsupportedChange)
	}
	if change.Resource != nil || change.Credential != nil || change.Account != (adapter.Account{}) ||
		change.Scope != "" || len(change.AccountPermissions) != 0 || len(change.Attributes) != 0 {
		return postgresconfig.RolePolicyTemplate{}, errors.New("postgres: direct role policy carries unrelated mutation fields")
	}
	template, err := rolePolicyTemplate(change.RolePolicySpec)
	if err != nil {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf("postgres: direct role policy spec: %w", err)
	}
	if change.ExpectedAdminIdentity == "" ||
		change.ExpectedAdminIdentity != change.Connection.AdminCredential.Username {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy expected admin identity does not match the credential: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if err := validateDirectRoleIdentifier("expected admin identity", change.ExpectedAdminIdentity); err != nil {
		return postgresconfig.RolePolicyTemplate{}, err
	}
	if change.Connection.AdminCredentialIncarnation <= 0 || change.Connection.ConfigIncarnation == "" {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy credential/config incarnation pins are required: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if change.ExpectedTargetIdentity == "" ||
		!strings.HasPrefix(change.ExpectedTargetIdentity, "postgres:system:") ||
		strings.TrimPrefix(change.ExpectedTargetIdentity, "postgres:system:") == "" {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy expected target identity is invalid: %w",
			adapter.ErrTargetIdentityConflict)
	}
	targetSuffix := strings.TrimPrefix(change.ExpectedTargetIdentity, "postgres:system:")
	targetValue, err := strconv.ParseUint(targetSuffix, 10, 64)
	if err != nil || targetValue == 0 || strconv.FormatUint(targetValue, 10) != targetSuffix {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy expected target identity is invalid: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if change.ExpectedDatabaseOID == 0 {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy expected database OID is required: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if err := validateDirectRoleIdentifier("expected database owner", change.ExpectedDatabaseOwner); err != nil {
		return postgresconfig.RolePolicyTemplate{}, err
	}
	if change.ExpectedDatabaseOwnerOID == 0 {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy expected database owner OID is required: %w",
			adapter.ErrTargetIdentityConflict)
	}
	if change.Kind == adapter.ChangePostgresRolePolicyCreateDatabaseV2 &&
		(len(template.OwnerRoles) != 1 || len(template.CreatorRoles) != 1 ||
			template.OwnerRoles[0] != change.ExpectedDatabaseOwner ||
			template.CreatorRoles[0] != change.ExpectedDatabaseOwner) {
		return postgresconfig.RolePolicyTemplate{}, errors.New(
			"postgres: database-created direct policy requires the pinned database owner as its single owner and creator scope")
	}
	if change.Permission != "" && change.Permission != rolePermissionID(template.RoleName) {
		return postgresconfig.RolePolicyTemplate{}, fmt.Errorf(
			"postgres: direct role policy permission does not match role %q", template.RoleName)
	}
	return template, nil
}

func validateDirectRoleIdentifier(field, value string) error {
	if value == "" || len(value) > maxIdentifierBytes || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("postgres: direct role policy %s is invalid: %w", field, adapter.ErrTargetIdentityConflict)
	}
	return nil
}

func (a *Adapter) planDirectRolePolicy(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	template, err := validateDirectRolePolicyChange(change)
	if err != nil {
		return nil, err
	}
	conn, tx, err := a.beginDirectRolePolicyTx(ctx, change.Connection, template.Database)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan %s: %w", change.Kind, err)
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck

	authority, err := validateDirectPolicyAuthority(ctx, tx, change, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan %s: %w", change.Kind, err)
	}
	state, err := observeDirectPolicyState(ctx, tx, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan %s: observe exact state: %w", change.Kind, err)
	}
	if err := validateDirectPolicyPlanState(change.Kind, template, state); err != nil {
		return nil, fmt.Errorf("postgres: plan %s: %w", change.Kind, err)
	}

	verb := "verify"
	if isDirectRolePolicyMutation(change.Kind) {
		verb = "enforce"
	}
	return adapterutil.SingleStepPlan(change, stepDirectRolePolicy,
		fmt.Sprintf("%s fixed %s PostgreSQL policy for role %q in database %q",
			verb, template.Profile, template.RoleName, template.Database),
		directRolePolicyPlanAttributes(change, template, authority)), nil
}

func (a *Adapter) beginDirectRolePolicyTx(
	ctx context.Context,
	cfg adapter.Connection,
	database string,
) (*pgx.Conn, pgx.Tx, error) {
	conn, err := a.connect(ctx, cfg, database)
	if err != nil {
		return nil, nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		closeQuietly(ctx, conn)
		return nil, nil, fmt.Errorf("begin serializable policy transaction: %w", err)
	}
	if _, err := tx.Exec(ctx, `set local search_path = pg_catalog`); err != nil {
		tx.Rollback(ctx) //nolint:errcheck
		closeQuietly(ctx, conn)
		return nil, nil, fmt.Errorf("set closed policy search path: %w", err)
	}
	return conn, tx, nil
}

func validateDirectPolicyAuthority(
	ctx context.Context,
	tx pgx.Tx,
	change adapter.DesiredChange,
	template postgresconfig.RolePolicyTemplate,
) (directPolicyAuthority, error) {
	var out directPolicyAuthority
	var sessionUser, currentUser, systemIdentifier string
	var superuser, inRecovery, readOnly bool
	err := tx.QueryRow(ctx, `
		select session_user, current_user,
		       coalesce((select r.rolsuper from pg_catalog.pg_roles r where r.rolname = session_user), false),
		       pg_catalog.pg_is_in_recovery(),
		       pg_catalog.current_setting('transaction_read_only')::boolean,
		       c.system_identifier::text,
		       pg_catalog.current_database(), d.oid, owner_role.rolname, owner_role.oid,
		       pg_catalog.current_setting('server_version_num')::integer
		from pg_catalog.pg_control_system() c
		join pg_catalog.pg_database d on d.datname = pg_catalog.current_database()
		join pg_catalog.pg_roles owner_role on owner_role.oid = d.datdba`).Scan(
		&sessionUser, &currentUser, &superuser, &inRecovery, &readOnly,
		&systemIdentifier, &out.database, &out.databaseOID, &out.databaseOwner, &out.databaseOwnerOID,
		&out.serverVersion,
	)
	if err != nil {
		return out, fmt.Errorf("probe live SUPERUSER authority: %w", err)
	}
	out.admin = sessionUser
	out.targetIdentity = "postgres:system:" + systemIdentifier
	if err := validateDirectPolicyAuthorityFacts(change, template, out,
		sessionUser, currentUser, superuser, inRecovery, readOnly); err != nil {
		return out, err
	}
	return out, nil
}

func validateDirectPolicyAuthorityFacts(
	change adapter.DesiredChange,
	template postgresconfig.RolePolicyTemplate,
	out directPolicyAuthority,
	sessionUser string,
	currentUser string,
	superuser bool,
	inRecovery bool,
	readOnly bool,
) error {
	switch {
	case sessionUser != change.ExpectedAdminIdentity || currentUser != change.ExpectedAdminIdentity ||
		sessionUser != change.Connection.AdminCredential.Username:
		return fmt.Errorf("live session/current admin identity changed: %w", adapter.ErrTargetIdentityConflict)
	case !superuser:
		return &adapter.InsufficientPrivilegeError{
			Engine: Engine, Admin: change.ExpectedAdminIdentity, Missing: "SUPERUSER",
			Detail: "PostgreSQL managed creation and role policies require a SUPERUSER connection admin",
		}
	case inRecovery || readOnly:
		return fmt.Errorf("live target is read-only: %w", adapter.ErrTargetIdentityConflict)
	case out.targetIdentity != change.ExpectedTargetIdentity:
		return fmt.Errorf("live PostgreSQL system identity changed: %w", adapter.ErrTargetIdentityConflict)
	case out.database != template.Database:
		return fmt.Errorf("live database name changed: %w", adapter.ErrTargetIdentityConflict)
	case out.databaseOID != change.ExpectedDatabaseOID:
		return fmt.Errorf("live database OID changed: %w", adapter.ErrTargetIdentityConflict)
	case out.databaseOwner != change.ExpectedDatabaseOwner:
		return fmt.Errorf("live database owner changed: %w", adapter.ErrTargetIdentityConflict)
	case out.databaseOwnerOID != change.ExpectedDatabaseOwnerOID:
		return fmt.Errorf("live database owner OID changed: %w", adapter.ErrTargetIdentityConflict)
	}
	return nil
}

func observeDirectPolicyState(
	ctx context.Context,
	q rolePolicyQuerier,
	template postgresconfig.RolePolicyTemplate,
) (*rolePolicyState, error) {
	state, err := observeRolePolicyState(ctx, q, template)
	if err != nil {
		return nil, err
	}
	if state.role.exists {
		safety, safetyErr := inspectPolicyRoleAcrossCluster(ctx, q, template.RoleName, template.Database)
		applyCrossDatabaseSafetyObservation(state, safety, safetyErr)
	}
	state.finish()
	return state, nil
}

func validateDirectPolicyPlanState(
	kind adapter.ChangeKind,
	template postgresconfig.RolePolicyTemplate,
	state *rolePolicyState,
) error {
	if state.hardBlockCode != "" {
		return fmt.Errorf("role %q cannot be changed safely (%s): %w",
			template.RoleName, state.hardBlockCode, adapter.ErrExternalIdentityConflict)
	}
	if isDirectRolePolicyCreate(kind) {
		if state.role.exists && len(state.missing)+len(state.extra) != 0 {
			return fmt.Errorf("existing role %q is not the exact lost-response state: %w",
				template.RoleName, adapter.ErrExternalIdentityConflict)
		}
		return nil
	}
	if !state.role.exists && isDirectRolePolicyMutation(kind) {
		return fmt.Errorf("policy role %q: %w", template.RoleName, adapter.ErrNotFound)
	}
	return nil
}

func directRolePolicyPlanAttributes(
	change adapter.DesiredChange,
	template postgresconfig.RolePolicyTemplate,
	authority directPolicyAuthority,
) map[string]any {
	return map[string]any{
		"expected_admin_identity":         change.ExpectedAdminIdentity,
		"expected_target_identity":        change.ExpectedTargetIdentity,
		"expected_database":               template.Database,
		"expected_database_oid":           uint64(change.ExpectedDatabaseOID),
		"expected_database_owner":         change.ExpectedDatabaseOwner,
		"expected_database_owner_oid":     uint64(change.ExpectedDatabaseOwnerOID),
		"expected_role":                   template.RoleName,
		"expected_profile":                template.Profile,
		"expected_spec_fingerprint":       postgresconfig.Fingerprint(template),
		"expected_config_incarnation":     change.Connection.ConfigIncarnation,
		"expected_credential_incarnation": change.Connection.AdminCredentialIncarnation,
		"observed_server_version":         authority.serverVersion,
	}
}

func validateDirectRolePolicyPlan(
	plan adapter.Plan,
	template postgresconfig.RolePolicyTemplate,
) error {
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepDirectRolePolicy {
		return errors.New("postgres: direct role policy plan has an invalid step vocabulary")
	}
	attrs := plan.Steps[0].Attributes
	expected := map[string]string{
		"expected_admin_identity":     plan.Change.ExpectedAdminIdentity,
		"expected_target_identity":    plan.Change.ExpectedTargetIdentity,
		"expected_database":           template.Database,
		"expected_database_owner":     plan.Change.ExpectedDatabaseOwner,
		"expected_role":               template.RoleName,
		"expected_profile":            template.Profile,
		"expected_spec_fingerprint":   postgresconfig.Fingerprint(template),
		"expected_config_incarnation": plan.Change.Connection.ConfigIncarnation,
	}
	for key, value := range expected {
		if actual, ok := attrs[key].(string); !ok || actual != value {
			return fmt.Errorf("postgres: direct role policy plan pin %q changed", key)
		}
	}
	oid, ok := planAttributeUint32(attrs["expected_database_oid"])
	if !ok || oid != plan.Change.ExpectedDatabaseOID {
		return errors.New("postgres: direct role policy plan database OID pin changed")
	}
	ownerOID, ok := planAttributeUint32(attrs["expected_database_owner_oid"])
	if !ok || ownerOID != plan.Change.ExpectedDatabaseOwnerOID {
		return errors.New("postgres: direct role policy plan database owner OID pin changed")
	}
	credentialIncarnation, ok := planAttributePositiveInt(attrs["expected_credential_incarnation"])
	if !ok || credentialIncarnation != plan.Change.Connection.AdminCredentialIncarnation {
		return errors.New("postgres: direct role policy plan credential incarnation pin changed")
	}
	return nil
}

func planAttributePositiveInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, typed > 0
	case int64:
		return int(typed), typed > 0 && int64(int(typed)) == typed
	case float64:
		return int(typed), typed > 0 && typed == float64(int(typed))
	default:
		return 0, false
	}
}

func planAttributeUint32(value any) (uint32, bool) {
	switch typed := value.(type) {
	case uint32:
		return typed, typed > 0
	case uint64:
		return uint32(typed), typed > 0 && typed <= uint64(^uint32(0))
	case int:
		return uint32(typed), typed > 0 && uint64(typed) <= uint64(^uint32(0))
	case float64:
		return uint32(typed), typed > 0 && typed <= float64(^uint32(0)) && typed == float64(uint32(typed))
	default:
		return 0, false
	}
}

func directPolicyStateExact(state *rolePolicyState) bool {
	return state.hardBlockCode == "" && len(state.missing) == 0 && len(state.extra) == 0
}

func directPolicyVerification(
	state *rolePolicyState,
	authority directPolicyAuthority,
) *adapter.Verification {
	details := "exact fixed PostgreSQL role policy"
	if !directPolicyStateExact(state) {
		details = fmt.Sprintf("role policy drift: missing=%d extra=%d blocked=%s",
			len(state.missing), len(state.extra), state.hardBlockCode)
	}
	return &adapter.Verification{
		Verified: directPolicyStateExact(state),
		Details:  details,
		Observed: map[string]any{
			"expected_fingerprint": fingerprintPolicyTokens(state.expected),
			"observed_fingerprint": fingerprintPolicyTokens(state.actual),
			"target_identity":      authority.targetIdentity,
			"database":             authority.database,
			"database_oid":         authority.databaseOID,
			"database_owner":       authority.databaseOwner,
			"database_owner_oid":   authority.databaseOwnerOID,
			"admin_identity":       authority.admin,
		},
	}
}

func (a *Adapter) verifyDirectRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	template, err := validateDirectRolePolicyChange(plan.Change)
	if err != nil {
		return nil, err
	}
	if err := validateDirectRolePolicyPlan(plan, template); err != nil {
		return nil, err
	}
	conn, tx, err := a.beginDirectRolePolicyTx(ctx, plan.Change.Connection, template.Database)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify %s: %w", plan.Change.Kind, err)
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	authority, err := validateDirectPolicyAuthority(ctx, tx, plan.Change, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify %s: %w", plan.Change.Kind, err)
	}
	state, err := observeDirectPolicyState(ctx, tx, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify %s: observe exact state: %w", plan.Change.Kind, err)
	}
	return directPolicyVerification(state, authority), nil
}

func (a *Adapter) applyDirectRolePolicy(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	change := plan.Change
	if !isDirectRolePolicyMutation(change.Kind) {
		return nil, fmt.Errorf("postgres: apply %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
	template, err := validateDirectRolePolicyChange(change)
	if err != nil {
		return nil, err
	}
	if err := validateDirectRolePolicyPlan(plan, template); err != nil {
		return nil, err
	}
	conn, tx, err := a.beginDirectRolePolicyTx(ctx, change.Connection, template.Database)
	if err != nil {
		return nil, fmt.Errorf("postgres: apply %s: %w", change.Kind, err)
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	authority, err := validateDirectPolicyAuthority(ctx, tx, change, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: apply %s: %w", change.Kind, err)
	}
	before, err := observeDirectPolicyState(ctx, tx, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: apply %s: observe exact state: %w", change.Kind, err)
	}
	if err := validateDirectPolicyPlanState(change.Kind, template, before); err != nil {
		return nil, fmt.Errorf("postgres: apply %s: %w", change.Kind, err)
	}

	status := adapter.StepApplied
	if directPolicyStateExact(before) {
		status = adapter.StepSkipped
	} else {
		if !before.role.exists {
			if _, err := tx.Exec(ctx, directCreatePolicyRoleSQL(template.RoleName)); err != nil {
				return nil, fmt.Errorf("postgres: apply %s: %w", change.Kind,
					directCreatePolicyRoleError(template.RoleName, err))
			}
		}
		statements, err := buildDirectRolePolicyStatements(ctx, tx, template, authority)
		if err != nil {
			return nil, fmt.Errorf("postgres: apply %s: build closed statement plan: %w", change.Kind, err)
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement.sql); err != nil {
				return nil, fmt.Errorf("postgres: apply %s: execute %s statement: %w",
					change.Kind, statement.kind, err)
			}
		}
		if _, err := validateDirectPolicyAuthority(ctx, tx, change, template); err != nil {
			return nil, fmt.Errorf("postgres: apply %s: post-statement authority fence: %w", change.Kind, err)
		}
	}

	after, err := observeDirectPolicyState(ctx, tx, template)
	if err != nil {
		return nil, fmt.Errorf("postgres: apply %s: exact read-back: %w", change.Kind, err)
	}
	verification := directPolicyVerification(after, authority)
	if !verification.Verified {
		return nil, fmt.Errorf("postgres: apply %s: %s", change.Kind, verification.Details)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("postgres: apply %s: commit direct policy transaction: %w", change.Kind, err)
	}
	return &adapter.Result{Steps: []adapter.StepResult{{Step: plan.Steps[0], Status: status}}}, nil
}

func directCreatePolicyRoleSQL(role string) string {
	return "create role " + sanitizeIdent(role) +
		" nologin nosuperuser nocreatedb nocreaterole noreplication nobypassrls inherit"
}

func directCreatePolicyRoleError(role string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == pgCodeDuplicateObject || pgErr.Code == "23505") {
		return adapterutil.IdentityConflict("role", role)
	}
	return fmt.Errorf("create policy role %q: %w", role, err)
}

func buildDirectRolePolicyStatements(
	ctx context.Context,
	tx pgx.Tx,
	template postgresconfig.RolePolicyTemplate,
	authority directPolicyAuthority,
) ([]directPolicyStatement, error) {
	revokes, err := collectDirectPolicyRevokes(ctx, tx, template.RoleName, authority.admin)
	if err != nil {
		return nil, err
	}
	desired := desiredDirectPolicyGrants(template)
	desired, err = addDesiredCurrentObjectGrants(ctx, tx, template, desired)
	if err != nil {
		return nil, err
	}
	memberships, err := directAdminMembershipRevokes(ctx, tx, template.RoleName, authority.admin, authority.serverVersion)
	if err != nil {
		return nil, err
	}
	// Membership cleanup deliberately runs last. A dependent/alternate grantor
	// failure therefore proves that every preceding ACL change rolls back with
	// the same transaction rather than leaving a partially repaired policy.
	out := make([]directPolicyStatement, 0, 1+len(revokes)+len(desired)+len(memberships))
	out = append(out, directPolicyStatement{kind: "clear-role-password",
		sql: "alter role " + sanitizeIdent(template.RoleName) + " password null"})
	out = append(out, revokes...)
	out = append(out, desired...)
	out = append(out, memberships...)
	return out, nil
}

func desiredDirectPolicyGrants(template postgresconfig.RolePolicyTemplate) []directPolicyStatement {
	role := sanitizeIdent(template.RoleName)
	out := []directPolicyStatement{{kind: "grant-database",
		sql: "grant connect on database " + sanitizeIdent(template.Database) + " to " + role}}
	for _, schema := range template.Schemas {
		out = append(out, directPolicyStatement{kind: "grant-schema",
			sql: "grant usage on schema " + sanitizeIdent(schema) + " to " + role})
	}
	tablePrivileges, sequencePrivileges := directProfilePrivileges(template.Profile)
	// Current objects are added by buildDirectRolePolicyStatements after a
	// catalog read because owner scoping cannot be represented by ALL IN SCHEMA.
	for _, creator := range template.CreatorRoles {
		for _, schema := range template.Schemas {
			prefix := "alter default privileges for role " + sanitizeIdent(creator) +
				" in schema " + sanitizeIdent(schema) + " grant "
			out = append(out,
				directPolicyStatement{kind: "grant-default-table",
					sql: prefix + tablePrivileges + " on tables to " + role},
				directPolicyStatement{kind: "grant-default-sequence",
					sql: prefix + sequencePrivileges + " on sequences to " + role},
			)
		}
	}
	return out
}

func directProfilePrivileges(profile string) (string, string) {
	if profile == postgresconfig.ProfileReadWrite {
		return "select, insert, update, delete", "select, update"
	}
	return "select", "select"
}

func appendCurrentObjectGrants(
	ctx context.Context,
	tx pgx.Tx,
	template postgresconfig.RolePolicyTemplate,
	statements []directPolicyStatement,
) ([]directPolicyStatement, error) {
	objects, err := discoverPolicyObjects(ctx, tx, template)
	if err != nil {
		return nil, err
	}
	tablePrivileges, sequencePrivileges := directProfilePrivileges(template.Profile)
	role := sanitizeIdent(template.RoleName)
	for _, object := range objects {
		kind := "table"
		privileges := tablePrivileges
		objectKind := "table"
		if object.relkind == "S" {
			kind = "sequence"
			privileges = sequencePrivileges
			objectKind = "sequence"
		}
		statements = append(statements, directPolicyStatement{
			kind: "grant-current-" + objectKind,
			sql: "grant " + privileges + " on " + kind + " " +
				pgx.Identifier{object.schema, object.name}.Sanitize() + " to " + role,
		})
	}
	return statements, nil
}

func directAdminMembershipRevokes(
	ctx context.Context,
	tx pgx.Tx,
	policyRole string,
	admin string,
	serverVersion int,
) ([]directPolicyStatement, error) {
	rows, err := tx.Query(ctx, `
		select grantor.rolname, am.admin_option,
		       coalesce((pg_catalog.to_jsonb(am)->>'inherit_option')::boolean, false),
		       coalesce((pg_catalog.to_jsonb(am)->>'set_option')::boolean, false)
		from pg_catalog.pg_auth_members am
		join pg_catalog.pg_roles granted on granted.oid = am.roleid
		join pg_catalog.pg_roles member_role on member_role.oid = am.member
		join pg_catalog.pg_roles grantor on grantor.oid = am.grantor
		where granted.rolname = $1 and member_role.rolname = $2
		order by grantor.rolname, am.admin_option`, policyRole, admin)
	if err != nil {
		return nil, fmt.Errorf("query exact admin membership grantors: %w", err)
	}
	type membership struct {
		grantor                               string
		adminOption, inheritOption, setOption bool
	}
	var found []membership
	for rows.Next() {
		var item membership
		if err := rows.Scan(&item.grantor, &item.adminOption, &item.inheritOption, &item.setOption); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan exact admin membership grantor: %w", err)
		}
		found = append(found, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("read exact admin membership grantors: %w", err)
	}
	rows.Close()
	if serverVersion < 160000 && len(found) > 1 {
		return nil, errors.New("multiple admin membership grantors are not safely addressable before PostgreSQL 16")
	}
	out := make([]directPolicyStatement, 0, 3*len(found))
	for _, item := range found {
		if item.grantor != admin {
			out = append(out, directPolicyStatement{kind: "set-membership-grantor-role",
				sql: "set local role " + sanitizeIdent(item.grantor)})
		}
		sql := "revoke " + sanitizeIdent(policyRole) + " from " + sanitizeIdent(admin)
		if serverVersion >= 160000 {
			sql += " granted by " + sanitizeIdent(item.grantor)
		}
		sql += " restrict"
		out = append(out, directPolicyStatement{kind: "revoke-admin-membership", sql: sql})
		if item.grantor != admin {
			out = append(out, directPolicyStatement{kind: "reset-membership-grantor-role", sql: "reset role"})
		}
	}
	return out, nil
}

func validateCatalogRoutineIdentity(value string) error {
	if value == "" || strings.ContainsAny(value, ";\x00\r\n") {
		return errors.New("catalog routine identity is not safely addressable")
	}
	return nil
}

func numericObjectIdentity(value uint32) string { return strconv.FormatUint(uint64(value), 10) }
