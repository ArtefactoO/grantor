package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

const StatsRole = "pg_read_all_stats"
const StatsPermission = "role:" + StatsRole

var ErrStatsMembershipUnsupported = errors.New("PostgreSQL statistics membership requires the pinned v1 contract")

type StatsMembershipPins = adapter.PostgresStatsMembershipPins

func RoleOID(attributes json.RawMessage) uint32 {
	var object struct {
		OID uint32 `json:"role_oid"`
	}
	if json.Unmarshal(attributes, &object) != nil {
		return 0
	}
	return object.OID
}

func ProtectedRole(name string) bool { return strings.HasPrefix(strings.ToLower(name), "pg_") }

func statsPins(change adapter.DesiredChange) (StatsMembershipPins, error) {
	var pins StatsMembershipPins
	if change.StatsMembership != nil {
		pins = *change.StatsMembership
	}
	if change.StatsMembership == nil || len(change.Attributes) != 0 || pins.AdminIdentity == "" || pins.TargetIdentity == "" ||
		pins.ConfigIncarnation == "" || pins.CredentialIncarnation <= 0 || pins.BuiltinOID == 0 || pins.SubjectOID == 0 ||
		change.Permission != StatsPermission || !adapter.IsPostgresStatsMembershipChange(change.Kind) ||
		change.ExpectedAdminIdentity != pins.AdminIdentity || change.ExpectedTargetIdentity != pins.TargetIdentity ||
		change.Scope != "" || change.Account.Kind != "login" || change.Account.AuthenticationScope != "" ||
		len(change.AccountPermissions) != 0 || change.ExpectedDatabaseOID != 0 || change.ExpectedDatabaseOwner != "" ||
		change.ExpectedDatabaseOwnerOID != 0 ||
		change.Resource != nil || change.RolePolicySpec != nil || change.Credential != nil ||
		change.Account.EngineIdentity == "" || ProtectedRole(change.Account.EngineIdentity) {
		return pins, ErrStatsMembershipUnsupported
	}
	return pins, nil
}

func (a *Adapter) statsTransaction(ctx context.Context, change adapter.DesiredChange) (*pgx.Conn, pgx.Tx, StatsMembershipPins, error) {
	pins, err := statsPins(change)
	if err != nil {
		return nil, nil, pins, err
	}
	if change.Connection.ConfigIncarnation != pins.ConfigIncarnation || change.Connection.AdminCredentialIncarnation != pins.CredentialIncarnation {
		return nil, nil, pins, adapter.ErrTargetIdentityConflict
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, nil, pins, err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		closeQuietly(ctx, conn)
		return nil, nil, pins, err
	}
	if err := checkStatsIdentities(ctx, tx, change, pins); err != nil {
		_ = tx.Rollback(ctx)
		closeQuietly(ctx, conn)
		return nil, nil, pins, err
	}
	return conn, tx, pins, nil
}

func checkStatsIdentities(ctx context.Context, tx pgx.Tx, change adapter.DesiredChange, pins StatsMembershipPins) error {
	change.ExpectedAdminIdentity, change.ExpectedTargetIdentity = pins.AdminIdentity, pins.TargetIdentity
	if err := requireLiveProvisioningAuthority(ctx, tx, change); err != nil {
		return err
	}
	for _, role := range []struct {
		name  string
		oid   uint32
		login bool
	}{{StatsRole, pins.BuiltinOID, false}, {change.Account.EngineIdentity, pins.SubjectOID, true}} {
		var oid uint32
		var login, unsafe, inherit, createDB bool
		if err := tx.QueryRow(ctx, `select oid,rolcanlogin,rolsuper or rolcreaterole or rolreplication or rolbypassrls,rolinherit,rolcreatedb
			from pg_catalog.pg_roles where rolname=$1`, role.name).Scan(&oid, &login, &unsafe, &inherit, &createDB); err != nil {
			return err
		}
		if oid != role.oid || (!role.login && login) || (role.login && change.Kind == adapter.ChangePostgresStatsMembershipGrantV1 && (!login || !inherit || unsafe)) || (!role.login && (unsafe || createDB)) {
			return fmt.Errorf("statistics membership role identity changed: %w", adapter.ErrTargetIdentityConflict)
		}
	}
	return nil
}

func statsMembershipPresent(ctx context.Context, tx pgx.Tx, member string) (bool, error) {
	var present bool
	err := tx.QueryRow(ctx, `select exists(select 1 from pg_catalog.pg_auth_members am
		join pg_catalog.pg_roles r on r.oid=am.roleid join pg_catalog.pg_roles m on m.oid=am.member
		where r.rolname=$1 and m.rolname=$2)`, StatsRole, member).Scan(&present)
	return present, err
}

func (a *Adapter) planStatsMembership(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	conn, tx, _, err := a.statsTransaction(ctx, change)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	step := stepGrant
	if change.Kind == adapter.ChangePostgresStatsMembershipRevokeV1 {
		step = stepRevoke
	}
	return adapterutil.SingleStepPlan(change, step, "update the protected statistics membership", nil), nil
}

func (a *Adapter) applyStatsMembership(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if len(plan.Steps) != 1 {
		return nil, ErrStatsMembershipUnsupported
	}
	conn, tx, pins, err := a.statsTransaction(ctx, plan.Change)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	var version int
	if err := tx.QueryRow(ctx, `select pg_catalog.current_setting('server_version_num')::int`).Scan(&version); err != nil {
		return nil, err
	}
	statement := "grant " + sanitizeIdent(StatsRole) + " to " + sanitizeIdent(plan.Change.Account.EngineIdentity)
	if version >= 160000 {
		statement += " with admin false, inherit true, set false"
	}
	if plan.Change.Kind == adapter.ChangePostgresStatsMembershipRevokeV1 {
		statement = "revoke " + sanitizeIdent(StatsRole) + " from " + sanitizeIdent(plan.Change.Account.EngineIdentity)
	}
	if _, err := tx.Exec(ctx, statement); err != nil {
		return nil, err
	}
	if err := checkStatsIdentities(ctx, tx, plan.Change, pins); err != nil {
		return nil, err
	}
	matched, err := statsMembershipSatisfied(ctx, tx, plan.Change, pins)
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, fmt.Errorf("statistics membership does not match the non-delegating intent: %w", adapter.ErrExternalIdentityConflict)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &adapter.Result{Steps: []adapter.StepResult{{Step: plan.Steps[0], Status: adapter.StepApplied}}}, nil
}

func (a *Adapter) verifyStatsMembership(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	conn, tx, pins, err := a.statsTransaction(ctx, plan.Change)
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	defer tx.Rollback(ctx) //nolint:errcheck
	matched, err := statsMembershipSatisfied(ctx, tx, plan.Change, pins)
	if err != nil {
		return nil, err
	}
	return adapterutil.VerifyResult(matched, "protected statistics membership matches the pinned intent"), nil
}

func statsMembershipSatisfied(ctx context.Context, tx pgx.Tx, change adapter.DesiredChange, pins StatsMembershipPins) (bool, error) {
	present, err := statsMembershipPresent(ctx, tx, change.Account.EngineIdentity)
	if err != nil {
		return false, err
	}
	if change.Kind == adapter.ChangePostgresStatsMembershipRevokeV1 {
		return !present, nil
	}
	var effective, delegable, settable bool
	err = tx.QueryRow(ctx, `select pg_catalog.pg_has_role($1,$2,'USAGE'),coalesce((select bool_or(am.admin_option)
		from pg_catalog.pg_auth_members am where am.roleid=$3 and am.member=$4),false),coalesce((select
		bool_or(coalesce((pg_catalog.to_jsonb(am)->>'set_option')::boolean,false)) from pg_catalog.pg_auth_members am where am.roleid=$3 and am.member=$4),false)`,
		change.Account.EngineIdentity, StatsRole, pins.BuiltinOID, pins.SubjectOID).Scan(&effective, &delegable, &settable)
	if err != nil {
		return false, err
	}
	var serverVersion int
	if err := tx.QueryRow(ctx, `select pg_catalog.current_setting('server_version_num')::integer`).Scan(&serverVersion); err != nil {
		return false, err
	}
	if serverVersion >= 160000 {
		var effectiveSet bool
		if err := tx.QueryRow(ctx, `select pg_catalog.pg_has_role($1,$2,'SET')`, change.Account.EngineIdentity, StatsRole).Scan(&effectiveSet); err != nil {
			return false, err
		}
		settable = settable || effectiveSet
	}
	return present && effective && !delegable && !settable, nil
}
