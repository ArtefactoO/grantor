package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func isDirectProvisioningChange(kind adapter.ChangeKind) bool {
	switch kind {
	case adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresAccountRestoreV2,
		adapter.ChangePostgresRoleCreateV2, adapter.ChangePostgresDatabaseCreateV2:
		return true
	default:
		return false
	}
}

func genericProvisioningKind(kind adapter.ChangeKind) adapter.ChangeKind {
	switch kind {
	case adapter.ChangePostgresAccountCreateV2:
		return adapter.ChangeAccountCreate
	case adapter.ChangePostgresAccountRestoreV2:
		return adapter.ChangeAccountRestore
	case adapter.ChangePostgresRoleCreateV2:
		return adapter.ChangeRoleCreate
	case adapter.ChangePostgresDatabaseCreateV2:
		return adapter.ChangeResourceCreate
	default:
		return ""
	}
}

func validateDirectProvisioningIntent(change adapter.DesiredChange) error {
	if !isDirectProvisioningChange(change.Kind) || change.Connection.Engine != Engine ||
		change.Connection.AdminCredentialIncarnation <= 0 || change.Connection.ConfigIncarnation == "" ||
		change.ExpectedAdminIdentity == "" ||
		change.ExpectedAdminIdentity != change.Connection.AdminCredential.Username {
		return fmt.Errorf("postgres: v2 provisioning identity/incarnation pins are incomplete: %w",
			adapter.ErrTargetIdentityConflict)
	}
	prefix := "postgres:system:"
	value := strings.TrimPrefix(change.ExpectedTargetIdentity, prefix)
	parsed, err := strconv.ParseUint(value, 10, 64)
	if !strings.HasPrefix(change.ExpectedTargetIdentity, prefix) || err != nil || parsed == 0 ||
		strconv.FormatUint(parsed, 10) != value {
		return fmt.Errorf("postgres: v2 provisioning target pin is invalid: %w", adapter.ErrTargetIdentityConflict)
	}
	if change.Kind == adapter.ChangePostgresDatabaseCreateV2 {
		if change.Resource == nil {
			return errors.New("postgres: v2 database create requires resource")
		}
		spec, err := parseDatabaseSpec(change.Resource.Attributes)
		if err != nil {
			return err
		}
		if spec.Owner == "" || change.ExpectedDatabaseOwner != spec.Owner ||
			change.ExpectedDatabaseOwnerOID == 0 {
			return fmt.Errorf("postgres: v2 database owner pin is incomplete: %w", adapter.ErrTargetIdentityConflict)
		}
	} else if change.ExpectedDatabaseOwner != "" || change.ExpectedDatabaseOwnerOID != 0 {
		return errors.New("postgres: non-database v2 provisioning carries database owner pins")
	}
	if (change.Kind == adapter.ChangePostgresAccountCreateV2 ||
		change.Kind == adapter.ChangePostgresAccountRestoreV2) &&
		!adapterutil.HasPasswordSecret(change.Credential) {
		return errors.New("postgres: v2 login provisioning requires a password credential")
	}
	if change.Kind == adapter.ChangePostgresRoleCreateV2 && change.Credential != nil {
		return errors.New("postgres: v2 NOLOGIN role must not carry a credential")
	}
	return nil
}

func requireLiveProvisioningAuthority(ctx context.Context, q rolePolicyQuerier,
	change adapter.DesiredChange,
) error {
	var sessionUser, currentUser string
	var superuser, recovery, readOnly bool
	if err := q.QueryRow(ctx, `select session_user,current_user,
		coalesce((select rolsuper from pg_catalog.pg_roles where rolname=session_user),false),
		pg_catalog.pg_is_in_recovery(),pg_catalog.current_setting('transaction_read_only')::boolean`).
		Scan(&sessionUser, &currentUser, &superuser, &recovery, &readOnly); err != nil {
		return fmt.Errorf("probe live PostgreSQL provisioning authority: %w", err)
	}
	if sessionUser != change.ExpectedAdminIdentity || currentUser != change.ExpectedAdminIdentity ||
		sessionUser != change.Connection.AdminCredential.Username {
		return fmt.Errorf("PostgreSQL provisioning admin identity changed: %w", adapter.ErrTargetIdentityConflict)
	}
	if !superuser {
		return &adapter.InsufficientPrivilegeError{Engine: Engine, Admin: sessionUser, Missing: "SUPERUSER"}
	}
	if recovery || readOnly {
		return fmt.Errorf("PostgreSQL provisioning target is read-only: %w", adapter.ErrTargetIdentityConflict)
	}
	var systemIdentifier string
	if err := q.QueryRow(ctx, `select system_identifier::text from pg_catalog.pg_control_system()`).Scan(&systemIdentifier); err != nil {
		return fmt.Errorf("read PostgreSQL system identity: %w", err)
	}
	if "postgres:system:"+systemIdentifier != change.ExpectedTargetIdentity {
		return fmt.Errorf("PostgreSQL provisioning target changed: %w", adapter.ErrTargetIdentityConflict)
	}
	if change.Kind == adapter.ChangePostgresDatabaseCreateV2 {
		var ownerOID uint32
		var ownerSuper bool
		if err := q.QueryRow(ctx, `select oid,rolsuper from pg_catalog.pg_roles where rolname=$1`,
			change.ExpectedDatabaseOwner).Scan(&ownerOID, &ownerSuper); errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("database owner %q is absent: %w", change.ExpectedDatabaseOwner, adapter.ErrTargetIdentityConflict)
		} else if err != nil {
			return err
		}
		if ownerOID != change.ExpectedDatabaseOwnerOID || ownerSuper {
			return fmt.Errorf("database owner identity changed or is unsafe: %w", adapter.ErrTargetIdentityConflict)
		}
	}
	return nil
}

func addProvisioningPlanPins(plan *adapter.Plan, change adapter.DesiredChange) {
	for i := range plan.Steps {
		if plan.Steps[i].Attributes == nil {
			plan.Steps[i].Attributes = map[string]any{}
		}
		plan.Steps[i].Attributes["expected_admin_identity"] = change.ExpectedAdminIdentity
		plan.Steps[i].Attributes["expected_target_identity"] = change.ExpectedTargetIdentity
		plan.Steps[i].Attributes["expected_config_incarnation"] = change.Connection.ConfigIncarnation
		plan.Steps[i].Attributes["expected_credential_incarnation"] = change.Connection.AdminCredentialIncarnation
		if change.ExpectedDatabaseOwner != "" {
			plan.Steps[i].Attributes["expected_database_owner"] = change.ExpectedDatabaseOwner
			plan.Steps[i].Attributes["expected_database_owner_oid"] = uint64(change.ExpectedDatabaseOwnerOID)
		}
	}
}

func (a *Adapter) planDirectProvisioning(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	if err := validateDirectProvisioningIntent(change); err != nil {
		return nil, err
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, err
	}
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		closeQuietly(ctx, conn)
		return nil, err
	}
	closeQuietly(ctx, conn)
	generic := change
	generic.Kind = genericProvisioningKind(change.Kind)
	var plan *adapter.Plan
	switch generic.Kind {
	case adapter.ChangeAccountCreate:
		plan, err = a.planAccountCreate(ctx, generic)
	case adapter.ChangeAccountRestore:
		plan, err = a.planAccountRestore(ctx, generic)
	case adapter.ChangeRoleCreate:
		plan, err = a.planRoleCreate(ctx, generic)
	case adapter.ChangeResourceCreate:
		plan, err = a.planResourceCreate(ctx, generic)
	}
	if err != nil {
		return nil, err
	}
	plan.Change = change
	addProvisioningPlanPins(plan, change)
	return plan, nil
}

func (a *Adapter) applyDirectProvisioning(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	change := plan.Change
	if err := validateDirectProvisioningIntent(change); err != nil {
		return nil, err
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		return nil, err
	}
	generic := change
	generic.Kind = genericProvisioningKind(change.Kind)
	genericPlan := plan
	genericPlan.Change = generic
	if change.Kind == adapter.ChangePostgresAccountRestoreV2 {
		return applyRestoreAtomic(ctx, conn, genericPlan)
	}
	if change.Kind == adapter.ChangePostgresDatabaseCreateV2 {
		return adapterutil.ApplySteps(ctx, genericPlan, conn, applyStep), nil
	}
	// account.create owns its CREATE ROLE + password transaction inside
	// applyCreateRole; role.create is a single CREATE ROLE statement. Starting
	// an outer transaction here would make the account path attempt a nested
	// pgx transaction on the same connection.
	result := adapterutil.ApplySteps(ctx, genericPlan, conn, applyStep)
	for i := range result.Steps {
		if result.Steps[i].Status == adapter.StepFailed {
			return result, errors.New("PostgreSQL v2 provisioning apply failed")
		}
	}
	return result, nil
}

func (a *Adapter) verifyDirectProvisioning(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	change := plan.Change
	if err := validateDirectProvisioningIntent(change); err != nil {
		return nil, err
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, err
	}
	defer closeQuietly(ctx, conn)
	if err := requireLiveProvisioningAuthority(ctx, conn, change); err != nil {
		return nil, err
	}
	generic := change
	generic.Kind = genericProvisioningKind(change.Kind)
	if generic.Kind == adapter.ChangeResourceCreate {
		return verifyDatabaseCreated(ctx, conn, generic)
	}
	name := generic.Account.EngineIdentity
	canLogin, found, err := roleLogin(ctx, conn, name)
	if err != nil {
		return nil, err
	}
	if generic.Kind == adapter.ChangeRoleCreate {
		return adapterutil.VerifyResult(found && !canLogin, fmt.Sprintf("role %q exists and is NOLOGIN", name)), nil
	}
	if !found || !canLogin {
		return adapterutil.VerifyResult(false, fmt.Sprintf("login role %q exists", name)), nil
	}
	if generic.Kind == adapter.ChangeAccountCreate || generic.Kind == adapter.ChangeAccountRestore {
		if generic.Credential == nil {
			return nil, errors.New("account credential is required")
		}
		if err := a.ProveCredential(ctx, generic.Connection, generic.Account, *generic.Credential); err != nil {
			return nil, err
		}
	}
	return adapterutil.VerifyResult(true, fmt.Sprintf("login role %q exists", name)), nil
}
