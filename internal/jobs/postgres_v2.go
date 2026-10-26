package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

func validatePostgresRuntimePins(conn connections.Connection, cfg adapter.Connection,
	expectedAdmin, expectedTarget, expectedConfig string, expectedCredential int,
) error {
	if conn.Engine != "postgres" || expectedAdmin == "" || expectedTarget == "" ||
		expectedConfig == "" || expectedCredential <= 0 ||
		cfg.AdminCredential.Username != expectedAdmin || cfg.ConfigIncarnation != expectedConfig ||
		cfg.AdminCredentialIncarnation != expectedCredential || connections.TargetIdentity(conn) != expectedTarget {
		return terminal(fmt.Errorf("PostgreSQL v2 provisioning pins no longer match current connection: %w",
			adapter.ErrTargetIdentityConflict))
	}
	return nil
}

// preflightPostgresV2Connector checks the active Hello marker before the
// worker resolves either the admin or account credential. The gateway repeats
// the same check against the exact selected session immediately before write.
func (e *MainExecutor) preflightPostgresV2Connector(ctx context.Context, operationKind string,
	connectionID uuid.UUID,
) error {
	if !isPostgresV2OperationKind(operationKind) {
		return nil
	}
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, connectionID)
	if err != nil {
		return err
	}
	viaConnector, err := connectorRoute(conn.ExecutionMode, operationKind, e.conn.Dispatcher != nil)
	if err != nil {
		return err
	}
	if viaConnector {
		return e.requireActiveConnectorCapability(adapter.CapPostgresSuperuserDirectV1)
	}
	return nil
}

// PostgreSQL SUPERUSER-direct operation kinds have their own versioned
// namespace. Keeping the worker vocabulary distinct from the generic kinds is
// a rollout fence: an old worker cannot reinterpret a new security contract,
// and a new worker can retire helper-era operations without changing other
// engines.
const (
	KindPostgresAccountCreateV2                  = "postgres.account.create.v2"
	KindPostgresAccountRestoreV2                 = "postgres.account.restore.v2"
	KindPostgresRoleCreateV2                     = "postgres.role.create.v2"
	KindPostgresResourceCreateDatabaseV2         = "postgres.resource.create.database.v2"
	KindPostgresDatabaseCreateWithRolesV2        = "postgres.resource.create.database_with_roles.v2"
	KindPostgresResourceCreateDatabaseForRolesV2 = "postgres.resource.create.database_for_roles.v2"
	KindPostgresRolePolicyApplyV2                = "postgres.role.policy.apply.v2"
	KindPostgresRolePolicyAdoptV2                = "postgres.role.policy.adopt.v2"
	KindPostgresRolePolicyRepairV2               = "postgres.role.policy.repair.v2"
	KindPostgresRolePolicyCreateV2               = "postgres.role.policy.create.v2"
	KindPostgresRolePolicyCreateDatabaseV2       = "postgres.role.policy.create_database.v2"
)

var errLegacyPostgresMutation = errors.New(
	"legacy PostgreSQL mutation is history-only; create a new SUPERUSER-direct operation")

// postgresV2OperationChangeKind records the closed root/child-to-adapter wire
// vocabulary. Root orchestration has no connector ChangeKind of its own.
var postgresV2OperationChangeKind = map[string]adapter.ChangeKind{
	KindPostgresAccountCreateV2:                  adapter.ChangePostgresAccountCreateV2,
	KindPostgresAccountRestoreV2:                 adapter.ChangePostgresAccountRestoreV2,
	KindPostgresRoleCreateV2:                     adapter.ChangePostgresRoleCreateV2,
	KindPostgresResourceCreateDatabaseV2:         adapter.ChangePostgresDatabaseCreateV2,
	KindPostgresResourceCreateDatabaseForRolesV2: adapter.ChangePostgresDatabaseCreateV2,
	KindPostgresRolePolicyApplyV2:                adapter.ChangePostgresRolePolicyApplyV2,
	KindPostgresRolePolicyAdoptV2:                adapter.ChangePostgresRolePolicyAdoptV2,
	KindPostgresRolePolicyRepairV2:               adapter.ChangePostgresRolePolicyRepairV2,
	KindPostgresRolePolicyCreateV2:               adapter.ChangePostgresRolePolicyCreateV2,
	KindPostgresRolePolicyCreateDatabaseV2:       adapter.ChangePostgresRolePolicyCreateDatabaseV2,
}

func isPostgresV2OperationKind(kind string) bool {
	if kind == KindPostgresDatabaseCreateWithRolesV2 {
		return true
	}
	_, ok := postgresV2OperationChangeKind[kind]
	return ok
}

func legacyPostgresOperationCandidate(kind string) bool {
	switch kind {
	case KindAccountCreate, KindAccountRestore, KindRoleCreate, KindResourceCreateDatabase,
		KindResourceCreatePreparedDatabase, KindDatabaseCreateWithRoles,
		KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair,
		KindRolePolicyCreate, KindRolePolicyCreateDatabase:
		return true
	default:
		return false
	}
}

// rejectLegacyPostgresOperation runs before executor dispatch and performs
// metadata-only classification. It never resolves Vault credentials, opens an
// adapter connection or contacts the target. Legacy values stay decodable and
// visible in operation history, but can no longer be retried into a broadened
// PostgreSQL authority model.
func (e *MainExecutor) rejectLegacyPostgresOperation(ctx context.Context, op operations.Operation) error {
	if !legacyPostgresOperationCandidate(op.Kind) {
		return nil
	}

	// These kinds were PostgreSQL-only even in the helper-era workflow.
	switch op.Kind {
	case KindResourceCreatePreparedDatabase, KindDatabaseCreateWithRoles,
		KindRolePolicyCreateDatabase:
		return terminal(fmt.Errorf("jobs: operation %s kind %q: %w", op.ID, op.Kind, errLegacyPostgresMutation))
	}

	// A role-policy payload carries its engine and can be classified without a
	// database read. Broken legacy payloads are left to the established decoder
	// so the historical validation error remains precise.
	switch op.Kind {
	case KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair, KindRolePolicyCreate:
		var payload RolePolicyPayload
		if err := json.Unmarshal(op.Payload, &payload); err == nil && payload.Spec.Engine == "postgres" {
			return terminal(fmt.Errorf("jobs: operation %s kind %q: %w", op.ID, op.Kind, errLegacyPostgresMutation))
		}
		return nil
	}

	if op.ConnectionID == nil || e.deps.Connections == nil || e.deps.Pool == nil {
		// Existing validation owns malformed/incompletely wired operations. In
		// production all three values are present before a target can be built.
		return nil
	}
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, *op.ConnectionID)
	if err != nil {
		return err
	}
	if conn.Engine != "postgres" {
		return nil
	}
	return terminal(fmt.Errorf("jobs: operation %s kind %q: %w", op.ID, op.Kind, errLegacyPostgresMutation))
}
