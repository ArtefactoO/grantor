package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

const KindPostgresStatsGrantV1 = "postgres.stats_membership.grant.v1"
const KindPostgresStatsRevokeV1 = "postgres.stats_membership.revoke.v1"

func IsPostgresStatsPermission(permission inventory.Permission) bool {
	return permission.Engine == postgres.Engine && permission.ExternalID == postgres.StatsPermission
}

// The worker checks Hello before resolving Vault material. Dispatch repeats
// this fence against the selected session, so reconnect cannot select an old
// connector after this metadata-only preflight.
func (e *MainExecutor) preflightStatsMembershipConnector(ctx context.Context, operationKind string, connectionID uuid.UUID) error {
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, connectionID)
	if err != nil {
		return err
	}
	viaConnector, err := connectorRoute(conn.ExecutionMode, operationKind, e.conn.Dispatcher != nil)
	if err != nil || !viaConnector {
		return err
	}
	return e.requireStatsMembershipConnectorCapabilities()
}

func (e *MainExecutor) requireStatsMembershipConnectorCapabilities() error {
	for _, capability := range []adapter.Capability{adapter.CapPostgresStatsMembershipV1, adapter.CapPostgresSuperuserDirectV1} {
		if err := e.requireActiveConnectorCapability(capability); err != nil {
			return err
		}
	}
	return nil
}

func BuildStatsMembershipPins(ctx context.Context, q accountcreation.Querier, conn connections.Connection,
	acct inventory.Account, permission inventory.Permission, creationID uuid.UUID,
) (*postgres.StatsMembershipPins, error) {
	var topology map[string]any
	if json.Unmarshal(conn.Topology, &topology) != nil {
		return nil, postgres.ErrStatsMembershipUnsupported
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	modeSupported := conn.ExecutionMode == connections.ExecutionModeDirect ||
		(conn.ExecutionMode == connections.ExecutionModeConnector && slices.Contains(conn.Capabilities, string(adapter.CapPostgresStatsMembershipV1)))
	if !ok || conn.Engine != postgres.Engine || !modeSupported || conn.Status != connections.StatusActive ||
		authority.Status != adapter.ProvisioningAuthorityConfirmed || authority.Reason != adapter.ProvisioningAuthoritySuperuserConfirmed ||
		authority.ExpectedAdminIdentity == "" || authority.ExpectedAdminIdentity != authority.ObservedAdminIdentity ||
		authority.CredentialIncarnation <= 0 || authority.ConfigIncarnation != connections.ConfigIncarnation(conn) ||
		authority.TargetIdentity == "" || authority.TargetIdentity != connections.TargetIdentity(conn) ||
		!IsPostgresStatsPermission(permission) || acct.Kind != inventory.AccountKindLogin || postgres.ProtectedRole(acct.EngineIdentity) {
		return nil, postgres.ErrStatsMembershipUnsupported
	}
	pins := &postgres.StatsMembershipPins{AdminIdentity: authority.ExpectedAdminIdentity, TargetIdentity: authority.TargetIdentity,
		ConfigIncarnation: authority.ConfigIncarnation, CredentialIncarnation: authority.CredentialIncarnation,
		BuiltinOID: postgres.RoleOID(permission.Attributes), SubjectOID: postgres.RoleOID(acct.Attributes)}
	if pins.BuiltinOID == 0 {
		return nil, postgres.ErrStatsMembershipUnsupported
	}
	if creationID != uuid.Nil {
		if acct.Status != inventory.AccountProvisioning {
			return nil, postgres.ErrStatsMembershipUnsupported
		}
		pins.SubjectOID = 0
		return pins, nil
	}
	if acct.Status != inventory.AccountActive && acct.Status != inventory.AccountDisabled {
		return nil, postgres.ErrStatsMembershipUnsupported
	}
	if pins.SubjectOID == 0 {
		// A verified creation receipt is an independent incarnation proof, not
		// a role-name lookup. The adapter still compares the live OID.
		if err := q.QueryRow(ctx, `select role_oid from account_creation_receipts where account_id=$1 and connection_id=$2
			and engine_identity=$3 and target_identity=$4 and phase='verified' and role_oid>0 order by updated_at desc limit 1`,
			acct.ID, conn.ID, acct.EngineIdentity, pins.TargetIdentity).Scan(&pins.SubjectOID); err != nil {
			return nil, err
		}
	}
	return pins, nil
}

func (e *MainExecutor) resolveStatsMembershipSubject(ctx context.Context, payload AccessPayload, acct inventory.Account) error {
	pins := payload.StatsMembership
	if pins == nil {
		return terminal(postgres.ErrStatsMembershipUnsupported)
	}
	if payload.StatsCreationOperationID == uuid.Nil {
		if pins.SubjectOID == 0 {
			return terminal(postgres.ErrStatsMembershipUnsupported)
		}
		return nil
	}
	r, err := accountcreation.NewStore().Get(ctx, e.deps.Pool, payload.StatsCreationOperationID)
	if err != nil {
		return err
	}
	oid, err := statsCreationSubjectOID(payload, acct, r)
	if err != nil {
		return terminal(err)
	}
	pins.SubjectOID = oid
	return nil
}

func statsCreationSubjectOID(payload AccessPayload, acct inventory.Account, r accountcreation.Receipt) (uint32, error) {
	pins := payload.StatsMembership
	if pins == nil || pins.SubjectOID != 0 || r.OperationID != payload.StatsCreationOperationID {
		return 0, postgres.ErrStatsMembershipUnsupported
	}
	if r.Phase != "verified" || r.RoleOID == 0 || r.AccountID != acct.ID || r.ConnectionID != acct.ConnectionID ||
		r.EngineIdentity != acct.EngineIdentity || r.TargetIdentity != pins.TargetIdentity ||
		r.ConfigIncarnation != pins.ConfigIncarnation || r.AdminIdentity != pins.AdminIdentity ||
		r.AdminCredentialIncarnation != pins.CredentialIncarnation || r.LifecycleVersion != payload.ExpectedAccountLifecycleVersion ||
		acct.Status != inventory.AccountActive {
		return 0, fmt.Errorf("statistics subject creation proof is stale or incomplete: %w", adapter.ErrTargetIdentityConflict)
	}
	return r.RoleOID, nil
}
