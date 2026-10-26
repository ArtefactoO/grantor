package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

const KindPostgresObjectACLGrantV1 = "postgres.object_acl.grant.v1"
const KindPostgresObjectACLRevokeV1 = "postgres.object_acl.revoke.v1"

func IsPostgresObjectPermission(p inventory.Permission) bool {
	return p.Engine == postgres.Engine && strings.HasPrefix(p.ExternalID, adapter.PostgresObjectACLPrefix)
}

func BuildObjectACLPins(conn connections.Connection, acct inventory.Account, permission inventory.Permission, binding *inventory.Binding) (*adapter.PostgresObjectACLPins, error) {
	p, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
	if err != nil || p.Kind == "column" || !IsPostgresObjectPermission(permission) {
		return nil, adapter.ErrPostgresObjectACL
	}
	var config struct {
		Templates []struct {
			RoleName string `json:"role_name"`
		} `json:"postgres_role_policy_templates"`
	}
	if len(conn.DiscoveryConfig) > 0 && json.Unmarshal(conn.DiscoveryConfig, &config) != nil {
		return nil, adapter.ErrPostgresObjectACL
	}
	for _, template := range config.Templates {
		if template.RoleName == acct.EngineIdentity {
			return nil, fmt.Errorf("use the existing role policy workflow for this role: %w", adapter.ErrPostgresObjectACL)
		}
	}
	var topology map[string]any
	if json.Unmarshal(conn.Topology, &topology) != nil {
		return nil, adapter.ErrPostgresObjectACL
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	if !ok || conn.Engine != postgres.Engine || conn.Status != connections.StatusActive ||
		(conn.ExecutionMode != connections.ExecutionModeDirect && conn.ExecutionMode != connections.ExecutionModeConnector) ||
		!slices.Contains(conn.Capabilities, string(adapter.CapPostgresObjectACLV1)) ||
		authority.Status != adapter.ProvisioningAuthorityConfirmed || authority.Reason != adapter.ProvisioningAuthoritySuperuserConfirmed ||
		authority.ExpectedAdminIdentity == "" || authority.ExpectedAdminIdentity != authority.ObservedAdminIdentity ||
		authority.CredentialIncarnation <= 0 || authority.ConfigIncarnation != connections.ConfigIncarnation(conn) ||
		authority.TargetIdentity != connections.TargetIdentity(conn) || authority.TargetIdentity != p.TargetIdentity ||
		(acct.Status != inventory.AccountActive && acct.Status != inventory.AccountDisabled) || postgres.ProtectedRole(acct.EngineIdentity) ||
		acct.EngineIdentity == authority.ExpectedAdminIdentity {
		return nil, adapter.ErrPostgresObjectACL
	}
	oid := postgres.RoleOID(acct.Attributes)
	if oid == 0 || oid == p.OwnerOID {
		return nil, adapter.ErrPostgresObjectACL
	}
	pins := &adapter.PostgresObjectACLPins{AdminIdentity: authority.ExpectedAdminIdentity, TargetIdentity: authority.TargetIdentity,
		ConfigIncarnation: authority.ConfigIncarnation, CredentialIncarnation: authority.CredentialIncarnation, SubjectOID: oid}
	if binding != nil {
		var observed struct {
			Grantors []adapter.PostgresACLGrantor `json:"grantors"`
		}
		if err := json.Unmarshal(binding.ObservedAttributes, &observed); err != nil {
			return nil, err
		}
		pins.Grantors = observed.Grantors
		if binding.ObservedState == inventory.BindingPresent && len(pins.Grantors) == 0 {
			return nil, fmt.Errorf("refresh object ACL discovery before revoking: %w", adapter.ErrPostgresObjectACL)
		}
		for _, g := range pins.Grantors {
			if g.GrantOption {
				return nil, fmt.Errorf("delegating ACL requires separate review: %w", adapter.ErrPostgresObjectACL)
			}
		}
	}
	return pins, nil
}

func (e *MainExecutor) preflightObjectACLConnector(ctx context.Context, operationKind string, id uuid.UUID) error {
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, id)
	if err != nil {
		return err
	}
	via, err := connectorRoute(conn.ExecutionMode, operationKind, e.conn.Dispatcher != nil)
	if err != nil || !via {
		return err
	}
	for _, capability := range []adapter.Capability{adapter.CapPostgresObjectACLV1, adapter.CapPostgresSuperuserDirectV1} {
		if err := e.requireActiveConnectorCapability(capability); err != nil {
			return err
		}
	}
	return nil
}
