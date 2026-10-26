package api

import (
	"errors"
	"slices"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func requireStatsMembershipConnection(conn connections.Connection, permission inventory.Permission) error {
	if !jobs.IsPostgresStatsPermission(permission) {
		return nil
	}
	if (conn.ExecutionMode != connections.ExecutionModeDirect && conn.ExecutionMode != connections.ExecutionModeConnector) || postgres.RoleOID(permission.Attributes) == 0 {
		return postgres.ErrStatsMembershipUnsupported
	}
	required := []adapter.Capability{adapter.CapAccessGrant}
	if conn.ExecutionMode == connections.ExecutionModeConnector {
		if !slices.Contains(conn.Capabilities, string(adapter.CapPostgresStatsMembershipV1)) {
			return postgres.ErrStatsMembershipUnsupported
		}
		required = append(required, adapter.CapPostgresStatsMembershipV1)
	}
	_, err := requirePostgresProvisioningAuthority(conn, required...)
	if err != nil {
		return errors.Join(postgres.ErrStatsMembershipUnsupported, err)
	}
	return err
}
