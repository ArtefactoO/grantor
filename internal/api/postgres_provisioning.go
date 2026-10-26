package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

var errPostgresProvisioningAuthority = errors.New("PostgreSQL SUPERUSER provisioning authority is not current")

type postgresProvisioningPins struct {
	AdminIdentity         string
	TargetIdentity        string
	CredentialIncarnation int
	ConfigIncarnation     string
	CatalogFingerprint    string
}

func requirePostgresProvisioningAuthority(conn connections.Connection,
	required ...adapter.Capability,
) (postgresProvisioningPins, error) {
	if conn.Engine != "postgres" {
		return postgresProvisioningPins{}, nil
	}
	authority := postgresProvisioningAuthorityProjection(conn)
	if authority == nil || conn.Status != connections.StatusActive ||
		authority.Status != adapter.ProvisioningAuthorityConfirmed ||
		authority.Reason != adapter.ProvisioningAuthoritySuperuserConfirmed ||
		authority.ExpectedAdminIdentity == "" || authority.ObservedAdminIdentity != authority.ExpectedAdminIdentity ||
		authority.CredentialIncarnation <= 0 || authority.ConfigIncarnation != connections.ConfigIncarnation(conn) ||
		authority.TargetIdentity == "" {
		return postgresProvisioningPins{}, fmt.Errorf("%w: refresh discovery with the configured SUPERUSER admin credential",
			errPostgresProvisioningAuthority)
	}
	caps := connectionCapabilitiesForProjection(conn)
	for _, capability := range append([]adapter.Capability{adapter.CapPostgresSuperuserDirectV1}, required...) {
		if !slices.Contains(caps, string(capability)) {
			return postgresProvisioningPins{}, fmt.Errorf("%w: capability %s is unavailable",
				errPostgresProvisioningAuthority, capability)
		}
	}
	var topology map[string]any
	if err := json.Unmarshal(conn.Topology, &topology); err != nil {
		return postgresProvisioningPins{}, fmt.Errorf("%w: malformed discovery topology", errPostgresProvisioningAuthority)
	}
	target := connections.TargetIdentity(conn)
	if target == "" || target != authority.TargetIdentity {
		return postgresProvisioningPins{}, fmt.Errorf("%w: physical target identity is inconsistent", errPostgresProvisioningAuthority)
	}
	pins := postgresProvisioningPins{
		AdminIdentity: authority.ExpectedAdminIdentity, TargetIdentity: target,
		CredentialIncarnation: authority.CredentialIncarnation,
		ConfigIncarnation:     authority.ConfigIncarnation,
		CatalogFingerprint:    adapterutil.StringAttr(topology, "postgres_role_policy_catalog_fingerprint"),
	}
	if slices.Contains(required, adapter.CapRolePolicyApply) || slices.Contains(required, adapter.CapRolePolicyCreate) {
		templates, err := postgresconfig.FromAttributes(connectionDiscoveryAttributes(conn))
		if err != nil || pins.CatalogFingerprint == "" ||
			pins.CatalogFingerprint != postgresconfig.CatalogFingerprint(templates) {
			return postgresProvisioningPins{}, fmt.Errorf("%w: role-policy catalog snapshot is stale",
				errPostgresProvisioningAuthority)
		}
	}
	return pins, nil
}

func connectionDiscoveryAttributes(conn connections.Connection) map[string]any {
	cfg, err := connections.AdapterConfig(conn)
	if err != nil {
		return nil
	}
	return cfg.Attributes
}

// lockProvisioningConnections acquires all connection advisory locks
// in stable order across engines before any item/account row lock or shared
// Vault IO. Per-item authority checks run under these same transaction locks.
func lockProvisioningConnections(ctx context.Context, tx pgx.Tx,
	items []connections.Connection,
) error {
	ids := make([]uuid.UUID, 0, len(items))
	for i := range items {
		if !slices.Contains(ids, items[i].ID) {
			ids = append(ids, items[i].ID)
		}
	}
	slices.SortFunc(ids, func(left, right uuid.UUID) int {
		return strings.Compare(left.String(), right.String())
	})
	for _, id := range ids {
		if err := locks.AcquireTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
