package api

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

type inventoryFreshness struct {
	Status          string           `json:"status"`
	SnapshotVersion string           `json:"snapshot_version"`
	ObservedAt      *time.Time       `json:"observed_at"`
	RefreshRequired bool             `json:"refresh_required"`
	Reason          string           `json:"reason,omitempty"`
	PolicyVersions  map[string]int64 `json:"role_policy_versions"`
}

func inventoryFreshnessFor(c connections.Connection, policies []rolepolicies.Policy) *inventoryFreshness {
	if c.Engine != "postgres" {
		return nil
	}
	f := &inventoryFreshness{Status: "current", ObservedAt: c.LastDiscoveryAt, PolicyVersions: map[string]int64{}}
	for _, policy := range policies {
		f.PolicyVersions[policy.TemplateKey] = policy.Version
	}
	if c.LastDiscoveryAt == nil {
		f.Status, f.RefreshRequired, f.Reason = "unavailable", true, "inventory_not_observed"
		return f
	}
	f.SnapshotVersion = c.LastDiscoveryAt.UTC().Format(time.RFC3339Nano)
	for _, policy := range policies {
		// Complete updates the policy observation and assignability, but the
		// object ACL attributes remain those of the last discovery snapshot.
		if policy.ObservedAt != nil && policy.ObservedAt.After(*c.LastDiscoveryAt) {
			f.Status, f.RefreshRequired, f.Reason = "stale", true, "role_policy_newer_than_inventory"
			return f
		}
	}
	var topology struct {
		Incomplete []string `json:"postgres_object_acl_incomplete_scopes"`
	}
	if json.Unmarshal(c.Topology, &topology) == nil && len(topology.Incomplete) > 0 {
		f.Status, f.RefreshRequired, f.Reason = "partial", true, "incomplete_discovery"
	}
	return f
}

func inventoryFreshnessForSnapshot(ctx context.Context, q rolepolicies.Querier, c connections.Connection, policies []rolepolicies.Policy) (*inventoryFreshness, error) {
	freshness := inventoryFreshnessFor(c, policies)
	if freshness == nil || freshness.Status == "unavailable" || freshness.Status == "stale" {
		return freshness, nil
	}
	store := rolepolicies.NewStore()
	for _, policy := range policies {
		if policy.TransitionOperationID == nil {
			continue
		}
		_, active, err := store.Repairability(ctx, q, policy)
		if err != nil {
			return nil, err
		}
		if active {
			freshness.Status, freshness.RefreshRequired, freshness.Reason = "stale", true, "role_policy_transition_in_progress"
			break
		}
	}
	return freshness, nil
}
