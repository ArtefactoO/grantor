package api

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

func TestInventoryFreshnessTracksPolicyAndDiscoverySnapshots(t *testing.T) {
	at := time.Date(2026, 10, 20, 10, 0, 0, 123000000, time.UTC)
	newer := at.Add(time.Second)
	for _, tc := range []struct {
		name     string
		at       *time.Time
		policies []rolepolicies.Policy
		topology json.RawMessage
		status   string
		reason   string
	}{
		{name: "no snapshot", status: "unavailable", reason: "inventory_not_observed"},
		{name: "same snapshot", at: &at, policies: []rolepolicies.Policy{{TemplateKey: "read", Version: 2, ObservedAt: &at}}, status: "current"},
		{name: "completed policy", at: &at, policies: []rolepolicies.Policy{{TemplateKey: "read", Version: 3, ObservedAt: &newer}}, status: "stale", reason: "role_policy_newer_than_inventory"},
		{name: "refreshed snapshot", at: &newer, policies: []rolepolicies.Policy{{TemplateKey: "read", Version: 3, ObservedAt: &newer}}, status: "current"},
		{name: "incomplete discovery", at: &at, topology: json.RawMessage(`{"postgres_object_acl_incomplete_scopes":["app"]}`), status: "partial", reason: "incomplete_discovery"},
		{name: "stale dominates partial", at: &at, topology: json.RawMessage(`{"postgres_object_acl_incomplete_scopes":["app"]}`), policies: []rolepolicies.Policy{{TemplateKey: "read", Version: 3, ObservedAt: &newer}}, status: "stale", reason: "role_policy_newer_than_inventory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := inventoryFreshnessFor(connections.Connection{Engine: "postgres", LastDiscoveryAt: tc.at, Topology: tc.topology}, tc.policies)
			if got.Status != tc.status || got.Reason != tc.reason || got.RefreshRequired != (tc.status != "current") {
				t.Fatalf("freshness = %+v", got)
			}
			versions := map[string]int64{}
			for _, policy := range tc.policies {
				versions[policy.TemplateKey] = policy.Version
			}
			if !reflect.DeepEqual(got.PolicyVersions, versions) {
				t.Fatalf("policy versions = %v, want %v", got.PolicyVersions, versions)
			}
			if tc.at != nil && (got.SnapshotVersion != tc.at.UTC().Format(time.RFC3339Nano) || !got.ObservedAt.Equal(*tc.at)) {
				t.Fatalf("snapshot identity = %+v", got)
			}
		})
	}
	if inventoryFreshnessFor(connections.Connection{Engine: "mongodb"}, nil) != nil {
		t.Fatal("unrelated engine received PostgreSQL freshness metadata")
	}
}
