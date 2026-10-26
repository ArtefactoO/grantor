package api

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

func statsAuthorityFixture(t *testing.T, mode string) connections.Connection {
	t.Helper()
	conn := connections.Connection{ID: uuid.New(), Engine: postgres.Engine, Environment: "test", Status: connections.StatusActive,
		ExecutionMode: mode, Endpoints: []string{"10.0.0.10:5432"}, TLSConfig: json.RawMessage(`{"mode":"disabled"}`),
		DiscoveryConfig: json.RawMessage(`{"database":"postgres"}`),
		Capabilities:    []string{string(adapter.CapAccessGrant), string(adapter.CapPostgresSuperuserDirectV1), string(adapter.CapPostgresStatsMembershipV1)}}
	observedAt := time.Now()
	conn.LastDiscoveryAt = &observedAt
	topology := map[string]any{"system_identifier": "42", adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt: observedAt, ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor", CredentialIncarnation: 1,
		ConfigIncarnation: connections.ConfigIncarnation(conn), TargetIdentity: "postgres:system:42"}}
	var err error
	conn.Topology, err = json.Marshal(topology)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestStatsMembershipConnectorRequiresNewCapabilityAndCurrentAuthority(t *testing.T) {
	permission := inventory.Permission{Engine: postgres.Engine, ExternalID: postgres.StatsPermission, Attributes: json.RawMessage(`{"role_oid":3375}`)}
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		conn := statsAuthorityFixture(t, mode)
		if err := requireStatsMembershipConnection(conn, permission); err != nil {
			t.Fatalf("current %s statistics authority refused: %v", mode, err)
		}
	}
	for _, test := range []struct {
		name string
		edit func(*connections.Connection, *inventory.Permission)
	}{
		{"old connector", func(c *connections.Connection, _ *inventory.Permission) {
			c.Capabilities = []string{string(adapter.CapAccessGrant), string(adapter.CapPostgresSuperuserDirectV1)}
		}},
		{"missing builtin OID", func(_ *connections.Connection, p *inventory.Permission) { p.Attributes = json.RawMessage(`{}`) }},
		{"changed endpoint", func(c *connections.Connection, _ *inventory.Permission) { c.Endpoints = []string{"10.0.0.11:5432"} }},
		{"degraded", func(c *connections.Connection, _ *inventory.Permission) { c.Status = connections.StatusDegraded }},
		{"unknown route", func(c *connections.Connection, _ *inventory.Permission) { c.ExecutionMode = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn, selected := statsAuthorityFixture(t, connections.ExecutionModeConnector), permission
			test.edit(&conn, &selected)
			if err := requireStatsMembershipConnection(conn, selected); !errors.Is(err, postgres.ErrStatsMembershipUnsupported) {
				t.Fatalf("unsupported statistics membership lost its conflict classification: %v", err)
			}
		})
	}
}
