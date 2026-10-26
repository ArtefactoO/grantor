package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

type statsCapabilityDispatcher struct {
	capabilities []adapter.Capability
	dispatches   int
}

func (d *statsCapabilityDispatcher) ActiveConnectorSupports(capability adapter.Capability) bool {
	return slices.Contains(d.capabilities, capability)
}

func (d *statsCapabilityDispatcher) Dispatch(context.Context, connector.Job, connector.JobCredentials) (connector.JobResult, error) {
	d.dispatches++
	return connector.JobResult{}, errors.New("unexpected dispatch during capability preflight")
}

func TestStatisticsConnectorRequiresBothMarkersWithoutDispatch(t *testing.T) {
	for _, capabilities := range [][]adapter.Capability{
		nil, {adapter.CapAccessGrant}, {adapter.CapPostgresSuperuserDirectV1}, {adapter.CapPostgresStatsMembershipV1},
		{adapter.CapPostgresStatsMembershipV1, adapter.CapPostgresSuperuserDirectV1},
	} {
		d := &statsCapabilityDispatcher{capabilities: capabilities}
		e := (&MainExecutor{}).WithConnector(ConnectorDeps{Dispatcher: d})
		err := e.requireStatsMembershipConnectorCapabilities()
		want := slices.Contains(capabilities, adapter.CapPostgresStatsMembershipV1) && slices.Contains(capabilities, adapter.CapPostgresSuperuserDirectV1)
		if (err == nil) != want || d.dispatches != 0 {
			t.Fatalf("capability fence = %v; dispatches=%d", err, d.dispatches)
		}
	}
}

func TestStatisticsPinsAcceptOnlyNegotiatedConnectorAndExactRoleIncarnation(t *testing.T) {
	conn := connections.Connection{ID: uuid.New(), Engine: postgres.Engine, ExecutionMode: connections.ExecutionModeConnector,
		Status: connections.StatusActive, Endpoints: []string{"10.0.0.10:5432"},
		Capabilities: []string{string(adapter.CapPostgresStatsMembershipV1)}}
	var err error
	conn.Topology, err = json.Marshal(map[string]any{"system_identifier": "42", adapter.PostgresProvisioningAuthorityTopologyKey: adapter.ProvisioningAuthorityAssessment{
		Status: adapter.ProvisioningAuthorityConfirmed, Reason: adapter.ProvisioningAuthoritySuperuserConfirmed,
		ObservedAt:            time.Now(),
		ExpectedAdminIdentity: "grantor", ObservedAdminIdentity: "grantor", CredentialIncarnation: 3,
		ConfigIncarnation: connections.ConfigIncarnation(conn), TargetIdentity: "postgres:system:42"}})
	if err != nil {
		t.Fatal(err)
	}
	acct := inventory.Account{ID: uuid.New(), ConnectionID: conn.ID, Kind: inventory.AccountKindLogin, EngineIdentity: "monitor",
		Status: inventory.AccountActive, Attributes: json.RawMessage(`{"role_oid":17001}`)}
	permission := inventory.Permission{Engine: postgres.Engine, ExternalID: postgres.StatsPermission, Attributes: json.RawMessage(`{"role_oid":3375}`)}
	pins, err := BuildStatsMembershipPins(t.Context(), nil, conn, acct, permission, uuid.Nil)
	if err != nil || pins.SubjectOID != 17001 || pins.BuiltinOID != 3375 {
		t.Fatalf("exact connector pins refused: %+v %v", pins, err)
	}
	conn.Capabilities = nil
	if _, err := BuildStatsMembershipPins(t.Context(), nil, conn, acct, permission, uuid.Nil); err == nil {
		t.Fatal("old connector admitted a new pinned operation")
	}
}
