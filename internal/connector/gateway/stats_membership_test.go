package gateway_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

func TestStatsMembershipGatewayRequiresBothMarkersBeforeAnyFrame(t *testing.T) {
	for _, caps := range [][]connector.Capability{{adapter.CapPostgresSuperuserDirectV1}, {adapter.CapPostgresStatsMembershipV1}} {
		t.Run(string(caps[0]), func(t *testing.T) {
			srv, addr, clientTLS := startGateway(t)
			conn := dialRaw(t, addr, clientTLS)
			if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "stats-runtime", Capabilities: caps}); err != nil {
				t.Fatal(err)
			}
			var ack wire.HelloAck
			if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
				t.Fatal(err)
			}
			for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresStatsMembershipGrantV1, adapter.ChangePostgresStatsMembershipRevokeV1} {
				for _, jobKind := range []connector.JobKind{connector.JobPlan, connector.JobApply, connector.JobVerify} {
					p := connector.MutationPayload{Connection: connector.ConnectionRef{ID: "stats-connection", Engine: "postgres", ConfigIncarnation: "stats-config"},
						Change: connector.ChangeRef{Kind: string(kind), Account: connector.AccountRef{Kind: "login", EngineIdentity: "monitor"}, Permission: "role:pg_read_all_stats",
							ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42", StatsMembership: &adapter.PostgresStatsMembershipPins{
								AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "stats-config", CredentialIncarnation: 3, BuiltinOID: 3375, SubjectOID: 17001}}}
					raw, err := p.Marshal()
					if err != nil {
						t.Fatal(err)
					}
					creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: "grantor", Secret: []byte("stats-gateway-canary")}, AdminCredentialIncarnation: 3}
					_, err = srv.Dispatch(t.Context(), connector.Job{ID: string(kind) + string(jobKind), Kind: jobKind, Engine: "postgres", ConnectionID: "stats-connection", ProtocolVersion: connector.ProtocolVersion, Payload: raw}, creds)
					creds.Zero()
					if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
						t.Fatalf("stats job was not rejected before dispatch: %v", err)
					}
				}
			}
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var one [1]byte
			if n, err := conn.Read(one[:]); n != 0 || err == nil {
				t.Fatal("job or credential frame sent to incompatible runtime")
			}
		})
	}
}
