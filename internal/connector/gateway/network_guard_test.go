package gateway_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

func TestGuardedDNSGatewayRejectsLegacyConnectorBeforeSecretFrames(t *testing.T) {
	srv, addr, clientTLS := startGateway(t)
	conn := dialRaw(t, addr, clientTLS)
	if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "legacy-dns",
		Capabilities: []connector.Capability{adapter.CapInventoryResources}}); err != nil {
		t.Fatal(err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		t.Fatal(err)
	}
	payload := connector.DiscoverPayload{Connection: connector.ConnectionRef{
		ID: "connection-id", Engine: "kafka", NetworkGuard: netguard.PrivateKubernetesDNSV1,
		Endpoints: []string{"kafka-cluster.test.svc.cluster.local:9092"},
	}}
	raw, err := payload.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err = srv.Dispatch(ctx, connector.Job{ID: "guarded-dns", Kind: connector.JobDiscover, Engine: "kafka", ConnectionID: "connection-id",
		ProtocolVersion: connector.ProtocolVersion, Payload: raw}, connector.JobCredentials{Admin: &adapter.Credential{
		Kind: "password", Username: "admin", Secret: []byte("guarded-dns-canary"),
	}})
	if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
		t.Fatalf("missing guard was not rejected: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var one [1]byte
	if n, err := conn.Read(one[:]); n != 0 || err == nil {
		t.Fatal("legacy connector received a job or credentials frame")
	}
}
