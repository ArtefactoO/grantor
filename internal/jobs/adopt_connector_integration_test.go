//go:build integration

package jobs_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

// The lifecycle test shares real PostgreSQL/Vault assertions with direct mode;
// only execution moves across the signed mTLS gateway/agent boundary.
func startAdoptProofConnector(t *testing.T) *gateway.Server {
	t.Helper()
	pair := conntest.GenTLS(t, "localhost", "connector-proof")
	key := []byte("integration-proof-signing-key")
	srv, err := gateway.New(gateway.Config{TLS: pair.ServerTLS, Signer: connector.NewHMACSigner("proof", key)})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	ag, err := agent.New(agent.Config{
		ConnectorID: "connector-proof", GatewayAddr: ln.Addr().String(), TLS: pair.ClientTLS,
		Verifier:     connector.NewHMACVerifier("proof", key),
		Capabilities: append(postgres.New().Manifest().Capabilities, connector.CapCredentialProofV1),
		NewAdapter:   func(string) (adapter.Adapter, error) { return postgres.New(), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- ag.Run(ctx) }()
	t.Cleanup(func() { cancel(); _ = srv.Close(); _ = ln.Close(); <-done })
	ready, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	if err := srv.WaitReady(ready); err != nil {
		t.Fatal(err)
	}
	return srv
}
