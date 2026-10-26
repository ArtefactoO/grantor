package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

func TestAccountCreationGatewayRequiresBothRuntimeMarkersBeforeCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []connector.Capability
	}{
		{"legacy authority only", []connector.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapCredentialProve}},
		{"new contract without authority", []connector.Capability{adapter.CapPostgresAccountCreationV1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, addr, clientTLS := startGateway(t)
			conn := dialRaw(t, addr, clientTLS)
			if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "creation-runtime", Capabilities: tc.caps}); err != nil {
				t.Fatal(err)
			}
			var ack wire.HelloAck
			if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
				t.Fatal(err)
			}
			for _, stage := range []string{"preflight", "create", "verify"} {
				payload := connector.AccountCreationPayload{Stage: stage, AccountID: "account-id", Request: connector.MutationPayload{
					Connection: connector.ConnectionRef{ID: "connection-id", Engine: "postgres", ConfigIncarnation: "config-1"},
					Change: connector.ChangeRef{Kind: string(adapter.ChangePostgresAccountCreateV2),
						Account:               connector.AccountRef{Kind: "login", EngineIdentity: "created_login"},
						ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42"}}}
				if stage == "verify" {
					payload.Proof = &adapter.AccountCreationProof{EngineIdentity: "created_login", RoleOID: 123, TargetIdentity: "postgres:system:42"}
				}
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: "grantor", Secret: []byte("gateway-creation-canary")},
					AdminCredentialIncarnation: 3, Account: &adapter.Credential{Kind: "password", Username: "created_login", Secret: []byte("gateway-creation-canary")}, AccountVaultVersion: 7}
				ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
				_, err = srv.Dispatch(ctx, connector.Job{ID: "creation-" + stage, Kind: connector.JobAccountCreation, Engine: "postgres", ConnectionID: "connection-id",
					ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "creation-" + stage, Payload: raw}, creds)
				cancel()
				creds.Zero()
				if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
					t.Fatalf("stage %s was not rejected before dispatch: %v", stage, err)
				}
			}
			// Rejection must not write either the signed job or TypeCredentials.
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var one [1]byte
			if n, err := conn.Read(one[:]); n != 0 || err == nil {
				t.Fatal("gateway sent a frame to a connector missing a required marker")
			}
		})
	}
}
