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

func TestObjectACLGatewayRejectsOldConnectorBeforeCredentials(t *testing.T) {
	for _, caps := range [][]connector.Capability{{adapter.CapPostgresSuperuserDirectV1}, {adapter.CapPostgresObjectACLV1}} {
		srv, addr, clientTLS := startGateway(t)
		conn := dialRaw(t, addr, clientTLS)
		if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "object-acl-runtime", Capabilities: caps}); err != nil {
			t.Fatal(err)
		}
		var ack wire.HelloAck
		if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
			t.Fatal(err)
		}
		p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: "items", ObjectOID: 12, OwnerOID: 13, Privilege: "SELECT"}
		pins := &adapter.PostgresObjectACLPins{AdminIdentity: "grantor", TargetIdentity: p.TargetIdentity, ConfigIncarnation: "config", CredentialIncarnation: 1, SubjectOID: 20}
		for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresObjectACLGrantV1, adapter.ChangePostgresObjectACLRevokeV1} {
			body := connector.MutationPayload{Connection: connector.ConnectionRef{ID: "acl", Engine: "postgres", ConfigIncarnation: "config"}, Change: connector.ChangeRef{
				Kind: string(kind), Account: connector.AccountRef{Kind: "login", EngineIdentity: "alice"}, Permission: p.PermissionID(), Scope: p.Scope(), ObjectACL: pins, ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity}}
			raw, _ := body.Marshal()
			creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: "grantor", Secret: []byte("acl-frame-canary")}, AdminCredentialIncarnation: 1}
			_, err := srv.Dispatch(t.Context(), connector.Job{ID: string(kind), Kind: connector.JobApply, Engine: "postgres", ConnectionID: "acl", ProtocolVersion: connector.ProtocolVersion, Payload: raw}, creds)
			creds.Zero()
			if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
				t.Fatalf("old runtime received object mutation: %v", err)
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var one [1]byte
		if n, err := conn.Read(one[:]); n != 0 || err == nil {
			t.Fatal("credential or job frame reached incompatible connector")
		}
	}
}
