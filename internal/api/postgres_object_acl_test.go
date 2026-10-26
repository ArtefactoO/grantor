package api

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestObjectACLPinsRequireAuthorityAndPreserveExternalOwnership(t *testing.T) {
	p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: "items", ObjectOID: 12, OwnerOID: 13, Privilege: "SELECT"}
	permission := inventory.Permission{Engine: "postgres", ExternalID: p.PermissionID()}
	account := inventory.Account{EngineIdentity: "alice", Kind: inventory.AccountKindLogin, Status: inventory.AccountActive, Ownership: inventory.OwnershipUnmanaged, Attributes: json.RawMessage(`{"role_oid":20}`)}
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		conn := statsAuthorityFixture(t, mode)
		conn.Capabilities = append(conn.Capabilities, string(adapter.CapPostgresObjectACLV1))
		pins, err := jobs.BuildObjectACLPins(conn, account, permission, nil)
		if err != nil || pins.SubjectOID != 20 || account.Ownership != inventory.OwnershipUnmanaged {
			t.Fatalf("%s direct intent: %v", mode, err)
		}
		conn.Endpoints = []string{"10.0.0.11:5432"}
		if _, err := jobs.BuildObjectACLPins(conn, account, permission, nil); !errors.Is(err, adapter.ErrPostgresObjectACL) {
			t.Fatal("changed config accepted")
		}
	}
	conn := statsAuthorityFixture(t, connections.ExecutionModeConnector)
	if _, err := jobs.BuildObjectACLPins(conn, account, permission, nil); !errors.Is(err, adapter.ErrPostgresObjectACL) {
		t.Fatal("old connector accepted")
	}
	conn.Capabilities = append(conn.Capabilities, string(adapter.CapPostgresObjectACLV1))
	binding := inventory.Binding{ObservedState: inventory.BindingPresent, ObservedAttributes: json.RawMessage(`{"grantors":[{"oid":13,"name":"owner","grant_option":true}]}`)}
	if _, err := jobs.BuildObjectACLPins(conn, account, permission, &binding); !errors.Is(err, adapter.ErrPostgresObjectACL) {
		t.Fatal("delegating external grant accepted for revoke")
	}
	conn.DiscoveryConfig = json.RawMessage(`{"postgres_role_policy_templates":[{"role_name":"alice"}]}`)
	if _, err := jobs.BuildObjectACLPins(conn, account, permission, nil); !errors.Is(err, adapter.ErrPostgresObjectACL) {
		t.Fatal("managed role policy bypass accepted")
	}
}
