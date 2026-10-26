package jobs

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestDatabaseCreationProofRequiresExactReceipt(t *testing.T) {
	for _, oid := range []any{uint32(42), float64(42), json.Number("42")} {
		v := &adapter.Verification{Verified: true, Observed: map[string]any{
			"database_oid": oid, "database_name": "app", "database_owner": "owner",
			"database_owner_oid": oid, "target_identity": "postgres:system:1",
		}}
		got, err := parseDatabaseCreationProof(v, "app", "postgres:system:1")
		if err != nil || got.OID != 42 || got.Owner != "owner" || got.OwnerOID != 42 {
			t.Fatalf("proof=%+v err=%v", got, err)
		}
	}
	for _, tc := range []struct {
		name  string
		proof *adapter.Verification
	}{
		{"nil", nil}, {"no observed", &adapter.Verification{Verified: true}},
		{"wrong database", &adapter.Verification{Verified: true, Observed: map[string]any{"database_oid": uint32(42), "database_name": "foreign", "database_owner": "owner", "database_owner_oid": uint32(43), "target_identity": "postgres:system:1"}}},
		{"wrong target", &adapter.Verification{Verified: true, Observed: map[string]any{"database_oid": uint32(42), "database_name": "app", "database_owner": "owner", "database_owner_oid": uint32(43), "target_identity": "postgres:system:2"}}},
		{"fractional oid", &adapter.Verification{Verified: true, Observed: map[string]any{"database_oid": 42.5, "database_name": "app", "database_owner": "owner", "database_owner_oid": uint32(43), "target_identity": "postgres:system:1"}}},
		{"missing owner oid", &adapter.Verification{Verified: true, Observed: map[string]any{"database_oid": uint32(42), "database_name": "app", "database_owner": "owner", "target_identity": "postgres:system:1"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseDatabaseCreationProof(tc.proof, "app", "postgres:system:1"); err == nil {
				t.Fatal("accepted absent or mismatched proof")
			}
		})
	}
}

func TestDatabaseRoleTemplatesFixedPair(t *testing.T) {
	pair, err := databaseRoleTemplates("App_DB", "app_owner", []string{"z_schema", "public"})
	if err != nil {
		t.Fatal(err)
	}
	if len(pair) != 2 || pair[0].RoleName != "r_App_DB" || pair[1].RoleName != "rw_App_DB" || pair[0].Profile != "read" || pair[1].Profile != "read_write" {
		t.Fatalf("unexpected pair: %+v", pair)
	}
	if pair[0].Key != "pg-app_db-read" || pair[1].Key != "pg-app_db-read-write" ||
		!reflect.DeepEqual(pair[0].Schemas, []string{"public", "z_schema"}) ||
		!reflect.DeepEqual(pair[0].OwnerRoles, []string{"app_owner"}) || !reflect.DeepEqual(pair[0].CreatorRoles, []string{"app_owner"}) {
		t.Fatalf("unexpected derived scope: %+v", pair)
	}
	for _, tc := range []struct {
		name, owner string
		schemas     []string
	}{
		{"bad-name", "owner", []string{"public"}}, {strings.Repeat("a", 61), "owner", []string{"public"}},
		{"app", "", []string{"public"}}, {"app", "owner", nil},
	} {
		if _, err := databaseRoleTemplates(tc.name, tc.owner, tc.schemas); err == nil {
			t.Fatalf("accepted unsupported scope %+v", tc)
		}
	}
	if _, err := databaseRoleTemplates("app", "owner", []string{"grantor"}); err != nil {
		t.Fatalf("the former helper schema must be an ordinary valid scope: %v", err)
	}
}

func TestDatabaseWorkflowChildrenHaveStableDistinctIdentities(t *testing.T) {
	parent := uuid.New()
	seen := map[uuid.UUID]bool{}
	for _, stage := range []string{"database", "discover_database", "discover_policies", "read", "read_write"} {
		id := databaseChildID(parent, stage)
		if id == parent || seen[id] || id != databaseChildID(parent, stage) || id == databaseChildID(uuid.New(), stage) {
			t.Fatal("unstable or shared child identity")
		}
		seen[id] = true
	}
}
