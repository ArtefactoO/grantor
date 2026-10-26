package adapter

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAccountCreationProofContainsOnlyRoleIncarnation(t *testing.T) {
	proof := AccountCreationProof{EngineIdentity: "fixture_login", RoleOID: 42, TargetIdentity: "postgres:system:123"}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"engine_identity": "fixture_login", "role_oid": float64(42), "target_identity": "postgres:system:123"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proof wire shape = %v", got)
	}
	if CapPostgresAccountCreationV1 == CapPostgresSuperuserDirectV1 || CapPostgresAccountCreationV1 == CapAccountCreate {
		t.Fatal("creation proof capability collided with an older contract")
	}
}
