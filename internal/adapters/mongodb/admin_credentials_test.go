package mongodb

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
)

func TestMongoAdminUpdateUserCommandRequiresMajorityWriteConcern(t *testing.T) {
	command := mongoAdminUpdateUserCommand("grantor", []byte("candidate"))
	raw, err := bson.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	var decoded bson.M
	if err := bson.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	writeConcern, ok := decoded["writeConcern"].(bson.M)
	if !ok || writeConcern["w"] != "majority" {
		t.Fatalf("writeConcern = %#v, want majority", decoded["writeConcern"])
	}
}
