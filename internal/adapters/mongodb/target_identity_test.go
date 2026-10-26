package mongodb

import (
	"errors"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestStandaloneProcessIDAcceptsOnlyObjectID(t *testing.T) {
	id := primitive.NewObjectID()
	for _, tc := range []struct {
		name  string
		hello bson.M
		want  string
	}{
		{
			name:  "bson map",
			hello: bson.M{"topologyVersion": bson.M{"processId": id}},
			want:  id.Hex(),
		},
		{
			name:  "ordered bson",
			hello: bson.M{"topologyVersion": bson.D{{Key: "processId", Value: id}}},
			want:  id.Hex(),
		},
		{
			name:  "validated hex string",
			hello: bson.M{"topologyVersion": bson.M{"processId": id.Hex()}},
			want:  id.Hex(),
		},
		{
			name:  "arbitrary string rejected",
			hello: bson.M{"topologyVersion": bson.M{"processId": "node-a"}},
		},
		{name: "missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := standaloneProcessID(tc.hello); got != tc.want {
				t.Fatalf("standaloneProcessID = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequireMongoTargetIdentityFailsClosedWithoutExpectedIdentity(t *testing.T) {
	err := requireMongoTargetIdentity(t.Context(), nil, "")
	if !errors.Is(err, adapter.ErrTargetIdentityConflict) {
		t.Fatalf("error = %v, want ErrTargetIdentityConflict", err)
	}
}
