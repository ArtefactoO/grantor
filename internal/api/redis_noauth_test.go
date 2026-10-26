package api

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

func TestRedisNoAuthDTORejectsCredentialOrOtherEngine(t *testing.T) {
	req := createConnectionRequest{DisplayName: "test", Engine: "redis", AuthMode: "none", Endpoints: []string{"10.42.0.1:6379"}}
	if err := req.validate([]string{"redis", "postgres"}); err != nil {
		t.Fatal(err)
	}
	req.AdminCredential = &adminCredentialRequest{Username: "default", Password: "fixture"}
	if err := req.validate([]string{"redis"}); err == nil {
		t.Fatal("no-auth credential was accepted")
	}
	req.AdminCredential = nil
	req.Engine = "postgres"
	if err := req.validate([]string{"postgres"}); err == nil {
		t.Fatal("PostgreSQL no-auth was accepted")
	}
	reg := connectionRegistrationRequest{RegistrationKey: "test", RequestID: uuid.New(), DisplayName: "Redis", Engine: "redis", AuthMode: "none", Environment: "test", Endpoints: []string{"10.42.0.1:6379"}}
	if err := reg.validate([]string{"redis"}); err != nil {
		t.Fatal(err)
	}
	reg.CredentialSourceID = uuid.New()
	reg.CredentialSourceVersion = 1
	if err := reg.validate([]string{"redis"}); err == nil {
		t.Fatal("no-auth delegated password accepted")
	}
	c := toConnectionJSON(connections.Connection{Engine: "redis", AuthMode: "none"}, nil)
	if c.AuthMode != "none" || !slices.Contains(c.SecurityFindings, "authentication_disabled") {
		t.Fatalf("missing explicit no-auth projection: %+v", c)
	}
}

func TestRegistrationPasswordModeIsCanonicalForReplay(t *testing.T) {
	omitted := connectionRegistrationRequest{RegistrationKey: "redis-replay", RequestID: uuid.New(), DisplayName: "Redis", Engine: "redis", Environment: "test", Endpoints: []string{"10.42.0.1:6379"}, CredentialSourceID: uuid.New(), CredentialSourceVersion: 1}
	explicit := omitted
	explicit.AuthMode = "password"
	for _, request := range []*connectionRegistrationRequest{&omitted, &explicit} {
		if err := request.validate([]string{"redis"}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := omitted.spec()
	if err != nil {
		t.Fatal(err)
	}
	b, err := explicit.spec()
	if err != nil {
		t.Fatal(err)
	}
	if !rawJSONEqual(a, b) {
		t.Fatalf("equivalent password registrations changed replay intent: %s vs %s", a, b)
	}
	none := omitted
	none.AuthMode = "none"
	none.CredentialSourceID = uuid.Nil
	none.CredentialSourceVersion = 0
	if err = none.validate([]string{"redis"}); err != nil {
		t.Fatal(err)
	}
	c, err := none.spec()
	if err != nil {
		t.Fatal(err)
	}
	if rawJSONEqual(a, c) {
		t.Fatal("explicit no-auth lost its distinct registration intent")
	}
}
