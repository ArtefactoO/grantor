package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func postgresProfilesTestRequest() postgresProfilesRequest {
	return postgresProfilesRequest{RequestID: uuid.New(), Database: "app", ExpectedTargetIdentity: "postgres:system:7429012345678901234"}
}

func TestPostgresProfilesRequestAcceptsOnlyFixedProfilesAndPortableIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*postgresProfilesRequest)
	}{
		{"missing request", func(r *postgresProfilesRequest) { r.RequestID = uuid.Nil }},
		{"missing target", func(r *postgresProfilesRequest) { r.ExpectedTargetIdentity = "" }},
		{"target whitespace", func(r *postgresProfilesRequest) { r.ExpectedTargetIdentity += " " }},
		{"SQL identifier", func(r *postgresProfilesRequest) { r.Database = "app;drop" }},
		{"long role name", func(r *postgresProfilesRequest) { r.Database = strings.Repeat("a", 62) }},
		{"arbitrary profile", func(r *postgresProfilesRequest) { r.Profiles = []string{"admin"} }},
		{"duplicate profile", func(r *postgresProfilesRequest) { r.Profiles = []string{"read", "read"} }},
		{"duplicate schema", func(r *postgresProfilesRequest) { r.Schemas = []string{"public", "public"} }},
		{"reserved schema", func(r *postgresProfilesRequest) { r.Schemas = []string{"pg_catalog"} }},
		{"duplicate owner", func(r *postgresProfilesRequest) { r.OwnerRoles = []string{"owner", "owner"} }},
		{"invalid creator", func(r *postgresProfilesRequest) { r.CreatorRoles = []string{"owner;drop"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := postgresProfilesTestRequest()
			tc.change(&req)
			if req.normalizeAndValidate() == nil {
				t.Fatal("invalid profile request was accepted")
			}
		})
	}
	req := postgresProfilesTestRequest()
	if err := req.normalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	templates, err := standardPostgresTemplates(req, "app_owner")
	if err != nil || len(templates) != 2 || templates[0].RoleName != "r_app" || templates[1].RoleName != "rw_app" ||
		templates[0].OwnerRoles[0] != "app_owner" || templates[1].CreatorRoles[0] != "app_owner" {
		t.Fatalf("standard templates = %+v, err=%v", templates, err)
	}
}

func TestPostgresProfilesReplayBindsIntentConfigurationAndTarget(t *testing.T) {
	req := postgresProfilesTestRequest()
	if err := req.normalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	conn := connections.Connection{ID: uuid.New(), Engine: "postgres", Endpoints: []string{"postgres:5432"}, DiscoveryConfig: json.RawMessage(`{}`)}
	payload, err := json.Marshal(postgresProfilesPayload{Intent: postgresProfilesIntent{Request: req, ConfigIncarnation: connections.ConfigIncarnation(conn), TemplateKeys: []string{"read", "rw"}}})
	if err != nil {
		t.Fatal(err)
	}
	op := operations.Operation{Kind: jobs.KindConnectionDiscover, ConnectionID: &conn.ID, Payload: payload}
	if _, err := postgresProfilesReplay(op, req, conn); err != nil {
		t.Fatalf("same request after topology reset: %v", err)
	}
	changed := req
	changed.Profiles = []string{"read"}
	if _, err := postgresProfilesReplay(op, changed, conn); err == nil {
		t.Fatal("request_id reused with another profile was accepted")
	}
	conn.Topology = json.RawMessage(`{"system_identifier":"7429012345678901235"}`)
	if _, err := postgresProfilesReplay(op, req, conn); err == nil {
		t.Fatal("replay accepted a different physical target")
	}
	conn.Topology = nil
	conn.Endpoints = []string{"other-postgres:5432"}
	if _, err := postgresProfilesReplay(op, req, conn); err == nil {
		t.Fatal("replay accepted another configuration incarnation")
	}
}
