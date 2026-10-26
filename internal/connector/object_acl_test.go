package connector_test

import (
	"encoding/json"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

func objectACLPayload() connector.MutationPayload {
	p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: "items", ObjectOID: 12, OwnerOID: 13, Privilege: "SELECT"}
	f := &adapter.PostgresObjectACLPins{AdminIdentity: "grantor", TargetIdentity: p.TargetIdentity, ConfigIncarnation: "acl-config", CredentialIncarnation: 2, SubjectOID: 20}
	return connector.MutationPayload{Connection: connector.ConnectionRef{ID: "acl", Engine: "postgres", Endpoints: []string{"pg:5432"}, ConfigIncarnation: f.ConfigIncarnation},
		Change: connector.ChangeRef{Kind: string(adapter.ChangePostgresObjectACLGrantV1), Account: connector.AccountRef{Kind: "login", EngineIdentity: "alice"}, Permission: p.PermissionID(), Scope: p.Scope(), ObjectACL: f,
			ExpectedAdminIdentity: f.AdminIdentity, ExpectedTargetIdentity: f.TargetIdentity}}
}

func TestObjectACLWireRejectsUnpinnedAndLegacyRequests(t *testing.T) {
	base := objectACLPayload()
	raw, _ := base.Marshal()
	got, err := connector.ParseMutationPayload(raw)
	if err != nil || got.Change.ObjectACL.SubjectOID != 20 {
		t.Fatalf("complete wire: %v", err)
	}
	for name, mutate := range map[string]func(*connector.MutationPayload){
		"generic":        func(p *connector.MutationPayload) { p.Change.Kind = string(adapter.ChangeGrant) },
		"missing pins":   func(p *connector.MutationPayload) { p.Change.ObjectACL = nil },
		"other engine":   func(p *connector.MutationPayload) { p.Connection.Engine = "redis" },
		"config":         func(p *connector.MutationPayload) { p.Connection.ConfigIncarnation = "other" },
		"scope":          func(p *connector.MutationPayload) { p.Change.Scope = "db:other" },
		"raw attributes": func(p *connector.MutationPayload) { p.Change.Attributes = map[string]any{"sql": "arbitrary"} },
		"policy":         func(p *connector.MutationPayload) { p.Change.RolePolicySpec = &adapter.RolePolicySpec{} },
		"catalog":        func(p *connector.MutationPayload) { p.Change.ExpectedCatalogFingerprint = "unexpected" },
	} {
		t.Run(name, func(t *testing.T) {
			p := objectACLPayload()
			mutate(&p)
			b, _ := p.Marshal()
			if _, err := connector.ParseMutationPayload(b); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	var document map[string]any
	_ = json.Unmarshal(raw, &document)
	document["change"].(map[string]any)["object_acl"].(map[string]any)["raw_sql"] = "arbitrary"
	raw, _ = json.Marshal(document)
	if _, err := connector.ParseMutationPayload(raw); err == nil {
		t.Fatal("unknown nested wire field accepted")
	}
}
