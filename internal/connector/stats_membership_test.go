package connector_test

import (
	"encoding/json"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
)

func statsPayload(kind adapter.ChangeKind) connector.MutationPayload {
	return connector.MutationPayload{Connection: connector.ConnectionRef{ID: "stats-connection", Engine: "postgres", ConfigIncarnation: "stats-config", Endpoints: []string{"pg:5432"}},
		Change: connector.ChangeRef{Kind: string(kind), Account: connector.AccountRef{Kind: "login", EngineIdentity: "monitor"}, Permission: "role:pg_read_all_stats",
			ExpectedAdminIdentity: "grantor", ExpectedTargetIdentity: "postgres:system:42",
			StatsMembership: &adapter.PostgresStatsMembershipPins{AdminIdentity: "grantor", TargetIdentity: "postgres:system:42", ConfigIncarnation: "stats-config", CredentialIncarnation: 3, BuiltinOID: 3375, SubjectOID: 17001}}}
}

func TestStatsMembershipPayloadPreservesCompleteClosedPins(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{adapter.ChangePostgresStatsMembershipGrantV1, adapter.ChangePostgresStatsMembershipRevokeV1} {
		p := statsPayload(kind)
		raw, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := connector.ParseMutationPayload(raw)
		if err != nil || got.Change.StatsMembership == nil || *got.Change.StatsMembership != *p.Change.StatsMembership {
			t.Fatalf("typed statistics pins were not preserved: %v", err)
		}
	}
}

func TestStatsMembershipPayloadRejectsMissingMixedAndConflictingPins(t *testing.T) {
	for name, mutate := range map[string]func(*connector.MutationPayload){
		"engine":             func(p *connector.MutationPayload) { p.Connection.Engine = "mongodb" },
		"no pins":            func(p *connector.MutationPayload) { p.Change.StatsMembership = nil },
		"subject oid":        func(p *connector.MutationPayload) { p.Change.StatsMembership.SubjectOID = 0 },
		"builtin oid":        func(p *connector.MutationPayload) { p.Change.StatsMembership.BuiltinOID = 0 },
		"credential version": func(p *connector.MutationPayload) { p.Change.StatsMembership.CredentialIncarnation = 0 },
		"config fence":       func(p *connector.MutationPayload) { p.Connection.ConfigIncarnation = "other" },
		"admin fence":        func(p *connector.MutationPayload) { p.Change.ExpectedAdminIdentity = "other" },
		"target fence":       func(p *connector.MutationPayload) { p.Change.ExpectedTargetIdentity = "other" },
		"protected subject":  func(p *connector.MutationPayload) { p.Change.Account.EngineIdentity = "pg_monitor" },
		"other permission":   func(p *connector.MutationPayload) { p.Change.Permission = "role:pg_monitor" },
		"group subject":      func(p *connector.MutationPayload) { p.Change.Account.Kind = "group" },
		"scope":              func(p *connector.MutationPayload) { p.Change.Scope = "db:app" },
		"auth scope":         func(p *connector.MutationPayload) { p.Change.Account.AuthenticationScope = "db:app" },
		"permission set":     func(p *connector.MutationPayload) { p.Change.AccountPermissions = []string{"role:app"} },
		"raw attributes":     func(p *connector.MutationPayload) { p.Change.Attributes = p.Change.StatsMembership.Attributes() },
		"policy": func(p *connector.MutationPayload) {
			p.Change.RolePolicySpec = &adapter.RolePolicySpec{Engine: "postgres"}
		},
		"resource":           func(p *connector.MutationPayload) { p.Change.Resource = &adapter.ResourceSpec{Kind: "database"} },
		"database oid":       func(p *connector.MutationPayload) { p.Change.ExpectedDatabaseOID = 42 },
		"database owner":     func(p *connector.MutationPayload) { p.Change.ExpectedDatabaseOwner = "owner" },
		"database owner oid": func(p *connector.MutationPayload) { p.Change.ExpectedDatabaseOwnerOID = 42 },
		"catalog":            func(p *connector.MutationPayload) { p.Change.ExpectedCatalogFingerprint = "fingerprint" },
	} {
		t.Run(name, func(t *testing.T) {
			p := statsPayload(adapter.ChangePostgresStatsMembershipGrantV1)
			mutate(&p)
			raw, err := p.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := connector.ParseMutationPayload(raw); err == nil {
				t.Fatal("unreviewed statistics payload accepted")
			}
		})
	}
	p := statsPayload(adapter.ChangePostgresStatsMembershipGrantV1)
	raw, _ := p.Marshal()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["change"].(map[string]any)["stats_membership"].(map[string]any)["raw_sql"] = "arbitrary statement"
	raw, _ = json.Marshal(doc)
	if _, err := connector.ParseMutationPayload(raw); err == nil {
		t.Fatal("unknown nested statistics field accepted")
	}
}

func TestStatsMembershipPinsHaveNoLegacyOrOtherTypedRoute(t *testing.T) {
	for _, kind := range []adapter.ChangeKind{adapter.ChangeGrant, adapter.ChangeRevoke, adapter.ChangePostgresAccountCreateV2} {
		p := statsPayload(kind)
		raw, _ := p.Marshal()
		if _, err := connector.ParseMutationPayload(raw); err == nil {
			t.Fatal("statistics pins accepted by another mutation kind")
		}
		p.Change.StatsMembership = nil
		p.Change.Attributes = map[string]any{"postgres_stats_membership_v1": adapter.PostgresStatsMembershipPins{BuiltinOID: 3375, SubjectOID: 17001}}
		raw, _ = p.Marshal()
		if _, err := connector.ParseMutationPayload(raw); err == nil {
			t.Fatal("legacy attributes bypassed the protected membership kind")
		}
	}
}
