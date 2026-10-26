package api

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestPostgresProfileSourcesSeparateCurrentSetRolePublicAndFuture(t *testing.T) {
	id := uuid.New()
	evidence := adapter.PostgresAccessEvidence{Version: 1, MembershipsSupported: true, Memberships: []adapter.PostgresRoleReachability{
		{Member: "alice", Role: "writer", IsMember: true, Usage: true, SetRole: true},
		{Member: "alice", Role: "noinherit_writer", IsMember: true, Usage: false, SetRole: true},
		{Member: "alice", Role: "membership_only", IsMember: true, Usage: false, SetRole: false},
	}}
	sources := postgresDiagnosticSources("alice", evidence)
	if _, ok := sources["membership_only"]; ok {
		t.Fatal("membership without INHERIT or SET became effective")
	}
	resources := []postgresDiagnosticResource{{ID: id, Kind: "table", Path: "app.public.items", Attributes: json.RawMessage(`{"owner":"another","public_privileges":["UPDATE"]}`)}}
	grants := []postgresDiagnosticGrant{}
	for _, subject := range []string{"alice", "writer", "noinherit_writer", "membership_only"} {
		grants = append(grants, postgresDiagnosticGrant{Subject: subject, ResourceID: id, Attributes: json.RawMessage(`{"object_kind":"table","privilege":"INSERT"}`), BindingAttributes: json.RawMessage(`{"grantors":[{"grant_option":false}]}`)})
	}
	topology := postgresDiagnosticTopology{ACLVersion: 1, Evidence: evidence, Defaults: []map[string]any{{"database": "app", "creator": "migrator", "grantee": "alice", "privilege": "TRUNCATE", "secret_unexpected_field": "must_not_escape"}}}
	out := postgresAccessDiagnosticsResponse{Database: "app", Profile: "read", Assessment: "unknown", Inventory: &inventoryFreshness{Status: "current"}}
	assessPostgresPrivileges(&out, "alice", json.RawMessage(`{}`), resources, grants, topology, sources)
	if out.Assessment != "exceeds_profile_in_snapshot" || !out.SnapshotExcessObserved || len(out.Findings) != 4 {
		t.Fatalf("assessment = %+v", out)
	}
	found := map[string]string{}
	for _, finding := range out.Findings {
		found[finding.Source.Kind] = finding.Source.Activation
		if finding.Privilege == "TRUNCATE" {
			t.Fatal("future default grant became current DML")
		}
	}
	if found["direct"] != "current" || found["inherited_role"] != "current" || found["set_role"] != "set_role_required" || found["public"] != "current" {
		t.Fatalf("sources = %#v", found)
	}
	if len(out.FutureDefaultPrivileges) != 1 || out.FutureDefaultPrivileges[0]["effect"] != "future_objects_only" {
		t.Fatal("future grants lost their separate scope")
	}
	if _, ok := out.FutureDefaultPrivileges[0]["secret_unexpected_field"]; ok {
		t.Fatal("default projection copied unrecognized metadata")
	}
}

func TestPostgresProfileBoundariesAndUnknownAssessment(t *testing.T) {
	for _, tc := range []struct {
		profile, kind, privilege string
		want                     bool
	}{
		{"read", "table", "SELECT", true}, {"read", "sequence", "SELECT", true}, {"read", "sequence", "USAGE", false},
		{"read_write", "table", "DELETE", true}, {"read_write", "table", "TRUNCATE", false}, {"read_write", "table", "TRIGGER", false},
		{"read_write", "schema", "CREATE", false}, {"read_write", "sequence", "UPDATE", true}, {"read_write", "sequence", "USAGE", false},
	} {
		if got := postgresPrivilegeWithinProfile(tc.profile, tc.kind, tc.privilege); got != tc.want {
			t.Errorf("%+v: %v", tc, got)
		}
	}
	for _, tc := range []struct {
		status    string
		supported bool
		truncated bool
	}{{"current", true, false}, {"stale", true, false}, {"partial", true, false}, {"current", false, false}, {"current", true, true}} {
		out := postgresAccessDiagnosticsResponse{Profile: "read", Assessment: "unknown", Inventory: &inventoryFreshness{Status: tc.status}, EvidenceTruncated: tc.truncated}
		assessPostgresPrivileges(&out, "alice", json.RawMessage(`{}`), nil, nil, postgresDiagnosticTopology{ACLVersion: 1, Evidence: adapter.PostgresAccessEvidence{MembershipsSupported: tc.supported}}, postgresDiagnosticSources("alice", adapter.PostgresAccessEvidence{}))
		if out.Assessment != "unknown" || out.SnapshotExcessObserved {
			t.Fatal("absence of current evidence became compliance")
		}
	}
}

func TestPostgresOwnershipNativeRolesAndSetRoleAttributes(t *testing.T) {
	db, schema := uuid.New(), uuid.New()
	evidence := adapter.PostgresAccessEvidence{MembershipsSupported: true, Memberships: []adapter.PostgresRoleReachability{{Member: "alice", Role: "owner", Usage: false, SetRole: true, IsMember: true}, {Member: "alice", Role: "pg_write_all_data", Usage: true, IsMember: true}, {Member: "alice", Role: "super", SetRole: true, IsMember: true}}}
	topology := postgresDiagnosticTopology{ACLVersion: 1, Evidence: evidence, RoleAttributes: map[string]json.RawMessage{"super": json.RawMessage(`{"superuser":true}`)}}
	resources := []postgresDiagnosticResource{{ID: db, Kind: "database", Path: "app", Attributes: json.RawMessage(`{"owner":"owner"}`)}, {ID: schema, Kind: "schema", Path: "app.public", Attributes: json.RawMessage(`{"owner":"pg_database_owner"}`)}}
	out := postgresAccessDiagnosticsResponse{Profile: "read", Inventory: &inventoryFreshness{Status: "current"}}
	assessPostgresPrivileges(&out, "alice", json.RawMessage(`{"superuser":false}`), resources, nil, topology, postgresDiagnosticSources("alice", evidence))
	found := map[string]bool{}
	for _, finding := range out.Findings {
		found[finding.Privilege+":"+finding.Source.Role+":"+finding.Source.Activation] = true
	}
	for _, want := range []string{"OWNER:owner:set_role_required", "OWNER:pg_database_owner:set_role_required", "pg_write_all_data:pg_write_all_data:current", "SUPERUSER:super:set_role_required"} {
		if !found[want] {
			t.Errorf("missing %s in %+v", want, out.Findings)
		}
	}
}

func TestPostgresHBAFirstMatchDatabasePeerTLSAndUncertainty(t *testing.T) {
	base := adapter.PostgresHBARule{Number: 1, Type: "host", Databases: []string{"app"}, Users: []string{"alice"}, Address: "10.20.30.0", Netmask: "255.255.255.0", AuthMethod: "scram-sha-256"}
	for _, tc := range []struct {
		name         string
		first        adapter.PostgresHBARule
		database, ip string
		tls          bool
		want         string
	}{
		{"first reject", func() adapter.PostgresHBARule { r := base; r.AuthMethod = "reject"; return r }(), "app", "10.20.30.5", false, "file_reject"},
		{"different database", base, "other", "10.20.30.5", false, "file_no_matching_rule"},
		{"different database peer IP", base, "app", "10.21.30.5", false, "file_no_matching_rule"},
		{"TLS only", func() adapter.PostgresHBARule { r := base; r.Type = "hostssl"; return r }(), "app", "10.20.30.5", false, "file_no_matching_rule"},
		{"TLS matches", func() adapter.PostgresHBARule { r := base; r.Type = "hostssl"; return r }(), "app", "10.20.30.5", true, "file_rule_match"},
		{"hostname", func() adapter.PostgresHBARule { r := base; r.Address = ".internal.example"; return r }(), "app", "10.20.30.5", false, "unknown"},
		{"regex", func() adapter.PostgresHBARule { r := base; r.Users = []string{"/^alice"}; return r }(), "app", "10.20.30.5", false, "unknown"},
		{"auth options", func() adapter.PostgresHBARule {
			r := base
			r.Options = []string{"ldapbindpasswd=not-for-output"}
			return r
		}(), "app", "10.20.30.5", false, "unknown"},
		{"malformed rule", adapter.PostgresHBARule{Number: 1, Error: "malformed not-for-output"}, "app", "10.20.30.5", false, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The second allow cannot bypass uncertainty in an earlier rule.
			rules := []adapter.PostgresHBARule{tc.first}
			if tc.want == "unknown" || tc.want == "file_reject" {
				second := base
				second.Number = 2
				rules = append(rules, second)
			}
			evidence := adapter.PostgresAccessEvidence{Endpoints: []adapter.PostgresHBAEndpoint{{Endpoint: "vip:5432", ServerRole: "primary", Available: true, Rules: rules}}}
			out := assessPostgresHBA(evidence, "alice", tc.database, netip.MustParseAddr(tc.ip), tc.tls, true)
			if len(out.Endpoints) != 1 || out.Endpoints[0].Status != tc.want {
				t.Fatalf("HBA = %+v", out)
			}
			if out.PrimaryCoverage != "observed" || out.StandbyCoverage != "unknown" {
				t.Fatal("primary-only VIP claimed standby coverage")
			}
			raw, _ := json.Marshal(out)
			if strings.Contains(string(raw), "not-for-output") {
				t.Fatal("raw HBA auth option or error leaked")
			}
		})
	}
}

func TestPostgresHBAMembershipIsIndependentOfInheritAndSet(t *testing.T) {
	evidence := adapter.PostgresAccessEvidence{MembershipsSupported: true, Memberships: []adapter.PostgresRoleReachability{{Member: "alice", Role: "readers", IsMember: true}}}
	if postgresHBAListMatch([]string{"+readers"}, "alice", "app", true, evidence) != hbaYes {
		t.Fatal("HBA membership incorrectly required INHERIT or SET")
	}
	if postgresHBAListMatch([]string{"samerole"}, "alice", "readers", false, evidence) != hbaYes {
		t.Fatal("database samerole lost membership")
	}
	if postgresHBAListMatch([]string{"sameuser"}, "alice", "sameuser", false, evidence) != hbaNo || postgresHBAListMatch([]string{"replication"}, "alice", "replication", false, evidence) != hbaNo {
		t.Fatal("database keyword was treated as a literal name")
	}
	evidence.MembershipsSupported = false
	if postgresHBAListMatch([]string{"+unseen"}, "alice", "app", true, evidence) != hbaUnknown {
		t.Fatal("partial membership became definite no-match")
	}
	if postgresHBAAddressMatch("2001:db8::", "ffff:ffff:ffff:ffff::", netip.MustParseAddr("2001:db8::5")) != hbaYes {
		t.Fatal("IPv6 mask did not match")
	}
	if postgresHBAAddressMatch("10.0.0.0", "255.0.255.0", netip.MustParseAddr("10.0.0.5")) != hbaUnknown {
		t.Fatal("noncontiguous mask was guessed")
	}
}

func TestPostgresLegacyHBAProjectionRedactsOptionValuesAndErrors(t *testing.T) {
	rules, _, ok := hbaRulesFromTopology(json.RawMessage(`{"hba_rules":[{"options":["ldapbindpasswd=legacy-secret"],"error":"legacy-secret in error"}]}`))
	if !ok || len(rules) != 1 || len(rules[0].Options) != 1 || rules[0].Options[0] != "configured" || rules[0].Error != "invalid_hba_rule" {
		t.Fatalf("legacy projection not sanitized: %+v", rules)
	}
	raw, _ := json.Marshal(rules)
	if strings.Contains(string(raw), "legacy-secret") {
		t.Fatal("legacy HBA secret exposed")
	}
}

func TestPostgresDiagnosticBoundsAndStaleHBACoverage(t *testing.T) {
	out := postgresAccessDiagnosticsResponse{Profile: "read", Assessment: "unknown", Inventory: &inventoryFreshness{Status: "current"}, EvidenceTruncated: true}
	resources := []postgresDiagnosticResource{}
	for range postgresDiagnosticFindingLimit + 1 {
		resources = append(resources, postgresDiagnosticResource{ID: uuid.New(), Kind: "table", Path: "app.public.items", Attributes: json.RawMessage(`{"public_privileges":["UPDATE"]}`)})
	}
	assessPostgresPrivileges(&out, "alice", json.RawMessage(`{}`), resources, nil, postgresDiagnosticTopology{ACLVersion: 1, Evidence: adapter.PostgresAccessEvidence{MembershipsSupported: true}}, postgresDiagnosticSources("alice", adapter.PostgresAccessEvidence{}))
	if len(out.Findings) != postgresDiagnosticFindingLimit || !out.FindingsTruncated || out.Assessment != "unknown" {
		t.Fatalf("bounds or partial assessment lost: %+v", out)
	}
	evidence := adapter.PostgresAccessEvidence{Endpoints: []adapter.PostgresHBAEndpoint{{Available: true, ServerRole: "primary", Truncated: true}}}
	hba := assessPostgresHBA(evidence, "alice", "app", netip.MustParseAddr("10.0.0.1"), false, true)
	if hba.Endpoints[0].Status != "unknown" || hba.Endpoints[0].Reason != "rules_truncated" {
		t.Fatal("truncated HBA rules became definite deny")
	}
	hba = assessPostgresHBA(evidence, "alice", "app", netip.MustParseAddr("10.0.0.1"), false, false)
	if hba.PrimaryCoverage != "stale" || hba.ApplicationReadiness != "not_verified" {
		t.Fatal("stale primary became live coverage")
	}
}
