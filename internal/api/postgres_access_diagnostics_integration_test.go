//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func TestIntegrationPostgresAccessDiagnosticsSnapshotScopeAndHBA(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	viewer, operator := session(auth.RoleViewer), session(auth.RoleOperator)
	connection, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{DisplayName: "diagnostics-" + uuid.NewString(), Engine: "postgres", Environment: "diagnostics-scope-" + uuid.NewString(), Endpoints: []string{"vip.internal:5432"}})
	if err != nil {
		t.Fatal(err)
	}
	p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:7429012345678901234", Database: "app", DatabaseOID: 42, Schema: "public", SchemaOID: 43, Kind: "table", Name: "items", ObjectOID: 44, OwnerOID: 45, Privilege: "UPDATE"}
	snapshot := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{{Kind: "login", EngineIdentity: "alice", Attributes: map[string]any{"can_login": true}}, {Kind: "group", EngineIdentity: "writer"}},
		Resources:   []adapter.ObservedResource{{Kind: "database", ExternalID: "db:app", Name: "app", CanonicalPath: "app", Attributes: map[string]any{"owner": "owner"}}, {Kind: "table", ExternalID: p.Scope(), ParentExternalID: "db:app", Name: "items", CanonicalPath: "app.public.items", Attributes: map[string]any{"owner": "owner", "public_privileges": []string{"INSERT"}}}},
		Permissions: []adapter.ObservedPermission{{ExternalID: p.PermissionID(), Name: "UPDATE ON app.public.items", ScopeExternalID: p.Scope(), Attributes: map[string]any{"object_kind": "table", "database": "app", "privilege": "UPDATE"}}},
		Bindings:    []adapter.ObservedBinding{{AccountEngineIdentity: "writer", PermissionExternalID: p.PermissionID(), ScopeExternalID: p.Scope(), Attributes: map[string]any{"direct_privilege": true}}}}
	if _, err := inventory.NewStore().UpsertSnapshot(t.Context(), env.pool, connection.ID, snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	topology := map[string]any{"postgres_object_acl_version": 1, "postgres_access_evidence": adapter.PostgresAccessEvidence{Version: 1, MembershipsSupported: true, Memberships: []adapter.PostgresRoleReachability{{Member: "alice", Role: "writer", IsMember: true, SetRole: true}}, Endpoints: []adapter.PostgresHBAEndpoint{{Endpoint: "vip.internal:5432", ServerRole: "primary", Available: true, Rules: []adapter.PostgresHBARule{{Number: 1, Type: "host", Databases: []string{"app"}, Users: []string{"+writer"}, Address: "10.1.2.0", Netmask: "255.255.255.0", AuthMethod: "reject"}, {Number: 2, Type: "host", Databases: []string{"all"}, Users: []string{"all"}, Address: "0.0.0.0", Netmask: "0.0.0.0", AuthMethod: "scram-sha-256"}}}}}, "postgres_default_privileges": []map[string]any{{"database": "app", "creator": "owner", "grantee": "alice", "privilege": "TRUNCATE"}}}
	update := func(at time.Time) {
		t.Helper()
		raw, err := json.Marshal(topology)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.pool.Exec(t.Context(), `update connections set status='active',last_discovery_at=$2,topology=$3 where id=$1`, connection.ID, at, raw); err != nil {
			t.Fatal(err)
		}
	}
	update(time.Now())
	accounts, err := inventory.NewStore().ListAccounts(t.Context(), env.pool, connection.ID)
	if err != nil {
		t.Fatal(err)
	}
	var accountID uuid.UUID
	for _, account := range accounts {
		if account.EngineIdentity == "alice" {
			accountID = account.ID
		}
	}
	if accountID == uuid.Nil {
		t.Fatal("LOGIN metadata not found")
	}
	path := "/api/v1/accounts/" + accountID.String() + "/postgres/access-diagnostics?database=app&profile=read&source_ip=10.1.2.3&tls=false"
	requireStatus(t, env.do(t, http.MethodGet, path, nil, &operator, false), http.StatusForbidden)
	requireStatus(t, env.do(t, http.MethodGet, path, nil, nil, false), http.StatusUnauthorized)
	read := func(path string) map[string]any {
		t.Helper()
		response := env.do(t, http.MethodGet, path, nil, &viewer, false)
		requireStatus(t, response, http.StatusOK)
		body := readBody(t, response)
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	out := read(path)
	if out["assessment"] != "exceeds_profile_in_snapshot" || out["snapshot_excess_observed"] != true {
		t.Fatalf("profile diagnosis = %#v", out)
	}
	hba := out["hba"].(map[string]any)
	endpoint := hba["endpoints"].([]any)[0].(map[string]any)
	if endpoint["status"] != "file_reject" || hba["standby_coverage"] != "unknown" {
		t.Fatalf("HBA = %#v", hba)
	}
	future := out["future_default_privileges"].([]any)
	if len(future) != 1 || future[0].(map[string]any)["effect"] != "future_objects_only" {
		t.Fatal("default grants became current privileges")
	}
	changed := read(strings.Replace(path, "source_ip=10.1.2.3", "source_ip=10.9.8.7", 1))
	if changed["hba"].(map[string]any)["endpoints"].([]any)[0].(map[string]any)["status"] != "file_rule_match" {
		t.Fatal("HBA did not use explicit database-peer IP")
	}
	topology["postgres_object_acl_incomplete_scopes"] = []string{"db:app"}
	update(time.Now())
	partial := read(path)
	if partial["assessment"] != "unknown" || partial["inventory"].(map[string]any)["status"] != "partial" {
		t.Fatal("partial snapshot became complete profile assessment")
	}
	delete(topology, "postgres_object_acl_incomplete_scopes")
	update(time.Now().Add(-time.Hour))
	stale := read(path)
	if stale["assessment"] != "unknown" || stale["hba"].(map[string]any)["endpoints"].([]any)[0].(map[string]any)["status"] != "unknown" {
		t.Fatal("stale snapshot became current access evidence")
	}
	requireStatus(t, env.do(t, http.MethodGet, strings.Replace(path, "source_ip=10.1.2.3", "source_ip=HTTP_CLIENT_IP", 1), nil, &viewer, false), http.StatusBadRequest)
}
