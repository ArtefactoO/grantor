//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

func TestPostgresAccessEvidenceDirectDiscovery(t *testing.T) {
	dsn := targetDSN(t)
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	var major int
	if err := conn.QueryRow(ctx, `select current_setting('server_version_num')::int`).Scan(&major); err != nil {
		t.Fatal(err)
	}
	if major < 160000 {
		t.Skip("per-membership INHERIT/SET test requires PostgreSQL 16+")
	}
	name := fmt.Sprintf("access_evidence_%d", time.Now().UnixNano())
	subject, reader, writer, memberOnly := name+"_login", name+"_r", name+"_rw", name+"_member"
	quote := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	table := pgx.Identifier{name, "items"}.Sanitize()
	exec := func(sql string) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{subject, reader, writer, memberOnly} {
		suffix := " nologin"
		if role == subject {
			suffix = " login noinherit"
		}
		exec("create role " + quote(role) + suffix)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		_, _ = c.Exec(context.Background(), "drop schema if exists "+quote(name)+" cascade")
		for _, role := range []string{subject, reader, writer, memberOnly} {
			_, _ = c.Exec(context.Background(), "drop role if exists "+quote(role))
		}
	})
	exec("create schema " + quote(name))
	exec("create table " + table + " (id int)")
	exec("grant " + quote(reader) + " to " + quote(subject) + " with inherit true, set true")
	exec("grant " + quote(writer) + " to " + quote(subject) + " with inherit false, set true")
	exec("grant " + quote(memberOnly) + " to " + quote(subject) + " with inherit false, set false")
	exec("grant pg_write_all_data to " + quote(writer))
	exec("grant select on " + table + " to " + quote(subject))
	exec("grant update on " + table + " to " + quote(writer))
	exec("grant insert on " + table + " to public")
	exec("alter default privileges in schema " + quote(name) + " grant delete on tables to " + quote(subject))
	snapshot, err := postgres.New().Discover(ctx, targetConnection(t, dsn))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot.Topology["postgres_access_evidence"])
	if err != nil {
		t.Fatal(err)
	}
	var evidence adapter.PostgresAccessEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Version != 1 || !evidence.MembershipsSupported || evidence.MembershipsTruncated {
		t.Fatalf("membership evidence unavailable: %+v", evidence)
	}
	found := map[string]adapter.PostgresRoleReachability{}
	for _, row := range evidence.Memberships {
		if row.Member == subject {
			found[row.Role] = row
		}
	}
	if !found[reader].Usage || !found[reader].SetRole || !found[reader].IsMember {
		t.Fatal("explicit INHERIT TRUE was lost")
	}
	if found[writer].Usage || !found[writer].SetRole || !found[writer].IsMember {
		t.Fatal("NOINHERIT SET role was reported as inherited")
	}
	if found[memberOnly].Usage || found[memberOnly].SetRole || !found[memberOnly].IsMember {
		t.Fatal("HBA-only membership was lost")
	}
	if found["pg_write_all_data"].Usage || !found["pg_write_all_data"].SetRole {
		t.Fatal("native data role reachability was lost")
	}
	if len(evidence.Endpoints) != 1 || !evidence.Endpoints[0].Available || evidence.Endpoints[0].ServerRole != "primary" {
		t.Fatalf("configured primary HBA not observed: %+v", evidence.Endpoints)
	}
	for _, endpoint := range evidence.Endpoints {
		for _, rule := range endpoint.Rules {
			for _, option := range rule.Options {
				if option != "configured" {
					t.Fatal("HBA option value exposed")
				}
			}
			if rule.Error != "" && rule.Error != "invalid_hba_rule" {
				t.Fatal("raw HBA error exposed")
			}
		}
	}
	direct, public, future := false, false, false
	for _, binding := range snapshot.Bindings {
		p, err := adapter.ParsePostgresObjectPrivilege(binding.PermissionExternalID)
		if err == nil && p.Schema == name && p.Name == "items" && p.Privilege == "SELECT" && binding.AccountEngineIdentity == subject {
			direct = true
		}
	}
	for _, resource := range snapshot.Resources {
		if resource.Name == "items" && strings.HasSuffix(resource.CanonicalPath, "."+name+".items") {
			value, _ := json.Marshal(resource.Attributes["public_privileges"])
			var privileges []string
			_ = json.Unmarshal(value, &privileges)
			for _, privilege := range privileges {
				public = public || privilege == "INSERT"
			}
		}
	}
	defaults, _ := json.Marshal(snapshot.Topology["postgres_default_privileges"])
	var rows []map[string]any
	_ = json.Unmarshal(defaults, &rows)
	for _, row := range rows {
		if row["schema"] == name && row["grantee"] == subject && row["privilege"] == "DELETE" {
			future = true
		}
	}
	if !direct || !public || !future {
		t.Fatalf("ACL evidence incomplete: direct=%v public=%v future=%v", direct, public, future)
	}
}
