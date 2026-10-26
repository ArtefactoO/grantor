//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

func TestObjectACLGrantRevokePreservesDataOtherGrantsAndInheritance(t *testing.T) {
	ctx := t.Context()
	dsn := targetDSN(t)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx) //nolint:errcheck
	name := fmt.Sprintf("object_acl_%d", time.Now().UnixNano())
	owner, alice, peer, group := name+"_owner", name+"_alice", name+"_peer", name+"_readers"
	ident := func(s string) string { return pgx.Identifier{s}.Sanitize() }
	table := pgx.Identifier{name, "items"}.Sanitize()
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	for _, role := range []string{owner, alice, peer, group} {
		exec("create role " + ident(role) + " nologin")
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		_, _ = c.Exec(context.Background(), "drop schema if exists "+ident(name)+" cascade")
		for _, role := range []string{alice, peer, group, owner} {
			_, _ = c.Exec(context.Background(), "drop role if exists "+ident(role))
		}
	})
	exec("create schema " + ident(name) + " authorization " + ident(owner))
	exec("set role " + ident(owner))
	exec("create table " + table + " (id int primary key)")
	exec("insert into " + table + " values (1),(2),(3)")
	exec("grant usage on schema " + ident(name) + " to " + ident(alice) + "," + ident(peer))
	exec("grant insert on " + table + " to " + ident(alice))
	exec("grant select on " + table + " to " + ident(peer))
	exec("reset role")
	cfg := targetConnection(t, dsn)
	cfg.ConfigIncarnation = "object-acl-test"
	cfg.AdminCredentialIncarnation = 1
	p := adapter.PostgresObjectPrivilege{Kind: "table", Schema: name, Name: "items", Privilege: "SELECT"}
	var physical string
	var subject uint32
	if err := admin.QueryRow(ctx, `select current_database(),(select oid from pg_database where datname=current_database()),system_identifier::text from pg_control_system()`).Scan(&p.Database, &p.DatabaseOID, &physical); err != nil {
		t.Fatal(err)
	}
	p.TargetIdentity = "postgres:system:" + physical
	if err := admin.QueryRow(ctx, `select c.oid,c.relowner,n.oid from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname='items'`, name).Scan(&p.ObjectOID, &p.OwnerOID, &p.SchemaOID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `select oid from pg_roles where rolname=$1`, alice).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	pins := adapter.PostgresObjectACLPins{AdminIdentity: cfg.AdminCredential.Username, TargetIdentity: p.TargetIdentity, ConfigIncarnation: cfg.ConfigIncarnation, CredentialIncarnation: 1, SubjectOID: subject}
	c := adapter.DesiredChange{Kind: adapter.ChangePostgresObjectACLGrantV1, Connection: cfg, Account: adapter.Account{Kind: "group", EngineIdentity: alice}, Permission: p.PermissionID(), Scope: p.Scope(), ObjectACL: &pins, ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity}
	a := postgres.New()
	for _, mutate := range []func(*adapter.PostgresObjectACLPins){
		func(f *adapter.PostgresObjectACLPins) { f.SubjectOID++ }, func(f *adapter.PostgresObjectACLPins) { f.ConfigIncarnation = "other" }, func(f *adapter.PostgresObjectACLPins) { f.CredentialIncarnation++ },
	} {
		bad := pins
		mutate(&bad)
		request := c
		request.ObjectACL = &bad
		if _, err := a.Plan(ctx, request); err == nil {
			t.Fatal("stale ACL proof accepted")
		}
	}
	plan, err := a.Plan(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := a.Apply(ctx, *plan); err != nil {
			t.Fatal(err)
		}
	}
	v, err := a.Verify(ctx, *plan)
	if err != nil || !v.Verified {
		t.Fatalf("grant verification: %v", err)
	}
	assertUnrelated := func() {
		t.Helper()
		var canInsert, peerSelect bool
		var count, total int
		if err := admin.QueryRow(ctx, `select has_table_privilege($1,$3,'INSERT'),has_table_privilege($2,$3,'SELECT')`, alice, peer, table).Scan(&canInsert, &peerSelect); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, "select count(*)::int,sum(id)::int from "+table).Scan(&count, &total); err != nil {
			t.Fatal(err)
		}
		if !canInsert || !peerSelect || count != 3 || total != 6 {
			t.Fatal("unrelated ACL or fixture data changed")
		}
	}
	assertUnrelated()
	snap, err := a.Discover(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == alice && b.PermissionExternalID == p.PermissionID() {
			found = true
		}
	}
	if !found {
		t.Fatal("direct ACL missing from discovery")
	}
	for _, permission := range snap.Permissions {
		object, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
		if err != nil || object.ObjectOID != p.ObjectOID || object.Kind != "table" {
			continue
		}
		switch object.Privilege {
		case "TRUNCATE", "TRIGGER":
			if !permission.Dangerous {
				t.Fatal("destructive or trigger privilege bypasses the dangerous grant gate")
			}
		case "SELECT":
			if permission.Dangerous {
				t.Fatal("ordinary table read requires the dangerous grant gate")
			}
		}
	}
	var ownerName string
	if err := admin.QueryRow(ctx, `select rolname from pg_roles where oid=$1`, p.OwnerOID).Scan(&ownerName); err != nil {
		t.Fatal(err)
	}
	pins.Grantors = []adapter.PostgresACLGrantor{{OID: p.OwnerOID, Name: ownerName}}
	exec("set role " + ident(owner))
	exec("grant select on " + table + " to " + ident(group))
	exec("reset role")
	exec("grant " + ident(group) + " to " + ident(alice))
	c.Kind = adapter.ChangePostgresObjectACLRevokeV1
	plan, err = a.Plan(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := a.Apply(ctx, *plan); err != nil {
			t.Fatal(err)
		}
	}
	v, err = a.Verify(ctx, *plan)
	if err != nil || !v.Verified {
		t.Fatalf("direct revoke should verify despite inherited access: %v", err)
	}
	var effective bool
	if err := admin.QueryRow(ctx, `select has_table_privilege($1,$2,'SELECT')`, alice, table).Scan(&effective); err != nil || !effective {
		t.Fatal("inherited read access lost")
	}
	assertUnrelated()
	exec("set role " + ident(owner))
	exec("grant select on " + table + " to " + ident(alice))
	exec("grant select(id) on " + table + " to " + ident(alice))
	exec("reset role")
	if _, err := a.Apply(ctx, *plan); err == nil {
		t.Fatal("table revoke accepted despite independent column ACL")
	}
	assertUnrelated()
	exec("set role " + ident(owner))
	exec("revoke select(id) on " + table + " from " + ident(alice))
	exec("reset role")
	// A delegating row must survive rejection, including its downstream grants.
	exec("set role " + ident(owner))
	exec("grant select on " + table + " to " + ident(alice) + " with grant option")
	exec("reset role")
	if _, err := a.Apply(ctx, *plan); err == nil {
		t.Fatal("delegating ACL revoke accepted")
	}
	assertUnrelated()
	exec("set role " + ident(owner))
	exec("drop table " + table)
	exec("create table " + table + " (id int)")
	exec("insert into " + table + " values(7)")
	exec("reset role")
	if _, err := a.Apply(ctx, *plan); err == nil {
		t.Fatal("recreated same-name table accepted by stale intent")
	}
	var remaining int
	if err := admin.QueryRow(ctx, "select sum(id)::int from "+table).Scan(&remaining); err != nil || remaining != 7 {
		t.Fatal("recreated table data changed")
	}
}
