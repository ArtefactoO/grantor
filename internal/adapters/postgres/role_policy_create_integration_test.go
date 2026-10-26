//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

// directPolicyFixture separates the database owner, current object owners and
// future object creators. A direct policy pins the first identity and grants
// the fixed profile only across the configured latter sets.
type directPolicyFixture struct {
	cc               *pgx.ConnConfig
	database         string
	databaseOwner    string
	databaseOwnerOID uint32
	admin            string
	adminPassword    string
	owners           []string
	creators         []string
	schemas          []string
	wrongSchema      string
	outsider         string
	downstream       string
	readRole         string
	readWriteRole    string
	fdw              string
	server           string
	traceSchema      string
	traceEvent       string
	systemIdentifier string
	databaseOID      uint32
	runtimeBaseline  policyPersistentCounters
	connection       adapter.Connection
	roles            []string
}

type policyPersistentCounters struct {
	schemas, routines, relations, types, extensions int
	eventTriggers, collations, conversions          int
	foreignWrappers, foreignServers, languages      int
	largeObjects, tempSchemas                       int
}

func TestRolePolicyDirectLifecycle(t *testing.T) {
	f := newDirectPolicyFixture(t)
	ad := New()
	read := f.change(adapter.ChangePostgresRolePolicyCreateV2, f.readRole, postgresconfig.ProfileRead)
	rw := f.change(adapter.ChangePostgresRolePolicyCreateV2, f.readWriteRole, postgresconfig.ProfileReadWrite)

	for _, change := range []*adapter.DesiredChange{&read, &rw} {
		plan, err := ad.Plan(t.Context(), *change)
		if err != nil {
			t.Fatalf("Plan %s: %v", change.RolePolicySpec.Profile, err)
		}
		result, err := ad.Apply(t.Context(), *plan)
		if err != nil {
			conn := f.open(t)
			state, observeErr := observeRolePolicyState(t.Context(), conn, rolePolicyTemplateFromSpec(change.RolePolicySpec))
			closeQuietly(t.Context(), conn)
			if observeErr == nil {
				t.Fatalf("Apply %s: %v; missing=%v extra=%v", change.RolePolicySpec.Profile, err, state.missing, state.extra)
			}
			t.Fatalf("Apply %s: %v; observe: %v", change.RolePolicySpec.Profile, err, observeErr)
		}
		if len(result.Steps) != 1 || result.Steps[0].Status != adapter.StepApplied {
			t.Fatalf("Apply %s = %+v, %v", change.RolePolicySpec.Profile, result, err)
		}
		verified, err := ad.Verify(t.Context(), *plan)
		if err != nil || !verified.Verified {
			t.Fatalf("Verify %s = %+v, %v", change.RolePolicySpec.Profile, verified, err)
		}
		// Simulate a lost COMMIT response: the immutable create plan must
		// converge by exact read-back without another target mutation.
		retry, err := ad.Apply(t.Context(), *plan)
		if err != nil || len(retry.Steps) != 1 || retry.Steps[0].Status != adapter.StepSkipped {
			t.Fatalf("lost-response retry %s = %+v, %v", change.RolePolicySpec.Profile, retry, err)
		}
	}

	assertNoRolePolicyRuntimeObjects(t, f)
	assertDirectProfile(t, f, f.readRole, postgresconfig.ProfileRead)
	assertDirectProfile(t, f, f.readWriteRole, postgresconfig.ProfileReadWrite)
	f.createFutureObjects(t)
	assertDirectProfile(t, f, f.readRole, postgresconfig.ProfileRead)
	assertDirectProfile(t, f, f.readWriteRole, postgresconfig.ProfileReadWrite)
	for _, change := range []adapter.DesiredChange{read, rw} {
		change.Kind = adapter.ChangePostgresRolePolicyVerifyV2
		plan, err := ad.Plan(t.Context(), change)
		if err != nil {
			t.Fatalf("Plan future Verify: %v", err)
		}
		verified, err := ad.Verify(t.Context(), *plan)
		if err != nil || !verified.Verified {
			t.Fatalf("future Verify = %+v, %v", verified, err)
		}
	}

	t.Run("apply_restores_existing_safe_role", func(t *testing.T) {
		conn := f.openAdmin(t)
		if _, err := conn.Exec(t.Context(), "revoke select on table "+
			pgx.Identifier{f.schemas[0], "current_table"}.Sanitize()+" from "+
			pgx.Identifier{f.readRole}.Sanitize()); err != nil {
			closeQuietly(t.Context(), conn)
			t.Fatal(err)
		}
		closeQuietly(t.Context(), conn)
		change := f.change(adapter.ChangePostgresRolePolicyApplyV2, f.readRole, postgresconfig.ProfileRead)
		plan, err := ad.Plan(t.Context(), change)
		if err != nil {
			t.Fatalf("Plan apply: %v", err)
		}
		result, err := ad.Apply(t.Context(), *plan)
		if err != nil || len(result.Steps) != 1 || result.Steps[0].Status != adapter.StepApplied {
			t.Fatalf("Apply existing policy = %+v, %v", result, err)
		}
		verified, err := ad.Verify(t.Context(), *plan)
		if err != nil || !verified.Verified {
			t.Fatalf("Verify apply = %+v, %v", verified, err)
		}
	})

	t.Run("repair_full_acl_surface_preserves_public", func(t *testing.T) {
		f.injectReadPolicyDrift(t)
		change := f.change(adapter.ChangePostgresRolePolicyRepairV2, f.readRole, postgresconfig.ProfileRead)
		plan, err := ad.Plan(t.Context(), change)
		if err != nil {
			t.Fatalf("Plan repair: %v", err)
		}
		result, err := ad.Apply(t.Context(), *plan)
		if err != nil || len(result.Steps) != 1 || result.Steps[0].Status != adapter.StepApplied {
			t.Fatalf("Apply repair = %+v, %v", result, err)
		}
		verified, err := ad.Verify(t.Context(), *plan)
		if err != nil || !verified.Verified {
			t.Fatalf("Verify repair = %+v, %v", verified, err)
		}
		assertDirectProfile(t, f, f.readRole, postgresconfig.ProfileRead)
		f.assertExtendedACLsAbsent(t, f.readRole)
		f.assertPolicyExact(t, f.readRole, postgresconfig.ProfileRead)
		f.assertPublicACLStillPresent(t)
	})

	t.Run("adopt_and_verify_are_read_only", func(t *testing.T) {
		for _, kind := range []adapter.ChangeKind{
			adapter.ChangePostgresRolePolicyAdoptV2,
			adapter.ChangePostgresRolePolicyVerifyV2,
		} {
			change := f.change(kind, f.readRole, postgresconfig.ProfileRead)
			plan, err := ad.Plan(t.Context(), change)
			if err != nil {
				t.Fatalf("Plan %s: %v", kind, err)
			}
			verification, err := ad.Verify(t.Context(), *plan)
			if err != nil || !verification.Verified {
				t.Fatalf("Verify %s = %+v, %v", kind, verification, err)
			}
			if _, err := ad.Apply(t.Context(), *plan); !errors.Is(err, adapter.ErrUnsupportedChange) {
				t.Fatalf("Apply read-only %s error = %v", kind, err)
			}
		}
	})

	t.Run("membership_cleanup_and_restrict_rollback", func(t *testing.T) {
		f.assertMembershipCleanup(t, ad)
	})
}

func TestRolePolicyDirectAuthorityRevokedAfterPlan(t *testing.T) {
	f := newDirectPolicyFixture(t)
	root, err := pgx.ConnectConfig(t.Context(), f.cc)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(t.Context(), root)
	suffix := f.readRole[len(f.readRole)-8:]
	admin, role := "gr_su_"+suffix, "gr_fence_"+suffix
	f.roles = append(f.roles, admin, role)
	const password = "grantor-direct-test"
	if _, err := root.Exec(t.Context(), "create role "+pgx.Identifier{admin}.Sanitize()+
		" login superuser password '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	connection := f.connection
	connection.AdminCredential = adapter.Credential{Kind: "password", Username: admin, Secret: []byte(password)}
	connection.AdminCredentialIncarnation++
	connection.ConfigIncarnation += "-alternate-admin"
	change := f.change(adapter.ChangePostgresRolePolicyCreateV2, role, postgresconfig.ProfileRead)
	change.Connection, change.ExpectedAdminIdentity = connection, admin
	ad := New()
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan as SUPERUSER: %v", err)
	}
	if _, err := root.Exec(t.Context(), "alter role "+pgx.Identifier{admin}.Sanitize()+" nosuperuser"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = root.Exec(context.Background(), "alter role "+pgx.Identifier{admin}.Sanitize()+" superuser")
	}()
	if _, err := ad.Apply(t.Context(), *plan); err == nil || !strings.Contains(strings.ToLower(err.Error()), "superuser") {
		t.Fatalf("Apply after SUPERUSER revoke error = %v", err)
	}
	var exists bool
	if err := root.QueryRow(t.Context(), `select exists(select 1 from pg_roles where rolname=$1)`, role).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("authority failure created the policy role")
	}

	for name, expected := range map[string]string{"missing": "", "mismatch": f.cc.User} {
		t.Run("expected_admin_"+name, func(t *testing.T) {
			candidate := change
			candidate.ExpectedAdminIdentity = expected
			if _, err := ad.Plan(t.Context(), candidate); err == nil {
				t.Fatal("invalid expected admin reached a plan")
			}
		})
	}
}

func TestRolePolicyCreateRejectsUnsafeOrNonExactExistingRole(t *testing.T) {
	f := newDirectPolicyFixture(t)
	cluster, err := pgx.ConnectConfig(t.Context(), f.cc)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(t.Context(), cluster)
	suffix := f.readRole[len(f.readRole)-8:]
	unsafe, nonExact, parent := "gr_unsafe_"+suffix, "gr_nonexact_"+suffix, "gr_parent_"+suffix
	f.roles = append(f.roles, unsafe, nonExact, parent)
	for _, statement := range []string{
		"create role " + pgx.Identifier{unsafe}.Sanitize() + " login createrole",
		"create role " + pgx.Identifier{nonExact}.Sanitize() + " nologin",
		"create role " + pgx.Identifier{parent}.Sanitize() + " nologin",
		"grant " + pgx.Identifier{parent}.Sanitize() + " to " + pgx.Identifier{nonExact}.Sanitize(),
	} {
		if _, err := cluster.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	ad := New()
	for _, role := range []string{unsafe, nonExact} {
		change := f.change(adapter.ChangePostgresRolePolicyCreateV2, role, postgresconfig.ProfileRead)
		if _, err := ad.Plan(t.Context(), change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
			t.Fatalf("Plan existing role %s error = %v", role, err)
		}
	}
	var login, createRole, inherits bool
	if err := cluster.QueryRow(t.Context(), `select rolcanlogin,rolcreaterole from pg_roles where rolname=$1`, unsafe).Scan(&login, &createRole); err != nil {
		t.Fatal(err)
	}
	if err := cluster.QueryRow(t.Context(), `select pg_has_role($1,$2,'MEMBER')`, nonExact, parent).Scan(&inherits); err != nil {
		t.Fatal(err)
	}
	if !login || !createRole || !inherits {
		t.Fatalf("rejected roles mutated: login=%v createrole=%v membership=%v", login, createRole, inherits)
	}
}

func newDirectPolicyFixture(t *testing.T) *directPolicyFixture {
	t.Helper()
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not configured")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := pgx.ConnectConfig(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(t.Context(), cluster)
	var superuser bool
	if err := cluster.QueryRow(t.Context(), `select rolsuper from pg_roles where rolname=session_user`).Scan(&superuser); err != nil {
		t.Fatal(err)
	}
	if !superuser {
		t.Skip("target DSN user is not SUPERUSER")
	}
	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	f := &directPolicyFixture{
		cc: cc, database: "gr_pd_" + suffix, databaseOwner: "gr_dbowner_" + suffix,
		admin: "gr_admin_" + suffix, adminPassword: "grantor-direct-test",
		owners:      []string{"gr_owner_a_" + suffix, "gr_owner_b_" + suffix},
		creators:    []string{"gr_creator_a_" + suffix, "gr_creator_b_" + suffix},
		schemas:     []string{"gr_schema_a_" + suffix, "gr_schema_b_" + suffix},
		wrongSchema: "gr_wrong_" + suffix, outsider: "gr_outside_" + suffix,
		downstream: "gr_down_" + suffix, readRole: "gr_read_" + suffix,
		readWriteRole: "gr_rw_" + suffix, fdw: "gr_fdw_" + suffix, server: "gr_server_" + suffix,
		traceSchema: "gr_trace_" + suffix, traceEvent: "gr_trace_event_" + suffix,
	}
	f.roles = append(f.roles, f.admin, f.databaseOwner)
	f.roles = append(f.roles, f.owners...)
	f.roles = append(f.roles, f.creators...)
	f.roles = append(f.roles, f.outsider, f.downstream, f.readRole, f.readWriteRole)
	baseRoles := append([]string{f.databaseOwner}, f.owners...)
	baseRoles = append(baseRoles, f.creators...)
	baseRoles = append(baseRoles, f.outsider, f.downstream)
	for _, role := range baseRoles {
		if _, err := cluster.Exec(t.Context(), "create role "+pgx.Identifier{role}.Sanitize()+" nologin"); err != nil {
			t.Fatalf("create role %q: %v", role, err)
		}
	}
	if _, err := cluster.Exec(t.Context(), "create role "+pgx.Identifier{f.admin}.Sanitize()+
		" login superuser password '"+f.adminPassword+"'"); err != nil {
		t.Fatal(err)
	}
	if _, err := cluster.Exec(t.Context(), "create database "+pgx.Identifier{f.database}.Sanitize()+
		" owner "+pgx.Identifier{f.databaseOwner}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if err := cluster.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&f.systemIdentifier); err != nil {
		t.Fatal(err)
	}
	if err := cluster.QueryRow(t.Context(), `
		select d.oid,r.oid from pg_database d join pg_roles r on r.oid=d.datdba where d.datname=$1`, f.database).
		Scan(&f.databaseOID, &f.databaseOwnerOID); err != nil {
		t.Fatal(err)
	}
	f.connection = adapter.Connection{
		ID: "direct-policy-" + suffix, Engine: Engine,
		Endpoints: []string{net.JoinHostPort(cc.Host, strconv.Itoa(int(cc.Port)))},
		TLS:       adapter.TLSConfig{Mode: "disabled"}, Attributes: map[string]any{"database": cc.Database},
		ConfigIncarnation: "integration-" + suffix, AdminCredentialIncarnation: 1,
		AdminCredential: adapter.Credential{Kind: "password", Username: f.admin, Secret: []byte(f.adminPassword)},
	}
	t.Cleanup(f.cleanup)
	f.createCurrentObjects(t)
	f.installDDLTrace(t)
	f.runtimeBaseline = f.readPersistentCounters(t)
	return f
}

func (f *directPolicyFixture) open(t *testing.T) *pgx.Conn {
	t.Helper()
	cc := f.cc.Copy()
	cc.Database = f.database
	cc.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func (f *directPolicyFixture) openAdmin(t *testing.T) *pgx.Conn {
	t.Helper()
	cc := f.cc.Copy()
	cc.Database, cc.User, cc.Password = f.database, f.admin, f.adminPassword
	cc.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	conn, err := pgx.ConnectConfig(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func (f *directPolicyFixture) change(kind adapter.ChangeKind, role, profile string) adapter.DesiredChange {
	owners := append([]string{}, f.owners...)
	owners = append(owners, f.creators...)
	spec := rolePolicySpec(postgresconfig.RolePolicyTemplate{
		Key: "integration-" + role, Name: role, Description: "SUPERUSER direct integration policy",
		RoleName: role, Database: f.database, Schemas: f.schemas,
		OwnerRoles: owners, CreatorRoles: f.creators, Profile: profile,
	})
	return adapter.DesiredChange{
		Kind: kind, Connection: f.connection, RolePolicySpec: &spec,
		ExpectedAdminIdentity:    f.connection.AdminCredential.Username,
		ExpectedTargetIdentity:   "postgres:system:" + f.systemIdentifier,
		ExpectedDatabaseOID:      f.databaseOID,
		ExpectedDatabaseOwner:    f.databaseOwner,
		ExpectedDatabaseOwnerOID: f.databaseOwnerOID,
	}
}

func (f *directPolicyFixture) createCurrentObjects(t *testing.T) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	for i, schema := range f.schemas {
		if _, err := conn.Exec(t.Context(), "create schema "+pgx.Identifier{schema}.Sanitize()+
			" authorization "+pgx.Identifier{f.owners[i]}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		for _, creator := range f.creators {
			if _, err := conn.Exec(t.Context(), "grant usage,create on schema "+pgx.Identifier{schema}.Sanitize()+
				" to "+pgx.Identifier{creator}.Sanitize()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := conn.Exec(t.Context(), "create schema "+pgx.Identifier{f.wrongSchema}.Sanitize()+
		" authorization "+pgx.Identifier{f.owners[0]}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"create foreign data wrapper " + pgx.Identifier{f.fdw}.Sanitize() + " no handler",
		"create server " + pgx.Identifier{f.server}.Sanitize() + " foreign data wrapper " + pgx.Identifier{f.fdw}.Sanitize(),
		"grant usage on foreign server " + pgx.Identifier{f.server}.Sanitize() + " to " + pgx.Identifier{f.owners[0]}.Sanitize(),
		"grant usage on foreign server " + pgx.Identifier{f.server}.Sanitize() + " to " + pgx.Identifier{f.creators[0]}.Sanitize(),
	} {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	for i, owner := range f.owners {
		schema := f.schemas[i]
		for _, statement := range []string{
			"set role " + pgx.Identifier{owner}.Sanitize(),
			"create table " + pgx.Identifier{schema, "current_table"}.Sanitize() + " (id bigint,payload text)",
			"create view " + pgx.Identifier{schema, "current_view"}.Sanitize() + " as select id from " + pgx.Identifier{schema, "current_table"}.Sanitize(),
			"create materialized view " + pgx.Identifier{schema, "current_matview"}.Sanitize() + " as select id from " + pgx.Identifier{schema, "current_table"}.Sanitize(),
			"create sequence " + pgx.Identifier{schema, "current_seq"}.Sanitize(),
			"reset role",
		} {
			if _, err := conn.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := conn.Exec(t.Context(), "set role "+pgx.Identifier{f.owners[0]}.Sanitize()+
		"; create foreign table "+pgx.Identifier{f.schemas[0], "current_foreign"}.Sanitize()+
		" (id bigint) server "+pgx.Identifier{f.server}.Sanitize()+"; reset role"); err != nil {
		t.Fatal(err)
	}
}

func (f *directPolicyFixture) installDDLTrace(t *testing.T) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	events := pgx.Identifier{f.traceSchema, "ddl_events"}.Sanitize()
	capture := pgx.Identifier{f.traceSchema, "capture_ddl"}.Sanitize()
	statements := []string{
		"create schema " + pgx.Identifier{f.traceSchema}.Sanitize(),
		"create table " + events + " (command_tag text not null, object_type text not null, object_identity text not null)",
		"create function " + capture + `() returns event_trigger
			language plpgsql security definer set search_path=pg_catalog as $trace$
			declare command record;
			begin
				for command in select * from pg_event_trigger_ddl_commands() loop
					execute 'insert into ` + events + ` (command_tag,object_type,object_identity) values ($1,$2,$3)'
						using command.command_tag,coalesce(command.object_type,''),coalesce(command.object_identity,'');
				end loop;
			end
			$trace$`,
		"create event trigger " + pgx.Identifier{f.traceEvent}.Sanitize() +
			" on ddl_command_end execute function " + capture + "()",
		"truncate table " + events,
	}
	for _, statement := range statements {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("install DDL trace with %q: %v", statement, err)
		}
	}
}

func (f *directPolicyFixture) readPersistentCounters(t *testing.T) policyPersistentCounters {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	var out policyPersistentCounters
	if err := conn.QueryRow(t.Context(), `select
		(select count(*) from pg_namespace),
		(select count(*) from pg_proc),
		(select count(*) from pg_class),
		(select count(*) from pg_type),
		(select count(*) from pg_extension),
		(select count(*) from pg_event_trigger),
		(select count(*) from pg_collation),
		(select count(*) from pg_conversion),
		(select count(*) from pg_foreign_data_wrapper),
		(select count(*) from pg_foreign_server),
		(select count(*) from pg_language),
		(select count(*) from pg_largeobject_metadata),
		(select count(*) from pg_namespace where nspname like 'pg_temp_%')`).Scan(
		&out.schemas, &out.routines, &out.relations, &out.types, &out.extensions,
		&out.eventTriggers, &out.collations, &out.conversions,
		&out.foreignWrappers, &out.foreignServers, &out.languages,
		&out.largeObjects, &out.tempSchemas,
	); err != nil {
		t.Fatal(err)
	}
	return out
}

func (f *directPolicyFixture) createFutureObjects(t *testing.T) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	for i, creator := range f.creators {
		schema := f.schemas[i]
		for _, statement := range []string{
			"set role " + pgx.Identifier{creator}.Sanitize(),
			"create table " + pgx.Identifier{schema, "future_table"}.Sanitize() + " (id bigint)",
			"create view " + pgx.Identifier{schema, "future_view"}.Sanitize() + " as select id from " + pgx.Identifier{schema, "future_table"}.Sanitize(),
			"create sequence " + pgx.Identifier{schema, "future_seq"}.Sanitize(),
			"reset role",
		} {
			if _, err := conn.Exec(t.Context(), statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := conn.Exec(t.Context(), "set role "+pgx.Identifier{f.creators[0]}.Sanitize()+
		"; create foreign table "+pgx.Identifier{f.schemas[0], "future_foreign"}.Sanitize()+
		" (id bigint) server "+pgx.Identifier{f.server}.Sanitize()+"; reset role"); err != nil {
		t.Fatal(err)
	}
}

func assertDirectProfile(t *testing.T, f *directPolicyFixture, role, profile string) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	write := profile == postgresconfig.ProfileReadWrite
	assertDirectPrivilege(t, conn, role, "database", f.database, "CONNECT", true, false)
	assertDirectPrivilege(t, conn, role, "database", f.database, "CREATE", false, false)
	assertDirectPrivilege(t, conn, role, "database", f.database, "TEMPORARY", false, false)
	for _, schema := range f.schemas {
		assertDirectPrivilege(t, conn, role, "schema", schema, "USAGE", true, false)
		assertDirectPrivilege(t, conn, role, "schema", schema, "CREATE", false, false)
		for _, object := range []string{"current_table", "current_view", "current_matview"} {
			assertRelationProfile(t, conn, role, schema+"."+object, write)
		}
		assertDirectPrivilege(t, conn, role, "relation", schema+".current_seq", "SELECT", true, false)
		assertDirectPrivilege(t, conn, role, "relation", schema+".current_seq", "UPDATE", write, false)
		assertDirectPrivilege(t, conn, role, "relation", schema+".current_seq", "USAGE", false, false)
		for _, object := range []string{"future_table", "future_view"} {
			if objectExists(t, conn, schema, object) {
				assertRelationProfile(t, conn, role, schema+"."+object, write)
			}
		}
		if objectExists(t, conn, schema, "future_seq") {
			assertDirectPrivilege(t, conn, role, "relation", schema+".future_seq", "SELECT", true, false)
			assertDirectPrivilege(t, conn, role, "relation", schema+".future_seq", "UPDATE", write, false)
		}
	}
	for _, object := range []string{"current_foreign", "future_foreign"} {
		if objectExists(t, conn, f.schemas[0], object) {
			assertRelationProfile(t, conn, role, f.schemas[0]+"."+object, write)
		}
	}
	ownerships, err := readPolicyRoleOwnerships(t.Context(), conn, role)
	if err != nil {
		t.Fatal(err)
	}
	if len(ownerships) != 0 {
		t.Fatalf("policy role %s owns objects: %v", role, ownerships)
	}
}

func assertRelationProfile(t *testing.T, conn *pgx.Conn, role, object string, write bool) {
	t.Helper()
	assertDirectPrivilege(t, conn, role, "relation", object, "SELECT", true, false)
	for _, privilege := range []string{"INSERT", "UPDATE", "DELETE"} {
		assertDirectPrivilege(t, conn, role, "relation", object, privilege, write, false)
	}
	for _, privilege := range []string{"TRUNCATE", "REFERENCES", "TRIGGER"} {
		assertDirectPrivilege(t, conn, role, "relation", object, privilege, false, false)
	}
}

func assertDirectPrivilege(t *testing.T, conn *pgx.Conn, role, kind, object, privilege string, want, grantable bool) {
	t.Helper()
	var query string
	switch kind {
	case "database":
		query = `select exists(select 1 from pg_database d cross join lateral aclexplode(d.datacl) a join pg_roles r on r.oid=a.grantee where r.rolname=$1 and d.datname=$2 and a.privilege_type=$3 and a.is_grantable=$4)`
	case "schema":
		query = `select exists(select 1 from pg_namespace n cross join lateral aclexplode(n.nspacl) a join pg_roles r on r.oid=a.grantee where r.rolname=$1 and n.nspname=$2 and a.privilege_type=$3 and a.is_grantable=$4)`
	case "relation":
		query = `select exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace cross join lateral aclexplode(c.relacl) a join pg_roles r on r.oid=a.grantee where r.rolname=$1 and n.nspname||'.'||c.relname=$2 and a.privilege_type=$3 and a.is_grantable=$4)`
	default:
		t.Fatalf("unknown object kind %q", kind)
	}
	var got bool
	if err := conn.QueryRow(t.Context(), query, role, object, privilege, grantable).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("direct %s %s on %s for %s = %v, want %v (grantable=%v)", kind, privilege, object, role, got, want, grantable)
	}
}

func objectExists(t *testing.T, conn *pgx.Conn, schema, name string) bool {
	t.Helper()
	var exists bool
	if err := conn.QueryRow(t.Context(), `select exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace where n.nspname=$1 and c.relname=$2)`, schema, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

func assertNoRolePolicyRuntimeObjects(t *testing.T, f *directPolicyFixture) {
	t.Helper()
	after := f.readPersistentCounters(t)
	if after != f.runtimeBaseline {
		t.Fatalf("direct Apply changed persistent same-database object counters:\n before=%+v\n after=%+v",
			f.runtimeBaseline, after)
	}
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	rows, err := conn.Query(t.Context(), "select command_tag,object_type,object_identity from "+
		pgx.Identifier{f.traceSchema, "ddl_events"}.Sanitize()+" order by command_tag,object_identity")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tag, objectType, identity string
		if err := rows.Scan(&tag, &objectType, &identity); err != nil {
			t.Fatal(err)
		}
		forbidden := tag == "DO" || tag == "SELECT INTO" ||
			(strings.HasPrefix(tag, "CREATE ") && tag != "CREATE ROLE")
		if forbidden {
			t.Fatalf("direct Apply executed forbidden DDL before its connection closed: tag=%q type=%q identity=%q",
				tag, objectType, identity)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func (f *directPolicyFixture) injectReadPolicyDrift(t *testing.T) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	schema := f.schemas[0]
	table := pgx.Identifier{schema, "current_table"}.Sanitize()
	var largeObject uint32
	if err := conn.QueryRow(t.Context(), `select lo_create(0)`).Scan(&largeObject); err != nil {
		t.Fatal(err)
	}
	statements := []string{
		"grant create,temporary on database " + pgx.Identifier{f.database}.Sanitize() + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant create on schema " + pgx.Identifier{schema}.Sanitize() + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant insert,update,delete,truncate,references,trigger on table " + table + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant select on table " + table + " to " + pgx.Identifier{f.readRole}.Sanitize() + " with grant option",
		"grant update (payload) on table " + table + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"create function " + pgx.Identifier{schema, "extra_fn"}.Sanitize() + "() returns integer language sql as 'select 1'",
		"grant execute on function " + pgx.Identifier{schema, "extra_fn"}.Sanitize() + "() to " + pgx.Identifier{f.readRole}.Sanitize(),
		"create type " + pgx.Identifier{schema, "extra_type"}.Sanitize() + " as enum ('one')",
		"grant usage on type " + pgx.Identifier{schema, "extra_type"}.Sanitize() + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		fmt.Sprintf("grant select,update on large object %d to %s", largeObject, pgx.Identifier{f.readRole}.Sanitize()),
		"grant usage on foreign data wrapper " + pgx.Identifier{f.fdw}.Sanitize() + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant usage on foreign server " + pgx.Identifier{f.server}.Sanitize() + " to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant usage on language plpgsql to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant create on tablespace pg_default to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant set on parameter work_mem to " + pgx.Identifier{f.readRole}.Sanitize(),
		"grant usage on schema " + pgx.Identifier{schema}.Sanitize() + " to public",
		"alter default privileges for role " + pgx.Identifier{f.creators[0]}.Sanitize() + " grant select on tables to " + pgx.Identifier{f.readRole}.Sanitize(),
		"alter default privileges for role " + pgx.Identifier{f.creators[0]}.Sanitize() + " in schema " + pgx.Identifier{schema}.Sanitize() + " grant select on tables to " + pgx.Identifier{f.readRole}.Sanitize() + " with grant option",
		"alter default privileges for role " + pgx.Identifier{f.creators[0]}.Sanitize() + " in schema " + pgx.Identifier{f.wrongSchema}.Sanitize() + " grant insert on tables to " + pgx.Identifier{f.readRole}.Sanitize(),
		"alter default privileges for role " + pgx.Identifier{f.outsider}.Sanitize() + " in schema " + pgx.Identifier{schema}.Sanitize() + " grant select on tables to " + pgx.Identifier{f.readRole}.Sanitize(),
		"alter default privileges for role " + pgx.Identifier{f.creators[0]}.Sanitize() + " in schema " + pgx.Identifier{schema}.Sanitize() + " grant execute on functions to " + pgx.Identifier{f.readRole}.Sanitize(),
		"alter default privileges for role " + pgx.Identifier{f.creators[0]}.Sanitize() + " in schema " + pgx.Identifier{schema}.Sanitize() + " grant usage on types to " + pgx.Identifier{f.readRole}.Sanitize(),
	}
	for _, statement := range statements {
		if _, err := conn.Exec(t.Context(), statement); err != nil {
			t.Fatalf("inject drift with %q: %v", statement, err)
		}
	}
}

func (f *directPolicyFixture) assertExtendedACLsAbsent(t *testing.T, role string) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	actual := make(map[string]struct{})
	if err := observeOtherACLs(t.Context(), conn, role, actual); err != nil {
		t.Fatal(err)
	}
	if len(actual) != 0 {
		t.Fatalf("extended ACLs survived repair: %v", actual)
	}
}

func (f *directPolicyFixture) assertPolicyExact(t *testing.T, role, profile string) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	change := f.change(adapter.ChangePostgresRolePolicyVerifyV2, role, profile)
	template := rolePolicyTemplateFromSpec(change.RolePolicySpec)
	state, err := observeRolePolicyState(t.Context(), conn, template)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.missing) != 0 || len(state.extra) != 0 {
		t.Fatalf("policy is not exact: missing=%v extra=%v", state.missing, state.extra)
	}
}

func rolePolicyTemplateFromSpec(spec *adapter.RolePolicySpec) postgresconfig.RolePolicyTemplate {
	return postgresconfig.RolePolicyTemplate{
		Key: spec.Key, Name: spec.Name, Description: spec.Description, RoleName: spec.RoleName,
		Database: spec.Database, Schemas: spec.Schemas, OwnerRoles: spec.OwnerRoles,
		CreatorRoles: spec.CreatorRoles, Profile: spec.Profile,
	}
}

func (f *directPolicyFixture) assertPublicACLStillPresent(t *testing.T) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	var exists bool
	if err := conn.QueryRow(t.Context(), `select exists(select 1 from pg_namespace n cross join lateral aclexplode(n.nspacl) a where n.nspname=$1 and a.grantee=0 and a.privilege_type='USAGE')`, f.schemas[0]).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("repair revoked PUBLIC-derived privilege")
	}
}

func (f *directPolicyFixture) assertMembershipCleanup(t *testing.T, ad *Adapter) {
	t.Helper()
	conn := f.open(t)
	defer closeQuietly(t.Context(), conn)
	var version int
	if err := conn.QueryRow(t.Context(), `select current_setting('server_version_num')::integer`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	admin := f.connection.AdminCredential.Username
	if version < 160000 {
		// A helper-era PG15 role may still contain the old structural admin
		// membership. The direct Apply contract removes it without creating or
		// requiring any helper object.
		if _, err := conn.Exec(t.Context(), "grant "+pgx.Identifier{f.readRole}.Sanitize()+" to "+
			pgx.Identifier{admin}.Sanitize()+" with admin option"); err != nil {
			t.Fatal(err)
		}
		if rows := membershipRows(t, conn, f.readRole, admin); rows != 1 {
			t.Fatalf("PG15 helper-era membership rows=%d, want 1", rows)
		}
		change := f.change(adapter.ChangePostgresRolePolicyApplyV2, f.readRole, postgresconfig.ProfileRead)
		plan, err := ad.Plan(t.Context(), change)
		if err != nil {
			t.Fatalf("PG15 Plan helper-era cleanup: %v", err)
		}
		if _, err := ad.Apply(t.Context(), *plan); err != nil {
			t.Fatalf("PG15 Apply helper-era cleanup: %v", err)
		}
		if rows := membershipRows(t, conn, f.readRole, admin); rows != 0 {
			t.Fatalf("PG15 Apply left helper-era admin membership: %d", rows)
		}
		verified, err := ad.Verify(t.Context(), *plan)
		if err != nil || !verified.Verified {
			t.Fatalf("PG15 helper-era cleanup Verify = %+v, %v", verified, err)
		}
		return
	}

	suffix := f.readRole[len(f.readRole)-8:]
	alternateGrantors := []string{"gr_alt1_" + suffix, "gr_alt2_" + suffix}
	f.roles = append(f.roles, alternateGrantors...)
	cluster, err := pgx.ConnectConfig(t.Context(), f.cc)
	if err != nil {
		t.Fatal(err)
	}
	defer closeQuietly(t.Context(), cluster)
	for _, grantor := range alternateGrantors {
		if _, err := cluster.Exec(t.Context(), "create role "+pgx.Identifier{grantor}.Sanitize()+" nologin"); err != nil {
			t.Fatal(err)
		}
	}
	adminConn := f.openAdmin(t)
	defer closeQuietly(t.Context(), adminConn)
	repair := f.change(adapter.ChangePostgresRolePolicyRepairV2, f.readRole, postgresconfig.ProfileRead)
	for i := 0; i < 2; i++ {
		options := "admin true,inherit false,set false"
		wantAdmin, wantInherit, wantSet := true, false, false
		if i == 1 {
			options = "admin false,inherit true,set true"
			wantAdmin, wantInherit, wantSet = false, true, true
		}
		statement := "grant " + pgx.Identifier{f.readRole}.Sanitize() + " to " +
			pgx.Identifier{admin}.Sanitize() + " with " + options
		if _, err := adminConn.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
		// PostgreSQL records grants issued by any SUPERUSER under the bootstrap
		// superuser grantor, not under the current named SUPERUSER.
		assertMembershipShape(t, conn, f.readRole, admin, f.cc.User, wantAdmin, wantInherit, wantSet)
		plan, err := ad.Plan(t.Context(), repair)
		if err != nil {
			t.Fatalf("Plan membership cleanup options %d: %v", i, err)
		}
		if _, err := ad.Apply(t.Context(), *plan); err != nil {
			t.Fatalf("Apply membership cleanup options %d: %v", i, err)
		}
		if rows := membershipRows(t, conn, f.readRole, admin); rows != 0 {
			t.Fatalf("admin membership options %d survived: %d", i, rows)
		}
	}

	// An alternate non-superuser grantor necessarily has ADMIN OPTION on the
	// policy role. That is outside the fixed role and fails closed at Plan;
	// the injected DELETE proves no policy mutation occurred.
	for i, grantor := range alternateGrantors {
		if _, err := adminConn.Exec(t.Context(), "grant "+pgx.Identifier{f.readRole}.Sanitize()+" to "+
			pgx.Identifier{grantor}.Sanitize()+" with admin true,inherit false,set false"); err != nil {
			t.Fatal(err)
		}
		options := "admin false,inherit true,set true"
		if i == 1 {
			options = "admin false,inherit false,set false"
		}
		if _, err := conn.Exec(t.Context(), "set role "+pgx.Identifier{grantor}.Sanitize()+"; grant "+
			pgx.Identifier{f.readRole}.Sanitize()+" to "+pgx.Identifier{admin}.Sanitize()+
			" with "+options+"; reset role"); err != nil {
			t.Fatal(err)
		}
	}
	var alternateRows int
	if err := conn.QueryRow(t.Context(), `
		select count(*) from pg_auth_members am
		join pg_roles r on r.oid=am.roleid join pg_roles m on m.oid=am.member
		where r.rolname=$1 and m.rolname=any($2::name[]) and am.admin_option`,
		f.readRole, alternateGrantors).Scan(&alternateRows); err != nil {
		t.Fatal(err)
	}
	if alternateRows != len(alternateGrantors) {
		t.Fatalf("alternate grantor rows=%d, want %d", alternateRows, len(alternateGrantors))
	}
	if _, err := conn.Exec(t.Context(), "grant delete on table "+pgx.Identifier{f.schemas[0], "current_table"}.Sanitize()+
		" to "+pgx.Identifier{f.readRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := ad.Plan(t.Context(), repair); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("alternate grantor Plan error = %v", err)
	}
	assertDirectPrivilege(t, conn, f.readRole, "relation", f.schemas[0]+".current_table", "DELETE", true, false)
	adminGrantors := membershipGrantors(t, conn, f.readRole, admin)
	if len(adminGrantors) != len(alternateGrantors) {
		t.Fatalf("admin membership grantors=%v, want both alternates %v", adminGrantors, alternateGrantors)
	}
	for _, grantor := range adminGrantors {
		if _, err := conn.Exec(t.Context(), "set role "+pgx.Identifier{grantor}.Sanitize()+"; revoke "+
			pgx.Identifier{f.readRole}.Sanitize()+" from "+pgx.Identifier{admin}.Sanitize()+
			" granted by "+pgx.Identifier{grantor}.Sanitize()+"; reset role"); err != nil {
			t.Fatal(err)
		}
	}
	for _, grantor := range alternateGrantors {
		if _, err := conn.Exec(t.Context(), "revoke "+pgx.Identifier{f.readRole}.Sanitize()+" from "+
			pgx.Identifier{grantor}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(t.Context(), "revoke delete on table "+pgx.Identifier{f.schemas[0], "current_table"}.Sanitize()+
		" from "+pgx.Identifier{f.readRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}

	// A grant made onward by the admin depends on its ADMIN OPTION. RESTRICT
	// must abort the whole repair instead of silently cascading third-party
	// access. The injected DELETE proves preceding ACL work rolled back too.
	if _, err := conn.Exec(t.Context(), "grant "+pgx.Identifier{f.readRole}.Sanitize()+" to "+
		pgx.Identifier{admin}.Sanitize()+" with admin true,inherit false,set false"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), "alter role "+pgx.Identifier{admin}.Sanitize()+" nosuperuser"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "alter role "+pgx.Identifier{admin}.Sanitize()+" superuser")
	}()
	if _, err := adminConn.Exec(t.Context(), "grant "+pgx.Identifier{f.readRole}.Sanitize()+" to "+
		pgx.Identifier{f.downstream}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), "alter role "+pgx.Identifier{admin}.Sanitize()+" superuser"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(t.Context(), "grant delete on table "+pgx.Identifier{f.schemas[0], "current_table"}.Sanitize()+
		" to "+pgx.Identifier{f.readRole}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	plan, err := ad.Plan(t.Context(), repair)
	if err != nil {
		t.Fatalf("Plan dependent cleanup: %v", err)
	}
	if _, err := ad.Apply(t.Context(), *plan); err == nil {
		t.Fatal("dependent membership cleanup silently cascaded")
	}
	if rows := membershipRows(t, conn, f.readRole, admin); rows == 0 {
		t.Fatal("failed RESTRICT cleanup removed admin membership")
	}
	if rows := membershipRows(t, conn, f.readRole, f.downstream); rows != 1 {
		t.Fatalf("failed RESTRICT cleanup changed downstream membership rows=%d", rows)
	}
	assertDirectPrivilege(t, conn, f.readRole, "relation", f.schemas[0]+".current_table", "DELETE", true, false)
}

func membershipGrantors(t *testing.T, conn *pgx.Conn, role, member string) []string {
	t.Helper()
	rows, err := conn.Query(t.Context(), `
		select g.rolname from pg_auth_members am join pg_roles r on r.oid=am.roleid
		join pg_roles m on m.oid=am.member join pg_roles g on g.oid=am.grantor
		where r.rolname=$1 and m.rolname=$2 order by g.rolname`, role, member)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var grantors []string
	for rows.Next() {
		var grantor string
		if err := rows.Scan(&grantor); err != nil {
			t.Fatal(err)
		}
		grantors = append(grantors, grantor)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return grantors
}

func assertMembershipShape(
	t *testing.T,
	conn *pgx.Conn,
	role, member, grantor string,
	wantAdmin, wantInherit, wantSet bool,
) {
	t.Helper()
	var gotGrantor string
	var gotAdmin, gotInherit, gotSet bool
	if err := conn.QueryRow(t.Context(), `
		select g.rolname,am.admin_option,
		       coalesce((to_jsonb(am)->>'inherit_option')::boolean,false),
		       coalesce((to_jsonb(am)->>'set_option')::boolean,false)
		from pg_auth_members am join pg_roles r on r.oid=am.roleid
		join pg_roles m on m.oid=am.member join pg_roles g on g.oid=am.grantor
		where r.rolname=$1 and m.rolname=$2`, role, member).
		Scan(&gotGrantor, &gotAdmin, &gotInherit, &gotSet); err != nil {
		t.Fatal(err)
	}
	if gotGrantor != grantor || gotAdmin != wantAdmin || gotInherit != wantInherit || gotSet != wantSet {
		t.Fatalf("membership = grantor:%s admin:%v inherit:%v set:%v, want %s/%v/%v/%v",
			gotGrantor, gotAdmin, gotInherit, gotSet, grantor, wantAdmin, wantInherit, wantSet)
	}
}

func membershipRows(t *testing.T, conn *pgx.Conn, role, member string) int {
	t.Helper()
	var rows int
	if err := conn.QueryRow(t.Context(), `select count(*) from pg_auth_members am join pg_roles r on r.oid=am.roleid join pg_roles m on m.oid=am.member where r.rolname=$1 and m.rolname=$2`, role, member).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

func (f *directPolicyFixture) cleanup() {
	ctx := context.Background()
	cc := f.cc.Copy()
	cc.Database = f.database
	if conn, err := pgx.ConnectConfig(ctx, cc); err == nil {
		for _, role := range f.roles {
			_, _ = conn.Exec(ctx, "drop owned by "+pgx.Identifier{role}.Sanitize()+" cascade")
		}
		_ = conn.Close(ctx)
	}
	cc = f.cc.Copy()
	if cluster, err := pgx.ConnectConfig(ctx, cc); err == nil {
		_, _ = cluster.Exec(ctx, "drop database if exists "+pgx.Identifier{f.database}.Sanitize()+" with (force)")
		for _, role := range f.roles {
			_, _ = cluster.Exec(ctx, "revoke all privileges on tablespace pg_default from "+pgx.Identifier{role}.Sanitize())
			_, _ = cluster.Exec(ctx, "revoke all privileges on parameter work_mem from "+pgx.Identifier{role}.Sanitize())
			_, _ = cluster.Exec(ctx, "drop owned by "+pgx.Identifier{role}.Sanitize()+" cascade")
		}
		for i := len(f.roles) - 1; i >= 0; i-- {
			_, _ = cluster.Exec(ctx, "drop role if exists "+pgx.Identifier{f.roles[i]}.Sanitize())
		}
		_ = cluster.Close(ctx)
	}
}
