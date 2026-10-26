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

func TestStatsMembershipDirectGrantProofAndRevoke(t *testing.T) {
	dsn := targetDSN(t)
	admin, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(t.Context()) //nolint:errcheck
	name := fmt.Sprintf("stats_monitor_%d", time.Now().UnixNano())
	if _, err := admin.Exec(t.Context(), "create role "+pgx.Identifier{name}.Sanitize()+" login password 'stats-fixture-password'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn := connectTarget(context.Background(), t, dsn, "")
		defer conn.Close(context.Background())
		_, _ = conn.Exec(context.Background(), "drop role if exists "+pgx.Identifier{name}.Sanitize())
	})
	cfg := targetConnection(t, dsn)
	cfg.ConfigIncarnation, cfg.AdminCredentialIncarnation = "stats-fixture-config", 1
	var builtin, subject uint32
	var system string
	if err := admin.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, postgres.StatsRole).Scan(&builtin); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, name).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&system); err != nil {
		t.Fatal(err)
	}
	pins := postgres.StatsMembershipPins{AdminIdentity: cfg.AdminCredential.Username, TargetIdentity: "postgres:system:" + system,
		ConfigIncarnation: cfg.ConfigIncarnation, CredentialIncarnation: 1, BuiltinOID: builtin, SubjectOID: subject}
	change := adapter.DesiredChange{Kind: adapter.ChangePostgresStatsMembershipGrantV1, Connection: cfg,
		Account: adapter.Account{Kind: "login", EngineIdentity: name}, Permission: postgres.StatsPermission, StatsMembership: &pins,
		ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity}
	a := postgres.New()
	for _, mutate := range []func(*postgres.StatsMembershipPins){
		func(p *postgres.StatsMembershipPins) { p.SubjectOID++ },
		func(p *postgres.StatsMembershipPins) { p.BuiltinOID++ },
		func(p *postgres.StatsMembershipPins) { p.AdminIdentity = "wrong_admin" },
		func(p *postgres.StatsMembershipPins) { p.TargetIdentity = "postgres:system:1" },
		func(p *postgres.StatsMembershipPins) { p.ConfigIncarnation = "wrong_config" },
		func(p *postgres.StatsMembershipPins) { p.CredentialIncarnation++ },
	} {
		bad := pins
		mutate(&bad)
		request := change
		request.StatsMembership = &bad
		request.ExpectedAdminIdentity, request.ExpectedTargetIdentity = bad.AdminIdentity, bad.TargetIdentity
		if _, err := a.Plan(t.Context(), request); err == nil {
			t.Fatal("unproven statistics grant accepted")
		}
		if _, err := a.Apply(t.Context(), adapter.Plan{Change: request, Steps: []adapter.PlanStep{{Kind: "grant"}}}); err == nil {
			t.Fatal("changed live fence accepted at apply")
		}
	}
	plan, err := a.Plan(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	var serverVersion int
	if err := admin.QueryRow(t.Context(), `select current_setting('server_version_num')::int`).Scan(&serverVersion); err != nil {
		t.Fatal(err)
	}
	if serverVersion >= 160000 {
		other := name + "_grantor"
		if _, err := admin.Exec(t.Context(), "create role "+pgx.Identifier{other}.Sanitize()+" nologin"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "grant "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" to "+pgx.Identifier{other}.Sanitize()+" with admin true"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "grant "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" to "+pgx.Identifier{name}.Sanitize()+" with admin false, inherit true, set true granted by "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Apply(t.Context(), *plan); err == nil {
			t.Fatal("foreign SET TRUE grant was accepted as exact SET FALSE")
		}
		verification, err := a.Verify(t.Context(), *plan)
		if err != nil || verification.Verified {
			t.Fatal("foreign SET TRUE row produced successful verification")
		}
		var rows int
		var stillSettable bool
		if err := admin.QueryRow(t.Context(), `select count(*),bool_or(set_option) from pg_auth_members where roleid=$1 and member=$2`, builtin, subject).Scan(&rows, &stillSettable); err != nil || rows != 1 || !stillSettable {
			t.Fatal("rejected apply changed foreign membership rows")
		}
		if _, err := admin.Exec(t.Context(), "revoke "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" from "+pgx.Identifier{name}.Sanitize()+" granted by "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "revoke "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" from "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "drop role "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		// Direct rows can all have SET FALSE while another membership chain
		// still enables SET ROLE. Refuse that effective escalation without
		// modifying the externally managed chain.
		if _, err := admin.Exec(t.Context(), "create role "+pgx.Identifier{other}.Sanitize()+" nologin"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "grant "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" to "+pgx.Identifier{other}.Sanitize()+" with admin false, inherit true, set true"); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "grant "+pgx.Identifier{other}.Sanitize()+" to "+pgx.Identifier{name}.Sanitize()+" with admin false, inherit true, set true"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Apply(t.Context(), *plan); err == nil {
			t.Fatal("indirect SET TRUE path accepted as non-settable membership")
		}
		verification, err = a.Verify(t.Context(), *plan)
		if err != nil || verification.Verified {
			t.Fatal("indirect SET TRUE path produced successful verification")
		}
		var directRows int
		var effectiveSet bool
		if err := admin.QueryRow(t.Context(), `select (select count(*) from pg_auth_members where roleid=$1 and member=$2),pg_has_role($3,$4,'SET')`, builtin, subject, name, postgres.StatsRole).Scan(&directRows, &effectiveSet); err != nil || directRows != 0 || !effectiveSet {
			t.Fatal("failed proof changed the external indirect membership path")
		}
		if _, err := admin.Exec(t.Context(), "revoke "+pgx.Identifier{other}.Sanitize()+" from "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "revoke "+pgx.Identifier{postgres.StatsRole}.Sanitize()+" from "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(t.Context(), "drop role "+pgx.Identifier{other}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.Apply(t.Context(), *plan); err != nil {
		t.Fatal(err)
	}
	verification, err := a.Verify(t.Context(), *plan)
	if err != nil || !verification.Verified {
		t.Fatalf("membership proof failed: %v", err)
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cc.User, cc.Password = name, "stats-fixture-password"
	monitor, err := pgx.ConnectConfig(t.Context(), cc)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := monitor.QueryRow(t.Context(), `select count(*) from pg_stat_activity`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	var totalSize int64
	if err := monitor.QueryRow(t.Context(), `select count(*),sum(pg_database_size(d.oid)) from pg_stat_database s join pg_database d on d.oid=s.datid`).Scan(&count, &totalSize); err != nil {
		t.Fatal(err)
	}
	_ = monitor.Close(t.Context())
	var elevated bool
	if err := admin.QueryRow(t.Context(), `select rolsuper or rolcreaterole or rolreplication or rolbypassrls from pg_roles where rolname=$1`, name).Scan(&elevated); err != nil || elevated {
		t.Fatal("monitoring login elevated")
	}
	change.Kind = adapter.ChangePostgresStatsMembershipRevokeV1
	plan, err = a.Plan(t.Context(), change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Apply(t.Context(), *plan); err != nil {
		t.Fatal(err)
	}
	verification, err = a.Verify(t.Context(), *plan)
	if err != nil || !verification.Verified {
		t.Fatal("statistics membership not revoked")
	}
}
