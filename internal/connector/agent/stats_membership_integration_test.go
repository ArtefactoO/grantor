//go:build integration

package agent_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

// Uses an explicitly supplied disposable target. No external cluster is
// discovered and no account credential is carried by a stats job.
func TestStatsMembershipConnectorActualPostgresPinsGrantAndRevoke(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is required")
	}
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	name := fmt.Sprintf("connector_stats_%d", time.Now().UnixNano())
	if _, err := admin.Exec(t.Context(), "create role "+pgx.Identifier{name}.Sanitize()+" login password 'connector-stats-fixture'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = admin.Exec(ctx, "drop role if exists "+pgx.Identifier{name}.Sanitize())
	})
	var builtin, subject uint32
	var physical string
	if err := admin.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, postgres.StatsRole).Scan(&builtin); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(t.Context(), `select oid from pg_roles where rolname=$1`, name).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(t.Context(), `select system_identifier::text from pg_control_system()`).Scan(&physical); err != nil {
		t.Fatal(err)
	}
	pins := adapter.PostgresStatsMembershipPins{AdminIdentity: parsed.User, TargetIdentity: "postgres:system:" + physical, ConfigIncarnation: "connector-stats-config", CredentialIncarnation: 3, BuiltinOID: builtin, SubjectOID: subject}
	base := connector.MutationPayload{Connection: connector.ConnectionRef{ID: "actual-stats", Engine: "postgres", ConfigIncarnation: pins.ConfigIncarnation, Endpoints: []string{net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port)))}},
		TLS: connector.TLSRef{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database},
		Change: connector.ChangeRef{Kind: string(adapter.ChangePostgresStatsMembershipGrantV1), Account: connector.AccountRef{Kind: "login", EngineIdentity: name}, Permission: postgres.StatsPermission,
			ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity, StatsMembership: &pins}}
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresStatsMembershipV1}},
		func(engine string) (adapter.Adapter, error) {
			if engine != postgres.Engine {
				t.Fatal("wrong target adapter")
			}
			return postgres.New(), nil
		}, runtime{})
	seq := 0
	dispatch := func(p connector.MutationPayload, jobKind connector.JobKind) (connector.JobResult, error) {
		seq++
		raw, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("actual-stats-%d", seq)
		creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: parsed.User, Secret: []byte(parsed.Password)}, AdminCredentialIncarnation: 3}
		defer creds.Zero()
		return rt.srv.Dispatch(t.Context(), connector.Job{ID: id, Kind: jobKind, Engine: "postgres", ConnectionID: p.Connection.ID, ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: id, Payload: raw}, creds)
	}
	for label, mutate := range map[string]func(*connector.MutationPayload, *adapter.PostgresStatsMembershipPins){
		"physical target": func(p *connector.MutationPayload, q *adapter.PostgresStatsMembershipPins) {
			q.TargetIdentity = "postgres:system:1"
			p.Change.ExpectedTargetIdentity = q.TargetIdentity
		},
		"live admin": func(p *connector.MutationPayload, q *adapter.PostgresStatsMembershipPins) {
			q.AdminIdentity = "wrong_admin"
			p.Change.ExpectedAdminIdentity = q.AdminIdentity
		},
		"config": func(p *connector.MutationPayload, _ *adapter.PostgresStatsMembershipPins) {
			p.Connection.ConfigIncarnation = "other"
		},
		"credential incarnation": func(_ *connector.MutationPayload, q *adapter.PostgresStatsMembershipPins) { q.CredentialIncarnation++ },
		"builtin oid":            func(_ *connector.MutationPayload, q *adapter.PostgresStatsMembershipPins) { q.BuiltinOID++ },
		"subject oid":            func(_ *connector.MutationPayload, q *adapter.PostgresStatsMembershipPins) { q.SubjectOID++ },
		"target unavailable": func(p *connector.MutationPayload, _ *adapter.PostgresStatsMembershipPins) {
			p.Connection.Endpoints = []string{"127.0.0.1:1"}
		},
	} {
		t.Run(label, func(t *testing.T) {
			p, q := base, pins
			p.Change.StatsMembership = &q
			mutate(&p, &q)
			res, err := dispatch(p, connector.JobApply)
			if err == nil && res.Status != connector.JobFailed {
				t.Fatal("unproven connector stats apply succeeded")
			}
			var present bool
			if err := admin.QueryRow(t.Context(), `select exists(select 1 from pg_auth_members where roleid=$1 and member=$2)`, builtin, subject).Scan(&present); err != nil || present {
				t.Fatal("failed stats proof changed membership")
			}
		})
	}
	for _, jobKind := range []connector.JobKind{connector.JobPlan, connector.JobApply, connector.JobVerify} {
		res, err := dispatch(base, jobKind)
		if err != nil || res.Status != connector.JobSuccess {
			t.Fatalf("valid pinned stats job failed: %v %s", err, res.Error)
		}
	}
	monitorConfig := parsed.Copy()
	monitorConfig.User, monitorConfig.Password = name, "connector-stats-fixture"
	monitor, err := pgx.ConnectConfig(t.Context(), monitorConfig)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := monitor.QueryRow(t.Context(), `select count(*) from pg_stat_activity`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	_ = monitor.Close(t.Context())
	var elevated bool
	if err := admin.QueryRow(t.Context(), `select rolsuper or rolcreaterole or rolreplication or rolbypassrls from pg_roles where rolname=$1`, name).Scan(&elevated); err != nil || elevated {
		t.Fatal("monitoring LOGIN became privileged")
	}
	base.Change.Kind = string(adapter.ChangePostgresStatsMembershipRevokeV1)
	res, err := dispatch(base, connector.JobApply)
	if err != nil || res.Status != connector.JobSuccess {
		t.Fatalf("pinned stats revoke failed: %v %s", err, res.Error)
	}
	var present bool
	if err := admin.QueryRow(t.Context(), `select exists(select 1 from pg_auth_members where roleid=$1 and member=$2)`, builtin, subject).Scan(&present); err != nil || present {
		t.Fatal("revoked stats membership remains")
	}
}
