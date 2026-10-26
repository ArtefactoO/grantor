//go:build integration

package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestPostgresAccessEvidenceSignedConnectorMatchesDirect(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is required")
	}
	ctx := t.Context()
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx) //nolint:errcheck
	name := fmt.Sprintf("connector_evidence_%d", time.Now().UnixNano())
	subject, role := name+"_login", name+"_writer"
	quote := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	for _, sql := range []string{"create role " + quote(subject) + " login noinherit", "create role " + quote(role) + " nologin", "grant " + quote(role) + " to " + quote(subject), "grant pg_write_all_data to " + quote(role)} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		for _, role := range []string{subject, role} {
			_, _ = c.Exec(context.Background(), "drop role if exists "+quote(role))
		}
	})
	endpoint := net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port)))
	ref := connector.ConnectionRef{ID: "access-evidence", Engine: "postgres", ConfigIncarnation: "evidence-config", Endpoints: []string{endpoint}}
	runtime := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresObjectACLV1}}, func(engine string) (adapter.Adapter, error) {
		if engine != "postgres" {
			t.Fatal("wrong engine")
		}
		return postgres.New(), nil
	}, runtime{})
	raw, err := json.Marshal(connector.DiscoverPayload{PostgresObjectACL: true, SnapshotEncoding: connector.SnapshotGzipV1, Connection: ref, TLS: connector.TLSRef{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database}})
	if err != nil {
		t.Fatal(err)
	}
	creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: parsed.User, Secret: []byte(parsed.Password)}, AdminCredentialIncarnation: 1}
	defer creds.Zero()
	result, err := runtime.srv.Dispatch(ctx, connector.Job{ID: "access-evidence-discover", Kind: connector.JobDiscover, Engine: "postgres", ConnectionID: ref.ID, ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "access-evidence-discover", Payload: raw}, creds)
	if err != nil || result.Status != connector.JobSuccess {
		t.Fatalf("signed discovery: %v / %+v", err, result.Error)
	}
	if bytes.Contains(result.Result, []byte(parsed.Password)) {
		t.Fatal("connector discovery exposed admin credential")
	}
	snapshot, err := connector.ParseDiscoveryResult(result.Result)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := postgres.New().Discover(ctx, adapter.Connection{ID: ref.ID, Engine: "postgres", Endpoints: []string{endpoint}, TLS: adapter.TLSConfig{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database}, AdminCredential: *creds.Admin})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(snapshot *adapter.Snapshot) adapter.PostgresAccessEvidence {
		t.Helper()
		raw, err := json.Marshal(snapshot.Topology["postgres_access_evidence"])
		if err != nil {
			t.Fatal(err)
		}
		var evidence adapter.PostgresAccessEvidence
		if err := json.Unmarshal(raw, &evidence); err != nil {
			t.Fatal(err)
		}
		return evidence
	}
	remoteEvidence, directEvidence := decode(snapshot), decode(direct)
	if !remoteEvidence.MembershipsSupported || len(remoteEvidence.Endpoints) != 1 || !remoteEvidence.Endpoints[0].Available || remoteEvidence.Endpoints[0].ServerRole != "primary" {
		t.Fatalf("connector lost diagnostic evidence: %+v", remoteEvidence)
	}
	find := func(evidence adapter.PostgresAccessEvidence, role string) adapter.PostgresRoleReachability {
		for _, row := range evidence.Memberships {
			if row.Member == subject && row.Role == role {
				return row
			}
		}
		return adapter.PostgresRoleReachability{}
	}
	for _, role := range []string{role, "pg_write_all_data"} {
		remote, direct := find(remoteEvidence, role), find(directEvidence, role)
		if remote != direct || !remote.IsMember || remote.Usage || !remote.SetRole {
			t.Fatalf("connector/direct reachability differs: remote=%+v direct=%+v", remote, direct)
		}
	}
	if remoteEvidence.Endpoints[0].ServerAddress != directEvidence.Endpoints[0].ServerAddress || len(remoteEvidence.Endpoints[0].Rules) != len(directEvidence.Endpoints[0].Rules) {
		t.Fatal("connector HBA endpoint coverage differs from direct")
	}
}
