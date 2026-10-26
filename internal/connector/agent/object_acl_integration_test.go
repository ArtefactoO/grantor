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

func TestObjectACLConnectorDiscoveryGrantAndRevoke(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is required")
	}
	ctx := t.Context()
	parsed, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx) //nolint:errcheck
	name := fmt.Sprintf("connector_acl_%d", time.Now().UnixNano())
	subject := name + "_user"
	table := pgx.Identifier{"public", name}.Sanitize()
	exec := func(sql string) {
		t.Helper()
		if _, err := admin.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec("create role " + pgx.Identifier{subject}.Sanitize() + " nologin")
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			return
		}
		defer c.Close(context.Background()) //nolint:errcheck
		_, _ = c.Exec(context.Background(), "drop table if exists "+table)
		_, _ = c.Exec(context.Background(), "alter default privileges in schema public revoke select on tables from "+pgx.Identifier{subject}.Sanitize())
		_, _ = c.Exec(context.Background(), "drop role if exists "+pgx.Identifier{subject}.Sanitize())
	})
	exec("create table " + table + " (id int)")
	exec("insert into " + table + " values(11)")
	exec("grant insert on " + table + " to " + pgx.Identifier{subject}.Sanitize())
	exec("grant select(id) on " + table + " to " + pgx.Identifier{subject}.Sanitize())
	exec("grant select on " + table + " to public")
	exec("alter default privileges in schema public grant select on tables to " + pgx.Identifier{subject}.Sanitize())
	ref := connector.ConnectionRef{ID: "actual-object-acl", Engine: "postgres", ConfigIncarnation: "acl-config", Endpoints: []string{net.JoinHostPort(parsed.Host, strconv.Itoa(int(parsed.Port)))}}
	rt := newRuntimeWith(t, pairs(t)[0], gateway.Config{}, agent.Config{Capabilities: []adapter.Capability{adapter.CapPostgresSuperuserDirectV1, adapter.CapPostgresObjectACLV1}},
		func(engine string) (adapter.Adapter, error) {
			if engine != "postgres" {
				t.Fatal("wrong engine")
			}
			return postgres.New(), nil
		}, runtime{})
	seq := 0
	dispatch := func(kind connector.JobKind, raw []byte) connector.JobResult {
		t.Helper()
		seq++
		id := fmt.Sprintf("object-acl-%d", seq)
		creds := connector.JobCredentials{Admin: &adapter.Credential{Kind: "password", Username: parsed.User, Secret: []byte(parsed.Password)}, AdminCredentialIncarnation: 2}
		defer creds.Zero()
		res, err := rt.srv.Dispatch(ctx, connector.Job{ID: id, Kind: kind, Engine: "postgres", ConnectionID: ref.ID, ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: id, Payload: raw}, creds)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	discover := func() *adapter.Snapshot {
		t.Helper()
		raw, err := json.Marshal(connector.DiscoverPayload{PostgresObjectACL: true, SnapshotEncoding: connector.SnapshotGzipV1, Connection: ref, TLS: connector.TLSRef{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database}})
		if err != nil {
			t.Fatal(err)
		}
		res := dispatch(connector.JobDiscover, raw)
		if res.Status != connector.JobSuccess {
			t.Fatal(res.Error)
		}
		if bytes.Contains(res.Result, []byte(parsed.Password)) {
			t.Fatal("discovery leaked credentials")
		}
		snap, err := connector.ParseDiscoveryResult(res.Result)
		if err != nil {
			t.Fatal(err)
		}
		return snap
	}
	snapshot := discover()
	legacyRequest, _ := json.Marshal(connector.DiscoverPayload{Connection: ref, TLS: connector.TLSRef{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database}})
	legacy := dispatch(connector.JobDiscover, legacyRequest)
	legacySnapshot, err := connector.ParseDiscoveryResult(legacy.Result)
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range legacySnapshot.Permissions {
		if _, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID); err == nil {
			t.Fatal("upgraded connector exposed unsupported ACL definitions to a legacy worker")
		}
	}
	var p adapter.PostgresObjectPrivilege
	for _, permission := range snapshot.Permissions {
		candidate, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
		if err == nil && candidate.Name == name && candidate.Kind == "table" && candidate.Privilege == "SELECT" {
			p = candidate
		}
	}
	if p.ObjectOID == 0 {
		t.Fatal("connector discovery lost object permission catalog")
	}
	columnSeen, publicSeen := false, false
	for _, permission := range snapshot.Permissions {
		candidate, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
		if err == nil && candidate.Name == name && candidate.Kind == "column" {
			columnSeen = true
		}
	}
	for _, resource := range snapshot.Resources {
		if resource.Kind == "table" && resource.Name == name {
			raw, _ := json.Marshal(resource.Attributes["public_privileges"])
			publicSeen = bytes.Contains(raw, []byte("SELECT"))
		}
	}
	if !columnSeen || !publicSeen {
		t.Fatal("connector lost column or PUBLIC observations")
	}
	defaults, err := json.Marshal(snapshot.Topology["postgres_default_privileges"])
	if err != nil || !bytes.Contains(defaults, []byte(subject)) {
		t.Fatal("connector lost default privileges")
	}
	var oid uint32
	if err := admin.QueryRow(ctx, `select oid from pg_roles where rolname=$1`, subject).Scan(&oid); err != nil {
		t.Fatal(err)
	}
	pins := adapter.PostgresObjectACLPins{AdminIdentity: parsed.User, TargetIdentity: p.TargetIdentity, ConfigIncarnation: ref.ConfigIncarnation, CredentialIncarnation: 2, SubjectOID: oid}
	request := connector.MutationPayload{Connection: ref, TLS: connector.TLSRef{Mode: "disabled"}, Attributes: map[string]any{"database": parsed.Database}, Change: connector.ChangeRef{
		Kind: string(adapter.ChangePostgresObjectACLGrantV1), Account: connector.AccountRef{Kind: "group", EngineIdentity: subject}, Permission: p.PermissionID(), Scope: p.Scope(), ObjectACL: &pins, ExpectedAdminIdentity: pins.AdminIdentity, ExpectedTargetIdentity: pins.TargetIdentity}}
	raw, _ := request.Marshal()
	result := dispatch(connector.JobApply, raw)
	if result.Status != connector.JobSuccess {
		t.Fatal(result.Error)
	}
	verified, err := connector.ParseSanitizedResult(result.Result)
	if err != nil || verified.Verification == nil {
		t.Fatalf("connector result: %v", err)
	}
	verification := verified.Verification
	if !verification.Verified {
		t.Fatalf("connector grant proof: %v", err)
	}
	var observed struct {
		Grantors []adapter.PostgresACLGrantor `json:"grantors"`
	}
	data, _ := json.Marshal(verification.Observed)
	if err := json.Unmarshal(data, &observed); err != nil || len(observed.Grantors) == 0 {
		t.Fatal("connector lost exact grantors")
	}
	found := false
	for _, b := range discover().Bindings {
		if b.AccountEngineIdentity == subject && b.PermissionExternalID == p.PermissionID() {
			found = true
		}
	}
	if !found {
		t.Fatal("connector snapshot lost actual direct grant")
	}
	pins.Grantors = observed.Grantors
	exec("revoke select(id) on " + table + " from " + pgx.Identifier{subject}.Sanitize())
	request.Change.Kind = string(adapter.ChangePostgresObjectACLRevokeV1)
	raw, _ = request.Marshal()
	result = dispatch(connector.JobApply, raw)
	if result.Status != connector.JobSuccess {
		t.Fatal(result.Error)
	}
	var direct, effectiveInsert bool
	var total int
	if err := admin.QueryRow(ctx, `select exists(select 1 from pg_catalog.pg_class c cross join lateral pg_catalog.aclexplode(c.relacl) a where c.oid=$2::regclass and a.grantee=(select oid from pg_roles where rolname=$1) and a.privilege_type='SELECT'),has_table_privilege($1,$2,'INSERT')`, subject, table).Scan(&direct, &effectiveInsert); err != nil || direct || !effectiveInsert {
		t.Fatal("connector revoke damaged unrelated ACL")
	}
	if err := admin.QueryRow(ctx, "select sum(id)::int from "+table).Scan(&total); err != nil || total != 11 {
		t.Fatal("connector mutated table data")
	}
	pins.SubjectOID++
	raw, _ = request.Marshal()
	result = dispatch(connector.JobApply, raw)
	if result.Status != connector.JobFailed {
		t.Fatal("connector accepted stale subject identity")
	}
}
