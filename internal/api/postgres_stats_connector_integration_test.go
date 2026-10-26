//go:build integration

package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// The observer retains only closed, secret-free identity pins; credentials
// always pass directly to the real signed gateway and are never recorded.
type statsConnectorObserver struct {
	*gateway.Server
	dispatches atomic.Int64
	mu         sync.Mutex
	changes    []adapter.ChangeKind
	pins       []adapter.PostgresStatsMembershipPins
}

func (o *statsConnectorObserver) Dispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	o.dispatches.Add(1)
	if job.Kind == connector.JobApply || job.Kind == connector.JobPlan || job.Kind == connector.JobVerify {
		payload, err := connector.ParseMutationPayload(job.Payload)
		if err == nil && payload.Change.Permission == postgres.StatsPermission {
			o.mu.Lock()
			o.changes = append(o.changes, adapter.ChangeKind(payload.Change.Kind))
			if payload.Change.StatsMembership != nil {
				o.pins = append(o.pins, *payload.Change.StatsMembership)
			}
			o.mu.Unlock()
		}
	}
	return o.Server.Dispatch(ctx, job, creds)
}

type statsConnectorVaultReader struct {
	client *vault.Client
	reads  atomic.Int64
}

func (r *statsConnectorVaultReader) Get(ctx context.Context, path string) (map[string]any, int, error) {
	r.reads.Add(1)
	return r.client.Get(ctx, path)
}

// A separate local harness leaves the shared direct-worker helper unchanged.
func newStatsConnectorEnv(t *testing.T, vaultClient *vault.Client) (*testEnv, *statsConnectorObserver, *statsConnectorVaultReader, func(bool)) {
	t.Helper()
	pool := pgtest.Pool(t)
	id := "stats-" + uniqueSuffix()[:8]
	pair := conntest.GenTLS(t, "localhost", id)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := connector.NewED25519Verifier("stats-gateway", public)
	server, err := gateway.New(gateway.Config{TLS: pair.ServerTLS,
		Signer: connector.NewED25519Signer("stats-gateway", private), Dedup: connectorjobs.NewStore(pool, 0),
		LivenessWindow: 5 * time.Second, QuiescenceTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	var stopAgent func()
	t.Cleanup(func() {
		if stopAgent != nil {
			stopAgent()
		}
		_ = listener.Close()
		_ = server.Close()
	})
	startAgent := func(statsCapability bool) {
		t.Helper()
		if stopAgent != nil {
			stopAgent()
			stopAgent = nil
		}
		capabilities := slices.Clone(postgres.New().Manifest().Capabilities)
		if !statsCapability {
			capabilities = slices.DeleteFunc(capabilities, func(c adapter.Capability) bool { return c == adapter.CapPostgresStatsMembershipV1 })
		}
		a, err := agent.New(agent.Config{GatewayAddr: listener.Addr().String(), ConnectorID: id,
			TLS: pair.ClientTLS, Verifier: verifier, HeartbeatInterval: 200 * time.Millisecond,
			Capabilities: capabilities, NewAdapter: func(string) (adapter.Adapter, error) { return postgres.New(), nil }})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- a.Run(ctx) }()
		stopAgent = func() {
			cancel()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Error("stats connector did not stop")
			}
		}
		deadline := time.Now().Add(10 * time.Second)
		for !server.ActiveConnectorSupports(adapter.CapPostgresSuperuserDirectV1) ||
			server.ActiveConnectorSupports(adapter.CapPostgresStatsMembershipV1) != statsCapability {
			if time.Now().After(deadline) {
				t.Fatal("stats connector did not negotiate the expected capability set")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	startAgent(true)
	observer := &statsConnectorObserver{Server: server}
	reader := &statsConnectorVaultReader{client: vaultClient}
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{Connections: connections.NewStore(), Inventory: inventory.NewStore(),
		Audit: audit.NewWriter(), Vault: reader, Pool: pool}).
		WithMutations(jobs.MutationDeps{Credentials: credentials.NewService(vaultClient, nil)}).
		WithConnector(jobs.ConnectorDeps{Dispatcher: observer})
	river, err := jobs.New(pool, operations.NewStore(), executor, jobs.Config{Queue: id, WorkerCount: 1,
		MaxAttempts: 1, SnoozeOnLock: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := river.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := river.Stop(ctx); err != nil {
			t.Errorf("stop stats worker: %v", err)
		}
	})
	env := buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: policy.EnforcementDisabled, dispatcher: river})
	return env, observer, reader, startAgent
}

func TestIntegrationStatsMembershipThroughSignedConnector(t *testing.T) {
	dsn := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set")
	}
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid target fixture DSN")
	}
	if !targetQueryBool(t.Context(), t, dsn, `select current_setting('server_version_num')::int >= 160000`) {
		t.Skip("statistics delegation regression requires PostgreSQL >= 16")
	}
	registerPostgresOnceAPI.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	vaultClient := newTestVault(t)
	env, observer, reader, startAgent := newStatsConnectorEnv(t, vaultClient)
	admin, operator := session(auth.RoleAdmin), session(auth.RoleOperator)
	connID, _ := createScopedConnection(t, env, admin, operator, map[string]any{
		"display_name": "Stats connector " + uniqueSuffix()[:8], "engine": postgres.Engine, "environment": "stats-" + uniqueSuffix()[:8],
		"execution_mode": "connector", "endpoints": []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		"tls_config": map[string]string{"mode": "disabled"}, "discovery_config": map[string]string{"database": cc.Database},
		"admin_credential": map[string]string{"username": cc.User, "password": cc.Password}})
	permission := findPermission(t, env.pool, connID, postgres.StatsPermission)
	if !permission.Assignable {
		t.Fatal("negotiated statistics connector role is not assignable")
	}
	principal := createPrincipalRow(t, env.pool, "Stats connector monitor "+uniqueSuffix()[:8])
	name := "stats_conn_" + uniqueSuffix()[:8]
	t.Cleanup(func() {
		targetExec(context.Background(), t, dsn, "drop role if exists "+pgx.Identifier{name}.Sanitize())
	})
	response := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access", map[string]any{
		"engine_identity": name, "items": []map[string]any{{"connection_id": connID, "permission_id": permission.ID}}}, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var access struct {
		Children []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(response.Body).Decode(&access); err != nil || len(access.Children) != 1 {
		t.Fatal("invalid connector principal-access receipt")
	}
	child := access.Children[0]
	if child.AccountCreateOperationID == nil {
		t.Fatal("connector LOGIN creation dependency is missing")
	}
	grant, err := operations.NewStore().Get(t.Context(), env.pool, child.GrantOperationID)
	if err != nil || grant.Kind != jobs.KindPostgresStatsGrantV1 {
		t.Fatal("connector used the legacy grant worker")
	}
	var payload jobs.AccessPayload
	if err := json.Unmarshal(grant.Payload, &payload); err != nil || payload.StatsMembership == nil ||
		payload.StatsMembership.SubjectOID != 0 || payload.StatsCreationOperationID != *child.AccountCreateOperationID {
		t.Fatal("connector grant did not defer the subject OID to the verified CREATE receipt")
	}
	waitOperation(t, env, child.GrantOperationID, operations.StatusSuccess, 30*time.Second)
	receipt, err := accountcreation.NewStore().Get(t.Context(), env.pool, *child.AccountCreateOperationID)
	if err != nil || receipt.Phase != "verified" || receipt.RoleOID == 0 || receipt.AccountID != child.AccountID || receipt.ConnectionID != connID {
		t.Fatal("connector LOGIN lacks a verified matching creation receipt")
	}
	if !targetQueryBool(t.Context(), t, dsn, `select oid=$2::oid and rolcanlogin and rolinherit and
		not (rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls) from pg_roles where rolname=$1`, name, receipt.RoleOID) {
		t.Fatal("created connector LOGIN identity or privilege boundary is wrong")
	}
	password, version := targetSecretPassword(t.Context(), t, vaultClient, receipt.CredentialPath)
	if version != receipt.CredentialVersion || !targetCanAuthenticate(t.Context(), t, cc, name, password) {
		t.Fatal("verified connector LOGIN cannot authenticate with its exact generated credential")
	}
	if !targetQueryBool(t.Context(), t, dsn, `select pg_has_role($1,$2,'USAGE') and exists (
		select 1 from pg_auth_members m join pg_roles r on r.oid=m.roleid join pg_roles u on u.oid=m.member
		where r.rolname=$2 and u.rolname=$1) and not exists (
		select 1 from pg_auth_members m join pg_roles r on r.oid=m.roleid join pg_roles u on u.oid=m.member
		where r.rolname=$2 and u.rolname=$1 and (m.admin_option or m.set_option or not m.inherit_option))`, name, postgres.StatsRole) {
		t.Fatal("statistics access is ineffective or delegating in at least one grantor row")
	}
	response = env.do(t, http.MethodDelete, "/api/v1/bindings/"+child.BindingID.String(), nil, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var revoked struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	waitOperation(t, env, revoked.OperationID, operations.StatusSuccess, 30*time.Second)
	if targetQueryBool(t.Context(), t, dsn, `select pg_has_role($1,$2,'MEMBER')`, name, postgres.StatsRole) {
		t.Fatal("connector revoke left a statistics grantor row")
	}
	observer.mu.Lock()
	changes, pins := slices.Clone(observer.changes), slices.Clone(observer.pins)
	observer.mu.Unlock()
	if !slices.Contains(changes, adapter.ChangePostgresStatsMembershipGrantV1) ||
		!slices.Contains(changes, adapter.ChangePostgresStatsMembershipRevokeV1) || len(changes) != len(pins) {
		t.Fatal("real signed connector did not execute both closed statistics primitives")
	}
	for i, pin := range pins {
		if !adapter.IsPostgresStatsMembershipChange(changes[i]) || pin.SubjectOID != receipt.RoleOID ||
			pin.AdminIdentity != receipt.AdminIdentity || pin.TargetIdentity != receipt.TargetIdentity ||
			pin.ConfigIncarnation != receipt.ConfigIncarnation || pin.CredentialIncarnation != receipt.AdminCredentialIncarnation ||
			pin.BuiltinOID != payload.StatsMembership.BuiltinOID {
			t.Fatal("signed statistics primitive lost a pinned identity or used a legacy fallback")
		}
	}

	// Keep the stored discovery snapshot deliberately stale. The currently
	// connected old agent must stop the worker before credentials or dispatch.
	startAgent(false)
	readsBefore, dispatchesBefore := reader.reads.Load(), observer.dispatches.Load()
	response = env.do(t, http.MethodPost, "/api/v1/bindings", map[string]any{
		"account_id": child.AccountID, "permission_id": permission.ID}, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var rejected struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(response.Body).Decode(&rejected); err != nil {
		t.Fatal(err)
	}
	waitOperation(t, env, rejected.OperationID, operations.StatusFailed, 30*time.Second)
	failed, err := operations.NewStore().Get(t.Context(), env.pool, rejected.OperationID)
	if err != nil || failed.Kind != jobs.KindPostgresStatsGrantV1 ||
		!strings.Contains(failed.Error, jobs.ErrConnectorCapabilityUnavailable.Error()) ||
		!strings.Contains(failed.Error, string(adapter.CapPostgresStatsMembershipV1)) {
		t.Fatal("old connector failed for a reason other than the negotiated statistics capability fence")
	}
	if reader.reads.Load() != readsBefore || observer.dispatches.Load() != dispatchesBefore {
		t.Fatal("old connector rejection crossed the credential/dispatch boundary")
	}
	if targetQueryBool(t.Context(), t, dsn, `select pg_has_role($1,$2,'MEMBER')`, name, postgres.StatsRole) {
		t.Fatal("old connector rejection changed target membership")
	}
}
