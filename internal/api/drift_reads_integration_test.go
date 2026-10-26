//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

type connectionDriftTracer struct {
	mu     sync.Mutex
	scopes [][]uuid.UUID
}

func (tracer *connectionDriftTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	if strings.Contains(strings.ToLower(query.SQL), "with requested as") {
		var ids []uuid.UUID
		if len(query.Args) == 1 {
			if scope, ok := query.Args[0].([]uuid.UUID); ok {
				ids = append(ids, scope...)
			}
		}
		tracer.mu.Lock()
		tracer.scopes = append(tracer.scopes, ids)
		tracer.mu.Unlock()
	}
	return ctx
}
func (*connectionDriftTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (tracer *connectionDriftTracer) take() [][]uuid.UUID {
	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	scopes := tracer.scopes
	tracer.scopes = nil
	return scopes
}

func driftScopeTestEnv(t *testing.T, source *testEnv, tracer pgx.QueryTracer) *testEnv {
	t.Helper()
	config := source.pool.Config()
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	authn, err := auth.New(t.Context(), auth.Config{IssuerURL: newFakeOIDC(t).URL, ClientID: "grantor", RedirectURL: "http://localhost/auth/callback", SessionSecret: []byte(testSessionSecret)})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.New(api.Config{
		Pool: pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Operations: operations.NewStore(),
		Audit: audit.NewWriter(), Credentials: credentials.NewService(nil, nil), Dispatcher: dispatcher, Auth: authn,
		Policy: policy.NewStore(), ScopeEnforcement: policy.EnforcementEnforce,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: source.codec}
}

type connectionDriftCounts struct {
	Unmanaged int `json:"unmanaged_bindings"`
	Drift     int `json:"drift_bindings"`
	Resources int `json:"missing_managed_resources"`
	Accounts  int `json:"missing_managed_accounts"`
}

func readConnectionDriftList(t *testing.T, env *testEnv, sess auth.Session) map[uuid.UUID]connectionDriftCounts {
	t.Helper()
	response := env.do(t, http.MethodGet, "/api/v1/connections", nil, &sess, false)
	requireStatus(t, response, http.StatusOK)
	var result struct {
		Connections []struct {
			ID    uuid.UUID              `json:"id"`
			Drift *connectionDriftCounts `json:"drift"`
		} `json:"connections"`
	}
	if err := json.Unmarshal(readBody(t, response), &result); err != nil {
		t.Fatal(err)
	}
	out := make(map[uuid.UUID]connectionDriftCounts, len(result.Connections))
	for _, conn := range result.Connections {
		if conn.Drift == nil {
			t.Fatalf("connection %s lost drift projection", conn.ID)
		}
		out[conn.ID] = *conn.Drift
	}
	return out
}

func TestIntegrationConnectionListBatchesVisibleDriftCounters(t *testing.T) {
	fixture := newObjectReadFixture(t, 1, 2, 1)
	tracer := &connectionDriftTracer{}
	env := driftScopeTestEnv(t, fixture.env, tracer)
	allowedEnvironment := "drift-visible-" + uuid.NewString()
	deniedEnvironment := "drift-denied-" + uuid.NewString()
	ownedIDs := []uuid.UUID{fixture.connectionID}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := env.pool.Exec(ctx, `delete from bindings where account_id in(select id from accounts where connection_id=any($1::uuid[]))`, ownedIDs); err != nil {
			t.Errorf("clean connection list fixture bindings: %v", err)
			return
		}
		if _, err := env.pool.Exec(ctx, `delete from connections where id=any($1::uuid[])`, ownedIDs); err != nil {
			t.Errorf("clean connection list fixtures: %v", err)
		}
		if _, err := env.pool.Exec(ctx, `delete from scope_policies where environment=$1 and subject_kind='role' and subject='operator'`, allowedEnvironment); err != nil {
			t.Errorf("clean connection list scope: %v", err)
		}
	})
	if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, fixture.connectionID, allowedEnvironment); err != nil {
		t.Fatal(err)
	}
	viewer := session(auth.RoleViewer)
	before := readConnectionDriftList(t, env, viewer)
	if before[fixture.connectionID] != (connectionDriftCounts{Unmanaged: 2}) {
		t.Fatalf("fixture drift = %+v, want two external bindings", before[fixture.connectionID])
	}
	if calls := tracer.take(); len(calls) != 1 {
		t.Fatalf("initial connection list batch queries = %d", len(calls))
	}
	for range 44 {
		conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
			DisplayName: "drift-empty-" + uuid.NewString(), Engine: "postgres", Environment: deniedEnvironment,
		})
		if err != nil {
			t.Fatal(err)
		}
		ownedIDs = append(ownedIDs, conn.ID)
	}
	after := readConnectionDriftList(t, env, viewer)
	if after[fixture.connectionID] != (connectionDriftCounts{Unmanaged: 2}) {
		t.Fatalf("batch changed populated counters: %+v", after[fixture.connectionID])
	}
	for _, id := range ownedIDs[1:] {
		if counters, found := after[id]; !found || counters != (connectionDriftCounts{}) {
			t.Fatalf("empty connection %s has missing/nonzero counters: %+v found=%v", id, counters, found)
		}
	}
	if calls := tracer.take(); len(calls) != 1 {
		t.Fatalf("44 extra connections changed batch query count to %d", len(calls))
	}
	admin := session(auth.RoleAdmin)
	createRolePolicy(t, env, admin, allowedEnvironment)
	operator := session(auth.RoleOperator)
	scoped := readConnectionDriftList(t, env, operator)
	if scoped[fixture.connectionID] != (connectionDriftCounts{Unmanaged: 2}) {
		t.Fatalf("scoped operator lost allowed counters: %+v", scoped[fixture.connectionID])
	}
	for _, id := range ownedIDs[1:] {
		if _, leaked := scoped[id]; leaked {
			t.Fatalf("connection outside operator scope leaked: %s", id)
		}
	}
	calls := tracer.take()
	if len(calls) != 1 {
		t.Fatalf("scoped list batch queries = %d", len(calls))
	}
	requested := make(map[uuid.UUID]bool, len(calls[0]))
	for _, id := range calls[0] {
		requested[id] = true
	}
	if !requested[fixture.connectionID] {
		t.Fatal("allowed connection missing from batch scope")
	}
	for _, id := range ownedIDs[1:] {
		if requested[id] {
			t.Fatalf("drift query received a connection filtered out by scope: %s", id)
		}
	}
}
