//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

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
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationObjectPrivilegePageBoundsNestedEvidenceWithoutChangingStoredACL(t *testing.T) {
	f := newObjectReadFixture(t, 1, 2, 1)
	const grantorsCount = 12000
	grantors := make([]any, 0, grantorsCount)
	public := []string{"SELECT", "SELECT", "TRUNCATE"}
	for i := range grantorsCount {
		grantors = append(grantors, map[string]any{"oid": i + 100, "name": fmt.Sprintf("grantor_%05d_", i) + strings.Repeat("x", 40), "grant_option": false})
		public = append(public, fmt.Sprintf("SELECT (column_%05d)", i))
	}
	observed, err := json.Marshal(map[string]any{"direct_privilege": true, "managed_binding_eligible": false, "grantors": grantors, "unknown_extension": strings.Repeat("x", 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	var bindingID uuid.UUID
	if err := f.env.pool.QueryRow(t.Context(), `update bindings set observed_attributes=$2 where account_id=$1 and scope_resource_id is not null returning id`, f.accountID, observed).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.pool.Exec(t.Context(), `update resources set attributes=jsonb_set(attributes,'{public_privileges}',$2::jsonb) where id=$1`, f.scopes[0], publicJSON); err != nil {
		t.Fatal(err)
	}
	viewer := session(auth.RoleViewer)
	path := "/api/v1/accounts/" + f.accountID.String() + "/object-privileges?limit=1"
	response := f.env.do(t, http.MethodGet, path, nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	body := readBody(t, response)
	if len(body) > 32<<10 || bytes.Contains(body, []byte("grantor_00000")) || bytes.Contains(body, []byte("unknown_extension")) || bytes.Contains(body, []byte("column_00000")) {
		t.Fatal("bounded page retained raw grantor or whole-table column evidence")
	}
	var page struct {
		Objects []struct {
			Public    []string `json:"public_privileges"`
			Truncated bool     `json:"public_privileges_truncated"`
			Bindings  []struct {
				Observed map[string]any `json:"observed_attributes"`
			} `json:"bindings"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(body, &page); err != nil || len(page.Objects) != 1 || len(page.Objects[0].Bindings) != 1 {
		t.Fatal("bounded page lost the fixture binding")
	}
	group := page.Objects[0]
	if !group.Truncated || len(group.Public) != 2 || group.Public[0] != "SELECT" || group.Public[1] != "TRUNCATE" {
		t.Fatal("PUBLIC projection changed scope or did not report omitted evidence")
	}
	attrs := group.Bindings[0].Observed
	if len(attrs) != 3 || attrs["direct_privilege"] != true || attrs["managed_binding_eligible"] != false || attrs["grantors_count"] != float64(grantorsCount) {
		t.Fatal("bounded binding projection lost management boundary or grantor count")
	}
	stored, err := inventory.NewStore().GetBinding(t.Context(), f.env.pool, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	var original map[string]json.RawMessage
	if err := json.Unmarshal(stored.ObservedAttributes, &original); err != nil || !bytes.Contains(original["grantors"], []byte("grantor_00000")) || len(original["unknown_extension"]) < 1<<20 {
		t.Fatal("read projection changed raw evidence required by mutations")
	}
	response = f.env.do(t, http.MethodGet, "/api/v1/accounts/"+f.accountID.String()+"/bindings", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	if !bytes.Contains(readBody(t, response), []byte("grantor_00000")) {
		t.Fatal("legacy full binding response no longer exposes its original non-secret ACL evidence")
	}
}

func TestIntegrationObjectPrivilegePagesRetainManagedIntentAndMissingDefinitions(t *testing.T) {
	for _, scenario := range []struct {
		name, desired, observed, status string
		visible                         bool
	}{
		{"failed grant", "present", "unknown", "failed", true},
		{"external revoke", "present", "absent", "drift", true},
		{"pending grant", "present", "unknown", "pending", true},
		{"failed revoke unknown", "absent", "unknown", "failed", true},
		{"revoke drift", "absent", "unknown", "drift", true},
		{"completed revoke", "absent", "absent", "synced", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f := newObjectReadFixture(t, 1, 2, 1)
			if _, err := f.env.pool.Exec(t.Context(), `update bindings set desired_state=$2,observed_state=$3,status=$4,updated_at=now() where account_id=$1 and scope_resource_id is not null`, f.accountID, scenario.desired, scenario.observed, scenario.status); err != nil {
				t.Fatal(err)
			}
			if _, err := f.env.pool.Exec(t.Context(), `update permission_definitions set status='missing' where connection_id=$1 and external_id like 'pgacl:v1:%'`, f.connectionID); err != nil {
				t.Fatal(err)
			}
			viewer := session(auth.RoleViewer)
			response := f.env.do(t, http.MethodGet, "/api/v1/accounts/"+f.accountID.String()+"/object-privileges?limit=1", nil, &viewer, false)
			requireStatus(t, response, http.StatusOK)
			var page struct {
				Total   int `json:"total_entries"`
				Objects []struct {
					Permissions []struct {
						Status     string `json:"status"`
						Assignable bool   `json:"assignable"`
					} `json:"permissions"`
					Bindings []struct {
						Desired  string `json:"desired_state"`
						Observed string `json:"observed_state"`
						Status   string `json:"status"`
					} `json:"bindings"`
				} `json:"objects"`
			}
			if err := json.Unmarshal(readBody(t, response), &page); err != nil {
				t.Fatal(err)
			}
			if !scenario.visible {
				if page.Total != 0 || len(page.Objects) != 0 {
					t.Fatal("completed absent history remained in active ACL pages")
				}
				return
			}
			if page.Total != 1 || len(page.Objects) != 1 || len(page.Objects[0].Permissions) != 1 || len(page.Objects[0].Bindings) != 1 {
				t.Fatal("managed intent or its missing definition disappeared from lazy detail")
			}
			if p := page.Objects[0].Permissions[0]; p.Status != "missing" || p.Assignable {
				t.Fatal("missing ACL definition became assignable")
			}
			if b := page.Objects[0].Bindings[0]; b.Desired != scenario.desired || b.Observed != scenario.observed || b.Status != scenario.status {
				t.Fatal("lazy projection changed managed intent or its failure state")
			}

			summaries, err := inventory.NewStore().DirectAccessSummaries(t.Context(), f.env.pool, f.connectionID)
			if err != nil || summaries[f.accountID].Bindings != 0 || summaries[f.accountID].Objects != 0 {
				t.Fatal("desired-only ACL inflated observed counters")
			}
		})
	}
}

type summarySnapshotTracer struct {
	once   sync.Once
	mutate func(context.Context) error
	errors chan error
}

func (tracer *summarySnapshotTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "count(distinct coalesce(b.scope_resource_id") {
		tracer.once.Do(func() { tracer.errors <- tracer.mutate(ctx) })
	}
	return ctx
}
func (*summarySnapshotTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func summaryEnvWithTracer(t *testing.T, source *testEnv, tracer pgx.QueryTracer) *testEnv {
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
	server, err := api.New(api.Config{Pool: pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Operations: operations.NewStore(), Audit: audit.NewWriter(), Credentials: credentials.NewService(nil, nil), Dispatcher: dispatcher, Auth: authn})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: source.codec}
}

func TestIntegrationAccountSummaryUsesOneRepeatableReadSnapshot(t *testing.T) {
	f := newObjectReadFixture(t, 1, 2, 1)
	if _, err := f.env.pool.Exec(t.Context(), `update accounts set attributes=attributes||'{"summary_epoch":"before"}'::jsonb where id=$1`, f.accountID); err != nil {
		t.Fatal(err)
	}
	tracer := &summarySnapshotTracer{errors: make(chan error, 1)}
	tracer.mutate = func(ctx context.Context) error {
		tx, err := f.env.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if _, err := tx.Exec(ctx, `update accounts set attributes=attributes||'{"summary_epoch":"after"}'::jsonb where id=$1`, f.accountID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `update bindings set observed_state='absent' where account_id=$1`, f.accountID); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	env := summaryEnvWithTracer(t, f.env, tracer)
	viewer := session(auth.RoleViewer)
	response := env.do(t, http.MethodGet, "/api/v1/connections/"+f.connectionID.String()+"/accounts?view=summary&include=bindings,provisioning", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	select {
	case err := <-tracer.errors:
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("fixture did not inject the concurrent inventory commit")
	}
	var out struct {
		Accounts []struct {
			ID         uuid.UUID      `json:"id"`
			Attributes map[string]any `json:"attributes"`
			Summary    struct {
				Bindings int `json:"direct_bindings"`
			} `json:"access_summary"`
			Bindings []struct {
				Observed string `json:"observed_state"`
			} `json:"bindings"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(readBody(t, response), &out); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range out.Accounts {
		if a.ID == f.accountID {
			found = true
			if a.Attributes["summary_epoch"] != "before" || a.Summary.Bindings != 1 || len(a.Bindings) != 1 || a.Bindings[0].Observed != "present" {
				t.Fatal("summary combined old account with new counters or role bindings")
			}
		}
	}
	if !found {
		t.Fatal("summary dropped the fixture account")
	}
	response = env.do(t, http.MethodGet, "/api/v1/connections/"+f.connectionID.String()+"/accounts?include=bindings,provisioning", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var legacy map[string]any
	if err := json.Unmarshal(readBody(t, response), &legacy); err != nil {
		t.Fatal(err)
	}
	for _, raw := range legacy["accounts"].([]any) {
		a := raw.(map[string]any)
		if a["id"] == f.accountID.String() {
			if _, exists := a["access_summary"]; exists {
				t.Fatal("legacy full response acquired summary projection")
			}
			if _, exists := a["bindings_projection"]; exists {
				t.Fatal("legacy full response lost its original full projection")
			}
			if len(a["bindings"].([]any)) != 2 || a["attributes"].(map[string]any)["summary_epoch"] != "after" {
				t.Fatal("legacy full response lost direct bindings or its new snapshot")
			}
		}
	}
}
