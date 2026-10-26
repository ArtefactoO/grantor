//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

type hbaReadTracer struct {
	mu      sync.Mutex
	queries []pgx.TraceQueryStartData
}

func (tracer *hbaReadTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(data.SQL)), "select") {
		tracer.mu.Lock()
		tracer.queries = append(tracer.queries, data)
		tracer.mu.Unlock()
	}
	return ctx
}
func (*hbaReadTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func (tracer *hbaReadTracer) snapshot() []pgx.TraceQueryStartData {
	tracer.mu.Lock()
	defer tracer.mu.Unlock()
	return append([]pgx.TraceQueryStartData(nil), tracer.queries...)
}

func TestIntegrationHBAReadsOnlyRolesWithConstantQueryCount(t *testing.T) {
	counts := []int{}
	for _, accounts := range []int{8, 153} {
		f := newObjectReadFixture(t, 100, accounts, accounts*40)
		if _, err := f.env.pool.Exec(t.Context(), `update connections set topology=jsonb_set(topology,'{hba_rules}','[{"number":1,"type":"host","databases":["all"],"users":["reader_000","+readers"],"address":"10.0.0.0","netmask":"255.0.0.0","auth_method":"scram-sha-256","options":[],"error":""}]') where id=$1`, f.connectionID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.env.pool.Exec(t.Context(), `update bindings b set observed_state='absent' from accounts a where a.id=b.account_id and a.connection_id=$1 and a.engine_identity in('reader_000','reader_001','reader_002','reader_004','reader_005') and b.scope_resource_id is null`, f.connectionID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.env.pool.Exec(t.Context(), `update accounts set status=case engine_identity when 'reader_001' then 'deleted' when 'reader_002' then 'missing' when 'reader_003' then 'disabled' else status end,kind=case when engine_identity='reader_004' then 'group' else kind end where connection_id=$1`, f.connectionID); err != nil {
			t.Fatal(err)
		}
		tracer := &hbaReadTracer{}
		env := summaryEnvWithTracer(t, f.env, tracer)
		viewer := session(auth.RoleViewer)
		response := env.do(t, http.MethodGet, "/api/v1/connections/"+f.connectionID.String()+"/hba", nil, &viewer, false)
		requireStatus(t, response, http.StatusOK)
		var result struct {
			Supported  bool     `json:"supported"`
			Customized bool     `json:"customized"`
			Uncovered  []string `json:"uncovered_accounts"`
		}
		if err := json.Unmarshal(readBody(t, response), &result); err != nil {
			t.Fatal(err)
		}
		if !result.Supported || !result.Customized || len(result.Uncovered) != 1 || result.Uncovered[0] != "reader_005" {
			t.Fatalf("role coverage changed with object ACL inventory: %+v", result)
		}
		queries := tracer.snapshot()
		counts = append(counts, len(queries))
		t.Logf("fixture accounts=%d object ACL bindings=%d HBA SELECTs=%d", accounts, accounts*40, len(queries))
		if len(queries) > 6 {
			t.Fatalf("HBA query count grows with LOGIN accounts: %d", len(queries))
		}
		for _, query := range queries {
			if strings.Contains(query.SQL, "from bindings where account_id") {
				t.Fatal("per-account binding read returned")
			}
			if strings.Contains(query.SQL, "from permission_definitions") && !strings.Contains(query.SQL, "not(engine='postgres' and external_id like 'pgacl:v1:%')") {
				t.Fatal("HBA loads object privilege definitions")
			}
		}
		deniedEnv := buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementEnforce})
		operator := session(auth.RoleOperator)
		requireStatus(t, deniedEnv.do(t, http.MethodGet, "/api/v1/connections/"+f.connectionID.String()+"/hba", nil, &operator, false), http.StatusForbidden)
	}
	if counts[0] != counts[1] {
		t.Fatalf("HBA is no longer a bounded read: %v", counts)
	}
}
