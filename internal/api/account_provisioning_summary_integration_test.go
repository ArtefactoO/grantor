//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func creationSummary(t *testing.T, env *testEnv, connectionID, accountID uuid.UUID, include string) map[string]json.RawMessage {
	t.Helper()
	viewer := session(auth.RoleViewer)
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+connectionID.String()+"/accounts"+include, nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var body struct {
		Accounts []struct {
			ID      uuid.UUID                  `json:"id"`
			Summary map[string]json.RawMessage `json:"provisioning_summary"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(readBody(t, resp), &body); err != nil {
		t.Fatal(err)
	}
	for _, acct := range body.Accounts {
		if acct.ID == accountID {
			return acct.Summary
		}
	}
	t.Fatal("account missing from its connection inventory")
	return nil
}

func TestIntegrationAccountProvisioningListSummary(t *testing.T) {
	env := newTestEnv(t, nil)
	for _, tc := range []struct {
		name, change, want string
		confirmed          bool
	}{
		{name: "confirmed role needs verification", confirmed: true, want: "verification_required"},
		{name: "lost create acknowledgement", want: "unknown"},
		{name: "automatic retry remains work", confirmed: true, change: "scheduled", want: "running"},
		{name: "queued predecessor remains work", confirmed: true, change: "predecessor", want: "running"},
		{name: "failed preflight", change: "planned", want: "failed"},
		{name: "older lifecycle cannot describe new account", confirmed: true, change: "stale", want: "unknown"},
		{name: "foreign connection operation excluded", confirmed: true, change: "foreign", want: "unknown"},
		{name: "active account has no creation summary", confirmed: true, change: "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acct, source := confirmedAccountCreationFixture(t, env, tc.confirmed)
			var err error
			switch tc.change {
			case "scheduled":
				_, err = env.pool.Exec(t.Context(), `insert into river_job(kind,args,state,max_attempts,attempt)
					values ('operation.execute',jsonb_build_object('operation_id',$1::text),'scheduled',5,1)`, source.ID)
			case "predecessor":
				_, err = env.pool.Exec(t.Context(), `insert into river_job(kind,args,state,max_attempts,attempt)
					values ('operation.execute',jsonb_build_object('operation_id',$1::text,
					'next_operation_ids',jsonb_build_array($2::text)),'available',5,0)`, uuid.New(), source.ID)
			case "planned":
				_, err = env.pool.Exec(t.Context(), `update account_creation_receipts set phase='planned',role_oid=0 where operation_id=$1`, source.ID)
			case "stale":
				_, err = env.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, acct.ID)
			case "foreign":
				foreign := activeFakeConnection(t, env.pool)
				_, err = env.pool.Exec(t.Context(), `update operations set connection_id=$2 where id=$1`, source.ID, foreign.ID)
			case "active":
				_, err = env.pool.Exec(t.Context(), `update accounts set status='active' where id=$1`, acct.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := creationSummary(t, env, acct.ConnectionID, acct.ID, "?include=bindings"); got != nil {
				t.Fatal("creation projection unexpectedly included without opt-in")
			}
			got := creationSummary(t, env, acct.ConnectionID, acct.ID, "?include=bindings,provisioning")
			if tc.want == "" {
				if got != nil {
					t.Fatal("active account retains creation status")
				}
				return
			}
			var state string
			if err := json.Unmarshal(got["state"], &state); err != nil || state != tc.want {
				t.Fatalf("creation state = %s, want %s: %v", state, tc.want, err)
			}
			for key := range got {
				if key != "state" && key != "operation_id" && key != "operation_status" {
					t.Fatalf("creation projection exposes internal field %s", key)
				}
			}
			if (tc.change == "stale" || tc.change == "foreign") && got["operation_id"] != nil {
				t.Fatal("stale or foreign operation presented as current creation")
			}
		})
	}
}

func TestIntegrationAccountProvisioningListSummaryScope(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	acct, _ := confirmedAccountCreationFixture(t, env, true)
	environment := "creation-summary-" + uuid.NewString()
	if _, err := env.pool.Exec(t.Context(), `update connections set environment=$2 where id=$1`, acct.ConnectionID, environment); err != nil {
		t.Fatal(err)
	}
	operator := session(auth.RoleOperator)
	path := "/api/v1/connections/" + acct.ConnectionID.String() + "/accounts?include=provisioning"
	resp := env.do(t, http.MethodGet, path, nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)
	admin := session(auth.RoleAdmin)
	createRolePolicy(t, env, admin, environment)
	resp = env.do(t, http.MethodGet, path, nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
}
