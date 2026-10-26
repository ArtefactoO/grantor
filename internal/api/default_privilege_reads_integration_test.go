//go:build integration

package api_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/auth"
)

type defaultPrivilegePageResult struct {
	Rules     []map[string]any `json:"rules"`
	Total     *int             `json:"total_entries"`
	Next      string           `json:"next_cursor"`
	Snapshot  string           `json:"snapshot_version"`
	Available bool             `json:"available"`
	Inventory json.RawMessage  `json:"inventory"`
}

func seedDefaultPrivilegeReadRules(t *testing.T, env *testEnv, connectionID uuid.UUID, count int) uuid.UUID {
	t.Helper()
	rules := make([]map[string]any, 0, count+2)
	for i := range count {
		rules = append(rules, map[string]any{"database": "app", "creator": fmt.Sprintf("creator_%04d", i), "schema": "public", "kind": "r", "grantee": "app_owner", "privilege": "SELECT", "grant_option": false})
	}
	for _, grantee := range []string{"PUBLIC", "readers"} {
		rules = append(rules, map[string]any{"database": "app", "creator": "other_creator", "schema": "public", "kind": "r", "grantee": grantee, "privilege": "SELECT", "grant_option": false})
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set topology=jsonb_set(jsonb_set(topology,'{postgres_object_acl_version}','1'),'{postgres_default_privileges}',$2::jsonb) where id=$1`, connectionID, raw); err != nil {
		t.Fatal(err)
	}
	var accountID uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `select id from accounts where connection_id=$1 and engine_identity='app_owner'`, connectionID).Scan(&accountID); err != nil {
		t.Fatal(err)
	}
	return accountID
}

func readDefaultPrivilegePage(t *testing.T, response *http.Response) defaultPrivilegePageResult {
	t.Helper()
	requireStatus(t, response, http.StatusOK)
	raw := readBody(t, response)
	if len(raw) > 32<<10 {
		t.Fatalf("bounded default ACL page is too large: %d bytes", len(raw))
	}
	var result defaultPrivilegePageResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIntegrationDefaultPrivilegesAreBoundedSearchableAndDirect(t *testing.T) {
	env, _, issuer := newPersonalAPIKeyEnv(t)
	conn, _ := seedPostgresProfilesConnection(t, env)
	accountID := seedDefaultPrivilegeReadRules(t, env, conn.ID, 5000)
	token := issueProfilesPersonalKey(t, env, issuer, auth.RoleAdmin, []string{"itest"})
	path := "/api/v1/accounts/" + accountID.String() + "/default-privileges"
	first := readDefaultPrivilegePage(t, env.doBearer(t, http.MethodGet, path+"?limit=8", nil, token))
	if !first.Available || first.Total == nil || *first.Total != 5000 || len(first.Rules) != 8 || first.Next == "" || first.Snapshot == "" || len(first.Inventory) == 0 {
		t.Fatalf("first default ACL page = %+v", first)
	}
	seen := map[string]bool{}
	for _, page := range []defaultPrivilegePageResult{first, readDefaultPrivilegePage(t, env.doBearer(t, http.MethodGet, path+"?limit=8&cursor="+url.QueryEscape(first.Next), nil, token))} {
		if len(page.Rules) != 8 || page.Total == nil || *page.Total != 5000 {
			t.Fatalf("unbounded or incomplete page: %+v", page)
		}
		for _, rule := range page.Rules {
			creator, _ := rule["creator"].(string)
			if seen[creator] || rule["grantee"] != "app_owner" {
				t.Fatalf("duplicate or inherited/PUBLIC rule: %+v", rule)
			}
			seen[creator] = true
		}
	}
	one := readDefaultPrivilegePage(t, env.doBearer(t, http.MethodGet, path+"?limit=1", nil, token))
	if len(one.Rules) != 1 || one.Total == nil || *one.Total != 5000 {
		t.Fatalf("limit=1 response = %+v", one)
	}
	searched := readDefaultPrivilegePage(t, env.doBearer(t, http.MethodGet, path+"?q=CREATOR_4999&limit=8", nil, token))
	if len(searched.Rules) != 1 || searched.Total == nil || *searched.Total != 1 || searched.Rules[0]["creator"] != "creator_4999" || searched.Next != "" {
		t.Fatalf("server-side search = %+v", searched)
	}
	denied := issueProfilesPersonalKey(t, env, issuer, auth.RoleAdmin, []string{"other-environment"})
	requireStatus(t, env.doBearer(t, http.MethodGet, path, nil, denied), http.StatusForbidden)
	for _, query := range []string{"limit=0", "limit=51", "limit=1000000", "q=" + strings.Repeat("a", 257), "cursor=!!", "cursor=" + strings.Repeat("A", 2049)} {
		requireStatus(t, env.doBearer(t, http.MethodGet, path+"?"+query, nil, token), http.StatusBadRequest)
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, path+"?q=other&cursor="+url.QueryEscape(first.Next), nil, token), http.StatusBadRequest)
	var otherAccount uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `select id from accounts where connection_id=$1 and engine_identity='r_reports'`, conn.ID).Scan(&otherAccount); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/accounts/"+otherAccount.String()+"/default-privileges?cursor="+url.QueryEscape(first.Next), nil, token), http.StatusBadRequest)
	otherConnection, _ := seedPostgresProfilesConnection(t, env)
	foreignAccount := seedDefaultPrivilegeReadRules(t, env, otherConnection.ID, 1)
	requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/accounts/"+foreignAccount.String()+"/default-privileges?cursor="+url.QueryEscape(first.Next), nil, token), http.StatusBadRequest)
	decoded, err := base64.RawURLEncoding.DecodeString(first.Next)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		string(decoded) + " {}",
		strings.TrimSuffix(string(decoded), "}") + `,"unexpected":true}`,
		strings.Replace(string(decoded), `"purpose":"defaults"`, `"purpose":"objects"`, 1),
	} {
		requireStatus(t, env.doBearer(t, http.MethodGet, path+"?cursor="+url.QueryEscape(base64.RawURLEncoding.EncodeToString([]byte(invalid))), nil, token), http.StatusBadRequest)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set last_discovery_at=last_discovery_at+interval '1 second' where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.doBearer(t, http.MethodGet, path+"?cursor="+url.QueryEscape(first.Next), nil, token), http.StatusConflict)
}

func TestIntegrationDefaultPrivilegesDistinguishUnknownFromObservedEmpty(t *testing.T) {
	env := newTestEnv(t, nil)
	conn, _ := seedPostgresProfilesConnection(t, env)
	accountID := seedDefaultPrivilegeReadRules(t, env, conn.ID, 0)
	path := "/api/v1/accounts/" + accountID.String() + "/default-privileges"
	viewer := session(auth.RoleViewer)
	for _, tc := range []struct {
		name      string
		topology  string
		available bool
	}{
		{"empty observed", `{"postgres_object_acl_version":1,"postgres_default_privileges":[]}`, true},
		{"no marker", `{"postgres_default_privileges":[]}`, false},
		{"no defaults", `{"postgres_object_acl_version":1}`, false},
		{"null defaults", `{"postgres_object_acl_version":1,"postgres_default_privileges":null}`, false},
		{"malformed array", `{"postgres_object_acl_version":1,"postgres_default_privileges":{}}`, false},
		{"malformed row", `{"postgres_object_acl_version":1,"postgres_default_privileges":[{"grantee":"app_owner"}]}`, false},
		{"malformed marker", `{"postgres_object_acl_version":"1","postgres_default_privileges":[]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := env.pool.Exec(t.Context(), `update connections set topology=$2::jsonb where id=$1`, conn.ID, tc.topology); err != nil {
				t.Fatal(err)
			}
			page := readDefaultPrivilegePage(t, env.do(t, http.MethodGet, path, nil, &viewer, false))
			if page.Available != tc.available || len(page.Rules) != 0 || page.Next != "" || (page.Total != nil) != tc.available {
				t.Fatalf("availability = %+v", page)
			}
			if page.Total != nil && *page.Total != 0 {
				t.Fatal("empty snapshot has nonzero total")
			}
		})
	}
}
