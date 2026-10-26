//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
)

type objectReadFixture struct {
	env                     *testEnv
	connectionID, accountID uuid.UUID
	scopes                  []uuid.UUID
}

func newObjectReadFixture(t *testing.T, tables, accounts, grants int) objectReadFixture {
	t.Helper()
	env := newTestEnv(t, nil)
	ctx := t.Context()
	c, err := connections.NewStore().Create(ctx, env.pool, connections.CreateParams{DisplayName: "read-fixture-" + uuid.NewString(), Engine: postgres.Engine, Environment: "itest"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := env.pool.Exec(cleanupCtx, `delete from bindings where account_id in(select id from accounts where connection_id=$1)`, c.ID); err != nil {
			t.Errorf("clean object fixture bindings: %v", err)
			return
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from connections where id=$1`, c.ID); err != nil {
			t.Errorf("clean object fixture: %v", err)
		}
	})
	scopes := make([]uuid.UUID, tables)
	resourceRows := [][]any{}
	for i := range tables {
		id := uuid.New()
		scopes[i] = id
		name := fmt.Sprintf("items_%05d", i)
		resourceRows = append(resourceRows, []any{id, c.ID, "table", "table:app.public." + name, name, "app.public." + name, []byte(`{"owner":"owner","public_privileges":["SELECT"]}`), "fixture"})
	}
	if _, err = env.pool.CopyFrom(ctx, pgx.Identifier{"resources"}, []string{"id", "connection_id", "kind", "external_id", "name", "canonical_path", "attributes", "fingerprint"}, pgx.CopyFromRows(resourceRows)); err != nil {
		t.Fatal(err)
	}
	accountIDs := make([]uuid.UUID, accounts)
	accountRows := [][]any{}
	for i := range accounts {
		accountIDs[i] = uuid.New()
		name := fmt.Sprintf("reader_%03d", i)
		kind := "login"
		if i == accounts-1 {
			name = "readers"
			kind = "group"
		}
		accountRows = append(accountRows, []any{accountIDs[i], c.ID, kind, name, "active", "unmanaged", []byte(`{"can_login":true}`)})
	}
	if _, err = env.pool.CopyFrom(ctx, pgx.Identifier{"accounts"}, []string{"id", "connection_id", "kind", "engine_identity", "status", "ownership", "attributes"}, pgx.CopyFromRows(accountRows)); err != nil {
		t.Fatal(err)
	}
	permissionIDs := make([]uuid.UUID, tables*3)
	permissionRows := [][]any{}
	roleID := uuid.New()
	permissionRows = append(permissionRows, []any{roleID, c.ID, postgres.Engine, "role:readers", "readers", nil, true, false, []byte(`{}`), "observed"})
	for i := range tables {
		name := fmt.Sprintf("items_%05d", i)
		for actionIndex, action := range []string{"SELECT", "UPDATE", "TRUNCATE"} {
			id := uuid.New()
			permissionIDs[i*3+actionIndex] = id
			p := adapter.PostgresObjectPrivilege{TargetIdentity: "postgres:system:42", Database: "app", DatabaseOID: 10, Kind: "table", Schema: "public", SchemaOID: 11, Name: name, ObjectOID: uint32(100 + i), OwnerOID: 13, Privilege: action}
			attrs, _ := json.Marshal(map[string]any{"kind": "postgres_object_privilege", "object_kind": "table", "column": "", "database": "app", "privilege": action})
			permissionRows = append(permissionRows, []any{id, c.ID, postgres.Engine, p.PermissionID(), action + " ON " + p.Label(), scopes[i], true, action == "TRUNCATE", attrs, "observed"})
		}
	}
	if _, err = env.pool.CopyFrom(ctx, pgx.Identifier{"permission_definitions"}, []string{"id", "connection_id", "engine", "external_id", "name", "scope_resource_id", "assignable", "dangerous", "attributes", "status"}, pgx.CopyFromRows(permissionRows)); err != nil {
		t.Fatal(err)
	}
	bindingRows := [][]any{}
	for i := range accounts - 1 {
		bindingRows = append(bindingRows, []any{accountIDs[i], roleID, nil, "external", "present", true, "observed", []byte(`{}`)})
	}
	for i := range grants {
		p := i % len(permissionIDs)
		a := i % accounts
		bindingRows = append(bindingRows, []any{accountIDs[a], permissionIDs[p], scopes[p/3], "external", "present", true, "observed", []byte(`{"direct_privilege":true,"grantors":[{"oid":13,"name":"owner","grant_option":false}]}`)})
	}
	if _, err = env.pool.CopyFrom(ctx, pgx.Identifier{"bindings"}, []string{"account_id", "permission_definition_id", "scope_resource_id", "source", "observed_state", "observed_effective", "status", "observed_attributes"}, pgx.CopyFromRows(bindingRows)); err != nil {
		t.Fatal(err)
	}
	_, err = env.pool.Exec(ctx, `update connections set status='active',last_discovery_at=now(),topology='{"system_identifier":"42","postgres_object_acl_version":1,"hba_rules":[{"placeholder":"bounded projection test"}],"postgres_default_privileges":[]}'::jsonb where id=$1`, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	return objectReadFixture{env: env, connectionID: c.ID, accountID: accountIDs[0], scopes: scopes}
}

func TestIntegrationBoundedObjectPagesAndLegacyReads(t *testing.T) {
	f := newObjectReadFixture(t, 25, 7, 100)
	viewer := session(auth.RoleViewer)
	env := f.env
	base := "/api/v1/connections/" + f.connectionID.String()
	account := "/api/v1/accounts/" + f.accountID.String()
	response := env.do(t, http.MethodGet, base+"/accounts?include=bindings", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var full struct {
		Accounts []struct {
			Bindings []struct {
				Observed map[string]any `json:"observed_attributes"`
			} `json:"bindings"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(readBody(t, response), &full); err != nil {
		t.Fatal(err)
	}
	fullDirect := 0
	for _, a := range full.Accounts {
		for _, b := range a.Bindings {
			if b.Observed["direct_privilege"] == true {
				fullDirect++
			}
		}
	}
	if fullDirect != 100 {
		t.Fatal("legacy full binding response lost direct grants")
	}
	response = env.do(t, http.MethodGet, base+"/accounts?view=summary&include=bindings,provisioning", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var compact struct {
		Accounts []struct {
			Projection string `json:"bindings_projection"`
			Summary    struct {
				Count int `json:"direct_bindings"`
			} `json:"access_summary"`
			Bindings []struct {
				Observed map[string]any `json:"observed_attributes"`
			} `json:"bindings"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(readBody(t, response), &compact); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range compact.Accounts {
		count += a.Summary.Count
		if a.Projection != "roles" {
			t.Fatal("summary did not declare role projection")
		}
		for _, b := range a.Bindings {
			if b.Observed["direct_privilege"] == true {
				t.Fatal("direct ACL escaped the compact list")
			}
		}
	}
	if count != 100 {
		t.Fatal("summary lost direct grants")
	}
	response = env.do(t, http.MethodGet, base+"/permissions?category=roles", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var catalog struct {
		Permissions []map[string]any `json:"permissions"`
	}
	if err := json.Unmarshal(readBody(t, response), &catalog); err != nil || len(catalog.Permissions) != 1 {
		t.Fatalf("role catalog grew with ACL: %d %v", len(catalog.Permissions), err)
	}
	var page struct {
		Objects []struct {
			Scope       uuid.UUID        `json:"scope_id"`
			Permissions []map[string]any `json:"permissions"`
			Bindings    []struct {
				ID uuid.UUID `json:"id"`
			} `json:"bindings"`
		} `json:"objects"`
		Next     string `json:"next_cursor"`
		Snapshot string `json:"snapshot_version"`
	}
	response = env.do(t, http.MethodGet, account+"/object-privileges?limit=2", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	if err := json.Unmarshal(readBody(t, response), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Objects) != 2 || len(page.Objects[0].Permissions) != 3 || page.Next == "" {
		t.Fatalf("unbounded/missing page: %+v", page)
	}
	response = env.do(t, http.MethodGet, account+"/object-privileges?limit=2&cursor="+url.QueryEscape(page.Next), nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var second struct {
		Objects []struct {
			Scope uuid.UUID `json:"scope_id"`
		} `json:"objects"`
	}
	if err := json.Unmarshal(readBody(t, response), &second); err != nil {
		t.Fatal(err)
	}
	for _, a := range page.Objects {
		for _, b := range second.Objects {
			if a.Scope == b.Scope {
				t.Fatal("pagination repeated a scope")
			}
		}
	}
	response = env.do(t, http.MethodGet, account+"/object-privileges?limit=999999", nil, &viewer, false)
	requireStatus(t, response, http.StatusBadRequest)
	response = env.do(t, http.MethodGet, account+"/object-privileges?cursor="+url.QueryEscape(page.Next)+"&q=different", nil, &viewer, false)
	requireStatus(t, response, http.StatusBadRequest)
	if _, err := env.pool.Exec(t.Context(), `update bindings set updated_at=updated_at+interval '1 second' where id=$1`, page.Objects[0].Bindings[0].ID); err != nil {
		t.Fatal(err)
	}
	response = env.do(t, http.MethodGet, account+"/object-privileges?cursor="+url.QueryEscape(page.Next), nil, &viewer, false)
	requireStatus(t, response, http.StatusConflict)
	other := newObjectReadFixture(t, 1, 2, 1)
	response = env.do(t, http.MethodGet, account+"/object-privileges?scope_resource_id="+other.scopes[0].String(), nil, &viewer, false)
	requireStatus(t, response, http.StatusNotFound)
	response = env.do(t, http.MethodGet, base+"/object-privilege-targets?q=items_00024&limit=2", nil, &viewer, false)
	requireStatus(t, response, http.StatusOK)
	var targets struct {
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal(readBody(t, response), &targets); err != nil || len(targets.Objects) != 1 {
		t.Fatalf("target search: %d %v", len(targets.Objects), err)
	}
}

func TestIntegrationLargeInventorySummaryPayloadRemainsBounded(t *testing.T) {
	f := newObjectReadFixture(t, 8100, 267, 105485)
	viewer := session(auth.RoleViewer)
	start := time.Now()
	r := f.env.do(t, http.MethodGet, "/api/v1/connections/"+f.connectionID.String()+"/accounts?view=summary&include=bindings,provisioning", nil, &viewer, false)
	requireStatus(t, r, http.StatusOK)
	body := readBody(t, r)
	elapsed := time.Since(start)
	if len(body) > 1<<20 {
		t.Fatalf("initial account summary is too large: %d bytes", len(body))
	}
	var rows struct {
		Accounts []struct {
			Summary struct {
				Bindings int `json:"direct_bindings"`
			} `json:"access_summary"`
			Bindings []json.RawMessage `json:"bindings"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatal(err)
	}
	grants := 0
	roles := 0
	for _, a := range rows.Accounts {
		grants += a.Summary.Bindings
		roles += len(a.Bindings)
	}
	if len(rows.Accounts) != 267 || grants != 105485 || roles != 266 {
		t.Fatalf("large summary: accounts=%d grants=%d role_bindings=%d", len(rows.Accounts), grants, roles)
	}
	t.Logf("large inventory: 24301 definitions, 105485 direct bindings; compact HTTP %d bytes in %s", len(body), elapsed)
}
