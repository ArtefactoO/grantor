//go:build integration

package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

func scopedReadToken(t *testing.T, env *testEnv, environment string) (string, string) {
	t.Helper()
	admin := session(auth.RoleAdmin)
	principal := createPrincipal(t, env, admin, "service")
	response := env.do(t, http.MethodPost, "/api/v1/scope-policies", map[string]any{
		"subject_kind": policy.SubjectPrincipal, "subject": principal, "environment": environment,
	}, &admin, true)
	requireStatus(t, response, http.StatusCreated)
	response = env.do(t, http.MethodPost, "/api/v1/principals/"+principal+"/tokens", map[string]string{
		"name": "scoped-read-regression",
	}, &admin, true)
	requireStatus(t, response, http.StatusCreated)
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(readBody(t, response), &issued); err != nil || issued.Token == "" {
		t.Fatalf("decode issued token: %v", err)
	}
	return issued.Token, principal
}

func scopedReadOperation(t *testing.T, env *testEnv, actor, kind string, connection, parent *uuid.UUID, status operations.Status, timestamp time.Time) operations.Operation {
	t.Helper()
	op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: kind, ConnectionID: connection, ParentID: parent, ActorType: "service", ActorID: actor,
		Payload: []byte(`{"marker":"scoped-read-fixture"}`),
	})
	if err != nil {
		t.Fatalf("create operation fixture: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(), "update operations set status = $2, created_at = $3 where id = $1", op.ID, status, timestamp); err != nil {
		t.Fatalf("set operation fixture state: %v", err)
	}
	return op
}

func TestIntegrationScopedReadOperationsFilterBeforePaginationAndCounts(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	environment := "scoped-read-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, environment)
	foreign := createDraftInEnv(t, env, "foreign-"+uuid.NewString())
	token, actor := scopedReadToken(t, env, environment)
	kind := "scoped.read." + uuid.NewString()
	base := time.Now().UTC().Truncate(time.Second)
	oldest := scopedReadOperation(t, env, actor, kind, &allowed.ID, nil, operations.StatusFailed, base)
	newer := scopedReadOperation(t, env, actor, kind, &allowed.ID, nil, operations.StatusSuccess, base.Add(time.Minute))
	ownGlobal := scopedReadOperation(t, env, actor, kind, nil, nil, operations.StatusPending, base.Add(2*time.Minute))
	allOwn := scopedReadOperation(t, env, "worker", kind, nil, nil, operations.StatusRunning, base.Add(3*time.Minute))
	scopedReadOperation(t, env, "worker", kind+".child", &allowed.ID, &allOwn.ID, operations.StatusPending, base)
	mixed := scopedReadOperation(t, env, actor, kind, &allowed.ID, nil, operations.StatusPartial, base.Add(4*time.Minute))
	child := scopedReadOperation(t, env, actor, kind+".child", &allowed.ID, &mixed.ID, operations.StatusPending, base)
	scopedReadOperation(t, env, actor, kind+".child", &foreign.ID, &child.ID, operations.StatusFailed, base)
	scopedReadOperation(t, env, "other-actor", kind, nil, nil, operations.StatusPending, base.Add(5*time.Minute))
	scopedReadOperation(t, env, actor, kind, &foreign.ID, nil, operations.StatusFailed, base.Add(6*time.Minute))
	foreignAccount, err := inventory.NewStore().CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
		ConnectionID: foreign.ID, EngineIdentity: "foreign-receipt-account",
	})
	if err != nil {
		t.Fatalf("create foreign receipt account: %v", err)
	}
	foreignReference := scopedReadOperation(t, env, actor, kind, nil, nil, operations.StatusFailed, base.Add(7*time.Minute))
	if _, err := env.pool.Exec(t.Context(), "update operations set account_id = $2 where id = $1", foreignReference.ID, foreignAccount.ID); err != nil {
		t.Fatalf("set foreign operation reference: %v", err)
	}

	want := []uuid.UUID{allOwn.ID, ownGlobal.ID, newer.ID, oldest.ID}
	for offset, id := range want {
		response := env.doBearer(t, http.MethodGet, fmt.Sprintf("/api/v1/operations?kind=%s&limit=1&offset=%d", kind, offset), nil, token)
		requireStatus(t, response, http.StatusOK)
		var page struct {
			Operations []struct {
				ID uuid.UUID `json:"id"`
			} `json:"operations"`
			Total        int64                               `json:"total"`
			StatusTotals struct{ Active, Errors, All int64 } `json:"status_totals"`
		}
		if err := json.Unmarshal(readBody(t, response), &page); err != nil {
			t.Fatalf("decode operations page: %v", err)
		}
		if len(page.Operations) != 1 || page.Operations[0].ID != id || page.Total != 4 || page.StatusTotals.Active != 2 || page.StatusTotals.Errors != 1 || page.StatusTotals.All != 4 {
			t.Fatalf("scoped page %d: %+v, want row %s and totals 4/2/1/4", offset, page, id)
		}
	}
	for _, path := range []string{
		"/api/v1/operations/" + mixed.ID.String(),
		"/api/v1/operations/" + foreignReference.ID.String(),
		"/api/v1/operations?connection_id=" + foreign.ID.String(),
		"/api/v1/audit?operation_id=" + mixed.ID.String(),
	} {
		response := env.doBearer(t, http.MethodGet, path, nil, token)
		requireStatus(t, response, http.StatusForbidden)
		if body := string(readBody(t, response)); strings.Contains(body, foreign.ID.String()) || strings.Contains(body, "scoped-read-fixture") {
			t.Fatalf("denial leaks scoped data: %s", body)
		}
	}
}

func TestIntegrationScopedReadAuditChecksCorrelatedOperationAndStandaloneActor(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	environment := "scoped-audit-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, environment)
	foreign := createDraftInEnv(t, env, "foreign-"+uuid.NewString())
	token, actor := scopedReadToken(t, env, environment)
	action := "scoped.audit." + uuid.NewString()
	base := time.Now().UTC().Truncate(time.Second)
	mixed := scopedReadOperation(t, env, actor, action, &allowed.ID, nil, operations.StatusPartial, base)
	scopedReadOperation(t, env, actor, action+".child", &foreign.ID, &mixed.ID, operations.StatusFailed, base)
	own := scopedReadOperation(t, env, "worker", action, nil, nil, operations.StatusSuccess, base)
	scopedReadOperation(t, env, "worker", action+".child", &allowed.ID, &own.ID, operations.StatusSuccess, base)
	seed := []struct {
		actor                 string
		connection, operation *uuid.UUID
		visible               bool
	}{
		{actor, &allowed.ID, nil, true},
		{"worker", nil, &own.ID, true},
		{actor, nil, nil, true},
		{"other-actor", nil, nil, false},
		{actor, &foreign.ID, nil, false},
		{actor, &allowed.ID, &mixed.ID, false},
	}
	var expected []int64
	for i, item := range seed {
		var id int64
		if err := env.pool.QueryRow(t.Context(), `insert into audit_events
			(occurred_at, actor_type, actor_id, action, connection_id, operation_id, result)
			values ($1, 'service', $2, $3, $4, $5, $6) returning id`,
			base.Add(time.Duration(i)*time.Minute), item.actor, action, item.connection, item.operation, audit.ResultSuccess).Scan(&id); err != nil {
			t.Fatalf("seed audit fixture: %v", err)
		}
		if item.visible {
			expected = append([]int64{id}, expected...)
		}
	}
	for offset, id := range expected {
		response := env.doBearer(t, http.MethodGet, fmt.Sprintf("/api/v1/audit?action=%s&limit=1&offset=%d", action, offset), nil, token)
		requireStatus(t, response, http.StatusOK)
		var page struct {
			Events []struct {
				ID int64 `json:"id"`
			} `json:"events"`
			Total int64 `json:"total"`
		}
		if err := json.Unmarshal(readBody(t, response), &page); err != nil {
			t.Fatalf("decode audit: %v", err)
		}
		if page.Total != 3 || len(page.Events) != 1 || page.Events[0].ID != id {
			t.Fatalf("audit page %d: %+v, want row %d total 3", offset, page, id)
		}
	}
}

func TestIntegrationScopedReadInventoryPrincipalAndDriftDoNotRevealForeignAccounts(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	environment := "scoped-inventory-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, environment)
	foreign := createDraftInEnv(t, env, "foreign-"+uuid.NewString())
	token, actor := scopedReadToken(t, env, environment)
	principalID := uuid.MustParse(actor)
	store := inventory.NewStore()
	create := func(connection uuid.UUID, identity string) inventory.Account {
		t.Helper()
		account, err := store.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
			ConnectionID: connection, EngineIdentity: identity, PrincipalID: &principalID,
		})
		if err != nil {
			t.Fatalf("create account fixture: %v", err)
		}
		return account
	}
	ownAccount := create(allowed.ID, "own-visible-account")
	foreignAccount := create(foreign.ID, "foreign-hidden-account")
	var foreignResource uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `insert into resources (connection_id, kind, external_id, name, canonical_path)
		values ($1, 'database', 'foreign-db', 'foreign-hidden-resource', 'foreign-db') returning id`, foreign.ID).Scan(&foreignResource); err != nil {
		t.Fatalf("create resource fixture: %v", err)
	}
	var foreignPermission, foreignBinding uuid.UUID
	if err := env.pool.QueryRow(t.Context(), `insert into permission_definitions (connection_id, engine, external_id, name, scope_resource_id)
		values ($1, 'fake', 'foreign-role', 'foreign-hidden-permission', $2) returning id`, foreign.ID, foreignResource).Scan(&foreignPermission); err != nil {
		t.Fatalf("create permission fixture: %v", err)
	}
	if err := env.pool.QueryRow(t.Context(), `insert into bindings (account_id, permission_definition_id, scope_resource_id, source, observed_state, status)
		values ($1, $2, $3, 'external', 'present', 'synced') returning id`, foreignAccount.ID, foreignPermission, foreignResource).Scan(&foreignBinding); err != nil {
		t.Fatalf("create binding fixture: %v", err)
	}
	for _, path := range []string{
		"/api/v1/accounts/" + foreignAccount.ID.String() + "/bindings",
		"/api/v1/resources/" + foreignResource.String() + "/bindings",
	} {
		response := env.doBearer(t, http.MethodGet, path, nil, token)
		requireStatus(t, response, http.StatusForbidden)
		if body := string(readBody(t, response)); strings.Contains(body, foreignPermission.String()) || strings.Contains(body, foreignBinding.String()) {
			t.Fatalf("forbidden binding read exposes foreign identity: %s", body)
		}
	}
	response := env.doBearer(t, http.MethodPost, "/api/v1/bindings/"+foreignBinding.String()+"/adopt", nil, token)
	requireStatus(t, response, http.StatusForbidden)
	var desired *string
	if err := env.pool.QueryRow(t.Context(), "select desired_state from bindings where id = $1", foreignBinding).Scan(&desired); err != nil || desired != nil {
		t.Fatalf("foreign binding changed despite denial: desired=%v, err=%v", desired, err)
	}
	response = env.doBearer(t, http.MethodGet, "/api/v1/accounts/"+ownAccount.ID.String()+"/bindings", nil, token)
	requireStatus(t, response, http.StatusOK)
	response = env.doBearer(t, http.MethodGet, "/api/v1/principals/"+actor, nil, token)
	requireStatus(t, response, http.StatusOK)
	body := readBody(t, response)
	if strings.Contains(string(body), "foreign-hidden-account") || strings.Contains(string(body), foreign.ID.String()) {
		t.Fatalf("principal detail exposes foreign account: %s", body)
	}
	var detail struct {
		Accounts []struct {
			ID uuid.UUID `json:"id"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &detail); err != nil || len(detail.Accounts) != 1 || detail.Accounts[0].ID != ownAccount.ID {
		t.Fatalf("principal detail: %+v, %v", detail, err)
	}
	response = env.doBearer(t, http.MethodGet, "/api/v1/principals?limit=1000", nil, token)
	requireStatus(t, response, http.StatusOK)
	var principals struct {
		Principals []struct {
			ID            uuid.UUID `json:"id"`
			AccountsCount int       `json:"accounts_count"`
		} `json:"principals"`
	}
	if err := json.Unmarshal(readBody(t, response), &principals); err != nil {
		t.Fatalf("decode principals: %v", err)
	}
	found := false
	for _, principal := range principals.Principals {
		if principal.ID == principalID {
			found = true
			if principal.AccountsCount != 1 {
				t.Fatalf("foreign accounts included in count: %d", principal.AccountsCount)
			}
		}
	}
	if !found {
		t.Fatal("principal absent from directory")
	}
	if _, err := env.pool.Exec(t.Context(), "update accounts set status = 'missing' where id = any($1::uuid[])", []uuid.UUID{ownAccount.ID, foreignAccount.ID}); err != nil {
		t.Fatalf("mark missing accounts: %v", err)
	}
	if _, err := store.CreateDriftBaseline(t.Context(), env.pool, inventory.DriftBaseline{
		Kind: inventory.DriftKindMissingAccount, RefID: foreignAccount.ID, ConnectionID: foreign.ID, CreatedBy: "foreign-operator", Reason: "foreign-baseline-detail",
	}); err != nil {
		t.Fatalf("create foreign baseline: %v", err)
	}
	response = env.doBearer(t, http.MethodGet, "/api/v1/drift", nil, token)
	requireStatus(t, response, http.StatusOK)
	body = readBody(t, response)
	if strings.Contains(string(body), foreign.ID.String()) || strings.Contains(string(body), "foreign-hidden-account") || strings.Contains(string(body), "foreign-baseline-detail") {
		t.Fatalf("global drift leaks foreign finding: %s", body)
	}
	if !strings.Contains(string(body), ownAccount.ID.String()) {
		t.Fatal("global drift omits own missing account")
	}
}
