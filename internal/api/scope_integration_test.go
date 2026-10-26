//go:build integration

// Integration-тесты enforcement scope policies API v1. Разделяют хелперы с
// api_integration_test.go (newScopeTestEnv, session, do, ...).
//
// Замечание про общую тестовую базу: политики роли 'operator' глобальны и
// накапливаются между прогонами. Поэтому тесты используют УНИКАЛЬНЫЕ окружения
// на прогон и проверяют доступ к конкретным connections (allowed/denied), а не
// точный размер списка: connection в неразрешённом уникальном окружении не
// подхватывается чужими политиками.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

// createDraftInEnv создаёт draft-connection в заданном окружении напрямую
// через store (scope-тестам не нужны Vault/admin credential).
func createDraftInEnv(t *testing.T, env *testEnv, environment string) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(context.Background(), env.pool, connections.CreateParams{
		DisplayName: "itest-scope-" + uuid.NewString(),
		Engine:      fake.Engine,
		Environment: environment,
		Endpoints:   []string{"itest-target:5432"},
	})
	if err != nil {
		t.Fatalf("create draft connection in %q: %v", environment, err)
	}
	return conn
}

// listConnectionIDs возвращает id connections из ответа списка.
func listConnectionIDs(t *testing.T, env *testEnv, sess auth.Session) map[string]bool {
	t.Helper()
	resp := env.do(t, http.MethodGet, "/api/v1/connections", nil, &sess, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Connections []connectionBody `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	ids := make(map[string]bool, len(list.Connections))
	for _, c := range list.Connections {
		ids[c.ID] = true
	}
	return ids
}

// createRolePolicy заводит role-политику operator→environment через admin API.
func createRolePolicy(t *testing.T, env *testEnv, admin auth.Session, environment string) {
	t.Helper()
	body := map[string]any{
		"subject_kind": policy.SubjectRole,
		"subject":      string(auth.RoleOperator),
		"environment":  environment,
	}
	resp := env.do(t, http.MethodPost, "/api/v1/scope-policies", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
}

func TestIntegrationScopeEnforceOperator(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	envAllowed := "scope-allow-" + uuid.NewString()
	envDenied := "scope-deny-" + uuid.NewString()
	allowed := createDraftInEnv(t, env, envAllowed)
	denied := createDraftInEnv(t, env, envDenied)

	// До заведения политики operator не видит ни одного из них (deny-by-default).
	if ids := listConnectionIDs(t, env, operator); ids[allowed.ID.String()] {
		t.Errorf("operator without policy sees connection %s in allowed env", allowed.ID)
	}
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+allowed.ID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// Заводим политику на окружение allowed.
	createRolePolicy(t, env, admin, envAllowed)

	// Теперь operator видит allowed, но не denied.
	ids := listConnectionIDs(t, env, operator)
	if !ids[allowed.ID.String()] {
		t.Errorf("operator does not see allowed connection %s after policy", allowed.ID)
	}
	if ids[denied.ID.String()] {
		t.Errorf("operator sees denied connection %s (env without policy)", denied.ID)
	}
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+allowed.ID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+denied.ID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// Мутация (refresh) чужого окружения тоже 403.
	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+denied.ID.String()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	// Вложенный инвентарь denied — 403.
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+denied.ID.String()+"/resources", nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// admin видит всё (scope не ограничивает).
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+denied.ID.String(), nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)

	// viewer read-only и не ограничивается scope: видит denied.
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+denied.ID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	if ids := listConnectionIDs(t, env, viewer); !ids[denied.ID.String()] {
		t.Errorf("viewer does not see connection %s (viewer is not scoped)", denied.ID)
	}
}

func TestIntegrationRuntimeConfigReportsEffectiveScopeMode(t *testing.T) {
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	for _, tc := range []struct {
		name string
		mode policy.EnforcementMode
	}{
		{name: "enforce", mode: policy.EnforcementEnforce},
		{name: "disabled", mode: policy.EnforcementDisabled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newScopeTestEnv(t, nil, tc.mode)

			resp := env.do(t, http.MethodGet, "/api/v1/runtime-config", nil, &operator, false)
			requireStatus(t, resp, http.StatusForbidden)

			resp = env.do(t, http.MethodGet, "/api/v1/runtime-config", nil, &admin, false)
			requireStatus(t, resp, http.StatusOK)
			var out map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatalf("decode runtime config: %v", err)
			}
			if len(out) != 1 || out["scope_enforcement"] != string(tc.mode) {
				t.Errorf("runtime config = %#v, want only scope_enforcement=%q", out, tc.mode)
			}
		})
	}
}

func TestIntegrationScopeDisabledAllowsAll(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementDisabled)
	operator := session(auth.RoleOperator)

	conn := createDraftInEnv(t, env, "scope-disabled-"+uuid.NewString())

	// disabled: operator видит connection любого окружения без политик.
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+conn.ID.String(), nil, &operator, false)
	requireStatus(t, resp, http.StatusOK)
	if ids := listConnectionIDs(t, env, operator); !ids[conn.ID.String()] {
		t.Errorf("operator does not see connection %s in disabled mode", conn.ID)
	}
}

func TestIntegrationScopePolicyManagement(t *testing.T) {
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)

	// Управление политиками — только admin.
	body := map[string]any{
		"subject_kind": policy.SubjectRole,
		"subject":      string(auth.RoleOperator),
		"environment":  "mgmt-" + uuid.NewString(),
	}
	resp := env.do(t, http.MethodPost, "/api/v1/scope-policies", body, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodGet, "/api/v1/scope-policies", nil, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// admin создаёт политику.
	resp = env.do(t, http.MethodPost, "/api/v1/scope-policies", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var created struct {
		ID          string `json:"id"`
		SubjectKind string `json:"subject_kind"`
		Environment string `json:"environment"`
	}
	if err := json.Unmarshal(readBody(t, resp), &created); err != nil {
		t.Fatalf("unmarshal created policy: %v", err)
	}
	if created.ID == "" || created.SubjectKind != policy.SubjectRole {
		t.Fatalf("unexpected created policy: %+v", created)
	}

	// Дубликат — 409.
	resp = env.do(t, http.MethodPost, "/api/v1/scope-policies", body, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	// GET содержит созданную политику.
	resp = env.do(t, http.MethodGet, "/api/v1/scope-policies", nil, &admin, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Policies []struct {
			ID string `json:"id"`
		} `json:"policies"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode policy list: %v", err)
	}
	found := false
	for _, p := range list.Policies {
		if p.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Errorf("created policy %s not found in list", created.ID)
	}

	// DELETE удаляет; повтор — 404.
	resp = env.do(t, http.MethodDelete, "/api/v1/scope-policies/"+created.ID, nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	resp = env.do(t, http.MethodDelete, "/api/v1/scope-policies/"+created.ID, nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)

	// Невалидный subject_kind — 400.
	bad := map[string]any{"subject_kind": "group", "subject": "x", "environment": "e"}
	resp = env.do(t, http.MethodPost, "/api/v1/scope-policies", bad, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
}
