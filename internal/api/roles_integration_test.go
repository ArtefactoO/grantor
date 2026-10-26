//go:build integration

// POST /api/v1/connections/{id}/roles — создание роли-контейнера без логина.
// Проверяется API-слой: RBAC, валидация, резервирование identity, поставленная
// операция и отсутствие какого-либо участия Vault.
package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestIntegrationCreateRole(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)
	path := "/api/v1/connections/" + conn.ID.String() + "/roles"
	name := "itest_role_" + uniqueSuffix()[:8]

	// RBAC и CSRF.
	resp := env.do(t, http.MethodPost, path, map[string]any{"name": name}, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// Валидация имени: оно уходит в CREATE ROLE идентификатором.
	for _, bad := range []map[string]any{
		{"name": ""},
		{"name": "   "},
		{"name": "app read"},
		{"name": "app\nread"},
	} {
		resp = env.do(t, http.MethodPost, path, bad, &operator, true)
		requireStatus(t, resp, http.StatusBadRequest)
	}

	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		AccountID   uuid.UUID `json:"account_id"`
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode create role response: %v", err)
	}

	// Строка резервирует identity: kind=group, provisioning, без credential.
	acct, err := inventory.NewStore().GetAccount(t.Context(), env.pool, out.AccountID)
	if err != nil {
		t.Fatalf("get created role account: %v", err)
	}
	if acct.Kind != inventory.AccountKindGroup {
		t.Errorf("account kind = %q, want group", acct.Kind)
	}
	if acct.Status != inventory.AccountProvisioning {
		t.Errorf("account status = %q, want provisioning", acct.Status)
	}
	if acct.Ownership != inventory.OwnershipManaged {
		t.Errorf("ownership = %q, want managed", acct.Ownership)
	}
	// У роли без логина credential нет и быть не должно.
	if acct.VaultPath != "" || acct.CredentialMode != nil {
		t.Errorf("role carries credential %q/%v, want none", acct.VaultPath, acct.CredentialMode)
	}

	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindRoleCreate {
		t.Errorf("operation kind = %q, want %q", op.Kind, jobs.KindRoleCreate)
	}
	if op.Status != operations.StatusPending {
		t.Errorf("operation status = %q, want pending (no approval gate for a bare role)", op.Status)
	}

	// Повторный запрос той же identity — 409, второй операции не появляется.
	before := countAccountOperations(t, env.pool, out.AccountID)
	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	if after := countAccountOperations(t, env.pool, out.AccountID); after != before {
		t.Errorf("operations after duplicate request = %d, want %d", after, before)
	}
}

func TestIntegrationCreateBareDatabaseRoleRequiresAdmin(t *testing.T) {
	for _, engine := range []string{"postgres", "mongodb"} {
		t.Run(engine, func(t *testing.T) {
			env := newTestEnv(t, nil)
			operator := session(auth.RoleOperator)
			conn := activeFakeConnection(t, env.pool)
			if _, err := env.pool.Exec(t.Context(), `update connections set engine=$2 where id=$1`, conn.ID, engine); err != nil {
				t.Fatalf("mark connection %s: %v", engine, err)
			}
			resp := env.do(t, http.MethodPost,
				"/api/v1/connections/"+conn.ID.String()+"/roles",
				map[string]any{"name": "operator_must_not_create"}, &operator, true)
			requireStatus(t, resp, http.StatusForbidden)
		})
	}
}

// Движок без role.create обязан отказать синхронно, а не ставить обречённую
// операцию: capability проверяется и по манифесту, и по эффективному набору
// подключения.
func TestIntegrationCreateRoleWithoutCapability(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)

	if _, err := env.pool.Exec(t.Context(),
		`update connections set capabilities = capabilities - 'role.create' where id = $1`,
		conn.ID); err != nil {
		t.Fatalf("drop role.create capability: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/roles",
		map[string]any{"name": "itest_role_" + uniqueSuffix()[:8]}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}
