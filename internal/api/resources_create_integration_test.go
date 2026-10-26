//go:build integration

// POST /api/v1/connections/{id}/resources — создание базы (architecture §11.2).
// Проверяется API-слой: RBAC (admin-only), валидация, резервирование
// planned-строки и поставленная операция.
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

func TestIntegrationCreateResourceDatabase(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	path := "/api/v1/connections/" + conn.ID.String() + "/resources"
	name := "itest_db_" + uniqueSuffix()[:8]

	// Создание баз — admin-only (§11.2): operator получает 403.
	resp := env.do(t, http.MethodPost, path, map[string]any{"name": name}, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &admin, false)
	requireStatus(t, resp, http.StatusForbidden)

	for _, bad := range []map[string]any{
		{"name": ""},
		{"name": "app db"},
		{"name": "app\ndb"},
		{"kind": "schema", "name": "app"},
		{"name": name, "connection_limit": -2},
	} {
		resp = env.do(t, http.MethodPost, path, bad, &admin, true)
		requireStatus(t, resp, http.StatusBadRequest)
	}

	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		ResourceID  uuid.UUID `json:"resource_id"`
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode create resource response: %v", err)
	}

	// Строка резервирует внешний идентификатор в статусе planned: до
	// подтверждённого создания объекта в целевой системе ещё нет.
	res, err := inventory.NewStore().GetResource(t.Context(), env.pool, out.ResourceID)
	if err != nil {
		t.Fatalf("get planned resource: %v", err)
	}
	if res.Status != inventory.ResourcePlanned {
		t.Errorf("resource status = %q, want planned", res.Status)
	}
	if res.Ownership != inventory.OwnershipManaged {
		t.Errorf("ownership = %q, want managed", res.Ownership)
	}
	// External id обязан совпасть с тем, что построит discovery, иначе
	// следующий снимок заведёт вторую строку того же объекта.
	if res.ExternalID != "db:"+name {
		t.Errorf("external id = %q, want db:%s", res.ExternalID, name)
	}

	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindResourceCreateDatabase {
		t.Errorf("operation kind = %q, want %q", op.Kind, jobs.KindResourceCreateDatabase)
	}
	if op.ResourceID == nil || *op.ResourceID != res.ID {
		t.Errorf("operation resource id = %v, want %s", op.ResourceID, res.ID)
	}

	// Повтор того же имени — 409, второй операции не появляется.
	resp = env.do(t, http.MethodPost, path, map[string]any{"name": name}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}

// Движок без resource.create.database отказывает синхронно, а не ставит
// обречённую операцию.
func TestIntegrationCreateResourceWithoutCapability(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)

	if _, err := env.pool.Exec(t.Context(),
		`update connections set capabilities = capabilities - 'resource.create.database' where id = $1`,
		conn.ID); err != nil {
		t.Fatalf("drop capability: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/resources",
		map[string]any{"name": "itest_db_" + uniqueSuffix()[:8]}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}
