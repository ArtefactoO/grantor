//go:build integration

// Integration-тесты DELETE /api/v1/connections/{id} на fake adapter.
// Проверяется, что удаление затрагивает ТОЛЬКО metadata grantor (строка
// connection + FK-каскад инвентаря + audit), не ходит в целевой кластер и
// не ставит операций worker; managed-аккаунты guard'ятся, ?force=true
// снимает запрет ценой орфанинга.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// deleteConnectionResp — тело 200-ответа DELETE /api/v1/connections/{id}.
type deleteConnectionResp struct {
	ID                      string `json:"id"`
	Deleted                 bool   `json:"deleted"`
	CascadedResources       int    `json:"cascaded_resources"`
	CascadedAccounts        int    `json:"cascaded_accounts"`
	OrphanedManagedAccounts int    `json:"orphaned_managed_accounts"`
}

// countOperationsByActor возвращает число операций конкретного уникального
// test actor. Глобальный COUNT(*) здесь был flaky: integration-тесты пакета
// выполняются параллельно и легитимно создают операции друг друга.
func countOperationsByActor(t *testing.T, pool *pgxpool.Pool, actorID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`select count(*) from operations where actor_id = $1`, actorID).Scan(&n); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	return n
}

func TestIntegrationDeleteConnectionUnmanaged(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	admin.Email = "delete-connection-" + uuid.NewString() + "@example.test"
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	// Active connection со сведённым fake-инвентарём: аккаунты svc-a/readers
	// (оба unmanaged, как обнаруженные discovery), 2 ресурса, 1 unmanaged
	// binding. Managed-аккаунтов нет — удаление разрешено без force.
	conn := activeFakeConnection(t, env.pool)
	path := "/api/v1/connections/" + conn.ID.String()

	opsBefore := countOperationsByActor(t, env.pool, admin.Email)

	// RBAC: не-admin не может удалять; без CSRF мутация отклоняется.
	resp := env.do(t, http.MethodDelete, path, nil, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodDelete, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodDelete, path, nil, &admin, false)
	requireStatus(t, resp, http.StatusForbidden)

	// admin без force: managed-аккаунтов нет — 200, инвентарь каскадно удалён.
	resp = env.do(t, http.MethodDelete, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out deleteConnectionResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !out.Deleted || out.ID != conn.ID.String() {
		t.Errorf("unexpected delete response: %+v", out)
	}
	if out.CascadedResources != 2 || out.CascadedAccounts != 2 {
		t.Errorf("cascade counts = %d resources / %d accounts, want 2 / 2", out.CascadedResources, out.CascadedAccounts)
	}
	if out.OrphanedManagedAccounts != 0 {
		t.Errorf("orphaned_managed_accounts = %d, want 0", out.OrphanedManagedAccounts)
	}

	// Строка connection и её инвентарь удалены (FK-каскад).
	if _, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID); err == nil {
		t.Error("connection row still present after delete")
	}
	accounts, err := inventory.NewStore().ListAccounts(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("accounts remain after delete: %d", len(accounts))
	}
	resources, err := inventory.NewStore().ListResources(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	if len(resources) != 0 {
		t.Errorf("resources remain after delete: %d", len(resources))
	}

	// Никаких операций worker удаление не поставило: target не тронут.
	if opsAfter := countOperationsByActor(t, env.pool, admin.Email); opsAfter != opsBefore {
		t.Errorf("operations count changed from %d to %d; delete must not enqueue jobs", opsBefore, opsAfter)
	}

	// Audit-событие connection.deleted записано (переживает FK-каскад: у
	// audit_events нет FK на connections) с actor из сессии и метаданными
	// metadata-only.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:       []string{"connection.deleted"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("connection.deleted audit events = %d, want 1", len(events))
	}
	if events[0].ActorID != admin.Email {
		t.Errorf("audit actor = %q, want %q", events[0].ActorID, admin.Email)
	}
	var meta map[string]any
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta["target_untouched"] != true {
		t.Errorf("audit metadata target_untouched = %v, want true", meta["target_untouched"])
	}
	if meta["force"] != false {
		t.Errorf("audit metadata force = %v, want false", meta["force"])
	}

	// Идемпотентность: повторное удаление того же id — 404.
	resp = env.do(t, http.MethodDelete, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationDeleteConnectionManagedGuard(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)

	conn := activeFakeConnection(t, env.pool)
	// Managed-аккаунт: реальный пользователь, созданный grantor в целевой
	// системе. Его наличие блокирует удаление без force (иначе он осиротеет).
	if _, err := inventory.NewStore().CreateManagedAccount(context.Background(), env.pool,
		inventory.CreateManagedAccountParams{
			ConnectionID:   conn.ID,
			EngineIdentity: "managed-user",
			CredentialMode: "generated",
		}); err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	path := "/api/v1/connections/" + conn.ID.String()

	// Без force — 409 с предупреждением про орфанинг; connection на месте.
	resp := env.do(t, http.MethodDelete, path, nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	body := readBody(t, resp)
	if !strings.Contains(string(body), "orphaned") {
		t.Errorf("409 body does not warn about orphaning: %s", body)
	}
	if _, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID); err != nil {
		t.Errorf("connection removed despite managed-accounts guard: %v", err)
	}

	// ?force=true — 200; метаданные удалены, орфанинг зафиксирован в ответе.
	resp = env.do(t, http.MethodDelete, path+"?force=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out deleteConnectionResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode force delete response: %v", err)
	}
	if out.OrphanedManagedAccounts != 1 {
		t.Errorf("orphaned_managed_accounts = %d, want 1", out.OrphanedManagedAccounts)
	}
	if _, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID); err == nil {
		t.Error("connection row still present after force delete")
	}

	// Audit force-удаления помечен force=true и target_untouched=true.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:       []string{"connection.deleted"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("connection.deleted audit events = %d, want 1", len(events))
	}
	var meta map[string]any
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta["force"] != true || meta["target_untouched"] != true {
		t.Errorf("audit metadata force=%v target_untouched=%v, want true/true", meta["force"], meta["target_untouched"])
	}
}

func TestIntegrationDeleteConnectionUnknown(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)

	// Несуществующий id — 404; невалидный uuid — 400.
	resp := env.do(t, http.MethodDelete, "/api/v1/connections/"+uuid.NewString(), nil, &admin, true)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodDelete, "/api/v1/connections/not-a-uuid", nil, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
}
