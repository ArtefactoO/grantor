//go:build integration

// Integration-тесты мутирующих endpoints API (этап 1b) на fake adapter.
// Проверяется только API-слой: валидация, RBAC, dangerous-контроль,
// созданные строки bindings/accounts/operations. Worker не запускается —
// операции остаются pending; сквозной цикл grant/revoke/rotate живёт в
// internal/jobs/mutations_integration_test.go.
package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/yopass"
)

func TestIntegrationPurgeDeletedAccount(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	store := inventory.NewStore()
	principal, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "purge principal",
	})
	if err != nil {
		t.Fatalf("create purge principal: %v", err)
	}
	acct, err := store.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "purge-me", PrincipalID: &principal.ID,
		CredentialMode: inventory.CredentialModeGenerated,
	})
	if err != nil {
		t.Fatalf("create purge account: %v", err)
	}

	resp := env.do(t, http.MethodDelete, "/api/v1/accounts/"+acct.ID.String()+"/purge?confirm=true", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+acct.ID.String()+"/purge", nil, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+acct.ID.String()+"/purge?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	if err := store.SetAccountStatus(t.Context(), env.pool, acct.ID, inventory.AccountDeleted); err != nil {
		t.Fatalf("mark purge account deleted: %v", err)
	}
	if _, err := principals.NewStore().SetStatus(t.Context(), env.pool, principal.ID, principals.StatusDeleted); err != nil {
		t.Fatalf("mark purge principal deleted: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+acct.ID.String()+"/purge?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out struct {
		AccountID uuid.UUID `json:"account_id"`
		Purged    bool      `json:"purged"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode purge response: %v", err)
	}
	if out.AccountID != acct.ID || !out.Purged {
		t.Errorf("purge response = %+v, want account %s purged", out, acct.ID)
	}
	if _, err := store.GetAccount(t.Context(), env.pool, acct.ID); !errors.Is(err, inventory.ErrNotFound) {
		t.Fatalf("purged account still exists or wrong error: %v", err)
	}
	if _, err := principals.NewStore().Get(t.Context(), env.pool, principal.ID); !errors.Is(err, principals.ErrNotFound) {
		t.Fatalf("orphan deleted principal still exists or wrong error: %v", err)
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &conn.ID, Actions: []string{"account.purged"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list purge audit: %v", err)
	}
	if len(events) != 1 || events[0].AccountID == nil || *events[0].AccountID != acct.ID {
		t.Fatalf("purge audit = %+v, want preserved account id %s", events, acct.ID)
	}
	principalEvents, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		Actions: []string{"principal.purged"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list principal purge audit: %v", err)
	}
	if len(principalEvents) != 1 || principalEvents[0].PrincipalID == nil ||
		*principalEvents[0].PrincipalID != principal.ID {
		t.Fatalf("principal purge audit = %+v, want principal %s", principalEvents, principal.ID)
	}

	// Незавершённая lifecycle-операция блокирует purge: tombstone остаётся,
	// пока операция не отменена или не завершена.
	busy, err := store.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "purge-busy", CredentialMode: inventory.CredentialModeGenerated,
	})
	if err != nil {
		t.Fatalf("create busy purge account: %v", err)
	}
	if err := store.SetAccountStatus(t.Context(), env.pool, busy.ID, inventory.AccountDeleted); err != nil {
		t.Fatalf("mark busy purge account deleted: %v", err)
	}
	busyOp, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: "account.restore", ConnectionID: &conn.ID, AccountID: &busy.ID,
		ActorType: "user", ActorID: "admin@example.com", CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create busy lifecycle operation: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+busy.ID.String()+"/purge?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	if _, err := store.GetAccount(t.Context(), env.pool, busy.ID); err != nil {
		t.Fatalf("busy account was removed despite active lifecycle operation: %v", err)
	}
	if _, err := operations.NewStore().Transition(t.Context(), env.pool, busyOp.ID,
		operations.StatusPending, operations.StatusCancelled, operations.TransitionOpts{}); err != nil {
		t.Fatalf("cancel busy lifecycle operation: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+busy.ID.String()+"/purge?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)

	orphan, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "purge orphan directly",
	})
	if err != nil {
		t.Fatalf("create direct purge principal: %v", err)
	}
	if _, err := principals.NewStore().SetStatus(t.Context(), env.pool, orphan.ID, principals.StatusDeleted); err != nil {
		t.Fatalf("mark direct purge principal deleted: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/principals/"+orphan.ID.String()+"/purge?confirm=true", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodDelete, "/api/v1/principals/"+orphan.ID.String()+"/purge", nil, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodDelete, "/api/v1/principals/"+orphan.ID.String()+"/purge?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	if _, err := principals.NewStore().Get(t.Context(), env.pool, orphan.ID); !errors.Is(err, principals.ErrNotFound) {
		t.Fatalf("directly purged principal still exists or wrong error: %v", err)
	}
}

// activateConnection проводит connection по state machine до active.
func activateConnection(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) {
	t.Helper()
	st := connections.NewStore()
	steps := []struct{ from, to connections.Status }{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	}
	for _, step := range steps {
		if _, err := st.Transition(context.Background(), pool, id, step.from, step.to); err != nil {
			t.Fatalf("transition %s -> %s: %v", step.from, step.to, err)
		}
	}
}

// seedFakeInventory сводит снапшот fake adapter в инвентарь connection:
// аккаунты svc-a/readers, permissions app-readonly/app-readwrite и
// dangerous superuser.
func seedFakeInventory(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	snap, err := fake.New().Discover(ctx, adapter.Connection{})
	if err != nil {
		t.Fatalf("fake discover: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := inventory.NewStore().UpsertSnapshot(ctx, tx, connID, snap, time.Now()); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit snapshot: %v", err)
	}
}

// activeFakeConnection создаёт активное подключение fake со сведённым
// инвентарём.
func activeFakeConnection(t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn := createDraft(t, pool)
	activateConnection(t, pool, conn.ID)
	seedFakeInventory(t, pool, conn.ID)
	current, err := connections.NewStore().Get(t.Context(), pool, conn.ID)
	if err != nil {
		t.Fatalf("get active fake connection: %v", err)
	}
	manifest := fake.New().Manifest()
	capabilities := make([]string, len(manifest.Capabilities))
	for i := range manifest.Capabilities {
		capabilities[i] = string(manifest.Capabilities[i])
	}
	current, err = connections.NewStore().Update(t.Context(), pool, current.ID, connections.UpdateParams{
		DisplayName: current.DisplayName, Environment: current.Environment,
		Tags: current.Tags, Endpoints: current.Endpoints, TLSConfig: current.TLSConfig,
		DiscoveryConfig: current.DiscoveryConfig, Capabilities: capabilities,
	})
	if err != nil {
		t.Fatalf("enable fake capabilities: %v", err)
	}
	return current
}

// findAccount возвращает аккаунт connection по engine identity.
func findAccount(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID, identity string) inventory.Account {
	t.Helper()
	accounts, err := inventory.NewStore().ListAccounts(context.Background(), pool, connID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	for _, a := range accounts {
		if a.EngineIdentity == identity {
			return a
		}
	}
	t.Fatalf("account %q not found among %d", identity, len(accounts))
	return inventory.Account{}
}

// findPermission возвращает permission connection по external id.
func findPermission(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID, externalID string) inventory.Permission {
	t.Helper()
	perms, err := inventory.NewStore().ListPermissions(context.Background(), pool, connID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	for _, p := range perms {
		if p.ExternalID == externalID {
			return p
		}
	}
	t.Fatalf("permission %q not found among %d", externalID, len(perms))
	return inventory.Permission{}
}

// grantResponse — тело 202-ответа POST /api/v1/bindings.
type grantResponse struct {
	OperationID uuid.UUID `json:"operation_id"`
	BindingID   uuid.UUID `json:"binding_id"`
}

func TestIntegrationCreateBinding(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")

	body := map[string]any{"account_id": acct.ID, "permission_id": perm.ID}

	// viewer не может выдавать доступы; без CSRF мутация отклоняется.
	resp := env.do(t, http.MethodPost, "/api/v1/bindings", body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", body, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/bindings", body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out grantResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}

	// Binding создан под управлением сервиса с desired present.
	binding, err := inventory.NewStore().GetBinding(t.Context(), env.pool, out.BindingID)
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingPresent {
		t.Errorf("binding desired = %v, want present", binding.DesiredState)
	}
	if binding.Source != "service" {
		t.Errorf("binding source = %q, want service", binding.Source)
	}
	if binding.Status != inventory.BindingStatusPending {
		t.Errorf("binding status = %q, want pending", binding.Status)
	}

	// Операция access.grant в pending и ссылается на binding.
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindAccessGrant || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want access.grant/pending", op.Kind, op.Status)
	}
	if op.BindingID == nil || *op.BindingID != out.BindingID {
		t.Errorf("operation binding_id = %v, want %s", op.BindingID, out.BindingID)
	}

	// Audit-событие запроса записано.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:      []string{"access.grant_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("no access.grant_requested audit event")
	}

	// Permission чужого connection — 400.
	otherConn := activeFakeConnection(t, env.pool)
	otherPerm := findPermission(t, env.pool, otherConn.ID, "role:app-readonly")
	resp = env.do(t, http.MethodPost, "/api/v1/bindings",
		map[string]any{"account_id": acct.ID, "permission_id": otherPerm.ID}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Несуществующий account — 404; отсутствие полей — 400.
	resp = env.do(t, http.MethodPost, "/api/v1/bindings",
		map[string]any{"account_id": uuid.New(), "permission_id": perm.ID}, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", map[string]any{}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)
}

func TestIntegrationCreateBindingDangerous(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	body := map[string]any{"account_id": acct.ID, "permission_id": dangerous.ID}

	// operator не может выдавать dangerous даже с confirm.
	withConfirm := map[string]any{"account_id": acct.ID, "permission_id": dangerous.ID, "confirm": true}
	resp := env.do(t, http.MethodPost, "/api/v1/bindings", withConfirm, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)

	// admin без confirm — 400.
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", body, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// admin с confirm — 202, payload операции несёт подтверждение.
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", withConfirm, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out grantResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	// jsonb нормализует представление (пробелы после двоеточий), поэтому
	// сверяем разобранное значение, а не подстроку.
	var confirmedPayload struct {
		Confirmed bool `json:"confirmed"`
	}
	if err := json.Unmarshal(op.Payload, &confirmedPayload); err != nil || !confirmedPayload.Confirmed {
		t.Errorf("operation payload %s does not carry confirmed flag (err=%v)", op.Payload, err)
	}
}

func TestIntegrationBulkGrant(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	readers := findAccount(t, env.pool, conn.ID, "readers")
	readonly := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	readwrite := findPermission(t, env.pool, conn.ID, "role:app-readwrite")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")

	body := map[string]any{"items": []map[string]any{
		{"account_id": acct.ID, "permission_id": readonly.ID},
		{"account_id": readers.ID, "permission_id": readwrite.ID},
	}}

	resp := env.do(t, http.MethodPost, "/api/v1/bindings/bulk", body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/bindings/bulk", body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			OperationID uuid.UUID `json:"operation_id"`
			BindingID   uuid.UUID `json:"binding_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode bulk response: %v", err)
	}
	if len(out.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(out.Children))
	}

	opStore := operations.NewStore()
	parent, err := opStore.Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get parent operation: %v", err)
	}
	if parent.Kind != jobs.KindBulkGrant || parent.Status != operations.StatusRunning {
		t.Errorf("parent kind/status = %q/%q, want bulk.grant/running", parent.Kind, parent.Status)
	}
	if parent.ConnectionID != nil {
		t.Errorf("parent connection_id = %v, want nil", parent.ConnectionID)
	}
	for _, child := range out.Children {
		op, err := opStore.Get(t.Context(), env.pool, child.OperationID)
		if err != nil {
			t.Fatalf("get child operation: %v", err)
		}
		if op.ParentID == nil || *op.ParentID != parent.ID {
			t.Errorf("child parent_id = %v, want %s", op.ParentID, parent.ID)
		}
		if op.Kind != jobs.KindAccessGrant || op.Status != operations.StatusPending {
			t.Errorf("child kind/status = %q/%q, want access.grant/pending", op.Kind, op.Status)
		}
	}

	// Detail parent отдаёт children и вычисленный aggregate_status:
	// worker не запущен, дети pending — running.
	resp = env.do(t, http.MethodGet, "/api/v1/operations/"+parent.ID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var detail struct {
		AggregateStatus string `json:"aggregate_status"`
		Children        []struct {
			ID uuid.UUID `json:"id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode operation detail: %v", err)
	}
	if len(detail.Children) != 2 {
		t.Errorf("detail children = %d, want 2", len(detail.Children))
	}
	if detail.AggregateStatus != "running" {
		t.Errorf("aggregate_status = %q, want running", detail.AggregateStatus)
	}

	// Dangerous в списке: operator — 403, пустой список — 400.
	withDangerous := map[string]any{"items": []map[string]any{
		{"account_id": acct.ID, "permission_id": dangerous.ID},
	}, "confirm": true}
	resp = env.do(t, http.MethodPost, "/api/v1/bindings/bulk", withDangerous, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, "/api/v1/bindings/bulk", map[string]any{"items": []any{}}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)
}

func TestIntegrationDeleteBinding(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")

	resp := env.do(t, http.MethodPost, "/api/v1/bindings",
		map[string]any{"account_id": acct.ID, "permission_id": perm.ID}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var created grantResponse
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}

	resp = env.do(t, http.MethodDelete, "/api/v1/bindings/"+created.BindingID.String(), nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out grantResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode revoke response: %v", err)
	}

	binding, err := inventory.NewStore().GetBinding(t.Context(), env.pool, created.BindingID)
	if err != nil {
		t.Fatalf("get binding: %v", err)
	}
	if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingAbsent {
		t.Errorf("binding desired = %v, want absent", binding.DesiredState)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindAccessRevoke || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want access.revoke/pending", op.Kind, op.Status)
	}

	// Несуществующий binding — 404.
	resp = env.do(t, http.MethodDelete, "/api/v1/bindings/"+uuid.NewString(), nil, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationManageAccountRoles(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	readonly := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	readwrite := findPermission(t, env.pool, conn.ID, "role:app-readwrite")

	initial, _, err := inventory.NewStore().EnsureBinding(
		t.Context(),
		env.pool,
		inventory.EnsureBindingParams{
			AccountID:    acct.ID,
			PermissionID: readonly.ID,
			DesiredState: inventory.BindingPresent,
			Source:       string(inventory.BindingSourceService),
		},
	)
	if err != nil {
		t.Fatalf("ensure initial binding: %v", err)
	}

	body := map[string]any{
		"add_permission_ids": []uuid.UUID{readwrite.ID},
		"remove_binding_ids": []uuid.UUID{initial.ID},
	}
	path := "/api/v1/accounts/" + acct.ID.String() + "/roles"
	resp := env.do(t, http.MethodPost, path, body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID `json:"operation_id"`
		Children    []struct {
			OperationID  uuid.UUID `json:"operation_id"`
			BindingID    uuid.UUID `json:"binding_id"`
			PermissionID uuid.UUID `json:"permission_id"`
			Action       string    `json:"action"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode role management response: %v", err)
	}
	if len(out.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(out.Children))
	}

	parent, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get parent: %v", err)
	}
	if parent.Kind != jobs.KindBulkAccountRoles || parent.Status != operations.StatusRunning {
		t.Errorf("parent kind/status = %q/%q, want bulk.account_roles/running", parent.Kind, parent.Status)
	}
	if parent.AccountID == nil || *parent.AccountID != acct.ID {
		t.Errorf("parent account_id = %v, want %s", parent.AccountID, acct.ID)
	}
	if parent.ConnectionID == nil || *parent.ConnectionID != conn.ID {
		t.Errorf("parent connection_id = %v, want %s", parent.ConnectionID, conn.ID)
	}

	actions := map[string]uuid.UUID{}
	for _, child := range out.Children {
		actions[child.Action] = child.PermissionID
		op, err := operations.NewStore().Get(t.Context(), env.pool, child.OperationID)
		if err != nil {
			t.Fatalf("get %s child: %v", child.Action, err)
		}
		if op.ParentID == nil || *op.ParentID != parent.ID {
			t.Errorf("%s child parent = %v, want %s", child.Action, op.ParentID, parent.ID)
		}
	}
	if actions["grant"] != readwrite.ID || actions["revoke"] != readonly.ID {
		t.Errorf("actions = %v, want grant %s and revoke %s", actions, readwrite.ID, readonly.ID)
	}
	gotInitial, err := inventory.NewStore().GetBinding(t.Context(), env.pool, initial.ID)
	if err != nil {
		t.Fatalf("get revoked binding: %v", err)
	}
	if gotInitial.DesiredState == nil || *gotInitial.DesiredState != inventory.BindingAbsent {
		t.Errorf("removed binding desired = %v, want absent", gotInitial.DesiredState)
	}
}

func TestIntegrationManageAccountRolesUsesSingleExplicitReplace(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	acct := findAccount(t, env.pool, conn.ID, "svc-a")
	readonly := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	readwrite := findPermission(t, env.pool, conn.ID, "role:app-readwrite")
	assignmentKey := "test:exclusive:app"
	if _, err := env.pool.Exec(t.Context(), `
		update permission_definitions set assignment_key = $3
		where id in ($1, $2)`, readonly.ID, readwrite.ID, assignmentKey); err != nil {
		t.Fatalf("set assignment keys: %v", err)
	}
	readonly = findPermission(t, env.pool, conn.ID, readonly.ExternalID)
	readwrite = findPermission(t, env.pool, conn.ID, readwrite.ExternalID)
	initial, _, err := inventory.NewStore().EnsureBinding(t.Context(), env.pool,
		inventory.EnsureBindingParams{
			AccountID: acct.ID, PermissionID: readonly.ID,
			DesiredState: inventory.BindingPresent, Source: string(inventory.BindingSourceService),
		})
	if err != nil {
		t.Fatalf("ensure initial exclusive binding: %v", err)
	}
	path := "/api/v1/accounts/" + acct.ID.String() + "/roles"

	// Императивная delta обязана назвать source binding явно; add B сам по
	// себе не трактуется как replacement.
	resp := env.do(t, http.MethodPost, path, map[string]any{
		"add_permission_ids": []uuid.UUID{readwrite.ID},
	}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	resp = env.do(t, http.MethodPost, path, map[string]any{
		"add_permission_ids": []uuid.UUID{readwrite.ID},
		"remove_binding_ids": []uuid.UUID{initial.ID},
	}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		Children []struct {
			OperationID  uuid.UUID `json:"operation_id"`
			BindingID    uuid.UUID `json:"binding_id"`
			PermissionID uuid.UUID `json:"permission_id"`
			Action       string    `json:"action"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode replace response: %v", err)
	}
	if len(out.Children) != 1 || out.Children[0].Action != "replace" ||
		out.Children[0].BindingID != initial.ID || out.Children[0].PermissionID != readwrite.ID {
		t.Fatalf("replace children = %+v", out.Children)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.Children[0].OperationID)
	if err != nil {
		t.Fatalf("get replace operation: %v", err)
	}
	if op.Kind != jobs.KindAccessReplace || op.BindingID == nil || *op.BindingID != initial.ID {
		t.Fatalf("replace operation = %+v", op)
	}
	var payload jobs.AccessReplacePayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		t.Fatalf("decode replace payload: %v", err)
	}
	if payload.FromPermissionDefinitionID != readonly.ID ||
		payload.ToPermissionDefinitionID != readwrite.ID || payload.AssignmentKey != assignmentKey {
		t.Fatalf("replace payload = %+v", payload)
	}
	reserved, err := inventory.NewStore().GetBinding(t.Context(), env.pool, initial.ID)
	if err != nil {
		t.Fatalf("get reserved binding: %v", err)
	}
	if reserved.PermissionDefinitionID != readwrite.ID || reserved.TransitionOperationID == nil ||
		*reserved.TransitionOperationID != op.ID || reserved.Version != payload.ExpectedBindingVersion {
		t.Fatalf("reserved binding = %+v", reserved)
	}
	var count int
	if err := env.pool.QueryRow(t.Context(), `
		select count(*) from bindings where account_id = $1 and assignment_key = $2`,
		acct.ID, assignmentKey).Scan(&count); err != nil {
		t.Fatalf("count assignment bindings: %v", err)
	}
	if count != 1 {
		t.Fatalf("assignment binding rows = %d, want 1", count)
	}
}

func TestIntegrationCreateAccount(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)

	identity := "itest_acct_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	body := map[string]any{
		"connection_id":   conn.ID,
		"engine_identity": identity,
		"credential":      map[string]any{"mode": "generated"},
	}

	resp := env.do(t, http.MethodPost, "/api/v1/accounts", body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, "/api/v1/accounts", body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw := readBody(t, resp)
	var out struct {
		AccountID   uuid.UUID `json:"account_id"`
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal create account response: %v", err)
	}

	acct, err := inventory.NewStore().GetAccount(t.Context(), env.pool, out.AccountID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	// Строка создаётся резервацией identity: живой учётка станет только после
	// подтверждённых Apply и Verify адаптера, поэтому сразу после запроса —
	// provisioning, а не active.
	if acct.Ownership != "managed" || acct.Status != "provisioning" || acct.Kind != "login" {
		t.Errorf("account ownership/status/kind = %q/%q/%q, want managed/provisioning/login",
			acct.Ownership, acct.Status, acct.Kind)
	}
	wantPath := "accounts/" + acct.ID.String() + "/credential"
	if acct.VaultPath != wantPath {
		t.Errorf("vault_path = %q, want %q", acct.VaultPath, wantPath)
	}

	// Секрет действительно лёг в Vault, а в ответ не попал.
	data, _, err := vaultClient.Get(t.Context(), wantPath)
	if err != nil {
		t.Fatalf("vault get %s: %v", wantPath, err)
	}
	password, _ := data["password"].(string)
	if data["username"] != identity || password == "" {
		t.Errorf("vault secret username = %v, password empty = %v", data["username"], password == "")
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("create account response leaks generated password")
	}

	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindAccountCreate || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want account.create/pending", op.Kind, op.Status)
	}

	// Audit-событие запроса не содержит пароль.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &acct.ID,
		Actions:   []string{"account.create_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if strings.Contains(string(events[0].Metadata), password) {
		t.Error("audit metadata leaks generated password")
	}

	// Повторное создание той же identity — 409.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts", body, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// provided mode кладёт заданный пароль, не раскрывая его в ответе.
	providedIdentity := identity + "_p"
	const providedPassword = "itest-provided-secret-marker"
	resp = env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{
		"connection_id":   conn.ID,
		"engine_identity": providedIdentity,
		"credential":      map[string]any{"mode": "provided", "password": providedPassword},
	}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw = readBody(t, resp)
	if strings.Contains(string(raw), providedPassword) {
		t.Fatal("create account response leaks provided password")
	}
	var provided struct {
		AccountID uuid.UUID `json:"account_id"`
	}
	if err := json.Unmarshal(raw, &provided); err != nil {
		t.Fatalf("unmarshal provided response: %v", err)
	}
	data, _, err = vaultClient.Get(t.Context(), "accounts/"+provided.AccountID.String()+"/credential")
	if err != nil {
		t.Fatalf("vault get provided credential: %v", err)
	}
	if data["password"] != providedPassword {
		t.Error("vault secret does not match provided password")
	}

	// Невалидный режим credential — 400; неактивный connection — 409.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{
		"connection_id":   conn.ID,
		"engine_identity": identity + "_x",
		"credential":      map[string]any{"mode": "external_identity"},
	}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	draft := createDraft(t, env.pool)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{
		"connection_id":   draft.ID,
		"engine_identity": identity + "_d",
		"credential":      map[string]any{"mode": "generated"},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationAccountCreateCapabilityGatePrecedesMetadataAndVault(t *testing.T) {
	env := newTestEnv(t, nil) // A blocked implicit create must not require Vault.
	operator := session(auth.RoleOperator)
	conn, err := connections.NewStore().Create(t.Context(), env.pool, connections.CreateParams{
		DisplayName: "itest-postgres-authority-gate-" + uuid.NewString(),
		Engine:      "postgres",
		Environment: "itest",
		Endpoints:   []string{"itest-target:5432"},
	})
	if err != nil {
		t.Fatalf("create postgres connection: %v", err)
	}
	activateConnection(t, env.pool, conn.ID)
	seedFakeInventory(t, env.pool, conn.ID)
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("get active postgres connection: %v", err)
	}

	// Simulate a current PostgreSQL discovery projection that retains
	// inventory/access but has no confirmed SUPERUSER authority. No target
	// service is needed: the fail-closed gate must run before Vault or jobs.
	filtered := make([]string, 0, len(conn.Capabilities))
	for _, capability := range conn.Capabilities {
		if capability != string(adapter.CapAccountCreate) {
			filtered = append(filtered, capability)
		}
	}
	capabilitiesJSON, err := json.Marshal(filtered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set capabilities=$2 where id=$1`,
		conn.ID, capabilitiesJSON); err != nil {
		t.Fatalf("remove effective account.create: %v", err)
	}

	var accountsBefore, operationsBefore int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from accounts where connection_id=$1`, conn.ID).
		Scan(&accountsBefore); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).
		Scan(&operationsBefore); err != nil {
		t.Fatal(err)
	}
	identity := "blocked_" + uniqueSuffix()[:8]
	resp := env.do(t, http.MethodPost, "/api/v1/accounts", map[string]any{
		"connection_id": conn.ID, "engine_identity": identity,
		"credential": map[string]any{"mode": "generated"},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	principal := createPrincipalRow(t, env.pool, "Blocked implicit account")
	permission := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access", map[string]any{
		"engine_identity": identity,
		"items":           []map[string]any{{"connection_id": conn.ID, "permission_id": permission.ID}},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	var accountsAfter, operationsAfter int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from accounts where connection_id=$1`, conn.ID).
		Scan(&accountsAfter); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).
		Scan(&operationsAfter); err != nil {
		t.Fatal(err)
	}
	if accountsAfter != accountsBefore || operationsAfter != operationsBefore {
		t.Fatalf("blocked create left metadata: accounts %d->%d operations %d->%d",
			accountsBefore, accountsAfter, operationsBefore, operationsAfter)
	}

	// Membership grant to an account that already exists is independent from
	// the creation authority and must remain available.
	existing := findAccount(t, env.pool, conn.ID, "svc-a")
	resp = env.do(t, http.MethodPost, "/api/v1/bindings", map[string]any{
		"account_id": existing.ID, "permission_id": permission.ID,
	}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
}

func TestIntegrationPostgresLegacyCreationAPIsRejectStaleCapabilities(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)
	staleCapabilities, err := json.Marshal([]string{
		string(adapter.CapAccountCreate), string(adapter.CapAccountRestore),
		string(adapter.CapRoleCreate), string(adapter.ResourceCapability("create", "database")),
		string(adapter.CapRolePolicyApply), string(adapter.CapRolePolicyCreate),
		string(adapter.CapInventoryAccounts), string(adapter.CapAccessGrant), string(adapter.CapAccessRevoke),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connections set engine='postgres', capabilities=$2,
		updated_at=now() where id=$1`, conn.ID, staleCapabilities); err != nil {
		t.Fatalf("seed stale PostgreSQL capabilities: %v", err)
	}
	conn, err = connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	tombstone := managedAccount(t, env.pool, conn.ID, "accounts/legacy-restore/credential")
	if err := inventory.NewStore().MarkAccountDeleted(t.Context(), env.pool, tombstone.ID, "test", "legacy fence"); err != nil {
		t.Fatal(err)
	}
	tombstone = accountRow(t, env.pool, tombstone.ID)

	var accountsBefore, resourcesBefore, operationsBefore int
	for query, dst := range map[string]*int{
		`select count(*) from accounts where connection_id=$1`:   &accountsBefore,
		`select count(*) from resources where connection_id=$1`:  &resourcesBefore,
		`select count(*) from operations where connection_id=$1`: &operationsBefore,
	} {
		if err := env.pool.QueryRow(t.Context(), query, conn.ID).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}

	requests := []struct {
		name string
		path string
		body any
	}{
		{name: "account", path: "/api/v1/accounts", body: map[string]any{
			"connection_id": conn.ID, "engine_identity": "legacy_login_" + uniqueSuffix()[:8],
			"credential": map[string]any{"mode": "generated"},
		}},
		{name: "restore", path: "/api/v1/accounts/" + tombstone.ID.String() + "/restore", body: map[string]any{
			"credential": map[string]any{"mode": "provided", "password": "legacy-restore-password"},
		}},
		{name: "role", path: "/api/v1/connections/" + conn.ID.String() + "/roles", body: map[string]any{
			"name": "legacy_role_" + uniqueSuffix()[:8],
		}},
		{name: "database", path: "/api/v1/connections/" + conn.ID.String() + "/resources", body: map[string]any{
			"kind": "database", "name": "legacy_db_" + uniqueSuffix()[:8],
		}},
		{name: "policy", path: "/api/v1/connections/" + conn.ID.String() + "/role-policies/legacy/create", body: map[string]any{
			"request_id": uuid.New(), "version": 0, "observed_fingerprint": "missing", "confirm": true,
			"expected_target_identity": "postgres:system:stale",
		}},
		{name: "database with roles", path: "/api/v1/connections/" + conn.ID.String() + "/resources/database-with-roles", body: map[string]any{
			"kind": "database", "name": "legacy_pair_" + uniqueSuffix()[:8], "owner": "app_owner",
			"create_default_roles": true, "request_id": uuid.New(), "updated_at": conn.UpdatedAt,
			"expected_target_identity": "postgres:system:stale",
		}},
	}
	for _, request := range requests {
		t.Run(request.name, func(t *testing.T) {
			resp := env.do(t, http.MethodPost, request.path, request.body, &admin, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}

	var accountsAfter, resourcesAfter, operationsAfter int
	for query, dst := range map[string]*int{
		`select count(*) from accounts where connection_id=$1`:   &accountsAfter,
		`select count(*) from resources where connection_id=$1`:  &resourcesAfter,
		`select count(*) from operations where connection_id=$1`: &operationsAfter,
	} {
		if err := env.pool.QueryRow(t.Context(), query, conn.ID).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	if accountsAfter != accountsBefore || resourcesAfter != resourcesBefore || operationsAfter != operationsBefore {
		t.Fatalf("legacy API fence left metadata: accounts %d->%d resources %d->%d operations %d->%d",
			accountsBefore, accountsAfter, resourcesBefore, resourcesAfter, operationsBefore, operationsAfter)
	}
}

func TestIntegrationRestoreAccountAPI(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	store := inventory.NewStore()

	newTombstone := func(t *testing.T) inventory.Account {
		t.Helper()
		acct := managedAccount(t, env.pool, conn.ID, "")
		if err := store.MarkAccountDeleted(t.Context(), env.pool, acct.ID, "seed", "restore test"); err != nil {
			t.Fatalf("mark tombstone: %v", err)
		}
		return acct
	}

	provided := newTombstone(t)
	base := "/api/v1/accounts/" + provided.ID.String() + "/restore"
	const password = "restore-provided-secret-marker"
	body := map[string]any{"credential": map[string]any{"mode": "provided", "password": password}}

	resp := env.do(t, http.MethodPost, base, body, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, base, body, &admin, false)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, base, body, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), password) || strings.Contains(string(raw), "link") {
		t.Fatal("restore response leaks credential material")
	}
	var out struct {
		AccountID   uuid.UUID `json:"account_id"`
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode restore response: %v", err)
	}
	if out.AccountID != provided.ID || out.OperationID == uuid.Nil {
		t.Fatalf("restore ids = %s/%s, want account %s and operation", out.AccountID, out.OperationID, provided.ID)
	}

	acct, err := store.GetAccount(t.Context(), env.pool, provided.ID)
	if err != nil {
		t.Fatalf("get reserved tombstone: %v", err)
	}
	if acct.Status != inventory.AccountDeleted || acct.LifecycleVersion != 1 || acct.PrincipalID != nil {
		t.Errorf("reserved metadata = status %q version %d principal %v; want deleted/1/nil",
			acct.Status, acct.LifecycleVersion, acct.PrincipalID)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get restore operation: %v", err)
	}
	var payload jobs.AccountPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		t.Fatalf("decode restore payload: %v", err)
	}
	if op.Kind != jobs.KindAccountRestore || payload.ExpectedStatus != inventory.AccountDeleted ||
		payload.ExpectedLifecycleVersion != 1 || payload.CredentialVaultVersion <= 0 ||
		payload.CredentialMode != inventory.CredentialModeProvided {
		t.Errorf("restore operation/payload = %q %+v", op.Kind, payload)
	}
	if strings.Contains(string(op.Payload), password) || strings.Contains(string(op.Payload), "accounts/") {
		t.Fatal("restore operation payload leaks password or Vault path")
	}
	secretData, secretVersion, err := vaultClient.Get(t.Context(), "accounts/"+provided.ID.String()+"/credential")
	if err != nil {
		t.Fatalf("get restore credential: %v", err)
	}
	if secretVersion != payload.CredentialVaultVersion || secretData["username"] != provided.EngineIdentity || secretData["password"] != password {
		t.Error("restore credential is not pinned to the intended identity/password version")
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &provided.ID, Actions: []string{"account.restore_requested"},
	}, 10, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("restore requested audit = %d, %v; want one", len(events), err)
	}
	if strings.Contains(string(events[0].Metadata), password) || strings.Contains(string(events[0].Metadata), "accounts/") {
		t.Fatal("restore audit leaks credential material")
	}

	// Pending restore owns the lifecycle reservation; duplicate request is
	// serialized to 409 and cannot advance the generation or enqueue again.
	resp = env.do(t, http.MethodPost, base, body, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	afterDuplicate, err := store.GetAccount(t.Context(), env.pool, provided.ID)
	if err != nil || afterDuplicate.LifecycleVersion != 1 {
		t.Fatalf("duplicate lifecycle version = %d, %v; want 1", afterDuplicate.LifecycleVersion, err)
	}

	generated := newTombstone(t)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+generated.ID.String()+"/restore",
		map[string]any{"credential": map[string]any{"mode": "generated"}}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	generatedRaw := readBody(t, resp)
	generatedData, _, err := vaultClient.Get(t.Context(), "accounts/"+generated.ID.String()+"/credential")
	if err != nil {
		t.Fatalf("get generated restore credential: %v", err)
	}
	generatedPassword, _ := generatedData["password"].(string)
	if generatedPassword == "" || strings.Contains(string(generatedRaw), generatedPassword) {
		t.Fatal("generated restore credential missing or leaked")
	}

	// Linked tombstone восстанавливается с актуальной версией общего секрета
	// глобального пользователя. Principal link и shared path не теряются, а
	// собственный account credential не создаётся.
	principal, err := principals.NewStore().Create(t.Context(), env.pool, principals.CreateParams{
		Type: principals.TypeHuman, DisplayName: "restore principal " + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create restore principal: %v", err)
	}
	credSvc := credentials.NewService(vaultClient, nil)
	if _, err := credSvc.RotatePrincipalCredential(t.Context(), principal.ID, conn.Environment,
		[]byte("principal-password-before-delete")); err != nil {
		t.Fatalf("seed principal credential: %v", err)
	}
	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), conn.Environment)
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	linked := managedAccount(t, env.pool, conn.ID, "")
	if _, err := env.pool.Exec(t.Context(), `
		update accounts set principal_id = $2, credential_mode = 'existing_vault_ref', vault_path = $3
		where id = $1`, linked.ID, principal.ID, sharedPath); err != nil {
		t.Fatalf("link restore account: %v", err)
	}
	if err := store.MarkAccountDeleted(t.Context(), env.pool, linked.ID, "seed", "linked restore test"); err != nil {
		t.Fatalf("mark linked tombstone: %v", err)
	}
	wantVersion, err := credSvc.RotatePrincipalCredential(t.Context(), principal.ID, conn.Environment,
		[]byte("principal-password-after-delete"))
	if err != nil {
		t.Fatalf("rotate principal credential: %v", err)
	}
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+linked.ID.String()+"/restore",
		map[string]any{"credential": map[string]any{"mode": "existing_vault_ref"}}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var linkedOut struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(readBody(t, resp), &linkedOut); err != nil {
		t.Fatalf("decode linked restore response: %v", err)
	}
	linkedOp, err := operations.NewStore().Get(t.Context(), env.pool, linkedOut.OperationID)
	if err != nil {
		t.Fatalf("get linked restore operation: %v", err)
	}
	var linkedPayload jobs.AccountPayload
	if err := json.Unmarshal(linkedOp.Payload, &linkedPayload); err != nil {
		t.Fatalf("decode linked restore payload: %v", err)
	}
	if linkedOp.PrincipalID == nil || *linkedOp.PrincipalID != principal.ID ||
		linkedPayload.CredentialMode != inventory.CredentialModeExistingVaultRef ||
		linkedPayload.SharedCredentialPath != sharedPath ||
		linkedPayload.CredentialVaultVersion != wantVersion {
		t.Errorf("linked restore operation = principal %v payload %+v", linkedOp.PrincipalID, linkedPayload)
	}
	linkedReserved, err := store.GetAccount(t.Context(), env.pool, linked.ID)
	if err != nil || linkedReserved.PrincipalID == nil || *linkedReserved.PrincipalID != principal.ID ||
		linkedReserved.VaultPath != sharedPath || linkedReserved.Status != inventory.AccountDeleted {
		t.Errorf("linked reserved tombstone = %+v, err=%v", linkedReserved, err)
	}

	active := managedAccount(t, env.pool, conn.ID, "")
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+active.ID.String()+"/restore",
		map[string]any{"credential": map[string]any{"mode": "generated"}}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, base,
		map[string]any{"credential": map[string]any{"mode": "provided", "password": "short"}}, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)

	withoutCapability, err := connections.NewStore().Update(t.Context(), env.pool, conn.ID, connections.UpdateParams{
		DisplayName: conn.DisplayName, Environment: conn.Environment, Tags: conn.Tags,
		Endpoints: conn.Endpoints, TLSConfig: conn.TLSConfig, DiscoveryConfig: conn.DiscoveryConfig,
		Capabilities: nil,
	})
	if err != nil || len(withoutCapability.Capabilities) != 0 {
		t.Fatalf("disable restore capability: %v, capabilities=%v", err, withoutCapability.Capabilities)
	}
	unsupported := newTombstone(t)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+unsupported.ID.String()+"/restore",
		map[string]any{"credential": map[string]any{"mode": "generated"}}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationRestoreVaultFailureRollsBackReservation(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "")
	if err := inventory.NewStore().MarkAccountDeleted(t.Context(), env.pool, acct.ID, "seed", "vault failure"); err != nil {
		t.Fatalf("mark tombstone: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/restore",
		map[string]any{"credential": map[string]any{"mode": "generated"}}, &admin, true)
	requireStatus(t, resp, http.StatusServiceUnavailable)
	after, err := inventory.NewStore().GetAccount(t.Context(), env.pool, acct.ID)
	if err != nil {
		t.Fatalf("get tombstone after Vault failure: %v", err)
	}
	if after.Status != inventory.AccountDeleted || after.LifecycleVersion != 0 {
		t.Errorf("Vault failure metadata = %q/v%d, want deleted/v0", after.Status, after.LifecycleVersion)
	}
}

func TestIntegrationPendingDeleteBlocksGrantShareAndLink(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "accounts/pending-delete/credential")
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	principal := createPrincipalRow(t, env.pool, "Pending Delete Principal")

	resp := env.do(t, http.MethodDelete,
		"/api/v1/accounts/"+acct.ID.String()+"?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)

	resp = env.do(t, http.MethodPost, "/api/v1/bindings",
		map[string]any{"account_id": acct.ID, "permission_id": perm.ID}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/link",
		map[string]any{"principal_id": principal.ID}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	bindings, err := inventory.NewStore().ListBindingsByAccount(t.Context(), env.pool, acct.ID)
	if err != nil {
		t.Fatalf("list bindings after blocked grant: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("blocked grant created %d bindings", len(bindings))
	}
	after, err := inventory.NewStore().GetAccount(t.Context(), env.pool, acct.ID)
	if err != nil {
		t.Fatalf("get account after blocked synchronous actions: %v", err)
	}
	if after.PrincipalID != nil || after.LifecycleVersion != 1 || after.Status != inventory.AccountActive {
		t.Errorf("pending delete metadata changed: principal=%v version=%d status=%q",
			after.PrincipalID, after.LifecycleVersion, after.Status)
	}
}

// managedAccount создаёт managed account напрямую через store (без Vault
// и worker) для сценариев disable/enable/rotate/delete/share.
func managedAccount(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID, vaultPath string) inventory.Account {
	t.Helper()
	acct, err := inventory.NewStore().CreateManagedAccount(context.Background(), pool, inventory.CreateManagedAccountParams{
		ConnectionID:   connID,
		EngineIdentity: "itest_mgd_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8],
		CredentialMode: "generated",
		VaultPath:      vaultPath,
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	return acct
}

func TestIntegrationAccountOperations(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "accounts/fake/credential")
	base := "/api/v1/accounts/" + acct.ID.String()

	expectOperation := func(t *testing.T, resp *http.Response, wantKind string) {
		t.Helper()
		var out struct {
			OperationID uuid.UUID `json:"operation_id"`
			AccountID   uuid.UUID `json:"account_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
		if err != nil {
			t.Fatalf("get operation: %v", err)
		}
		if op.Kind != wantKind || op.Status != operations.StatusPending {
			t.Errorf("operation kind/status = %q/%q, want %s/pending", op.Kind, op.Status, wantKind)
		}
		if op.AccountID == nil || *op.AccountID != acct.ID {
			t.Errorf("operation account_id = %v, want %s", op.AccountID, acct.ID)
		}
	}

	resp := env.do(t, http.MethodPost, base+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	expectOperation(t, resp, jobs.KindAccountDisable)

	acct = managedAccount(t, env.pool, conn.ID, "accounts/fake-enable/credential")
	if err := inventory.NewStore().SetAccountStatus(t.Context(), env.pool, acct.ID, inventory.AccountDisabled); err != nil {
		t.Fatalf("seed disabled account: %v", err)
	}
	base = "/api/v1/accounts/" + acct.ID.String()
	resp = env.do(t, http.MethodPost, base+"/enable", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	expectOperation(t, resp, jobs.KindAccountEnable)

	acct = managedAccount(t, env.pool, conn.ID, "accounts/fake-rotate/credential")
	base = "/api/v1/accounts/" + acct.ID.String()
	resp = env.do(t, http.MethodPost, base+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	expectOperation(t, resp, jobs.KindCredentialRotate)

	acct = managedAccount(t, env.pool, conn.ID, "accounts/fake-delete/credential")
	base = "/api/v1/accounts/" + acct.ID.String()

	// Удаление: operator — 403 (роль admin), без confirm — 400, причина
	// длиннее 500 символов — 400, admin с confirm — 202. Необязательная
	// причина из тела {"reason":"..."} попадает (обрезанная по краям) в
	// payload операции account.delete.
	resp = env.do(t, http.MethodDelete, base+"?confirm=true", nil, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodDelete, base, nil, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodDelete, base+"?confirm=true",
		map[string]any{"reason": strings.Repeat("r", 501)}, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodDelete, base+"?confirm=true",
		map[string]any{"reason": "  duplicate of shared service role  "}, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var delOut struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&delOut); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	delOp, err := operations.NewStore().Get(t.Context(), env.pool, delOut.OperationID)
	if err != nil {
		t.Fatalf("get delete operation: %v", err)
	}
	if delOp.Kind != jobs.KindAccountDelete || delOp.Status != operations.StatusPending {
		t.Errorf("delete operation kind/status = %q/%q, want %s/pending", delOp.Kind, delOp.Status, jobs.KindAccountDelete)
	}
	var delPayload jobs.AccountPayload
	if err := json.Unmarshal(delOp.Payload, &delPayload); err != nil {
		t.Fatalf("unmarshal delete payload: %v", err)
	}
	if delPayload.Reason != "duplicate of shared service role" {
		t.Errorf("delete payload reason = %q, want trimmed reason", delPayload.Reason)
	}

	// Unmanaged-аккаунт из discovery управлению не подлежит — 409.
	unmanaged := findAccount(t, env.pool, conn.ID, "svc-a")
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+unmanaged.ID.String()+"/disable", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Rotate без сохранённого credential допустим: у аккаунта, принятого
	// через adopt mode=metadata, первую версию секрета создаёт именно первая
	// ротация — операция ставится как обычно (202).
	bare := managedAccount(t, env.pool, conn.ID, "")
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+bare.ID.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
}

func TestIntegrationShareWithoutYopass(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	acct := managedAccount(t, env.pool, conn.ID, "accounts/fake/credential")

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusServiceUnavailable)
}

func TestIntegrationShareWithYopass(t *testing.T) {
	vaultClient := newTestVault(t)
	yopassAddr := os.Getenv("GRANTOR_TEST_YOPASS_ADDR")
	if yopassAddr == "" {
		t.Skip("GRANTOR_TEST_YOPASS_ADDR is not set; skipping share integration test")
	}
	yopassClient, err := yopass.New(yopass.Config{APIURL: yopassAddr, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("yopass.New: %v", err)
	}
	env := newTestEnvWithYopass(t, vaultClient, yopassClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)

	// Managed account с реальным credential в Vault.
	acct := managedAccount(t, env.pool, conn.ID, "")
	const password = "itest-share-secret-marker"
	credSvc := credentials.NewService(vaultClient, nil)
	_, path, err := credSvc.PutAccountCredential(t.Context(), acct.ID, acct.EngineIdentity, []byte(password))
	if err != nil {
		t.Fatalf("put account credential: %v", err)
	}
	if err := inventory.NewStore().SetAccountVaultPath(t.Context(), env.pool, acct.ID, path); err != nil {
		t.Fatalf("set vault path: %v", err)
	}

	sharePath := "/api/v1/accounts/" + acct.ID.String() + "/share"
	resp := env.do(t, http.MethodPost, sharePath, nil, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, sharePath, nil, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	raw := readBody(t, resp)
	var out struct {
		Link           string `json:"link"`
		ExpiresInHours int    `json:"expires_in_hours"`
		OneTime        bool   `json:"one_time"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal share response: %v", err)
	}
	if !strings.HasPrefix(out.Link, "http://localhost:58090/#/s/") {
		t.Errorf("link = %q, want yopass web format", out.Link)
	}
	if out.ExpiresInHours != 24 || !out.OneTime {
		t.Errorf("share params = %d/%v, want 24/true", out.ExpiresInHours, out.OneTime)
	}
	if strings.Contains(string(raw), password) {
		t.Fatal("share response leaks password in plaintext")
	}

	// Audit фиксирует факт выдачи, но не ссылку и не секрет.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &acct.ID,
		Actions:   []string{"credential_shared"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("credential_shared events = %d, want 1", len(events))
	}
	metadata := string(events[0].Metadata)
	if strings.Contains(metadata, out.Link) || strings.Contains(metadata, password) {
		t.Error("audit metadata leaks link or password")
	}
	var meta struct {
		Channel string `json:"channel"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.Channel != "yopass" {
		t.Errorf("audit metadata %s misses channel (err=%v)", metadata, err)
	}
}
