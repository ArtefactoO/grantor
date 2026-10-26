//go:build integration

// Integration-тесты principal-centric выдачи доступа. Проверяется
// API-слой на fake adapter (worker не запускается): RBAC, dangerous-
// контроль, созданные аккаунты с общим секретом принципала и корректная
// per-environment привязка vault_path. Сквозной цикл с реальным
// провижинингом и логином — в internal/jobs/principal_access_integration_test.go.
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// activeFakeConnectionEnv — активное fake-подключение в заданном окружении
// со сведённым инвентарём.
func activeFakeConnectionEnv(t *testing.T, pool *pgxpool.Pool, env string) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(context.Background(), pool, connections.CreateParams{
		DisplayName: "itest-api-" + uuid.NewString(),
		Engine:      fake.Engine,
		Environment: env,
		Endpoints:   []string{"itest-target:5432"},
	})
	if err != nil {
		t.Fatalf("create draft connection: %v", err)
	}
	activateConnection(t, pool, conn.ID)
	seedFakeInventory(t, pool, conn.ID)
	return conn
}

// createPrincipalRow создаёт принципала напрямую через store.
func createPrincipalRow(t *testing.T, pool *pgxpool.Pool, displayName string) principals.Principal {
	t.Helper()
	p, err := principals.NewStore().Create(context.Background(), pool, principals.CreateParams{
		Type:        principals.TypeService,
		DisplayName: displayName,
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	return p
}

// principalAccessChildBody — дочерний результат ответа /access.
type principalAccessChildBody struct {
	ConnectionID             uuid.UUID  `json:"connection_id"`
	Environment              string     `json:"environment"`
	AccountID                uuid.UUID  `json:"account_id"`
	CredentialMode           string     `json:"credential_mode"`
	AccountCreated           bool       `json:"account_created"`
	AccountCreateOperationID *uuid.UUID `json:"account_create_operation_id"`
	GrantOperationID         uuid.UUID  `json:"grant_operation_id"`
	BindingID                uuid.UUID  `json:"binding_id"`
}

func TestIntegrationPrincipalAccessSharedPerEnvironment(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)

	principal := createPrincipalRow(t, env.pool, "Payments Service")

	// Два подключения окружения test и одно окружения prod.
	connTestA := activeFakeConnectionEnv(t, env.pool, "test")
	connTestB := activeFakeConnectionEnv(t, env.pool, "test")
	connProd := activeFakeConnectionEnv(t, env.pool, "prod")
	permA := findPermission(t, env.pool, connTestA.ID, "role:app-readonly")
	permB := findPermission(t, env.pool, connTestB.ID, "role:app-readonly")
	permProd := findPermission(t, env.pool, connProd.ID, "role:app-readonly")

	identity := "itest_pr_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	body := map[string]any{
		"engine_identity": identity,
		"items": []map[string]any{
			{"connection_id": connTestA.ID, "permission_id": permA.ID},
			{"connection_id": connTestB.ID, "permission_id": permB.ID},
			{"connection_id": connProd.ID, "permission_id": permProd.ID},
		},
	}
	path := "/api/v1/principals/" + principal.ID.String() + "/access"

	// viewer не может выдавать доступ; без CSRF мутация отклоняется.
	resp := env.do(t, http.MethodPost, path, body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, path, body, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out struct {
		OperationID uuid.UUID                  `json:"operation_id"`
		Children    []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode access response: %v", err)
	}
	if len(out.Children) != 3 {
		t.Fatalf("children = %d, want 3", len(out.Children))
	}

	parent, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get parent operation: %v", err)
	}
	if parent.Kind != jobs.KindBulkPrincipalAccess || parent.Status != operations.StatusRunning {
		t.Errorf("parent kind/status = %q/%q, want bulk.principal_access/running", parent.Kind, parent.Status)
	}
	if parent.PrincipalID == nil || *parent.PrincipalID != principal.ID {
		t.Errorf("parent principal_id = %v, want %s", parent.PrincipalID, principal.ID)
	}

	wantTestPath := "principals/" + principal.ID.String() + "/environments/test/credential"
	wantProdPath := "principals/" + principal.ID.String() + "/environments/prod/credential"

	invStore := inventory.NewStore()
	pathByConn := map[uuid.UUID]string{
		connTestA.ID: wantTestPath,
		connTestB.ID: wantTestPath,
		connProd.ID:  wantProdPath,
	}
	accountByConn := make(map[uuid.UUID]uuid.UUID, len(out.Children))
	for _, child := range out.Children {
		accountByConn[child.ConnectionID] = child.AccountID
		acct, err := invStore.GetAccount(t.Context(), env.pool, child.AccountID)
		if err != nil {
			t.Fatalf("get account: %v", err)
		}
		if acct.PrincipalID == nil || *acct.PrincipalID != principal.ID {
			t.Errorf("account principal_id = %v, want %s", acct.PrincipalID, principal.ID)
		}
		if acct.CredentialMode == nil || *acct.CredentialMode != "existing_vault_ref" {
			t.Errorf("account credential_mode = %v, want existing_vault_ref", acct.CredentialMode)
		}
		if acct.EngineIdentity != identity {
			t.Errorf("account engine_identity = %q, want %q", acct.EngineIdentity, identity)
		}
		if want := pathByConn[child.ConnectionID]; acct.VaultPath != want {
			t.Errorf("connection %s account vault_path = %q, want %q", child.ConnectionID, acct.VaultPath, want)
		}
		if child.CredentialMode != "existing_vault_ref" {
			t.Errorf("child credential_mode = %q, want existing_vault_ref", child.CredentialMode)
		}
		if !child.AccountCreated || child.AccountCreateOperationID == nil {
			t.Errorf("child %s: account_created=%v op=%v, want created with op",
				child.ConnectionID, child.AccountCreated, child.AccountCreateOperationID)
		}

		// account.create — дочерняя операция parent, в статусе pending
		// (worker не запущен).
		createOp, err := operations.NewStore().Get(t.Context(), env.pool, *child.AccountCreateOperationID)
		if err != nil {
			t.Fatalf("get account.create op: %v", err)
		}
		if createOp.Kind != jobs.KindAccountCreate || createOp.Status != operations.StatusPending {
			t.Errorf("account.create op kind/status = %q/%q, want account.create/pending", createOp.Kind, createOp.Status)
		}
		if createOp.ParentID == nil || *createOp.ParentID != parent.ID {
			t.Errorf("account.create op parent = %v, want %s", createOp.ParentID, parent.ID)
		}

		// Binding под управлением сервиса с desired present.
		binding, err := invStore.GetBinding(t.Context(), env.pool, child.BindingID)
		if err != nil {
			t.Fatalf("get binding: %v", err)
		}
		if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingPresent {
			t.Errorf("binding desired = %v, want present", binding.DesiredState)
		}
	}

	// Аккаунты test-окружения делят один секрет; prod — независимый.
	testData, _, err := vaultClient.Get(t.Context(), wantTestPath)
	if err != nil {
		t.Fatalf("vault get test secret: %v", err)
	}
	prodData, _, err := vaultClient.Get(t.Context(), wantProdPath)
	if err != nil {
		t.Fatalf("vault get prod secret: %v", err)
	}
	testPw, _ := testData["password"].(string)
	prodPw, _ := prodData["password"].(string)
	if testPw == "" || prodPw == "" {
		t.Fatalf("empty shared secret: test empty=%v prod empty=%v", testPw == "", prodPw == "")
	}
	if testPw == prodPw {
		t.Error("shared secrets of different environments are identical")
	}
	finishProvisionChildren(t, env, out.Children)

	// Точно такое же назначение не создаёт вторую операцию.
	resp = env.do(t, http.MethodPost, path, map[string]any{
		"engine_identity": identity,
		"items": []map[string]any{
			{"connection_id": connTestA.ID, "permission_id": permA.ID},
		},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Ротация ограничена environment=test. Аккаунт, ранее отвязанный от
	// общего секрета (rotate {"detach":true} — собственный vault_path и
	// credential_mode=generated), в неё НЕ попадает: отвязка durable, а
	// обратный путь — явный rotate {"attach":true}. Prod-аккаунт в children
	// тоже не попадает, и его Vault-версия не меняется.
	testAAccountID := accountByConn[connTestA.ID]
	if _, err := env.pool.Exec(t.Context(), `
		update accounts set credential_mode = 'generated', vault_path = $2 where id = $1`,
		testAAccountID, "accounts/"+testAAccountID.String()+"/credential"); err != nil {
		t.Fatalf("mark account as locally rotated: %v", err)
	}
	_, prodVersionBefore, err := vaultClient.Get(t.Context(), wantProdPath)
	if err != nil {
		t.Fatalf("vault get prod before scoped rotation: %v", err)
	}
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/rotate?environment=test",
		nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var rotated struct {
		Children []struct {
			ConnectionID uuid.UUID `json:"connection_id"`
			OperationID  uuid.UUID `json:"operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode scoped rotate response: %v", err)
	}
	if len(rotated.Children) != 1 {
		t.Fatalf("scoped rotate children = %d, want only the account still on the shared secret",
			len(rotated.Children))
	}
	for _, child := range rotated.Children {
		if child.ConnectionID == connProd.ID {
			t.Fatal("prod connection was included in test rotation")
		}
		if child.ConnectionID == connTestA.ID {
			t.Fatal("detached account was silently pulled back onto the shared secret")
		}
		op, err := operations.NewStore().Get(t.Context(), env.pool, child.OperationID)
		if err != nil {
			t.Fatalf("get rotate child: %v", err)
		}
		if op.PrincipalID == nil || *op.PrincipalID != principal.ID {
			t.Errorf("rotate child principal = %v, want %s", op.PrincipalID, principal.ID)
		}
		var payload jobs.AccountPayload
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			t.Fatalf("decode rotate child payload: %v", err)
		}
		if payload.SharedCredentialPath != wantTestPath {
			t.Errorf("rotate child shared path = %q, want %q", payload.SharedCredentialPath, wantTestPath)
		}
	}
	_, prodVersionAfter, err := vaultClient.Get(t.Context(), wantProdPath)
	if err != nil {
		t.Fatalf("vault get prod after scoped rotation: %v", err)
	}
	if prodVersionAfter != prodVersionBefore {
		t.Errorf("prod vault version changed during test rotation: %d -> %d", prodVersionBefore, prodVersionAfter)
	}

	// После явной отвязки тот же managed account больше нельзя молча
	// переиспользовать от имени принципала: иначе target получит роль, а в
	// профиле пользователя не будет ни аккаунта, ни назначения.
	if _, err := invStore.LinkAccountPrincipal(t.Context(), env.pool, testAAccountID, nil); err != nil {
		t.Fatalf("unlink reused account: %v", err)
	}
	resp = env.do(t, http.MethodPost, path, map[string]any{
		"engine_identity": identity,
		"items": []map[string]any{
			{"connection_id": connTestA.ID, "permission_id": permA.ID},
		},
	}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
}

func TestIntegrationPrincipalAccessMultipleRolesSameConnection(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	principal := createPrincipalRow(t, env.pool, "Granular Access Service")
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	readOnly := findPermission(t, env.pool, conn.ID, "role:app-readonly")
	readWrite := findPermission(t, env.pool, conn.ID, "role:app-readwrite")

	body := map[string]any{
		"items": []map[string]any{
			{"connection_id": conn.ID, "permission_id": readOnly.ID},
			{"connection_id": conn.ID, "permission_id": readWrite.ID},
		},
	}
	resp := env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/access", body, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)

	var out struct {
		OperationID uuid.UUID                  `json:"operation_id"`
		Children    []principalAccessChildBody `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode access response: %v", err)
	}
	if len(out.Children) != 2 {
		t.Fatalf("children = %d, want one granular grant per selected role", len(out.Children))
	}
	if out.Children[0].AccountID != out.Children[1].AccountID {
		t.Fatalf("roles use different accounts: %s and %s", out.Children[0].AccountID, out.Children[1].AccountID)
	}

	wantPermissions := map[uuid.UUID]bool{readOnly.ID: false, readWrite.ID: false}
	createdAccounts := 0
	invStore := inventory.NewStore()
	for _, child := range out.Children {
		if child.AccountCreated {
			createdAccounts++
		}
		binding, err := invStore.GetBinding(t.Context(), env.pool, child.BindingID)
		if err != nil {
			t.Fatalf("get binding %s: %v", child.BindingID, err)
		}
		if _, expected := wantPermissions[binding.PermissionDefinitionID]; !expected {
			t.Errorf("unexpected permission binding %s", binding.PermissionDefinitionID)
		} else {
			wantPermissions[binding.PermissionDefinitionID] = true
		}
		requireOperation(t, env, child.GrantOperationID, jobs.KindAccessGrant, operations.StatusPending, &out.OperationID)
	}
	if createdAccounts != 1 {
		t.Errorf("accounts created = %d, want one shared account", createdAccounts)
	}
	for permissionID, seen := range wantPermissions {
		if !seen {
			t.Errorf("selected permission %s did not get its own binding", permissionID)
		}
	}
}

func TestIntegrationPrincipalAccessDangerous(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	principal := createPrincipalRow(t, env.pool, "Ops Service")
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")
	path := "/api/v1/principals/" + principal.ID.String() + "/access"

	item := map[string]any{"connection_id": conn.ID, "permission_id": dangerous.ID}
	withConfirm := map[string]any{"items": []map[string]any{item}, "confirm": true}
	without := map[string]any{"items": []map[string]any{item}}

	// operator не может выдавать dangerous даже с confirm.
	resp := env.do(t, http.MethodPost, path, withConfirm, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	// admin без confirm — 400.
	resp = env.do(t, http.MethodPost, path, without, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
	// admin с confirm — 202.
	resp = env.do(t, http.MethodPost, path, withConfirm, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
}

func TestIntegrationPrincipalAccessWithoutVault(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	principal := createPrincipalRow(t, env.pool, "No Vault Service")
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	perm := findPermission(t, env.pool, conn.ID, "role:app-readonly")

	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/access",
		map[string]any{"items": []map[string]any{{"connection_id": conn.ID, "permission_id": perm.ID}}},
		&operator, true)
	requireStatus(t, resp, http.StatusServiceUnavailable)
}

func TestIntegrationPrincipalShareWithoutYopass(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	principal := createPrincipalRow(t, env.pool, "Share Service")

	// environment обязателен.
	resp := env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Yopass не сконфигурирован — 503.
	resp = env.do(t, http.MethodPost, "/api/v1/principals/"+principal.ID.String()+"/share?environment=test", nil, &operator, true)
	requireStatus(t, resp, http.StatusServiceUnavailable)
}
