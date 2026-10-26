//go:build integration

// Сквозной e2e-тест осознанного выбора при ротации против реального целевого
// PostgreSQL (GRANTOR_TEST_TARGET_PG_DSN) с полноценным River worker: каждый
// шаг проверяется НАСТОЯЩИМ логином в целевую систему, а не только строкой в
// metadata. Именно на живом стенде обнаружилось, что ротация аккаунта на
// общем секрете принципала молча уводит его на персональный пароль, оставляя
// общий секрет и /principals/{id}/share со старым, уже мёртвым значением.
package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// targetLoginOK — учётная запись реально логинится в целевой PostgreSQL с
// этим паролем. Единственная честная проверка «пароль рабочий»: metadata и
// Vault могут быть согласованы между собой и при этом расходиться с целью.
func targetLoginOK(ctx context.Context, t *testing.T, adminDSN, user, password string) bool {
	t.Helper()
	cc, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse target dsn: %v", err)
	}
	cc.User = user
	cc.Password = password
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(connectCtx, cc)
	if err != nil {
		return false
	}
	defer conn.Close(ctx) //nolint:errcheck
	return conn.Ping(connectCtx) == nil
}

// vaultPassword читает значение пароля по пути Vault.
func vaultPassword(t *testing.T, client *vault.Client, path string) string {
	t.Helper()
	data, _, err := client.Get(t.Context(), path)
	if err != nil {
		t.Fatalf("vault get %s: %v", path, err)
	}
	password, _ := data["password"].(string)
	if password == "" {
		t.Fatalf("vault path %s has no password", path)
	}
	return password
}

// createTargetPGConnection создаёт через API подключение к целевому
// PostgreSQL и доводит его до active (refresh + discovery worker).
func createTargetPGConnection(t *testing.T, env *testEnv, admin, operator auth.Session,
	targetDSN, environment, displayName string) uuid.UUID {
	t.Helper()
	cc, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	discoveryConfig, err := json.Marshal(map[string]string{"database": cc.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections", map[string]any{
		"display_name":     displayName,
		"engine":           postgres.Engine,
		"environment":      environment,
		"endpoints":        []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		"tls_config":       map[string]string{"mode": "disabled"},
		"discovery_config": json.RawMessage(discoveryConfig),
		"admin_credential": map[string]string{"username": cc.User, "password": cc.Password},
	}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var connOut struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&connOut); err != nil {
		t.Fatalf("decode connection: %v", err)
	}
	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+connOut.ID.String()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var refreshOut struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&refreshOut); err != nil {
		t.Fatalf("decode refresh: %v", err)
	}
	waitOperation(t, env, refreshOut.OperationID, operations.StatusSuccess, 90*time.Second)
	return connOut.ID
}

// TestIntegrationRotateSharedCredentialChoicePostgresE2E проходит весь цикл
// выбора на живой цели: отказ без намерения → ротация общего пароля с
// подтверждением → отвязка одного аккаунта → ротация принципала мимо него →
// возврат аккаунта на общий пароль.
func TestIntegrationRotateSharedCredentialChoicePostgresE2E(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping rotation choice e2e test")
	}
	vaultClient := newTestVault(t)
	registerPostgresOnceAPI.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})
	ctx := context.Background()
	// Порог 1: два аккаунта на общем секрете уже требуют подтверждения.
	env := newWorkerEnv(t, vaultClient, testEnvOpts{rotationConfirmThreshold: 1})
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)

	sfx := uniqueSuffix()[:8]
	const environment = "rotchc"
	groupRole := "gr_rot_readers_" + sfx
	targetExec(ctx, t, targetDSN,
		`do $$ begin create role `+groupRole+` nologin; exception when duplicate_object then null; end $$`)

	// Два подключения к одной целевой БД в одном окружении: их аккаунты
	// принципала делят один пароль (ADR-0008).
	connA := createTargetPGConnection(t, env, admin, operator, targetDSN, environment, "itest-rot-a-"+sfx)
	connB := createTargetPGConnection(t, env, admin, operator, targetDSN, environment, "itest-rot-b-"+sfx)

	resp := env.do(t, http.MethodPost, "/api/v1/principals", map[string]any{
		"type": "service", "display_name": "Rotation Choice " + sfx,
	}, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
	var principal struct {
		ID          uuid.UUID `json:"id"`
		DisplayName string    `json:"display_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		t.Fatalf("decode principal: %v", err)
	}

	idA, idB := "gr_rot_a_"+sfx, "gr_rot_b_"+sfx
	accountA := provisionSharedAccount(t, env, operator, principal.ID, connA, groupRole, idA)
	accountB := provisionSharedAccount(t, env, operator, principal.ID, connB, groupRole, idB)

	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), environment)
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	firstShared := vaultPassword(t, vaultClient, sharedPath)
	for _, id := range []string{idA, idB} {
		if !targetLoginOK(ctx, t, targetDSN, id, firstShared) {
			t.Fatalf("role %s cannot log in with the shared principal password", id)
		}
	}

	// 1. Ротация аккаунта на общем секрете без намерения — 409 с выбором.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+accountA.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	var choice sharedCredentialConflictBody
	if err := json.NewDecoder(resp.Body).Decode(&choice); err != nil {
		t.Fatalf("decode choice conflict: %v", err)
	}
	if choice.Code != "shared_credential_requires_choice" ||
		choice.SharedCredential.AffectedAccounts != 2 || !choice.SharedCredential.RequiresConfirm {
		t.Fatalf("choice conflict = %+v, want 2 affected accounts requiring confirm", choice)
	}

	// 2. Первый вариант выбора — ротация общего пароля. Масштаб (2 > порог 1)
	// требует подтверждения в том же запросе.
	rotatePath := "/api/v1/principals/" + principal.ID.String() + "/rotate?environment=" + environment
	resp = env.do(t, http.MethodPost, rotatePath, nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	var scale principalRotateConfirmBody
	if err := json.NewDecoder(resp.Body).Decode(&scale); err != nil {
		t.Fatalf("decode scale conflict: %v", err)
	}
	if scale.Code != "rotation_requires_confirm" || scale.Rotation.AffectedAccounts != 2 {
		t.Fatalf("scale conflict = %+v, want rotation_requires_confirm for 2 accounts", scale)
	}

	resp = env.do(t, http.MethodPost, rotatePath, map[string]any{"confirm": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var sharedRotate struct {
		Children []struct {
			AccountID   uuid.UUID `json:"account_id"`
			OperationID uuid.UUID `json:"operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sharedRotate); err != nil {
		t.Fatalf("decode principal rotate: %v", err)
	}
	if len(sharedRotate.Children) != 2 {
		t.Fatalf("principal rotate children = %d, want 2", len(sharedRotate.Children))
	}
	for _, child := range sharedRotate.Children {
		waitOperation(t, env, child.OperationID, operations.StatusSuccess, 120*time.Second)
	}
	secondShared := vaultPassword(t, vaultClient, sharedPath)
	if secondShared == firstShared {
		t.Fatal("shared principal password did not change")
	}
	for _, id := range []string{idA, idB} {
		if !targetLoginOK(ctx, t, targetDSN, id, secondShared) {
			t.Errorf("role %s cannot log in with the rotated shared password", id)
		}
		if targetLoginOK(ctx, t, targetDSN, id, firstShared) {
			t.Errorf("role %s still accepts the previous shared password", id)
		}
	}

	// 3. Второй вариант выбора — отвязка одного аккаунта: собственный пароль,
	// новый vault_path в ответе, соседний аккаунт не затронут.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+accountA.String()+"/rotate",
		map[string]any{"detach": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var detach rotateAccountBody
	if err := json.NewDecoder(resp.Body).Decode(&detach); err != nil {
		t.Fatalf("decode detach: %v", err)
	}
	ownPath, err := vault.AccountCredentialPath(accountA.String())
	if err != nil {
		t.Fatalf("account credential path: %v", err)
	}
	if detach.VaultPath != ownPath || !detach.Detached {
		t.Fatalf("detach response = %q/%v, want %q/true", detach.VaultPath, detach.Detached, ownPath)
	}
	waitOperation(t, env, detach.OperationID, operations.StatusSuccess, 120*time.Second)

	ownPassword := vaultPassword(t, vaultClient, ownPath)
	if !targetLoginOK(ctx, t, targetDSN, idA, ownPassword) {
		t.Error("detached account does not accept its own new password")
	}
	if targetLoginOK(ctx, t, targetDSN, idA, secondShared) {
		t.Error("detached account still accepts the shared principal password")
	}
	if vaultPassword(t, vaultClient, sharedPath) != secondShared {
		t.Error("detach changed the shared principal password")
	}
	if !targetLoginOK(ctx, t, targetDSN, idB, secondShared) {
		t.Error("sibling account lost the shared password after the detach")
	}
	detached := accountRow(t, env.pool, accountA)
	if detached.VaultPath != ownPath || detached.CredentialMode == nil ||
		*detached.CredentialMode != inventory.CredentialModeGenerated {
		t.Errorf("detached account = %q/%v, want own path with generated mode",
			detached.VaultPath, detached.CredentialMode)
	}

	// 4. Ротация принципала после отвязки идёт мимо отвязанного аккаунта
	// (один аккаунт — порог 1 больше не срабатывает).
	resp = env.do(t, http.MethodPost, rotatePath, nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var afterDetach struct {
		Children []struct {
			AccountID   uuid.UUID `json:"account_id"`
			OperationID uuid.UUID `json:"operation_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&afterDetach); err != nil {
		t.Fatalf("decode principal rotate after detach: %v", err)
	}
	if len(afterDetach.Children) != 1 || afterDetach.Children[0].AccountID != accountB {
		t.Fatalf("principal rotate children = %+v, want only account B", afterDetach.Children)
	}
	waitOperation(t, env, afterDetach.Children[0].OperationID, operations.StatusSuccess, 120*time.Second)
	thirdShared := vaultPassword(t, vaultClient, sharedPath)
	if thirdShared == secondShared {
		t.Fatal("shared principal password did not change on the second rotation")
	}
	if !targetLoginOK(ctx, t, targetDSN, idA, ownPassword) {
		t.Error("principal rotation changed the password of the detached account")
	}
	if !targetLoginOK(ctx, t, targetDSN, idB, thirdShared) {
		t.Error("account B did not get the newly rotated shared password")
	}

	// 5. Обратный путь: аккаунт возвращается на общий пароль принципала —
	// без генерации нового секрета, с текущим общим значением.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+accountA.String()+"/rotate",
		map[string]any{"attach": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var attach rotateAccountBody
	if err := json.NewDecoder(resp.Body).Decode(&attach); err != nil {
		t.Fatalf("decode attach: %v", err)
	}
	if attach.VaultPath != sharedPath || !attach.Attached {
		t.Fatalf("attach response = %q/%v, want %q/true", attach.VaultPath, attach.Attached, sharedPath)
	}
	waitOperation(t, env, attach.OperationID, operations.StatusSuccess, 120*time.Second)
	if vaultPassword(t, vaultClient, sharedPath) != thirdShared {
		t.Error("attach rotated the shared principal password instead of reusing it")
	}
	if !targetLoginOK(ctx, t, targetDSN, idA, thirdShared) {
		t.Error("attached account does not accept the shared principal password")
	}
	attached := accountRow(t, env.pool, accountA)
	if attached.VaultPath != sharedPath || attached.CredentialMode == nil ||
		*attached.CredentialMode != inventory.CredentialModeExistingVaultRef {
		t.Errorf("attached account = %q/%v, want shared path with existing_vault_ref mode",
			attached.VaultPath, attached.CredentialMode)
	}
}

// provisionSharedAccount выдаёт принципалу роль groupRole в подключении и
// дожидается, пока worker создаст учётку в целевой системе.
func provisionSharedAccount(t *testing.T, env *testEnv, operator auth.Session,
	principalID, connID uuid.UUID, groupRole, identity string) uuid.UUID {
	t.Helper()
	perm := findPermission(t, env.pool, connID, "role:"+groupRole)
	access := grantPrincipalAccessItems(t, env, &operator, principalID, identity, []map[string]any{
		{"connection_id": connID, "permission_id": perm.ID},
	})
	if len(access.Children) != 1 || access.Children[0].AccountCreateOperationID == nil {
		t.Fatalf("access children = %+v, want a single created account", access.Children)
	}
	waitOperation(t, env, *access.Children[0].AccountCreateOperationID, operations.StatusSuccess, 120*time.Second)
	waitOperation(t, env, access.Children[0].GrantOperationID, operations.StatusSuccess, 120*time.Second)
	return access.Children[0].AccountID
}
