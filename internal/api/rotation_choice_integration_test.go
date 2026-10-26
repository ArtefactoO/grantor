//go:build integration

// Integration-тесты осознанного выбора при ротации аккаунта на общем секрете
// принципала (ADR-0008: один пароль на пару principal+environment).
//
// Закрываемый баг ручного E2E (воспроизводился на всех шести движках):
// POST /accounts/{id}/rotate на аккаунте с credential_mode=existing_vault_ref
// МОЛЧА уводил его с общего секрета принципала на персональный путь. Новый
// пароль применялся к цели корректно, но общий секрет оставался со старым
// значением, остальные аккаунты принципала продолжали жить на нём, а
// /principals/{id}/share выдавал пароль, для отротированного аккаунта уже
// мёртвый. Ни confirm, ни предупреждения, ни нового vault_path в ответе.
package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// sharedCredentialConflictBody — 409-контракт «нужен осознанный выбор».
type sharedCredentialConflictBody struct {
	Error            string `json:"error"`
	Code             string `json:"code"`
	SharedCredential struct {
		PrincipalID          uuid.UUID `json:"principal_id"`
		PrincipalDisplayName string    `json:"principal_display_name"`
		Environment          string    `json:"environment"`
		AffectedAccounts     int       `json:"affected_accounts"`
		AffectedConnections  []struct {
			ConnectionID uuid.UUID `json:"connection_id"`
			DisplayName  string    `json:"display_name"`
			AccountID    uuid.UUID `json:"account_id"`
		} `json:"affected_connections"`
		ConfirmThreshold int  `json:"confirm_threshold"`
		RequiresConfirm  bool `json:"requires_confirm"`
	} `json:"shared_credential"`
}

// rotateAccountBody — 202-ответ ротации аккаунта.
type rotateAccountBody struct {
	AccountID   uuid.UUID `json:"account_id"`
	OperationID uuid.UUID `json:"operation_id"`
	VaultPath   string    `json:"vault_path"`
	Detached    bool      `json:"detached"`
	Attached    bool      `json:"attached"`
}

// principalRotateConfirmBody — 409-контракт масштабной ротации принципала.
type principalRotateConfirmBody struct {
	Error    string `json:"error"`
	Code     string `json:"code"`
	Rotation struct {
		AffectedAccounts int      `json:"affected_accounts"`
		Environments     []string `json:"environments"`
		ConfirmThreshold int      `json:"confirm_threshold"`
	} `json:"rotation"`
}

// sharedPrincipalAccounts выдаёт принципалу доступ в count подключениях
// одного окружения и доводит их аккаунты до active: получается ровно та
// конфигурация, где несколько аккаунтов делят один пароль окружения.
func sharedPrincipalAccounts(t *testing.T, env *testEnv, sess *auth.Session,
	principalID uuid.UUID, environment, identity string, count int) []principalAccessChildBody {
	t.Helper()
	items := make([]map[string]any, 0, count)
	for range count {
		conn := activeFakeConnectionEnv(t, env.pool, environment)
		items = append(items, map[string]any{
			"connection_id": conn.ID,
			"permission_id": findPermission(t, env.pool, conn.ID, "role:app-readonly").ID,
		})
	}
	access := grantPrincipalAccessItems(t, env, sess, principalID, identity, items)
	if len(access.Children) != count {
		t.Fatalf("access children = %d, want %d", len(access.Children), count)
	}
	finishProvisionChildren(t, env, access.Children)
	return access.Children
}

// TestIntegrationRotateSharedAccountRequiresChoice: ротация аккаунта на общем
// секрете без явного намерения — 409 с машиночитаемым кодом и полным
// контекстом; операция при этом не ставится и аккаунт не меняется.
func TestIntegrationRotateSharedAccountRequiresChoice(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newRotationConfirmTestEnv(t, vaultClient, 2)
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Choice Service "+uniqueSuffix())
	identity := "itest_chc_" + uniqueSuffix()[:8]
	children := sharedPrincipalAccounts(t, env, &operator, principal.ID, "test", identity, 3)
	target := children[0].AccountID

	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	before := accountRow(t, env.pool, target)
	if before.VaultPath != sharedPath {
		t.Fatalf("fixture account vault_path = %q, want shared %q", before.VaultPath, sharedPath)
	}
	opsBefore := countAccountOperations(t, env.pool, target)

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+target.String()+"/rotate", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	var conflict sharedCredentialConflictBody
	raw := readBody(t, resp)
	if err := json.Unmarshal(raw, &conflict); err != nil {
		t.Fatalf("decode conflict: %v (body %s)", err, raw)
	}
	if conflict.Code != "shared_credential_requires_choice" {
		t.Errorf("code = %q, want shared_credential_requires_choice", conflict.Code)
	}
	if conflict.SharedCredential.PrincipalID != principal.ID {
		t.Errorf("principal_id = %s, want %s", conflict.SharedCredential.PrincipalID, principal.ID)
	}
	if conflict.SharedCredential.PrincipalDisplayName != principal.DisplayName {
		t.Errorf("principal_display_name = %q, want %q",
			conflict.SharedCredential.PrincipalDisplayName, principal.DisplayName)
	}
	if conflict.SharedCredential.Environment != "test" {
		t.Errorf("environment = %q, want test", conflict.SharedCredential.Environment)
	}
	if conflict.SharedCredential.AffectedAccounts != 3 {
		t.Errorf("affected_accounts = %d, want 3", conflict.SharedCredential.AffectedAccounts)
	}
	if n := len(conflict.SharedCredential.AffectedConnections); n != 3 {
		t.Fatalf("affected_connections = %d, want 3", n)
	}
	// Каждое затронутое подключение названо: id + человекочитаемое имя.
	wantAccounts := map[uuid.UUID]bool{}
	for _, child := range children {
		wantAccounts[child.AccountID] = true
	}
	for _, item := range conflict.SharedCredential.AffectedConnections {
		if item.DisplayName == "" {
			t.Errorf("affected connection %s has no display_name", item.ConnectionID)
		}
		if !wantAccounts[item.AccountID] {
			t.Errorf("affected connections contain unexpected account %s", item.AccountID)
		}
	}
	// Порог: 3 аккаунта больше порога 2 — подтверждение обязательно.
	if conflict.SharedCredential.ConfirmThreshold != 2 || !conflict.SharedCredential.RequiresConfirm {
		t.Errorf("confirm_threshold/requires_confirm = %d/%v, want 2/true",
			conflict.SharedCredential.ConfirmThreshold, conflict.SharedCredential.RequiresConfirm)
	}
	// Ни путь секрета, ни его значение в 409 не утекают.
	if bodyContains(raw, sharedPath) {
		t.Error("conflict body leaks the shared credential path")
	}

	// Отказ не ставит операцию и не трогает аккаунт.
	if n := countAccountOperations(t, env.pool, target); n != opsBefore {
		t.Errorf("operations after refused rotate = %d, want %d", n, opsBefore)
	}
	after := accountRow(t, env.pool, target)
	if after.VaultPath != before.VaultPath || after.LifecycleVersion != before.LifecycleVersion {
		t.Errorf("account changed after refused rotate: %q/%d, want %q/%d",
			after.VaultPath, after.LifecycleVersion, before.VaultPath, before.LifecycleVersion)
	}
}

// TestIntegrationRotateSharedAccountDetach: явное {"detach":true} выполняет
// отвязку, возвращает новый vault_path и не задевает остальные аккаунты
// принципала; ротация принципала после этого отвязанный аккаунт пропускает.
func TestIntegrationRotateSharedAccountDetach(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newRotationConfirmTestEnv(t, vaultClient, 2)
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Detach Choice "+uniqueSuffix())
	identity := "itest_dch_" + uniqueSuffix()[:8]
	children := sharedPrincipalAccounts(t, env, &operator, principal.ID, "test", identity, 3)
	detached, kept := children[0].AccountID, children[1].AccountID

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+detached.String()+"/rotate",
		map[string]any{"detach": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var rotated rotateAccountBody
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	ownPath, err := vault.AccountCredentialPath(detached.String())
	if err != nil {
		t.Fatalf("account credential path: %v", err)
	}
	// Отвязка видна через API: новый путь и явный флаг в ответе.
	if rotated.VaultPath != ownPath {
		t.Errorf("vault_path = %q, want %q", rotated.VaultPath, ownPath)
	}
	if !rotated.Detached {
		t.Error("detached = false, want true")
	}

	// Операция — обычный credential.rotate без общего пути: executor
	// сгенерирует собственный пароль аккаунта.
	requireCredentialRotatePayload(t, env, rotated.OperationID, "")

	// Соседний аккаунт остался на общем секрете принципала.
	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	if got := accountRow(t, env.pool, kept); got.VaultPath != sharedPath {
		t.Errorf("sibling account vault_path = %q, want %q", got.VaultPath, sharedPath)
	}

	// Executor успешно применил новый пароль: фиксируем результат так же, как
	// это делает success-хвост credential.rotate.
	applyDetachedRotation(t, env, detached, rotated.OperationID, ownPath)

	// Ротация принципала отвязанный аккаунт больше не трогает.
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/rotate?environment=test",
		map[string]any{"confirm": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var principalRotate struct {
		Children []struct {
			AccountID uuid.UUID `json:"account_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&principalRotate); err != nil {
		t.Fatalf("decode principal rotate: %v", err)
	}
	if len(principalRotate.Children) != 2 {
		t.Errorf("principal rotate children = %d, want 2 (detached account excluded)",
			len(principalRotate.Children))
	}
	for _, child := range principalRotate.Children {
		if child.AccountID == detached {
			t.Error("principal rotate touched the detached account")
		}
	}
	// Собственный секрет отвязанного аккаунта ротация принципала не переписала.
	if got := accountRow(t, env.pool, detached); got.VaultPath != ownPath {
		t.Errorf("detached account vault_path = %q, want %q", got.VaultPath, ownPath)
	}
}

// TestIntegrationRotateAttachBackToPrincipalCredential: обратный путь —
// {"attach":true} возвращает отвязанный аккаунт на общий пароль принципала.
func TestIntegrationRotateAttachBackToPrincipalCredential(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newRotationConfirmTestEnv(t, vaultClient, 2)
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Attach Back "+uniqueSuffix())
	identity := "itest_atb_" + uniqueSuffix()[:8]
	children := sharedPrincipalAccounts(t, env, &operator, principal.ID, "test", identity, 2)
	acctID := children[0].AccountID

	// Аккаунт на общем секрете вернуть «обратно» нельзя — он уже там.
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/rotate",
		map[string]any{"attach": true}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	// Взаимоисключающие намерения — 400, а не молчаливый выбор одного из них.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/rotate",
		map[string]any{"attach": true, "detach": true}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Отвязываем и доводим ротацию до успеха.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/rotate",
		map[string]any{"detach": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var detachOut rotateAccountBody
	if err := json.NewDecoder(resp.Body).Decode(&detachOut); err != nil {
		t.Fatalf("decode detach response: %v", err)
	}
	ownPath, err := vault.AccountCredentialPath(acctID.String())
	if err != nil {
		t.Fatalf("account credential path: %v", err)
	}
	applyDetachedRotation(t, env, acctID, detachOut.OperationID, ownPath)

	// Возврат на общий пароль принципала.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/rotate",
		map[string]any{"attach": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var attached rotateAccountBody
	if err := json.NewDecoder(resp.Body).Decode(&attached); err != nil {
		t.Fatalf("decode attach response: %v", err)
	}
	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	if attached.VaultPath != sharedPath || !attached.Attached {
		t.Errorf("attach response = %q/%v, want %q/true", attached.VaultPath, attached.Attached, sharedPath)
	}
	// Операция несёт путь общего секрета: executor применит ТЕКУЩИЙ общий
	// пароль, а не сгенерирует новый.
	requireCredentialRotatePayload(t, env, attached.OperationID, sharedPath)
	// Режим зафиксирован сразу, путь — только после успеха операции: до него
	// аккаунт продолжает жить на собственном рабочем секрете.
	pending := accountRow(t, env.pool, acctID)
	if pending.CredentialMode == nil || *pending.CredentialMode != inventory.CredentialModeExistingVaultRef {
		t.Errorf("credential_mode = %v, want existing_vault_ref", pending.CredentialMode)
	}
	if pending.VaultPath != ownPath {
		t.Errorf("vault_path before the operation succeeds = %q, want the own secret %q",
			pending.VaultPath, ownPath)
	}
}

// TestIntegrationPrincipalRotateConfirmThreshold: масштабная ротация общего
// секрета требует явного confirm, ротация ниже порога — нет.
func TestIntegrationPrincipalRotateConfirmThreshold(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newRotationConfirmTestEnv(t, vaultClient, 2)
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Threshold Service "+uniqueSuffix())
	identity := "itest_thr_" + uniqueSuffix()[:8]
	sharedPrincipalAccounts(t, env, &operator, principal.ID, "test", identity, 3)
	path := "/api/v1/principals/" + principal.ID.String() + "/rotate?environment=test"

	resp := env.do(t, http.MethodPost, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	var conflict principalRotateConfirmBody
	if err := json.NewDecoder(resp.Body).Decode(&conflict); err != nil {
		t.Fatalf("decode conflict: %v", err)
	}
	if conflict.Code != "rotation_requires_confirm" {
		t.Errorf("code = %q, want rotation_requires_confirm", conflict.Code)
	}
	if conflict.Rotation.AffectedAccounts != 3 || conflict.Rotation.ConfirmThreshold != 2 {
		t.Errorf("rotation = %d accounts / threshold %d, want 3/2",
			conflict.Rotation.AffectedAccounts, conflict.Rotation.ConfirmThreshold)
	}
	if len(conflict.Rotation.Environments) != 1 || conflict.Rotation.Environments[0] != "test" {
		t.Errorf("environments = %v, want [test]", conflict.Rotation.Environments)
	}

	// С подтверждением ротация выполняется.
	resp = env.do(t, http.MethodPost, path, map[string]any{"confirm": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)

	// Ниже порога подтверждение не требуется: у второго принципала два
	// аккаунта, порог 2 — 2 не больше 2.
	small := createPrincipalRow(t, env.pool, "Small Service "+uniqueSuffix())
	sharedPrincipalAccounts(t, env, &operator, small.ID, "test", "itest_sml_"+uniqueSuffix()[:8], 2)
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+small.ID.String()+"/rotate?environment=test", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
}

// TestIntegrationGetAccountAndDeletePhantomStatuses: карточка аккаунта по id
// и точечное удаление «фантомных» строк (provisioning/missing, ADR-0017).
func TestIntegrationGetAccountAndDeletePhantomStatuses(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	viewer := session(auth.RoleViewer)

	principal := createPrincipalRow(t, env.pool, "Phantom Service "+uniqueSuffix())
	identity := "itest_pht_" + uniqueSuffix()[:8]
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		{"connection_id": conn.ID, "permission_id": findPermission(t, env.pool, conn.ID, "role:app-readonly").ID},
	})
	acctID := access.Children[0].AccountID
	// Провалившийся account.create — та самая «фантомная» строка ADR-0017:
	// учётки в целевой системе нет, а аккаунт остался в provisioning.
	finishOperation(t, env, *access.Children[0].AccountCreateOperationID, operations.StatusFailed)

	// GET /accounts/{id}: карточка доступна viewer и совпадает со строкой.
	resp := env.do(t, http.MethodGet, "/api/v1/accounts/"+acctID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var card struct {
		ID             uuid.UUID  `json:"id"`
		PrincipalID    *uuid.UUID `json:"principal_id"`
		ConnectionID   uuid.UUID  `json:"connection_id"`
		EngineIdentity string     `json:"engine_identity"`
		CredentialMode *string    `json:"credential_mode"`
		VaultPath      string     `json:"vault_path"`
		Status         string     `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		t.Fatalf("decode account card: %v", err)
	}
	if card.ID != acctID || card.ConnectionID != conn.ID || card.EngineIdentity != identity {
		t.Errorf("account card = %+v, want account %s of connection %s", card, acctID, conn.ID)
	}
	// Свежесозданный аккаунт принципала ещё не подтверждён на target.
	if card.Status != string(inventory.AccountProvisioning) {
		t.Errorf("status = %q, want provisioning", card.Status)
	}
	if card.PrincipalID == nil || *card.PrincipalID != principal.ID {
		t.Errorf("principal_id = %v, want %s", card.PrincipalID, principal.ID)
	}

	// Неизвестный id — 404, невалидный — 400.
	resp = env.do(t, http.MethodGet, "/api/v1/accounts/"+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodGet, "/api/v1/accounts/not-a-uuid", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)

	// An unconfirmed CREATE may have collided with an existing target role.
	// DELETE is not a metadata-only cleanup; explicit recovery is required.
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+acctID.String()+"?confirm=true",
		map[string]any{"reason": "phantom row"}, &admin, true)
	requireStatus(t, resp, http.StatusConflict)

	// То же для missing (discovery не нашёл managed-аккаунт).
	secondConn := activeFakeConnectionEnv(t, env.pool, "test")
	missing := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity+"_m", []map[string]any{
		{"connection_id": secondConn.ID,
			"permission_id": findPermission(t, env.pool, secondConn.ID, "role:app-readonly").ID},
	})
	missingID := missing.Children[0].AccountID
	finishOperation(t, env, *missing.Children[0].AccountCreateOperationID, operations.StatusSuccess)
	if _, err := env.pool.Exec(t.Context(),
		`update accounts set status = 'missing' where id = $1`, missingID); err != nil {
		t.Fatalf("simulate missing account: %v", err)
	}
	resp = env.do(t, http.MethodDelete, "/api/v1/accounts/"+missingID.String()+"?confirm=true", nil, &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
}

// requireCredentialRotatePayload проверяет kind операции и её источник
// пароля: пустой wantSharedPath — обычная per-account ротация (executor
// сгенерирует новый секрет), непустой — применение общего секрета принципала.
func requireCredentialRotatePayload(t *testing.T, env *testEnv, opID uuid.UUID, wantSharedPath string) {
	t.Helper()
	op, err := operations.NewStore().Get(t.Context(), env.pool, opID)
	if err != nil {
		t.Fatalf("get operation %s: %v", opID, err)
	}
	if op.Kind != jobs.KindCredentialRotate {
		t.Errorf("operation kind = %q, want %q", op.Kind, jobs.KindCredentialRotate)
	}
	var payload jobs.AccountPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		t.Fatalf("decode operation payload: %v", err)
	}
	if payload.SharedCredentialPath != wantSharedPath {
		t.Errorf("payload shared_credential_path = %q, want %q",
			payload.SharedCredentialPath, wantSharedPath)
	}
}

// applyDetachedRotation воспроизводит success-хвост credential.rotate для
// отвязанной ротации: операция доводится до success, а на строке аккаунта
// оказываются собственный путь и режим credential — ровно то, что делает
// executor. Insert-only окружение этих тестов worker не запускает; сквозной
// путь с реальным применением пароля к цели —
// TestIntegrationRotateSharedCredentialChoicePostgresE2E.
func applyDetachedRotation(t *testing.T, env *testEnv, accountID, opID uuid.UUID, ownPath string) {
	t.Helper()
	finishOperation(t, env, opID, operations.StatusSuccess)
	if _, err := env.pool.Exec(t.Context(), `
		update accounts set vault_path = $2, credential_mode = 'generated' where id = $1`,
		accountID, ownPath); err != nil {
		t.Fatalf("apply detached rotation: %v", err)
	}
}

// finishOperation доводит поставленную API операцию до терминального статуса
// (worker в insert-only окружении не запущен): пока операция pending/running,
// account держит lifecycle-резерв и следующая ручка получает 409.
func finishOperation(t *testing.T, env *testEnv, opID uuid.UUID, status operations.Status) {
	t.Helper()
	store := operations.NewStore()
	if _, err := store.Transition(t.Context(), env.pool, opID,
		operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{}); err != nil {
		t.Fatalf("start operation %s: %v", opID, err)
	}
	if _, err := store.Transition(t.Context(), env.pool, opID,
		operations.StatusRunning, status, operations.TransitionOpts{}); err != nil {
		t.Fatalf("finish operation %s: %v", opID, err)
	}
}

// bodyContains — подстрока в теле ответа (проверки на утечку путей секретов).
func bodyContains(body []byte, want string) bool {
	return strings.Contains(string(body), want)
}
