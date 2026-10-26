//go:build integration

// Integration-тесты POST /api/v1/accounts/{id}/adopt: принятие
// unmanaged-аккаунта под управление. Здесь проверяется API-слой (guards,
// RBAC, метаданные, созданная операция, отсутствие секретов в
// operations/audit); сквозной password-цикл с worker и реальным целевым
// PostgreSQL живёт в internal/jobs/adopt_integration_test.go.
package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// adoptMetadataResponse — тело 200-ответа adopt в режиме metadata.
type adoptMetadataResponse struct {
	Account struct {
		ID             uuid.UUID `json:"id"`
		Ownership      string    `json:"ownership"`
		VaultPath      string    `json:"vault_path"`
		CredentialMode *string   `json:"credential_mode"`
	} `json:"account"`
	AdoptedBindings int `json:"adopted_bindings"`
}

// adoptOperationResponse — тело 202-ответа adopt в режиме password.
type adoptOperationResponse struct {
	AccountID   uuid.UUID `json:"account_id"`
	OperationID uuid.UUID `json:"operation_id"`
	// AdoptBindings — флаг, унесённый в операцию: сами bindings принимаются
	// на её успехе, а не в ответе ручки.
	AdoptBindings bool `json:"adopt_bindings"`
}

// countAccountOperations считает операции аккаунта в metadata database.
func countAccountOperations(t *testing.T, pool *pgxpool.Pool, accountID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(t.Context(),
		`select count(*) from operations where account_id = $1`, accountID).Scan(&n); err != nil {
		t.Fatalf("count operations: %v", err)
	}
	return n
}

// unmanagedLoginAccount вставляет unmanaged login-аккаунт напрямую в
// metadata database: в fake-снапшоте login-аккаунт ровно один (svc-a), а
// сценариям adopt нужен свой на каждый шаг (после adopt аккаунт занят
// lifecycle-операцией). Строка выглядит так же, как принесённая discovery.
func unmanagedLoginAccount(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID) inventory.Account {
	t.Helper()
	identity := "itest_unm_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `
		insert into accounts (connection_id, kind, engine_identity, status, ownership)
		values ($1, 'login', $2, 'active', 'unmanaged')
		returning id`, connID, identity).Scan(&id); err != nil {
		t.Fatalf("insert unmanaged login account: %v", err)
	}
	acct, err := inventory.NewStore().GetAccount(t.Context(), pool, id)
	if err != nil {
		t.Fatalf("get unmanaged login account: %v", err)
	}
	return acct
}

// grantUnmanagedBinding добавляет аккаунту unmanaged binding (desired NULL),
// как это делает discovery: нужен сценариям adopt_bindings.
func grantUnmanagedBinding(t *testing.T, pool *pgxpool.Pool, accountID, permissionID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `
		insert into bindings (account_id, permission_definition_id, source, desired_state, observed_state, status)
		values ($1, $2, 'external', null, 'present', 'pending')`, accountID, permissionID); err != nil {
		t.Fatalf("insert unmanaged binding: %v", err)
	}
}

func TestIntegrationAdoptAccountMetadata(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := activeFakeConnection(t, env.pool)
	invStore := inventory.NewStore()

	// Принять под управление можно только login-аккаунт, поэтому берём
	// unmanaged login и вешаем на него unmanaged binding (в fake-снапшоте
	// такой binding несёт readers, но readers — kind=group).
	target := unmanagedLoginAccount(t, env.pool, conn.ID)
	grantUnmanagedBinding(t, env.pool, target.ID, findPermission(t, env.pool, conn.ID, "role:app-readonly").ID)
	path := "/api/v1/accounts/" + target.ID.String() + "/adopt"
	body := map[string]any{"mode": "metadata", "adopt_bindings": true}

	// RBAC и CSRF: viewer — 403, мутация без CSRF — 403.
	resp := env.do(t, http.MethodPost, path, body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)
	resp = env.do(t, http.MethodPost, path, body, &operator, false)
	requireStatus(t, resp, http.StatusForbidden)

	// Валидация тела: неизвестный режим, пустой пароль в password-режиме,
	// пароль в metadata-режиме — 400.
	for _, bad := range []map[string]any{
		{"mode": "takeover"},
		{"mode": "password"},
		{"mode": "password", "password": ""},
		{"mode": "set_password"},
		{"mode": "verify_password"},
		{"mode": "verify_password", "password": ""},
		{"mode": "metadata", "password": "x"},
	} {
		resp = env.do(t, http.MethodPost, path, bad, &operator, true)
		requireStatus(t, resp, http.StatusBadRequest)
	}

	// Успешный metadata adopt: 200, ownership managed, vault_path и
	// credential_mode честно пусты, binding принят.
	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	var out adoptMetadataResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}
	if out.Account.Ownership != "managed" {
		t.Errorf("response ownership = %q, want managed", out.Account.Ownership)
	}
	if out.Account.VaultPath != "" || out.Account.CredentialMode != nil {
		t.Errorf("response vault_path/credential_mode = %q/%v, want empty (grantor does not own the secret yet)",
			out.Account.VaultPath, out.Account.CredentialMode)
	}
	if out.AdoptedBindings != 1 {
		t.Errorf("adopted_bindings = %d, want 1", out.AdoptedBindings)
	}

	got, err := invStore.GetAccount(t.Context(), env.pool, target.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Ownership != inventory.OwnershipManaged || got.VaultPath != "" || got.CredentialMode != nil {
		t.Errorf("account after adopt = %q/%q/%v, want managed with empty credential",
			got.Ownership, got.VaultPath, got.CredentialMode)
	}
	bindings, err := invStore.ListBindingsByAccount(t.Context(), env.pool, target.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	for _, b := range bindings {
		if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			t.Errorf("binding %s desired = %v, want present after adopt", b.ID, b.DesiredState)
		}
	}

	// Metadata-режим не ставит операций: целевая система не затронута.
	if n := countAccountOperations(t, env.pool, target.ID); n != 0 {
		t.Errorf("operations after metadata adopt = %d, want 0", n)
	}

	// Audit-событие account.adopted с режимом и счётчиком bindings.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &target.ID,
		Actions:   []string{"account.adopted"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.adopted events = %d, want 1", len(events))
	}
	var meta struct {
		Mode            string `json:"mode"`
		AdoptedBindings int    `json:"adopted_bindings"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil ||
		meta.Mode != "metadata" || meta.AdoptedBindings != 1 {
		t.Errorf("audit metadata = %s (err=%v), want mode=metadata adopted_bindings=1",
			events[0].Metadata, err)
	}

	// Повторный adopt уже managed-аккаунта — 409 (идемпотентность повторного
	// запроса на уровне ответа, без побочных эффектов).
	resp = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Managed-аккаунт, созданный grantor, — тоже 409.
	managed := managedAccount(t, env.pool, conn.ID, "")
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+managed.ID.String()+"/adopt",
		map[string]any{"mode": "metadata"}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Несуществующий аккаунт — 404.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+uuid.NewString()+"/adopt",
		map[string]any{"mode": "metadata"}, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationAdoptAccountDangerousBindings(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)

	// svc-a получает unmanaged binding на dangerous permission
	// (role:superuser) — как будто его нашёл discovery.
	svc := findAccount(t, env.pool, conn.ID, "svc-a")
	dangerous := findPermission(t, env.pool, conn.ID, "role:superuser")
	if _, err := env.pool.Exec(t.Context(), `
		insert into bindings (account_id, permission_definition_id, source, desired_state, observed_state, status)
		values ($1, $2, 'external', null, 'present', 'pending')`,
		svc.ID, dangerous.ID); err != nil {
		t.Fatalf("insert unmanaged dangerous binding: %v", err)
	}

	path := "/api/v1/accounts/" + svc.ID.String() + "/adopt"
	withBindings := map[string]any{"mode": "metadata", "adopt_bindings": true}

	// Operator не может массово принять dangerous binding (симметрично
	// точечному adopt binding) — 403; аккаунт остаётся unmanaged.
	resp := env.do(t, http.MethodPost, path, withBindings, &operator, true)
	requireStatus(t, resp, http.StatusForbidden)
	got, err := inventory.NewStore().GetAccount(t.Context(), env.pool, svc.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Ownership != inventory.OwnershipUnmanaged {
		t.Errorf("ownership after refused adopt = %q, want unmanaged", got.Ownership)
	}

	// Admin — 200 с принятым dangerous binding.
	resp = env.do(t, http.MethodPost, path, withBindings, &admin, true)
	requireStatus(t, resp, http.StatusOK)
	var out adoptMetadataResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}
	if out.AdoptedBindings != 1 {
		t.Errorf("adopted_bindings = %d, want 1", out.AdoptedBindings)
	}
}

func TestIntegrationAdoptAccountGenerate(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	invStore := inventory.NewStore()

	// svc-a — единственный login-аккаунт fake-снапшота, без bindings.
	svc := findAccount(t, env.pool, conn.ID, "svc-a")
	path := "/api/v1/accounts/" + svc.ID.String() + "/adopt"

	// Валидация: generate-режим не принимает пароль — 400.
	resp := env.do(t, http.MethodPost, path,
		map[string]any{"mode": "generate", "password": "x"}, &operator, true)
	requireStatus(t, resp, http.StatusBadRequest)

	// Успешный generate adopt: 202 с операцией, без принятых bindings.
	resp = env.do(t, http.MethodPost, path,
		map[string]any{"mode": "generate"}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out adoptOperationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}
	if out.AccountID != svc.ID || out.AdoptBindings {
		t.Errorf("adopt response = %+v, want account %s without adopt_bindings", out, svc.ID)
	}

	// До успеха операции аккаунт остаётся unmanaged: состояния «managed без
	// применённого credential» этот путь не создаёт. vault_path пуст —
	// generate-режим ничего не предзаписывает в Vault.
	got, err := invStore.GetAccount(t.Context(), env.pool, svc.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Ownership != inventory.OwnershipUnmanaged || got.VaultPath != "" {
		t.Errorf("account before apply = %q/%q, want unmanaged with empty vault_path",
			got.Ownership, got.VaultPath)
	}

	// Операция — credential.rotate с несекретными флагами adopt + adopt_generate.
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindCredentialRotate || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want credential.rotate/pending", op.Kind, op.Status)
	}
	var payload struct {
		Adopt         bool `json:"adopt"`
		AdoptGenerate bool `json:"adopt_generate"`
	}
	if err := json.Unmarshal(op.Payload, &payload); err != nil || !payload.Adopt || !payload.AdoptGenerate {
		t.Errorf("operation payload %s does not carry adopt+adopt_generate (err=%v)", op.Payload, err)
	}

	// Audit фиксирует запрос adopt с режимом generate.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &svc.ID,
		Actions:   []string{"account.adopt_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.adopt_requested events = %d, want 1", len(events))
	}
	var meta struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.Mode != "generate" {
		t.Errorf("audit metadata = %s (err=%v), want mode=generate", events[0].Metadata, err)
	}

	// Вариант adopt_bindings: login-аккаунт с unmanaged binding. В
	// асинхронных режимах права принимаются ТОЛЬКО на успехе операции — до
	// этого и ownership, и bindings остаются непринятыми. Иначе провал
	// кред-операции оставлял бы управляемые bindings у неуправляемого
	// аккаунта и убирал внешний грант из отчёта о дрифте.
	withBindings := unmanagedLoginAccount(t, env.pool, conn.ID)
	grantUnmanagedBinding(t, env.pool, withBindings.ID, findPermission(t, env.pool, conn.ID, "role:app-readonly").ID)
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+withBindings.ID.String()+"/adopt",
		map[string]any{"mode": "generate", "adopt_bindings": true}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var withBindingsOut adoptOperationResponse
	if err := json.NewDecoder(resp.Body).Decode(&withBindingsOut); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}
	if !withBindingsOut.AdoptBindings {
		t.Error("adopt_bindings = false, want true: the flag must be carried into the operation")
	}
	adopted, err := invStore.GetAccount(t.Context(), env.pool, withBindings.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if adopted.Ownership != inventory.OwnershipUnmanaged {
		t.Errorf("ownership before apply = %q, want unmanaged", adopted.Ownership)
	}
	bindings, err := invStore.ListBindingsByAccount(t.Context(), env.pool, withBindings.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	for _, b := range bindings {
		if b.DesiredState != nil {
			t.Errorf("binding %s desired = %v, want nil until the operation succeeds", b.ID, *b.DesiredState)
		}
	}
}

// TestIntegrationAdoptAccountSetPassword — режим set_password: заданный
// оператором НОВЫЙ пароль предзаписывается по каноническому пути и
// применяется к учётке операцией credential.rotate. Здесь же проверяется
// обратная совместимость: прежнее имя режима password принимается и означает
// ровно то же самое.
func TestIntegrationAdoptAccountSetPassword(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	invStore := inventory.NewStore()

	svc := findAccount(t, env.pool, conn.ID, "svc-a")
	path := "/api/v1/accounts/" + svc.ID.String() + "/adopt"
	const password = "itest-adopt-secret-marker"

	resp := env.do(t, http.MethodPost, path,
		map[string]any{"mode": "set_password", "password": password}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), password) {
		t.Fatal("adopt response leaks password")
	}
	var out adoptOperationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal adopt response: %v", err)
	}
	if out.AccountID != svc.ID || out.AdoptBindings {
		t.Errorf("adopt response = %+v, want account %s without adopt_bindings", out, svc.ID)
	}

	// До успеха операции аккаунт остаётся unmanaged: состояния «managed без
	// применённого credential» не возникает.
	got, err := invStore.GetAccount(t.Context(), env.pool, svc.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Ownership != inventory.OwnershipUnmanaged || got.VaultPath != "" {
		t.Errorf("account before apply = %q/%q, want unmanaged with empty vault_path",
			got.Ownership, got.VaultPath)
	}

	// Пароль уже в Vault (username = engine identity) — записан ДО операции.
	wantPath := "accounts/" + svc.ID.String() + "/credential"
	data, version, err := vaultClient.Get(t.Context(), wantPath)
	if err != nil {
		t.Fatalf("vault get %s: %v", wantPath, err)
	}
	if data["username"] != svc.EngineIdentity || data["password"] != password {
		t.Errorf("vault secret username = %v, password matches = %v",
			data["username"], data["password"] == password)
	}
	if version != 1 {
		t.Errorf("vault version = %d, want 1", version)
	}

	// Операция — обычный credential.rotate с несекретным флагом adopt.
	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindCredentialRotate || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want credential.rotate/pending", op.Kind, op.Status)
	}
	var payload struct {
		Adopt bool `json:"adopt"`
	}
	if err := json.Unmarshal(op.Payload, &payload); err != nil || !payload.Adopt {
		t.Errorf("operation payload %s does not carry adopt flag (err=%v)", op.Payload, err)
	}
	if strings.Contains(string(op.Payload), password) {
		t.Fatal("operation payload leaks password")
	}

	// Audit фиксирует запрос adopt; секрета нигде в operations/audit нет
	// (канарейка-пароль отсутствует в обеих таблицах).
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &svc.ID,
		Actions:   []string{"account.adopt_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.adopt_requested events = %d, want 1", len(events))
	}
	var meta struct {
		Mode            string `json:"mode"`
		AdoptedBindings int    `json:"adopted_bindings"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.Mode != "set_password" {
		t.Errorf("audit metadata = %s (err=%v), want mode=set_password", events[0].Metadata, err)
	}
	for _, sweep := range []string{
		`select count(*) from operations where payload::text like '%' || $1 || '%'
		   or coalesce(plan::text, '') like '%' || $1 || '%'
		   or coalesce(result::text, '') like '%' || $1 || '%'
		   or error like '%' || $1 || '%'`,
		`select count(*) from audit_events where metadata::text like '%' || $1 || '%'`,
	} {
		var n int
		if err := env.pool.QueryRow(t.Context(), sweep, password).Scan(&n); err != nil {
			t.Fatalf("canary sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("password canary found by sweep %q: %d rows", sweep, n)
		}
	}
}

// TestIntegrationAdoptAccountLegacyPasswordMode — прежнее имя режима
// (mode=password) продолжает работать после разделения режимов: тот же
// 202-ответ, та же операция credential.rotate с флагом adopt, тот же
// предзаписанный секрет по каноническому пути. В audit режим записывается
// каноническим именем set_password — именно оно честно описывает, что пароль
// учётной записи будет заменён.
func TestIntegrationAdoptAccountLegacyPasswordMode(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)

	target := unmanagedLoginAccount(t, env.pool, conn.ID)
	const password = "itest-legacy-adopt-secret"
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+target.ID.String()+"/adopt",
		map[string]any{"mode": "password", "password": password}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var out adoptOperationResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode adopt response: %v", err)
	}

	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindCredentialRotate {
		t.Errorf("operation kind = %q, want %q", op.Kind, jobs.KindCredentialRotate)
	}
	// Секрет предзаписан по каноническому пути — как у канонического имени
	// режима.
	data, _, err := vaultClient.Get(t.Context(), "accounts/"+target.ID.String()+"/credential")
	if err != nil {
		t.Fatalf("vault get credential: %v", err)
	}
	if data["password"] != password {
		t.Error("legacy password mode did not pre-write the provided secret")
	}

	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &target.ID,
		Actions:   []string{"account.adopt_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.adopt_requested events = %d, want 1", len(events))
	}
	var meta struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.Mode != "set_password" {
		t.Errorf("audit metadata = %s (err=%v), want canonical mode=set_password", events[0].Metadata, err)
	}
}

// TestIntegrationAdoptAccountVerifyPassword — режим verify_password на
// API-слое: проверяемый пароль уходит во ВРЕМЕННЫЙ adopt-proof (канонический
// путь остаётся пустым — до подтверждения grantor не объявляет пароль своим),
// ставится операция account.adopt_verify с закреплённой версией, ownership
// остаётся unmanaged, а сам секрет не попадает ни в payload, ни в audit.
func TestIntegrationAdoptAccountVerifyPassword(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	invStore := inventory.NewStore()

	target := unmanagedLoginAccount(t, env.pool, conn.ID)
	path := "/api/v1/accounts/" + target.ID.String() + "/adopt"
	const password = "itest-adopt-verify-secret-marker"

	resp := env.do(t, http.MethodPost, path,
		map[string]any{"mode": "verify_password", "password": password}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), password) {
		t.Fatal("adopt response leaks password")
	}
	var out adoptOperationResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal adopt response: %v", err)
	}

	// Ownership до успеха операции не меняется, канонический путь секрета
	// пуст: подтверждения ещё не было.
	got, err := invStore.GetAccount(t.Context(), env.pool, target.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Ownership != inventory.OwnershipUnmanaged || got.VaultPath != "" {
		t.Errorf("account before verification = %q/%q, want unmanaged with empty vault_path",
			got.Ownership, got.VaultPath)
	}
	if _, _, err := vaultClient.Get(t.Context(), "accounts/"+target.ID.String()+"/credential"); err == nil {
		t.Error("verify_password wrote the canonical credential path before proving the password")
	}

	// Проверяемый пароль лежит во временном adopt-proof с username = engine
	// identity; именно его версия закреплена в payload операции.
	proofPath := "accounts/" + target.ID.String() + "/adopt-proof"
	data, proofVersion, err := vaultClient.Get(t.Context(), proofPath)
	if err != nil {
		t.Fatalf("vault get %s: %v", proofPath, err)
	}
	if data["username"] != target.EngineIdentity || data["password"] != password {
		t.Errorf("adopt proof username = %v, password matches = %v",
			data["username"], data["password"] == password)
	}

	op, err := operations.NewStore().Get(t.Context(), env.pool, out.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Kind != jobs.KindAccountAdoptVerify || op.Status != operations.StatusPending {
		t.Errorf("operation kind/status = %q/%q, want %s/pending", op.Kind, op.Status, jobs.KindAccountAdoptVerify)
	}
	var payload struct {
		Adopt                  bool `json:"adopt"`
		AdoptGenerate          bool `json:"adopt_generate"`
		CredentialVaultVersion int  `json:"credential_vault_version"`
	}
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		t.Fatalf("unmarshal operation payload: %v", err)
	}
	if !payload.Adopt || payload.AdoptGenerate || payload.CredentialVaultVersion != proofVersion {
		t.Errorf("operation payload %s does not pin the adopt proof version %d", op.Payload, proofVersion)
	}
	if strings.Contains(string(op.Payload), password) {
		t.Fatal("operation payload leaks password")
	}

	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &target.ID,
		Actions:   []string{"account.adopt_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.adopt_requested events = %d, want 1", len(events))
	}
	var meta struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || meta.Mode != "verify_password" {
		t.Errorf("audit metadata = %s (err=%v), want mode=verify_password", events[0].Metadata, err)
	}
	for _, sweep := range []string{
		`select count(*) from operations where payload::text like '%' || $1 || '%'
		   or coalesce(plan::text, '') like '%' || $1 || '%'
		   or coalesce(result::text, '') like '%' || $1 || '%'
		   or error like '%' || $1 || '%'`,
		`select count(*) from audit_events where metadata::text like '%' || $1 || '%'`,
	} {
		var n int
		if err := env.pool.QueryRow(t.Context(), sweep, password).Scan(&n); err != nil {
			t.Fatalf("canary sweep: %v", err)
		}
		if n != 0 {
			t.Errorf("password canary found by sweep %q: %d rows", sweep, n)
		}
	}
}

// Connector adoption stages the exact candidate and defers proof/ownership to
// the worker. No password is promoted and no account is managed at enqueue time.
func TestIntegrationAdoptAccountVerifyPasswordConnectorAccepted(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)
	target := unmanagedLoginAccount(t, env.pool, conn.ID)
	if _, err := env.pool.Exec(t.Context(),
		`update connections set execution_mode = 'connector' where id = $1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+target.ID.String()+"/adopt",
		map[string]any{"mode": "verify_password", "password": "itest-proof-candidate"}, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	if n := countAccountOperations(t, env.pool, target.ID); n != 1 {
		t.Fatalf("operations = %d", n)
	}
	if _, _, err := vaultClient.Get(t.Context(), "accounts/"+target.ID.String()+"/adopt-proof"); err != nil {
		t.Fatal("proof was not staged")
	}
	if _, _, err := vaultClient.Get(t.Context(), "accounts/"+target.ID.String()+"/credential"); err == nil {
		t.Fatal("unproved credential was promoted")
	}
	got, err := inventory.NewStore().GetAccount(t.Context(), env.pool, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ownership != inventory.OwnershipUnmanaged {
		t.Fatal("account managed before proof")
	}
}

// Учётка, под которой grantor управляет подключением, не принимается под
// управление ни одним путём: adopt сменил бы ей пароль и отнял бы у grantor
// доступ к самому подключению. Отметку ставит discovery в
// attributes.connection_admin; до этого теста гейт не был покрыт вовсе, а
// link-and-manage обходил его целиком.
func TestIntegrationAdoptConnectionAdminRejected(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	conn := activeFakeConnection(t, env.pool)

	target := unmanagedLoginAccount(t, env.pool, conn.ID)
	if _, err := env.pool.Exec(t.Context(),
		`update accounts set attributes = '{"connection_admin": true}'::jsonb where id = $1`,
		target.ID); err != nil {
		t.Fatalf("mark connection admin account: %v", err)
	}

	for _, mode := range []string{"metadata", "generate", "set_password", "verify_password"} {
		body := map[string]any{"mode": mode}
		if mode == "set_password" || mode == "verify_password" {
			body["password"] = "irrelevant-secret"
		}
		resp := env.do(t, http.MethodPost,
			"/api/v1/accounts/"+target.ID.String()+"/adopt", body, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}

	// Тот же запрет на link-and-manage: без него скрытие кнопки в UI
	// обходится прямым вызовом API.
	principalID := createServicePrincipal(t, env, operator, "conn-admin-guard-"+uniqueSuffix()[:8])
	resp := env.do(t, http.MethodPost,
		"/api/v1/accounts/"+target.ID.String()+"/link-and-manage",
		map[string]any{"principal_id": principalID}, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Учётка осталась неуправляемой.
	acct, err := inventory.NewStore().GetAccount(t.Context(), env.pool, target.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if acct.Ownership != inventory.OwnershipUnmanaged {
		t.Errorf("ownership = %q, want unmanaged", acct.Ownership)
	}
}
