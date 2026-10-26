//go:build integration

// Integration-тесты двух связанных инвариантов носителя credential:
//
//   - указатель на секрет (vault_path) не переживает смену принципала: после
//     unlink или перепривязки он не может ссылаться на общий секрет чужого
//     принципала, а share обязан отказать, даже если такая строка уже есть в
//     базе (защита в глубину для данных, испорченных до исправления);
//   - lifecycle- и credential-операции применимы только к kind=login: роль
//     без логина (kind=group) — носитель ПРАВ, и delete над ней означал бы на
//     целевой системе DROP ROLE с каскадным отзывом доступа у всех членов.
package api_test

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/yopass"
)

// newTestYopass возвращает клиента Yopass из окружения harness или
// пропускает тест. Нужен там, где отсутствие guard должно давать реальную
// выданную ссылку, а не 503: иначе тест «зеленел» бы по не той причине.
func newTestYopass(t *testing.T) *yopass.Client {
	t.Helper()
	addr := os.Getenv("GRANTOR_TEST_YOPASS_ADDR")
	if addr == "" {
		t.Skip("GRANTOR_TEST_YOPASS_ADDR is not set; skipping credential share test")
	}
	c, err := yopass.New(yopass.Config{APIURL: addr, PublicURL: "http://localhost:58090"})
	if err != nil {
		t.Fatalf("yopass.New: %v", err)
	}
	return c
}

// managedGroupAccount вставляет managed-аккаунт с kind=group напрямую в
// metadata database: через API такая строка теперь не создаётся, но в
// существующих базах она есть — её оставил adopt без guard по kind.
func managedGroupAccount(t *testing.T, pool *pgxpool.Pool, connID uuid.UUID) inventory.Account {
	t.Helper()
	identity := "itest_grp_" + uniqueSuffix()[:8]
	var id uuid.UUID
	if err := pool.QueryRow(t.Context(), `
		insert into accounts (connection_id, kind, engine_identity, credential_mode, vault_path, status, ownership)
		values ($1, 'group', $2, 'generated', 'accounts/fake/credential', 'active', 'managed')
		returning id`, connID, identity).Scan(&id); err != nil {
		t.Fatalf("insert managed group account: %v", err)
	}
	acct, err := inventory.NewStore().GetAccount(t.Context(), pool, id)
	if err != nil {
		t.Fatalf("get managed group account: %v", err)
	}
	return acct
}

// accountRow перечитывает аккаунт из metadata database.
func accountRow(t *testing.T, pool *pgxpool.Pool, id uuid.UUID) inventory.Account {
	t.Helper()
	acct, err := inventory.NewStore().GetAccount(t.Context(), pool, id)
	if err != nil {
		t.Fatalf("get account %s: %v", id, err)
	}
	return acct
}

// TestIntegrationUnlinkDetachesPrincipalSharedCredential: unlink и
// перепривязка на другого принципала снимают указатель на общий секрет
// прежнего принципала вместе с credential_mode, а share по такому аккаунту
// отказывает.
func TestIntegrationUnlinkDetachesPrincipalSharedCredential(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnvWithYopass(t, vaultClient, newTestYopass(t))
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Detach Service "+uniqueSuffix())
	other := createPrincipalRow(t, env.pool, "Other Service "+uniqueSuffix())
	// Три подключения одного окружения: один аккаунт отвязываем, второй
	// перепривязываем, третий остаётся на общем секрете — иначе ротация
	// принципала не найдёт что ротировать.
	items := make([]map[string]any, 0, 3)
	for i := 0; i < 3; i++ {
		conn := activeFakeConnectionEnv(t, env.pool, "test")
		items = append(items, map[string]any{
			"connection_id": conn.ID,
			"permission_id": findPermission(t, env.pool, conn.ID, "role:app-readonly").ID,
		})
	}
	identity := "itest_dtc_" + uniqueSuffix()[:8]
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, items)
	if len(access.Children) != 3 {
		t.Fatalf("access children = %d, want 3", len(access.Children))
	}
	finishProvisionChildren(t, env, access.Children)

	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}
	unlinked, relinked := access.Children[0].AccountID, access.Children[1].AccountID
	for _, id := range []uuid.UUID{unlinked, relinked} {
		acct := accountRow(t, env.pool, id)
		if acct.VaultPath != sharedPath || acct.CredentialMode == nil ||
			*acct.CredentialMode != inventory.CredentialModeExistingVaultRef {
			t.Fatalf("account %s = %q/%v, want shared secret of the principal", id, acct.VaultPath, acct.CredentialMode)
		}
	}

	// Пока аккаунт принадлежит принципалу, выдача его общего пароля законна.
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+unlinked.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusCreated)

	// Отвязка снимает и указатель, и режим: аккаунт больше не делит секрет
	// принципала.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+unlinked.String()+"/unlink", nil, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	after := accountRow(t, env.pool, unlinked)
	if after.PrincipalID != nil || after.VaultPath != "" || after.CredentialMode != nil {
		t.Fatalf("account after unlink = principal %v, vault_path %q, mode %v; want detached",
			after.PrincipalID, after.VaultPath, after.CredentialMode)
	}

	// Факт сброса виден в audit: доступ к аккаунту на целевой системе
	// сохраняется, но grantor больше не знает его пароля.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		AccountID: &unlinked, Actions: []string{"account.unlinked"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("account.unlinked events = %d, want 1", len(events))
	}
	var meta struct {
		CredentialReferenceCleared bool `json:"credential_reference_cleared"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil || !meta.CredentialReferenceCleared {
		t.Errorf("audit metadata = %s (err=%v), want credential_reference_cleared", events[0].Metadata, err)
	}
	if strings.Contains(string(events[0].Metadata), sharedPath) {
		t.Error("audit metadata leaks the shared credential path")
	}

	// Перепривязка на другого принципала — тот же сброс: указатель на секрет
	// первого принципала не переезжает вместе с аккаунтом.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+relinked.String()+"/link",
		map[string]any{"principal_id": other.ID}, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	moved := accountRow(t, env.pool, relinked)
	if moved.PrincipalID == nil || *moved.PrincipalID != other.ID {
		t.Fatalf("account principal = %v, want %s", moved.PrincipalID, other.ID)
	}
	if moved.VaultPath != "" || moved.CredentialMode != nil {
		t.Errorf("account after relink = %q/%v, want detached from the previous principal secret",
			moved.VaultPath, moved.CredentialMode)
	}

	// Ротация общего секрета принципала (третий аккаунт всё ещё на нём) —
	// исходный сценарий утечки. Ни отвязанный, ни перепривязанный аккаунт в
	// неё не попадают, и выдать по ним пароль принципала нельзя.
	resp = env.do(t, http.MethodPost,
		"/api/v1/principals/"+principal.ID.String()+"/rotate?environment=test", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var rotate struct {
		Children []struct {
			AccountID uuid.UUID `json:"account_id"`
		} `json:"children"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotate); err != nil {
		t.Fatalf("decode rotate response: %v", err)
	}
	for _, child := range rotate.Children {
		if child.AccountID == unlinked || child.AccountID == relinked {
			t.Errorf("rotate touched detached account %s", child.AccountID)
		}
	}
	for _, id := range []uuid.UUID{unlinked, relinked} {
		resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+id.String()+"/share", nil, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
	}
}

// TestIntegrationShareRejectsForeignPrincipalSecret: строка с указателем на
// общий секрет ЧУЖОГО принципала (такие остались от версий без сброса
// указателя) не выдаётся через share. Проверка идёт с настроенным Yopass:
// без guard ручка вернула бы 201 и рабочую ссылку на актуальный пароль
// принципала.
func TestIntegrationShareRejectsForeignPrincipalSecret(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnvWithYopass(t, vaultClient, newTestYopass(t))
	operator := session(auth.RoleOperator)

	principal := createPrincipalRow(t, env.pool, "Foreign Service "+uniqueSuffix())
	conn := activeFakeConnectionEnv(t, env.pool, "test")
	identity := "itest_frg_" + uniqueSuffix()[:8]
	access := grantPrincipalAccessItems(t, env, &operator, principal.ID, identity, []map[string]any{
		{"connection_id": conn.ID, "permission_id": findPermission(t, env.pool, conn.ID, "role:app-readonly").ID},
	})
	finishProvisionChildren(t, env, access.Children)
	acctID := access.Children[0].AccountID
	sharedPath, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
	if err != nil {
		t.Fatalf("principal credential path: %v", err)
	}

	// Воспроизводим строку, оставленную прежним unlink: принципала нет, а
	// указатель на его общий секрет остался.
	if _, err := env.pool.Exec(t.Context(),
		`update accounts set principal_id = null where id = $1`, acctID); err != nil {
		t.Fatalf("simulate stale pointer: %v", err)
	}
	stale := accountRow(t, env.pool, acctID)
	if stale.VaultPath != sharedPath || stale.PrincipalID != nil {
		t.Fatalf("fixture = %q/%v, want stale pointer without principal", stale.VaultPath, stale.PrincipalID)
	}

	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)
	body := string(readBody(t, resp))
	if strings.Contains(body, sharedPath) {
		t.Error("share error leaks the shared credential path")
	}
	if strings.Contains(body, "link") {
		t.Errorf("share response looks like a delivery: %s", body)
	}

	// Тот же аккаунт, но указатель ведёт в раздел ДРУГОГО принципала:
	// принадлежность проверяется, а не просто наличие принципала.
	other := createPrincipalRow(t, env.pool, "Owner Service "+uniqueSuffix())
	if _, err := env.pool.Exec(t.Context(),
		`update accounts set principal_id = $2 where id = $1`, acctID, other.ID); err != nil {
		t.Fatalf("relink to another principal: %v", err)
	}
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusConflict)

	// Собственный путь аккаунта тем же guard не отбрасывается: он ни на
	// какого принципала не ссылается.
	ownPath, err := vault.AccountCredentialPath(acctID.String())
	if err != nil {
		t.Fatalf("account credential path: %v", err)
	}
	if _, err := vaultClient.Put(t.Context(), ownPath, map[string]any{
		"username": identity, "password": "itest-own-secret-marker",
	}); err != nil {
		t.Fatalf("put own credential: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(),
		`update accounts set vault_path = $2, credential_mode = 'generated' where id = $1`,
		acctID, ownPath); err != nil {
		t.Fatalf("point account at its own secret: %v", err)
	}
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+acctID.String()+"/share", nil, &operator, true)
	requireStatus(t, resp, http.StatusCreated)
}

// TestIntegrationAccountKindGuards: над носителем прав (kind=group) закрыты
// delete/rotate/disable/enable/share и кредовые режимы adopt; разрешён ровно
// один путь — adopt в режиме metadata, который целевую систему не трогает.
func TestIntegrationAccountKindGuards(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	admin := session(auth.RoleAdmin)
	conn := activeFakeConnection(t, env.pool)

	// readers из fake-снапшота — роль без логина, найденная discovery.
	readers := findAccount(t, env.pool, conn.ID, "readers")
	if readers.Kind != inventory.AccountKindGroup {
		t.Fatalf("fixture account kind = %q, want group", readers.Kind)
	}
	// Кредовые режимы закрыты все до одного: у роли нет пароля, который можно
	// подтвердить, задать или сгенерировать. Проверяем их ДО metadata-adopt —
	// иначе сработал бы более ранний guard "account is already managed" и
	// проверка стала бы бессмысленной.
	var resp *http.Response
	for _, mode := range []map[string]any{
		{"mode": "generate"},
		{"mode": "set_password", "password": "itest-should-never-be-stored"},
		{"mode": "verify_password", "password": "itest-should-never-be-stored"},
		// Legacy-синоним set_password закрыт наравне с каноническим именем.
		{"mode": "password", "password": "itest-should-never-be-stored"},
	} {
		resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+readers.ID.String()+"/adopt", mode, &operator, true)
		requireStatus(t, resp, http.StatusConflict)
		// Отказ обязан объяснять причину и подсказывать разрешённый путь,
		// иначе тест зеленел бы на любом постороннем 409.
		if body := string(readBody(t, resp)); !strings.Contains(body, "metadata") {
			t.Errorf("conflict body for mode %v = %s, want a hint that only metadata adoption is available",
				mode["mode"], body)
		}
		got := accountRow(t, env.pool, readers.ID)
		if got.Ownership != inventory.OwnershipUnmanaged {
			t.Errorf("ownership after refused adopt = %q, want unmanaged", got.Ownership)
		}
		if got.VaultPath != "" {
			t.Errorf("vault path after refused credential adoption = %q, want empty", got.VaultPath)
		}
	}
	// metadata — единственный разрешённый режим: роль берётся под наблюдение,
	// пароль ей при этом не заводится.
	resp = env.do(t, http.MethodPost, "/api/v1/accounts/"+readers.ID.String()+"/adopt",
		map[string]any{"mode": "metadata"}, &operator, true)
	requireStatus(t, resp, http.StatusOK)
	adopted := accountRow(t, env.pool, readers.ID)
	if adopted.Ownership != inventory.OwnershipManaged {
		t.Errorf("ownership after metadata adoption = %q, want managed", adopted.Ownership)
	}
	if adopted.VaultPath != "" {
		t.Errorf("vault path after metadata adoption = %q, want empty", adopted.VaultPath)
	}

	// Managed group-аккаунт (наследие adopt без guard): lifecycle- и
	// credential-операции над ним закрыты.
	group := managedGroupAccount(t, env.pool, conn.ID)
	base := "/api/v1/accounts/" + group.ID.String()
	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   any
		sess   auth.Session
	}{
		{"disable", http.MethodPost, base + "/disable", nil, operator},
		{"enable", http.MethodPost, base + "/enable", nil, operator},
		{"rotate", http.MethodPost, base + "/rotate", nil, operator},
		{"share", http.MethodPost, base + "/share", nil, operator},
		// account.delete для PostgreSQL — DROP ROLE: самый разрушительный
		// путь, поэтому проверяем именно подтверждённый вариант.
		{"delete", http.MethodDelete, base + "?confirm=true", nil, admin},
		{"restore", http.MethodPost, base + "/restore",
			map[string]any{"credential": map[string]any{"mode": "generated"}}, admin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sess := tc.sess
			resp := env.do(t, tc.method, tc.path, tc.body, &sess, true)
			requireStatus(t, resp, http.StatusConflict)
		})
	}
	// Ни одна отклонённая ручка не поставила операцию.
	if n := countAccountOperations(t, env.pool, group.ID); n != 0 {
		t.Errorf("operations for a group account = %d, want 0", n)
	}
	if got := accountRow(t, env.pool, group.ID); got.Status != inventory.AccountActive {
		t.Errorf("group account status = %q, want active (untouched)", got.Status)
	}
}
