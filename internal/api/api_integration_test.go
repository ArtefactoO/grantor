//go:build integration

// Integration-тесты API v1 против реального PostgreSQL (pgtest,
// GRANTOR_TEST_DB_DSN) и Vault (GRANTOR_TEST_VAULT_ADDR/TOKEN/MOUNT;
// тесты, которым нужен Vault, пропускаются без него).
//
// Dex не нужен: Authenticator собирается через auth.New против
// минимального фейкового OIDC discovery endpoint (JWKS и token exchange
// в тестах не используются), а session cookies и CSRF tokens
// генерируются напрямую через auth.Codec с тем же session secret.
package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/fake"
	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/yopass"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// testSessionSecret — общий секрет Authenticator и Codec тестов: cookies,
// подписанные Codec, валидны для сервера.
const testSessionSecret = "0123456789abcdef0123456789abcdef"

// registerFakeOnce защищает от повторной регистрации fake adapter:
// registry глобален на процесс, а Register паникует на дубликате.
var registerFakeOnce sync.Once

func registerFakeAdapter() {
	registerFakeOnce.Do(func() {
		adapter.Register(fake.Engine, func() adapter.Adapter { return fake.New() })
	})
}

// newFakeOIDC поднимает минимальный OIDC discovery endpoint: auth.New
// выполняет только discovery, поэтому достаточно issuer и адресов
// endpoints (они в тестах не вызываются).
func newFakeOIDC(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			srv.URL, srv.URL+"/auth", srv.URL+"/token", srv.URL+"/keys")
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestVault возвращает клиента Vault из окружения или пропускает
// тест, если Vault для integration-тестов не настроен.
func newTestVault(t *testing.T) *vault.Client {
	t.Helper()
	addr := os.Getenv("GRANTOR_TEST_VAULT_ADDR")
	token := os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if addr == "" || token == "" {
		t.Skip("set GRANTOR_TEST_VAULT_ADDR and GRANTOR_TEST_VAULT_TOKEN to run Vault-backed API tests")
	}
	mount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if mount == "" {
		mount = "secret"
	}
	c, err := vault.New(vault.Config{Address: addr, Token: token, Mount: mount})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	return c
}

// testEnv — собранный API-сервер поверх реальных stores и pgtest.Pool.
type testEnv struct {
	pool  *pgxpool.Pool
	srv   *httptest.Server
	codec auth.Codec
}

// testEnvOpts — необязательные параметры сборки testEnv: клиенты
// Vault/Yopass и флаги политик (scope enforcement, approval workflow,
// mass-revoke threshold). Zero value повторяет дефолты cmd/api для dev.
type testEnvOpts struct {
	vault               *vault.Client
	yopass              *yopass.Client
	enforcement         policy.EnforcementMode
	approvalRequired    bool
	massRevokeThreshold int
	// rotationConfirmThreshold — порог подтверждения ротации общего секрета
	// принципала (GRANTOR_ROTATION_CONFIRM_THRESHOLD). 0 = gate выключен:
	// дефолт cmd/api здесь намеренно не повторяется, чтобы существующие
	// тесты ротации не начали требовать confirm.
	rotationConfirmThreshold int
	// dispatcher переопределяет диспетчер операций: e2e-тесты каскада
	// передают полноценный River с worker, чтобы поставленные API операции
	// реально исполнялись. nil — insert-only, как раньше.
	dispatcher                 jobs.Dispatcher
	beforeAdminCredentialStage func(context.Context, uuid.UUID) error
}

// newTestEnv собирает httptest.Server с полным wiring API (как cmd/api).
// vaultClient может быть nil: тогда создание connection отвечает 503.
// Yopass в этом варианте не сконфигурирован: share отвечает 503. Scope
// enforcement выключен (поведение по умолчанию для существующих тестов).
func newTestEnv(t *testing.T, vaultClient *vault.Client) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: policy.EnforcementDisabled})
}

// newTestEnvWithYopass — newTestEnv с настроенным клиентом Yopass для
// сценариев одноразовой выдачи credentials.
func newTestEnvWithYopass(t *testing.T, vaultClient *vault.Client, yopassClient *yopass.Client) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{vault: vaultClient, yopass: yopassClient, enforcement: policy.EnforcementDisabled})
}

// newApprovalTestEnv — newTestEnv с включённым approval workflow опасных
// грантов (ADR-0010): опасный грант создаётся в pending_approval.
func newApprovalTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{enforcement: policy.EnforcementDisabled, approvalRequired: true})
}

// newMassRevokeTestEnv — newTestEnv с заданным порогом mass-revoke gate
// (GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD). approvalRequired при этом
// НЕ включается: порог работает независимо от основного флага.
func newMassRevokeTestEnv(t *testing.T, vaultClient *vault.Client, threshold int) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{
		vault:               vaultClient,
		enforcement:         policy.EnforcementDisabled,
		massRevokeThreshold: threshold,
	})
}

// newRotationConfirmTestEnv — newTestEnv с заданным порогом подтверждения
// ротации общего секрета принципала (GRANTOR_ROTATION_CONFIRM_THRESHOLD).
func newRotationConfirmTestEnv(t *testing.T, vaultClient *vault.Client, threshold int) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{
		vault:                    vaultClient,
		enforcement:              policy.EnforcementDisabled,
		rotationConfirmThreshold: threshold,
	})
}

// newScopeTestEnv — newTestEnv с заданным режимом scope enforcement (тесты
// scope policies).
func newScopeTestEnv(t *testing.T, vaultClient *vault.Client, enforcement policy.EnforcementMode) *testEnv {
	t.Helper()
	return buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: enforcement})
}

// buildTestEnv собирает httptest.Server с полным wiring API (как cmd/api),
// включая scope policies (enforcement) и token-auth service-принципалов.
func buildTestEnv(t *testing.T, opts testEnvOpts) *testEnv {
	t.Helper()
	vaultClient, yopassClient := opts.vault, opts.yopass
	enforcement, approvalRequired := opts.enforcement, opts.approvalRequired
	registerFakeAdapter()
	pool := pgtest.Pool(t)

	serviceTokens := servicetoken.NewStore()
	authn, err := auth.New(t.Context(), auth.Config{
		IssuerURL:     newFakeOIDC(t).URL,
		ClientID:      "grantor",
		RedirectURL:   "http://localhost/auth/callback",
		SessionSecret: []byte(testSessionSecret),
		TokenAuth:     api.NewServiceTokenAuth(pool, serviceTokens),
	})
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	codec, err := auth.NewCodec([]byte(testSessionSecret))
	if err != nil {
		t.Fatalf("auth.NewCodec: %v", err)
	}

	dispatcher := opts.dispatcher
	if dispatcher == nil {
		insertOnly, err := jobs.NewInsertOnly(pool)
		if err != nil {
			t.Fatalf("jobs.NewInsertOnly: %v", err)
		}
		dispatcher = insertOnly
	}
	server, err := api.New(api.Config{
		Pool:                pool,
		Connections:         connections.NewStore(),
		Inventory:           inventory.NewStore(),
		Operations:          operations.NewStore(),
		Audit:               audit.NewWriter(),
		Vault:               vaultClient,
		Credentials:         credentials.NewService(vaultClient, yopassClient),
		Dispatcher:          dispatcher,
		Auth:                authn,
		Policy:              policy.NewStore(),
		ScopeEnforcement:    enforcement,
		ServiceTokens:       serviceTokens,
		ApprovalRequired:    approvalRequired,
		MassRevokeThreshold: opts.massRevokeThreshold,

		RotationConfirmThreshold:   opts.rotationConfirmThreshold,
		BeforeAdminCredentialStage: opts.beforeAdminCredentialStage,
	})
	if err != nil {
		t.Fatalf("api.New: %v", err)
	}

	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)

	return &testEnv{pool: pool, srv: srv, codec: codec}
}

// session возвращает свежую сессию с заданной ролью.
func session(role auth.Role) auth.Session {
	return auth.Session{
		Subject:   "sub-" + string(role),
		Email:     string(role) + "@grantor.dev",
		Role:      role,
		ExpiresAt: time.Now().Add(time.Hour),
	}
}

// do выполняет запрос к тестовому серверу. sess == nil — анонимный
// запрос; csrf добавляет валидный заголовок X-Grantor-CSRF.
func (e *testEnv) do(t *testing.T, method, path string, body any, sess *auth.Session, csrf bool) *http.Response {
	t.Helper()

	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sess != nil {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: e.codec.Encode(*sess)})
		if csrf {
			req.Header.Set(auth.CSRFHeader, e.codec.CSRFToken(*sess))
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	t.Cleanup(func() { resp.Body.Close() }) //nolint:errcheck
	return resp
}

// readBody читает тело ответа целиком (для проверок на утечку секретов
// до разбора JSON).
func readBody(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return b
}

// requireStatus проверяет HTTP-статус ответа.
func requireStatus(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s: status = %d, want %d; body: %s",
			resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want, body)
	}
}

// createDraft создаёт connection в статусе draft напрямую через store
// (без Vault): для read-only и refresh сценариев admin credential не
// нужен.
func createDraft(t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(context.Background(), pool, connections.CreateParams{
		DisplayName: "itest-api-" + uuid.NewString(),
		Engine:      fake.Engine,
		Environment: "itest",
		Endpoints:   []string{"itest-target:5432"},
	})
	if err != nil {
		t.Fatalf("create draft connection: %v", err)
	}
	return conn
}

// connectionBody — подмножество connectionJSON для разбора ответов.
type connectionBody struct {
	ID                  string          `json:"id"`
	DisplayName         string          `json:"display_name"`
	Engine              string          `json:"engine"`
	Status              string          `json:"status"`
	VaultAdminPath      string          `json:"vault_admin_path"`
	AdminCredentialMode string          `json:"admin_credential_mode"`
	Endpoints           []string        `json:"endpoints"`
	Capabilities        []string        `json:"capabilities"`
	Drift               *map[string]int `json:"drift"`
}

func TestIntegrationAuthRequired(t *testing.T) {
	env := newTestEnv(t, nil)

	resp := env.do(t, http.MethodGet, "/api/v1/connections", nil, nil, false)
	requireStatus(t, resp, http.StatusUnauthorized)
}

func TestIntegrationCreateConnection(t *testing.T) {
	vaultClient := newTestVault(t)
	env := newTestEnv(t, vaultClient)
	admin := session(auth.RoleAdmin)
	viewer := session(auth.RoleViewer)

	const password = "itest-secret-marker-value"
	body := map[string]any{
		"display_name": "itest-create-" + uuid.NewString(),
		"engine":       fake.Engine,
		"environment":  "itest",
		"tags":         []string{"itest"},
		"endpoints":    []string{"target-postgres:5432"},
		"admin_credential": map[string]string{
			"username": "grantor_admin",
			"password": password,
		},
	}

	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	raw := readBody(t, resp)
	if strings.Contains(string(raw), password) {
		t.Fatal("create response leaks admin password")
	}
	var conn connectionBody
	if err := json.Unmarshal(raw, &conn); err != nil {
		t.Fatalf("unmarshal create response: %v", err)
	}
	if conn.Status != string(connections.StatusDraft) {
		t.Errorf("status = %q, want draft", conn.Status)
	}
	if !slices.Contains(conn.Capabilities, string(adapter.CapAccountRestore)) {
		t.Errorf("capabilities = %v, want adapter manifest account.restore", conn.Capabilities)
	}
	wantPath := "connections/" + conn.ID + "/admin"
	if conn.VaultAdminPath != wantPath {
		t.Errorf("vault_admin_path = %q, want %q", conn.VaultAdminPath, wantPath)
	}

	// Секрет действительно лёг в Vault.
	data, _, err := vaultClient.Get(t.Context(), wantPath)
	if err != nil {
		t.Fatalf("vault get %s: %v", wantPath, err)
	}
	if data["username"] != "grantor_admin" || data["password"] != password {
		t.Error("vault secret does not match submitted admin credential")
	}

	// vault_admin_path сохранён и в metadata database.
	connID, err := uuid.Parse(conn.ID)
	if err != nil {
		t.Fatalf("parse connection id %q: %v", conn.ID, err)
	}
	stored, err := connections.NewStore().Get(t.Context(), env.pool, connID)
	if err != nil {
		t.Fatalf("get stored connection: %v", err)
	}
	if stored.VaultAdminPath != wantPath {
		t.Errorf("stored vault_admin_path = %q, want %q", stored.VaultAdminPath, wantPath)
	}

	// Audit-событие создания записано с actor из сессии.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &connID,
		Actions:      []string{"connection.created"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	if events[0].ActorID != admin.Email {
		t.Errorf("audit actor = %q, want %q", events[0].ActorID, admin.Email)
	}
	if strings.Contains(string(events[0].Metadata), password) {
		t.Error("audit metadata leaks admin password")
	}

	// viewer не может создавать connections.
	resp = env.do(t, http.MethodPost, "/api/v1/connections", body, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	// Мутирующий запрос без CSRF-заголовка отклоняется.
	resp = env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, false)
	requireStatus(t, resp, http.StatusForbidden)

	// Незарегистрированный engine — 400.
	bad := map[string]any{}
	for k, v := range body {
		bad[k] = v
	}
	bad["engine"] = "no-such-engine"
	resp = env.do(t, http.MethodPost, "/api/v1/connections", bad, &admin, true)
	requireStatus(t, resp, http.StatusBadRequest)
}

func TestIntegrationListAndGetConnections(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	conn := createDraft(t, env.pool)

	resp := env.do(t, http.MethodGet, "/api/v1/connections", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Connections []connectionBody `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, c := range list.Connections {
		if c.ID == conn.ID.String() {
			found = true
			if c.Drift == nil {
				t.Error("list item has no drift summary")
			}
		}
	}
	if !found {
		t.Fatalf("connection %s not found in list of %d", conn.ID, len(list.Connections))
	}

	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+conn.ID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var got connectionBody
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if got.Status != string(connections.StatusDraft) || got.Drift == nil {
		t.Errorf("unexpected detail: status=%q drift=%v", got.Status, got.Drift)
	}

	// Несуществующий id — 404; невалидный uuid — 400.
	resp = env.do(t, http.MethodGet, "/api/v1/connections/"+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodGet, "/api/v1/connections/not-a-uuid", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
}

func TestIntegrationEmptyInventoryLists(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	conn := createDraft(t, env.pool)

	cases := []struct {
		path string
		key  string
	}{
		{"/api/v1/connections/" + conn.ID.String() + "/resources", "resources"},
		{"/api/v1/connections/" + conn.ID.String() + "/accounts", "accounts"},
		{"/api/v1/connections/" + conn.ID.String() + "/permissions", "permissions"},
	}
	for _, tc := range cases {
		resp := env.do(t, http.MethodGet, tc.path, nil, &viewer, false)
		requireStatus(t, resp, http.StatusOK)
		body := readBody(t, resp)
		// Пустой инвентарь отдаётся как [], а не null.
		if !strings.Contains(string(body), fmt.Sprintf("%q:[]", tc.key)) {
			t.Errorf("GET %s: expected empty %q array, got: %s", tc.path, tc.key, body)
		}
	}

	// Вложенные списки несуществующего connection — 404.
	resp := env.do(t, http.MethodGet, "/api/v1/connections/"+uuid.NewString()+"/resources", nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)

	// Bindings несуществующих account/resource — 404.
	resp = env.do(t, http.MethodGet, "/api/v1/accounts/"+uuid.NewString()+"/bindings", nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
	resp = env.do(t, http.MethodGet, "/api/v1/resources/"+uuid.NewString()+"/bindings", nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationResourceTreeProjectionAndLazyDetail(t *testing.T) {
	env := newTestEnv(t, nil)
	viewer := session(auth.RoleViewer)
	conn := createDraft(t, env.pool)
	resourceID := uuid.New()
	if _, err := env.pool.Exec(t.Context(), `
		insert into resources (
			id, connection_id, kind, external_id, name, canonical_path,
			attributes, fingerprint, status, ownership
		) values ($1, $2, 'database', 'db:app', 'app', 'app',
			'{"owner":"svc_app"}'::jsonb, 'heavy-fingerprint', 'observed', 'unmanaged')`,
		resourceID, conn.ID); err != nil {
		t.Fatalf("insert resource: %v", err)
	}

	listPath := "/api/v1/connections/" + conn.ID.String() + "/resources"
	resp := env.do(t, http.MethodGet, listPath+"?view=tree", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var tree struct {
		Resources []map[string]any `json:"resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tree); err != nil {
		t.Fatalf("decode tree resources: %v", err)
	}
	if len(tree.Resources) != 1 {
		t.Fatalf("tree resources = %d, want 1", len(tree.Resources))
	}
	for _, omitted := range []string{"attributes", "fingerprint", "canonical_path", "created_at", "updated_at"} {
		if _, exists := tree.Resources[0][omitted]; exists {
			t.Errorf("tree resource unexpectedly contains heavyweight field %q", omitted)
		}
	}
	if tree.Resources[0]["name"] != "app" || tree.Resources[0]["kind"] != "database" {
		t.Errorf("tree resource = %+v, want app database", tree.Resources[0])
	}

	resp = env.do(t, http.MethodGet, "/api/v1/resources/"+resourceID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var detail map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode resource detail: %v", err)
	}
	if detail["fingerprint"] != "heavy-fingerprint" {
		t.Errorf("detail fingerprint = %v, want heavy-fingerprint", detail["fingerprint"])
	}
	attrs, _ := detail["attributes"].(map[string]any)
	if attrs["owner"] != "svc_app" {
		t.Errorf("detail attributes = %#v, want owner svc_app", attrs)
	}

	resp = env.do(t, http.MethodGet, listPath+"?view=unknown", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
	resp = env.do(t, http.MethodGet, "/api/v1/resources/"+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationRefresh(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	conn := createDraft(t, env.pool)
	path := "/api/v1/connections/" + conn.ID.String() + "/refresh"

	// viewer не может запускать refresh.
	resp := env.do(t, http.MethodPost, path, nil, &viewer, true)
	requireStatus(t, resp, http.StatusForbidden)

	windowBefore := time.Now().Unix() / 60
	resp = env.do(t, http.MethodPost, path, nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	var first struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&first); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}

	// Операция в pending, connection переведён в discovering.
	op, err := operations.NewStore().Get(t.Context(), env.pool, first.OperationID)
	if err != nil {
		t.Fatalf("get operation: %v", err)
	}
	if op.Status != operations.StatusPending {
		t.Errorf("operation status = %q, want pending", op.Status)
	}
	if op.Kind != jobs.KindConnectionDiscover {
		t.Errorf("operation kind = %q, want %q", op.Kind, jobs.KindConnectionDiscover)
	}
	if op.ConnectionID == nil || *op.ConnectionID != conn.ID {
		t.Errorf("operation connection_id = %v, want %s", op.ConnectionID, conn.ID)
	}
	refreshed, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if refreshed.Status != connections.StatusDiscovering {
		t.Errorf("connection status = %q, want discovering", refreshed.Status)
	}

	// Повторный refresh в том же минутном окне возвращает ту же операцию.
	resp = env.do(t, http.MethodPost, path, nil, &operator, true)
	windowAfter := time.Now().Unix() / 60
	requireStatus(t, resp, http.StatusAccepted)
	var second struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&second); err != nil {
		t.Fatalf("decode second refresh response: %v", err)
	}
	if windowBefore == windowAfter && second.OperationID != first.OperationID {
		t.Errorf("second refresh operation = %s, want %s (same idempotency window)",
			second.OperationID, first.OperationID)
	}

	// Audit-событие refresh записано.
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:      []string{"connection.refresh_requested"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("no connection.refresh_requested audit event")
	}

	// Refresh несуществующего connection — 404.
	resp = env.do(t, http.MethodPost, "/api/v1/connections/"+uuid.NewString()+"/refresh", nil, &operator, true)
	requireStatus(t, resp, http.StatusNotFound)
}

func TestIntegrationOperationsListAndGet(t *testing.T) {
	env := newTestEnv(t, nil)
	operator := session(auth.RoleOperator)
	viewer := session(auth.RoleViewer)
	connA := createDraft(t, env.pool)
	connB := createDraft(t, env.pool)

	refresh := func(id uuid.UUID) uuid.UUID {
		resp := env.do(t, http.MethodPost, "/api/v1/connections/"+id.String()+"/refresh", nil, &operator, true)
		requireStatus(t, resp, http.StatusAccepted)
		var out struct {
			OperationID uuid.UUID `json:"operation_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode refresh response: %v", err)
		}
		return out.OperationID
	}
	opA := refresh(connA.ID)
	opB := refresh(connB.ID)

	// Фильтр по connection_id возвращает только операции connA.
	resp := env.do(t, http.MethodGet, "/api/v1/operations?connection_id="+connA.ID.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var list struct {
		Operations []struct {
			ID           uuid.UUID  `json:"id"`
			ConnectionID *uuid.UUID `json:"connection_id"`
		} `json:"operations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatalf("decode operations list: %v", err)
	}
	foundA := false
	for _, op := range list.Operations {
		if op.ConnectionID == nil || *op.ConnectionID != connA.ID {
			t.Errorf("operation %s has connection_id %v, want %s", op.ID, op.ConnectionID, connA.ID)
		}
		if op.ID == opA {
			foundA = true
		}
		if op.ID == opB {
			t.Errorf("operation %s of another connection leaked into filtered list", opB)
		}
	}
	if !foundA {
		t.Errorf("operation %s not found in filtered list", opA)
	}

	// Detail существующей операции и 404 на несуществующую.
	resp = env.do(t, http.MethodGet, "/api/v1/operations/"+opA.String(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var detail struct {
		ID   uuid.UUID `json:"id"`
		Kind string    `json:"kind"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode operation detail: %v", err)
	}
	if detail.ID != opA || detail.Kind != jobs.KindConnectionDiscover {
		t.Errorf("unexpected detail: %+v", detail)
	}
	resp = env.do(t, http.MethodGet, "/api/v1/operations/"+uuid.NewString(), nil, &viewer, false)
	requireStatus(t, resp, http.StatusNotFound)

	// Невалидный фильтр — 400.
	resp = env.do(t, http.MethodGet, "/api/v1/operations?connection_id=zzz", nil, &viewer, false)
	requireStatus(t, resp, http.StatusBadRequest)
}

func TestIntegrationVaultUnavailable(t *testing.T) {
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)

	body := map[string]any{
		"display_name": "itest-no-vault-" + uuid.NewString(),
		"engine":       fake.Engine,
		"endpoints":    []string{"target:5432"},
		"admin_credential": map[string]string{
			"username": "grantor_admin",
			"password": "unused-secret",
		},
	}
	resp := env.do(t, http.MethodPost, "/api/v1/connections", body, &admin, true)
	requireStatus(t, resp, http.StatusServiceUnavailable)
}
