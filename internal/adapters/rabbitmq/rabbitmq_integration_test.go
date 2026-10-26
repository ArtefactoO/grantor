//go:build integration

// Интеграционные тесты RabbitMQ adapter (discovery и мутации). Требуют
// «целевой» RabbitMQ с включённым Management-плагином: URL админского
// подключения задаётся через GRANTOR_TEST_RABBITMQ_URL
// ("http://<user>:<pass>@host:15672"), иначе тесты пропускаются. Фикстура
// создаётся идемпотентно, поэтому тесты можно запускать многократно над одним
// и тем же брокером.
//
// URL и пароли в логи не выводятся: секретный материал берётся из URL и
// передаётся заголовком Authorization, но не печатается.
package rabbitmq_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

const (
	// rabbitEnv — переменная окружения с URL Management API (admin).
	rabbitEnv = "GRANTOR_TEST_RABBITMQ_URL"
	// appVhost — vhost фикстуры.
	appVhost = "app_vhost"
	// fixtureUser — служебный пользователь фикстуры. Сортируется раньше
	// админского логина, поэтому contract suite выбирает именно его как
	// активный login-аккаунт и не трогает администратора.
	fixtureUser = "app_svc"
)

// target возвращает разобранный URL целевого RabbitMQ или пропускает тест.
func target(t *testing.T) (rawURL string, base, user, pass string) {
	t.Helper()
	rawURL = os.Getenv(rabbitEnv)
	if rawURL == "" {
		t.Skipf("%s is not set; skipping RabbitMQ integration test", rabbitEnv)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rabbitEnv, err)
	}
	pass, _ = u.User.Password()
	return rawURL, u.Scheme + "://" + u.Host, u.User.Username(), pass
}

// connectionFromURL строит adapter.Connection из URL: endpoint (host:port),
// admin credential и TLS-режим по scheme.
func connectionFromURL(t *testing.T, rawURL string) adapter.Connection {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", rabbitEnv, err)
	}
	mode := "disabled"
	if u.Scheme == "https" {
		mode = "require"
	}
	pass, _ := u.User.Password()
	return adapter.Connection{
		ID:        "conn-rabbitmq-target",
		Engine:    rabbitmq.Engine,
		Endpoints: []string{u.Host},
		TLS:       adapter.TLSConfig{Mode: mode},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: u.User.Username(),
			Secret:   []byte(pass),
		},
	}
}

// TestContract прогоняет общий contract suite поверх целевого RabbitMQ.
// Manifest объявляет access.grant/revoke, поэтому suite выполняет grant/revoke
// тесты: фикстура даёт активный login-аккаунт (app_svc) и не менее двух
// assignable не-dangerous permissions (tag-роли management/monitoring/
// policymaker).
func TestContract(t *testing.T) {
	rawURL, base, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, user, pass)
	conn := connectionFromURL(t, rawURL)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return rabbitmq.New(), conn
		},
	})
}

// TestValidateConnection проверяет, что admin credential проходит валидацию.
func TestValidateConnection(t *testing.T) {
	rawURL, _, _, _ := target(t)
	ctx := context.Background()
	if err := rabbitmq.New().ValidateConnection(ctx, connectionFromURL(t, rawURL)); err != nil {
		t.Fatalf("ValidateConnection: %v", err)
	}
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры и верно
// классифицирует топологию, аккаунты, permissions и bindings.
func TestDiscoverFixture(t *testing.T) {
	rawURL, base, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, user, pass)

	snap, err := rabbitmq.New().Discover(ctx, connectionFromURL(t, rawURL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Одноузловой контейнер — standalone; под GRANTOR_TEST_CLUSTERS harness
	// присоединяет к цели второй узел, и та же цель становится cluster.
	if want := wantRabbitTopology(); snap.Topology["topology"] != want {
		t.Errorf("topology = %v, want %s", snap.Topology["topology"], want)
	}

	resources := map[string]adapter.ObservedResource{}
	for _, r := range snap.Resources {
		resources[r.ExternalID] = r
	}
	for _, id := range []string{"vhost:/", "vhost:" + appVhost} {
		r, ok := resources[id]
		if !ok {
			t.Errorf("resource %q not found", id)
			continue
		}
		if r.Kind != "vhost" || r.Fingerprint == "" {
			t.Errorf("resource %q = %+v, want kind vhost with fingerprint", id, r)
		}
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		accounts[a.EngineIdentity] = a
	}
	svc, ok := accounts[fixtureUser]
	if !ok {
		t.Fatalf("account %q not found", fixtureUser)
	}
	if svc.Kind != "login" || svc.Disabled {
		t.Errorf("account %q = %+v, want active login", fixtureUser, svc)
	}

	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		perms[p.ExternalID] = p
	}
	if admin, ok := perms["tag:administrator"]; !ok || !admin.Dangerous {
		t.Error("permission tag:administrator must exist and be dangerous")
	}
	if mgmt, ok := perms["tag:management"]; !ok || mgmt.Dangerous || !mgmt.Assignable {
		t.Error("permission tag:management must exist, be assignable and non-dangerous")
	}
	// Полный доступ внутри одного vhost — базовый рабочий доступ, а не
	// эскалация: опасным он не считается (см. buildPermissions).
	if va, ok := perms["vhost-access:"+appVhost]; !ok || va.Dangerous || !va.Assignable {
		t.Error("permission vhost-access:app_vhost must exist, be assignable and non-dangerous")
	}

	// Фикстурный пользователь имеет тег monitoring и full-permission на
	// app_vhost, значит должны присутствовать оба binding.
	if !hasBinding(snap, fixtureUser, "tag:monitoring") {
		t.Errorf("binding %s -> tag:monitoring not found", fixtureUser)
	}
	if !hasBinding(snap, fixtureUser, "vhost-access:"+appVhost) {
		t.Errorf("binding %s -> vhost-access:%s not found", fixtureUser, appVhost)
	}
}

// TestTopologyStandalone проверяет определение standalone на одноузловом
// контейнере (multi-node cluster проверяется юнит-тестом по canned JSON, а
// живьём — TestTopologyCluster под GRANTOR_TEST_CLUSTERS).
func TestTopologyStandalone(t *testing.T) {
	rawURL, _, _, _ := target(t)
	if rabbitClustered() {
		t.Skipf("%s is set: the target broker is clustered; see TestTopologyCluster", rabbitClusterEnv)
	}
	ctx := context.Background()
	snap, err := rabbitmq.New().Discover(ctx, connectionFromURL(t, rawURL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}
	if snap.Topology["node_count"] != 1 {
		t.Errorf("node_count = %v, want 1", snap.Topology["node_count"])
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл пользователя:
// create -> grant tag (login через Management API) -> rotate (новый пароль
// работает, старый — нет) -> disable -> enable -> grant vhost-permission
// (в т.ч. на default vhost "/", проверяя %2F-кодирование) -> set/clear tag ->
// delete.
func TestAccountLifecycle(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, adminUser, adminPass)
	conn := connectionFromURL(t, rawURL)
	ad := rabbitmq.New()

	user := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	admin := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	t.Cleanup(func() { admin.delete(ctx, "/api/users/"+url.PathEscape(user)) })

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: conn,
		Account:    account,
		Credential: cred,
	})

	// Тег monitoring делает пользователя способным логиниться в Management API.
	grant := func(permission string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: permission,
		}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("tag:monitoring"))
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("tag:monitoring")) // повтор — StepSkipped

	if status := login(ctx, t, base, user, string(cred.Secret)); status != http.StatusOK {
		t.Fatalf("login with generated password: status %d, want 200", status)
	}
	if err := ad.ProveCredential(ctx, conn, account, *cred); err != nil {
		t.Fatalf("ProveCredential with generated password: %v", err)
	}

	// Ротация пароля: новый работает, старый — нет; тег monitoring сохранён.
	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if status := login(ctx, t, base, user, string(rotated.Secret)); status != http.StatusOK {
		t.Fatalf("login with rotated password: status %d, want 200", status)
	}
	if err := ad.ProveCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("ProveCredential with rotated password: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account, *cred); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("ProveCredential with old password: error = %v, want ErrExternalIdentityConflict", err)
	}
	if status := login(ctx, t, base, user, string(cred.Secret)); status == http.StatusOK {
		t.Fatal("login with old password must fail after rotation")
	}

	// Disable: снятие всех прав и маркер. После disable Management API для
	// пользователя недоступен (нет функциональных тегов).
	adaptertest.PlanApplyVerify(ctx, t, ad, disableEnable(conn, account, adapter.ChangeAccountDisable))
	adaptertest.PlanApplyVerify(ctx, t, ad, disableEnable(conn, account, adapter.ChangeAccountDisable)) // idempotent
	if status := login(ctx, t, base, user, string(rotated.Secret)); status == http.StatusOK {
		t.Fatal("disabled user must not be able to use the management API")
	}

	// Enable снимает маркер.
	adaptertest.PlanApplyVerify(ctx, t, ad, disableEnable(conn, account, adapter.ChangeAccountEnable))
	adaptertest.PlanApplyVerify(ctx, t, ad, disableEnable(conn, account, adapter.ChangeAccountEnable)) // idempotent

	// Grant vhost-permission на именованный vhost и на default "/" (%2F).
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("vhost-access:"+appVhost))
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("vhost-access:/"))
	revokeSlash := grant("vhost-access:/")
	revokeSlash.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revokeSlash)

	// Set/clear тега: management восстанавливает доступ к Management API.
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("tag:management"))
	if status := login(ctx, t, base, user, string(rotated.Secret)); status != http.StatusOK {
		t.Fatalf("login after re-granting management tag: status %d, want 200", status)
	}
	revokeMgmt := grant("tag:management")
	revokeMgmt.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revokeMgmt)

	// Delete и его идемпотентность.
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err == nil {
		t.Error("RotateCredential must fail for a deleted user")
	}
}

func TestPermissionTemplateLifecycleAndRediscovery(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, adminUser, adminPass)
	admin := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	// Restore the shared fixture regardless of where the test fails.
	t.Cleanup(func() {
		admin.put(context.Background(), t,
			"/api/permissions/"+url.PathEscape(appVhost)+"/"+url.PathEscape(fixtureUser),
			map[string]any{"configure": ".*", "write": ".*", "read": ".*"})
	})

	template := rabbitmqconfig.PermissionTemplate{
		Key: "etl-worker", Name: "ETL worker", Description: "ETL queues only",
		Vhost:     appVhost,
		Configure: `^(status_changes|project_etl_match_state_updates)$`,
		Write:     `^project_etl_match_state_updates$`,
		Read:      `^(status_changes|project_etl_match_state_updates)$`,
	}
	conn := connectionFromURL(t, rawURL)
	conn.Attributes = map[string]any{rabbitmqconfig.AttributePermissionTemplates: []rabbitmqconfig.PermissionTemplate{template}}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn,
		Account:    adapter.Account{Kind: "login", EngineIdentity: fixtureUser},
		Permission: "rabbitmq-template:" + template.Key,
		Scope:      "vhost:" + appVhost,
	}
	ad := rabbitmq.New()
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	for attempt := 0; attempt < 2; attempt++ {
		snap, err := ad.Discover(ctx, conn)
		if err != nil {
			t.Fatalf("Discover attempt %d: %v", attempt+1, err)
		}
		if !hasBinding(snap, fixtureUser, change.Permission) {
			t.Fatalf("discovery attempt %d did not match managed template binding", attempt+1)
		}
		matchedPermission := false
		for _, permission := range snap.Permissions {
			if permission.ExternalID == change.Permission {
				matchedPermission = permission.AssignmentKey == "rabbitmq:vhost:"+appVhost
			}
		}
		if !matchedPermission {
			t.Fatalf("discovery attempt %d did not publish template assignment slot", attempt+1)
		}
		for _, binding := range snap.Bindings {
			if binding.AccountEngineIdentity == fixtureUser && binding.ScopeExternalID == "vhost:"+appVhost &&
				(binding.AssignmentKey != "rabbitmq:vhost:"+appVhost ||
					binding.Attributes["template_matched"] != true ||
					binding.Attributes[adapter.AttrBindingEffective] != true) {
				t.Fatalf("discovery attempt %d reports template mismatch: %+v", attempt+1, binding)
			}
		}
	}
}

// TestAccountDeleteThenRestore воспроизводит сценарий «пользователя удалили по
// ошибке»: account.delete убирает его с target, а account.restore пересоздаёт
// со свежим credential. Проверяется не read-back adapter, а факты на брокере:
// наличие записи в GET /api/users и НАСТОЯЩИЙ вход восстановленной учёткой в
// Management API. Вход требует функционального тега, поэтому после restore
// выдаётся tag:monitoring — именно так учётка получает права обратно.
//
// Дополнительно фиксируются идемпотентность retry и отказ восстановить чужую
// identity: с неверным credential Plan обязан вернуть
// ErrExternalIdentityConflict. Для RabbitMQ это особенно важно — PUT
// /api/users перезаписал бы и пароль, и теги живого пользователя.
func TestAccountDeleteThenRestore(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	conn := connectionFromURL(t, rawURL)
	ad := rabbitmq.New()

	user := "gr_restore_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	admin := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	t.Cleanup(func() { admin.delete(ctx, "/api/users/"+url.PathEscape(user)) })

	initial, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: initial,
	})
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: "tag:monitoring",
	})
	if status := login(ctx, t, base, user, string(initial.Secret)); status != http.StatusOK {
		t.Fatalf("login after create: status %d, want 200", status)
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	if admin.userExists(ctx, t, user) {
		t.Fatalf("user %q still exists in /api/users after account.delete", user)
	}

	restored, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeAccountRestore, Connection: conn, Account: account, Credential: restored,
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	if !admin.userExists(ctx, t, user) {
		t.Fatalf("user %q is absent in /api/users after account.restore", user)
	}
	// Восстановленная учётка создаётся без тегов, поэтому Management API ей
	// ещё закрыт; права возвращает обычный grant, после которого проверяется
	// настоящий вход.
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: "tag:monitoring",
	})
	if status := login(ctx, t, base, user, string(restored.Secret)); status != http.StatusOK {
		t.Fatalf("login with the restored credential: status %d, want 200", status)
	}
	if status := login(ctx, t, base, user, string(initial.Secret)); status == http.StatusOK {
		t.Fatal("login with the pre-delete password must fail after restore")
	}

	// Retry уже применённого restore: Plan доказывает credential и строит
	// recovery-план, Apply ничего не меняет — в том числе не сбрасывает
	// выданный тег.
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	if status := login(ctx, t, base, user, string(restored.Secret)); status != http.StatusOK {
		t.Fatalf("recovery retry must not reset password or tags: status %d, want 200", status)
	}

	bad := *restored
	bad.Secret = []byte("wrong-restore-proof")
	conflicting := change
	conflicting.Credential = &bad
	if _, err := ad.Plan(ctx, conflicting); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("Plan restore of an existing identity with a wrong credential = %v, want conflict", err)
	}
	if status := login(ctx, t, base, user, string(restored.Secret)); status != http.StatusOK {
		t.Fatalf("refused restore must not touch the existing user: status %d, want 200", status)
	}
}

// disableEnable собирает DesiredChange для disable/enable.
func disableEnable(conn adapter.Connection, account adapter.Account, kind adapter.ChangeKind) adapter.DesiredChange {
	return adapter.DesiredChange{Kind: kind, Connection: conn, Account: account}
}

// hasBinding сообщает, есть ли в snapshot binding account -> permission.
func hasBinding(snap *adapter.Snapshot, identity, permission string) bool {
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == identity && b.PermissionExternalID == permission {
			return true
		}
	}
	return false
}

// login аутентифицируется указанным пользователем в Management API
// (GET /api/whoami) и возвращает HTTP-статус. Пароль не печатается.
func login(ctx context.Context, t *testing.T, base, user, pass string) int {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, base+"/api/whoami", nil)
	if err != nil {
		t.Fatalf("build whoami request: %v", err)
	}
	req.SetBasicAuth(user, pass)
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatalf("whoami request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// mgmt — минимальный клиент Management API для подготовки фикстуры и cleanup.
type mgmt struct {
	base string
	user string
	pass string
	hc   *http.Client
}

func httpClient() *http.Client { return &http.Client{Timeout: 20 * time.Second} }

// do выполняет запрос к Management API и возвращает статус и тело ответа.
func (m *mgmt) do(ctx context.Context, t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, method, m.base+path, reader)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, path, err)
	}
	req.SetBasicAuth(m.user, m.pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

// put выполняет PUT и падает на не-2xx.
func (m *mgmt) put(ctx context.Context, t *testing.T, path string, body any) {
	t.Helper()
	if status, data := m.do(ctx, t, http.MethodPut, path, body); status < 200 || status >= 300 {
		t.Fatalf("PUT %s: status %d: %s", path, status, strings.TrimSpace(string(data)))
	}
}

// userExists читает GET /api/users/{name} админским подключением: нативная
// проверка существования учётки, независимая от read-back adapter.
func (m *mgmt) userExists(ctx context.Context, t *testing.T, name string) bool {
	t.Helper()
	status, body := m.do(ctx, t, http.MethodGet, "/api/users/"+url.PathEscape(name), nil)
	switch {
	case status == http.StatusOK:
		return true
	case status == http.StatusNotFound:
		return false
	default:
		t.Fatalf("GET /api/users/%s: status %d: %s", name, status, strings.TrimSpace(string(body)))
		return false
	}
}

// delete выполняет DELETE, игнорируя результат (используется в cleanup).
func (m *mgmt) delete(ctx context.Context, path string) {
	reqCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodDelete, m.base+path, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(m.user, m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// ensureFixture идемпотентно создаёт фикстуру: vhost app_vhost, пользователь
// app_svc (пароль + тег monitoring) с полным доступом на app_vhost.
func ensureFixture(ctx context.Context, t *testing.T, base, adminUser, adminPass string) {
	t.Helper()
	m := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}

	m.put(ctx, t, "/api/vhosts/"+url.PathEscape(appVhost), map[string]any{})
	m.put(ctx, t, "/api/users/"+url.PathEscape(fixtureUser), map[string]any{
		"password": "app_svc_fixture_pwd",
		"tags":     "monitoring",
	})
	m.put(ctx, t, "/api/permissions/"+url.PathEscape(appVhost)+"/"+url.PathEscape(fixtureUser), map[string]any{
		"configure": ".*",
		"write":     ".*",
		"read":      ".*",
	})
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): администратор проходит валидацию, а пользователь с тегом monitoring
// (доступ к Management API есть, но нет administrator) отклоняется с
// adapter.InsufficientPrivilegeError, называющим отсутствующий тег и не
// содержащим пароль. Тег monitoring выбран специально: без функциональных тегов
// пользователь не смог бы даже прочитать /api/overview, и проверка тега не была
// бы достигнута.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ad := rabbitmq.New()

	// Positive: настоящий администратор проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, connectionFromURL(t, rawURL)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: пользователь с тегом monitoring, но без administrator.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	admin := &mgmt{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	admin.put(ctx, t, "/api/users/"+url.PathEscape(probe), map[string]any{
		"password": probePass,
		"tags":     "monitoring",
	})
	t.Cleanup(func() { admin.delete(ctx, "/api/users/"+url.PathEscape(probe)) })

	conn := connectionFromURL(t, rawURL)
	conn.AdminCredential = adapter.Credential{Kind: "password", Username: probe, Secret: []byte(probePass)}

	err := ad.ValidateConnection(ctx, conn)
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without the administrator tag")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !strings.Contains(pe.Missing, "administrator") {
		t.Errorf("missing = %q, want it to mention administrator", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}
