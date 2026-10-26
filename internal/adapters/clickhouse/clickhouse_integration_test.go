//go:build integration

// Интеграционные тесты ClickHouse adapter (discovery и мутации). Требуют
// «целевой» ClickHouse с включённым access management у admin-учётки: URL
// HTTP-интерфейса задаётся через GRANTOR_TEST_CLICKHOUSE_URL
// ("http://<user>:<pass>@host:8123"), иначе тесты пропускаются. Фикстура
// создаётся идемпотентно, поэтому тесты можно запускать многократно над
// одним и тем же сервером.
//
// URL и пароли в логи не выводятся: секретный материал берётся из URL и
// передаётся заголовками X-ClickHouse-User / X-ClickHouse-Key, но не
// печатается.
package clickhouse_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
)

const (
	// clickhouseEnv — переменная окружения с URL HTTP-интерфейса (admin).
	clickhouseEnv = "GRANTOR_TEST_CLICKHOUSE_URL"
	// targetDatabase — база фикстуры, создаваемая в целевом сервере.
	targetDatabase = "grantor_target_appdb"
	// fixtureUser — служебный пользователь фикстуры. Сортируется раньше
	// админского логина, поэтому contract suite выбирает именно его как
	// активный login-аккаунт и не трогает администратора.
	fixtureUser = "app_svc"
	// fixturePassword — небоевой пароль фикстурного пользователя.
	fixturePassword = "app_svc_fixture_pwd"
)

// target возвращает разобранный URL целевого ClickHouse или пропускает тест.
func target(t *testing.T) (rawURL string, base, user, pass string) {
	t.Helper()
	rawURL = os.Getenv(clickhouseEnv)
	if rawURL == "" {
		t.Skipf("%s is not set; skipping ClickHouse integration test", clickhouseEnv)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %s: %v", clickhouseEnv, err)
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
		t.Fatalf("parse %s: %v", clickhouseEnv, err)
	}
	mode := "disabled"
	if u.Scheme == "https" {
		mode = "require"
	}
	pass, _ := u.User.Password()
	return adapter.Connection{
		ID:        "conn-clickhouse-target",
		Engine:    clickhouse.Engine,
		Endpoints: []string{u.Host},
		TLS:       adapter.TLSConfig{Mode: mode},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: u.User.Username(),
			Secret:   []byte(pass),
		},
	}
}

// TestContract прогоняет общий contract suite поверх целевого ClickHouse.
// Manifest объявляет access.grant/revoke, поэтому suite выполняет grant/revoke
// тесты: фикстура даёт активный login-аккаунт (app_svc) и две assignable
// не-dangerous роли (app_ro/app_rw).
func TestContract(t *testing.T) {
	rawURL, base, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, user, pass)
	conn := connectionFromURL(t, rawURL)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return clickhouse.New(), conn
		},
	})
}

// TestCredentialProof exercises ClickHouse HTTP authentication, exact
// currentUser() identity and exception-code 516 as the negative proof.
func TestCredentialProof(t *testing.T) {
	rawURL, base, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, user, pass)
	ad := clickhouse.New()
	conn := connectionFromURL(t, rawURL)
	account := adapter.Account{Kind: "login", EngineIdentity: fixtureUser}
	if err := ad.ProveCredential(ctx, conn, account,
		adapter.Credential{Kind: "password", Secret: []byte(fixturePassword)}); err != nil {
		t.Fatalf("ProveCredential: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account,
		adapter.Credential{Kind: "password", Secret: []byte("definitely-wrong-password")}); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("mismatched credential error = %v, want ErrExternalIdentityConflict", err)
	}
}

// TestValidateConnection проверяет, что admin credential проходит валидацию.
func TestValidateConnection(t *testing.T) {
	rawURL, _, _, _ := target(t)
	ctx := context.Background()
	if err := clickhouse.New().ValidateConnection(ctx, connectionFromURL(t, rawURL)); err != nil {
		t.Fatalf("ValidateConnection: %v", err)
	}
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры: базу,
// роли, пользователя, ролевой binding и binding прямого гранта, а также
// корректную топологию standalone и исключение служебных баз.
func TestDiscoverFixture(t *testing.T) {
	rawURL, base, user, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, user, pass)

	snap, err := clickhouse.New().Discover(ctx, connectionFromURL(t, rawURL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.ServerVersion == "" {
		t.Error("snapshot has empty server version")
	}
	// Одноузловой контейнер — standalone; под GRANTOR_TEST_CLUSTERS harness
	// записывает в config.d определение grantor_cluster, и та же цель
	// становится cluster.
	if want := wantClickhouseTopology(); snap.Topology["topology"] != want {
		t.Errorf("topology = %v, want %s", snap.Topology["topology"], want)
	}

	resources := map[string]adapter.ObservedResource{}
	for _, r := range snap.Resources {
		resources[r.ExternalID] = r
	}
	db, ok := resources["db:"+targetDatabase]
	if !ok {
		t.Fatalf("resource db:%s not found", targetDatabase)
	}
	if db.Kind != "database" || db.Fingerprint == "" {
		t.Errorf("resource db:%s = %+v, want kind database with fingerprint", targetDatabase, db)
	}
	for _, id := range []string{"db:system", "db:INFORMATION_SCHEMA", "db:information_schema"} {
		if _, ok := resources[id]; ok {
			t.Errorf("system database %q must not appear in resources", id)
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
	for _, id := range []string{"role:app_ro", "role:app_rw"} {
		p, ok := perms[id]
		if !ok {
			t.Errorf("permission %q not found", id)
			continue
		}
		if !p.Assignable {
			t.Errorf("permission %q must be assignable", id)
		}
		if p.Dangerous {
			t.Errorf("permission %q must not be dangerous", id)
		}
	}
	privID := "priv:SELECT:db:" + targetDatabase
	if p, ok := perms[privID]; !ok {
		t.Errorf("permission %q not found", privID)
	} else {
		if p.Assignable {
			t.Errorf("permission %q must not be assignable (observed direct grant)", privID)
		}
		if p.ScopeExternalID != "db:"+targetDatabase {
			t.Errorf("permission %q scope = %q, want db:%s", privID, p.ScopeExternalID, targetDatabase)
		}
	}

	if !hasBinding(snap, fixtureUser, "role:app_ro") {
		t.Errorf("binding %s -> role:app_ro not found", fixtureUser)
	}
	if !hasBinding(snap, fixtureUser, privID) {
		t.Errorf("binding %s -> %s not found", fixtureUser, privID)
	}
}

// TestTopologyStandalone проверяет определение standalone на одноузловом
// контейнере (multi-host cluster проверяется юнит-тестом по canned строкам
// system.clusters, а живьём — TestTopologyCluster под GRANTOR_TEST_CLUSTERS).
func TestTopologyStandalone(t *testing.T) {
	rawURL, _, _, _ := target(t)
	if clickhouseClustered() {
		t.Skipf("%s is set: the target server is clustered; see TestTopologyCluster", clickhouseClusterEnv)
	}
	ctx := context.Background()
	snap, err := clickhouse.New().Discover(ctx, connectionFromURL(t, rawURL))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл пользователя: create
// со сгенерированным паролем -> реальный вход (SELECT 1 по HTTP) -> ротация
// (новый пароль работает, старый нет) -> disable (HOST NONE, вход запрещён)
// -> enable (HOST ANY, вход снова работает) -> grant/revoke роли -> delete.
// Пароли и URL в логи не попадают.
func TestAccountLifecycle(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, adminUser, adminPass)
	conn := connectionFromURL(t, rawURL)
	ad := clickhouse.New()

	name := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name}
	admin := &chx{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	t.Cleanup(func() { admin.execQuietly(ctx, "DROP USER IF EXISTS "+backquote(name)) })

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
	// Повтор создания отклоняется: существующая identity не присваивается
	// даже собственной операцией — идемпотентность повтора обеспечивает ядро
	// (см. adaptertest.Run/AccountCreateRefusesExistingIdentity).
	if _, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Connection: conn,
		Account:    account,
		Credential: cred,
	}); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("repeated account.create error = %v, want ErrExternalIdentityConflict", err)
	}
	if status := login(ctx, t, base, name, string(cred.Secret)); status != http.StatusOK {
		t.Fatalf("login with generated password: status %d, want 200", status)
	}

	// Ротация пароля: новый работает, старый — нет.
	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if status := login(ctx, t, base, name, string(rotated.Secret)); status != http.StatusOK {
		t.Fatalf("login with rotated password: status %d, want 200", status)
	}
	if status := login(ctx, t, base, name, string(cred.Secret)); status == http.StatusOK {
		t.Fatal("login with old password must fail after rotation")
	}

	// Disable: HOST NONE, вход запрещён; повтор идемпотентен.
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountDisable))
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountDisable))
	if status := login(ctx, t, base, name, string(rotated.Secret)); status == http.StatusOK {
		t.Fatal("disabled user must not be able to log in")
	}

	// Enable: HOST ANY, вход и гранты восстановлены; повтор идемпотентен.
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountEnable))
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountEnable))
	if status := login(ctx, t, base, name, string(rotated.Secret)); status != http.StatusOK {
		t.Fatalf("login after enable: status %d, want 200", status)
	}

	// Grant роли (и идемпотентный повтор), затем revoke.
	grant := adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: "role:app_ro",
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	revoke := grant
	revoke.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)

	// Delete и его идемпотентность.
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountDelete))
	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountDelete))
	if status := login(ctx, t, base, name, string(rotated.Secret)); status == http.StatusOK {
		t.Fatal("deleted user must not be able to log in")
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err == nil {
		t.Error("RotateCredential must fail for a deleted user")
	} else if !errors.Is(err, adapter.ErrNotFound) {
		t.Errorf("RotateCredential error = %v, want ErrNotFound", err)
	}
}

// TestAccountDeleteThenRestore воспроизводит сценарий «пользователя удалили по
// ошибке»: account.delete убирает его с target, а account.restore пересоздаёт
// со свежим credential. Проверяется не read-back adapter, а факты на сервере:
// наличие строки в system.users и НАСТОЯЩИЙ вход восстановленной учёткой.
// Дополнительно фиксируются идемпотентность retry и отказ восстановить чужую
// identity: с неверным credential Plan обязан вернуть
// ErrExternalIdentityConflict, а не перезаписать пароль существующего
// пользователя.
func TestAccountDeleteThenRestore(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	conn := connectionFromURL(t, rawURL)
	ad := clickhouse.New()

	name := "gr_restore_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name}
	admin := &chx{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	t.Cleanup(func() { admin.execQuietly(ctx, "DROP USER IF EXISTS "+backquote(name)) })

	initial, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: initial,
	})
	if status := login(ctx, t, base, name, string(initial.Secret)); status != http.StatusOK {
		t.Fatalf("login after create: status %d, want 200", status)
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, lifecycleChange(conn, account, adapter.ChangeAccountDelete))
	if admin.userCount(ctx, t, name) != 0 {
		t.Fatalf("user %q still exists in system.users after account.delete", name)
	}

	restored, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeAccountRestore, Connection: conn, Account: account, Credential: restored,
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	if admin.userCount(ctx, t, name) != 1 {
		t.Fatalf("user %q is absent in system.users after account.restore", name)
	}
	if status := login(ctx, t, base, name, string(restored.Secret)); status != http.StatusOK {
		t.Fatalf("login with the restored credential: status %d, want 200", status)
	}
	if status := login(ctx, t, base, name, string(initial.Secret)); status == http.StatusOK {
		t.Fatal("login with the pre-delete password must fail after restore")
	}

	// Retry уже применённого restore: Plan доказывает credential и строит
	// recovery-план, Apply ничего не меняет.
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	bad := *restored
	bad.Secret = []byte("wrong-restore-proof")
	conflicting := change
	conflicting.Credential = &bad
	if _, err := ad.Plan(ctx, conflicting); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("Plan restore of an existing identity with a wrong credential = %v, want conflict", err)
	}
	if status := login(ctx, t, base, name, string(restored.Secret)); status != http.StatusOK {
		t.Fatalf("refused restore must not touch the existing password: status %d, want 200", status)
	}
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): администратор с ACCESS MANAGEMENT проходит валидацию, а пользователь
// лишь с SELECT на одной базе отклоняется с
// adapter.InsufficientPrivilegeError, называющим отсутствующую привилегию и
// не содержащим пароль.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	rawURL, base, adminUser, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, base, adminUser, adminPass)
	ad := clickhouse.New()

	// Positive: настоящий admin проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, connectionFromURL(t, rawURL)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: пользователь только с SELECT на фикстурной базе. randomHex
	// даёт только [0-9a-f], поэтому пароль-литерал безопасно встраивается в
	// DDL фикстуры.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	admin := &chx{base: base, user: adminUser, pass: adminPass, hc: httpClient()}
	admin.exec(ctx, t,
		"CREATE USER "+backquote(probe)+" IDENTIFIED WITH sha256_password BY '"+probePass+"'")
	t.Cleanup(func() { admin.execQuietly(ctx, "DROP USER IF EXISTS "+backquote(probe)) })
	admin.exec(ctx, t, "GRANT SELECT ON "+targetDatabase+".* TO "+backquote(probe))

	conn := connectionFromURL(t, rawURL)
	conn.AdminCredential = adapter.Credential{Kind: "password", Username: probe, Secret: []byte(probePass)}

	err := ad.ValidateConnection(ctx, conn)
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without ACCESS MANAGEMENT")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !strings.Contains(pe.Missing, "ACCESS MANAGEMENT") {
		t.Errorf("missing = %q, want it to mention ACCESS MANAGEMENT", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}

// lifecycleChange собирает DesiredChange без credential для lifecycle-шагов.
func lifecycleChange(conn adapter.Connection, account adapter.Account, kind adapter.ChangeKind) adapter.DesiredChange {
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

// login выполняет SELECT 1 по HTTP-интерфейсу указанным пользователем и
// возвращает HTTP-статус. Пароль передаётся заголовком и не печатается.
func login(ctx context.Context, t *testing.T, base, user, pass string) int {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, base+"/", strings.NewReader("SELECT 1"))
	if err != nil {
		t.Fatalf("build login request: %v", err)
	}
	req.Header.Set("X-ClickHouse-User", user)
	req.Header.Set("X-ClickHouse-Key", pass)
	resp, err := httpClient().Do(req)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// chx — минимальный HTTP-клиент ClickHouse для подготовки фикстуры и cleanup.
type chx struct {
	base string
	user string
	pass string
	hc   *http.Client
}

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

// do выполняет один statement и возвращает HTTP-статус. Тело ответа
// сознательно не читается в сообщения ошибок: сервер цитирует statement, а он
// может содержать фикстурный пароль.
func (m *chx) do(ctx context.Context, stmt string) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		m.base+"/?wait_end_of_query=1", strings.NewReader(stmt))
	if err != nil {
		return 0, err
	}
	req.Header.Set("X-ClickHouse-User", m.user)
	req.Header.Set("X-ClickHouse-Key", m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// exec выполняет statement и падает на не-2xx (без вывода тела ответа и
// самого statement — они могут содержать фикстурные пароли).
func (m *chx) exec(ctx context.Context, t *testing.T, stmt string) {
	t.Helper()
	status, err := m.do(ctx, stmt)
	if err != nil {
		t.Fatalf("execute fixture statement: %v", err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("fixture statement rejected with status %d", status)
	}
}

// execQuietly выполняет statement, игнорируя результат (cleanup).
func (m *chx) execQuietly(ctx context.Context, stmt string) {
	_, _ = m.do(ctx, stmt)
}

// userCount читает системную таблицу напрямую админским подключением: это
// нативная проверка существования учётки, независимая от read-back adapter.
// Имя подставляется параметром запроса, а не конкатенацией.
func (m *chx) userCount(ctx context.Context, t *testing.T, name string) int {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("wait_end_of_query", "1")
	q.Set("param_name", name)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, m.base+"/?"+q.Encode(),
		strings.NewReader(`SELECT count() FROM system.users WHERE name = {name:String}`))
	if err != nil {
		t.Fatalf("build system.users request: %v", err)
	}
	req.Header.Set("X-ClickHouse-User", m.user)
	req.Header.Set("X-ClickHouse-Key", m.pass)
	resp, err := m.hc.Do(req)
	if err != nil {
		t.Fatalf("read system.users: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read system.users response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("read system.users: status %d", resp.StatusCode)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatalf("parse system.users count %q: %v", strings.TrimSpace(string(body)), err)
	}
	return n
}

// backquote экранирует идентификатор в backticks (имена в тестах состоят из
// [a-z0-9_], экранирование тривиально).
func backquote(s string) string { return "`" + s + "`" }

// ensureFixture идемпотентно создаёт фикстуру в целевом сервере: базу
// grantor_target_appdb, роли app_ro/app_rw (SELECT / SELECT+INSERT на базе),
// пользователя app_svc с ролью app_ro и прямым грантом SELECT на базе.
func ensureFixture(ctx context.Context, t *testing.T, base, adminUser, adminPass string) {
	t.Helper()
	m := &chx{base: base, user: adminUser, pass: adminPass, hc: httpClient()}

	stmts := []string{
		"CREATE DATABASE IF NOT EXISTS " + targetDatabase,
		"CREATE ROLE IF NOT EXISTS app_ro",
		"CREATE ROLE IF NOT EXISTS app_rw",
		"GRANT SELECT ON " + targetDatabase + ".* TO app_ro",
		"GRANT SELECT, INSERT ON " + targetDatabase + ".* TO app_rw",
		"CREATE USER IF NOT EXISTS " + fixtureUser + " IDENTIFIED WITH sha256_password BY '" + fixturePassword + "'",
		"GRANT app_ro TO " + fixtureUser,
		"GRANT SELECT ON " + targetDatabase + ".* TO " + fixtureUser,
	}
	for _, stmt := range stmts {
		m.exec(ctx, t, stmt)
	}
}
