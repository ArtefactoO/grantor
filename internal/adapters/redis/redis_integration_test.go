//go:build integration

// Интеграционные тесты Redis adapter (discovery и мутации). Требуют «целевой»
// Redis 6.2+ с requirepass; harness accepts REDIS_IMAGE for the 6.2/7 matrix
// (scripts/test-integration.sh). Подключение задаётся через
// GRANTOR_TEST_REDIS_ADDR (host:port) + GRANTOR_TEST_REDIS_PASSWORD (пароль
// admin-пользователя default), иначе тесты пропускаются. Фикстура создаётся
// идемпотентно, поэтому тесты можно запускать многократно над одним и тем же
// сервером.
//
// Пароли в логи не выводятся: секретный материал передаётся только внутри
// AUTH/ACL SETUSER.
package redis_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	adredis "github.com/ArtefactoO/grantor/internal/adapters/redis"
)

const (
	// Переменные окружения целевого сервера (admin credential = default).
	addrEnv = "GRANTOR_TEST_REDIS_ADDR"
	passEnv = "GRANTOR_TEST_REDIS_PASSWORD"
	// fixtureUser — служебный пользователь фикстуры: активный login-аккаунт
	// для contract suite (default в managed-инвентарь не попадает).
	fixtureUser = "app_svc"
	// fixturePass — заведомо небоевой пароль фикстурного пользователя.
	fixturePass = "app_svc_fixture_pwd"
	// probeKey — ключ для поведенческих проверок доступа.
	probeKey = "grantor:it:probe"
)

// target возвращает адрес сервера и admin-пароль или пропускает тест.
func target(t *testing.T) (addr, pass string) {
	t.Helper()
	addr = os.Getenv(addrEnv)
	if addr == "" {
		t.Skipf("%s is not set; skipping Redis integration test", addrEnv)
	}
	pass = os.Getenv(passEnv)
	if pass == "" {
		t.Skipf("%s is not set; skipping Redis integration test", passEnv)
	}
	return addr, pass
}

// connection строит adapter.Connection целевого сервера. Username пуст:
// admin-учётка — пользователь default через requirepass.
func connection(addr, pass string) adapter.Connection {
	return adapter.Connection{
		ID:        "conn-redis-target",
		Engine:    adredis.Engine,
		Endpoints: []string{addr},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:   "password",
			Secret: []byte(pass),
		},
	}
}

// adminGoRedis строит прямой go-redis клиент для подготовки фикстуры и
// независимой проверки состояния.
func adminGoRedis(t *testing.T, addr, user, pass string) *goredis.Client {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr:        addr,
		Username:    user,
		Password:    pass,
		DialTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second,
	})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// ensureFixture идемпотентно создаёт фикстуру: пользователя app_svc без прав
// (managed-empty форма). Существующий пользователь не трогается: contract
// suite сам выдаёт и снимает bundles.
func ensureFixture(ctx context.Context, t *testing.T, addr, pass string) {
	t.Helper()
	adm := adminGoRedis(t, addr, "", pass)
	users, err := adm.ACLList(ctx).Result()
	if err != nil {
		t.Fatalf("acl list: %v", err)
	}
	for _, line := range users {
		if strings.HasPrefix(line, "user "+fixtureUser+" ") {
			return
		}
	}
	if err := adm.ACLSetUser(ctx, fixtureUser, "on", ">"+fixturePass, "nocommands", "resetkeys", "resetchannels").Err(); err != nil {
		t.Fatalf("create fixture user: %v", err)
	}
}

// userProbe выполняет GET probeKey от имени пользователя и классифицирует
// результат: authenticated — пароль принят (команда прошла или отклонена
// авторизацией), allowed — чтение разрешено.
func userProbe(ctx context.Context, t *testing.T, addr, user, pass string) (authenticated, allowed bool) {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{
		Addr:        addr,
		Username:    user,
		Password:    pass,
		DialTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second,
		MaxRetries:  -1,
	})
	defer func() { _ = client.Close() }()
	err := client.Get(ctx, probeKey).Err()
	switch {
	case err == nil || errors.Is(err, goredis.Nil):
		return true, true
	case goredis.HasErrorPrefix(err, "NOPERM"):
		return true, false
	default:
		if !strings.Contains(err.Error(), "WRONGPASS") && !strings.Contains(err.Error(), "NOAUTH") {
			t.Logf("probe error treated as auth failure: %v", err)
		}
		return false, false
	}
}

// userSet пытается выполнить SET от имени пользователя; nil — запись прошла.
func userSet(ctx context.Context, addr, user, pass string) error {
	client := goredis.NewClient(&goredis.Options{
		Addr:        addr,
		Username:    user,
		Password:    pass,
		DialTimeout: 10 * time.Second,
		ReadTimeout: 15 * time.Second,
		MaxRetries:  -1,
	})
	defer func() { _ = client.Close() }()
	return client.Set(ctx, probeKey, "grantor-test", time.Minute).Err()
}

// TestContract прогоняет общий contract suite поверх целевого сервера.
// Manifest объявляет access.grant/revoke, поэтому suite выполняет grant/revoke
// тесты: фикстура даёт активный login-аккаунт (app_svc), а adapter — два
// assignable не-dangerous permission bundles (read, write, monitoring).
func TestContract(t *testing.T) {
	addr, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, addr, pass)
	conn := connection(addr, pass)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return adredis.New(), conn
		},
	})
}

// TestValidateConnection проверяет, что admin credential проходит валидацию.
func TestValidateConnection(t *testing.T) {
	addr, pass := target(t)
	if err := adredis.New().ValidateConnection(context.Background(), connection(addr, pass)); err != nil {
		t.Fatalf("ValidateConnection: %v", err)
	}
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры и верно
// классифицирует топологию, аккаунты и permissions.
func TestDiscoverFixture(t *testing.T) {
	addr, pass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, addr, pass)

	snap, err := adredis.New().Discover(ctx, connection(addr, pass))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	// Одноузловой redis-server — standalone; ресурсов у Redis нет.
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}
	if snap.ServerVersion == "" {
		t.Error("server version must be discovered")
	}
	if len(snap.Resources) != 0 {
		t.Errorf("resources = %v, want none", snap.Resources)
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		accounts[a.EngineIdentity] = a
		if a.EngineIdentity == "default" {
			t.Error("the default user must not be inventoried as a managed account")
		}
	}
	svc, ok := accounts[fixtureUser]
	if !ok {
		t.Fatalf("account %q not found", fixtureUser)
	}
	if svc.Kind != "login" || svc.Disabled {
		t.Errorf("account %q = %+v, want active login", fixtureUser, svc)
	}
	if svc.Attributes["has_password"] != true {
		t.Errorf("account %q must have has_password=true", fixtureUser)
	}

	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		perms[p.ExternalID] = p
	}
	if admin, ok := perms["admin"]; !ok || !admin.Dangerous || !admin.Assignable {
		t.Error("permission admin must exist, be assignable and dangerous")
	}
	for _, name := range []string{"read", "write"} {
		if p, ok := perms[name]; !ok || p.Dangerous || !p.Assignable {
			t.Errorf("permission %s must exist, be assignable and non-dangerous", name)
		}
	}
}

// TestTopologyStandalone проверяет определение standalone на одноузловом
// сервере (cluster/sentinel проверяются юнит-тестом по canned INFO).
func TestTopologyStandalone(t *testing.T) {
	addr, pass := target(t)
	snap, err := adredis.New().Discover(context.Background(), connection(addr, pass))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.Topology["topology"] != "standalone" {
		t.Errorf("topology = %v, want standalone", snap.Topology["topology"])
	}
	if snap.Topology["role"] != "master" {
		t.Errorf("role = %v, want master", snap.Topology["role"])
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл пользователя:
// create -> AUTH работает -> rotate (новый пароль работает, старый — нет) ->
// grant read -> binding виден и чтение реально работает, запись отклоняется
// NOPERM -> disable (флаг off: AUTH отклоняется, правила сохранены) ->
// enable (доступ возвращается без re-grant) -> revoke (чтение отклоняется) ->
// delete (AUTH невозможен, аккаунт исчезает из discovery).
func TestAccountLifecycle(t *testing.T) {
	addr, adminPass := target(t)
	ctx := context.Background()
	ensureFixture(ctx, t, addr, adminPass)
	conn := connection(addr, adminPass)
	ad := adredis.New()

	user := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	t.Cleanup(func() {
		// Идемпотентная зачистка на случай падения теста посередине.
		plan, err := ad.Plan(context.Background(), adapter.DesiredChange{
			Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
		})
		if err == nil {
			_, _ = ad.Apply(context.Background(), *plan)
		}
	})

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

	// AUTH принят (новый пользователь без прав: команда отклоняется NOPERM,
	// а не WRONGPASS).
	if authOK, allowed := userProbe(ctx, t, addr, user, string(cred.Secret)); !authOK || allowed {
		t.Fatalf("fresh user: authenticated=%v allowed=%v, want authenticated without access", authOK, allowed)
	}

	// Ротация пароля: новый работает, старый — нет.
	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if authOK, _ := userProbe(ctx, t, addr, user, string(rotated.Secret)); !authOK {
		t.Fatal("auth with rotated password must succeed")
	}
	if err := ad.ProveCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("ProveCredential with exact identity/password: %v", err)
	}
	wrong := *rotated
	wrong.Secret = []byte("definitely-wrong-password")
	if err := ad.ProveCredential(ctx, conn, account, wrong); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("ProveCredential wrong password error = %v, want ErrExternalIdentityConflict", err)
	}
	if authOK, _ := userProbe(ctx, t, addr, user, string(cred.Secret)); authOK {
		t.Fatal("auth with old password must fail after rotation")
	}

	// Grant read: binding наблюдаем в discovery, чтение работает, запись —
	// NOPERM (read-only поведение).
	grant := func(permission string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: permission,
		}
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("read"))
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("read")) // повтор — StepSkipped

	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !hasBinding(snap, user, "read") {
		t.Fatalf("binding %s -> read not found after grant", user)
	}
	if authOK, allowed := userProbe(ctx, t, addr, user, string(rotated.Secret)); !authOK || !allowed {
		t.Fatalf("read after grant: authenticated=%v allowed=%v, want full read access", authOK, allowed)
	}
	if err := userSet(ctx, addr, user, string(rotated.Secret)); err == nil {
		t.Fatal("read-only user must not be able to SET")
	} else if !goredis.HasErrorPrefix(err, "NOPERM") {
		t.Fatalf("SET by read-only user failed with %v, want NOPERM", err)
	}

	// Disable: нативный флаг off блокирует AUTH, правила сохраняются.
	disable := adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Connection: conn, Account: account}
	adaptertest.PlanApplyVerify(ctx, t, ad, disable)
	adaptertest.PlanApplyVerify(ctx, t, ad, disable) // idempotent
	if authOK, _ := userProbe(ctx, t, addr, user, string(rotated.Secret)); authOK {
		t.Fatal("disabled user must not authenticate")
	}
	snap, err = ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if acc, ok := findAccount(snap, user); !ok || !acc.Disabled {
		t.Errorf("account %q must be observed disabled, got %+v", user, acc)
	}
	if !hasBinding(snap, user, "read") {
		t.Error("rules must survive disable (native off flag is non-lossy)")
	}

	// Enable: доступ возвращается без повторного grant.
	enable := adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Connection: conn, Account: account}
	adaptertest.PlanApplyVerify(ctx, t, ad, enable)
	adaptertest.PlanApplyVerify(ctx, t, ad, enable) // idempotent
	if authOK, allowed := userProbe(ctx, t, addr, user, string(rotated.Secret)); !authOK || !allowed {
		t.Fatalf("access after enable: authenticated=%v allowed=%v, want restored read access", authOK, allowed)
	}

	// Второй bundle: write добавляется и снимается независимо от read.
	adaptertest.PlanApplyVerify(ctx, t, ad, grant("write"))
	if err := userSet(ctx, addr, user, string(rotated.Secret)); err != nil {
		t.Fatalf("SET after write grant: %v", err)
	}
	revokeWrite := grant("write")
	revokeWrite.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revokeWrite)
	if authOK, allowed := userProbe(ctx, t, addr, user, string(rotated.Secret)); !authOK || !allowed {
		t.Fatal("read access must survive revoking the write bundle")
	}

	// Revoke read: чтение отклоняется авторизацией.
	revoke := grant("read")
	revoke.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke) // повтор — StepSkipped
	if _, allowed := userProbe(ctx, t, addr, user, string(rotated.Secret)); allowed {
		t.Fatal("read after revoke must fail")
	}

	// Delete и его идемпотентность: аккаунт и его правила исчезают.
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	if authOK, _ := userProbe(ctx, t, addr, user, string(rotated.Secret)); authOK {
		t.Fatal("auth must fail after delete")
	}
	snap, err = ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if _, ok := findAccount(snap, user); ok {
		t.Errorf("account %q must be absent after delete", user)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err == nil {
		t.Error("RotateCredential must fail for a deleted user")
	} else if !errors.Is(err, adapter.ErrNotFound) {
		t.Errorf("RotateCredential error = %v, want adapter.ErrNotFound", err)
	}
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): администратор проходит валидацию, а ACL-пользователи без прав на
// администрирование ACL отклоняются с adapter.InsufficientPrivilegeError,
// называющим отсутствующую привилегию и не содержащим пароль. Покрываются оба
// пути отказа: NOPERM на ранней команде и евалюатор правил (пользователь
// умеет читать ACL, но не менять).
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	addr, adminPass := target(t)
	ctx := context.Background()
	ad := adredis.New()

	// Positive: настоящий администратор проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, connection(addr, adminPass)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	adm := adminGoRedis(t, addr, "", adminPass)
	probeConn := func(user, pass string) adapter.Connection {
		c := connection(addr, adminPass)
		c.AdminCredential = adapter.Credential{Kind: "password", Username: user, Secret: []byte(pass)}
		return c
	}
	assertInsufficient := func(t *testing.T, err error, pass string) {
		t.Helper()
		if err == nil {
			t.Fatal("ValidateConnection must reject a non-admin user")
		}
		var pe *adapter.InsufficientPrivilegeError
		if !errors.As(err, &pe) {
			t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
		}
		if !errors.Is(err, adapter.ErrInsufficientAdminPrivilege) {
			t.Error("error must wrap adapter.ErrInsufficientAdminPrivilege")
		}
		if !strings.Contains(pe.Missing, "acl") && !strings.Contains(pe.Missing, "@admin") {
			t.Errorf("missing = %q, want it to mention ACL administration", pe.Missing)
		}
		if strings.Contains(err.Error(), pass) {
			t.Error("error message leaks the probe password")
		}
	}

	t.Run("noperm on early command", func(t *testing.T) {
		user := "gr_probe_" + adaptertest.RandomHex(t, 4)
		pass := "probe" + adaptertest.RandomHex(t, 8)
		if err := adm.ACLSetUser(ctx, user, "on", ">"+pass).Err(); err != nil {
			t.Fatalf("create probe user: %v", err)
		}
		t.Cleanup(func() { _ = adm.ACLDelUser(context.Background(), user).Err() })
		assertInsufficient(t, ad.ValidateConnection(ctx, probeConn(user, pass)), pass)
	})

	t.Run("read-only acl introspection", func(t *testing.T) {
		user := "gr_probe_" + adaptertest.RandomHex(t, 4)
		pass := "probe" + adaptertest.RandomHex(t, 8)
		// Пользователь умеет PING и читать ACL, но не менять его: гейт обязан
		// дойти до евалюатора правил и отказать.
		if err := adm.ACLSetUser(ctx, user, "on", ">"+pass,
			"+ping", "+acl|whoami", "+acl|list").Err(); err != nil {
			t.Fatalf("create probe user: %v", err)
		}
		t.Cleanup(func() { _ = adm.ACLDelUser(context.Background(), user).Err() })
		assertInsufficient(t, ad.ValidateConnection(ctx, probeConn(user, pass)), pass)
	})
}

// TestGrantRefusesUnmanagedRules проверяет, что grant не перезаписывает
// чужие (unmanaged) ACL-правила.
func TestGrantRefusesUnmanagedRules(t *testing.T) {
	addr, adminPass := target(t)
	ctx := context.Background()
	conn := connection(addr, adminPass)
	ad := adredis.New()
	adm := adminGoRedis(t, addr, "", adminPass)

	user := "gr_foreign_" + adaptertest.RandomHex(t, 4)
	if err := adm.ACLSetUser(ctx, user, "on", ">foreign-pwd", "~app:*", "+get").Err(); err != nil {
		t.Fatalf("create foreign user: %v", err)
	}
	t.Cleanup(func() { _ = adm.ACLDelUser(context.Background(), user).Err() })

	plan, err := ad.Plan(ctx, adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    adapter.Account{Kind: "login", EngineIdentity: user},
		Permission: "read",
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	res, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Steps[0].Status != adapter.StepFailed {
		t.Fatalf("step status = %s, want failed for unmanaged rules", res.Steps[0].Status)
	}
	if !strings.Contains(res.Steps[0].Error, "not managed") {
		t.Errorf("step error = %q, want it to mention unmanaged rules", res.Steps[0].Error)
	}

	// Discovery показывает такие правила как неназначаемую observed
	// permission с binding.
	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	found := false
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == user && strings.HasPrefix(b.PermissionExternalID, "acl:") {
			found = true
		}
	}
	if !found {
		t.Error("foreign rules must surface as an observed acl:* binding")
	}
}

// TestAccessRevokeKeepsOtherBundles — регрессия на отзыв, уничтожавший
// остальные права аккаунта. Прежняя реализация реконструировала целевой набор
// bundles из текущего ACL, а admin (+@all) стирал в движке ранее выданный
// read: revoke admin получал пустой набор, сносил доступ целиком и при этом
// завершался успехом, а метаданные продолжали показывать read.
//
// Тест закрывает три следствия исправления:
//
//   - admin не комбинируется с read/write: grant отклоняется внятной ошибкой
//     и на этапе плана, и при применении, а выданный read остаётся цел
//     (подтверждается функциональной пробой, а не только чтением ACL);
//   - целевой набор строится из desired-состояния ядра, поэтому revoke не
//     трогает остальные права и чинит расхождение, возникшее вне grantor;
//   - Verify не подтверждает успех, когда остальные права аккаунта пропали, —
//     метаданные не врут.
func TestAccessRevokeKeepsOtherBundles(t *testing.T) {
	addr, adminPass := target(t)
	ctx := context.Background()
	conn := connection(addr, adminPass)
	ad := adredis.New()
	adm := adminGoRedis(t, addr, "", adminPass)

	user := "gr_keep_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: user}
	t.Cleanup(func() { _ = adm.ACLDelUser(context.Background(), user).Err() })

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	pwd := string(cred.Secret)
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: cred,
	})

	access := func(kind adapter.ChangeKind, permission string, desired []string) adapter.DesiredChange {
		return adapter.DesiredChange{
			Kind: kind, Connection: conn, Account: account,
			Permission: permission, AccountPermissions: desired,
		}
	}
	// assertReadOnly проверяет фактом, а не описанием ACL: чтение работает,
	// запись отбивается NOPERM.
	assertReadOnly := func(t *testing.T, stage string) {
		t.Helper()
		if authOK, allowed := userProbe(ctx, t, addr, user, pwd); !authOK || !allowed {
			t.Fatalf("%s: authenticated=%v read allowed=%v, want working read access", stage, authOK, allowed)
		}
		if err := userSet(ctx, addr, user, pwd); err == nil {
			t.Fatalf("%s: read-only user must not be able to SET", stage)
		} else if !goredis.HasErrorPrefix(err, "NOPERM") {
			t.Fatalf("%s: SET failed with %v, want NOPERM", stage, err)
		}
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "read", []string{"read"}))
	assertReadOnly(t, "after grant read")

	// Grant admin поверх read отклоняется планом: набор непредставим в ACL.
	if _, err := ad.Plan(ctx, access(adapter.ChangeGrant, "admin", []string{"read", "admin"})); err == nil {
		t.Fatal("Plan(grant admin) with read already granted must fail")
	} else if !strings.Contains(err.Error(), "read") {
		t.Errorf("Plan error = %q, want it to name the bundle admin would erase", err)
	}

	// Тот же отказ на применении: план без desired-состояния (деградированный
	// режим) не должен превратиться в тихое +@all.
	plan, err := ad.Plan(ctx, access(adapter.ChangeGrant, "admin", nil))
	if err != nil {
		t.Fatalf("Plan(grant admin) without desired state: %v", err)
	}
	res, err := ad.Apply(ctx, *plan)
	if err != nil {
		t.Fatalf("Apply(grant admin): %v", err)
	}
	if res.Steps[0].Status != adapter.StepFailed {
		t.Fatalf("step status = %s, want failed for an unrepresentable bundle set", res.Steps[0].Status)
	}
	assertReadOnly(t, "after refused grant admin")

	// Revoke не трогает остальные права: write снимается, read остаётся.
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeGrant, "write", []string{"read", "write"}))
	if err := userSet(ctx, addr, user, pwd); err != nil {
		t.Fatalf("SET after write grant: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, access(adapter.ChangeRevoke, "write", []string{"read"}))
	assertReadOnly(t, "after revoke write")

	// Расхождение вне grantor: правила аккаунта снесены в движке (ровно тот
	// результат, который производил прежний revoke). Desired-состояние ядра
	// по-прежнему read.
	if err := adm.ACLSetUser(ctx, user, "nocommands", "resetkeys", "resetchannels").Err(); err != nil {
		t.Fatalf("collapse acl out of band: %v", err)
	}
	if _, allowed := userProbe(ctx, t, addr, user, pwd); allowed {
		t.Fatal("fixture is broken: access must be gone after the out-of-band collapse")
	}

	revoke := access(adapter.ChangeRevoke, "admin", []string{"read"})
	rplan, err := ad.Plan(ctx, revoke)
	if err != nil {
		t.Fatalf("Plan(revoke admin): %v", err)
	}
	// Ключевая проверка «метаданные не врут»: отозванного bundle нет, но и
	// read нет — успех подтверждать нельзя.
	ver, err := ad.Verify(ctx, *rplan)
	if err != nil {
		t.Fatalf("Verify(revoke admin) before apply: %v", err)
	}
	if ver.Verified {
		t.Fatal("Verify must not confirm a revoke that lost the other bundles of the account")
	}
	if !strings.Contains(ver.Details, "read") {
		t.Errorf("verification details = %q, want them to name the missing bundle", ver.Details)
	}

	// Штатная операция приводит правила к desired-состоянию: read восстановлен
	// без пересоздания binding.
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)
	assertReadOnly(t, "after revoke admin over collapsed acl")

	// Метаданные согласованы с фактом: discovery видит read и только read.
	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if !hasBinding(snap, user, "read") {
		t.Error("binding read must be observed after the repairing revoke")
	}
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity != user {
			continue
		}
		if b.PermissionExternalID != "read" {
			t.Errorf("unexpected binding %q for user %q", b.PermissionExternalID, user)
		}
	}
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

// findAccount возвращает наблюдаемый аккаунт по engine identity.
func findAccount(snap *adapter.Snapshot, identity string) (adapter.ObservedAccount, bool) {
	for _, a := range snap.Accounts {
		if a.EngineIdentity == identity {
			return a, true
		}
	}
	return adapter.ObservedAccount{}, false
}

// TestProveCredential проверяет контракт adapter.CredentialProver на живом
// Redis — тот, на котором держится adopt mode=verify_password.
//
// Сценарии: верный пароль подтверждается, неверный отвергается
// ErrExternalIdentityConflict, пользователь с nopass (принимает любой пароль)
// честно объявляется недоказуемым ErrCredentialProofUnsupported. Отдельно
// проверяется главное свойство режима: после ЛЮБОГО из исходов пароль
// пользователя на сервере не изменился.
func TestProveCredential(t *testing.T) {
	addr, pass := target(t)
	ctx := context.Background()
	adm := adminGoRedis(t, addr, "", pass)
	ad := adredis.New()
	conn := connection(addr, pass)

	const (
		proveUser     = "grantor_it_prove"
		proveUserPass = "prove-real-password-1"
		nopassUser    = "grantor_it_nopass"
	)
	t.Cleanup(func() {
		for _, name := range []string{proveUser, nopassUser} {
			_ = adm.ACLDelUser(context.Background(), name).Err()
		}
	})
	if err := adm.ACLSetUser(ctx, proveUser, "reset", "on", ">"+proveUserPass, "~*", "+@read").Err(); err != nil {
		t.Fatalf("create prove fixture user: %v", err)
	}
	if err := adm.ACLSetUser(ctx, nopassUser, "reset", "on", "nopass", "~*", "+@read").Err(); err != nil {
		t.Fatalf("create nopass fixture user: %v", err)
	}

	account := adapter.Account{Kind: "login", EngineIdentity: proveUser}
	credential := func(secret string) adapter.Credential {
		return adapter.Credential{Kind: "password", Username: proveUser, Secret: []byte(secret)}
	}

	// Верный пароль — доказан. Пользователю разрешён только @read, поэтому
	// путь проходит через ветку NOPERM: запрещённая команда не должна
	// выглядеть отказом аутентификации.
	if err := ad.ProveCredential(ctx, conn, account, credential(proveUserPass)); err != nil {
		t.Errorf("ProveCredential with the real password: %v", err)
	}
	// Пароль не изменился: логин им по-прежнему работает.
	if authenticated, _ := userProbe(ctx, t, addr, proveUser, proveUserPass); !authenticated {
		t.Error("the real password stopped working after a successful proof")
	}

	// Неверный пароль — отказ, и снова без изменения учётки.
	err := ad.ProveCredential(ctx, conn, account, credential("prove-wrong-password-9"))
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("ProveCredential with a wrong password: err = %v, want ErrExternalIdentityConflict", err)
	}
	if authenticated, _ := userProbe(ctx, t, addr, proveUser, proveUserPass); !authenticated {
		t.Error("the real password stopped working after a rejected proof")
	}

	// nopass: сервер примет любое значение, поэтому доказать конкретный
	// пароль невозможно — fail-closed вместо ложного успеха.
	nopassAccount := adapter.Account{Kind: "login", EngineIdentity: nopassUser}
	err = ad.ProveCredential(ctx, conn, nopassAccount, adapter.Credential{
		Kind: "password", Username: nopassUser, Secret: []byte("anything-goes"),
	})
	if !errors.Is(err, adapter.ErrCredentialProofUnsupported) {
		t.Errorf("ProveCredential for a nopass user: err = %v, want ErrCredentialProofUnsupported", err)
	}

	// Выключенный пользователь (ACL off) не может доказать пароль: Redis
	// отвечает WRONGPASS, и это трактуется как отказ.
	if err := adm.ACLSetUser(ctx, proveUser, "off").Err(); err != nil {
		t.Fatalf("disable prove fixture user: %v", err)
	}
	err = ad.ProveCredential(ctx, conn, account, credential(proveUserPass))
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Errorf("ProveCredential for a disabled user: err = %v, want ErrExternalIdentityConflict", err)
	}
}
