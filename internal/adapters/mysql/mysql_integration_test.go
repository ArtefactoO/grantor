//go:build integration

// Интеграционные тесты MySQL adapter (discovery и мутации). Требуют «целевой»
// MySQL 8.0+: DSN админского подключения задаётся через
// GRANTOR_TEST_MYSQL_DSN (например root:pass@tcp(127.0.0.1:3306)/), иначе
// тесты пропускаются. Фикстура создаётся идемпотентно, поэтому тесты можно
// запускать многократно над одним кластером. Роли требуют MySQL 8.0: на более
// старых серверах и на MariaDB role-зависимые тесты пропускаются. Секреты
// (пароли, DSN) в логи не попадают.
package mysql_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
)

const (
	// targetEnv — переменная окружения с DSN админского подключения к
	// целевому MySQL.
	targetEnv = "GRANTOR_TEST_MYSQL_DSN"
	// targetDatabase — база фикстуры, создаваемая в целевом сервере.
	targetDatabase = "grantor_target_appdb"
	// fixturePassword — небоевой пароль тестовых аккаунтов фикстуры.
	fixturePassword = "Fixture-Pass-1"
)

// TestContract прогоняет общий contract suite поверх целевого MySQL. Manifest
// объявляет access.grant/revoke, поэтому suite выполняет grant/revoke тесты:
// фикстура даёт активные login-аккаунты и две assignable не-dangerous роли
// app_ro/app_rw. На серверах без ролей MySQL 8.0 тест пропускается.
func TestContract(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	if !targetSupportsRoles(ctx, t, dsn) {
		t.Skip("target server does not support MySQL 8.0 roles; skipping contract suite")
	}
	ensureFixture(ctx, t, dsn)
	conn := targetConnection(t, dsn)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return mysql.New(), conn
		},
	})
}

// TestCredentialProof exercises the real MySQL handshake, exact CURRENT_USER
// user@host selection and the mandatory rejected-password negative probe.
func TestCredentialProof(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ensureFixture(ctx, t, dsn)
	ad := mysql.New()
	conn := targetConnection(t, dsn)
	account := adapter.Account{Kind: "login", EngineIdentity: "svc_app@%"}
	if err := ad.ProveCredential(ctx, conn, account,
		adapter.Credential{Kind: "password", Secret: []byte(fixturePassword)}); err != nil {
		t.Fatalf("ProveCredential: %v", err)
	}
	if err := ad.ProveCredential(ctx, conn, account,
		adapter.Credential{Kind: "password", Secret: []byte("definitely-wrong-password")}); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("mismatched credential error = %v, want ErrExternalIdentityConflict", err)
	}
}

// TestDiscoverFixture проверяет, что discovery видит объекты фикстуры: базу,
// таблицу, индекс, view, аккаунты (user@host), роли и binding, а также
// корректную топологию standalone.
func TestDiscoverFixture(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	rolesOK := targetSupportsRoles(ctx, t, dsn)
	ensureFixture(ctx, t, dsn)

	snap, err := mysql.New().Discover(ctx, targetConnection(t, dsn))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.ServerVersion == "" {
		t.Error("snapshot has empty server version")
	}
	if got := snap.Topology["topology"]; got != "standalone" {
		t.Errorf("topology = %v, want standalone", got)
	}

	byID := map[string]adapter.ObservedResource{}
	for _, r := range snap.Resources {
		byID[r.ExternalID] = r
	}
	wantResources := []struct {
		id   string
		kind string
	}{
		{id: "db:" + targetDatabase, kind: "database"},
		{id: "table:" + targetDatabase + ".events", kind: "table"},
		{id: "view:" + targetDatabase + ".events_recent", kind: "view"},
		{id: "index:" + targetDatabase + ".events.events_created_at_idx", kind: "index"},
	}
	for _, want := range wantResources {
		r, ok := byID[want.id]
		if !ok {
			t.Errorf("resource %q not found in snapshot", want.id)
			continue
		}
		if r.Kind != want.kind {
			t.Errorf("resource %q kind = %q, want %q", want.id, r.Kind, want.kind)
		}
		if r.Fingerprint == "" {
			t.Errorf("resource %q has empty fingerprint", want.id)
		}
	}
	if idx, ok := byID["index:"+targetDatabase+".events.events_created_at_idx"]; ok {
		if want := "table:" + targetDatabase + ".events"; idx.ParentExternalID != want {
			t.Errorf("index parent = %q, want %q", idx.ParentExternalID, want)
		}
		if idx.Attributes["unique"] != false {
			t.Errorf("index unique attribute = %v, want false", idx.Attributes["unique"])
		}
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		if strings.HasPrefix(a.EngineIdentity, "mysql.") {
			t.Errorf("system account %q must not appear in accounts", a.EngineIdentity)
		}
		accounts[a.EngineIdentity] = a
	}
	if svc, ok := accounts["svc_app@%"]; !ok {
		t.Error("account svc_app@% not found")
	} else {
		if svc.Kind != "login" {
			t.Errorf("account svc_app@%% kind = %q, want login", svc.Kind)
		}
		if svc.Disabled {
			t.Error("account svc_app@% must not be disabled")
		}
	}
	if _, ok := accounts["reader@%"]; !ok {
		t.Error("account reader@% not found")
	}

	if !rolesOK {
		return
	}
	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		perms[p.ExternalID] = p
	}
	for _, id := range []string{"role:app_ro@%", "role:app_rw@%"} {
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

	found := false
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == "svc_app@%" && b.PermissionExternalID == "role:app_ro@%" {
			found = true
			break
		}
	}
	if !found {
		t.Error("binding svc_app@% -> role:app_ro@% not found")
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл аккаунта: create со
// сгенерированным паролем -> реальный вход -> ротация (новый пароль работает,
// старый нет) -> disable (ACCOUNT LOCK, вход запрещён) -> enable (ACCOUNT
// UNLOCK, вход снова работает) -> grant роли (если сервер их поддерживает) ->
// delete. Пароли и DSN в логи не попадают.
func TestAccountLifecycle(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	rolesOK := targetSupportsRoles(ctx, t, dsn)
	if rolesOK {
		ensureFixture(ctx, t, dsn)
	}
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	identity := name + "@%"
	account := adapter.Account{Kind: "login", EngineIdentity: identity}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

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
	if err := tryLogin(ctx, dsn, name, string(cred.Secret)); err != nil {
		t.Fatalf("login with generated password: %v", err)
	}

	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if err := tryLogin(ctx, dsn, name, string(rotated.Secret)); err != nil {
		t.Fatalf("login with rotated password: %v", err)
	}
	if err := tryLogin(ctx, dsn, name, string(cred.Secret)); err == nil {
		t.Fatal("login with old password must fail after rotation")
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountDisable,
		Connection: conn,
		Account:    account,
	})
	if err := tryLogin(ctx, dsn, name, string(rotated.Secret)); err == nil {
		t.Fatal("login must fail while account is locked")
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountEnable,
		Connection: conn,
		Account:    account,
	})
	if err := tryLogin(ctx, dsn, name, string(rotated.Secret)); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}

	if rolesOK {
		adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
			Kind:       adapter.ChangeGrant,
			Connection: conn,
			Account:    account,
			Permission: "role:app_ro@%",
		})
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountDelete,
		Connection: conn,
		Account:    account,
	})
	if exists := userPresent(ctx, t, dsn, name); exists {
		t.Errorf("account %q still exists after account.delete", identity)
	}
}

// TestAccountDeleteThenRestore воспроизводит сценарий «учётку удалили по
// ошибке»: account.delete убирает её с target, а account.restore пересоздаёт
// её со свежим credential. Проверяется не read-back adapter, а факты на
// сервере: наличие строки в mysql.user и НАСТОЯЩИЙ логин восстановленной
// учёткой. Дополнительно фиксируются идемпотентность retry (второй restore
// проходит credential proof и ничего не меняет) и отказ восстановить чужую
// identity: с неверным credential Plan обязан вернуть
// ErrExternalIdentityConflict, а не перезаписать пароль существующей учётки.
func TestAccountDeleteThenRestore(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_restore_" + adaptertest.RandomHex(t, 4)
	identity := name + "@%"
	account := adapter.Account{Kind: "login", EngineIdentity: identity}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

	initial, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: initial,
	})
	if err := tryLogin(ctx, dsn, name, string(initial.Secret)); err != nil {
		t.Fatalf("login after create: %v", err)
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountDelete, Connection: conn, Account: account,
	})
	if userPresent(ctx, t, dsn, name) {
		t.Fatalf("account %q still exists after account.delete", identity)
	}

	restored, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangeAccountRestore, Connection: conn, Account: account, Credential: restored,
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	if !userPresent(ctx, t, dsn, name) {
		t.Fatalf("account %q is absent in mysql.user after account.restore", identity)
	}
	if err := tryLogin(ctx, dsn, name, string(restored.Secret)); err != nil {
		t.Fatalf("login with the restored credential: %v", err)
	}
	if err := tryLogin(ctx, dsn, name, string(initial.Secret)); err == nil {
		t.Fatal("login with the pre-delete password must fail after restore")
	}

	// Retry уже применённого restore: Plan обязан доказать credential и
	// построить recovery-план, Apply — ничего не менять.
	adaptertest.PlanApplyVerify(ctx, t, ad, change)

	bad := *restored
	bad.Secret = []byte("wrong-restore-proof")
	conflicting := change
	conflicting.Credential = &bad
	if _, err := ad.Plan(ctx, conflicting); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("Plan restore of an existing identity with a wrong credential = %v, want conflict", err)
	}
	if err := tryLogin(ctx, dsn, name, string(restored.Secret)); err != nil {
		t.Fatalf("refused restore must not touch the existing password: %v", err)
	}
}

// TestDiscoverReflectsDefaultRoleActivity фиксирует требование
// docs/architecture.md 13.1: снимок обязан инвентаризовать default roles и
// потому отличать выданную роль от фактически активной. Проверка привязана к
// реальному поведению сервера: после SET DEFAULT ROLE NONE роль остаётся
// выданной (ребро mysql.role_edges на месте), но на логине уже не
// активируется — CURRENT_ROLE() = NONE, — и это обязано быть видно в
// атрибутах binding.
func TestDiscoverReflectsDefaultRoleActivity(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	if !targetSupportsRoles(ctx, t, dsn) {
		t.Skip("target server does not support MySQL 8.0 roles")
	}
	ensureFixture(ctx, t, dsn)
	setActivateAllRolesOnLogin(ctx, t, dsn, false)
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_defrole_" + adaptertest.RandomHex(t, 4)
	identity := name + "@%"
	account := adapter.Account{Kind: "login", EngineIdentity: identity}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeAccountCreate, Connection: conn, Account: account, Credential: cred,
	})
	const role = "app_ro@%"
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind: adapter.ChangeGrant, Connection: conn, Account: account, Permission: "role:" + role,
	})

	snap, err := ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if got := snap.Topology["activate_all_roles_on_login"]; got != false {
		t.Errorf("topology activate_all_roles_on_login = %v, want false", got)
	}
	if got := accountDefaultRoles(t, snap, identity); !slices.Contains(got, role) {
		t.Errorf("account %q default_roles = %v, want it to contain %q", identity, got, role)
	}
	assertBindingActivity(t, snap, identity, "role:"+role, true)

	// Роль остаётся выданной, но перестаёт активироваться на логине.
	adminExec(ctx, t, dsn, "SET DEFAULT ROLE NONE TO '"+name+"'@'%'")
	current, err := currentRoleOfUser(ctx, dsn, name, string(cred.Secret))
	if err != nil {
		t.Fatalf("read CURRENT_ROLE() of the granted account: %v", err)
	}
	if !strings.EqualFold(strings.TrimSpace(current), "NONE") {
		t.Fatalf("CURRENT_ROLE() = %q, want NONE after SET DEFAULT ROLE NONE", current)
	}

	snap, err = ad.Discover(ctx, conn)
	if err != nil {
		t.Fatalf("Discover after SET DEFAULT ROLE NONE: %v", err)
	}
	if got := accountDefaultRoles(t, snap, identity); len(got) != 0 {
		t.Errorf("account %q default_roles = %v, want empty", identity, got)
	}
	// Ребро выдачи обязано остаться: снимок различает «роль выдана» и
	// «роль активна», а не теряет binding целиком.
	assertBindingActivity(t, snap, identity, "role:"+role, false)
}

// assertBindingActivity проверяет атрибуты активности binding: default_role и
// active обязаны совпадать с ожидаемым (при activate_all_roles_on_login=OFF
// они равны друг другу).
func assertBindingActivity(t *testing.T, snap *adapter.Snapshot, identity, permission string, want bool) {
	t.Helper()
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity != identity || b.PermissionExternalID != permission {
			continue
		}
		if got := b.Attributes["default_role"]; got != want {
			t.Errorf("binding %s -> %s default_role = %v, want %v", identity, permission, got, want)
		}
		// Ключ контрактный (adapter.AttrBindingEffective): по нему ядро
		// отличает «право выдано» от «право действует».
		if got := b.Attributes[adapter.AttrBindingEffective]; got != want {
			t.Errorf("binding %s -> %s effective = %v, want %v", identity, permission, got, want)
		}
		return
	}
	t.Fatalf("binding %s -> %s not found in snapshot", identity, permission)
}

// accountDefaultRoles возвращает атрибут default_roles аккаунта из snapshot.
func accountDefaultRoles(t *testing.T, snap *adapter.Snapshot, identity string) []string {
	t.Helper()
	for _, a := range snap.Accounts {
		if a.EngineIdentity != identity {
			continue
		}
		roles, ok := a.Attributes["default_roles"].([]string)
		if !ok {
			t.Fatalf("account %q has no default_roles attribute: %+v", identity, a.Attributes)
		}
		return roles
	}
	t.Fatalf("account %q not found in snapshot", identity)
	return nil
}

// TestGrantActivatesRoleForRealLogin — регрессия на «выданная роль без
// доступа». Проверка выполняется настоящим логином выданной учёткой и
// запросом, который разрешает только роль: read-back по SHOW GRANTS или
// mysql.role_edges такую ошибку не ловит, потому что при
// activate_all_roles_on_login=OFF роль числится выданной, но на логине не
// активируется (CURRENT_ROLE() = NONE) и запрос отклоняется с ER_TABLEACCESS_
// DENIED_ERROR. Негативная часть: после revoke тот же запрос снова отклоняется.
func TestGrantActivatesRoleForRealLogin(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	if !targetSupportsRoles(ctx, t, dsn) {
		t.Skip("target server does not support MySQL 8.0 roles")
	}
	ensureFixture(ctx, t, dsn)
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_role_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name + "@%"}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

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
	password := string(cred.Secret)

	// До grant роль-зависимый запрос обязан отклоняться: иначе положительная
	// проверка ниже ничего не доказывает.
	if err := selectAsUser(ctx, dsn, name, password); err == nil {
		t.Fatal("account without the role must not be able to read the role-protected table")
	}

	grant := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    account,
		Permission: "role:app_ro@%",
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)

	role, err := currentRoleOfUser(ctx, dsn, name, password)
	if err != nil {
		t.Fatalf("read CURRENT_ROLE() after grant: %v", err)
	}
	if !strings.Contains(role, "app_ro") {
		t.Fatalf("CURRENT_ROLE() = %q after grant, want the granted role to be active on login", role)
	}
	if err := selectAsUser(ctx, dsn, name, password); err != nil {
		t.Fatalf("query allowed by the granted role must succeed after grant: %v", err)
	}

	// Повторный grant остаётся идемпотентным и не ломает активацию.
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	if err := selectAsUser(ctx, dsn, name, password); err != nil {
		t.Fatalf("query must still succeed after a repeated grant: %v", err)
	}

	revoke := grant
	revoke.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)

	if err := selectAsUser(ctx, dsn, name, password); err == nil {
		t.Fatal("query allowed by the role must be denied after revoke")
	}
	role, err = currentRoleOfUser(ctx, dsn, name, password)
	if err != nil {
		t.Fatalf("read CURRENT_ROLE() after revoke: %v", err)
	}
	if role != "NONE" {
		t.Errorf("CURRENT_ROLE() = %q after revoke, want NONE", role)
	}
	if n := defaultRoleCount(ctx, t, dsn, name); n != 0 {
		t.Errorf("account has %d default role rows after revoke, want 0", n)
	}
}

// TestGrantRepairsMissingDefaultRole фиксирует поведение на состоянии,
// оставшемся от прежней реализации: роль выдана, но не является default role.
// Verify обязан такое состояние не подтверждать, а Apply — чинить его, не
// сваливаясь в StepSkipped по наличию ребра role_edges.
func TestGrantRepairsMissingDefaultRole(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	if !targetSupportsRoles(ctx, t, dsn) {
		t.Skip("target server does not support MySQL 8.0 roles")
	}
	ensureFixture(ctx, t, dsn)
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_legacy_" + adaptertest.RandomHex(t, 4)
	// RandomHex даёт только [0-9a-f], поэтому пароль-литерал безопасно
	// встраивается в DDL фикстуры.
	password := "legacy" + adaptertest.RandomHex(t, 8)
	account := adapter.Account{Kind: "login", EngineIdentity: name + "@%"}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

	adminExec(ctx, t, dsn, "CREATE USER '"+name+"'@'%' IDENTIFIED BY '"+password+"'")
	// Состояние «как до исправления»: только GRANT, без SET DEFAULT ROLE.
	adminExec(ctx, t, dsn, "GRANT 'app_ro'@'%' TO '"+name+"'@'%'")
	if err := selectAsUser(ctx, dsn, name, password); err == nil {
		t.Fatal("granted-but-inactive role must not give access; fixture does not reproduce the bug")
	}

	grant := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    account,
		Permission: "role:app_ro@%",
	}
	plan, err := ad.Plan(ctx, grant)
	if err != nil {
		t.Fatalf("Plan(grant): %v", err)
	}
	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if ver.Verified {
		t.Fatal("Verify must not confirm a granted role that does not activate on login")
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	if err := selectAsUser(ctx, dsn, name, password); err != nil {
		t.Fatalf("query allowed by the role must succeed after the repairing apply: %v", err)
	}
}

// TestGrantWithActivateAllRolesOnLogin проверяет второй режим сервера: при
// activate_all_roles_on_login=ON роли активируются на логине независимо от
// mysql.default_roles. Grant и revoke обязаны оставаться корректными и здесь.
func TestGrantWithActivateAllRolesOnLogin(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	if !targetSupportsRoles(ctx, t, dsn) {
		t.Skip("target server does not support MySQL 8.0 roles")
	}
	ensureFixture(ctx, t, dsn)
	setActivateAllRolesOnLogin(ctx, t, dsn, true)
	conn := targetConnection(t, dsn)
	ad := mysql.New()

	name := "gr_actall_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name + "@%"}
	t.Cleanup(func() { dropUserQuietly(dsn, name) })

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
	password := string(cred.Secret)

	grant := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Connection: conn,
		Account:    account,
		Permission: "role:app_ro@%",
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, grant)
	if err := selectAsUser(ctx, dsn, name, password); err != nil {
		t.Fatalf("query allowed by the granted role must succeed with activate_all_roles_on_login=ON: %v", err)
	}

	revoke := grant
	revoke.Kind = adapter.ChangeRevoke
	adaptertest.PlanApplyVerify(ctx, t, ad, revoke)
	if err := selectAsUser(ctx, dsn, name, password); err == nil {
		t.Fatal("query must be denied after revoke even with activate_all_roles_on_login=ON")
	}
}

// selectAsUser выполняет от имени указанной учётки запрос, разрешённый только
// ролью app_ro (SELECT по таблице фикстуры). Ошибка означает, что роль на
// логине не активна. Пароль передаётся полем конфигурации и не попадает в
// тексты ошибок.
func selectAsUser(ctx context.Context, dsn, user, password string) error {
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return err
	}
	cc.User = user
	cc.Passwd = password
	cc.DBName = ""
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	var n int64
	return db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+targetDatabase+`.events`).Scan(&n)
}

// currentRoleOfUser возвращает CURRENT_ROLE() для сессии указанной учётки:
// "NONE" либо перечисление активных ролей.
func currentRoleOfUser(ctx context.Context, dsn, user, password string) (string, error) {
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", err
	}
	cc.User = user
	cc.Passwd = password
	cc.DBName = ""
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		return "", err
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	var role string
	if err := db.QueryRowContext(ctx, `SELECT CURRENT_ROLE()`).Scan(&role); err != nil {
		return "", err
	}
	return role, nil
}

// defaultRoleCount возвращает число записей аккаунта в mysql.default_roles.
func defaultRoleCount(ctx context.Context, t *testing.T, dsn, name string) int64 {
	t.Helper()
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()
	var n int64
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM mysql.default_roles WHERE USER = ? AND HOST = '%'`, name).Scan(&n); err != nil {
		t.Fatalf("count default roles: %v", err)
	}
	return n
}

// adminExec выполняет statement фикстуры админским подключением.
func adminExec(ctx context.Context, t *testing.T, dsn, stmt string) {
	t.Helper()
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("apply fixture statement: %v", err)
	}
}

// setActivateAllRolesOnLogin переключает глобальную переменную сервера и
// восстанавливает прежнее значение по завершении теста. Если у админа нет прав
// на изменение глобальных переменных, тест пропускается.
func setActivateAllRolesOnLogin(ctx context.Context, t *testing.T, dsn string, on bool) {
	t.Helper()
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()

	var previous int64
	if err := db.QueryRowContext(ctx, `SELECT @@GLOBAL.activate_all_roles_on_login`).Scan(&previous); err != nil {
		t.Skipf("server does not expose activate_all_roles_on_login: %v", err)
	}
	value := "OFF"
	if on {
		value = "ON"
	}
	if _, err := db.ExecContext(ctx, `SET GLOBAL activate_all_roles_on_login = `+value); err != nil {
		t.Skipf("cannot change activate_all_roles_on_login: %v", err)
	}
	t.Cleanup(func() {
		restore := openTarget(t, dsn, "", "", "")
		defer func() { _ = restore.Close() }()
		_, _ = restore.ExecContext(context.Background(),
			`SET GLOBAL activate_all_roles_on_login = `+strconv.FormatInt(previous, 10))
	})
}

// targetDSN возвращает DSN целевого MySQL или пропускает тест.
func targetDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(targetEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping target MySQL integration test", targetEnv)
	}
	return dsn
}

// adminConfig разбирает DSN в конфигурацию go-sql-driver.
func adminConfig(t *testing.T, dsn string) *mysqldriver.Config {
	t.Helper()
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	return cc
}

// targetConnection строит adapter.Connection из DSN админского подключения:
// endpoint и admin credential берутся из разобранного DSN.
func targetConnection(t *testing.T, dsn string) adapter.Connection {
	t.Helper()
	cc := adminConfig(t, dsn)
	return adapter.Connection{
		ID:         "conn-mysql-target",
		Engine:     mysql.Engine,
		Endpoints:  []string{cc.Addr},
		TLS:        adapter.TLSConfig{Mode: "disabled"},
		Attributes: map[string]any{},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: cc.User,
			Secret:   []byte(cc.Passwd),
		},
	}
}

// openTarget открывает пул к целевому серверу по DSN; user/password/database
// переопределяют значения из DSN (пустые — оставляют как в DSN).
func openTarget(t *testing.T, dsn, user, password, database string) *sql.DB {
	t.Helper()
	cc := adminConfig(t, dsn)
	if user != "" {
		cc.User = user
		cc.Passwd = password
	}
	cc.DBName = database
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		t.Fatalf("build connector: %v", err)
	}
	return sql.OpenDB(connector)
}

// targetSupportsRoles сообщает, поддерживает ли целевой сервер роли MySQL 8.0.
func targetSupportsRoles(ctx context.Context, t *testing.T, dsn string) bool {
	t.Helper()
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()
	var version string
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		t.Fatalf("read server version: %v", err)
	}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return false
	}
	return majorAtLeast8(version)
}

// majorAtLeast8 сообщает, что major-версия >= 8 (покрывает 8.x, 9.x и т.д.).
func majorAtLeast8(version string) bool {
	digits := ""
	for _, r := range version {
		if r < '0' || r > '9' {
			break
		}
		digits += string(r)
	}
	if digits == "" {
		return false
	}
	// Достаточно первого символа: одноцифровые major < 8 отсеются, 8/9 и
	// многоцифровые (10+) вернут true.
	if len(digits) > 1 {
		return true
	}
	return digits[0] >= '8'
}

// ensureFixture идемпотентно создаёт фикстуру в целевом сервере: базу appdb с
// таблицей events (+ индекс) и view, роли app_ro/app_rw (только на MySQL 8.0),
// аккаунты svc_app@% и reader@% и role bindings svc_app->app_ro,
// reader->app_rw.
func ensureFixture(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()

	admin := openTarget(t, dsn, "", "", "")
	defer func() { _ = admin.Close() }()

	objectStmts := []string{
		`CREATE DATABASE IF NOT EXISTS ` + targetDatabase,
		`CREATE TABLE IF NOT EXISTS ` + targetDatabase + `.events (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			created_at DATETIME NOT NULL,
			KEY events_created_at_idx (created_at)
		)`,
		`CREATE OR REPLACE VIEW ` + targetDatabase + `.events_recent AS
			SELECT id, name FROM ` + targetDatabase + `.events`,
	}
	for _, stmt := range objectStmts {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply object fixture: %v", err)
		}
	}

	// Аккаунты создаются идемпотентно (CREATE USER IF NOT EXISTS). Пароли —
	// небоевые константы фикстуры.
	userStmts := []string{
		`CREATE USER IF NOT EXISTS 'svc_app'@'%' IDENTIFIED BY '` + fixturePassword + `'`,
		`CREATE USER IF NOT EXISTS 'reader'@'%' IDENTIFIED BY '` + fixturePassword + `'`,
	}
	for _, stmt := range userStmts {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply user fixture: %v", err)
		}
	}

	if !targetSupportsRoles(ctx, t, dsn) {
		return
	}
	roleStmts := []string{
		`CREATE ROLE IF NOT EXISTS 'app_ro'@'%'`,
		`CREATE ROLE IF NOT EXISTS 'app_rw'@'%'`,
		`GRANT SELECT ON ` + targetDatabase + `.* TO 'app_ro'@'%'`,
		`GRANT SELECT, INSERT, UPDATE ON ` + targetDatabase + `.* TO 'app_rw'@'%'`,
		`GRANT 'app_ro'@'%' TO 'svc_app'@'%'`,
		`GRANT 'app_rw'@'%' TO 'reader'@'%'`,
	}
	for _, stmt := range roleStmts {
		if _, err := admin.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("apply role fixture: %v", err)
		}
	}
}

// tryLogin пытается подключиться к целевому серверу указанным пользователем.
// Пароль передаётся полем конфигурации и не попадает в тексты ошибок.
func tryLogin(ctx context.Context, dsn, user, password string) error {
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return err
	}
	cc.User = user
	cc.Passwd = password
	cc.DBName = ""
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	return db.PingContext(ctx)
}

// userPresent сообщает, существует ли аккаунт name@% в mysql.user.
func userPresent(ctx context.Context, t *testing.T, dsn, name string) bool {
	t.Helper()
	db := openTarget(t, dsn, "", "", "")
	defer func() { _ = db.Close() }()
	var exists int64
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM mysql.user WHERE User = ? AND Host = '%')`, name).Scan(&exists); err != nil {
		t.Fatalf("check account after delete: %v", err)
	}
	return exists != 0
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): привилегированный admin (root) проходит валидацию, а аккаунт лишь с
// SELECT (без CREATE USER и GRANT OPTION) отклоняется с
// adapter.InsufficientPrivilegeError, называющим отсутствующую привилегию и не
// содержащим пароль. Роли MySQL 8.0 для этого теста не нужны.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ad := mysql.New()

	// Positive: настоящий admin (root) проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, targetConnection(t, dsn)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: аккаунт только с SELECT на одной базе. randomHex даёт только
	// [0-9a-f], поэтому пароль-литерал безопасно встраивается в DDL.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	admin := openTarget(t, dsn, "", "", "")
	defer func() { _ = admin.Close() }()
	if _, err := admin.ExecContext(ctx,
		"CREATE USER '"+probe+"'@'%' IDENTIFIED BY '"+probePass+"'"); err != nil {
		t.Fatalf("create underprivileged probe user: %v", err)
	}
	t.Cleanup(func() { dropUserQuietly(dsn, probe) })
	if _, err := admin.ExecContext(ctx,
		"GRANT SELECT ON `mysql`.* TO '"+probe+"'@'%'"); err != nil {
		t.Fatalf("grant SELECT to probe user: %v", err)
	}

	conn := targetConnection(t, dsn)
	conn.AdminCredential = adapter.Credential{Kind: "password", Username: probe, Secret: []byte(probePass)}

	err := ad.ValidateConnection(ctx, conn)
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without CREATE USER / GRANT OPTION")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !strings.Contains(pe.Missing, "CREATE USER") {
		t.Errorf("missing = %q, want it to mention CREATE USER", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}

// dropUserQuietly удаляет временный аккаунт name@% напрямую админским
// подключением. Ошибки игнорируются: cleanup не должен маскировать результат
// теста.
func dropUserQuietly(dsn, name string) {
	cc, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return
	}
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		return
	}
	db := sql.OpenDB(connector)
	defer func() { _ = db.Close() }()
	_, _ = db.ExecContext(context.Background(), "DROP USER IF EXISTS '"+name+"'@'%'")
}
