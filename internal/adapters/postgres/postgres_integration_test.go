//go:build integration

// Интеграционные тесты PostgreSQL adapter (discovery и мутации). Требуют
// «целевой» PostgreSQL 16 (отдельный от metadata database): DSN админского
// подключения задаётся через GRANTOR_TEST_TARGET_PG_DSN, иначе тесты
// пропускаются. Фикстура создаётся идемпотентно, поэтому тесты можно
// запускать многократно над одним и тем же кластером. Для проверок паролей
// (lifecycle) целевой кластер должен требовать парольную аутентификацию
// host-подключений (не trust).
package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adaptertest"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
)

const (
	// targetEnv — переменная окружения с DSN админского подключения к
	// целевому PostgreSQL.
	targetEnv = "GRANTOR_TEST_TARGET_PG_DSN"
	// targetDatabase — база фикстуры, создаваемая в целевом кластере.
	targetDatabase = "grantor_target_app"
)

// TestContract прогоняет общий contract suite поверх целевого PostgreSQL.
// Manifest объявляет access.grant и access.revoke, поэтому suite выполняет
// grant/revoke тесты: фикстура даёт активный LOGIN-аккаунт gr_svc и две
// assignable не-dangerous роли gr_readers/gr_writers, как требует harness.
func TestContract(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ensureFixture(ctx, t, dsn)
	conn := targetConnection(t, dsn)

	adaptertest.Run(t, adaptertest.Harness{
		New: func(*testing.T) (adapter.Adapter, adapter.Connection) {
			return postgres.New(), conn
		},
		SkipLegacyCreation: true,
	})
}

// TestDiscoverFixture проверяет поверх contract suite, что discovery видит
// объекты фикстуры: базу, схему, таблицу, индекс, view, роли, membership —
// и не показывает служебные pg_% роли.
func TestDiscoverFixture(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ensureFixture(ctx, t, dsn)

	snap, err := postgres.New().Discover(ctx, targetConnection(t, dsn))
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if snap.ServerVersion == "" {
		t.Error("snapshot has empty server version")
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
		{id: "schema:" + targetDatabase + ".app", kind: "schema"},
		{id: "table:" + targetDatabase + ".app.payments", kind: "table"},
		{id: "index:" + targetDatabase + ".app.payments_created_at_idx", kind: "index"},
		{id: "view:" + targetDatabase + ".app.recent_payments", kind: "view"},
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
	if idx, ok := byID["index:"+targetDatabase+".app.payments_created_at_idx"]; ok {
		if want := "table:" + targetDatabase + ".app.payments"; idx.ParentExternalID != want {
			t.Errorf("index parent = %q, want %q", idx.ParentExternalID, want)
		}
		if idx.Attributes["unique"] != false || idx.Attributes["primary"] != false {
			t.Errorf("index attributes = %v, want non-unique non-primary", idx.Attributes)
		}
	}
	if pk, ok := byID["index:"+targetDatabase+".app.payments_pkey"]; ok {
		if pk.Attributes["primary"] != true {
			t.Errorf("primary key index attributes = %v, want primary=true", pk.Attributes)
		}
	} else {
		t.Error("primary key index of app.payments not found in snapshot")
	}

	accounts := map[string]adapter.ObservedAccount{}
	for _, a := range snap.Accounts {
		if strings.HasPrefix(a.EngineIdentity, "pg_") {
			t.Errorf("system role %q must not appear in accounts", a.EngineIdentity)
		}
		accounts[a.EngineIdentity] = a
	}
	if svc, ok := accounts["gr_svc"]; !ok {
		t.Error("account gr_svc not found")
	} else if svc.Kind != "login" {
		t.Errorf("account gr_svc kind = %q, want login", svc.Kind)
	}
	if readers, ok := accounts["gr_readers"]; !ok {
		t.Error("account gr_readers not found")
	} else if readers.Kind != "group" {
		t.Errorf("account gr_readers kind = %q, want group", readers.Kind)
	}

	perms := map[string]adapter.ObservedPermission{}
	for _, p := range snap.Permissions {
		if strings.HasPrefix(p.Name, "pg_") && p.Name != postgres.StatsRole {
			t.Errorf("system role %q must not appear in permissions", p.Name)
		}
		perms[p.ExternalID] = p
	}
	if readers, ok := perms["role:gr_readers"]; !ok {
		t.Error("permission role:gr_readers not found")
	} else {
		if !readers.Assignable {
			t.Error("permission role:gr_readers must be assignable")
		}
		if readers.Dangerous {
			t.Error("permission role:gr_readers must not be dangerous")
		}
	}
	if writers, ok := perms["role:gr_writers"]; !ok {
		t.Error("permission role:gr_writers not found")
	} else if writers.Dangerous {
		t.Error("permission role:gr_writers must not be dangerous")
	}
	if adminLike, ok := perms["role:gr_admin_like"]; !ok {
		t.Error("permission role:gr_admin_like not found")
	} else if !adminLike.Dangerous {
		t.Error("permission role:gr_admin_like must be dangerous (CREATEROLE)")
	}

	found := false
	for _, b := range snap.Bindings {
		if b.AccountEngineIdentity == "gr_svc" && b.PermissionExternalID == "role:gr_readers" {
			found = true
			break
		}
	}
	if !found {
		t.Error("binding gr_svc -> role:gr_readers not found")
	}
}

func TestPostgresSuperuserDirectProvisioningV2(t *testing.T) {
	dsn := targetDSN(t)
	ctx := t.Context()
	admin := connectTarget(ctx, t, dsn, "")
	defer admin.Close(context.Background()) //nolint:errcheck
	var adminIdentity, systemIdentifier string
	var superuser bool
	if err := admin.QueryRow(ctx, `select session_user,
		coalesce((select rolsuper from pg_roles where rolname=session_user),false),
		(select system_identifier::text from pg_control_system())`).Scan(&adminIdentity, &superuser, &systemIdentifier); err != nil {
		t.Fatal(err)
	}
	if !superuser {
		t.Fatalf("%s must use a PostgreSQL SUPERUSER for v2 integration", targetEnv)
	}
	suffix := strings.ReplaceAll(fmt.Sprintf("%d", time.Now().UnixNano()), "-", "")
	owner, account, restored := "v2_owner_"+suffix, "v2_login_"+suffix, "v2_restore_"+suffix
	group, database := "v2_group_"+suffix, "v2_db_"+suffix
	t.Cleanup(func() {
		cleanup := connectTarget(context.Background(), t, dsn, "")
		defer cleanup.Close(context.Background()) //nolint:errcheck
		for _, statement := range []string{
			"drop database if exists " + pgx.Identifier{database}.Sanitize() + " with (force)",
			"drop role if exists " + pgx.Identifier{account}.Sanitize(),
			"drop role if exists " + pgx.Identifier{restored}.Sanitize(),
			"drop role if exists " + pgx.Identifier{group}.Sanitize(),
			"drop role if exists " + pgx.Identifier{owner}.Sanitize(),
		} {
			if _, err := cleanup.Exec(context.Background(), statement); err != nil {
				t.Error(err)
			}
		}
	})
	if _, err := admin.Exec(ctx, "create role "+pgx.Identifier{owner}.Sanitize()+" nologin"); err != nil {
		t.Fatal(err)
	}
	var ownerOID uint32
	if err := admin.QueryRow(ctx, `select oid from pg_roles where rolname=$1`, owner).Scan(&ownerOID); err != nil {
		t.Fatal(err)
	}
	cfg := targetConnection(t, dsn)
	cfg.ConfigIncarnation = strings.Repeat("a", 64)
	cfg.AdminCredentialIncarnation = 1
	target := "postgres:system:" + systemIdentifier
	ad := postgres.New()
	apply := func(change adapter.DesiredChange) *adapter.Verification {
		t.Helper()
		plan, err := ad.Plan(ctx, change)
		if err != nil {
			t.Fatalf("Plan(%s): %v", change.Kind, err)
		}
		result, err := ad.Apply(ctx, *plan)
		if err != nil {
			t.Fatalf("Apply(%s): %v (result=%+v)", change.Kind, err, result)
		}
		verification, err := ad.Verify(ctx, *plan)
		if err != nil || !verification.Verified {
			t.Fatalf("Verify(%s): %+v / %v", change.Kind, verification, err)
		}
		return verification
	}
	for _, item := range []struct {
		kind adapter.ChangeKind
		name string
		cred *adapter.Credential
	}{
		{adapter.ChangePostgresAccountCreateV2, account, &adapter.Credential{Kind: "password", Username: account, Secret: []byte("Grantor-v2-account-42!")}},
		{adapter.ChangePostgresAccountRestoreV2, restored, &adapter.Credential{Kind: "password", Username: restored, Secret: []byte("Grantor-v2-restore-42!")}},
		{adapter.ChangePostgresRoleCreateV2, group, nil},
	} {
		kind := "login"
		if item.kind == adapter.ChangePostgresRoleCreateV2 {
			kind = "group"
		}
		apply(adapter.DesiredChange{Kind: item.kind, Connection: cfg,
			Account: adapter.Account{Kind: kind, EngineIdentity: item.name}, Credential: item.cred,
			ExpectedAdminIdentity: adminIdentity, ExpectedTargetIdentity: target})
	}
	verification := apply(adapter.DesiredChange{Kind: adapter.ChangePostgresDatabaseCreateV2, Connection: cfg,
		Resource:              &adapter.ResourceSpec{Kind: "database", Name: database, Attributes: map[string]any{"owner": owner}},
		ExpectedAdminIdentity: adminIdentity, ExpectedTargetIdentity: target,
		ExpectedDatabaseOwner: owner, ExpectedDatabaseOwnerOID: ownerOID})
	if verification.Observed["database_owner"] != owner || verification.Observed["database_owner_oid"] != ownerOID {
		t.Fatalf("database verification lost owner incarnation: %+v", verification.Observed)
	}
}

// targetDSN возвращает DSN целевого PostgreSQL или пропускает тест.
func targetDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv(targetEnv)
	if dsn == "" {
		t.Skipf("%s is not set; skipping target PostgreSQL integration test", targetEnv)
	}
	return dsn
}

// targetConnection строит adapter.Connection из DSN админского подключения:
// endpoint, maintenance-база и admin credential берутся из разобранного DSN.
func targetConnection(t *testing.T, dsn string) adapter.Connection {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	return adapter.Connection{
		ID:         "conn-postgres-target",
		Engine:     postgres.Engine,
		Endpoints:  []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		TLS:        adapter.TLSConfig{Mode: "disabled"},
		Attributes: map[string]any{"database": cc.Database},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: cc.User,
			Secret:   []byte(cc.Password),
		},
	}
}

func targetV2ConnectionPins(t *testing.T, dsn string) (adapter.Connection, string, string) {
	t.Helper()
	ctx := t.Context()
	admin := connectTarget(ctx, t, dsn, "")
	defer admin.Close(context.Background()) //nolint:errcheck
	var adminIdentity, systemIdentifier string
	var superuser bool
	if err := admin.QueryRow(ctx, `select session_user,
		coalesce((select rolsuper from pg_roles where rolname=session_user),false),
		(select system_identifier::text from pg_control_system())`).
		Scan(&adminIdentity, &superuser, &systemIdentifier); err != nil {
		t.Fatal(err)
	}
	if !superuser {
		t.Fatalf("%s must use a PostgreSQL SUPERUSER for v2 integration", targetEnv)
	}
	cfg := targetConnection(t, dsn)
	cfg.ConfigIncarnation = strings.Repeat("a", 64)
	cfg.AdminCredentialIncarnation = 1
	return cfg, adminIdentity, "postgres:system:" + systemIdentifier
}

// connectTarget открывает прямое pgx-подключение по DSN; непустой database
// переопределяет базу из DSN.
func connectTarget(ctx context.Context, t *testing.T, dsn, database string) *pgx.Conn {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	if database != "" {
		cc.Database = database
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatalf("connect to target database %q: %v", cc.Database, err)
	}
	return conn
}

func connectTargetAs(
	ctx context.Context,
	t *testing.T,
	dsn, database, username, password string,
) *pgx.Conn {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	cc.Database = database
	cc.User = username
	cc.Password = password
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatalf("connect to target database %q as role %q: %v", database, username, err)
	}
	return conn
}

// closeTarget закрывает подключение, игнорируя ошибку закрытия.
func closeTarget(ctx context.Context, conn *pgx.Conn) {
	_ = conn.Close(ctx)
}

// ensureFixture идемпотентно создаёт фикстуру в целевом кластере: базу
// grantor_target_app со схемой app, таблицей app.payments (с индексом) и
// view, а также роли gr_readers/gr_writers (NOLOGIN), gr_svc (LOGIN),
// gr_admin_like (NOLOGIN CREATEROLE) и membership gr_svc -> gr_readers.
func ensureFixture(ctx context.Context, t *testing.T, dsn string) {
	t.Helper()

	admin := connectTarget(ctx, t, dsn, "")
	defer closeTarget(ctx, admin)

	var exists bool
	if err := admin.QueryRow(ctx,
		`select exists (select 1 from pg_database where datname = $1)`,
		targetDatabase).Scan(&exists); err != nil {
		t.Fatalf("check fixture database: %v", err)
	}
	if !exists {
		// CREATE DATABASE нельзя выполнять в транзакции: одиночный Exec в
		// pgx работает в autocommit, поэтому это безопасно.
		if _, err := admin.Exec(ctx, `create database `+targetDatabase); err != nil {
			t.Fatalf("create fixture database: %v", err)
		}
	}

	// Роли создаются через DO-блоки с подавлением duplicate_object, чтобы
	// повторные запуски не падали. GRANT membership идемпотентен сам по
	// себе (повторный GRANT даёт только NOTICE).
	roleStmts := []string{
		`do $$ begin create role gr_readers nologin; exception when duplicate_object then null; end $$`,
		`do $$ begin create role gr_writers nologin; exception when duplicate_object then null; end $$`,
		`do $$ begin create role gr_svc login password 'x'; exception when duplicate_object then null; end $$`,
		`do $$ begin create role gr_admin_like nologin createrole; exception when duplicate_object then null; end $$`,
		`grant gr_readers to gr_svc`,
	}
	for _, stmt := range roleStmts {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("apply role fixture %q: %v", stmt, err)
		}
	}

	app := connectTarget(ctx, t, dsn, targetDatabase)
	defer closeTarget(ctx, app)

	objectStmts := []string{
		`create schema if not exists app`,
		`create table if not exists app.payments (
			id bigint generated always as identity primary key,
			amount numeric not null,
			created_at timestamptz not null default now()
		)`,
		`create index if not exists payments_created_at_idx on app.payments (created_at)`,
		`create or replace view app.recent_payments as
			select id, amount, created_at from app.payments`,
	}
	for _, stmt := range objectStmts {
		if _, err := app.Exec(ctx, stmt); err != nil {
			t.Fatalf("apply object fixture %q: %v", stmt, err)
		}
	}
}

// TestAccountLifecycle прогоняет полный жизненный цикл LOGIN-аккаунта:
// create со сгенерированным паролем -> реальный вход -> ротация пароля
// (новый работает, старый — нет) -> disable (вход запрещён) -> enable
// (вход снова работает) -> delete (роли нет).
func TestAccountLifecycle(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	conn, adminIdentity, targetIdentity := targetV2ConnectionPins(t, dsn)
	ad := postgres.New()

	name := "gr_tmp_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name}
	t.Cleanup(func() { dropRoleQuietly(dsn, name) })

	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:                   adapter.ChangePostgresAccountCreateV2,
		Connection:             conn,
		Account:                account,
		Credential:             cred,
		ExpectedAdminIdentity:  adminIdentity,
		ExpectedTargetIdentity: targetIdentity,
	})
	if err := tryLogin(ctx, t, dsn, name, string(cred.Secret)); err != nil {
		t.Fatalf("login with generated password: %v", err)
	}

	rotated, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if err := ad.RotateCredential(ctx, conn, account, *rotated); err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if err := tryLogin(ctx, t, dsn, name, string(rotated.Secret)); err != nil {
		t.Fatalf("login with rotated password: %v", err)
	}
	if err := tryLogin(ctx, t, dsn, name, string(cred.Secret)); err == nil {
		t.Fatal("login with old password must fail after rotation")
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountDisable,
		Connection: conn,
		Account:    account,
	})
	if err := tryLogin(ctx, t, dsn, name, string(rotated.Secret)); err == nil {
		t.Fatal("login must fail while account is disabled")
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountEnable,
		Connection: conn,
		Account:    account,
	})
	if err := tryLogin(ctx, t, dsn, name, string(rotated.Secret)); err != nil {
		t.Fatalf("login after enable: %v", err)
	}

	adaptertest.PlanApplyVerify(ctx, t, ad, adapter.DesiredChange{
		Kind:       adapter.ChangeAccountDelete,
		Connection: conn,
		Account:    account,
	})

	admin := connectTarget(ctx, t, dsn, "")
	defer closeTarget(ctx, admin)
	var exists bool
	if err := admin.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("check role after delete: %v", err)
	}
	if exists {
		t.Errorf("role %q still exists after account.delete", name)
	}
}

func TestAccountRestoreCredentialProofAndRetry(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	conn, adminIdentity, targetIdentity := targetV2ConnectionPins(t, dsn)
	ad := postgres.New()
	name := "gr_restore_" + adaptertest.RandomHex(t, 4)
	account := adapter.Account{Kind: "login", EngineIdentity: name}
	t.Cleanup(func() { dropRoleQuietly(dsn, name) })
	cred, err := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	change := adapter.DesiredChange{
		Kind: adapter.ChangePostgresAccountRestoreV2, Connection: conn, Account: account, Credential: cred,
		ExpectedAdminIdentity: adminIdentity, ExpectedTargetIdentity: targetIdentity,
	}
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	if err := tryLogin(ctx, t, dsn, name, string(cred.Secret)); err != nil {
		t.Fatalf("login after restore: %v", err)
	}
	// Retry после target success обязан пройти proof и быть idempotent.
	adaptertest.PlanApplyVerify(ctx, t, ad, change)
	bad := *cred
	bad.Secret = []byte("wrong-restore-proof")
	change.Credential = &bad
	if _, err := ad.Plan(ctx, change); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("Plan existing identity with wrong credential error = %v, want conflict", err)
	}
}

// TestAccountRestoreAtomicRollbackOnPasswordFailure фиксирует критическую
// границу CREATE ROLE -> PASSWORD: второй statement намеренно падает на NUL,
// а транзакция обязана откатить уже созданную role целиком.
func TestAccountRestoreAtomicRollbackOnPasswordFailure(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	conn, adminIdentity, targetIdentity := targetV2ConnectionPins(t, dsn)
	ad := postgres.New()
	name := "gr_restore_fail_" + adaptertest.RandomHex(t, 4)
	t.Cleanup(func() { dropRoleQuietly(dsn, name) })
	change := adapter.DesiredChange{
		Kind: adapter.ChangePostgresAccountRestoreV2, Connection: conn,
		Account:               adapter.Account{Kind: "login", EngineIdentity: name},
		Credential:            &adapter.Credential{Kind: "password", Username: name, Secret: []byte{'x', 0, 'y'}},
		ExpectedAdminIdentity: adminIdentity, ExpectedTargetIdentity: targetIdentity,
	}
	plan, err := ad.Plan(ctx, change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if _, err := ad.Apply(ctx, *plan); err == nil {
		t.Fatal("Apply with invalid password: err = nil, want rollback error")
	}
	admin := connectTarget(ctx, t, dsn, "")
	defer closeTarget(ctx, admin)
	var exists bool
	if err := admin.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, name).Scan(&exists); err != nil {
		t.Fatalf("check role after failed restore: %v", err)
	}
	if exists {
		t.Fatalf("role %q survived failed password statement; restore is not atomic", name)
	}
}

// tryLogin пытается подключиться к целевому кластеру указанным пользователем
// в базу postgres (CONNECT на неё по умолчанию разрешён PUBLIC). Пароль
// передаётся полем конфигурации и не попадает в DSN и тексты ошибок.
func tryLogin(ctx context.Context, t *testing.T, dsn, user, password string) error {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	cc.User = user
	cc.Password = password
	cc.Database = "postgres"
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return err
	}
	_ = conn.Close(ctx)
	return nil
}

// TestValidateConnectionPrivilegeGate проверяет матрицу минимальных привилегий
// (R4): привилегированный admin (superuser контейнера) проходит валидацию, а
// LOGIN-роль без CREATEROLE/SUPERUSER отклоняется с
// adapter.InsufficientPrivilegeError, называющим отсутствующую привилегию и не
// содержащим пароль.
func TestValidateConnectionPrivilegeGate(t *testing.T) {
	dsn := targetDSN(t)
	ctx := context.Background()
	ad := postgres.New()

	// Positive: настоящий admin (superuser) проходит проверку привилегий.
	if err := ad.ValidateConnection(ctx, targetConnection(t, dsn)); err != nil {
		t.Fatalf("ValidateConnection with privileged admin: %v", err)
	}

	// Negative: создаём LOGIN-роль без CREATEROLE/SUPERUSER. randomHex даёт
	// только [0-9a-f], поэтому пароль-литерал безопасно встраивается в DDL.
	probe := "gr_probe_" + adaptertest.RandomHex(t, 4)
	probePass := "probe" + adaptertest.RandomHex(t, 8)
	admin := connectTarget(ctx, t, dsn, "")
	defer closeTarget(ctx, admin)
	if _, err := admin.Exec(ctx,
		"create role "+pgx.Identifier{probe}.Sanitize()+" login nosuperuser nocreaterole password '"+probePass+"'"); err != nil {
		t.Fatalf("create underprivileged probe role: %v", err)
	}
	t.Cleanup(func() { dropRoleQuietly(dsn, probe) })

	conn := targetConnection(t, dsn)
	conn.AdminCredential = adapter.Credential{Kind: "password", Username: probe, Secret: []byte(probePass)}

	err := ad.ValidateConnection(ctx, conn)
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without CREATEROLE/SUPERUSER")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !strings.Contains(pe.Missing, "CREATEROLE") {
		t.Errorf("missing = %q, want it to mention CREATEROLE", pe.Missing)
	}
	if strings.Contains(err.Error(), probePass) {
		t.Error("error message leaks the probe password")
	}
}

// dropRoleQuietly удаляет временную роль напрямую админским подключением.
// Ошибки игнорируются: cleanup не должен маскировать результат теста.
func dropRoleQuietly(dsn, name string) {
	ctx := context.Background()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	_, _ = conn.Exec(ctx, "drop role if exists "+pgx.Identifier{name}.Sanitize())
}
