package postgres

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestQuoteLiteral(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "plain", want: "'plain'"},
		{in: "", want: "''"},
		{in: "O'Brien", want: "'O''Brien'"},
		{in: "''", want: "''''''"},
		{in: `back\slash`, want: `'back\slash'`},
		{in: "юникод-пароль", want: "'юникод-пароль'"},
	}
	for _, tt := range tests {
		got, err := quoteLiteral(tt.in)
		if err != nil {
			t.Errorf("quoteLiteral(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("quoteLiteral(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	if _, err := quoteLiteral("bad\x00byte"); err == nil {
		t.Error("quoteLiteral must reject NUL bytes")
	}
}

func TestRoleNameFromPermission(t *testing.T) {
	name, err := roleNameFromPermission("role:gr_readers")
	if err != nil {
		t.Fatalf("roleNameFromPermission: %v", err)
	}
	if name != "gr_readers" {
		t.Errorf("roleNameFromPermission = %q, want gr_readers", name)
	}
	for _, bad := range []string{"", "role:", "gr_readers", "db:app"} {
		if _, err := roleNameFromPermission(bad); err == nil {
			t.Errorf("roleNameFromPermission(%q): expected error", bad)
		}
	}
}

func TestGenerateCredential(t *testing.T) {
	ctx := context.Background()
	a := New()

	def, err := a.GenerateCredential(ctx, adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential(default): %v", err)
	}
	if def.Kind != "password" {
		t.Errorf("credential kind = %q, want password", def.Kind)
	}
	if len(def.Secret) != adapterutil.DefaultPasswordLength {
		t.Errorf("default credential length = %d, want %d", len(def.Secret), adapterutil.DefaultPasswordLength)
	}

	cred, err := a.GenerateCredential(ctx, adapter.CredentialPolicy{Length: 48})
	if err != nil {
		t.Fatalf("GenerateCredential(48): %v", err)
	}
	if len(cred.Secret) != 48 {
		t.Errorf("credential length = %d, want 48", len(cred.Secret))
	}
	alphabet := regexp.MustCompile(`^[A-Za-z0-9]+$`)
	if !alphabet.Match(cred.Secret) {
		t.Errorf("credential contains characters outside [a-zA-Z0-9]: %q", cred.Secret)
	}

	other, err := a.GenerateCredential(ctx, adapter.CredentialPolicy{Length: 48})
	if err != nil {
		t.Fatalf("GenerateCredential(48): %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated credentials must differ")
	}
}

// TestPlanKinds проверяет маппинг ChangeKind -> шаги плана на ветках, не
// требующих подключения к БД, и default-ветку ErrUnsupportedChange.
func TestPlanKinds(t *testing.T) {
	ctx := context.Background()
	a := New()
	account := adapter.Account{Kind: "login", EngineIdentity: "gr_tmp"}

	// Создание баз поддерживается, а прочие виды ресурсов — нет: capability
	// параметризована видом, и объявлен только database.
	t.Run("resource.create of another kind is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:     adapter.ChangeResourceCreate,
			Resource: &adapter.ResourceSpec{Kind: "schema", Name: "app"},
		})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(resource.create schema): err = %v, want ErrUnsupportedChange", err)
		}
	})

	t.Run("resource.create without a spec is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeResourceCreate})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(resource.create) without spec: err = %v, want ErrUnsupportedChange", err)
		}
	})

	t.Run("unknown kind is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeKind("bogus")})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(bogus): err = %v, want ErrUnsupportedChange", err)
		}
	})

	t.Run("revoke", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:       adapter.ChangeRevoke,
			Account:    account,
			Permission: "role:gr_readers",
		})
		if err != nil {
			t.Fatalf("Plan(revoke): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepRevoke {
			t.Fatalf("Plan(revoke) steps = %+v, want single %q step", plan.Steps, stepRevoke)
		}
		if !strings.Contains(plan.Steps[0].Description, "revoke") {
			t.Errorf("revoke description = %q, want mention of revoke", plan.Steps[0].Description)
		}
	})

	t.Run("disable", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: account})
		if err != nil {
			t.Fatalf("Plan(account.disable): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepAlterLogin {
			t.Fatalf("Plan(account.disable) steps = %+v, want single %q step", plan.Steps, stepAlterLogin)
		}
		if plan.Steps[0].Attributes["login"] != false {
			t.Errorf("disable step attributes = %v, want login=false", plan.Steps[0].Attributes)
		}
		if !strings.Contains(plan.Steps[0].Description, "disable") {
			t.Errorf("disable description = %q, want mention of disable", plan.Steps[0].Description)
		}
	})

	t.Run("enable", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: account})
		if err != nil {
			t.Fatalf("Plan(account.enable): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepAlterLogin {
			t.Fatalf("Plan(account.enable) steps = %+v, want single %q step", plan.Steps, stepAlterLogin)
		}
		if plan.Steps[0].Attributes["login"] != true {
			t.Errorf("enable step attributes = %v, want login=true", plan.Steps[0].Attributes)
		}
	})

	t.Run("delete warns about memberships", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeAccountDelete, Account: account})
		if err != nil {
			t.Fatalf("Plan(account.delete): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepDropRole {
			t.Fatalf("Plan(account.delete) steps = %+v, want single %q step", plan.Steps, stepDropRole)
		}
		if !strings.Contains(strings.ToLower(plan.Steps[0].Description), "membership") {
			t.Errorf("delete description = %q, want warning about memberships", plan.Steps[0].Description)
		}
	})

	t.Run("grant with malformed permission", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:       adapter.ChangeGrant,
			Account:    account,
			Permission: "gr_readers",
		})
		if err == nil {
			t.Error("Plan(grant) with malformed permission: expected error")
		}
	})

	t.Run("grant with scope is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:       adapter.ChangeGrant,
			Account:    account,
			Permission: "role:gr_readers",
			Scope:      "db:app",
		})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(grant with scope): err = %v, want ErrUnsupportedChange", err)
		}
	})

	t.Run("empty account identity", func(t *testing.T) {
		for _, kind := range []adapter.ChangeKind{
			adapter.ChangeAccountDisable,
			adapter.ChangeAccountEnable,
			adapter.ChangeAccountDelete,
		} {
			if _, err := a.Plan(ctx, adapter.DesiredChange{Kind: kind}); err == nil {
				t.Errorf("Plan(%s) with empty account identity: expected error", kind)
			}
		}
	})
}

func TestManifestDeclaresMutationCapabilities(t *testing.T) {
	m := New().Manifest()
	for _, c := range []adapter.Capability{
		adapter.CapAccessGrant,
		adapter.CapAccessRevoke,
		adapter.CapAccountCreate,
		adapter.CapAccountDisable,
		adapter.CapAccountEnable,
		adapter.CapAccountDelete,
		adapter.CapCredentialRotate,
	} {
		if !m.HasCapability(c) {
			t.Errorf("manifest must declare capability %q", c)
		}
	}
}

// TestRotateCredentialValidatesInput фиксирует валидацию аргументов до
// любых попыток подключения к целевой системе.
func TestRotateCredentialValidatesInput(t *testing.T) {
	ctx := context.Background()
	cfg := adapter.Connection{Engine: Engine, Endpoints: []string{"localhost:5432"}}
	if err := New().RotateCredential(ctx, cfg,
		adapter.Account{Kind: "login"},
		adapter.Credential{Kind: "password", Secret: []byte("x")}); err == nil ||
		!strings.Contains(err.Error(), "engine identity") {
		t.Errorf("RotateCredential without identity: err = %v, want engine identity error", err)
	}
	if err := New().RotateCredential(ctx, cfg,
		adapter.Account{Kind: "login", EngineIdentity: "gr_svc"},
		adapter.Credential{Kind: "password"}); err == nil ||
		!strings.Contains(err.Error(), "secret is empty") {
		t.Errorf("RotateCredential without secret: err = %v, want secret error", err)
	}
}

// Сборка CREATE DATABASE — центральный пункт security review (S8): имя и
// опции приходят от оператора, а параметров CREATE DATABASE не принимает,
// поэтому всё уходит в текст запроса.
func TestCreateDatabaseSQL(t *testing.T) {
	limit := 25
	cases := []struct {
		name string
		db   string
		spec databaseSpec
		want string
	}{
		{
			name: "минимальная база",
			db:   "appdb",
			want: `create database "appdb"`,
		},
		{
			name: "все опции",
			db:   "appdb",
			spec: databaseSpec{
				Owner: "app_owner", Template: "template0", Encoding: "UTF8",
				Locale: "en_US.utf8", Tablespace: "fast", ConnectionLimit: &limit,
			},
			want: `create database "appdb" owner "app_owner" template "template0" ` +
				`encoding 'UTF8' locale 'en_US.utf8' tablespace "fast" connection limit 25`,
		},
		{
			name: "кавычка в имени экранируется",
			db:   `ev"il`,
			want: `create database "ev""il"`,
		},
		{
			name: "апостроф в литерале экранируется",
			db:   "appdb",
			spec: databaseSpec{Locale: "en_US'--"},
			want: `create database "appdb" locale 'en_US''--'`,
		},
		{
			name: "точка с запятой остаётся частью идентификатора",
			db:   "app; drop database postgres",
			want: `create database "app; drop database postgres"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := createDatabaseSQL(tc.db, tc.spec)
			if err != nil {
				t.Fatalf("createDatabaseSQL: %v", err)
			}
			if got != tc.want {
				t.Errorf("createDatabaseSQL =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}

	t.Run("NUL в литерале отвергается", func(t *testing.T) {
		if _, err := createDatabaseSQL("appdb", databaseSpec{Locale: "en\x00US"}); err == nil {
			t.Error("createDatabaseSQL with a NUL literal = nil error, want refusal")
		}
	})
}

// Разбор опций строгий: молча проигнорированная опция означала бы базу с не
// теми параметрами, а отката у создания нет.
func TestParseDatabaseSpec(t *testing.T) {
	spec, err := parseDatabaseSpec(map[string]any{
		"owner": " app_owner ", "connection_limit": float64(10),
	})
	if err != nil {
		t.Fatalf("parseDatabaseSpec: %v", err)
	}
	if spec.Owner != "app_owner" {
		t.Errorf("owner = %q, want trimmed app_owner", spec.Owner)
	}
	if spec.ConnectionLimit == nil || *spec.ConnectionLimit != 10 {
		t.Errorf("connection_limit = %v, want 10", spec.ConnectionLimit)
	}

	for name, attrs := range map[string]map[string]any{
		"неизвестная опция":        {"superuser": "yes"},
		"нестроковый owner":        {"owner": 42},
		"дробный connection_limit": {"connection_limit": float64(1.5)},
		"connection_limit < -1":    {"connection_limit": float64(-2)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDatabaseSpec(attrs); err == nil {
				t.Errorf("parseDatabaseSpec(%v) = nil error, want refusal", attrs)
			}
		})
	}
}

// Шаблон и tablespace без явного allowlist подключения запрещены: оба
// выходят за пределы «завести пустую базу» (architecture §11.2).
func TestDatabaseCreateAllowlists(t *testing.T) {
	empty := adapter.Connection{}
	if err := checkAllowed(empty, adapter.AttrDatabaseCreateTemplates, "template", "template0"); err == nil {
		t.Error("template without an allowlist = nil error, want refusal")
	}
	if err := checkAllowed(empty, adapter.AttrDatabaseCreateTemplates, "template", ""); err != nil {
		t.Errorf("unset template must stay allowed: %v", err)
	}

	configured := adapter.Connection{Attributes: map[string]any{
		adapter.AttrDatabaseCreateTemplates: []string{"template0"},
	}}
	if err := checkAllowed(configured, adapter.AttrDatabaseCreateTemplates, "template", "template0"); err != nil {
		t.Errorf("allowlisted template rejected: %v", err)
	}
	if err := checkAllowed(configured, adapter.AttrDatabaseCreateTemplates, "template", "template1"); err == nil {
		t.Error("template outside the allowlist = nil error, want refusal")
	}
	// Списки приезжают из jsonb как []any.
	fromJSON := adapter.Connection{Attributes: map[string]any{
		adapter.AttrDatabaseCreateTemplates: []any{"template0"},
	}}
	if err := checkAllowed(fromJSON, adapter.AttrDatabaseCreateTemplates, "template", "template0"); err != nil {
		t.Errorf("allowlist decoded from json rejected: %v", err)
	}
}
