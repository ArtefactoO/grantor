package mysql

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestParseUserHost(t *testing.T) {
	tests := []struct {
		identity string
		user     string
		host     string
		wantErr  bool
	}{
		{identity: "app@10.%", user: "app", host: "10.%"},
		{identity: "app@localhost", user: "app", host: "localhost"},
		{identity: "svc_app@%", user: "svc_app", host: "%"},
		// host может быть пустым: split по последнему '@'.
		{identity: "app@", user: "app", host: ""},
		// '@' допустим внутри username, host — после последнего '@'.
		{identity: "we@rd@10.%", user: "we@rd", host: "10.%"},
		// без '@' — ошибка (host обязателен).
		{identity: "userwithouthost", wantErr: true},
		{identity: "", wantErr: true},
		// пустой user — ошибка.
		{identity: "@localhost", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parseUserHost(tt.identity)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseUserHost(%q): expected error", tt.identity)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseUserHost(%q): %v", tt.identity, err)
			continue
		}
		if got.user != tt.user || got.host != tt.host {
			t.Errorf("parseUserHost(%q) = (%q, %q), want (%q, %q)", tt.identity, got.user, got.host, tt.user, tt.host)
		}
		if got.String() != tt.identity {
			t.Errorf("parseUserHost(%q).String() = %q, want round-trip", tt.identity, got.String())
		}
	}
}

func TestUserHostQuoted(t *testing.T) {
	tests := []struct {
		user string
		host string
		want string
	}{
		{user: "app", host: "%", want: "'app'@'%'"},
		{user: "app", host: "10.%", want: "'app'@'10.%'"},
		{user: "svc_app", host: "localhost", want: "'svc_app'@'localhost'"},
		{user: "o'brien", host: "%", want: `'o\'brien'@'%'`},
		{user: `back\slash`, host: "%", want: `'back\\slash'@'%'`},
	}
	for _, tt := range tests {
		u := userHost{user: tt.user, host: tt.host}
		if got := u.quoted(); got != tt.want {
			t.Errorf("userHost{%q,%q}.quoted() = %q, want %q", tt.user, tt.host, got, tt.want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "plain", want: "'plain'"},
		{in: "", want: "''"},
		{in: "O'Brien", want: `'O\'Brien'`},
		{in: `back\slash`, want: `'back\\slash'`},
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

func TestDangerousPrivileges(t *testing.T) {
	tests := []struct {
		name  string
		privs []string
		want  bool
	}{
		{name: "empty", privs: nil, want: false},
		{name: "read only", privs: []string{"SELECT", "SHOW VIEW"}, want: false},
		{name: "write", privs: []string{"SELECT", "INSERT", "UPDATE", "DELETE"}, want: false},
		{name: "super", privs: []string{"SELECT", "SUPER"}, want: true},
		{name: "grant option", privs: []string{"SELECT", "GRANT OPTION"}, want: true},
		{name: "create user", privs: []string{"CREATE USER"}, want: true},
		{name: "system_user dynamic", privs: []string{"SYSTEM_USER"}, want: true},
		{name: "case insensitive", privs: []string{"super"}, want: true},
		{name: "whitespace", privs: []string{" GRANT OPTION "}, want: true},
	}
	for _, tt := range tests {
		if got := dangerousPrivileges(tt.privs); got != tt.want {
			t.Errorf("%s: dangerousPrivileges(%v) = %v, want %v", tt.name, tt.privs, got, tt.want)
		}
	}
}

func TestParseGrantee(t *testing.T) {
	tests := []struct {
		grantee string
		user    string
		host    string
		ok      bool
	}{
		{grantee: "'app_ro'@'%'", user: "app_ro", host: "%", ok: true},
		{grantee: "'svc'@'10.%'", user: "svc", host: "10.%", ok: true},
		{grantee: "'root'@'localhost'", user: "root", host: "localhost", ok: true},
		{grantee: "'app'@''", user: "app", host: "", ok: true},
		{grantee: "app@%", ok: false},
		{grantee: "", ok: false},
	}
	for _, tt := range tests {
		user, host, ok := parseGrantee(tt.grantee)
		if ok != tt.ok {
			t.Errorf("parseGrantee(%q) ok = %v, want %v", tt.grantee, ok, tt.ok)
			continue
		}
		if ok && (user != tt.user || host != tt.host) {
			t.Errorf("parseGrantee(%q) = (%q, %q), want (%q, %q)", tt.grantee, user, host, tt.user, tt.host)
		}
	}
}

func TestClassifyTopology(t *testing.T) {
	tests := []struct {
		name          string
		readOnly      bool
		superReadOnly bool
		replicaStatus bool
		replicas      bool
		want          string
	}{
		{name: "standalone", want: "standalone"},
		{name: "read_only replica", readOnly: true, want: "replica"},
		{name: "super_read_only replica", superReadOnly: true, want: "replica"},
		{name: "replica status", replicaStatus: true, want: "replica"},
		{name: "source with replicas", replicas: true, want: "source"},
		{name: "replica wins over replicas", readOnly: true, replicas: true, want: "replica"},
	}
	for _, tt := range tests {
		got := classifyTopology(tt.readOnly, tt.superReadOnly, tt.replicaStatus, tt.replicas)
		if got != tt.want {
			t.Errorf("%s: classifyTopology(%v,%v,%v,%v) = %q, want %q",
				tt.name, tt.readOnly, tt.superReadOnly, tt.replicaStatus, tt.replicas, got, tt.want)
		}
	}
}

func TestSupportsRoles(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{version: "8.0.36", want: true},
		{version: "8.0.36-0ubuntu0.22.04.1", want: true},
		{version: "8.4.0", want: true},
		{version: "9.0.1", want: true},
		{version: "5.7.44", want: false},
		{version: "5.6.51", want: false},
		{version: "10.11.2-MariaDB-1:10.11.2+maria~ubu2204", want: false},
		{version: "8.0.32-MariaDB", want: false},
		{version: "", want: false},
		{version: "garbage", want: false},
	}
	for _, tt := range tests {
		if got := supportsRoles(tt.version); got != tt.want {
			t.Errorf("supportsRoles(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestTableTypeToKind(t *testing.T) {
	tests := []struct {
		tableType string
		want      string
		ok        bool
	}{
		{tableType: "BASE TABLE", want: "table", ok: true},
		{tableType: "VIEW", want: "view", ok: true},
		{tableType: "base table", want: "table", ok: true},
		{tableType: "SYSTEM VIEW", ok: false},
		{tableType: "", ok: false},
	}
	for _, tt := range tests {
		got, ok := tableTypeToKind(tt.tableType)
		if got != tt.want || ok != tt.ok {
			t.Errorf("tableTypeToKind(%q) = (%q, %v), want (%q, %v)", tt.tableType, got, ok, tt.want, tt.ok)
		}
	}
}

func TestExternalIDs(t *testing.T) {
	if got := databaseExternalID("appdb"); got != "db:appdb" {
		t.Errorf("databaseExternalID = %q, want db:appdb", got)
	}
	if got := relationExternalID("table", "appdb", "events"); got != "table:appdb.events" {
		t.Errorf("relationExternalID(table) = %q, want table:appdb.events", got)
	}
	if got := relationExternalID("view", "appdb", "recent"); got != "view:appdb.recent" {
		t.Errorf("relationExternalID(view) = %q, want view:appdb.recent", got)
	}
	if got := indexExternalID("appdb", "events", "events_created_at_idx"); got != "index:appdb.events.events_created_at_idx" {
		t.Errorf("indexExternalID = %q, want index:appdb.events.events_created_at_idx", got)
	}
	if got := rolePermissionID("app_ro", "%"); got != "role:app_ro@%" {
		t.Errorf("rolePermissionID = %q, want role:app_ro@%%", got)
	}
}

func TestRolePermissionIdentity(t *testing.T) {
	if got := rolePermissionIdentity("role:app_ro@%"); got != "app_ro@%" {
		t.Errorf("rolePermissionIdentity(role:app_ro@%%) = %q, want app_ro@%%", got)
	}
	// Строка без префикса возвращается как есть (parseUserHost затем ругнётся).
	if got := rolePermissionIdentity("app_ro@%"); got != "app_ro@%" {
		t.Errorf("rolePermissionIdentity(app_ro@%%) = %q, want app_ro@%%", got)
	}
}

// TestNextDefaultRoles фиксирует регрессию: grant обязан добавлять роль в
// набор default roles (иначе при activate_all_roles_on_login=OFF выданная роль
// не активируется на логине), revoke — убирать её, и обе операции обязаны
// сохранять чужие default roles аккаунта, но отбрасывать записи о ролях,
// которые аккаунту уже не выданы.
func TestNextDefaultRoles(t *testing.T) {
	ro := userHost{user: "app_ro", host: "%"}
	rw := userHost{user: "app_rw", host: "%"}
	foreign := userHost{user: "foreign", host: "10.%"}
	stale := userHost{user: "stale", host: "%"}

	tests := []struct {
		name    string
		current []userHost
		granted []userHost
		role    userHost
		include bool
		want    []userHost
	}{
		{
			name:    "grant adds role to empty default set",
			granted: []userHost{ro},
			role:    ro,
			include: true,
			want:    []userHost{ro},
		},
		{
			name:    "grant keeps foreign default roles",
			current: []userHost{foreign},
			granted: []userHost{foreign, ro},
			role:    ro,
			include: true,
			want:    []userHost{ro, foreign},
		},
		{
			name:    "grant drops default roles that are no longer granted",
			current: []userHost{foreign, stale},
			granted: []userHost{foreign, ro},
			role:    ro,
			include: true,
			want:    []userHost{ro, foreign},
		},
		{
			name:    "grant of a role that is not granted yields no default entry",
			current: []userHost{foreign},
			granted: []userHost{foreign},
			role:    ro,
			include: true,
			want:    []userHost{foreign},
		},
		{
			name:    "revoke removes only the target role",
			current: []userHost{ro, rw, foreign},
			granted: []userHost{rw, foreign},
			role:    ro,
			include: false,
			want:    []userHost{rw, foreign},
		},
		{
			name:    "revoke of the only default role yields an empty set",
			current: []userHost{ro},
			granted: nil,
			role:    ro,
			include: false,
			want:    []userHost{},
		},
		{
			name:    "duplicate rows are collapsed",
			current: []userHost{foreign, foreign},
			granted: []userHost{foreign, ro},
			role:    ro,
			include: true,
			want:    []userHost{ro, foreign},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextDefaultRoles(tt.current, tt.granted, tt.role, tt.include)
			if len(got) != len(tt.want) {
				t.Fatalf("nextDefaultRoles = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("nextDefaultRoles = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// TestNextDefaultRolesIsDeterministic проверяет, что порядок результата не
// зависит от порядка строк mysql.default_roles: MySQL его не гарантирует, а
// statement должен быть детерминированным.
func TestNextDefaultRolesIsDeterministic(t *testing.T) {
	a := userHost{user: "a_role", host: "%"}
	b := userHost{user: "b_role", host: "%"}
	c := userHost{user: "b_role", host: "10.%"}
	granted := []userHost{a, b, c}

	first := nextDefaultRoles([]userHost{c, b, a}, granted, a, true)
	second := nextDefaultRoles([]userHost{a, c, b}, granted, a, true)
	// Порядок — (user, host) лексикографически: '%' (0x25) < '1' (0x31).
	want := []userHost{a, b, c} // a_role@%, b_role@%, b_role@10.%
	for i := range want {
		if first[i] != want[i] || second[i] != want[i] {
			t.Fatalf("nextDefaultRoles order = %v / %v, want %v", first, second, want)
		}
	}
}

func TestSetDefaultRoleStatement(t *testing.T) {
	member := userHost{user: "svc_app", host: "%"}
	if got := setDefaultRoleStatement(member, nil); got != "SET DEFAULT ROLE NONE TO 'svc_app'@'%'" {
		t.Errorf("empty set statement = %q", got)
	}
	roles := []userHost{{user: "app_ro", host: "%"}, {user: "o'brien", host: "10.%"}}
	want := `SET DEFAULT ROLE 'app_ro'@'%', 'o\'brien'@'10.%' TO 'svc_app'@'%'`
	if got := setDefaultRoleStatement(member, roles); got != want {
		t.Errorf("statement = %q, want %q", got, want)
	}
}

func TestFingerprint(t *testing.T) {
	attrs := map[string]any{"table_type": "BASE TABLE", "engine": "InnoDB"}
	same := map[string]any{"engine": "InnoDB", "table_type": "BASE TABLE"}

	a := fingerprint("table", "table:appdb.events", attrs)
	b := fingerprint("table", "table:appdb.events", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}

	changed := fingerprint("table", "table:appdb.events", map[string]any{"table_type": "VIEW", "engine": "InnoDB"})
	if changed == a {
		t.Error("fingerprint must change when attributes change")
	}
	if fingerprint("view", "table:appdb.events", attrs) == a {
		t.Error("fingerprint must change when kind changes")
	}
	if fingerprint("table", "table:appdb.other", attrs) == a {
		t.Error("fingerprint must change when external id changes")
	}
	if fingerprint("db", "db:x", nil) != fingerprint("db", "db:x", map[string]any{}) {
		t.Error("nil and empty attributes must produce the same fingerprint")
	}

	// Значение-слайс (columns индекса) должно давать стабильный отпечаток
	// для одинакового содержимого, собранного отдельными инстансами.
	idxA := map[string]any{"unique": false, "columns": []string{"created_at"}}
	idxB := map[string]any{"unique": false, "columns": []string{"created_at"}}
	if fingerprint("index", "index:appdb.events.i", idxA) != fingerprint("index", "index:appdb.events.i", idxB) {
		t.Error("fingerprint with slice attribute must be stable")
	}
}

func TestConnConfig(t *testing.T) {
	cfg := testConnection("disabled")
	cc, err := connConfig(cfg, "appdb")
	if err != nil {
		t.Fatalf("connConfig: %v", err)
	}
	if cc.Addr != "db.example.com:3306" {
		t.Errorf("addr = %q, want db.example.com:3306", cc.Addr)
	}
	if cc.User != "admin" {
		t.Errorf("user = %q, want admin", cc.User)
	}
	if cc.Passwd != "s3cr3t-password" {
		t.Error("passwd field does not match admin credential")
	}
	if cc.DBName != "appdb" {
		t.Errorf("dbname = %q, want appdb", cc.DBName)
	}
	if cc.Net != "tcp" {
		t.Errorf("net = %q, want tcp", cc.Net)
	}
	if cc.TLSConfig != "false" {
		t.Errorf("tls config for disabled mode = %q, want false", cc.TLSConfig)
	}

	t.Run("explicit port", func(t *testing.T) {
		c := testConnection("disabled")
		c.Endpoints = []string{"db.example.com:3307"}
		got, err := connConfig(c, "")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if got.Addr != "db.example.com:3307" {
			t.Errorf("addr = %q, want db.example.com:3307", got.Addr)
		}
	})

	t.Run("no endpoints", func(t *testing.T) {
		c := testConnection("disabled")
		c.Endpoints = nil
		if _, err := connConfig(c, ""); err == nil {
			t.Error("expected error for empty endpoints")
		}
	})

	t.Run("empty username", func(t *testing.T) {
		c := testConnection("disabled")
		c.AdminCredential.Username = ""
		if _, err := connConfig(c, ""); err == nil {
			t.Error("expected error for empty admin username")
		}
	})

	t.Run("tls require registers config", func(t *testing.T) {
		got, err := connConfig(testConnection("require"), "")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if got.TLSConfig == "false" || got.TLSConfig == "" {
			t.Errorf("tls mode require must register a named tls config, got %q", got.TLSConfig)
		}
	})

	t.Run("tls unknown mode", func(t *testing.T) {
		if _, err := connConfig(testConnection("prefer"), ""); err == nil {
			t.Error("expected error for unsupported tls mode")
		}
	})
}

func TestBuildTLSConfig(t *testing.T) {
	t.Run("disabled is nil", func(t *testing.T) {
		conf, err := adapterutil.BuildTLSConfig(adapter.TLSConfig{Mode: "disabled"}, "db.example.com")
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if conf != nil {
			t.Error("disabled mode must produce nil tls config")
		}
	})
	t.Run("require skips verification", func(t *testing.T) {
		conf, err := adapterutil.BuildTLSConfig(adapter.TLSConfig{Mode: "require"}, "db.example.com")
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if conf == nil || !conf.InsecureSkipVerify {
			t.Error("require mode must skip certificate verification")
		}
	})
	t.Run("verify-full sets server name", func(t *testing.T) {
		conf, err := adapterutil.BuildTLSConfig(adapter.TLSConfig{Mode: "verify-full"}, "db.example.com")
		if err != nil {
			t.Fatalf("buildTLSConfig: %v", err)
		}
		if conf == nil || conf.ServerName != "db.example.com" || conf.InsecureSkipVerify {
			t.Errorf("verify-full must verify hostname, got %+v", conf)
		}
	})
	t.Run("invalid ca pem", func(t *testing.T) {
		_, err := adapterutil.BuildTLSConfig(adapter.TLSConfig{Mode: "verify-full", CACertPEM: []byte("not a pem")}, "db.example.com")
		if err == nil {
			t.Error("expected error for invalid CA PEM")
		}
	})
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "db.example.com:3307", host: "db.example.com", port: 3307},
		{endpoint: "db.example.com", host: "db.example.com", port: 3306},
		{endpoint: "[::1]:3306", host: "::1", port: 3306},
		{endpoint: "db.example.com:notaport", wantErr: true},
		{endpoint: "db.example.com:0", wantErr: true},
		{endpoint: "", wantErr: true},
	}
	for _, tt := range tests {
		host, port, err := adapterutil.SplitEndpoint(tt.endpoint, defaultPort)
		if tt.wantErr {
			if err == nil {
				t.Errorf("splitEndpoint(%q): expected error", tt.endpoint)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitEndpoint(%q): %v", tt.endpoint, err)
			continue
		}
		if host != tt.host || port != tt.port {
			t.Errorf("splitEndpoint(%q) = (%q, %d), want (%q, %d)", tt.endpoint, host, port, tt.host, tt.port)
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

func TestManifest(t *testing.T) {
	m := New().Manifest()
	if m.Engine != Engine {
		t.Errorf("engine = %q, want %q", m.Engine, Engine)
	}
	if m.ConnectionSchema != "mysql-connection-v1" {
		t.Errorf("connection schema = %q, want mysql-connection-v1", m.ConnectionSchema)
	}
	for _, c := range []adapter.Capability{
		adapter.CapInventoryResources,
		adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions,
		adapter.CapInventoryBindings,
		adapter.CapAccountCreate,
		adapter.CapAccountDisable,
		adapter.CapAccountEnable,
		adapter.CapAccountDelete,
		adapter.CapCredentialRotate,
		adapter.CapCredentialProve,
		adapter.CapAccountRestore,
		adapter.CapAccessGrant,
		adapter.CapAccessRevoke,
	} {
		if !m.HasCapability(c) {
			t.Errorf("manifest must declare capability %q", c)
		}
	}
	if !adapter.SupportsCredentialProof(New()) {
		t.Error("manifest and implementation must satisfy credential proof guard")
	}
}

func TestProveCredentialRequiresExactMySQLAccountAndPassword(t *testing.T) {
	const supplied = "supplied-secret"
	var calls []adapter.Connection
	a := New()
	a.identityProbe = func(_ context.Context, cfg adapter.Connection) (string, error) {
		copyCfg := cfg
		copyCfg.AdminCredential.Secret = append([]byte(nil), cfg.AdminCredential.Secret...)
		calls = append(calls, copyCfg)
		if len(calls) == 1 {
			return "svc@10.%", nil
		}
		return "", &mysqldriver.MySQLError{Number: 1045, Message: "access denied"}
	}
	err := a.ProveCredential(t.Context(), adapter.Connection{},
		adapter.Account{Kind: "login", EngineIdentity: "svc@10.%"},
		adapter.Credential{Kind: "password", Secret: []byte(supplied)})
	if err != nil {
		t.Fatalf("ProveCredential: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("probe calls = %d, want positive and negative", len(calls))
	}
	for i, call := range calls {
		if call.AdminCredential.Username != "svc" {
			t.Errorf("call %d username = %q, want protocol username svc", i, call.AdminCredential.Username)
		}
	}
	if string(calls[0].AdminCredential.Secret) != supplied {
		t.Error("positive probe did not use supplied password")
	}
	if string(calls[1].AdminCredential.Secret) == supplied || len(calls[1].AdminCredential.Secret) == 0 {
		t.Error("negative probe must use an unrelated non-empty password")
	}
}

func TestProveCredentialMySQLFailsClosed(t *testing.T) {
	account := adapter.Account{Kind: "login", EngineIdentity: "svc@%"}
	credential := adapter.Credential{Kind: "password", Secret: []byte("secret")}

	t.Run("server selected another user@host", func(t *testing.T) {
		a := New()
		a.identityProbe = func(context.Context, adapter.Connection) (string, error) {
			return "svc@localhost", nil
		}
		if err := a.ProveCredential(t.Context(), adapter.Connection{}, account, credential); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
			t.Fatalf("error = %v, want ErrExternalIdentityConflict", err)
		}
	})

	t.Run("supplied password rejected", func(t *testing.T) {
		a := New()
		a.identityProbe = func(context.Context, adapter.Connection) (string, error) {
			return "", &mysqldriver.MySQLError{Number: 1045, Message: "access denied"}
		}
		if err := a.ProveCredential(t.Context(), adapter.Connection{}, account, credential); !errors.Is(err, adapter.ErrExternalIdentityConflict) {
			t.Fatalf("error = %v, want ErrExternalIdentityConflict", err)
		}
	})

	t.Run("authentication bypass accepts random password", func(t *testing.T) {
		a := New()
		a.identityProbe = func(context.Context, adapter.Connection) (string, error) {
			return "svc@%", nil
		}
		if err := a.ProveCredential(t.Context(), adapter.Connection{}, account, credential); !errors.Is(err, adapter.ErrCredentialProofUnsupported) {
			t.Fatalf("error = %v, want ErrCredentialProofUnsupported", err)
		}
	})

	t.Run("negative probe transport failure is ambiguous", func(t *testing.T) {
		calls := 0
		a := New()
		a.identityProbe = func(context.Context, adapter.Connection) (string, error) {
			calls++
			if calls == 1 {
				return "svc@%", nil
			}
			return "", errors.New("transport unavailable")
		}
		if err := a.ProveCredential(t.Context(), adapter.Connection{}, account, credential); !errors.Is(err, adapter.ErrCredentialProofUnsupported) {
			t.Fatalf("error = %v, want ErrCredentialProofUnsupported", err)
		}
	})
}

// TestPlanRejectsInvalidInput проверяет ветки Plan, не требующие подключения
// к БД: неизвестный/неподдерживаемый ChangeKind и пустой EngineIdentity.
func TestPlanRejectsInvalidInput(t *testing.T) {
	ctx := context.Background()
	a := New()

	t.Run("resource.create is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeResourceCreate})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(resource.create): err = %v, want ErrUnsupportedChange", err)
		}
	})
	t.Run("unknown kind is unsupported", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeKind("bogus")})
		if !errors.Is(err, adapter.ErrUnsupportedChange) {
			t.Errorf("Plan(bogus): err = %v, want ErrUnsupportedChange", err)
		}
	})
	t.Run("disable with empty identity", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeAccountDisable})
		if err == nil {
			t.Error("Plan(account.disable) with empty identity: expected error")
		}
	})
	t.Run("delete with empty identity", func(t *testing.T) {
		_, err := a.Plan(ctx, adapter.DesiredChange{Kind: adapter.ChangeAccountDelete})
		if err == nil {
			t.Error("Plan(account.delete) with empty identity: expected error")
		}
	})
	t.Run("enable produces unlock step", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:    adapter.ChangeAccountEnable,
			Account: adapter.Account{EngineIdentity: "svc_app@%"},
		})
		if err != nil {
			t.Fatalf("Plan(account.enable): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepLockAccount {
			t.Fatalf("Plan(account.enable) steps = %+v, want single %q step", plan.Steps, stepLockAccount)
		}
		if plan.Steps[0].Attributes["unlock"] != true {
			t.Errorf("enable step attributes = %v, want unlock=true", plan.Steps[0].Attributes)
		}
		if !strings.Contains(strings.ToLower(plan.Steps[0].Description), "unlock") {
			t.Errorf("enable description = %q, want mention of unlock", plan.Steps[0].Description)
		}
	})
	t.Run("delete warns about grants", func(t *testing.T) {
		plan, err := a.Plan(ctx, adapter.DesiredChange{
			Kind:    adapter.ChangeAccountDelete,
			Account: adapter.Account{EngineIdentity: "svc_app@%"},
		})
		if err != nil {
			t.Fatalf("Plan(account.delete): %v", err)
		}
		if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepDropUser {
			t.Fatalf("Plan(account.delete) steps = %+v, want single %q step", plan.Steps, stepDropUser)
		}
		if !strings.Contains(strings.ToLower(plan.Steps[0].Description), "grant") {
			t.Errorf("delete description = %q, want warning about grants", plan.Steps[0].Description)
		}
	})
}

// TestRotateCredentialValidatesInput фиксирует валидацию аргументов до любых
// попыток подключения к целевой системе.
func TestRotateCredentialValidatesInput(t *testing.T) {
	ctx := context.Background()
	cfg := adapter.Connection{Engine: Engine, Endpoints: []string{"localhost:3306"}}
	if err := New().RotateCredential(ctx, cfg,
		adapter.Account{Kind: "login"},
		adapter.Credential{Kind: "password", Secret: []byte("x")}); err == nil ||
		!strings.Contains(err.Error(), "engine identity") {
		t.Errorf("RotateCredential without identity: err = %v, want engine identity error", err)
	}
	if err := New().RotateCredential(ctx, cfg,
		adapter.Account{Kind: "login", EngineIdentity: "svc_app@%"},
		adapter.Credential{Kind: "password"}); err == nil ||
		!strings.Contains(err.Error(), "secret is empty") {
		t.Errorf("RotateCredential without secret: err = %v, want secret error", err)
	}
}

func testConnection(tlsMode string) adapter.Connection {
	return adapter.Connection{
		ID:        "conn-test",
		Engine:    Engine,
		Endpoints: []string{"db.example.com"},
		TLS:       adapter.TLSConfig{Mode: tlsMode},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte("s3cr3t-password"),
		},
	}
}

func TestParseGrantStatement(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantOK      bool
		wantScope   string
		wantGrant   bool
		wantPrivs   []string // подмножество, которое обязано присутствовать
		absentPrivs []string
	}{
		{
			name:      "global all privileges with grant option",
			line:      "GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION",
			wantOK:    true,
			wantScope: "*.*",
			wantGrant: true,
			wantPrivs: []string{"ALL PRIVILEGES"},
		},
		{
			name:      "global create user list",
			line:      "GRANT SELECT, INSERT, CREATE USER, DROP ROLE ON *.* TO `admin`@`%` WITH GRANT OPTION",
			wantOK:    true,
			wantScope: "*.*",
			wantGrant: true,
			wantPrivs: []string{"SELECT", "INSERT", "CREATE USER", "DROP ROLE"},
		},
		{
			name:        "database scoped select without grant option",
			line:        "GRANT SELECT ON `appdb`.* TO `reader`@`%`",
			wantOK:      true,
			wantScope:   "`appdb`.*",
			wantGrant:   false,
			wantPrivs:   []string{"SELECT"},
			absentPrivs: []string{"CREATE USER"},
		},
		{
			name:      "usage only global",
			line:      "GRANT USAGE ON *.* TO `reader`@`%`",
			wantOK:    true,
			wantScope: "*.*",
			wantGrant: false,
			wantPrivs: []string{"USAGE"},
		},
		{
			// назначение роли — без части ON, парсер обязан вернуть ok=false.
			name:   "role assignment line",
			line:   "GRANT `app_ro`@`%` TO `svc_app`@`%`",
			wantOK: false,
		},
		{
			name:   "not a grant line",
			line:   "REVOKE SELECT ON *.* FROM `x`@`%`",
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privs, scope, grant, ok := parseGrantStatement(tt.line)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if scope != tt.wantScope {
				t.Errorf("scope = %q, want %q", scope, tt.wantScope)
			}
			if grant != tt.wantGrant {
				t.Errorf("grantOption = %v, want %v", grant, tt.wantGrant)
			}
			for _, p := range tt.wantPrivs {
				if !privs[p] {
					t.Errorf("privileges %v missing %q", privs, p)
				}
			}
			for _, p := range tt.absentPrivs {
				if privs[p] {
					t.Errorf("privileges %v must not contain %q", privs, p)
				}
			}
		})
	}
}

func TestAdminGrantCapabilities(t *testing.T) {
	tests := []struct {
		name           string
		lines          []string
		wantCreateUser bool
		wantGrantOpt   bool
	}{
		{
			name:           "root all privileges",
			lines:          []string{"GRANT ALL PRIVILEGES ON *.* TO `root`@`%` WITH GRANT OPTION"},
			wantCreateUser: true,
			wantGrantOpt:   true,
		},
		{
			name: "explicit create user plus grant option",
			lines: []string{
				"GRANT USAGE ON *.* TO `admin`@`%`",
				"GRANT CREATE USER ON *.* TO `admin`@`%` WITH GRANT OPTION",
			},
			wantCreateUser: true,
			wantGrantOpt:   true,
		},
		{
			name: "read only user",
			lines: []string{
				"GRANT USAGE ON *.* TO `reader`@`%`",
				"GRANT SELECT ON `appdb`.* TO `reader`@`%`",
			},
			wantCreateUser: false,
			wantGrantOpt:   false,
		},
		{
			// CREATE USER на конкретной базе не считается: привилегия должна
			// быть глобальной (в реальности CREATE USER не бывает db-scoped,
			// но парсер обязан игнорировать любые не-*.* строки).
			name: "create user not global is ignored",
			lines: []string{
				"GRANT CREATE USER ON `appdb`.* TO `x`@`%` WITH GRANT OPTION",
			},
			wantCreateUser: false,
			wantGrantOpt:   false,
		},
		{
			// ALL PRIVILEGES без grant option: создавать может, grant/revoke — нет.
			name:           "all privileges without grant option",
			lines:          []string{"GRANT ALL PRIVILEGES ON *.* TO `svc`@`%`"},
			wantCreateUser: true,
			wantGrantOpt:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := adminGrantCapabilities(tt.lines)
			if g.canCreateUser != tt.wantCreateUser {
				t.Errorf("canCreateUser = %v, want %v", g.canCreateUser, tt.wantCreateUser)
			}
			if g.hasGrantOption != tt.wantGrantOpt {
				t.Errorf("hasGrantOption = %v, want %v", g.hasGrantOption, tt.wantGrantOpt)
			}
		})
	}
}

func TestMissingMySQLPrivileges(t *testing.T) {
	tests := []struct {
		name string
		g    adminGrants
		want string
	}{
		{name: "both missing", g: adminGrants{}, want: "the global CREATE USER privilege and GRANT OPTION"},
		{name: "create user missing", g: adminGrants{hasGrantOption: true}, want: "the global CREATE USER privilege"},
		{name: "grant option missing", g: adminGrants{canCreateUser: true}, want: "the global GRANT OPTION"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := missingMySQLPrivileges(tt.g); got != tt.want {
				t.Errorf("missingMySQLPrivileges() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestIsAuthenticationFailure фиксирует классификацию отказов MySQL: identity
// conflict допустим только для настоящего отказа аутентификации, а отказ
// доступа к базе, блокировка учётки и транспортные ошибки обязаны остаться
// unavailable/ambiguous.
func TestIsAuthenticationFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "access denied",
			err:  &mysqldriver.MySQLError{Number: erAccessDenied},
			want: true,
		},
		{
			name: "access denied without password",
			err:  &mysqldriver.MySQLError{Number: erAccessDeniedNoPassword},
			want: true,
		},
		{
			name: "wrapped access denied",
			err:  fmt.Errorf("connect to %q: %w", "db:3306", &mysqldriver.MySQLError{Number: erAccessDenied}),
			want: true,
		},
		{
			name: "database access denied is authorisation, not authentication",
			err:  &mysqldriver.MySQLError{Number: 1044},
			want: false,
		},
		{
			name: "account locked",
			err:  &mysqldriver.MySQLError{Number: 3118},
			want: false,
		},
		{name: "transport error", err: errors.New("dial tcp: timeout"), want: false},
		{name: "nil error", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthenticationFailure(tt.err); got != tt.want {
				t.Errorf("isAuthenticationFailure(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestManifestDeclaresRestoreWithProver проверяет обязательное условие
// ADR-0016: CapAccountRestore может объявлять только adapter, реализующий
// CredentialProver.
func TestManifestDeclaresRestoreWithProver(t *testing.T) {
	ad := New()
	if !ad.Manifest().HasCapability(adapter.CapAccountRestore) {
		t.Fatal("manifest must declare account.restore")
	}
	if _, ok := any(ad).(adapter.CredentialProver); !ok {
		t.Error("adapter declares account.restore without CredentialProver")
	}
}

// TestPlanAccountRestoreRejectsInvalidInput — restore обязан требовать
// разбираемую identity user@host и непустой credential ещё до обращения к
// целевой системе.
func TestPlanAccountRestoreRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		change  adapter.DesiredChange
		wantMsg string
	}{
		{
			name: "identity without host",
			change: adapter.DesiredChange{
				Kind:       adapter.ChangeAccountRestore,
				Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
				Credential: &adapter.Credential{Kind: "password", Secret: []byte("pwd")},
			},
			wantMsg: "user@host",
		},
		{
			name: "missing credential",
			change: adapter.DesiredChange{
				Kind:    adapter.ChangeAccountRestore,
				Account: adapter.Account{Kind: "login", EngineIdentity: "svc@%"},
			},
			wantMsg: "credential",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New().Plan(t.Context(), tt.change)
			if err == nil {
				t.Fatal("Plan: err = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}

// Роль MySQL 8 живёт в mysql.user и отличается от учётной записи только
// тройкой признаков, которые ставит CREATE ROLE. Пока адаптер отдавал роли
// как login-аккаунты, оператор мог принять роль под управление и «включить»
// её: ACCOUNT UNLOCK превращал роль в живую учётку без пароля с хостом `%`.
func TestIsRoleRow(t *testing.T) {
	cases := []struct {
		name      string
		locked    string
		expired   string
		emptyAuth bool
		want      bool
	}{
		{name: "роль после CREATE ROLE", locked: "Y", expired: "Y", emptyAuth: true, want: true},
		{name: "регистр признаков не значим", locked: "y", expired: "y", emptyAuth: true, want: true},
		// Каждый признак по отдельности встречается и у обычных учёток,
		// поэтому ролью считается только полное совпадение тройки.
		{name: "заблокированная учётка с паролем", locked: "Y", expired: "Y", emptyAuth: false},
		{name: "учётка с истёкшим паролем", locked: "N", expired: "Y", emptyAuth: true},
		{name: "беспарольная незаблокированная учётка", locked: "N", expired: "N", emptyAuth: true},
		{name: "обычная учётка", locked: "N", expired: "N", emptyAuth: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRoleRow(tc.locked, tc.expired, tc.emptyAuth); got != tc.want {
				t.Errorf("isRoleRow(%q, %q, %v) = %v, want %v",
					tc.locked, tc.expired, tc.emptyAuth, got, tc.want)
			}
		})
	}
}
