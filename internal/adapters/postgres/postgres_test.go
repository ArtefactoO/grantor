package postgres

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestRelkindToKind(t *testing.T) {
	tests := []struct {
		relkind string
		want    string
		ok      bool
	}{
		{relkind: "r", want: "table", ok: true},
		{relkind: "p", want: "table", ok: true},
		{relkind: "v", want: "view", ok: true},
		{relkind: "m", want: "materialized_view", ok: true},
		{relkind: "S", want: "sequence", ok: true},
		{relkind: "i", ok: false},
		{relkind: "I", ok: false},
		{relkind: "c", ok: false},
		{relkind: "", ok: false},
	}
	for _, tt := range tests {
		got, ok := relkindToKind(tt.relkind)
		if got != tt.want || ok != tt.ok {
			t.Errorf("relkindToKind(%q) = (%q, %v), want (%q, %v)", tt.relkind, got, ok, tt.want, tt.ok)
		}
	}
}

func TestRandomProbePasswordIsPostgresSafe(t *testing.T) {
	for range 128 {
		password, err := randomProbePassword()
		if err != nil {
			t.Fatalf("randomProbePassword: %v", err)
		}
		if len(password) != 64 {
			t.Fatalf("password length = %d, want 64 hex bytes", len(password))
		}
		for _, b := range password {
			if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
				t.Fatalf("password contains non-hex byte %#x", b)
			}
		}
		clear(password)
	}
}

func TestRoleDangerous(t *testing.T) {
	tests := []struct {
		name string
		role roleInfo
		want bool
	}{
		{name: "plain", role: roleInfo{}, want: false},
		{name: "createdb only", role: roleInfo{createDB: true}, want: false},
		{name: "superuser", role: roleInfo{super: true}, want: true},
		{name: "createrole", role: roleInfo{createRole: true}, want: true},
		{name: "replication", role: roleInfo{replication: true}, want: true},
		{name: "bypassrls", role: roleInfo{bypassRLS: true}, want: true},
		{name: "combined", role: roleInfo{createDB: true, createRole: true}, want: true},
	}
	for _, tt := range tests {
		if got := tt.role.dangerous(); got != tt.want {
			t.Errorf("%s: dangerous() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDiscoveryPublishesPostgresRoleAndDatabaseOwnerIncarnations(t *testing.T) {
	role := roleInfo{oid: 17001, name: "app_owner"}
	if got := role.account(time.Now()).Attributes["role_oid"]; got != uint32(17001) {
		t.Fatalf("role_oid = %#v, want 17001", got)
	}
	resource := databaseResource(databaseInfo{name: "app", owner: "app_owner", oid: 18001, ownerOID: 17001})
	if resource.Attributes["database_oid"] != uint32(18001) ||
		resource.Attributes["owner_oid"] != uint32(17001) || resource.Attributes["owner"] != "app_owner" {
		t.Fatalf("database incarnation attrs = %#v", resource.Attributes)
	}
}

func TestRoleAccount(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	login := roleInfo{name: "svc", canLogin: true, super: true}
	acct := login.account(now)
	if acct.Kind != "login" {
		t.Errorf("login role: Kind = %q, want login", acct.Kind)
	}
	if acct.Disabled {
		t.Error("login role without valid_until must not be disabled")
	}
	if got := acct.Attributes["superuser"]; got != true {
		t.Errorf("login role: superuser attribute = %v, want true", got)
	}

	group := roleInfo{name: "readers"}
	if got := group.account(now).Kind; got != "group" {
		t.Errorf("group role: Kind = %q, want group", got)
	}

	expired := roleInfo{name: "old", canLogin: true, validUntil: &past}
	if !expired.account(now).Disabled {
		t.Error("role with rolvaliduntil in the past must be disabled")
	}

	active := roleInfo{name: "new", canLogin: true, validUntil: &future}
	activeAcct := active.account(now)
	if activeAcct.Disabled {
		t.Error("role with rolvaliduntil in the future must not be disabled")
	}
	if _, ok := activeAcct.Attributes["valid_until"]; !ok {
		t.Error("role with rolvaliduntil must expose valid_until attribute")
	}
}

func TestRolesToObserved(t *testing.T) {
	now := time.Now()
	roles := []roleInfo{
		{name: "gr_svc", canLogin: true},
		{name: "gr_readers"},
		{name: "gr_admin_like", createRole: true},
	}
	accounts, permissions := rolesToObserved(roles, now)
	if len(accounts) != 3 {
		t.Fatalf("len(accounts) = %d, want 3", len(accounts))
	}
	if len(permissions) != 3 {
		t.Fatalf("len(permissions) = %d, want 3 (LOGIN stays observed but not assignable)", len(permissions))
	}
	for _, p := range permissions {
		if p.ExternalID != "role:gr_svc" && !p.Assignable {
			t.Errorf("permission %q must be assignable", p.ExternalID)
		}
		if p.ScopeExternalID != "" {
			t.Errorf("permission %q must be cluster-wide", p.ExternalID)
		}
	}
	if permissions[2].ExternalID != "role:gr_admin_like" || !permissions[2].Dangerous {
		t.Errorf("CREATEROLE permission = %+v, want role:gr_admin_like dangerous", permissions[2])
	}
	if permissions[1].ExternalID != "role:gr_readers" || permissions[1].Dangerous {
		t.Errorf("plain group permission = %+v, want role:gr_readers non-dangerous", permissions[1])
	}
}

func TestLoginPermissionIsPresentWithoutMembership(t *testing.T) {
	_, permissions := rolesToObserved([]roleInfo{{name: "service_predict_nba", canLogin: true}}, time.Now())
	if len(permissions) != 1 || permissions[0].Assignable || permissions[0].Attributes["login_role"] != true {
		t.Fatalf("LOGIN must remain observed and nonassignable: %+v", permissions)
	}
}

func TestMembershipsToObserved(t *testing.T) {
	roles := map[string]roleInfo{
		"gr_group":  {name: "gr_group"},
		"gr_parent": {name: "gr_parent", canLogin: true, createRole: true},
	}
	known := map[string]bool{"role:gr_group": true}
	memberships := []membershipInfo{
		{role: "gr_group", member: "gr_svc", adminOption: true},
		{role: "gr_parent", member: "gr_svc"},
		{role: "gr_parent", member: "gr_other"},
	}

	bindings, extra := membershipsToObserved(memberships, roles, known)
	if len(bindings) != 3 {
		t.Fatalf("len(bindings) = %d, want 3", len(bindings))
	}
	if got := bindings[0]; got.AccountEngineIdentity != "gr_svc" ||
		got.PermissionExternalID != "role:gr_group" ||
		got.Attributes["admin_option"] != true {
		t.Errorf("binding[0] = %+v, want gr_svc -> role:gr_group with admin_option", got)
	}

	// Для LOGIN-родителя должна добираться ровно одна неназначаемая
	// permission, даже если на роль ссылаются несколько bindings.
	if len(extra) != 1 {
		t.Fatalf("len(extra) = %d, want 1", len(extra))
	}
	p := extra[0]
	if p.ExternalID != "role:gr_parent" || p.Assignable {
		t.Errorf("extra permission = %+v, want non-assignable role:gr_parent", p)
	}
	if !p.Dangerous {
		t.Error("extra permission for CREATEROLE login role must be dangerous")
	}
	if p.Attributes["login_role"] != true {
		t.Errorf("extra permission attributes = %v, want login_role=true", p.Attributes)
	}
}

func TestFingerprint(t *testing.T) {
	attrs := map[string]any{"owner": "postgres", "relkind": "r"}
	same := map[string]any{"relkind": "r", "owner": "postgres"}

	a := fingerprint("table", "table:app.public.t", attrs)
	b := fingerprint("table", "table:app.public.t", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}

	changed := fingerprint("table", "table:app.public.t", map[string]any{"owner": "other", "relkind": "r"})
	if changed == a {
		t.Error("fingerprint must change when attributes change")
	}
	otherKind := fingerprint("view", "table:app.public.t", attrs)
	if otherKind == a {
		t.Error("fingerprint must change when kind changes")
	}
	otherID := fingerprint("table", "table:app.public.u", attrs)
	if otherID == a {
		t.Error("fingerprint must change when external id changes")
	}
	if fingerprint("db", "db:x", nil) != fingerprint("db", "db:x", map[string]any{}) {
		t.Error("nil and empty attributes must produce the same fingerprint")
	}
}

func TestExternalIDs(t *testing.T) {
	if got := databaseExternalID("app"); got != "db:app" {
		t.Errorf("databaseExternalID = %q, want db:app", got)
	}
	if got := schemaExternalID("app", "public"); got != "schema:app.public" {
		t.Errorf("schemaExternalID = %q, want schema:app.public", got)
	}
	if got := relationExternalID("table", "app", "public", "t"); got != "table:app.public.t" {
		t.Errorf("relationExternalID = %q, want table:app.public.t", got)
	}
	if got := indexExternalID("app", "public", "t_idx"); got != "index:app.public.t_idx" {
		t.Errorf("indexExternalID = %q, want index:app.public.t_idx", got)
	}
	if got := rolePermissionID("gr_readers"); got != "role:gr_readers" {
		t.Errorf("rolePermissionID = %q, want role:gr_readers", got)
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "db.example.com:6432", host: "db.example.com", port: 6432},
		{endpoint: "db.example.com", host: "db.example.com", port: 5432},
		{endpoint: "[::1]:5433", host: "::1", port: 5433},
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

func TestQuoteDSNValue(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "plain", want: "plain"},
		{in: "with space", want: "'with space'"},
		{in: `a'b\c`, want: `'a\'b\\c'`},
		{in: "", want: "''"},
	}
	for _, tt := range tests {
		if got := quoteDSNValue(tt.in); got != tt.want {
			t.Errorf("quoteDSNValue(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func testConnection(tlsMode string) adapter.Connection {
	return adapter.Connection{
		ID:        "conn-test",
		Engine:    Engine,
		Endpoints: []string{"db.example.com:6432"},
		TLS:       adapter.TLSConfig{Mode: tlsMode},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte("s3cr3t-password"),
		},
	}
}

func TestConnConfig(t *testing.T) {
	t.Run("fields", func(t *testing.T) {
		cc, err := connConfig(testConnection("disabled"), "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if cc.Host != "db.example.com" || cc.Port != 6432 {
			t.Errorf("host:port = %s:%d, want db.example.com:6432", cc.Host, cc.Port)
		}
		if cc.Database != "appdb" {
			t.Errorf("database = %q, want appdb", cc.Database)
		}
		if cc.User != "admin" {
			t.Errorf("user = %q, want admin", cc.User)
		}
		if cc.Password != "s3cr3t-password" {
			t.Error("password field does not match admin credential")
		}
		if cc.TLSConfig != nil {
			t.Error("tls mode disabled must produce nil TLSConfig")
		}
		if cc.ConnectTimeout != adapterutil.DefaultDialTimeout {
			t.Errorf("connect timeout = %v, want %v", cc.ConnectTimeout, adapterutil.DefaultDialTimeout)
		}
	})

	t.Run("password not leaked into conn string", func(t *testing.T) {
		cc, err := connConfig(testConnection("disabled"), "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if strings.Contains(cc.ConnString(), "s3cr3t") {
			t.Errorf("conn string leaks password: %q", cc.ConnString())
		}
	})

	t.Run("default port", func(t *testing.T) {
		cfg := testConnection("disabled")
		cfg.Endpoints = []string{"db.example.com"}
		cc, err := connConfig(cfg, "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if cc.Port != defaultPort {
			t.Errorf("port = %d, want %d", cc.Port, defaultPort)
		}
	})

	t.Run("no endpoints", func(t *testing.T) {
		cfg := testConnection("disabled")
		cfg.Endpoints = nil
		if _, err := connConfig(cfg, "appdb"); err == nil {
			t.Error("expected error for empty endpoints")
		}
	})

	t.Run("empty username", func(t *testing.T) {
		cfg := testConnection("disabled")
		cfg.AdminCredential.Username = ""
		if _, err := connConfig(cfg, "appdb"); err == nil {
			t.Error("expected error for empty admin username")
		}
	})

	t.Run("empty database", func(t *testing.T) {
		if _, err := connConfig(testConnection("disabled"), ""); err == nil {
			t.Error("expected error for empty database name")
		}
	})

	t.Run("tls require", func(t *testing.T) {
		cc, err := connConfig(testConnection("require"), "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if cc.TLSConfig == nil || !cc.TLSConfig.InsecureSkipVerify {
			t.Error("tls mode require must skip certificate verification")
		}
	})

	t.Run("tls verify-ca", func(t *testing.T) {
		cc, err := connConfig(testConnection("verify-ca"), "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if cc.TLSConfig == nil || cc.TLSConfig.VerifyPeerCertificate == nil {
			t.Error("tls mode verify-ca must set custom chain verification")
		}
	})

	t.Run("tls verify-full", func(t *testing.T) {
		cc, err := connConfig(testConnection("verify-full"), "appdb")
		if err != nil {
			t.Fatalf("connConfig: %v", err)
		}
		if cc.TLSConfig == nil {
			t.Fatal("tls mode verify-full must produce TLSConfig")
		}
		if cc.TLSConfig.ServerName != "db.example.com" {
			t.Errorf("server name = %q, want db.example.com", cc.TLSConfig.ServerName)
		}
		if cc.TLSConfig.InsecureSkipVerify {
			t.Error("tls mode verify-full must not skip verification")
		}
	})

	t.Run("tls unknown mode", func(t *testing.T) {
		if _, err := connConfig(testConnection("prefer"), "appdb"); err == nil {
			t.Error("expected error for unsupported tls mode")
		}
	})

	t.Run("tls invalid ca pem", func(t *testing.T) {
		cfg := testConnection("verify-full")
		cfg.TLS.CACertPEM = []byte("not a pem")
		if _, err := connConfig(cfg, "appdb"); err == nil {
			t.Error("expected error for invalid CA PEM")
		}
	})
}

// fakeSSLServer поднимает loopback TCP-listener, читает SSLRequest (8 байт)
// и отвечает reply, если replyValid; иначе закрывает соединение без ответа.
// Возвращает endpoint "host:port".
func fakeSSLServer(t *testing.T, reply byte, replyValid bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		var req [8]byte
		if _, err := io.ReadFull(conn, req[:]); err != nil {
			return
		}
		if replyValid {
			_, _ = conn.Write([]byte{reply})
		}
	}()
	return ln.Addr().String()
}

func TestServerSupportsTLS(t *testing.T) {
	cases := []struct {
		name          string
		reply         byte
		replyValid    bool
		wantSupported bool
		wantOK        bool
	}{
		{"server supports tls", 'S', true, true, true},
		{"server rejects tls", 'N', true, false, true},
		{"unexpected reply -> undetermined", 'X', true, false, false},
		{"no reply -> undetermined", 0, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := fakeSSLServer(t, tc.reply, tc.replyValid)
			supported, ok := serverSupportsTLS(t.Context(), ep)
			if supported != tc.wantSupported || ok != tc.wantOK {
				t.Errorf("serverSupportsTLS = (%v, %v), want (%v, %v)",
					supported, ok, tc.wantSupported, tc.wantOK)
			}
		})
	}

	t.Run("uses adapter dialer", func(t *testing.T) {
		ep := fakeSSLServer(t, 'S', true)
		called := false
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			called = true
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		supported, ok := serverSupportsTLSWithDialer(t.Context(), ep, dial)
		if !supported || !ok {
			t.Fatalf("serverSupportsTLSWithDialer = (%v, %v), want (true, true)", supported, ok)
		}
		if !called {
			t.Fatal("PostgreSQL TLS probe bypassed configured dialer")
		}
	})

	t.Run("unreachable -> undetermined", func(t *testing.T) {
		// Порт 1 на loopback: соединение отклоняется, детект не удаётся.
		if supported, ok := serverSupportsTLS(t.Context(), "127.0.0.1:1"); ok || supported {
			t.Errorf("serverSupportsTLS(unreachable) = (%v, %v), want (false, false)", supported, ok)
		}
	})

	t.Run("invalid endpoint -> undetermined", func(t *testing.T) {
		if supported, ok := serverSupportsTLS(t.Context(), "host:bogus"); ok || supported {
			t.Errorf("serverSupportsTLS(invalid) = (%v, %v), want (false, false)", supported, ok)
		}
	})
}

func TestMaintenanceDatabase(t *testing.T) {
	cfg := testConnection("disabled")
	if got := maintenanceDatabase(cfg); got != "postgres" {
		t.Errorf("default maintenance database = %q, want postgres", got)
	}
	cfg.Attributes = map[string]any{"database": "maintenance"}
	if got := maintenanceDatabase(cfg); got != "maintenance" {
		t.Errorf("maintenance database = %q, want maintenance", got)
	}
	cfg.Attributes = map[string]any{"database": 42}
	if got := maintenanceDatabase(cfg); got != "postgres" {
		t.Errorf("non-string attribute must fall back to postgres, got %q", got)
	}
}
