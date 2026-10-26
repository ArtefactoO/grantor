package clickhouse

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

func TestManifest(t *testing.T) {
	m := New().Manifest()
	if m.Engine != Engine {
		t.Errorf("engine = %q, want %q", m.Engine, Engine)
	}
	if m.Version == "" || m.ConnectionSchema == "" {
		t.Error("manifest must set Version and ConnectionSchema")
	}
	for _, want := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapAccountCreate, adapter.CapAccountDisable,
		adapter.CapAccountEnable, adapter.CapAccountDelete,
		adapter.CapCredentialRotate, adapter.CapCredentialProve,
		adapter.CapAccountRestore,
	} {
		if !m.HasCapability(want) {
			t.Errorf("manifest must declare %q", want)
		}
	}
	if !adapter.SupportsCredentialProof(New()) {
		t.Error("manifest and implementation must satisfy credential proof guard")
	}
	if !slices.Contains(m.ResourceKinds, "database") {
		t.Errorf("manifest must declare database resource kind, got %v", m.ResourceKinds)
	}
}

func TestProveCredentialClickHouseExactIdentityAndNegativeProof(t *testing.T) {
	const supplied = "supplied-secret"
	var users, keys []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		users = append(users, r.Header.Get("X-ClickHouse-User"))
		key := r.Header.Get("X-ClickHouse-Key")
		keys = append(keys, key)
		if key != supplied {
			w.Header().Set("X-ClickHouse-Exception-Code", "516")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "authentication failed")
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"user":"svc"}]}`)
	}))
	defer srv.Close()

	err := New().ProveCredential(t.Context(), clickHouseProofConnection(t, srv.URL),
		adapter.Account{Kind: "login", EngineIdentity: "svc"},
		adapter.Credential{Kind: "password", Secret: []byte(supplied)})
	if err != nil {
		t.Fatalf("ProveCredential: %v", err)
	}
	if !slices.Equal(users, []string{"svc", "svc"}) {
		t.Errorf("probe users = %v, want exact identity twice", users)
	}
	if len(keys) != 2 || keys[0] != supplied || keys[1] == supplied || keys[1] == "" {
		t.Errorf("positive/negative keys were not separated safely")
	}
}

func TestProveCredentialClickHouseFailsClosed(t *testing.T) {
	account := adapter.Account{Kind: "login", EngineIdentity: "svc"}
	credential := adapter.Credential{Kind: "password", Secret: []byte("supplied-secret")}

	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{
			name: "server reports another identity",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"data":[{"user":"default"}]}`)
			},
			want: adapter.ErrExternalIdentityConflict,
		},
		{
			name: "supplied password rejected",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("X-ClickHouse-Exception-Code", "516")
				w.WriteHeader(http.StatusForbidden)
			},
			want: adapter.ErrExternalIdentityConflict,
		},
		{
			name: "authentication bypass accepts random password",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"data":[{"user":"svc"}]}`)
			},
			want: adapter.ErrCredentialProofUnsupported,
		},
		{
			name: "proxy status is not target authentication proof",
			handler: func() http.HandlerFunc {
				calls := 0
				return func(w http.ResponseWriter, _ *http.Request) {
					calls++
					if calls == 1 {
						_, _ = io.WriteString(w, `{"data":[{"user":"svc"}]}`)
						return
					}
					w.WriteHeader(http.StatusUnauthorized)
				}
			}(),
			want: adapter.ErrCredentialProofUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			err := New().ProveCredential(t.Context(), clickHouseProofConnection(t, srv.URL), account, credential)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func clickHouseProofConnection(t *testing.T, rawURL string) adapter.Connection {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return adapter.Connection{
		Engine: Engine, Endpoints: []string{u.Host}, TLS: adapter.TLSConfig{Mode: "disabled"},
	}
}

func TestParsePermission(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "role:app_ro", want: "app_ro"},
		{in: "role:my role", want: "my role"},
		{in: "role:", wantErr: true},
		{in: "priv:SELECT:db:appdb", wantErr: true},
		{in: "priv:ALL", wantErr: true},
		{in: "app_ro", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parsePermission(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parsePermission(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePermission(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parsePermission(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}

	// Прямые privilege-гранты отклоняются как unsupported change.
	_, err := parsePermission("priv:SELECT:db:appdb")
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("parsePermission(priv:...) error = %v, want ErrUnsupportedChange", err)
	}
}

func TestAdminHasAccessManagement(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{
			name:  "all with grant option",
			lines: []string{"GRANT ALL ON *.* TO grantor WITH GRANT OPTION"},
			want:  true,
		},
		{
			name:  "explicit access management",
			lines: []string{"GRANT ACCESS MANAGEMENT ON *.* TO admin2"},
			want:  true,
		},
		{
			name: "access management in a list",
			lines: []string{
				"GRANT SELECT ON appdb.* TO admin2",
				"GRANT SHOW, ACCESS MANAGEMENT ON *.* TO admin2",
			},
			want: true,
		},
		{
			name:  "select only on a database",
			lines: []string{"GRANT SELECT ON appdb.* TO probe"},
			want:  false,
		},
		{
			name:  "all on a database is not global",
			lines: []string{"GRANT ALL ON appdb.* TO probe"},
			want:  false,
		},
		{
			name:  "role assignment line is skipped",
			lines: []string{"GRANT app_ro TO probe"},
			want:  false,
		},
		{
			name:  "select and insert on global scope",
			lines: []string{"GRANT SELECT, INSERT ON *.* TO probe"},
			want:  false,
		},
		{name: "empty", lines: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := adminHasAccessManagement(tt.lines); got != tt.want {
				t.Errorf("adminHasAccessManagement(%v) = %v, want %v", tt.lines, got, tt.want)
			}
		})
	}
}

func TestParseGrantStatement(t *testing.T) {
	privs, scope, grantOption, ok := parseGrantStatement("GRANT SELECT, INSERT ON appdb.* TO svc WITH GRANT OPTION")
	if !ok {
		t.Fatal("expected statement to parse")
	}
	if !privs["SELECT"] || !privs["INSERT"] {
		t.Errorf("privs = %v, want SELECT and INSERT", privs)
	}
	if scope != "appdb.*" {
		t.Errorf("scope = %q, want appdb.*", scope)
	}
	if !grantOption {
		t.Error("grantOption must be true")
	}

	if _, _, _, ok := parseGrantStatement("GRANT app_ro TO svc"); ok {
		t.Error("role assignment without ON must not parse as a privilege grant")
	}
	if _, _, _, ok := parseGrantStatement("REVOKE SELECT ON appdb.* FROM svc"); ok {
		t.Error("non-GRANT statement must not parse")
	}
}

// testDanger — набор опасных привилегий, какой строит loadDangerousPrivileges
// из system.privileges: сами группы плюс развёрнутые в них конкретные типы.
var testDanger = dangerSet{
	"access management":             true,
	"create user":                   true,
	"role admin":                    true,
	"system":                        true,
	"system shutdown":               true,
	"sources":                       true,
	"remote":                        true,
	"introspection":                 true,
	"named collection admin":        true,
	"displaysecretsinshowandselect": true,
	"set definer":                   true,
}

func TestDangerousAccessType(t *testing.T) {
	tests := []struct {
		access string
		global bool
		want   bool
	}{
		{access: "ACCESS MANAGEMENT", global: true, want: true},
		{access: "ACCESS MANAGEMENT", global: false, want: true},
		{access: "ALL", global: true, want: true},
		{access: "ALL PRIVILEGES", global: true, want: true},
		{access: "ALL", global: false, want: false},
		{access: "SELECT", global: true, want: false},
		{access: "SELECT", global: false, want: false},
		{access: "INSERT", global: false, want: false},
		// ClickHouse хранит конкретный тип, а не группу: без разворачивания
		// иерархии эти гранты проходили как безобидные.
		{access: "CREATE USER", global: true, want: true},
		{access: "SYSTEM SHUTDOWN", global: true, want: true},
		{access: "REMOTE", global: true, want: true},
		{access: "displaySecretsInShowAndSelect", global: true, want: true},
	}
	for _, tt := range tests {
		if got := dangerousAccessType(testDanger, tt.access, tt.global); got != tt.want {
			t.Errorf("dangerousAccessType(%q, global=%v) = %v, want %v", tt.access, tt.global, got, tt.want)
		}
	}
}

func TestRoleDangerous(t *testing.T) {
	if roleDangerous([]chGrant{{RoleName: "ro", AccessType: "SELECT", Database: "appdb"}}, testDanger) {
		t.Error("SELECT on a database must not be dangerous")
	}
	if !roleDangerous([]chGrant{{RoleName: "ops", AccessType: "SELECT", Database: "appdb", GrantOption: true}}, testDanger) {
		t.Error("grant option must make the role dangerous")
	}
	if !roleDangerous([]chGrant{{RoleName: "adm", AccessType: "ACCESS MANAGEMENT"}}, testDanger) {
		t.Error("ACCESS MANAGEMENT must make the role dangerous")
	}
	if !roleDangerous([]chGrant{{RoleName: "root", AccessType: "ALL"}}, testDanger) {
		t.Error("global ALL must make the role dangerous")
	}
	if roleDangerous([]chGrant{{RoleName: "x", AccessType: "ALL", Database: "appdb"}}, testDanger) {
		t.Error("ALL scoped to a database must not be dangerous")
	}
	if roleDangerous([]chGrant{{RoleName: "x", AccessType: "ALL", GrantOption: true, PartialRevoke: true}}, testDanger) {
		t.Error("partial revoke rows must be ignored")
	}
}

func TestRolePermission(t *testing.T) {
	own := []chGrant{{RoleName: "app_ro", AccessType: "SELECT", Database: "appdb"}}
	p := rolePermission(chRole{Name: "app_ro", Storage: "local_directory"}, own, own, testDanger)
	if p.ExternalID != "role:app_ro" || p.Name != "app_ro" {
		t.Errorf("permission = %+v, want role:app_ro", p)
	}
	if !p.Assignable || p.Dangerous {
		t.Error("read-only role must be assignable and non-dangerous")
	}
	if p.ScopeExternalID != "" {
		t.Errorf("role scope = %q, want cluster-wide (empty)", p.ScopeExternalID)
	}
	privs, _ := p.Attributes["privileges"].([]string)
	if !slices.Equal(privs, []string{"SELECT ON appdb.*"}) {
		t.Errorf("privileges attribute = %v, want [SELECT ON appdb.*]", privs)
	}
}

func TestBuildPrivilegeGrants(t *testing.T) {
	userSet := map[string]bool{"svc": true, "admin": true}
	dbSet := map[string]bool{"appdb": true}
	grants := []chGrant{
		{UserName: "svc", AccessType: "SELECT", Database: "appdb"},
		{UserName: "admin", AccessType: "ALL", GrantOption: true},
		// Гранты уровня таблицы/колонки, частичные revoke и гранты на
		// системные базы попадают в инвентарь: молча выброшенные, они
		// означали бы доступ, которого grantor не показывает (system.users)
		// либо шире фактического (одна колонка вместо всей таблицы).
		{UserName: "svc", AccessType: "SELECT", Database: "appdb", Table: "events"},
		{UserName: "svc", AccessType: "SELECT", Database: "appdb", Table: "events", Column: "id"},
		{UserName: "svc", AccessType: "SELECT", Database: "system", Table: "users"},
		{UserName: "svc", AccessType: "INSERT", Database: "appdb", PartialRevoke: true},
		// Дубликат permission от второго пользователя не создаёт второй
		// permission, но создаёт binding.
		{UserName: "admin", AccessType: "SELECT", Database: "appdb"},
	}
	perms, bindings := buildPrivilegeGrants(grants, userSet, dbSet, testDanger)

	byID := map[string]adapter.ObservedPermission{}
	for _, p := range perms {
		byID[p.ExternalID] = p
	}
	if len(perms) != 6 {
		t.Fatalf("permission count = %d (%v), want 6", len(perms), perms)
	}
	// Грант на системную базу виден, но без scope: система не в инвентаре.
	sysGrant, ok := byID["priv:SELECT:db:system:table:users"]
	if !ok {
		t.Fatal("grant on a system table must be visible")
	}
	if sysGrant.ScopeExternalID != "" {
		t.Errorf("system grant scope = %q, want empty", sysGrant.ScopeExternalID)
	}
	// Частичный revoke сужает доступ и опасным быть не может.
	revoke, ok := byID["priv:INSERT:db:appdb:revoke"]
	if !ok {
		t.Fatal("partial revoke must be visible")
	}
	if revoke.Dangerous || revoke.Attributes["partial_revoke"] != true {
		t.Errorf("partial revoke permission = %+v", revoke)
	}
	sel, ok := byID["priv:SELECT:db:appdb"]
	if !ok {
		t.Fatal("priv:SELECT:db:appdb must exist")
	}
	if sel.Assignable {
		t.Error("direct privilege grant must not be assignable")
	}
	if sel.Dangerous {
		t.Error("SELECT on a database must not be dangerous")
	}
	if sel.ScopeExternalID != "db:appdb" {
		t.Errorf("scope = %q, want db:appdb", sel.ScopeExternalID)
	}
	all, ok := byID["priv:ALL"]
	if !ok {
		t.Fatal("priv:ALL must exist")
	}
	if !all.Dangerous {
		t.Error("global ALL must be dangerous")
	}
	if all.ScopeExternalID != "" {
		t.Errorf("global grant scope = %q, want empty", all.ScopeExternalID)
	}

	if len(bindings) != 7 {
		t.Fatalf("binding count = %d (%v), want 7", len(bindings), bindings)
	}
	foundAdminAll := false
	for _, b := range bindings {
		if b.AccountEngineIdentity == "admin" && b.PermissionExternalID == "priv:ALL" {
			foundAdminAll = true
			if b.Attributes["grant_option"] != true {
				t.Error("admin ALL binding must record grant_option=true")
			}
		}
	}
	if !foundAdminAll {
		t.Error("binding admin -> priv:ALL not found")
	}
}

func TestTopologyFromClusters(t *testing.T) {
	t.Run("standalone single local replica", func(t *testing.T) {
		topo := topologyFromClusters([]chClusterHost{
			{Cluster: "default", HostName: "localhost", Port: 9000, IsLocal: true},
		})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
	})

	t.Run("all-local demo cluster", func(t *testing.T) {
		topo := topologyFromClusters([]chClusterHost{
			{Cluster: "test_shard_localhost", HostName: "localhost", Port: 9000, IsLocal: true},
			{Cluster: "test_two_shards", HostName: "localhost", Port: 9000, IsLocal: true},
			{Cluster: "test_two_shards", HostName: "localhost", Port: 9001, IsLocal: true},
		})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone for all-local clusters", topo["topology"])
		}
	})

	t.Run("cluster with remote hosts", func(t *testing.T) {
		topo := topologyFromClusters([]chClusterHost{
			{Cluster: "prod", HostName: "ch1", Port: 9000, IsLocal: true},
			{Cluster: "prod", HostName: "ch2", Port: 9000, IsLocal: false},
			{Cluster: "prod", HostName: "ch3", Port: 9000, IsLocal: false},
			{Cluster: "test_shard_localhost", HostName: "localhost", Port: 9000, IsLocal: true},
		})
		if topo["topology"] != "cluster" {
			t.Fatalf("topology = %v, want cluster", topo["topology"])
		}
		if topo["cluster_name"] != "prod" {
			t.Errorf("cluster_name = %v, want prod", topo["cluster_name"])
		}
		hosts, ok := topo["hosts"].([]string)
		if !ok || !slices.Equal(hosts, []string{"ch1:9000", "ch2:9000", "ch3:9000"}) {
			t.Errorf("hosts = %v, want sorted [ch1:9000 ch2:9000 ch3:9000]", topo["hosts"])
		}
		if topo["host_count"] != 3 {
			t.Errorf("host_count = %v, want 3", topo["host_count"])
		}
	})

	t.Run("remote-only cluster is not participation", func(t *testing.T) {
		topo := topologyFromClusters([]chClusterHost{
			{Cluster: "remote", HostName: "ch2", Port: 9000, IsLocal: false},
			{Cluster: "remote", HostName: "ch3", Port: 9000, IsLocal: false},
		})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone when the server is not a member", topo["topology"])
		}
	})

	t.Run("empty", func(t *testing.T) {
		topo := topologyFromClusters(nil)
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone for empty clusters", topo["topology"])
		}
	})
}

// rowFromJSON разбирает JSON-объект в строку результата FORMAT JSON.
func rowFromJSON(t *testing.T, raw string) map[string]json.RawMessage {
	t.Helper()
	var row map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &row); err != nil {
		t.Fatalf("unmarshal row: %v", err)
	}
	return row
}

func TestParseUserAndDisabledDetection(t *testing.T) {
	t.Run("scalar auth_type, host any", func(t *testing.T) {
		u := parseUser(rowFromJSON(t, `{
			"name":"svc","storage":"local_directory","auth_type":"sha256_password",
			"host_ip":["::/0"],"host_names":[],"host_names_regexp":[],"host_names_like":[]
		}`))
		if u.Name != "svc" || u.Storage != "local_directory" {
			t.Errorf("user = %+v, want svc/local_directory", u)
		}
		if !slices.Equal(u.AuthTypes, []string{"sha256_password"}) {
			t.Errorf("auth types = %v, want [sha256_password]", u.AuthTypes)
		}
		acc := userToObserved(u)
		if acc.Kind != "login" || acc.EngineIdentity != "svc" {
			t.Errorf("account = %+v, want login svc", acc)
		}
		if acc.Disabled {
			t.Error("user with host_ip ::/0 must not be disabled")
		}
	})

	t.Run("array auth_type (24.9+)", func(t *testing.T) {
		u := parseUser(rowFromJSON(t, `{
			"name":"svc","storage":"local_directory","auth_type":["sha256_password","ssh_key"],
			"host_ip":["::/0"],"host_names":[],"host_names_regexp":[],"host_names_like":[]
		}`))
		if !slices.Equal(u.AuthTypes, []string{"sha256_password", "ssh_key"}) {
			t.Errorf("auth types = %v, want both methods", u.AuthTypes)
		}
	})

	t.Run("host none means disabled", func(t *testing.T) {
		u := parseUser(rowFromJSON(t, `{
			"name":"off","storage":"local_directory","auth_type":"sha256_password",
			"host_ip":[],"host_names":[],"host_names_regexp":[],"host_names_like":[]
		}`))
		if !hostNone(u) {
			t.Error("empty host restrictions must be HOST NONE")
		}
		if !userToObserved(u).Disabled {
			t.Error("HOST NONE user must be observed as disabled")
		}
	})

	t.Run("named host restriction is not disabled", func(t *testing.T) {
		u := parseUser(rowFromJSON(t, `{
			"name":"svc","storage":"local_directory","auth_type":"sha256_password",
			"host_ip":[],"host_names":["app.example.com"],"host_names_regexp":[],"host_names_like":[]
		}`))
		if userToObserved(u).Disabled {
			t.Error("user with a host name restriction must not be disabled")
		}
	})
}

func TestRawHelpers(t *testing.T) {
	row := rowFromJSON(t, `{
		"s":"text","null_s":null,"n":5,"quoted_n":"7",
		"b1":1,"b0":0,"bq":"1","bt":true,"arr":["a","b"],"null_arr":null
	}`)
	if got := rawString(row, "s"); got != "text" {
		t.Errorf("rawString = %q, want text", got)
	}
	if got := rawString(row, "null_s"); got != "" {
		t.Errorf("rawString(null) = %q, want empty", got)
	}
	if got := rawString(row, "missing"); got != "" {
		t.Errorf("rawString(missing) = %q, want empty", got)
	}
	if got := rawInt(row, "n"); got != 5 {
		t.Errorf("rawInt = %d, want 5", got)
	}
	if got := rawInt(row, "quoted_n"); got != 7 {
		t.Errorf("rawInt(quoted) = %d, want 7", got)
	}
	for _, key := range []string{"b1", "bq", "bt"} {
		if !rawBool(row, key) {
			t.Errorf("rawBool(%q) = false, want true", key)
		}
	}
	if rawBool(row, "b0") || rawBool(row, "missing") {
		t.Error("rawBool must be false for 0 and missing keys")
	}
	if got := rawStrings(row, "arr"); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("rawStrings = %v, want [a b]", got)
	}
	if got := rawStrings(row, "null_arr"); got != nil {
		t.Errorf("rawStrings(null) = %v, want nil", got)
	}
}

func TestQuoteIdentAndLiteral(t *testing.T) {
	if got := quoteIdent("app_ro"); got != "`app_ro`" {
		t.Errorf("quoteIdent = %q, want `app_ro`", got)
	}
	if got := quoteIdent("we`ird\\name"); got != "`we\\`ird\\\\name`" {
		t.Errorf("quoteIdent escaping = %q", got)
	}

	lit, err := quoteLiteral(`pa'ss\word`)
	if err != nil {
		t.Fatalf("quoteLiteral: %v", err)
	}
	if lit != `'pa\'ss\\word'` {
		t.Errorf("quoteLiteral = %q, want 'pa\\'ss\\\\word'", lit)
	}
	if _, err := quoteLiteral("bad\x00pass"); err == nil {
		t.Error("quoteLiteral must reject NUL bytes")
	}
}

func TestExternalIDs(t *testing.T) {
	if got := databaseExternalID("appdb"); got != "db:appdb" {
		t.Errorf("databaseExternalID = %q, want db:appdb", got)
	}
	if got := rolePermissionID("app_ro"); got != "role:app_ro" {
		t.Errorf("rolePermissionID = %q, want role:app_ro", got)
	}
	for _, tt := range []struct {
		g        chGrant
		wantID   string
		wantName string
	}{
		{chGrant{AccessType: "SELECT", Database: "appdb"}, "priv:SELECT:db:appdb", "SELECT ON appdb.*"},
		{chGrant{AccessType: "ALL"}, "priv:ALL", "ALL ON *.*"},
		// Уровень таблицы и колонки различим по id: иначе узкий грант
		// схлопывался бы с широким и показывал доступ шире фактического.
		{chGrant{AccessType: "SELECT", Database: "appdb", Table: "events"},
			"priv:SELECT:db:appdb:table:events", "SELECT ON appdb.events"},
		{chGrant{AccessType: "SELECT", Database: "appdb", Table: "events", Column: "id"},
			"priv:SELECT:db:appdb:table:events:col:id", "SELECT(id) ON appdb.events"},
		{chGrant{AccessType: "INSERT", Database: "appdb", PartialRevoke: true},
			"priv:INSERT:db:appdb:revoke", "REVOKE INSERT ON appdb.*"},
	} {
		if got := privPermissionID(tt.g); got != tt.wantID {
			t.Errorf("privPermissionID(%+v) = %q, want %q", tt.g, got, tt.wantID)
		}
		if got := privPermissionName(tt.g); got != tt.wantName {
			t.Errorf("privPermissionName(%+v) = %q, want %q", tt.g, got, tt.wantName)
		}
	}
}

func TestFormatGrant(t *testing.T) {
	tests := []struct {
		g    chGrant
		want string
	}{
		{g: chGrant{AccessType: "SELECT", Database: "appdb"}, want: "SELECT ON appdb.*"},
		{g: chGrant{AccessType: "SELECT", Database: "appdb", Table: "events"}, want: "SELECT ON appdb.events"},
		{g: chGrant{AccessType: "SELECT", Database: "appdb", Table: "events", Column: "id"}, want: "SELECT(id) ON appdb.events"},
		{g: chGrant{AccessType: "ALL", GrantOption: true}, want: "ALL ON *.* WITH GRANT OPTION"},
	}
	for _, tt := range tests {
		if got := formatGrant(tt.g); got != tt.want {
			t.Errorf("formatGrant(%+v) = %q, want %q", tt.g, got, tt.want)
		}
	}
}

func TestFingerprintDeterminism(t *testing.T) {
	attrs := map[string]any{"engine": "Atomic", "comment": "app database"}
	same := map[string]any{"comment": "app database", "engine": "Atomic"}
	a := fingerprint("database", "db:appdb", attrs)
	b := fingerprint("database", "db:appdb", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}
	if fingerprint("database", "db:other", attrs) == a {
		t.Error("fingerprint must change when external id changes")
	}
	if fingerprint("database", "db:appdb", map[string]any{"engine": "Lazy"}) == a {
		t.Error("fingerprint must change when attributes change")
	}
	if fingerprint("database", "db:x", nil) != fingerprint("database", "db:x", map[string]any{}) {
		t.Error("nil and empty attributes must produce the same fingerprint")
	}
}

func TestPlanAccessRedactsSecretAndParses(t *testing.T) {
	ad := New()
	const marker = "s3cr3t-marker"
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Permission: "role:app_ro",
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	}
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepGrantRole {
		t.Fatalf("unexpected plan steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	if step.Attributes["user"] != "svc" || step.Attributes["role"] != "app_ro" {
		t.Errorf("plan attributes = %v, want user=svc role=app_ro", step.Attributes)
	}

	revoke := change
	revoke.Kind = adapter.ChangeRevoke
	rplan, err := ad.Plan(t.Context(), revoke)
	if err != nil {
		t.Fatalf("Plan(revoke): %v", err)
	}
	if rplan.Steps[0].Kind != stepRevokeRole {
		t.Errorf("revoke step kind = %q, want %q", rplan.Steps[0].Kind, stepRevokeRole)
	}
}

func TestPlanAccountCreateRequiresPassword(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountCreate,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Error("account.create without password credential must fail")
	}

	// Форма плана проверяется без target: сам Plan обращается к ClickHouse,
	// чтобы отказать в создании поверх существующего пользователя.
	const marker = "s3cr3t-marker"
	plan := accountCreatePlan(adapter.DesiredChange{
		Kind:       adapter.ChangeAccountCreate,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "svc"},
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	})
	step := plan.Steps[0]
	if step.Kind != stepCreateUser || step.Attributes["with_password"] != true {
		t.Errorf("unexpected create step: %+v", step)
	}
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	for k, v := range step.Attributes {
		if strings.Contains(fmt.Sprint(v), marker) {
			t.Errorf("plan attribute %q leaks secret", k)
		}
	}
}

func TestPlanDisableEnable(t *testing.T) {
	acct := adapter.Account{Kind: "login", EngineIdentity: "svc"}

	// Форма плана проверяется без target: сам Plan обращается к ClickHouse,
	// чтобы не потерять сетевые ограничения учётки (см. planDisableEnable).
	dis := disableEnablePlan(adapter.DesiredChange{Kind: adapter.ChangeAccountDisable, Account: acct})
	if dis.Steps[0].Kind != stepDisableUser {
		t.Errorf("disable step kind = %q, want %q", dis.Steps[0].Kind, stepDisableUser)
	}
	if !strings.Contains(dis.Steps[0].Description, "HOST NONE") {
		t.Errorf("disable description = %q, want it to mention HOST NONE", dis.Steps[0].Description)
	}

	en := disableEnablePlan(adapter.DesiredChange{Kind: adapter.ChangeAccountEnable, Account: acct})
	if en.Steps[0].Kind != stepEnableUser {
		t.Errorf("enable step kind = %q, want %q", en.Steps[0].Kind, stepEnableUser)
	}
	if !strings.Contains(en.Steps[0].Description, "HOST ANY") {
		t.Errorf("enable description = %q, want it to mention HOST ANY", en.Steps[0].Description)
	}
}

func TestPlanUnsupportedChange(t *testing.T) {
	ad := New()
	_, err := ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeResourceCreate,
		Account: adapter.Account{EngineIdentity: "svc"},
	})
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("Plan(resource.create) error = %v, want ErrUnsupportedChange", err)
	}

	_, err = ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{EngineIdentity: "svc"},
		Permission: "priv:SELECT:db:appdb",
	})
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("Plan(grant priv:...) error = %v, want ErrUnsupportedChange", err)
	}

	_, err = ad.Plan(t.Context(), adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{EngineIdentity: "svc"},
		Permission: "role:app_ro",
		Scope:      "db:appdb",
	})
	if !errors.Is(err, adapter.ErrUnsupportedChange) {
		t.Errorf("Plan(grant with scope) error = %v, want ErrUnsupportedChange", err)
	}
}

func TestGenerateCredential(t *testing.T) {
	ad := New()
	cred, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if cred.Kind != "password" {
		t.Errorf("kind = %q, want password", cred.Kind)
	}
	if len(cred.Secret) != adapterutil.DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(cred.Secret), adapterutil.DefaultPasswordLength)
	}
	for _, b := range cred.Secret {
		if !strings.ContainsRune(adapterutil.PasswordAlphabet, rune(b)) {
			t.Fatalf("password contains char outside alphabet: %q", string(b))
		}
	}

	custom, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{Length: 12})
	if err != nil {
		t.Fatalf("GenerateCredential(12): %v", err)
	}
	if len(custom.Secret) != 12 {
		t.Errorf("custom length = %d, want 12", len(custom.Secret))
	}

	other, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated passwords must differ")
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "ch.example.com:8123", host: "ch.example.com", port: 8123},
		{endpoint: "ch.example.com", host: "ch.example.com", port: defaultPort},
		{endpoint: "[::1]:8443", host: "::1", port: 8443},
		{endpoint: "ch.example.com:notaport", wantErr: true},
		{endpoint: "ch.example.com:0", wantErr: true},
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

func TestNewClientSchemeAndNoSecretLeak(t *testing.T) {
	const password = "s3cr3t-admin-password"
	cfg := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"ch.example.com:8123"},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte(password),
		},
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	if c.baseURL != "http://ch.example.com:8123" {
		t.Errorf("baseURL = %q, want http://ch.example.com:8123", c.baseURL)
	}
	if c.username != "admin" {
		t.Errorf("username = %q, want admin", c.username)
	}

	// Секрет не должен появляться ни в одном текстовом представлении клиента.
	for _, rendered := range []string{
		fmt.Sprintf("%v", c),
		fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c),
		fmt.Sprintf("%s", c.secret),
		fmt.Sprintf("%v", c.secret),
	} {
		if strings.Contains(rendered, password) {
			t.Errorf("rendered client leaks secret: %q", rendered)
		}
	}
	raw, err := json.Marshal(c.secret)
	if err != nil {
		t.Fatalf("marshal secret: %v", err)
	}
	if strings.Contains(string(raw), password) {
		t.Errorf("marshaled secret leaks value: %s", raw)
	}

	// verify-full переключает scheme на https.
	cfg.TLS = adapter.TLSConfig{Mode: "verify-full"}
	tlsClient, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient(verify-full): %v", err)
	}
	if !strings.HasPrefix(tlsClient.baseURL, "https://") {
		t.Errorf("verify-full baseURL = %q, want https:// prefix", tlsClient.baseURL)
	}
}

// TestSecretStatementErrorRedaction проверяет редактирование ошибок statement
// с секретом: сервер (httptest) цитирует запрос в теле ответа, но текст
// ошибки exec(containsSecret=true) обязан содержать только код исключения —
// без пароля. Для statement без секрета фрагмент тела ответа сохраняется.
func TestSecretStatementErrorRedaction(t *testing.T) {
	const password = "s3cr3t-created-password"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-ClickHouse-Exception-Code", "62")
		w.WriteHeader(http.StatusInternalServerError)
		// ClickHouse цитирует запрос в сообщении об ошибке.
		_, _ = fmt.Fprintf(w, "Code: 62. DB::Exception: Syntax error: failed at position 1: %s", body)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	c, err := newClient(adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{u.Host},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte("admin-secret"),
		},
	})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}

	stmt := "CREATE USER u IDENTIFIED WITH sha256_password BY '" + password + "'"
	err = c.exec(t.Context(), stmt, true)
	if err == nil {
		t.Fatal("exec must fail")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("secret statement error leaks password: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "62") {
		t.Errorf("secret statement error = %q, want it to mention exception code 62", err.Error())
	}

	err = c.exec(t.Context(), "SELECT malformed", false)
	if err == nil {
		t.Fatal("exec must fail")
	}
	if !strings.Contains(err.Error(), "DB::Exception") {
		t.Errorf("non-secret error = %q, want body snippet preserved", err.Error())
	}
}

// TestValidateConnectionInsufficientPrivilege проверяет негативную ветку
// матрицы минимальных привилегий на фейковом сервере: SHOW GRANTS без ACCESS
// MANAGEMENT даёт adapter.InsufficientPrivilegeError, и текст ошибки не
// содержит пароль.
func TestValidateConnectionInsufficientPrivilege(t *testing.T) {
	const password = "probe-password-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "version()") {
			_, _ = fmt.Fprint(w, `{"data":[{"version":"24.8.1.1"}],"rows":1}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"data":[{"GRANTS FOR probe":"GRANT SELECT ON appdb.* TO probe"}],"rows":1}`)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}
	err = New().ValidateConnection(t.Context(), adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{u.Host},
		TLS:       adapter.TLSConfig{Mode: "disabled"},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "probe",
			Secret:   []byte(password),
		},
	})
	if err == nil {
		t.Fatal("ValidateConnection must reject an admin without ACCESS MANAGEMENT")
	}
	var pe *adapter.InsufficientPrivilegeError
	if !errors.As(err, &pe) {
		t.Fatalf("error = %v, want *adapter.InsufficientPrivilegeError", err)
	}
	if !errors.Is(err, adapter.ErrInsufficientAdminPrivilege) {
		t.Error("error must unwrap to ErrInsufficientAdminPrivilege")
	}
	if !strings.Contains(pe.Missing, "ACCESS MANAGEMENT") {
		t.Errorf("missing = %q, want it to mention ACCESS MANAGEMENT", pe.Missing)
	}
	if strings.Contains(err.Error(), password) {
		t.Error("error message leaks the admin password")
	}
}

// TestIsAuthenticationFailure фиксирует классификацию отказов ClickHouse:
// identity conflict допустим только для настоящего отказа аутентификации,
// всё остальное (в том числе отказ авторизации 497 ACCESS_DENIED, транспорт
// и произвольные ошибки) обязано остаться ambiguous/unavailable.
func TestIsAuthenticationFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "authentication failed (modern code)",
			err:  statusError(http.StatusForbidden, "516", []byte("Code: 516. AUTHENTICATION_FAILED")),
			want: true,
		},
		{
			name: "unknown user (historical code)",
			err:  statusError(http.StatusForbidden, "192", nil),
			want: true,
		},
		{
			name: "wrong password (historical code)",
			err:  statusError(http.StatusForbidden, "193", nil),
			want: true,
		},
		{
			name: "forbidden without exception code",
			err:  statusError(http.StatusForbidden, "", nil),
			want: true,
		},
		{
			name: "access denied is authorisation, not authentication",
			err:  statusError(http.StatusForbidden, "497", nil),
			want: false,
		},
		{
			name: "server error",
			err:  statusError(http.StatusInternalServerError, "999", nil),
			want: false,
		},
		{
			name: "redacted statement error keeps the code",
			err:  secretStatementError(http.StatusForbidden, "516"),
			want: true,
		},
		{name: "plain error", err: errors.New("dial tcp: timeout"), want: false},
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

// TestPlanAccountRestoreRequiresCredential — restore без пароля невозможен:
// восстановленный пользователь обязан получить доказуемый credential.
func TestPlanAccountRestoreRequiresCredential(t *testing.T) {
	_, err := New().Plan(t.Context(), adapter.DesiredChange{
		Kind:    adapter.ChangeAccountRestore,
		Account: adapter.Account{Kind: "login", EngineIdentity: "svc"},
	})
	if err == nil {
		t.Fatal("Plan account.restore without credential: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "credential") {
		t.Errorf("error = %q, want it to mention the missing credential", err)
	}
}

// TestEffectiveRoleGrantsExpandsNestedRoles фиксирует, что опасность роли
// считается по действующим правам: обёртка над опасной ролью опасна сама.
// Пока разворачивания не было, такая обёртка проходила гейт как безобидная,
// а её член получал управление доступом через унаследованный грант.
func TestEffectiveRoleGrantsExpandsNestedRoles(t *testing.T) {
	own := map[string][]chGrant{
		"admin_core": {{RoleName: "admin_core", AccessType: "ACCESS MANAGEMENT"}},
		"wrapper":    {{RoleName: "wrapper", AccessType: "SELECT", Database: "appdb"}},
		"deep":       nil,
		"plain":      {{RoleName: "plain", AccessType: "SELECT", Database: "appdb"}},
	}
	nested := map[string][]string{
		"wrapper": {"admin_core"},
		"deep":    {"wrapper"},
	}
	effective := effectiveRoleGrants(own, nested)

	if !roleDangerous(effective["wrapper"], testDanger) {
		t.Error("role nesting a dangerous role must be dangerous")
	}
	if !roleDangerous(effective["deep"], testDanger) {
		t.Error("danger must propagate through the whole chain")
	}
	if roleDangerous(effective["plain"], testDanger) {
		t.Error("unrelated role must stay non-dangerous")
	}
	// Собственные привилегии обёртки в атрибутах не подменяются
	// унаследованными: атрибуты описывают определение роли.
	p := rolePermission(chRole{Name: "wrapper"}, own["wrapper"], effective["wrapper"], testDanger)
	privs, _ := p.Attributes["privileges"].([]string)
	if !slices.Equal(privs, []string{"SELECT ON appdb.*"}) {
		t.Errorf("privileges attribute = %v, want only own grants", privs)
	}
	if !p.Dangerous {
		t.Error("wrapper permission must be marked dangerous")
	}
}

// TestEffectiveRoleGrantsTolerantToCycles: обход не должен зацикливаться,
// даже если движок когда-нибудь вернёт цикл в графе ролей.
func TestEffectiveRoleGrantsTolerantToCycles(t *testing.T) {
	own := map[string][]chGrant{
		"a": {{RoleName: "a", AccessType: "SELECT", Database: "appdb"}},
		"b": {{RoleName: "b", AccessType: "ACCESS MANAGEMENT"}},
	}
	nested := map[string][]string{"a": {"b"}, "b": {"a"}}
	effective := effectiveRoleGrants(own, nested)
	if len(effective["a"]) != 2 || len(effective["b"]) != 2 {
		t.Errorf("effective grants = %v, want both roles to see both grants", effective)
	}
}
