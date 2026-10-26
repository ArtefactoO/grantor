package mongodb

import (
	"errors"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

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
	// disable/enable сознательно не объявляются.
	if m.HasCapability(adapter.CapAccountDisable) || m.HasCapability(adapter.CapAccountEnable) {
		t.Error("manifest must not declare account.disable/account.enable")
	}
	for _, want := range []adapter.Capability{
		adapter.CapInventoryResources, adapter.CapInventoryAccounts,
		adapter.CapInventoryPermissions, adapter.CapInventoryBindings,
		adapter.CapAccessGrant, adapter.CapAccessRevoke,
		adapter.CapRolePolicyApply,
		adapter.CapAccountCreate, adapter.CapAccountDelete,
		adapter.CapCredentialProve,
		adapter.CapCredentialRotate,
	} {
		if !m.HasCapability(want) {
			t.Errorf("manifest must declare %q", want)
		}
	}
}

func TestProveCredentialRejectsIdentityMismatchBeforeDial(t *testing.T) {
	err := New().ProveCredential(t.Context(), adapter.Connection{},
		adapter.Account{EngineIdentity: "alice@admin"},
		adapter.Credential{Username: "bob", Secret: []byte("not-a-secret")})
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		t.Fatalf("error = %v, want ErrExternalIdentityConflict", err)
	}
}

func TestParseEngineIdentity(t *testing.T) {
	tests := []struct {
		in      string
		user    string
		authDB  string
		wantErr bool
	}{
		{in: "svc_app@appdb", user: "svc_app", authDB: "appdb"},
		{in: "reader@admin", user: "reader", authDB: "admin"},
		{in: "alice@example.com@$external", user: "alice@example.com", authDB: "$external"},
		{in: "user", wantErr: true},
		{in: "", wantErr: true},
		{in: "@admin", wantErr: true},
		{in: "user@", wantErr: true},
	}
	for _, tt := range tests {
		user, authDB, err := parseEngineIdentity(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseEngineIdentity(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseEngineIdentity(%q): %v", tt.in, err)
			continue
		}
		if user != tt.user || authDB != tt.authDB {
			t.Errorf("parseEngineIdentity(%q) = (%q, %q), want (%q, %q)", tt.in, user, authDB, tt.user, tt.authDB)
		}
	}
}

func TestParseRolePermission(t *testing.T) {
	tests := []struct {
		in      string
		roleDB  string
		role    string
		wantErr bool
	}{
		{in: "role:appdb.readWrite", roleDB: "appdb", role: "readWrite"},
		{in: "role:admin.root", roleDB: "admin", role: "root"},
		{in: "role:appdb.my.custom.role", roleDB: "appdb", role: "my.custom.role"},
		{in: "readWrite", wantErr: true},
		{in: "role:", wantErr: true},
		{in: "role:appdb", wantErr: true},
		{in: "role:.readWrite", wantErr: true},
		{in: "role:appdb.", wantErr: true},
	}
	for _, tt := range tests {
		roleDB, role, err := parseRolePermission(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseRolePermission(%q): expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRolePermission(%q): %v", tt.in, err)
			continue
		}
		if roleDB != tt.roleDB || role != tt.role {
			t.Errorf("parseRolePermission(%q) = (%q, %q), want (%q, %q)", tt.in, roleDB, role, tt.roleDB, tt.role)
		}
	}
}

func TestTopologyFromHello(t *testing.T) {
	t.Run("standalone", func(t *testing.T) {
		topo := topologyFromHello(bson.M{"isWritablePrimary": true})
		if topo["topology"] != "standalone" {
			t.Errorf("topology = %v, want standalone", topo["topology"])
		}
		if _, ok := topo["set_name"]; ok {
			t.Error("standalone must not expose set_name")
		}
		if topo["writable_primary"] != true {
			t.Errorf("writable_primary = %v, want true", topo["writable_primary"])
		}
	})

	t.Run("replica set", func(t *testing.T) {
		topo := topologyFromHello(bson.M{
			"setName": "rs0",
			"hosts":   bson.A{"h1:27017", "h2:27017"},
		})
		if topo["topology"] != "replica_set" {
			t.Errorf("topology = %v, want replica_set", topo["topology"])
		}
		if topo["set_name"] != "rs0" {
			t.Errorf("set_name = %v, want rs0", topo["set_name"])
		}
		hosts, ok := topo["hosts"].([]string)
		if !ok || len(hosts) != 2 || hosts[0] != "h1:27017" {
			t.Errorf("hosts = %v, want [h1:27017 h2:27017]", topo["hosts"])
		}
	})

	t.Run("sharded", func(t *testing.T) {
		// mongos возвращает msg=isdbgrid; setName при этом может быть пустым.
		topo := topologyFromHello(bson.M{"msg": "isdbgrid"})
		if topo["topology"] != "sharded" {
			t.Errorf("topology = %v, want sharded", topo["topology"])
		}
	})

	t.Run("sharded wins over set name", func(t *testing.T) {
		topo := topologyFromHello(bson.M{"msg": "isdbgrid", "setName": "cfg"})
		if topo["topology"] != "sharded" {
			t.Errorf("topology = %v, want sharded", topo["topology"])
		}
	})
}

func TestDangerousRole(t *testing.T) {
	dangerous := []string{
		"root", "dbOwner", "userAdmin", "userAdminAnyDatabase",
		"dbAdminAnyDatabase", "readWriteAnyDatabase", "__system", "clusterAdmin",
	}
	for _, r := range dangerous {
		if !dangerousRole(r) {
			t.Errorf("role %q must be dangerous", r)
		}
	}
	safe := []string{"read", "readWrite", "dbAdmin", "app_reader", ""}
	for _, r := range safe {
		if dangerousRole(r) {
			t.Errorf("role %q must not be dangerous", r)
		}
	}
}

func TestBuildPermissions(t *testing.T) {
	dbSet := map[string]bool{"appdb": true, "admin": true}
	assigned := map[roleRef]bool{
		{Role: "read", DB: "appdb"}:  true,
		{Role: "root", DB: "admin"}:  true,
		{Role: "read", DB: "nodata"}: true, // база вне инвентаря -> scope пустой
	}
	custom := []customRole{
		{
			Role: "app_admin", DB: "appdb", ObservationComplete: true,
			DirectRoles: []roleRef{{Role: "dbOwner", DB: "appdb"}},
			InheritedPrivileges: []rolePrivilege{{
				Resource: roleResource{DB: "appdb"}, Actions: []string{"dropCollection"},
			}},
		},
	}
	perms := buildPermissions(custom, assigned, dbSet)

	byID := map[string]adapter.ObservedPermission{}
	for _, p := range perms {
		byID[p.ExternalID] = p
	}

	read, ok := byID["role:appdb.read"]
	if !ok {
		t.Fatal("permission role:appdb.read not built")
	}
	if read.Dangerous {
		t.Error("role:appdb.read must not be dangerous")
	}
	if read.ScopeExternalID != "db:appdb" {
		t.Errorf("role:appdb.read scope = %q, want db:appdb", read.ScopeExternalID)
	}

	if root, ok := byID["role:admin.root"]; !ok || !root.Dangerous || root.Assignable {
		t.Error("unobserved role:admin.root must be built, dangerous and nonassignable")
	}

	// custom-роль, наследующая dbOwner, опасна.
	if adminRole, ok := byID["role:appdb.app_admin"]; !ok || !adminRole.Dangerous || !adminRole.Assignable {
		t.Error("custom role inheriting dbOwner must be dangerous")
	}

	// назначение на базу вне инвентаря -> пустой scope, но permission есть.
	if p, ok := byID["role:nodata.read"]; !ok || p.ScopeExternalID != "" {
		t.Errorf("role:nodata.read must exist with empty scope, got %+v", p)
	}
}

func TestExternalIDs(t *testing.T) {
	if got := databaseExternalID("appdb"); got != "db:appdb" {
		t.Errorf("databaseExternalID = %q, want db:appdb", got)
	}
	if got := collectionExternalID("appdb", "events"); got != "collection:appdb.events" {
		t.Errorf("collectionExternalID = %q, want collection:appdb.events", got)
	}
	if got := viewExternalID("appdb", "recent_events"); got != "view:appdb.recent_events" {
		t.Errorf("viewExternalID = %q, want view:appdb.recent_events", got)
	}
	if got := indexExternalID("appdb", "events", "created_at_1"); got != "index:appdb.events.created_at_1" {
		t.Errorf("indexExternalID = %q, want index:appdb.events.created_at_1", got)
	}
	if got := rolePermissionID("appdb", "readWrite"); got != "role:appdb.readWrite" {
		t.Errorf("rolePermissionID = %q, want role:appdb.readWrite", got)
	}
	if got := engineIdentity("svc_app", "appdb"); got != "svc_app@appdb" {
		t.Errorf("engineIdentity = %q, want svc_app@appdb", got)
	}
}

func TestFingerprintDeterminism(t *testing.T) {
	// Вложенные документы: порядок ключей map в Go случайный, поэтому
	// fingerprint обязан канонизировать значения (иначе discovery не
	// повторяем).
	attrs := map[string]any{
		"unique": true,
		"keys":   map[string]any{"created_at": int32(1), "user_id": int32(-1)},
	}
	same := map[string]any{
		"keys":   map[string]any{"user_id": int32(-1), "created_at": int32(1)},
		"unique": true,
	}
	a := fingerprint("index", "index:appdb.events.created_at_1", attrs)
	b := fingerprint("index", "index:appdb.events.created_at_1", same)
	if a != b {
		t.Errorf("fingerprints for identical content differ: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("fingerprint length = %d, want 16", len(a))
	}
	if fingerprint("view", "index:appdb.events.created_at_1", attrs) == a {
		t.Error("fingerprint must change when kind changes")
	}
	if fingerprint("index", "index:appdb.events.other", attrs) == a {
		t.Error("fingerprint must change when external id changes")
	}
	changed := fingerprint("index", "index:appdb.events.created_at_1", map[string]any{"unique": false, "keys": attrs["keys"]})
	if changed == a {
		t.Error("fingerprint must change when attributes change")
	}
	if fingerprint("database", "db:x", nil) != fingerprint("database", "db:x", map[string]any{}) {
		t.Error("nil and empty attributes must produce the same fingerprint")
	}
}

func TestNormalizeValue(t *testing.T) {
	oid := primitive.NewObjectID()
	bin := primitive.Binary{Subtype: 4, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
	in := bson.M{
		"nested": bson.D{{Key: "a", Value: int32(1)}},
		"list":   bson.A{"x", bin},
		"oid":    oid,
	}
	out, ok := normalizeValue(in).(map[string]any)
	if !ok {
		t.Fatalf("normalizeValue did not return map[string]any, got %T", normalizeValue(in))
	}
	nested, ok := out["nested"].(map[string]any)
	if !ok || nested["a"] != int32(1) {
		t.Errorf("nested bson.D not normalized to map: %#v", out["nested"])
	}
	list, ok := out["list"].([]any)
	if !ok || len(list) != 2 || list[1] != "deadbeef" {
		t.Errorf("binary in list not normalized to hex: %#v", out["list"])
	}
	if out["oid"] != oid.Hex() {
		t.Errorf("object id not normalized to hex: %v", out["oid"])
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

	// Уникальность: два подряд сгенерированных пароля не должны совпадать.
	other, err := ad.GenerateCredential(t.Context(), adapter.CredentialPolicy{})
	if err != nil {
		t.Fatalf("GenerateCredential: %v", err)
	}
	if string(other.Secret) == string(cred.Secret) {
		t.Error("two generated passwords must differ")
	}
}

func TestPlanUnsupportedChange(t *testing.T) {
	ad := New()
	for _, kind := range []adapter.ChangeKind{
		adapter.ChangeAccountDisable, adapter.ChangeAccountEnable, adapter.ChangeResourceCreate,
	} {
		_, err := ad.Plan(t.Context(), adapter.DesiredChange{
			Kind:    kind,
			Account: adapter.Account{EngineIdentity: "svc_app@appdb"},
		})
		if err == nil {
			t.Errorf("Plan(%s): expected unsupported change error", kind)
		}
	}
}

func TestPlanAccessRedactsSecretAndParses(t *testing.T) {
	ad := New()
	const marker = "s3cr3t-marker"
	change := adapter.DesiredChange{
		Kind:       adapter.ChangeGrant,
		Account:    adapter.Account{Kind: "login", EngineIdentity: "reader@admin"},
		Permission: "role:appdb.read",
		Credential: &adapter.Credential{Kind: "password", Secret: []byte(marker)},
	}
	plan, err := ad.Plan(t.Context(), change)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepGrant {
		t.Fatalf("unexpected plan steps: %+v", plan.Steps)
	}
	step := plan.Steps[0]
	if strings.Contains(step.Description, marker) {
		t.Errorf("plan description leaks secret: %q", step.Description)
	}
	if step.Attributes["role"] != "read" || step.Attributes["role_db"] != "appdb" {
		t.Errorf("plan attributes = %v, want role=read role_db=appdb", step.Attributes)
	}
	if step.Attributes["user"] != "reader" || step.Attributes["auth_db"] != "admin" {
		t.Errorf("plan attributes = %v, want user=reader auth_db=admin", step.Attributes)
	}
}

func TestSplitEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		host     string
		port     uint16
		wantErr  bool
	}{
		{endpoint: "mongo.example.com:27018", host: "mongo.example.com", port: 27018},
		{endpoint: "mongo.example.com", host: "mongo.example.com", port: defaultPort},
		{endpoint: "[::1]:27017", host: "::1", port: 27017},
		{endpoint: "mongo.example.com:notaport", wantErr: true},
		{endpoint: "mongo.example.com:0", wantErr: true},
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

func TestClientOptionsNoSecretLeak(t *testing.T) {
	cfg := adapter.Connection{
		Engine:    Engine,
		Endpoints: []string{"mongo.example.com"},
		Attributes: map[string]any{
			"auth_source": "admin",
			"replica_set": "rs0",
		},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: "admin",
			Secret:   []byte("s3cr3t-password"),
		},
	}
	opts, err := clientOptions(cfg)
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	if len(opts.Hosts) != 1 || opts.Hosts[0] != "mongo.example.com:27017" {
		t.Errorf("hosts = %v, want [mongo.example.com:27017]", opts.Hosts)
	}
	if opts.Auth == nil || opts.Auth.Username != "admin" || opts.Auth.AuthSource != "admin" {
		t.Errorf("auth = %+v, want username=admin authSource=admin", opts.Auth)
	}
	if opts.ReplicaSet == nil || *opts.ReplicaSet != "rs0" {
		t.Errorf("replica set = %v, want rs0", opts.ReplicaSet)
	}

	// Пустой username — подключение без аутентификации (Mongo без auth):
	// options без Credential, ошибки нет.
	cfg.AdminCredential.Username = ""
	noAuth, err := clientOptions(cfg)
	if err != nil {
		t.Fatalf("clientOptions without username: %v", err)
	}
	if noAuth.Auth != nil {
		t.Errorf("auth = %+v, want nil for empty username", noAuth.Auth)
	}
}
