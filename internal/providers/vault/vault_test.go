package vault

import (
	"testing"
	"time"
)

func TestNewValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"empty config", Config{}},
		{"missing address", Config{Token: "test-token"}},
		{"missing token", Config{Address: "http://127.0.0.1:8200"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.cfg); err == nil {
				t.Errorf("New(%s): expected error", tt.name)
			}
		})
	}
}

func TestConfigWithDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.Mount != DefaultMount {
		t.Errorf("default Mount = %q, want %q", cfg.Mount, DefaultMount)
	}
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("default Timeout = %v, want %v", cfg.Timeout, DefaultTimeout)
	}

	custom := Config{Mount: "kv", Timeout: time.Second}.withDefaults()
	if custom.Mount != "kv" {
		t.Errorf("custom Mount = %q, want kv", custom.Mount)
	}
	if custom.Timeout != time.Second {
		t.Errorf("custom Timeout = %v, want %v", custom.Timeout, time.Second)
	}
}

func TestNewAppliesDefaultMount(t *testing.T) {
	c, err := New(Config{Address: "http://127.0.0.1:8200", Token: "test-token"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Mount() != DefaultMount {
		t.Errorf("Mount() = %q, want %q", c.Mount(), DefaultMount)
	}
}

func TestNewKeepsCustomMount(t *testing.T) {
	c, err := New(Config{Address: "http://127.0.0.1:8200", Token: "test-token", Mount: "kv"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.Mount() != "kv" {
		t.Errorf("Mount() = %q, want kv", c.Mount())
	}
}

func TestPathBuilders(t *testing.T) {
	tests := []struct {
		name string
		fn   func(string) (string, error)
		id   string
		want string
	}{
		{"connection admin", ConnectionAdminPath, "conn-1", "connections/conn-1/admin"},
		{"account credential", AccountCredentialPath, "acc-1", "accounts/acc-1/credential"},
		{"connector identity", ConnectorIdentityPath, "cn-1", "connectors/cn-1/identity"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.fn(tt.id)
			if err != nil {
				t.Fatalf("%s(%q): %v", tt.name, tt.id, err)
			}
			if got != tt.want {
				t.Errorf("%s(%q) = %q, want %q", tt.name, tt.id, got, tt.want)
			}

			if _, err := tt.fn(""); err == nil {
				t.Errorf("%s(empty id): expected error", tt.name)
			}
			if _, err := tt.fn("a/b"); err == nil {
				t.Errorf("%s(id with '/'): expected error", tt.name)
			}
		})
	}
}

func TestPrincipalEnvironmentCredentialPath(t *testing.T) {
	got, err := PrincipalEnvironmentCredentialPath("pr-1", "prod")
	if err != nil {
		t.Fatalf("PrincipalEnvironmentCredentialPath: %v", err)
	}
	if want := "principals/pr-1/environments/prod/credential"; got != want {
		t.Errorf("PrincipalEnvironmentCredentialPath = %q, want %q", got, want)
	}

	// Оба сегмента валидируются: пустые и содержащие '/' значения — ошибка.
	bad := []struct {
		name string
		id   string
		env  string
	}{
		{"empty id", "", "prod"},
		{"empty env", "pr-1", ""},
		{"id with slash", "a/b", "prod"},
		{"env with slash", "pr-1", "pr/od"},
	}
	for _, tt := range bad {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PrincipalEnvironmentCredentialPath(tt.id, tt.env); err == nil {
				t.Errorf("PrincipalEnvironmentCredentialPath(%q, %q): expected error", tt.id, tt.env)
			}
		})
	}
}

func TestConnectionAdminChangeStagePath(t *testing.T) {
	got, err := ConnectionAdminChangeStagePath("conn-1", "op-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "connections/conn-1/admin-changes/op-1" {
		t.Fatalf("stage path = %q", got)
	}
	for _, ids := range [][2]string{{"", "op"}, {"conn", ""}, {"a/b", "op"}, {"conn", "a/b"}} {
		if _, err := ConnectionAdminChangeStagePath(ids[0], ids[1]); err == nil {
			t.Fatalf("stage path accepted invalid ids %q", ids)
		}
	}
}

func TestPrincipalScopedPathPredicates(t *testing.T) {
	shared, err := PrincipalEnvironmentCredentialPath("pr-1", "prod")
	if err != nil {
		t.Fatalf("PrincipalEnvironmentCredentialPath: %v", err)
	}
	own, err := AccountCredentialPath("acc-1")
	if err != nil {
		t.Fatalf("AccountCredentialPath: %v", err)
	}

	tests := []struct {
		name        string
		path        string
		principalID string
		wantScoped  bool
		wantBelongs bool
	}{
		{"shared path of the same principal", shared, "pr-1", true, true},
		{"shared path of another principal", shared, "pr-2", true, false},
		// Префикс без завершающего '/' совпал бы: "pr-1" против "pr-11".
		{"principal id is a prefix of another", "principals/pr-11/environments/prod/credential", "pr-1", true, false},
		{"own account path is not principal scoped", own, "pr-1", false, false},
		{"empty path", "", "pr-1", false, false},
		{"empty principal id owns nothing", shared, "", true, false},
		// Похожий, но чужой корень: принадлежность к принципалу неприменима.
		{"lookalike root", "principalsX/pr-1/credential", "pr-1", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPrincipalScopedPath(tt.path); got != tt.wantScoped {
				t.Errorf("IsPrincipalScopedPath(%q) = %v, want %v", tt.path, got, tt.wantScoped)
			}
			if got := PathBelongsToPrincipal(tt.path, tt.principalID); got != tt.wantBelongs {
				t.Errorf("PathBelongsToPrincipal(%q, %q) = %v, want %v",
					tt.path, tt.principalID, got, tt.wantBelongs)
			}
		})
	}
}

func TestValidateID(t *testing.T) {
	if err := ValidateID("conn-1"); err != nil {
		t.Errorf("ValidateID(conn-1) = %v, want nil", err)
	}
	if err := ValidateID(""); err == nil {
		t.Error("ValidateID(empty): expected error")
	}
	if err := ValidateID("a/b"); err == nil {
		t.Error("ValidateID(a/b): expected error")
	}
	if err := ValidateID("/"); err == nil {
		t.Error("ValidateID(/): expected error")
	}
}
