package directory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

func TestSearchFilter(t *testing.T) {
	cases := []struct {
		name     string
		template string
		subject  string
		want     string
		wantErr  bool
	}{
		{
			name:     "plain subject",
			template: "(mail=%s)",
			subject:  "alice@grantor.test",
			want:     "(mail=alice@grantor.test)",
		},
		{
			name:     "injection attempt is escaped",
			template: "(mail=%s)",
			subject:  "*)(objectClass=*",
			want:     `(mail=\2a\29\28objectClass=\2a)`,
		},
		{
			name:     "parentheses and backslash are escaped",
			template: "(uid=%s)",
			subject:  `a\b(c)d`,
			want:     `(uid=a\5cb\28c\29d)`,
		},
		{
			name:     "template without placeholder",
			template: "(mail=alice)",
			subject:  "alice@grantor.test",
			wantErr:  true,
		},
		{
			name:     "template with two placeholders",
			template: "(|(mail=%s)(uid=%s))",
			subject:  "alice@grantor.test",
			wantErr:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := searchFilter(tc.template, tc.subject)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("searchFilter(%q, %q) = %q, want error", tc.template, tc.subject, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("searchFilter(%q, %q): %v", tc.template, tc.subject, err)
			}
			if got != tc.want {
				t.Errorf("searchFilter(%q, %q) = %q, want %q", tc.template, tc.subject, got, tc.want)
			}
		})
	}
}

// TestSearchFilterInjectionNeverExpands прогоняет заведомо враждебные
// субъекты: результат не должен содержать неэкранированных скобок или
// звёздочек из subject — фильтр остаётся одним условием равенства.
func TestSearchFilterInjectionNeverExpands(t *testing.T) {
	hostile := []string{
		"*)(userAccountControl=*)",
		"*)(&(objectClass=*)",
		"admin)(|(cn=*)",
		"*",
		"\x00",
	}
	for _, subject := range hostile {
		got, err := searchFilter("(mail=%s)", subject)
		if err != nil {
			t.Fatalf("searchFilter with subject %q: %v", subject, err)
		}
		inner := strings.TrimSuffix(strings.TrimPrefix(got, "(mail="), ")")
		if strings.ContainsAny(inner, "()*\x00") {
			t.Errorf("subject %q produced filter %q with unescaped metacharacters", subject, got)
		}
	}
}

func TestNewLDAPValidation(t *testing.T) {
	valid := LDAPConfig{
		URL:    "ldap://ldap.example.com:389",
		BaseDN: "dc=example,dc=com",
	}

	cases := []struct {
		name    string
		mutate  func(c *LDAPConfig)
		wantErr bool
	}{
		{name: "valid minimal config", mutate: func(c *LDAPConfig) {}},
		{name: "valid ldaps", mutate: func(c *LDAPConfig) { c.URL = "ldaps://ldap.example.com:636" }},
		{name: "empty url", mutate: func(c *LDAPConfig) { c.URL = "" }, wantErr: true},
		{name: "non-ldap scheme", mutate: func(c *LDAPConfig) { c.URL = "http://ldap.example.com" }, wantErr: true},
		{name: "empty base dn", mutate: func(c *LDAPConfig) { c.BaseDN = "" }, wantErr: true},
		{
			name:    "user filter without placeholder",
			mutate:  func(c *LDAPConfig) { c.UserFilter = "(mail=alice)" },
			wantErr: true,
		},
		{
			name:    "syntactically invalid user filter",
			mutate:  func(c *LDAPConfig) { c.UserFilter = "((mail=%s" },
			wantErr: true,
		},
		{
			name:    "syntactically invalid disabled filter",
			mutate:  func(c *LDAPConfig) { c.DisabledFilter = "(((" },
			wantErr: true,
		},
		{
			name:   "ad disabled filter is accepted",
			mutate: func(c *LDAPConfig) { c.DisabledFilter = "(userAccountControl:1.2.840.113556.1.4.803:=2)" },
		},
		{
			name:    "garbage ca pem",
			mutate:  func(c *LDAPConfig) { c.CACertPEM = []byte("not a pem") },
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			p, err := NewLDAP(cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("NewLDAP: expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewLDAP: %v", err)
			}
			if p == nil {
				t.Fatal("NewLDAP returned nil provider without error")
			}
		})
	}
}

// TestNewLDAPDefaultUserFilter: пустой UserFilter получает дефолт
// (mail=%s) — субъект принципала — корпоративный email.
func TestNewLDAPDefaultUserFilter(t *testing.T) {
	p, err := NewLDAP(LDAPConfig{
		URL:          "ldap://ldap.example.com",
		BaseDN:       "dc=example,dc=com",
		BindDN:       "cn=admin,dc=example,dc=com",
		BindPassword: secret.FromString("bind-password"),
	})
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}
	if p.cfg.UserFilter != defaultUserFilter {
		t.Errorf("UserFilter = %q, want default %q", p.cfg.UserFilter, defaultUserFilter)
	}
}

// TestLDAPConfigBindPasswordRedacted: пароль bind в конфигурации — это
// secret.Value, любое текстовое представление конфига его редактирует.
func TestLDAPConfigBindPasswordRedacted(t *testing.T) {
	cfg := LDAPConfig{
		URL:          "ldap://ldap.example.com",
		BaseDN:       "dc=example,dc=com",
		BindPassword: secret.FromString("super-secret-bind"),
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		s := fmt.Sprintf(verb, cfg)
		if strings.Contains(s, "super-secret-bind") {
			t.Errorf("bind password leaked into %s-formatted config: %s", verb, s)
		}
		if !strings.Contains(s, "REDACTED") {
			t.Errorf("%s-formatted config does not show redaction marker: %s", verb, s)
		}
	}
}
