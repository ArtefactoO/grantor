package mysql

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

func TestFormatEngineIdentity(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		base  string
		want  string
	}{
		{name: "bare name gets default host", base: "e2e_global", want: "e2e_global@%"},
		{
			name:  "configured default host",
			attrs: map[string]any{attrDefaultAccountHost: "10.%"},
			base:  "e2e_global",
			want:  "e2e_global@10.%",
		},
		{name: "already user@host is untouched", base: "svc@localhost", want: "svc@localhost"},
		{
			name:  "already user@host wins over configured host",
			attrs: map[string]any{attrDefaultAccountHost: "10.%"},
			base:  "svc@localhost",
			want:  "svc@localhost",
		},
		{name: "empty host part is preserved", base: "svc@", want: "svc@"},
	}
	a := New()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := a.FormatEngineIdentity(adapter.Connection{Engine: Engine, Attributes: tc.attrs}, tc.base)
			if err != nil {
				t.Fatalf("FormatEngineIdentity(%q): %v", tc.base, err)
			}
			if got != tc.want {
				t.Errorf("FormatEngineIdentity(%q) = %q, want %q", tc.base, got, tc.want)
			}
		})
	}
}

// TestFormatEngineIdentityIsParsable замыкает контракт с мутациями: то, что
// вернул форматтер, обязано разбираться parseUserHost — иначе account.create
// упал бы ровно на той проверке, ради которой форматирование и вводилось.
func TestFormatEngineIdentityIsParsable(t *testing.T) {
	got, err := New().FormatEngineIdentity(adapter.Connection{Engine: Engine}, "e2e_global")
	if err != nil {
		t.Fatalf("FormatEngineIdentity: %v", err)
	}
	uh, err := parseUserHost(got)
	if err != nil {
		t.Fatalf("parseUserHost(%q): %v", got, err)
	}
	if uh.user != "e2e_global" || uh.host != defaultAccountHost {
		t.Errorf("parseUserHost(%q) = %+v, want user=e2e_global host=%s", got, uh, defaultAccountHost)
	}
}

func TestFormatEngineIdentityEmptyBase(t *testing.T) {
	if _, err := New().FormatEngineIdentity(adapter.Connection{Engine: Engine}, ""); err == nil {
		t.Fatal("FormatEngineIdentity(\"\"): err = nil, want error")
	}
}
