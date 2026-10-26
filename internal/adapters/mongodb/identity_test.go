package mongodb

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
		{name: "bare name gets default authdb", base: "e2e_global", want: "e2e_global@admin"},
		{
			name:  "configured auth source",
			attrs: map[string]any{"auth_source": "apps"},
			base:  "e2e_global",
			want:  "e2e_global@apps",
		},
		{name: "already user@authdb is untouched", base: "svc@apps", want: "svc@apps"},
		{
			name:  "already user@authdb wins over configured auth source",
			attrs: map[string]any{"auth_source": "apps"},
			base:  "svc@other",
			want:  "svc@other",
		},
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
// вернул форматтер, обязано разбираться parseEngineIdentity — иначе
// account.create упал бы ровно на той проверке, ради которой
// форматирование и вводилось.
func TestFormatEngineIdentityIsParsable(t *testing.T) {
	got, err := New().FormatEngineIdentity(adapter.Connection{Engine: Engine}, "e2e_global")
	if err != nil {
		t.Fatalf("FormatEngineIdentity: %v", err)
	}
	user, authDB, err := parseEngineIdentity(got)
	if err != nil {
		t.Fatalf("parseEngineIdentity(%q): %v", got, err)
	}
	if user != "e2e_global" || authDB != defaultAuthSource {
		t.Errorf("parseEngineIdentity(%q) = (%q, %q), want (e2e_global, %s)", got, user, authDB, defaultAuthSource)
	}
}

func TestFormatEngineIdentityEmptyBase(t *testing.T) {
	if _, err := New().FormatEngineIdentity(adapter.Connection{Engine: Engine}, ""); err == nil {
		t.Fatal("FormatEngineIdentity(\"\"): err = nil, want error")
	}
}
