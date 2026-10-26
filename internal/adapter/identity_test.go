package adapter

import (
	"context"
	"strings"
	"testing"
)

// stubAdapter — минимальная заглушка Adapter для проверки диспетчеризации
// FormatEngineIdentity. Методы, которых тест не касается, возвращают нули.
type stubAdapter struct{ suffix string }

func (stubAdapter) Manifest() Manifest { return Manifest{} }
func (stubAdapter) ValidateConnection(context.Context, Connection) error {
	return nil
}
func (stubAdapter) Discover(context.Context, Connection) (*Snapshot, error) { return nil, nil }
func (stubAdapter) Plan(context.Context, DesiredChange) (*Plan, error)      { return nil, nil }
func (stubAdapter) Apply(context.Context, Plan) (*Result, error)            { return nil, nil }
func (stubAdapter) Verify(context.Context, Plan) (*Verification, error)     { return nil, nil }
func (stubAdapter) GenerateCredential(context.Context, CredentialPolicy) (*Credential, error) {
	return nil, nil
}
func (stubAdapter) RotateCredential(context.Context, Connection, Account, Credential) error {
	return nil
}

// formattingAdapter реализует опциональный контракт; plainAdapter — нет.
type formattingAdapter struct{ stubAdapter }

func (a formattingAdapter) FormatEngineIdentity(cfg Connection, base string) (string, error) {
	if strings.Contains(base, "@") {
		return base, nil
	}
	return base + "@" + a.suffix, nil
}

func TestFormatEngineIdentityDispatch(t *testing.T) {
	Register("itest-identity-formatting", func() Adapter {
		return formattingAdapter{stubAdapter{suffix: "host"}}
	})
	Register("itest-identity-plain", func() Adapter { return stubAdapter{} })

	cases := []struct {
		name   string
		engine string
		base   string
		want   string
	}{
		{name: "formatter applied", engine: "itest-identity-formatting", base: "svc", want: "svc@host"},
		{name: "formatter is idempotent", engine: "itest-identity-formatting", base: "svc@other", want: "svc@other"},
		{name: "adapter without formatter passes base through", engine: "itest-identity-plain", base: "svc", want: "svc"},
		// Неизвестный engine — не ошибка вызывающего: поведение остаётся прежним.
		{name: "unregistered engine passes base through", engine: "itest-identity-missing", base: "svc", want: "svc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatEngineIdentity(Connection{Engine: tc.engine}, tc.base)
			if err != nil {
				t.Fatalf("FormatEngineIdentity: %v", err)
			}
			if got != tc.want {
				t.Errorf("FormatEngineIdentity(%q, %q) = %q, want %q", tc.engine, tc.base, got, tc.want)
			}
		})
	}
}

func TestFormatEngineIdentityEmptyBase(t *testing.T) {
	if _, err := FormatEngineIdentity(Connection{Engine: "itest-identity-plain"}, ""); err == nil {
		t.Fatal("FormatEngineIdentity with empty base: err = nil, want error")
	}
}
