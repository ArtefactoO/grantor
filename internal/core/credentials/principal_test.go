package credentials

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPrincipalCredentialsWithoutClients(t *testing.T) {
	s := NewService(nil, nil)
	id := uuid.New()

	if _, _, err := s.EnsurePrincipalCredential(t.Context(), id, "prod", func() ([]byte, error) {
		return []byte("x"), nil
	}); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("EnsurePrincipalCredential error = %v, want ErrVaultNotConfigured", err)
	}
	if _, _, err := s.GetPrincipalCredential(t.Context(), id, "prod"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("GetPrincipalCredential error = %v, want ErrVaultNotConfigured", err)
	}
	if _, err := s.PrincipalCredentialExists(t.Context(), id, "prod"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("PrincipalCredentialExists error = %v, want ErrVaultNotConfigured", err)
	}
	if _, err := s.RotatePrincipalCredential(t.Context(), id, "prod", []byte("x")); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("RotatePrincipalCredential error = %v, want ErrVaultNotConfigured", err)
	}
	if _, _, err := s.GetPasswordByPath(t.Context(), "principals/x/environments/prod/credential"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("GetPasswordByPath error = %v, want ErrVaultNotConfigured", err)
	}
	// Yopass проверяется раньше Vault: без обоих клиентов share честно
	// сообщает про канал доставки.
	if _, err := s.SharePrincipalCredential(t.Context(), id, "Alice", nil, "prod", 0); !errors.Is(err, ErrYopassNotConfigured) {
		t.Errorf("SharePrincipalCredential error = %v, want ErrYopassNotConfigured", err)
	}
	if err := s.DeletePrincipalCredential(t.Context(), id, "prod"); !errors.Is(err, ErrVaultNotConfigured) {
		t.Errorf("DeletePrincipalCredential error = %v, want ErrVaultNotConfigured", err)
	}
}

func TestPrincipalCredentialPathGuard(t *testing.T) {
	// Guard удаления: только пути общих секретов принципалов; чужие
	// префиксы (accounts/, connections/, connectors/) удалять нельзя.
	cases := []struct {
		path string
		want bool
	}{
		{"principals/11111111/environments/prod/credential", true},
		{"accounts/11111111/credential", false},
		{"connections/11111111/admin", false},
		{"connectors/11111111/identity", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := principalCredentialPath(tc.path); got != tc.want {
			t.Errorf("principalCredentialPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	// Длина по умолчанию и алфавит.
	pw, err := GeneratePassword(0)
	if err != nil {
		t.Fatalf("GeneratePassword: %v", err)
	}
	if len(pw) != DefaultPasswordLength {
		t.Errorf("default length = %d, want %d", len(pw), DefaultPasswordLength)
	}
	for _, c := range pw {
		if !strings.ContainsRune(passwordAlphabet, rune(c)) {
			t.Fatalf("password byte %q is outside alphabet", c)
		}
	}

	pw32, err := GeneratePassword(32)
	if err != nil {
		t.Fatalf("GeneratePassword(32): %v", err)
	}
	if len(pw32) != 32 {
		t.Errorf("length = %d, want 32", len(pw32))
	}

	// Два вызова дают разные пароли (криптослучайность).
	other, err := GeneratePassword(32)
	if err != nil {
		t.Fatalf("GeneratePassword(32): %v", err)
	}
	if string(pw32) == string(other) {
		t.Error("two generated passwords are identical")
	}
}

func TestPrincipalShareMessageFormat(t *testing.T) {
	// Сообщение без логина оставляло получателя с паролем, но без имени
	// учётной записи — login обязан присутствовать, когда он известен.
	got := principalShareMessage("Alice Example", []string{"aexample"}, "prod", []byte("p@ss"))
	want := "user: Alice Example\nlogin: aexample\nenvironment: prod\npassword: p@ss"
	if string(got) != want {
		t.Errorf("principalShareMessage = %q, want %q", got, want)
	}

	got = principalShareMessage("Alice Example", []string{"a", "a@%"}, "prod", []byte("p@ss"))
	want = "user: Alice Example\nlogin: a, a@%\nenvironment: prod\npassword: p@ss"
	if string(got) != want {
		t.Errorf("principalShareMessage(multi) = %q, want %q", got, want)
	}

	got = principalShareMessage("Alice Example", nil, "prod", []byte("p@ss"))
	want = "user: Alice Example\nenvironment: prod\npassword: p@ss"
	if string(got) != want {
		t.Errorf("principalShareMessage(no logins) = %q, want %q", got, want)
	}
}
