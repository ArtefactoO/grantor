//go:build integration

// Integration-тесты провайдера Authentik против реальной инсталляции.
//
// В отличие от LDAP-теста, каталог здесь не сидируется: инсталляция
// Authentik зеркалит корпоративный AD, и тест не вправе его менять.
// Поэтому субъекты задаются окружением, а сам тест проверяет контракт
// провайдера на том, что в каталоге уже есть.
package directory

import (
	"context"
	"os"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

// authentikTestProvider собирает провайдер из GRANTOR_TEST_AUTHENTIK_* или
// пропускает тест, если инсталляция не задана.
func authentikTestProvider(t *testing.T) *AuthentikProvider {
	t.Helper()
	baseURL := os.Getenv("GRANTOR_TEST_AUTHENTIK_URL")
	token := os.Getenv("GRANTOR_TEST_AUTHENTIK_TOKEN")
	if baseURL == "" || token == "" {
		t.Skip("GRANTOR_TEST_AUTHENTIK_URL/TOKEN are not set; skipping authentik test")
	}
	p, err := NewAuthentik(AuthentikConfig{
		BaseURL: baseURL,
		Token:   secret.FromString(token),
		Group:   os.Getenv("GRANTOR_TEST_AUTHENTIK_GROUP"),
	})
	if err != nil {
		t.Fatalf("NewAuthentik: %v", err)
	}
	return p
}

func TestIntegrationAuthentikStatuses(t *testing.T) {
	p := authentikTestProvider(t)
	ctx := context.Background()

	active := os.Getenv("GRANTOR_TEST_AUTHENTIK_ACTIVE_SUBJECT")
	disabled := os.Getenv("GRANTOR_TEST_AUTHENTIK_DISABLED_SUBJECT")
	if active == "" {
		t.Skip("GRANTOR_TEST_AUTHENTIK_ACTIVE_SUBJECT is not set")
	}
	// Заведомо отсутствующий субъект: проверяет, что каталог отвечает
	// missing, а не ошибкой.
	const missing = "grantor-nonexistent-subject"

	subjects := []string{active, missing}
	if disabled != "" {
		subjects = append(subjects, disabled)
	}

	got, err := p.Statuses(ctx, subjects)
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if got[active] != StatusActive {
		t.Errorf("Statuses[%q] = %q, want %q", active, got[active], StatusActive)
	}
	if got[missing] != StatusMissing {
		t.Errorf("Statuses[%q] = %q, want %q", missing, got[missing], StatusMissing)
	}
	if disabled != "" && got[disabled] != StatusDisabled {
		t.Errorf("Statuses[%q] = %q, want %q", disabled, got[disabled], StatusDisabled)
	}
}

func TestIntegrationAuthentikSearch(t *testing.T) {
	p := authentikTestProvider(t)
	ctx := context.Background()

	entries, err := p.Search(ctx, "", 5)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Search returned no entries; directory is expected to be non-empty")
	}
	if len(entries) > 5 {
		t.Errorf("Search returned %d entries, want limit 5 enforced by the directory", len(entries))
	}
	for _, e := range entries {
		if e.Subject == "" {
			t.Errorf("entry without subject: %+v", e)
		}
		if e.Status != StatusActive && e.Status != StatusDisabled {
			t.Errorf("entry %q has unexpected status %q", e.Subject, e.Status)
		}
	}

	// Поиск по подстроке субъекта обязан находить его же: иначе оператор
	// не сможет завести конкретного человека.
	query := entries[0].Subject
	found, err := p.Search(ctx, query, 10)
	if err != nil {
		t.Fatalf("Search(%q): %v", query, err)
	}
	var hit bool
	for _, e := range found {
		if e.Subject == query {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("Search(%q) did not return the subject itself", query)
	}
}
