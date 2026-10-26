//go:build integration

// Integration-тесты LDAP-провайдера против реального OpenLDAP
// (scripts/test-integration.sh): сидированы alice (активная) и carol
// (employeeType=disabled); bob отсутствует в каталоге намеренно.
package directory

import (
	"context"
	"os"
	"testing"

	"github.com/ArtefactoO/grantor/internal/secret"
)

// Сидированные субъекты (см. scripts/test-integration.sh).
const (
	seededActiveSubject   = "alice@grantor.test"
	seededDisabledSubject = "carol@grantor.test"
	seededMissingSubject  = "bob@grantor.test"
	// seededDisabledFilter — атрибут блокировки тестового каталога;
	// в AD его роль играет (userAccountControl:1.2.840.113556.1.4.803:=2).
	seededDisabledFilter = "(employeeType=disabled)"
)

// testProvider собирает LDAP-провайдер из GRANTOR_TEST_LDAP_* или
// пропускает тест, если каталог не поднят.
func testProvider(t *testing.T, disabledFilter string) *LDAPProvider {
	t.Helper()
	url := os.Getenv("GRANTOR_TEST_LDAP_URL")
	if url == "" {
		t.Skip("GRANTOR_TEST_LDAP_URL is not set; skipping ldap test")
	}
	p, err := NewLDAP(LDAPConfig{
		URL:            url,
		BindDN:         os.Getenv("GRANTOR_TEST_LDAP_BIND_DN"),
		BindPassword:   secret.FromString(os.Getenv("GRANTOR_TEST_LDAP_BIND_PASSWORD")),
		BaseDN:         os.Getenv("GRANTOR_TEST_LDAP_BASE_DN"),
		DisabledFilter: disabledFilter,
	})
	if err != nil {
		t.Fatalf("NewLDAP: %v", err)
	}
	return p
}

func TestIntegrationLDAPStatuses(t *testing.T) {
	p := testProvider(t, seededDisabledFilter)
	ctx := context.Background()

	got, err := p.Statuses(ctx, []string{
		seededActiveSubject, seededDisabledSubject, seededMissingSubject,
	})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}

	want := map[string]Status{
		seededActiveSubject:   StatusActive,
		seededDisabledSubject: StatusDisabled,
		seededMissingSubject:  StatusMissing,
	}
	if len(got) != len(want) {
		t.Errorf("Statuses returned %d entries, want %d: %v", len(got), len(want), got)
	}
	for subject, st := range want {
		if got[subject] != st {
			t.Errorf("status[%s] = %q, want %q", subject, got[subject], st)
		}
	}
}

// TestIntegrationLDAPWithoutDisabledFilter: без disabled filter
// существующая запись всегда active — детекция только по отсутствию.
func TestIntegrationLDAPWithoutDisabledFilter(t *testing.T) {
	p := testProvider(t, "")
	ctx := context.Background()

	got, err := p.Statuses(ctx, []string{seededDisabledSubject, seededMissingSubject})
	if err != nil {
		t.Fatalf("Statuses: %v", err)
	}
	if got[seededDisabledSubject] != StatusActive {
		t.Errorf("status[%s] without disabled filter = %q, want %q",
			seededDisabledSubject, got[seededDisabledSubject], StatusActive)
	}
	if got[seededMissingSubject] != StatusMissing {
		t.Errorf("status[%s] = %q, want %q", seededMissingSubject, got[seededMissingSubject], StatusMissing)
	}
}

// TestIntegrationLDAPInjectionSafety: враждебный subject с
// LDAP-метасимволами экранируется и трактуется литералом — он не
// расширяет фильтр до (mail=*) и сообщается как missing, а не как
// найденная запись.
func TestIntegrationLDAPInjectionSafety(t *testing.T) {
	p := testProvider(t, seededDisabledFilter)
	ctx := context.Background()

	hostile := []string{
		"*",
		"*)(objectClass=*",
		"alice@grantor.test)(mail=*",
	}
	got, err := p.Statuses(ctx, hostile)
	if err != nil {
		t.Fatalf("Statuses with hostile subjects: %v", err)
	}
	for _, subject := range hostile {
		if got[subject] != StatusMissing {
			t.Errorf("hostile subject %q reported %q, want %q (escaped literal matches nothing)",
				subject, got[subject], StatusMissing)
		}
	}
}
