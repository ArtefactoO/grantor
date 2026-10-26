package api

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

func TestSlugIdentity(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "simple", in: "payments", want: "payments"},
		{name: "spaces and case", in: "Payments Service", want: "payments_service"},
		{name: "email", in: "john.doe@corp.io", want: "john_doe_corp_io"},
		{name: "trim underscores", in: "  Ops!  ", want: "ops"},
		{name: "digits kept", in: "svc42", want: "svc42"},
		{name: "only separators", in: "@@ ##", want: "principal"},
		{name: "empty", in: "", want: "principal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := slugIdentity(tc.in); got != tc.want {
				t.Errorf("slugIdentity(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestAccountIdentityBase(t *testing.T) {
	base := principals.Principal{DisplayName: "Payments Service", ExternalSubject: "sub-123"}

	// Явный override имеет приоритет.
	if got := accountIdentityBase(base, "svc_override"); got != "svc_override" {
		t.Errorf("override identity = %q, want svc_override", got)
	}
	// Без override берётся external subject.
	if got := accountIdentityBase(base, ""); got != "sub-123" {
		t.Errorf("external subject identity = %q, want sub-123", got)
	}
	// Без override и subject — slug display name.
	noSubject := principals.Principal{DisplayName: "Payments Service"}
	if got := accountIdentityBase(noSubject, ""); got != "payments_service" {
		t.Errorf("slug identity = %q, want payments_service", got)
	}
	// Subject с '@' (UPN или email) обрезается до локальной части: у mysql и
	// mongodb '@' разделяет identity и host/authdb, поэтому "ivan@corp.com"
	// иначе создал бы учётку на хосте "corp.com".
	upn := principals.Principal{DisplayName: "Ivan", ExternalSubject: "ivan@corp.com"}
	if got := accountIdentityBase(upn, ""); got != "ivan" {
		t.Errorf("upn identity = %q, want ivan", got)
	}
	// Явный override остаётся нетронутым: там оператор пишет engine identity
	// сам и знает форму движка.
	if got := accountIdentityBase(upn, "svc@10.0.0.%"); got != "svc@10.0.0.%" {
		t.Errorf("override with host = %q, want svc@10.0.0.%%", got)
	}
	// Subject без локальной части осмысленного имени не даёт — берётся slug.
	weird := principals.Principal{DisplayName: "Ivan", ExternalSubject: "@corp.com"}
	if got := accountIdentityBase(weird, ""); got != "ivan" {
		t.Errorf("subject without local part = %q, want ivan", got)
	}
}

// TestAccountIdentityUnregisteredEngine фиксирует безопасный fallback:
// движок, adapter которого в этом процессе не зарегистрирован, оставляет
// базовое имя без изменений (прежнее поведение). Engine-специфичное
// оформление покрыто в самих adapters (mysql/mongodb identity_test.go) и
// end-to-end в integration-тестах, где adapters зарегистрированы.
func TestAccountIdentityUnregisteredEngine(t *testing.T) {
	p := principals.Principal{DisplayName: "E2E Global"}
	conn := connections.Connection{ID: uuid.New(), Engine: "engine-that-is-not-registered"}
	got, err := accountIdentity(conn, p, "")
	if err != nil {
		t.Fatalf("accountIdentity: %v", err)
	}
	if got != "e2e_global" {
		t.Errorf("accountIdentity = %q, want e2e_global", got)
	}
}

func TestEnvironmentOf(t *testing.T) {
	if got := environmentOf(connections.Connection{Environment: "prod"}); got != "prod" {
		t.Errorf("environmentOf(prod) = %q, want prod", got)
	}
	if got := environmentOf(connections.Connection{}); got != defaultEnvironment {
		t.Errorf("environmentOf(empty) = %q, want %q", got, defaultEnvironment)
	}
}

func TestPrincipalAccessRequestValidate(t *testing.T) {
	valid := principalAccessRequest{Items: []principalAccessItem{
		{ConnectionID: uuid.New(), PermissionID: uuid.New()},
	}}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid request: unexpected error: %v", err)
	}

	if err := (&principalAccessRequest{}).validate(); err == nil {
		t.Error("empty items: err = nil, want error")
	}

	tooMany := principalAccessRequest{Items: make([]principalAccessItem, maxBulkItems+1)}
	for i := range tooMany.Items {
		tooMany.Items[i] = principalAccessItem{ConnectionID: uuid.New(), PermissionID: uuid.New()}
	}
	if err := tooMany.validate(); err == nil {
		t.Error("too many items: err = nil, want error")
	}

	missing := principalAccessRequest{Items: []principalAccessItem{
		{ConnectionID: uuid.New(), PermissionID: uuid.New()},
		{ConnectionID: uuid.New()},
	}}
	err := missing.validate()
	if err == nil {
		t.Fatal("missing permission_id: err = nil, want error")
	}
	if !strings.Contains(err.Error(), "items[1]") {
		t.Errorf("error %q does not point to failing item", err)
	}

	// Срок в прошлом бессмыслен: maintenance отозвал бы доступ раньше, чем
	// worker его выдал.
	past := time.Now().Add(-time.Hour)
	expired := principalAccessRequest{
		Items:     []principalAccessItem{{ConnectionID: uuid.New(), PermissionID: uuid.New()}},
		ExpiresAt: &past,
	}
	if err := expired.validate(); err == nil {
		t.Error("past expires_at: err = nil, want error")
	}
	future := time.Now().Add(time.Hour)
	temporary := principalAccessRequest{
		Items:     []principalAccessItem{{ConnectionID: uuid.New(), PermissionID: uuid.New()}},
		ExpiresAt: &future,
	}
	if err := temporary.validate(); err != nil {
		t.Errorf("future expires_at: unexpected error: %v", err)
	}
}

func TestPrincipalAccessItemValidate(t *testing.T) {
	ok := principalAccessItem{ConnectionID: uuid.New(), PermissionID: uuid.New()}
	if err := ok.validate(); err != nil {
		t.Errorf("valid item: unexpected error: %v", err)
	}
	if err := (&principalAccessItem{PermissionID: uuid.New()}).validate(); err == nil {
		t.Error("missing connection_id: err = nil, want error")
	}
	if err := (&principalAccessItem{ConnectionID: uuid.New()}).validate(); err == nil {
		t.Error("missing permission_id: err = nil, want error")
	}
}
