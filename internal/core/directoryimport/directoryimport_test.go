package directoryimport

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
)

// Маппинг каталога в зеркало — общий для импорта и фонового поллинга;
// missing означает deleted, а не ошибку.
func TestExternalIdentityObservation(t *testing.T) {
	cases := []struct {
		in   directory.Status
		want principals.ExternalIdentityStatus
	}{
		{directory.StatusActive, principals.ExternalIdentityActive},
		{directory.StatusDisabled, principals.ExternalIdentityDisabled},
		{directory.StatusMissing, principals.ExternalIdentityDeleted},
	}
	for _, tc := range cases {
		got, err := ExternalIdentityObservation(tc.in)
		if err != nil {
			t.Fatalf("ExternalIdentityObservation(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("ExternalIdentityObservation(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if _, err := ExternalIdentityObservation(directory.Status("bogus")); err == nil {
		t.Error("ExternalIdentityObservation(bogus): expected error")
	}
}

// ProviderName у выключенного каталога пуст — API по нему решает, блокировать
// ли ручное заведение провайдера.
func TestProviderNameGuards(t *testing.T) {
	var nilService *Service
	if got := nilService.ProviderName(); got != "" {
		t.Errorf("nil service ProviderName = %q, want empty", got)
	}
	if got := New(nil, nil, "authentik").ProviderName(); got != "" {
		t.Errorf("service without provider ProviderName = %q, want empty", got)
	}
	svc := New(nil, directory.NewStatic(nil, nil), "authentik")
	if got := svc.ProviderName(); got != "authentik" {
		t.Errorf("ProviderName = %q, want authentik", got)
	}
}
