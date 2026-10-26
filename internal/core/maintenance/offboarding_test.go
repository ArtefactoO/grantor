package maintenance

import (
	"strings"
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/metrics"
)

func TestExternalIdentityObservation(t *testing.T) {
	cases := []struct {
		name       string
		status     directory.Status
		wantStatus principals.ExternalIdentityStatus
		wantReason string
		wantErr    string
	}{
		{
			name:       "active",
			status:     directory.StatusActive,
			wantStatus: principals.ExternalIdentityActive,
		},
		{
			name:       "disabled",
			status:     directory.StatusDisabled,
			wantStatus: principals.ExternalIdentityDisabled,
			wantReason: metrics.ReasonDirectoryDisabled,
		},
		{
			name:       "missing maps to deleted",
			status:     directory.StatusMissing,
			wantStatus: principals.ExternalIdentityDeleted,
			wantReason: metrics.ReasonDirectoryMissing,
		},
		{
			name:    "unknown fails closed",
			status:  directory.Status("degraded"),
			wantErr: "unsupported directory status",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, reason, err := externalIdentityObservation(tc.status)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("externalIdentityObservation(%q): %v", tc.status, err)
			}
			if status != tc.wantStatus || reason != tc.wantReason {
				t.Errorf("externalIdentityObservation(%q) = (%q, %q), want (%q, %q)",
					tc.status, status, reason, tc.wantStatus, tc.wantReason)
			}
		})
	}
}

func TestOffboardingIncomplete(t *testing.T) {
	cases := []struct {
		name     string
		accounts int
		bindings int
		want     bool
	}{
		{"nothing active", 0, 0, false},
		{"active account", 1, 0, true},
		{"present binding only", 0, 2, true},
		{"both", 3, 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := offboardingIncomplete(tc.accounts, tc.bindings); got != tc.want {
				t.Errorf("offboardingIncomplete(%d, %d) = %v, want %v", tc.accounts, tc.bindings, got, tc.want)
			}
		})
	}
}

// TestStatsIsZeroOffboarding дополняет TestStatsIsZero: счётчики
// offboarding-контура тоже делают прогон непустым.
func TestStatsIsZeroOffboarding(t *testing.T) {
	if (Stats{PrincipalsDisabled: 1}).IsZero() {
		t.Error("Stats{PrincipalsDisabled:1}.IsZero() = true, want false")
	}
	if (Stats{OffboardingIncomplete: 1}).IsZero() {
		t.Error("Stats{OffboardingIncomplete:1}.IsZero() = true, want false")
	}
}
