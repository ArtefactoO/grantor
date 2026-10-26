package maintenance

import (
	"testing"
	"time"
)

func TestExceedsMaxAge(t *testing.T) {
	cases := []struct {
		name   string
		age    time.Duration
		maxAge time.Duration
		want   bool
	}{
		{"older than threshold", 100 * time.Hour, 90 * time.Hour, true},
		{"younger than threshold", 10 * time.Hour, 90 * time.Hour, false},
		{"exactly at threshold", 90 * time.Hour, 90 * time.Hour, false},
		{"just over threshold", 90*time.Hour + time.Nanosecond, 90 * time.Hour, true},
		{"disabled: zero max age", 100 * time.Hour, 0, false},
		{"disabled: negative max age", 100 * time.Hour, -time.Hour, false},
		{"disabled with zero age", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := exceedsMaxAge(tc.age, tc.maxAge); got != tc.want {
				t.Errorf("exceedsMaxAge(%v, %v) = %v, want %v", tc.age, tc.maxAge, got, tc.want)
			}
		})
	}
}

// TestStatsIsZeroAdminCredentialsAged дополняет TestStatsIsZero: новый счётчик
// старения тоже делает прогон непустым.
func TestStatsIsZeroAdminCredentialsAged(t *testing.T) {
	if (Stats{AdminCredentialsAged: 1}).IsZero() {
		t.Error("Stats{AdminCredentialsAged:1}.IsZero() = true, want false")
	}
	if !(Stats{}).IsZero() {
		t.Error("empty Stats.IsZero() = false, want true")
	}
}

// TestConfigWithDefaultsAdminCredentialMaxAge проверяет, что порог старения
// НЕ получает дефолт (0 = выключено), в отличие от retention/interval.
func TestConfigWithDefaultsAdminCredentialMaxAge(t *testing.T) {
	if got := (Config{}).withDefaults().AdminCredentialMaxAge; got != 0 {
		t.Errorf("AdminCredentialMaxAge default = %v, want 0 (disabled)", got)
	}
	if got := (Config{AdminCredentialMaxAge: 90 * time.Hour}).withDefaults().AdminCredentialMaxAge; got != 90*time.Hour {
		t.Errorf("AdminCredentialMaxAge = %v, want preserved 90h", got)
	}
}
