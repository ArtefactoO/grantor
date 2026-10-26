package ratelimit

import (
	"testing"
	"time"
)

func TestAnomalyWindowEnabled(t *testing.T) {
	cases := []struct {
		name string
		w    AnomalyWindow
		want bool
	}{
		{"both set", AnomalyWindow{Threshold: 20, Window: time.Hour}, true},
		{"zero threshold", AnomalyWindow{Threshold: 0, Window: time.Hour}, false},
		{"negative threshold", AnomalyWindow{Threshold: -1, Window: time.Hour}, false},
		{"zero window", AnomalyWindow{Threshold: 20, Window: 0}, false},
		{"negative window", AnomalyWindow{Threshold: 20, Window: -time.Hour}, false},
		{"empty", AnomalyWindow{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.w.Enabled(); got != tc.want {
				t.Errorf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRevealAnomalyKey(t *testing.T) {
	got := RevealAnomalyKey("user@grantor.dev")
	// Тот же префикс, что у reveal-ведра лимитера (поверхность reveal/share);
	// таблица окна аномалии отдельная, поэтому коллизии с лимитером нет.
	if want := keyPrefixReveal + "user@grantor.dev"; got != want {
		t.Errorf("RevealAnomalyKey = %q, want %q", got, want)
	}
	// Ключ несёт субъект, но не credential (инвариант раздела 24).
	if got == "" {
		t.Error("RevealAnomalyKey returned empty key")
	}
}
