package maintenance

import (
	"testing"
	"time"
)

func TestConfigWithDefaults(t *testing.T) {
	got := Config{}.withDefaults()
	if got.MissingResourceRetention != defaultMissingResourceRetention {
		t.Errorf("MissingResourceRetention = %v, want %v", got.MissingResourceRetention, defaultMissingResourceRetention)
	}
	if got.OperationRetention != defaultOperationRetention {
		t.Errorf("OperationRetention = %v, want %v", got.OperationRetention, defaultOperationRetention)
	}
	if got.AuditRetention != defaultAuditRetention {
		t.Errorf("AuditRetention = %v, want %v", got.AuditRetention, defaultAuditRetention)
	}
	if got.Interval != defaultInterval {
		t.Errorf("Interval = %v, want %v", got.Interval, defaultInterval)
	}
}

func TestConfigWithDefaultsPreservesValues(t *testing.T) {
	in := Config{
		MissingResourceRetention: time.Hour,
		OperationRetention:       2 * time.Hour,
		AuditRetention:           3 * time.Hour,
		Interval:                 15 * time.Minute,
	}
	if got := in.withDefaults(); got != in {
		t.Errorf("withDefaults overwrote provided values: got %+v, want %+v", got, in)
	}
}

func TestStatsIsZero(t *testing.T) {
	if !(Stats{}).IsZero() {
		t.Error("empty Stats.IsZero() = false, want true")
	}
	cases := []Stats{
		{MissingResourcesDeleted: 1},
		{OperationsDeleted: 1},
		{BindingsExpired: 1},
	}
	for _, s := range cases {
		if s.IsZero() {
			t.Errorf("Stats%+v.IsZero() = true, want false", s)
		}
	}
}
