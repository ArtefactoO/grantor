package credentialcheck

import (
	"testing"
	"time"
)

func TestStatsIsZero(t *testing.T) {
	if !(Stats{}).IsZero() {
		t.Error("empty Stats: IsZero = false, want true")
	}
	// Недоступный Vault — тоже событие прогона: планировщик обязан его
	// залогировать, а не считать прогон пустым.
	if (Stats{PathsUnavailable: 1}).IsZero() {
		t.Error("Stats with an unavailable path: IsZero = true, want false")
	}
	if (Stats{Diverged: 1}).IsZero() {
		t.Error("Stats with a divergence: IsZero = true, want false")
	}
}

func TestInterval(t *testing.T) {
	r := New(nil, nil, Config{Interval: 5 * time.Minute})
	if got := r.Interval(); got != 5*time.Minute {
		t.Errorf("Interval = %v, want 5m", got)
	}
}

// Без Vault сверять не с чем: прогон обязан вернуть ошибку, а не тихо
// отчитаться пустым результатом — иначе выключенный Vault выглядел бы как
// «расхождений нет».
func TestRunOnceWithoutVault(t *testing.T) {
	r := New(nil, nil, Config{Interval: time.Minute})
	if _, err := r.RunOnce(t.Context()); err == nil {
		t.Fatal("RunOnce without vault: err = nil, want error")
	}
}
