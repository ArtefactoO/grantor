package rediscovery

import (
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/core/connections"
)

// TestNeedsRediscovery покрывает чистую функцию «кому пора»: комбинации
// статуса connection и возраста снимка относительно порога свежести.
func TestNeedsRediscovery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	staleAfter := time.Hour
	fresh := now.Add(-time.Minute)
	stale := now.Add(-2 * time.Hour)
	exactly := now.Add(-staleAfter)

	tests := []struct {
		name            string
		status          connections.Status
		lastDiscoveryAt *time.Time
		want            bool
	}{
		// Статусы, допускающие discovery без переходов state machine.
		{"active stale", connections.StatusActive, &stale, true},
		{"active fresh", connections.StatusActive, &fresh, false},
		{"active no snapshot", connections.StatusActive, nil, true},
		// Ровно staleAfter — уже пора (нестрогое сравнение).
		{"active exactly stale threshold", connections.StatusActive, &exactly, true},
		{"degraded stale", connections.StatusDegraded, &stale, true},
		{"degraded fresh", connections.StatusDegraded, &fresh, false},
		{"degraded no snapshot", connections.StatusDegraded, nil, true},
		// Статусы, где авто-discovery не ставится, — независимо от возраста
		// снимка: там он запрещён, ещё не имеет смысла или уже идёт.
		{"draft stale", connections.StatusDraft, &stale, false},
		{"validating stale", connections.StatusValidating, &stale, false},
		{"discovering stale", connections.StatusDiscovering, &stale, false},
		{"connection_failed stale", connections.StatusConnectionFailed, &stale, false},
		{"discovery_failed stale", connections.StatusDiscoveryFailed, &stale, false},
		{"disabled stale", connections.StatusDisabled, &stale, false},
		{"disabled no snapshot", connections.StatusDisabled, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NeedsRediscovery(tc.status, tc.lastDiscoveryAt, now, staleAfter)
			if got != tc.want {
				t.Errorf("NeedsRediscovery(%q, %v) = %v, want %v",
					tc.status, tc.lastDiscoveryAt, got, tc.want)
			}
		})
	}
}
