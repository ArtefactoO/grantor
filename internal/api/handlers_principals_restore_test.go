package api

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// Выводимый из системы принципал не должен получать новых прав и секретов,
// но в отличие от tombstone обязан оставаться восстановимым.
func TestPrincipalStatusBlocksPendingPurge(t *testing.T) {
	cases := []struct {
		name          string
		status        principals.Status
		blockDisabled bool
		wantBlocked   bool
	}{
		{"active allowed", principals.StatusActive, false, false},
		{"active allowed for secrets", principals.StatusActive, true, false},
		{"pending purge blocks actions", principals.StatusPendingPurge, false, true},
		{"pending purge blocks secrets", principals.StatusPendingPurge, true, true},
		{"deleted blocks everything", principals.StatusDeleted, false, true},
		{"disabled allows lifecycle", principals.StatusDisabled, false, false},
		{"disabled blocks secrets", principals.StatusDisabled, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := principalStatusBlocks(tc.status, tc.blockDisabled)
			if (msg != "") != tc.wantBlocked {
				t.Fatalf("principalStatusBlocks(%q, %v) = %q, blocked=%v want %v",
					tc.status, tc.blockDisabled, msg, msg != "", tc.wantBlocked)
			}
		})
	}
}

// Новый статус обязан быть валидным для схемы: иначе SetStatus отвергнет
// переход ещё до записи, а CHECK-ограничение — после.
func TestPendingPurgeIsValidStatus(t *testing.T) {
	if !principals.StatusPendingPurge.Valid() {
		t.Fatal("StatusPendingPurge.Valid() = false, want true")
	}
}
