package locks

import (
	"testing"

	"github.com/google/uuid"
)

// TestConnectionLockKeyGolden фиксирует значения ключей для известных
// uuid: ключ обязан быть стабильным между процессами, платформами и
// версиями grantor, иначе разные worker перестанут исключать друг
// друга. Если этот тест сломался — алгоритм хэширования изменился, что
// недопустимо без миграции всех running workers.
func TestConnectionLockKeyGolden(t *testing.T) {
	tests := []struct {
		id   string
		want int64
	}{
		{"00000000-0000-0000-0000-000000000000", -8637869204239850395},
		{"6ba7b810-9dad-11d1-80b4-00c04fd430c8", -7999481426279782372},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			if got := ConnectionLockKey(uuid.MustParse(tt.id)); got != tt.want {
				t.Errorf("ConnectionLockKey(%s) = %d, want %d", tt.id, got, tt.want)
			}
		})
	}
}

func TestConnectionLockKeyDeterministic(t *testing.T) {
	for range 10 {
		id := uuid.New()
		first := ConnectionLockKey(id)
		second := ConnectionLockKey(id)
		if first != second {
			t.Fatalf("ConnectionLockKey(%s) not deterministic: %d != %d", id, first, second)
		}
	}
}

func TestConnectionLockKeyDistinct(t *testing.T) {
	const n = 1000
	seen := make(map[int64]uuid.UUID, n)
	for range n {
		id := uuid.New()
		key := ConnectionLockKey(id)
		if prev, dup := seen[key]; dup {
			t.Fatalf("ConnectionLockKey collision: %s and %s both map to %d", prev, id, key)
		}
		seen[key] = id
	}
}
