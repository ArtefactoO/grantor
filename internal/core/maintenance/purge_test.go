package maintenance

import (
	"testing"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
)

// Purge удаляет только живые managed-логины: групповые роли и unmanaged не
// принадлежат grantor'у, tombstone удалять нечего.
func TestPurgeDeletableAccount(t *testing.T) {
	base := inventory.Account{
		Kind:      inventory.AccountKindLogin,
		Ownership: inventory.OwnershipManaged,
		Status:    inventory.AccountActive,
	}
	cases := []struct {
		name   string
		mutate func(a inventory.Account) inventory.Account
		want   bool
	}{
		{"managed login", func(a inventory.Account) inventory.Account { return a }, true},
		{"disabled managed login", func(a inventory.Account) inventory.Account {
			a.Status = inventory.AccountDisabled
			return a
		}, true},
		{"deleted tombstone", func(a inventory.Account) inventory.Account {
			a.Status = inventory.AccountDeleted
			return a
		}, false},
		{"unmanaged", func(a inventory.Account) inventory.Account {
			a.Ownership = inventory.OwnershipUnmanaged
			return a
		}, false},
		{"managed group role", func(a inventory.Account) inventory.Account {
			a.Kind = inventory.AccountKindGroup
			return a
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := purgeDeletableAccount(tc.mutate(base)); got != tc.want {
				t.Errorf("purgeDeletableAccount = %v, want %v", got, tc.want)
			}
		})
	}
}
