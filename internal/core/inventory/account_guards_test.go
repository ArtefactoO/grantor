package inventory

import (
	"testing"

	"github.com/google/uuid"
)

func TestAccountHoldsCredential(t *testing.T) {
	tests := []struct {
		kind string
		want bool
	}{
		{AccountKindLogin, true},
		{AccountKindGroup, false},
		// Список разрешающий: неизвестный kind считается не-носителем, пока
		// обратное не доказано явно.
		{"role", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run("kind="+tt.kind, func(t *testing.T) {
			if got := AccountHoldsCredential(Account{Kind: tt.kind}); got != tt.want {
				t.Errorf("AccountHoldsCredential(kind=%q) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

func TestCredentialPointerForeign(t *testing.T) {
	owner := uuid.New()
	other := uuid.New()
	sharedOf := func(id uuid.UUID) string {
		return "principals/" + id.String() + "/environments/prod/credential"
	}

	tests := []struct {
		name        string
		vaultPath   string
		principalID *uuid.UUID
		want        bool
	}{
		{
			name:        "shared secret of the current principal",
			vaultPath:   sharedOf(owner),
			principalID: &owner,
			want:        false,
		},
		{
			// Отвязка: указатель на общий секрет прежнего принципала остался
			// бы «висячим» — ровно та дыра, ради которой предикат заведён.
			name:        "shared secret without a principal",
			vaultPath:   sharedOf(owner),
			principalID: nil,
			want:        true,
		},
		{
			// Перепривязка на другого принципала.
			name:        "shared secret of another principal",
			vaultPath:   sharedOf(other),
			principalID: &owner,
			want:        true,
		},
		{
			name:        "own account path without a principal",
			vaultPath:   "accounts/" + uuid.New().String() + "/credential",
			principalID: nil,
			want:        false,
		},
		{
			name:        "own account path with a principal",
			vaultPath:   "accounts/" + uuid.New().String() + "/credential",
			principalID: &owner,
			want:        false,
		},
		{
			name:        "empty path",
			vaultPath:   "",
			principalID: nil,
			want:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CredentialPointerForeign(tt.vaultPath, tt.principalID); got != tt.want {
				t.Errorf("CredentialPointerForeign(%q) = %v, want %v", tt.vaultPath, got, tt.want)
			}
			acct := Account{VaultPath: tt.vaultPath, PrincipalID: tt.principalID}
			if got := AccountCredentialPointerForeign(acct); got != tt.want {
				t.Errorf("AccountCredentialPointerForeign = %v, want %v", got, tt.want)
			}
		})
	}
}
