package api

// Юнит-тесты чистых решений ручек accounts: валидация причины удаления
// (DELETE /accounts/{id}), решение «ротация требует осознанного выбора» и
// пороговая логика подтверждения ротации. Без БД и HTTP-сервера.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func TestConnectionCanCreateAccountHonorsEffectiveCapabilityAndPhaseBoundary(t *testing.T) {
	active := connections.Connection{
		Engine: "fake", Status: connections.StatusActive,
		Capabilities: []string{string(adapter.CapAccountCreate)},
	}
	if !connectionCanCreateAccount(active) {
		t.Fatal("active non-PostgreSQL connection lost account.create")
	}
	withoutCapability := active
	withoutCapability.Capabilities = nil
	if connectionCanCreateAccount(withoutCapability) {
		t.Fatal("connection without effective account.create was accepted")
	}
	postgresLegacy := active
	postgresLegacy.Engine = "postgres"
	if connectionCanCreateAccount(postgresLegacy) {
		t.Fatal("PostgreSQL generic account.create remained enabled from stale capabilities")
	}
}

func TestNormalizeDeleteReason(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty", raw: "", want: ""},
		{name: "whitespace only becomes empty", raw: "  \t\n ", want: ""},
		{name: "trimmed", raw: "  staffer left the team \n", want: "staffer left the team"},
		{name: "max length ok", raw: strings.Repeat("a", deleteReasonMaxLen), want: strings.Repeat("a", deleteReasonMaxLen)},
		{name: "too long", raw: strings.Repeat("a", deleteReasonMaxLen+1), wantErr: true},
		// Лимит считается в символах, не байтах: 500 кириллических символов
		// (1000 байт UTF-8) проходят.
		{name: "multibyte runes within limit", raw: strings.Repeat("ы", deleteReasonMaxLen), want: strings.Repeat("ы", deleteReasonMaxLen)},
		{name: "multibyte runes over limit", raw: strings.Repeat("ы", deleteReasonMaxLen+1), wantErr: true},
		// Trim выполняется до проверки длины: пробельные края не съедают лимит.
		{name: "trim before limit", raw: "  " + strings.Repeat("a", deleteReasonMaxLen) + "  ", want: strings.Repeat("a", deleteReasonMaxLen)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := normalizeDeleteReason(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRestoreAccountRequestValidate(t *testing.T) {
	validProvided := "restore-password-strong"
	cases := []struct {
		name    string
		req     restoreAccountRequest
		wantErr bool
	}{
		{name: "generated", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeGenerated}}},
		{name: "provided", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeProvided, Password: validProvided}}},
		{name: "principal credential", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModePrincipal}}},
		{name: "missing credential", req: restoreAccountRequest{}, wantErr: true},
		{name: "unknown mode", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: "existing"}}, wantErr: true},
		{name: "generated password", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeGenerated, Password: validProvided}}, wantErr: true},
		{name: "principal password", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModePrincipal, Password: validProvided}}, wantErr: true},
		{name: "provided short", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeProvided, Password: "short"}}, wantErr: true},
		{name: "provided too long", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeProvided, Password: strings.Repeat("a", restorePasswordMaxRunes+1)}}, wantErr: true},
		{name: "provided nul", req: restoreAccountRequest{Credential: &restoreCredentialRequest{Mode: credentialModeProvided, Password: "valid-password\x00value"}}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.req.validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("validate error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// sharedCredentialAccount собирает аккаунт принципала на общем секрете
// окружения: ровно та топология, ротация которой требует выбора оператора.
func sharedCredentialAccount(principalID uuid.UUID) inventory.Account {
	mode := inventory.CredentialModeExistingVaultRef
	return inventory.Account{
		ID:             uuid.New(),
		PrincipalID:    &principalID,
		Kind:           inventory.AccountKindLogin,
		CredentialMode: &mode,
		VaultPath:      "principals/" + principalID.String() + "/environments/prod/credential",
		Status:         inventory.AccountActive,
		Ownership:      inventory.OwnershipManaged,
	}
}

// TestAccountSharesPrincipalCredential фиксирует решение «ротация уведёт
// аккаунт с общего пароля, поэтому нужен явный выбор оператора».
func TestAccountSharesPrincipalCredential(t *testing.T) {
	principalID := uuid.New()
	other := uuid.New()
	generated := inventory.CredentialModeGenerated

	withMode := func(a inventory.Account, mode string) inventory.Account {
		a.CredentialMode = &mode
		return a
	}

	cases := []struct {
		name    string
		account func() inventory.Account
		want    bool
	}{
		{
			name:    "shared credential of own principal",
			account: func() inventory.Account { return sharedCredentialAccount(principalID) },
			want:    true,
		},
		{
			// Не-живой аккаунт всё равно сидит на общем секрете: ротация
			// увела бы его с общего пароля так же молча.
			name: "provisioning account still shares the secret",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.Status = inventory.AccountProvisioning
				return a
			},
			want: true,
		},
		{
			name: "own account credential",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.VaultPath = "accounts/" + a.ID.String() + "/credential"
				return withMode(a, generated)
			},
			want: false,
		},
		{
			name: "no credential at all",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.VaultPath = ""
				a.CredentialMode = nil
				return a
			},
			want: false,
		},
		{
			name: "no principal",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.PrincipalID = nil
				return a
			},
			want: false,
		},
		{
			// Указатель в раздел чужого принципала уже сломан (share по нему
			// отказывает): ротация — штатная починка, а не осознанный выбор.
			name: "foreign principal pointer needs no choice",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.PrincipalID = &other
				return a
			},
			want: false,
		},
		{
			// Режим важен наравне с путём: пара (credential_mode, vault_path)
			// обязана быть согласованной.
			name: "principal path without existing_vault_ref mode",
			account: func() inventory.Account {
				return withMode(sharedCredentialAccount(principalID), generated)
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountSharesPrincipalCredential(tc.account()); got != tc.want {
				t.Errorf("accountSharesPrincipalCredential = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAccountRotatableOnSharedCredential: список затронутых аккаунтов в
// 409-контексте обязан совпадать с тем, что реально ротирует
// POST /principals/{id}/rotate — только managed и живые active.
func TestAccountRotatableOnSharedCredential(t *testing.T) {
	principalID := uuid.New()

	cases := []struct {
		name    string
		account func() inventory.Account
		want    bool
	}{
		{
			name:    "managed active",
			account: func() inventory.Account { return sharedCredentialAccount(principalID) },
			want:    true,
		},
		{
			name: "unmanaged",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.Ownership = inventory.OwnershipUnmanaged
				return a
			},
			want: false,
		},
	}
	for _, status := range []inventory.AccountStatus{
		inventory.AccountDisabled, inventory.AccountProvisioning,
		inventory.AccountMissing, inventory.AccountDeleted,
	} {
		cases = append(cases, struct {
			name    string
			account func() inventory.Account
			want    bool
		}{
			name: "status " + string(status),
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.Status = status
				return a
			},
			want: false,
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountRotatableOnSharedCredential(tc.account()); got != tc.want {
				t.Errorf("accountRotatableOnSharedCredential = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRotationRequiresConfirm фиксирует пороговую логику: gate выключен при
// threshold <= 0 и срабатывает строго БОЛЬШЕ порога (как RequiresMassRevoke).
func TestRotationRequiresConfirm(t *testing.T) {
	cases := []struct {
		name      string
		threshold int
		accounts  int
		want      bool
	}{
		{name: "disabled by zero threshold", threshold: 0, accounts: 100},
		{name: "disabled by negative threshold", threshold: -1, accounts: 100},
		{name: "below threshold", threshold: 2, accounts: 1},
		{name: "at threshold", threshold: 2, accounts: 2},
		{name: "above threshold", threshold: 2, accounts: 3, want: true},
		{name: "single account with threshold one", threshold: 1, accounts: 1},
		{name: "two accounts with threshold one", threshold: 1, accounts: 2, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rotationRequiresConfirm(tc.threshold, tc.accounts); got != tc.want {
				t.Errorf("rotationRequiresConfirm(%d, %d) = %v, want %v",
					tc.threshold, tc.accounts, got, tc.want)
			}
		})
	}
}

// TestAccountOperationCapability: каждая lifecycle-операция, которую ставит
// enqueueAccountOperation, знает свою capability движка. Без записи в этой
// таблице ручка ответила бы 202 и оставила заведомо обречённую операцию
// (кейс ручного E2E: mongodb account.disable жил в ретраях почти две минуты).
func TestAccountOperationCapability(t *testing.T) {
	want := map[string]adapter.Capability{
		jobs.KindAccountDisable:   adapter.CapAccountDisable,
		jobs.KindAccountEnable:    adapter.CapAccountEnable,
		jobs.KindAccountDelete:    adapter.CapAccountDelete,
		jobs.KindCredentialRotate: adapter.CapCredentialRotate,
	}
	if len(accountOperationCapability) != len(want) {
		t.Fatalf("capability map size = %d, want %d", len(accountOperationCapability), len(want))
	}
	for kind, capability := range want {
		if got := accountOperationCapability[kind]; got != capability {
			t.Errorf("capability of %q = %q, want %q", kind, got, capability)
		}
	}
	// Движок-заглушка capability_test объявляет только inventory.accounts:
	// ни одна lifecycle-операция на нём не поддерживается.
	registerCapTestOnce.Do(func() {
		adapter.Register(capTestEngine, func() adapter.Adapter { return capTestAdapter{} })
	})
	for kind, capability := range accountOperationCapability {
		if engineSupports(capTestEngine, capability) {
			t.Errorf("engine without capabilities must not support %q", kind)
		}
	}
}
