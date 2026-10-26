package api

// Юнит-тесты чистых функций каскада disable/enable и offboard принципала:
// вычисление набора дочерних операций, разбиение аккаунтов на
// managed/unmanaged, отбор bindings к отзыву, guard статусов и разбор
// подтверждения offboard. Без БД и HTTP-сервера.

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// acct собирает аккаунт для тестов каскада.
func acct(ownership inventory.Ownership, status inventory.AccountStatus, identity string) inventory.Account {
	return inventory.Account{
		ID:             uuid.New(),
		ConnectionID:   uuid.New(),
		EngineIdentity: identity,
		Ownership:      ownership,
		Status:         status,
	}
}

func TestCascadeStatusTargets(t *testing.T) {
	managedActive := acct(inventory.OwnershipManaged, inventory.AccountActive, "m_active")
	managedDisabled := acct(inventory.OwnershipManaged, inventory.AccountDisabled, "m_disabled")
	unmanagedActive := acct(inventory.OwnershipUnmanaged, inventory.AccountActive, "u_active")
	managedDeleted := acct(inventory.OwnershipManaged, inventory.AccountDeleted, "m_deleted")
	accounts := []inventory.Account{managedActive, managedDisabled, unmanagedActive, managedDeleted}

	// Каскад disable: только managed-активные; уже disabled, unmanaged и
	// deleted пропускаются.
	got := cascadeStatusTargets(accounts, inventory.AccountDisabled)
	if len(got) != 1 || got[0].EngineIdentity != "m_active" {
		t.Errorf("disable targets = %+v, want only m_active", got)
	}
	// Каскад enable: только managed-выключенные.
	got = cascadeStatusTargets(accounts, inventory.AccountActive)
	if len(got) != 1 || got[0].EngineIdentity != "m_disabled" {
		t.Errorf("enable targets = %+v, want only m_disabled", got)
	}
	// Пустой вход — пустой (не nil-паника) выход.
	if got = cascadeStatusTargets(nil, inventory.AccountDisabled); len(got) != 0 {
		t.Errorf("empty input targets = %+v, want empty", got)
	}
}

func TestPartitionOffboardAccounts(t *testing.T) {
	managed := acct(inventory.OwnershipManaged, inventory.AccountActive, "m1")
	managedDisabled := acct(inventory.OwnershipManaged, inventory.AccountDisabled, "m2")
	unmanaged := acct(inventory.OwnershipUnmanaged, inventory.AccountActive, "u1")

	gotManaged, gotUnmanaged := partitionOffboardAccounts([]inventory.Account{managed, unmanaged, managedDisabled})
	if len(gotManaged) != 2 || gotManaged[0].EngineIdentity != "m1" || gotManaged[1].EngineIdentity != "m2" {
		t.Errorf("managed = %+v, want [m1 m2]", gotManaged)
	}
	if len(gotUnmanaged) != 1 || gotUnmanaged[0].EngineIdentity != "u1" ||
		gotUnmanaged[0].ConnectionID != unmanaged.ConnectionID {
		t.Errorf("unmanaged = %+v, want [u1]", gotUnmanaged)
	}

	// Пустой вход: оба списка пустые, unmanaged сериализуем как [] (не null).
	gotManaged, gotUnmanaged = partitionOffboardAccounts(nil)
	if len(gotManaged) != 0 || gotUnmanaged == nil || len(gotUnmanaged) != 0 {
		t.Errorf("empty input = (%+v, %+v), want empty slices", gotManaged, gotUnmanaged)
	}
}

func TestOffboardRevokeBindings(t *testing.T) {
	present := inventory.BindingPresent
	absent := inventory.BindingAbsent
	managedPresent := inventory.Binding{ID: uuid.New(), DesiredState: &present}
	managedAbsent := inventory.Binding{ID: uuid.New(), DesiredState: &absent}
	unmanaged := inventory.Binding{ID: uuid.New(), DesiredState: nil}

	got := offboardRevokeBindings([]inventory.Binding{managedPresent, managedAbsent, unmanaged})
	if len(got) != 1 || got[0].ID != managedPresent.ID {
		t.Errorf("revoke bindings = %+v, want only managed-present", got)
	}
}

func TestPrincipalStatusBlocks(t *testing.T) {
	cases := []struct {
		name          string
		status        principals.Status
		blockDisabled bool
		want          string
	}{
		{"active allowed", principals.StatusActive, true, ""},
		{"disabled allowed for non-secret action", principals.StatusDisabled, false, ""},
		{"disabled blocks share/rotate", principals.StatusDisabled, true, "principal is disabled"},
		{"deleted blocks everything", principals.StatusDeleted, false, "principal is deleted"},
		{"deleted blocks share/rotate too", principals.StatusDeleted, true, "principal is deleted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := principalStatusBlocks(tc.status, tc.blockDisabled); got != tc.want {
				t.Errorf("principalStatusBlocks(%q, %v) = %q, want %q", tc.status, tc.blockDisabled, got, tc.want)
			}
		})
	}
}

// TestAccountOnOwnCredential фиксирует дополнительность предикатов: вместе
// с accountRotatableOnSharedCredential они покрывают managed+active
// носителей credential ровно один раз, без пересечения и без дыр.
func TestAccountOnOwnCredential(t *testing.T) {
	principalID := uuid.New()
	generated := inventory.CredentialModeGenerated

	ownCredential := func() inventory.Account {
		mode := generated
		a := sharedCredentialAccount(principalID)
		a.CredentialMode = &mode
		a.VaultPath = "accounts/" + a.ID.String() + "/credential"
		return a
	}

	cases := []struct {
		name    string
		account func() inventory.Account
		want    bool
	}{
		{name: "own credential", account: ownCredential, want: true},
		{
			name: "adopted without credential",
			account: func() inventory.Account {
				a := ownCredential()
				a.CredentialMode = nil
				a.VaultPath = ""
				return a
			},
			want: true,
		},
		{
			name:    "shared credential belongs to the other predicate",
			account: func() inventory.Account { return sharedCredentialAccount(principalID) },
			want:    false,
		},
		{
			name: "foreign principal pointer is not shared",
			account: func() inventory.Account {
				a := sharedCredentialAccount(principalID)
				a.VaultPath = "principals/" + uuid.NewString() + "/environments/prod/credential"
				return a
			},
			want: true,
		},
		{
			name: "group holds no credential",
			account: func() inventory.Account {
				a := ownCredential()
				a.Kind = inventory.AccountKindGroup
				return a
			},
			want: false,
		},
		{
			name: "unmanaged",
			account: func() inventory.Account {
				a := ownCredential()
				a.Ownership = inventory.OwnershipUnmanaged
				return a
			},
			want: false,
		},
		{
			name: "disabled",
			account: func() inventory.Account {
				a := ownCredential()
				a.Status = inventory.AccountDisabled
				return a
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acct := tc.account()
			if got := accountOnOwnCredential(acct); got != tc.want {
				t.Errorf("accountOnOwnCredential = %v, want %v", got, tc.want)
			}
			if accountOnOwnCredential(acct) && accountRotatableOnSharedCredential(acct) {
				t.Error("account matched both rotation predicates")
			}
		})
	}
}

func TestParseOffboardOptions(t *testing.T) {
	cases := []struct {
		name    string
		query   string
		body    string
		want    offboardOptions
		wantErr bool
	}{
		{name: "query confirm", query: "?confirm=true", want: offboardOptions{Confirm: true}},
		{name: "body confirm", body: `{"confirm":true}`, want: offboardOptions{Confirm: true}},
		{name: "no confirm", want: offboardOptions{}},
		{name: "body confirm false", body: `{"confirm":false}`, want: offboardOptions{}},
		{name: "query wins over empty body", query: "?confirm=true", body: "", want: offboardOptions{Confirm: true}},
		{
			name:  "takeover with query confirm",
			query: "?confirm=true",
			body:  `{"takeover_credentials":true}`,
			want:  offboardOptions{Confirm: true, Takeover: true},
		},
		{
			name: "takeover with body confirm",
			body: `{"confirm":true,"takeover_credentials":true}`,
			want: offboardOptions{Confirm: true, Takeover: true},
		},
		// Takeover без подтверждения самого offboard не выполняется: ручка
		// отказывает по Confirm раньше, чем дойдёт до паролей.
		{name: "takeover without confirm", body: `{"takeover_credentials":true}`, want: offboardOptions{Takeover: true}},
		{name: "takeover defaults to off", body: `{"confirm":true}`, want: offboardOptions{Confirm: true}},
		{name: "malformed body", body: `{"confirm":`, wantErr: true},
		// Нечитаемое тело — ошибка даже при confirm в query: молча потерять
		// takeover значит выполнить не то действие, которое просили.
		{name: "malformed body with query confirm", query: "?confirm=true", body: `{"confirm":`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/v1/principals/x/offboard"+tc.query, nil)
			got, err := parseOffboardOptions(r, []byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if got != tc.want {
				t.Errorf("options = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPrincipalResponseFields(t *testing.T) {
	p := principals.Principal{
		ID:          uuid.New(),
		Type:        principals.TypeService,
		DisplayName: "Payments",
		Status:      principals.StatusDisabled,
	}
	fields, err := principalResponseFields(p)
	if err != nil {
		t.Fatalf("principalResponseFields: %v", err)
	}
	if fields["id"] != p.ID.String() {
		t.Errorf("id = %v, want %s", fields["id"], p.ID)
	}
	if fields["status"] != string(principals.StatusDisabled) {
		t.Errorf("status = %v, want disabled", fields["status"])
	}
	if fields["display_name"] != "Payments" {
		t.Errorf("display_name = %v, want Payments", fields["display_name"])
	}
}
