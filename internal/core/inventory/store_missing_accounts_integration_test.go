//go:build integration

// Discovery и managed-аккаунты, которых нет в целевой системе. До фикса
// discovery вообще не проверял managed-аккаунты: строка, чей пользователь в
// кластере отсутствует (в том числе фантом после провала account.create),
// переживала сколько угодно циклов discovery и в дрифт не попадала.
package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// connectionWithAccountInventory создаёт подключение с включённой
// capability inventory.accounts: именно она разрешает discovery делать
// вывод «аккаунта на target нет».
func connectionWithAccountInventory(ctx context.Context, t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName:  "itest-missing-accounts-" + uuid.NewString(),
		Engine:       "postgres",
		Capabilities: []string{string(adapter.CapInventoryAccounts)},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return conn
}

// accountsSnapshot строит минимальный снапшот с перечисленными аккаунтами.
func accountsSnapshot(identities ...string) *adapter.Snapshot {
	snap := &adapter.Snapshot{ServerVersion: "16.4", ObservedAt: time.Now()}
	for _, id := range identities {
		snap.Accounts = append(snap.Accounts, adapter.ObservedAccount{Kind: "login", EngineIdentity: id})
	}
	return snap
}

func TestIntegrationDiscoveryMarksManagedAccountMissing(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := connectionWithAccountInventory(ctx, t, pool)

	live, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "gr_live",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	phantom, err := store.CreateProvisioningAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "gr_phantom",
	})
	if err != nil {
		t.Fatalf("create provisioning account: %v", err)
	}
	if phantom.Status != inventory.AccountProvisioning {
		t.Fatalf("new provisioning account status = %q, want provisioning", phantom.Status)
	}

	// Снимок видит только gr_live: gr_phantom на target нет.
	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, accountsSnapshot("gr_live"), time.Now())
	if err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
	if stats.MissingAccounts != 0 {
		t.Errorf("missing accounts = %d, want 0 (provisioning is not touched by discovery)", stats.MissingAccounts)
	}
	if got := accountStatus(ctx, t, store, pool, live.ID); got != inventory.AccountActive {
		t.Errorf("observed account status = %q, want active", got)
	}
	// Provisioning остаётся собственностью незавершённой операции.
	if got := accountStatus(ctx, t, store, pool, phantom.ID); got != inventory.AccountProvisioning {
		t.Errorf("provisioning account status = %q, want provisioning", got)
	}

	// Живой managed-аккаунт исчез из целевой системы -> missing.
	stats, err = store.UpsertSnapshot(ctx, pool, conn.ID, accountsSnapshot(), time.Now())
	if err != nil {
		t.Fatalf("upsert snapshot without accounts: %v", err)
	}
	if stats.MissingAccounts != 1 {
		t.Errorf("missing accounts = %d, want 1", stats.MissingAccounts)
	}
	if got := accountStatus(ctx, t, store, pool, live.ID); got != inventory.AccountMissing {
		t.Errorf("vanished account status = %q, want missing", got)
	}

	// Оба расхождения видны в сводке и отчёте дрифта.
	counters, err := store.DriftSummary(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("drift summary: %v", err)
	}
	if counters.MissingManagedAccounts != 2 {
		t.Errorf("drift summary missing managed accounts = %d, want 2", counters.MissingManagedAccounts)
	}
	findings, err := store.DriftFindings(ctx, pool, &conn.ID)
	if err != nil {
		t.Fatalf("drift findings: %v", err)
	}
	missing := 0
	for _, f := range findings {
		if f.Kind == inventory.DriftKindMissingAccount {
			missing++
		}
	}
	if missing != 2 {
		t.Errorf("missing_account findings = %d, want 2", missing)
	}

	// Вернулся на target -> снова active (discovery не оставляет ложный missing).
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, accountsSnapshot("gr_live"), time.Now()); err != nil {
		t.Fatalf("upsert snapshot after return: %v", err)
	}
	if got := accountStatus(ctx, t, store, pool, live.ID); got != inventory.AccountActive {
		t.Errorf("returned account status = %q, want active", got)
	}
}

// TestIntegrationDiscoveryKeepsAccountsWithoutCapability закрывает главный
// риск пометки missing: подключение без capability inventory.accounts
// присылает пустой список аккаунтов не потому, что их нет на target, а
// потому что adapter их не собирает. Стирать такой инвентарь нельзя.
func TestIntegrationDiscoveryKeepsAccountsWithoutCapability(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)

	acct, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "gr_no_capability",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, accountsSnapshot(), time.Now())
	if err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}
	if stats.MissingAccounts != 0 {
		t.Errorf("missing accounts = %d, want 0 without inventory.accounts capability", stats.MissingAccounts)
	}
	if got := accountStatus(ctx, t, store, pool, acct.ID); got != inventory.AccountActive {
		t.Errorf("account status = %q, want active", got)
	}
}

// Unmanaged-строка удалённого из кластера пользователя раньше жила active
// вечно: markMissingAccounts фильтровал ownership='managed'. Пометка missing
// касается и linked-строк (principal_id задан) — привязка сама по себе не
// делает учётку существующей на target.
func TestIntegrationDiscoveryMarksUnmanagedAccountMissing(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := connectionWithAccountInventory(ctx, t, pool)

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID,
		accountsSnapshot("ext_user", "ext_linked"), time.Now()); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	extID := accountID(ctx, t, pool, store, conn.ID, "ext_user")
	linkedID := accountID(ctx, t, pool, store, conn.ID, "ext_linked")
	principal, err := principals.NewStore().Create(ctx, pool, principals.CreateParams{
		Type: principals.TypeService, DisplayName: "missing-linked " + uuid.NewString()[:8],
	})
	if err != nil {
		t.Fatalf("create principal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`update accounts set principal_id = $2 where id = $1`, linkedID, principal.ID); err != nil {
		t.Fatalf("link account: %v", err)
	}

	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, accountsSnapshot(), time.Now())
	if err != nil {
		t.Fatalf("snapshot without accounts: %v", err)
	}
	if stats.MissingAccounts != 2 {
		t.Errorf("missing accounts = %d, want 2 (unmanaged and linked)", stats.MissingAccounts)
	}
	if got := accountStatus(ctx, t, store, pool, extID); got != inventory.AccountMissing {
		t.Errorf("unmanaged account status = %q, want missing", got)
	}
	if got := accountStatus(ctx, t, store, pool, linkedID); got != inventory.AccountMissing {
		t.Errorf("linked account status = %q, want missing", got)
	}

	// Исчезнувший unmanaged — состояние каталога, не расхождение: в
	// счётчики дрифта он не попадает.
	counters, err := store.DriftSummary(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("drift summary: %v", err)
	}
	if counters.MissingManagedAccounts != 0 {
		t.Errorf("drift missing managed accounts = %d, want 0", counters.MissingManagedAccounts)
	}

	// Вернулся на target -> снова active.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID,
		accountsSnapshot("ext_user", "ext_linked"), time.Now()); err != nil {
		t.Fatalf("snapshot after return: %v", err)
	}
	if got := accountStatus(ctx, t, store, pool, extID); got != inventory.AccountActive {
		t.Errorf("returned unmanaged account status = %q, want active", got)
	}
}

// accountStatus читает текущий статус аккаунта.
func accountStatus(ctx context.Context, t *testing.T, store *inventory.Store, pool *pgxpool.Pool, id uuid.UUID) inventory.AccountStatus {
	t.Helper()
	acct, err := store.GetAccount(ctx, pool, id)
	if err != nil {
		t.Fatalf("get account %s: %v", id, err)
	}
	return acct.Status
}
