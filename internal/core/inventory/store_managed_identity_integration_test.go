//go:build integration

// Управляемая учётная запись и роль движка — разные сущности, даже когда
// движок их не различает. В PostgreSQL disable ставит NOLOGIN, и следующий
// discovery видит роль без логина: до фикса это (а) превращало учётку в
// group, из-за чего enable/rotate/share начинали отвечать 409 и вернуть её
// можно было только руками в СУБД, и (б) публиковало её как назначаемое
// право — выдача такого «права» другому принципалу передавала ему все
// привилегии владельца учётки.
package inventory_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestIntegrationManagedAccountIsNotDemotedToRole(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()

	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-managed-identity-" + uuid.NewString(),
		Engine:      "postgres",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	acct, err := store.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: "gr_managed",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}

	// Снимок после disable: движок отдаёт ту же identity уже как роль без
	// логина и публикует её как назначаемое право — ровно то, что делает
	// PostgreSQL-адаптер для NOLOGIN-роли.
	snap := &adapter.Snapshot{ServerVersion: "16.4", ObservedAt: time.Now()}
	snap.Accounts = []adapter.ObservedAccount{
		{Kind: "group", EngineIdentity: "gr_managed"},
		{Kind: "group", EngineIdentity: "real_group"},
	}
	snap.Permissions = []adapter.ObservedPermission{
		{
			ExternalID: "role:gr_managed", Name: "gr_managed", Assignable: true,
			AccountEngineIdentity: "gr_managed",
		},
		{
			ExternalID: "role:real_group", Name: "real_group", Assignable: true,
			AccountEngineIdentity: "real_group",
		},
	}
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatalf("upsert snapshot: %v", err)
	}

	// Учётка осталась учётной записью: иначе lifecycle-ручки её замуруют.
	got, err := store.GetAccount(ctx, pool, acct.ID)
	if err != nil {
		t.Fatalf("get account: %v", err)
	}
	if got.Kind != "login" {
		t.Errorf("managed account kind = %q, want login (engine reports group after disable)", got.Kind)
	}

	// Собственная учётка не предлагается к выдаче, а настоящая роль — да.
	perms, err := store.ListPermissions(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	assignable := map[string]bool{}
	for _, p := range perms {
		assignable[p.ExternalID] = p.Assignable
	}
	if assignable["role:gr_managed"] {
		t.Error("managed account is offered as an assignable permission: granting it would hand over its privileges")
	}
	if !assignable["role:real_group"] {
		t.Error("real group is not assignable: the guard must not swallow genuine roles")
	}
}
