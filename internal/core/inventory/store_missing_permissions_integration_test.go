//go:build integration

// Discovery и права, которых больше нет в целевой системе. До миграции 00026
// у permission_definitions не было пометки исчезновения вовсе: роль,
// удалённая из кластера, вечно оставалась assignable и предлагалась в
// диалогах выдачи.
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
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestLoginRolePermissionRecoversFalseMissingWithoutEnablingAssignment(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	conn := connectionWithPermissionInventory(ctx, t, pool)
	store := inventory.NewStore()
	account := adapter.ObservedAccount{Kind: "login", EngineIdentity: "service_predict_nba"}
	permission := adapter.ObservedPermission{ExternalID: "role:service_predict_nba", Name: "service_predict_nba",
		Assignable: false, AccountEngineIdentity: "service_predict_nba", Attributes: map[string]any{"login_role": true}}
	// Historical snapshot: a LOGIN parent with a member was published as a permission.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{Accounts: []adapter.ObservedAccount{account}, Permissions: []adapter.ObservedPermission{permission}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Old discovery omitted the LOGIN permission after its last member vanished.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{Accounts: []adapter.ObservedAccount{account}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := permissionByExternalID(ctx, t, store, pool, conn.ID, permission.ExternalID)
	if before.Status != inventory.PermissionMissing {
		t.Fatal("fixture did not reproduce stale Missing")
	}
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, &adapter.Snapshot{Accounts: []adapter.ObservedAccount{account}, Permissions: []adapter.ObservedPermission{permission}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	after := permissionByExternalID(ctx, t, store, pool, conn.ID, permission.ExternalID)
	if after.ID != before.ID || after.Status != inventory.PermissionObserved || after.Assignable {
		t.Fatalf("LOGIN observation recovery is wrong: %+v", after)
	}
	if got := accountStatus(ctx, t, store, pool, accountID(ctx, t, pool, store, conn.ID, account.EngineIdentity)); got != inventory.AccountActive {
		t.Fatalf("account changed to %s", got)
	}
}

// connectionWithPermissionInventory создаёт подключение с capability
// inventory.permissions: именно она разрешает discovery делать вывод
// «права на target нет».
func connectionWithPermissionInventory(ctx context.Context, t *testing.T, pool *pgxpool.Pool) connections.Connection {
	t.Helper()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName: "itest-missing-permissions-" + uuid.NewString(),
		Engine:      "postgres",
		Capabilities: []string{
			string(adapter.CapInventoryAccounts),
			string(adapter.CapInventoryPermissions),
		},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	return conn
}

// rolesSnapshot строит снапшот postgres-вида: каждая NOLOGIN-роль живёт
// двумя проекциями — account kind=group и permission role:<имя>.
func rolesSnapshot(roles ...string) *adapter.Snapshot {
	snap := &adapter.Snapshot{ServerVersion: "16.4", ObservedAt: time.Now()}
	for _, role := range roles {
		snap.Accounts = append(snap.Accounts, adapter.ObservedAccount{
			Kind: "group", EngineIdentity: role,
		})
		snap.Permissions = append(snap.Permissions, adapter.ObservedPermission{
			ExternalID: "role:" + role, Name: role,
			Assignable: true, AccountEngineIdentity: role,
		})
	}
	return snap
}

// permissionByExternalID находит право в каталоге connection или валит тест.
func permissionByExternalID(ctx context.Context, t *testing.T, store *inventory.Store,
	pool *pgxpool.Pool, connectionID uuid.UUID, externalID string) inventory.Permission {
	t.Helper()
	permissions, err := store.ListPermissions(ctx, pool, connectionID)
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	for _, p := range permissions {
		if p.ExternalID == externalID {
			return p
		}
	}
	t.Fatalf("permission %q not found among %d permissions", externalID, len(permissions))
	return inventory.Permission{}
}

func TestIntegrationDiscoveryMarksPermissionMissing(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := connectionWithPermissionInventory(ctx, t, pool)

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_read", "app_write"), time.Now()); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	read := permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if read.Status != inventory.PermissionObserved {
		t.Fatalf("fresh permission status = %q, want observed", read.Status)
	}

	// Роль удалили из кластера: обе её проекции помечаются одним сведением.
	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_write"), time.Now())
	if err != nil {
		t.Fatalf("snapshot without app_read: %v", err)
	}
	if stats.MissingPermissions != 1 {
		t.Errorf("missing permissions = %d, want 1", stats.MissingPermissions)
	}
	read = permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if read.Status != inventory.PermissionMissing {
		t.Errorf("vanished permission status = %q, want missing", read.Status)
	}
	markedAt := read.UpdatedAt
	// NOLOGIN-роль живёт двумя проекциями (account kind=group и permission
	// role:<имя>) — одно сведение помечает обе.
	if got := accountStatus(ctx, t, store, pool,
		accountID(ctx, t, pool, store, conn.ID, "app_read")); got != inventory.AccountMissing {
		t.Errorf("vanished group-account status = %q, want missing (both projections)", got)
	}

	// Повторное сведение того же снапшота идемпотентно: missing-строка не
	// перезаписывается и updated_at (момент пометки) не бампается.
	stats, err = store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_write"), time.Now())
	if err != nil {
		t.Fatalf("repeat snapshot: %v", err)
	}
	if stats.MissingPermissions != 0 {
		t.Errorf("repeat missing permissions = %d, want 0", stats.MissingPermissions)
	}
	read = permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if !read.UpdatedAt.Equal(markedAt) {
		t.Errorf("missing permission updated_at bumped on repeat: %v -> %v", markedAt, read.UpdatedAt)
	}

	// Роль вернулась в кластер -> право снова observed.
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_read", "app_write"), time.Now()); err != nil {
		t.Fatalf("snapshot after return: %v", err)
	}
	read = permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if read.Status != inventory.PermissionObserved {
		t.Errorf("returned permission status = %q, want observed", read.Status)
	}
}

// Подключение без inventory.permissions присылает пустой список прав не
// потому, что их нет на target, а потому что adapter их не собирает —
// стирать каталог прав нельзя.
func TestIntegrationDiscoveryKeepsPermissionsWithoutCapability(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn, err := connections.NewStore().Create(ctx, pool, connections.CreateParams{
		DisplayName:  "itest-missing-permissions-nocap-" + uuid.NewString(),
		Engine:       "redis",
		Capabilities: []string{string(adapter.CapInventoryAccounts)},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_read"), time.Now()); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	empty := &adapter.Snapshot{ServerVersion: "7", ObservedAt: time.Now()}
	empty.Accounts = append(empty.Accounts, adapter.ObservedAccount{Kind: "group", EngineIdentity: "app_read"})
	stats, err := store.UpsertSnapshot(ctx, pool, conn.ID, empty, time.Now())
	if err != nil {
		t.Fatalf("snapshot without permissions: %v", err)
	}
	if stats.MissingPermissions != 0 {
		t.Errorf("missing permissions = %d, want 0 (no capability)", stats.MissingPermissions)
	}
	read := permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if read.Status != inventory.PermissionObserved {
		t.Errorf("permission status = %q, want observed (catalog preserved)", read.Status)
	}
}

// Управляемая учётка не публикуется как назначаемое право: выключенная
// (NOLOGIN) она внешне неотличима от роли, и выдача такого «права» передала бы
// чужие привилегии. Управляемая РОЛЬ — наоборот, ровно то, что grantor завёл,
// чтобы её выдавать (role.create, ADR-0020), и остаётся assignable.
func TestIntegrationManagedRoleStaysAssignable(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := connectionWithPermissionInventory(ctx, t, pool)

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_read", "svc_bot"), time.Now()); err != nil {
		t.Fatalf("initial snapshot: %v", err)
	}
	// app_read берётся под управление как роль-контейнер, svc_bot — как
	// обычная учётная запись.
	if _, err := pool.Exec(ctx, `
		update accounts set ownership = 'managed'
		where connection_id = $1 and engine_identity in ('app_read', 'svc_bot')`, conn.ID); err != nil {
		t.Fatalf("adopt accounts: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		update accounts set kind = 'login'
		where connection_id = $1 and engine_identity = 'svc_bot'`, conn.ID); err != nil {
		t.Fatalf("mark svc_bot as login: %v", err)
	}

	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, rolesSnapshot("app_read", "svc_bot"), time.Now()); err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	role := permissionByExternalID(ctx, t, store, pool, conn.ID, "role:app_read")
	if !role.Assignable {
		t.Error("managed group role must stay assignable: it exists to be granted")
	}
	account := permissionByExternalID(ctx, t, store, pool, conn.ID, "role:svc_bot")
	if account.Assignable {
		t.Error("managed login account must not be published as an assignable permission")
	}
}
