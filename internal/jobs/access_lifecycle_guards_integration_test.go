//go:build integration

package jobs

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ArtefactoO/grantor/db/migrations"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// accessLifecycleGuardPool mirrors pgtest.Pool without importing pgtest: that
// helper imports this package to apply River migrations, which would create an
// import cycle for an internal package test that exercises restoreAccountAccess.
func accessLifecycleGuardPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("GRANTOR_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_DB_DSN is not set; skipping database test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create database pool: %v", err)
	}
	t.Cleanup(pool.Close)
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire migration lock connection: %v", err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, "select pg_advisory_lock($1)", migrations.LockKey); err != nil {
		t.Fatalf("acquire migration lock: %v", err)
	}
	defer func() {
		if _, err := lockConn.Exec(ctx, "select pg_advisory_unlock($1)", migrations.LockKey); err != nil {
			t.Errorf("release migration lock: %v", err)
		}
	}()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close() //nolint:errcheck
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatalf("create goose provider: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("apply core migrations: %v", err)
	}
	if err := MigrateUp(ctx, pool); err != nil {
		t.Fatalf("apply River migrations: %v", err)
	}
	return pool
}

func TestAccountLifecycleAndRestoreBlockPendingDangerousAccessGrant(t *testing.T) {
	ctx := context.Background()
	pool := accessLifecycleGuardPool(t)
	connStore := connections.NewStore()
	invStore := inventory.NewStore()
	opStore := operations.NewStore()

	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName: "access-lifecycle-guard-" + uuid.NewString(), Engine: "fake",
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	account, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "guarded-" + uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	var permissionID uuid.UUID
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions
			(connection_id, engine, external_id, name, assignable, dangerous)
		values ($1, 'fake', $2, 'Dangerous role', true, true)
		returning id`, conn.ID, "role:dangerous:"+uuid.NewString()).Scan(&permissionID); err != nil {
		t.Fatalf("insert dangerous permission: %v", err)
	}
	binding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID: account.ID, PermissionID: permissionID, DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure dangerous binding: %v", err)
	}
	grant, _, err := opStore.Create(ctx, pool, operations.CreateParams{
		Kind: KindAccessGrant, ConnectionID: &conn.ID, AccountID: &account.ID,
		BindingID: &binding.ID, ActorType: "test", ActorID: t.Name(),
		CorrelationID: uuid.NewString(), RequiresApproval: true,
	})
	if err != nil {
		t.Fatalf("create pending dangerous grant: %v", err)
	}
	if grant.Status != operations.StatusPendingApproval {
		t.Fatalf("dangerous grant status = %q, want pending_approval", grant.Status)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin enable reservation: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := invStore.ReserveAccountLifecycle(ctx, tx, account.ID, inventory.AccountActive); err != nil {
		t.Fatalf("reserve lifecycle metadata: %v", err)
	}
	if err := invStore.EnsureNoActiveAccessOperations(ctx, tx, account.ID); !errors.Is(err, inventory.ErrAccountLifecycleBusy) {
		t.Fatalf("enable gate with pending dangerous grant error = %v, want ErrAccountLifecycleBusy", err)
	}

	executor := NewMainExecutor(DiscoveryDeps{Inventory: invStore, Pool: pool})
	_, err = executor.restoreAccountAccess(ctx, operations.Operation{ID: uuid.New()}, conn,
		adapter.Connection{}, nil, false, account)
	if !errors.Is(err, inventory.ErrAccountLifecycleBusy) {
		t.Fatalf("restoreAccountAccess with unfinished grant error = %v, want ErrAccountLifecycleBusy", err)
	}
}
