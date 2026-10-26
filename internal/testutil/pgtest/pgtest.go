// Package pgtest — helpers для тестов с реальным PostgreSQL. Тесты
// подключаются к базе из GRANTOR_TEST_DB_DSN; если переменная не задана,
// тест пропускается. Миграции (goose core schema + служебные таблицы
// River) применяются идемпотентно под advisory lock, поэтому пакеты
// тестов могут выполняться параллельно над одной базой.
package pgtest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ArtefactoO/grantor/db/migrations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// DSN возвращает DSN тестовой базы из GRANTOR_TEST_DB_DSN или
// пропускает тест, если переменная не задана.
func DSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("GRANTOR_TEST_DB_DSN")
	if dsn == "" {
		t.Skip("GRANTOR_TEST_DB_DSN is not set; skipping database test")
	}
	return dsn
}

// Pool возвращает пул соединений к тестовой базе с применёнными
// миграциями core schema (goose) и River. Пул закрывается в t.Cleanup.
func Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, DSN(t))
	if err != nil {
		t.Fatalf("pgtest: create pool: %v", err)
	}
	t.Cleanup(pool.Close)

	migrate(ctx, t, pool)
	return pool
}

// migrate идемпотентно применяет все миграции под session advisory
// lock (migrations.LockKey — общий ключ с cmd/migrate): goose и
// rivermigrate сами по себе идемпотентны, lock защищает от гонок при
// параллельном старте нескольких тестовых пакетов.
func migrate(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("pgtest: acquire migration lock connection: %v", err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, "select pg_advisory_lock($1)", migrations.LockKey); err != nil {
		t.Fatalf("pgtest: acquire migration lock: %v", err)
	}
	defer func() {
		if _, err := lockConn.Exec(ctx, "select pg_advisory_unlock($1)", migrations.LockKey); err != nil {
			t.Errorf("pgtest: release migration lock: %v", err)
		}
	}()

	// stdlib.OpenDBFromPool даёт *sql.DB поверх пула; закрытие db не
	// закрывает сам пул.
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close() //nolint:errcheck

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatalf("pgtest: create goose provider: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("pgtest: apply core migrations: %v", err)
	}

	if err := jobs.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("pgtest: apply river migrations: %v", err)
	}
}
