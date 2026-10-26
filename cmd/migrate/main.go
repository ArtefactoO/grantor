// Command grantor-migrate применяет миграции metadata database: goose
// core schema и служебные таблицы River. Это будущий db-migrate Job
// (docs/architecture.md, раздел 27.6): запуск идемпотентен, параллельные
// запуски сериализуются session advisory lock (migrations.LockKey — тот
// же ключ, что в pgtest). Завершается кодом 0 при успехе, 1 при ошибке.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ArtefactoO/grantor/db/migrations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

const (
	// pingAttempts и pingInterval задают ожидание готовности БД:
	// в docker-compose migrate может стартовать раньше, чем PostgreSQL
	// начнёт принимать соединения.
	pingAttempts = 30
	pingInterval = time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("grantor-migrate: fatal", "error", err)
		os.Exit(1)
	}
}

// run ждёт готовности БД и применяет все миграции под session advisory
// lock.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("GRANTOR_DB_DSN")
	if dsn == "" {
		return errors.New("GRANTOR_DB_DSN is required")
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()

	if err := waitForDB(ctx, pool); err != nil {
		return err
	}

	// Session advisory lock сериализует параллельные запуски migrate:
	// goose и rivermigrate идемпотентны, lock защищает от гонок
	// одновременного применения. Держится на выделенном соединении до
	// конца работы; при аварийном завершении процесс закрывает
	// соединение и сервер освобождает lock сам.
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration lock connection: %w", err)
	}
	defer lockConn.Release()
	if _, err := lockConn.Exec(ctx, "select pg_advisory_lock($1)", migrations.LockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := lockConn.Exec(ctx, "select pg_advisory_unlock($1)", migrations.LockKey); err != nil {
			slog.Error("grantor-migrate: release migration lock", "error", err)
		}
	}()

	// stdlib.OpenDBFromPool даёт *sql.DB поверх пула; закрытие db не
	// закрывает сам пул.
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close() //nolint:errcheck

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		return fmt.Errorf("create goose provider: %w", err)
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return fmt.Errorf("apply core migrations: %w", err)
	}
	slog.Info("grantor-migrate: core migrations applied", "applied", len(results))

	if err := jobs.MigrateUp(ctx, pool); err != nil {
		return fmt.Errorf("apply river migrations: %w", err)
	}
	slog.Info("grantor-migrate: river migrations applied")

	slog.Info("grantor-migrate: done")
	return nil
}

// waitForDB ждёт готовности PostgreSQL: до pingAttempts попыток ping с
// интервалом pingInterval между ними.
func waitForDB(ctx context.Context, pool *pgxpool.Pool) error {
	var lastErr error
	for attempt := 1; attempt <= pingAttempts; attempt++ {
		lastErr = pool.Ping(ctx)
		if lastErr == nil {
			return nil
		}
		slog.Warn("grantor-migrate: database is not ready yet",
			"attempt", attempt, "max_attempts", pingAttempts, "error", lastErr)
		if attempt == pingAttempts {
			break
		}
		select {
		case <-time.After(pingInterval):
		case <-ctx.Done():
			return fmt.Errorf("wait for database: %w", ctx.Err())
		}
	}
	return fmt.Errorf("database is not ready after %d attempts: %w", pingAttempts, lastErr)
}
