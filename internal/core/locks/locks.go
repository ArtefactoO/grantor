// Package locks — per-connection advisory locks в metadata database
// (docs/architecture.md, раздел 19): не более одной mutating operation
// на connection одновременно. Используются transaction-scoped advisory
// locks PostgreSQL — они автоматически освобождаются при commit или
// rollback, поэтому lock невозможно «забыть» отпустить даже при падении
// worker.
package locks

import (
	"context"
	"fmt"
	"hash/fnv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ConnectionLockKey строит детерминированный bigint-ключ advisory lock
// из connection id.
//
// pg_advisory_xact_lock принимает 64-битный ключ, а uuid — 128 бит,
// поэтому id хэшируется FNV-1a 64 от его 16 байт. FNV-1a выбран как
// стабильный между процессами, платформами и версиями Go (в отличие от
// maphash с случайным seed), что обязательно: разные worker должны
// получать один и тот же ключ для одного connection. Теоретическая
// коллизия двух connection id деградирует безопасно: две несвязанные
// операции лишь выполнятся последовательно, взаимное исключение не
// нарушается.
func ConnectionLockKey(id uuid.UUID) int64 {
	h := fnv.New64a()
	h.Write(id[:]) //nolint:errcheck // hash.Hash.Write не возвращает ошибок.
	return int64(h.Sum64())
}

// AcquireTx блокирующе берёт advisory lock connection в рамках
// транзакции tx. Lock освобождается автоматически при завершении tx.
func AcquireTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	if _, err := tx.Exec(ctx, "select pg_advisory_xact_lock($1)", ConnectionLockKey(id)); err != nil {
		return fmt.Errorf("locks: acquire connection lock %s: %w", id, err)
	}
	return nil
}

// TryAcquireTx пытается взять advisory lock connection без ожидания.
// Возвращает false, если lock уже удерживается другой транзакцией.
// Взятый lock освобождается автоматически при завершении tx.
func TryAcquireTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (bool, error) {
	var acquired bool
	err := tx.QueryRow(ctx, "select pg_try_advisory_xact_lock($1)", ConnectionLockKey(id)).Scan(&acquired)
	if err != nil {
		return false, fmt.Errorf("locks: try acquire connection lock %s: %w", id, err)
	}
	return acquired, nil
}
