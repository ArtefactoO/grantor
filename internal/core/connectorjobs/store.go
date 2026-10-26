// Package connectorjobs — durable-дедупликация заданий execution connector
// поверх таблицы metadata DB connector_job_dedup
// (db/migrations/00008_connector_job_dedup.sql; раздел 24 архитектуры, R5
// duplicate execution). Store реализует контракт gateway.DedupStore
// (структурно, без импорта gateway): worker, встраивающий gateway, передаёт
// его в gateway.Config.Dedup — результаты успешно завершённых заданий
// переживают рестарт процесса, и повторно доставленное задание (тот же
// IdempotencyKey/Nonce) не исполняется второй раз.
//
// Секреты: result хранит connector.JobResult как jsonb. По контракту
// internal/connector (раздел 24) plan/result/error задания sanitized и
// секретов не содержат; инвариант дополнительно покрыт динамическим
// canary-sweep'ом metadata DB (TestIntegrationNoSecretsInMetadataDB
// перечисляет колонки по information_schema — новая jsonb-колонка попадает
// под скан автоматически) и адресной проверкой в интеграционном тесте
// connector phase 2.
//
// TTL/GC: выбран cleanup-on-insert (удаление записей старше TTL перед каждой
// вставкой), а не прогон в планировщике internal/core/maintenance. Причины:
// таблица мала (по записи на успешное задание, ключи уникальны), окно
// дедупликации короткое (retry той же операции — минуты, не сутки), а
// подключение maintenance к connector добавило бы зависимость пакета
// обслуживания от контракта connector ради одного DELETE. Индекс по
// created_at (см. миграцию) делает cleanup дешёвым.
package connectorjobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/connector"
)

// DefaultTTL — время жизни записи дедупликации по умолчанию. Сутки покрывают
// retry-политику River (минуты) с большим запасом и не дают таблице расти.
const DefaultTTL = 24 * time.Hour

// Store — durable-store дедупликации заданий connector. В отличие от прочих
// stores ядра держит пул сам: контракт gateway.DedupStore не передаёт Querier
// per-call, а транзакционность вызывающего здесь не нужна (запись результата
// задания независима от транзакций operation engine).
type Store struct {
	pool *pgxpool.Pool
	ttl  time.Duration
}

// NewStore возвращает Store поверх пула metadata DB. ttl <= 0 заменяется
// DefaultTTL.
func NewStore(pool *pgxpool.Pool, ttl time.Duration) *Store {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{pool: pool, ttl: ttl}
}

// Lookup возвращает ранее сохранённый результат задания по ключу
// дедупликации; отсутствие записи — не ошибка (ok=false).
func (s *Store) Lookup(ctx context.Context, key string) (connector.JobResult, bool, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx,
		`select result from connector_job_dedup where dedup_key = $1`, key,
	).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return connector.JobResult{}, false, nil
	}
	if err != nil {
		return connector.JobResult{}, false, fmt.Errorf("connectorjobs: lookup: %w", err)
	}
	var res connector.JobResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return connector.JobResult{}, false, fmt.Errorf("connectorjobs: unmarshal cached result: %w", err)
	}
	return res, true, nil
}

// Store сохраняет результат задания под ключом дедупликации. Повторная
// вставка того же ключа — no-op (first write wins, ON CONFLICT DO NOTHING):
// конкурентная доставка дубликата не перезаписывает результат. Перед вставкой
// выполняется GC записей старше TTL (см. doc-комментарий пакета).
func (s *Store) Store(ctx context.Context, key string, res connector.JobResult) error {
	raw, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("connectorjobs: marshal result: %w", err)
	}
	if _, err := s.pool.Exec(ctx,
		`delete from connector_job_dedup where created_at < $1`,
		time.Now().Add(-s.ttl),
	); err != nil {
		return fmt.Errorf("connectorjobs: gc expired entries: %w", err)
	}
	if _, err := s.pool.Exec(ctx, `
		insert into connector_job_dedup (dedup_key, job_id, result)
		values ($1, $2, $3)
		on conflict (dedup_key) do nothing`,
		key, res.JobID, raw,
	); err != nil {
		return fmt.Errorf("connectorjobs: store result: %w", err)
	}
	return nil
}
