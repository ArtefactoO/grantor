package gateway

import (
	"context"
	"sync"

	"github.com/ArtefactoO/grantor/internal/connector"
)

// DedupStore хранит результаты успешно завершённых заданий по ключу
// дедупликации, чтобы повторно доставленное задание (тот же
// IdempotencyKey/Nonce) не исполнялось дважды (раздел 24, R5 duplicate
// execution). Кешируются только успешные результаты — политику применяет
// Dispatch: закешированная ошибка сделала бы retry операции бессмысленным
// (повтор возвращал бы старый failed-результат вместо нового исполнения).
//
// Реализации: in-memory (memoryDedup, дефолт standalone-бинаря без metadata
// DB) и durable поверх таблицы connector_job_dedup
// (internal/core/connectorjobs) — её подключает worker, встраивающий gateway
// (этап 2): результаты переживают рестарт процесса.
type DedupStore interface {
	// Lookup возвращает ранее сохранённый результат по ключу.
	Lookup(ctx context.Context, key string) (connector.JobResult, bool, error)
	// Store запоминает результат под ключом. Повторная запись того же
	// ключа не обязана перезаписывать результат (first write wins).
	Store(ctx context.Context, key string, res connector.JobResult) error
}

// memoryDedup — in-memory реализация DedupStore: живёт только в пределах
// процесса gateway и теряется при рестарте. Используется, когда durable
// store не сконфигурирован (standalone cmd/connector-gateway без metadata
// DB). Безопасна для конкурентного доступа.
type memoryDedup struct {
	mu   sync.Mutex
	seen map[string]connector.JobResult
}

func newMemoryDedup() *memoryDedup {
	return &memoryDedup{seen: map[string]connector.JobResult{}}
}

// Lookup возвращает ранее сохранённый результат по ключу.
func (d *memoryDedup) Lookup(_ context.Context, key string) (connector.JobResult, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	res, ok := d.seen[key]
	return res, ok, nil
}

// Store запоминает результат под ключом (first write wins).
func (d *memoryDedup) Store(_ context.Context, key string, res connector.JobResult) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; !ok {
		d.seen[key] = res
	}
	return nil
}

// dedupKey выбирает ключ дедупликации задания: IdempotencyKey приоритетен как
// логический ключ операции; при его отсутствии используется Nonce (anti-replay
// подписи). Если пусты оба — ключа нет и дедупликация не применяется.
func dedupKey(job connector.Job) string {
	switch {
	case job.IdempotencyKey != "":
		return "idem:" + job.IdempotencyKey
	case job.Nonce != "":
		return "nonce:" + job.Nonce
	default:
		return ""
	}
}
