package jobs

import (
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// NewInsertOnly возвращает insert-only River-диспетчер для API-процесса:
// клиент без Workers и Queues умеет только ставить jobs (InsertTx), а
// выполняет их отдельный worker-процесс, собранный через New.
//
// EnqueueOperationTx работает полноценно и использует те же дефолты
// Config (Queue, MaxAttempts), что и worker, поэтому поставленные API
// jobs попадают в очередь, которую слушает worker. Start у insert-only
// клиента вызывать нельзя: River вернёт ошибку, потому что workers не
// зарегистрированы; Stop тоже не нужен — фоновых горутин у клиента нет.
func NewInsertOnly(pool *pgxpool.Pool) (*River, error) {
	cfg := Config{}.withDefaults()

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("jobs: create insert-only river client: %w", err)
	}
	return &River{client: client, cfg: cfg}, nil
}
