// Package rediscovery — периодический авто-rediscovery подключений
// (docs/architecture.md, разделы 5.1 и 9). Прогон находит connections со
// снимком старше порога свежести и ставит для них операцию
// connection.discover — ту же, что ручной refresh в API
// (POST /api/v1/connections/{id}/refresh), с тем же idempotency key
// минутного окна (jobs.DiscoverOperationKey), поэтому ручной и
// автоматический синк не дублируются.
//
// Пакет сознательно отделён от internal/core/maintenance: maintenance не
// знает про jobs.Dispatcher (см. его doc-комментарий), а авто-rediscovery
// без постановки job в очередь бессмыслен. Устройство при этом
// зеркальное: прогон выполняется фоново в worker-процессе (scheduler.go и
// cmd/worker) как singleton через PostgreSQL advisory lock — несколько
// реплик worker берут один фиксированный ключ, работает взявшая lock.
//
// Что делает один прогон (RunOnce):
//
//   - выбирает connections в статусах active и degraded — из них discovery
//     выполняется без переходов state machine (см. executeDiscover в
//     internal/jobs и refreshTransitions в internal/api); статусы, где
//     discovery запрещён или ещё не имеет смысла (draft, validating,
//     discovering, connection_failed, discovery_failed, disabled), не
//     трогаются;
//   - пропускает connections с уже незавершённой операцией discovery
//     (pending_approval/pending/running): пока предыдущий снимок не
//     доехал, новый ставить незачем;
//   - для оставшихся решает свежесть чистой функцией NeedsRediscovery:
//     снимок (last_discovery_at) старше порога либо отсутствует вовсе;
//   - ставит операцию connection.discover идемпотентно (минутное окно
//     jobs.DiscoverOperationKey), enqueue-ит её тем же Dispatcher, что и
//     API, и пишет audit-событие connection.autodiscovery_requested.
//     Routing в connector для execution_mode=connector делает executor —
//     enqueue-путь одинаков с ручным refresh.
package rediscovery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

const (
	// rediscoveryLockClass и rediscoveryLockObj — фиксированный ключ
	// singleton advisory lock прогона авто-rediscovery. Двухаргументная
	// форма pg_try_advisory_xact_lock(classid, objid) — её пространство
	// ключей отдельно от одноаргументных per-connection locks; classid
	// общий с maintenance ("GRAN"), objid свой ("DISC") — прогоны
	// обслуживания и rediscovery друг друга не блокируют.
	rediscoveryLockClass int32 = 0x4752_414e // "GRAN"
	rediscoveryLockObj   int32 = 0x4449_5343 // "DISC"
)

// Актор операций и audit-событий авто-rediscovery: сервисный субъект без
// привязки к человеку, по образцу grantor-maintenance.
const (
	rediscoveryActorType = "service"
	rediscoveryActorID   = "grantor-rediscovery"
)

// auditActionAutodiscoveryRequested — audit action постановки авто-discovery.
// Отличим от connection.refresh_requested ручного refresh (internal/api):
// по actor и action видно, человек нажал кнопку или сработал планировщик.
const auditActionAutodiscoveryRequested = "connection.autodiscovery_requested"

// Config — настройки авто-rediscovery.
type Config struct {
	// Interval — период прогонов планировщика и одновременно порог
	// свежести снимка: connection, чей last_discovery_at старше Interval,
	// получает новую операцию discovery. Значение <= 0 недопустимо для
	// Runner — решение «выключено» принимает cmd/worker по env
	// GRANTOR_DISCOVERY_INTERVAL (0 = планировщик не запускается вовсе).
	Interval time.Duration
}

// Stats — результат одного прогона. Нулевой Stats означает, что прогон
// либо никому не ставил discovery, либо был пропущен (advisory lock
// удерживает другая реплика).
type Stats struct {
	// DiscoveriesRequested — поставлено новых операций discovery.
	DiscoveriesRequested int
	// Deduplicated — connections, для которых операция уже существовала
	// в минутном окне idempotency key (например, гонка с ручным refresh):
	// новая не создавалась.
	Deduplicated int
}

// IsZero сообщает, что прогон не поставил и не переиспользовал ни одной
// операции.
func (s Stats) IsZero() bool {
	return s.DiscoveriesRequested == 0 && s.Deduplicated == 0
}

// NeedsRediscovery — чистая функция «кому пора»: решает, нужен ли
// connection новый discovery. true, когда статус допускает discovery без
// переходов state machine (active, degraded) и снимок старше staleAfter
// либо отсутствует вовсе (lastDiscoveryAt == nil — active без снимка не
// встречается в штатном flow, но пропускать такой connection точно не
// надо). Ровно staleAfter — уже пора: сравнение нестрогое.
func NeedsRediscovery(status connections.Status, lastDiscoveryAt *time.Time, now time.Time, staleAfter time.Duration) bool {
	if status != connections.StatusActive && status != connections.StatusDegraded {
		return false
	}
	if lastDiscoveryAt == nil {
		return true
	}
	return now.Sub(*lastDiscoveryAt) >= staleAfter
}

// Runner выполняет прогоны авто-rediscovery над одним пулом соединений.
type Runner struct {
	pool       *pgxpool.Pool
	cfg        Config
	operations *operations.Store
	dispatcher jobs.Dispatcher
	audit      *audit.Writer
}

// New собирает Runner. Dispatcher обязателен — без него постановка
// discovery невозможна. Audit по умолчанию не пишется (включается через
// WithAudit, как у maintenance.Runner).
func New(pool *pgxpool.Pool, cfg Config, dispatcher jobs.Dispatcher) *Runner {
	return &Runner{
		pool:       pool,
		cfg:        cfg,
		operations: operations.NewStore(),
		dispatcher: dispatcher,
	}
}

// WithAudit включает запись audit-события connection.autodiscovery_requested
// и возвращает тот же Runner (chained wiring в main). nil-writer оставляет
// audit выключенным.
func (r *Runner) WithAudit(w *audit.Writer) *Runner {
	r.audit = w
	return r
}

// Interval возвращает период прогонов (он же порог свежести снимка).
func (r *Runner) Interval() time.Duration {
	return r.cfg.Interval
}

// candidate — connection-кандидат на авто-rediscovery.
type candidate struct {
	id              uuid.UUID
	status          connections.Status
	lastDiscoveryAt *time.Time
}

// RunOnce выполняет один прогон под единой транзакцией, удерживающей
// singleton advisory lock: выборка кандидатов, идемпотентное создание
// операций, enqueue и audit коммитятся вместе. Если lock уже удерживает
// другая реплика worker — прогон тихо пропускается (пустой Stats, nil).
func (r *Runner) RunOnce(ctx context.Context) (Stats, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Stats{}, fmt.Errorf("rediscovery: begin tx: %w", err)
	}
	// После успешного Commit откат — no-op с ErrTxClosed; ошибку
	// игнорируем сознательно.
	defer tx.Rollback(ctx) //nolint:errcheck

	var acquired bool
	if err := tx.QueryRow(ctx,
		`select pg_try_advisory_xact_lock($1, $2)`,
		rediscoveryLockClass, rediscoveryLockObj,
	).Scan(&acquired); err != nil {
		return Stats{}, fmt.Errorf("rediscovery: acquire singleton lock: %w", err)
	}
	if !acquired {
		// Прогон выполняет другая реплика — тихо выходим.
		return Stats{}, nil
	}

	// Кандидаты: статусы, из которых discovery выполняется как есть, без
	// уже незавершённой операции discovery (пока предыдущая не доехала —
	// например, connector offline — новую не плодим). Свежесть снимка
	// решает NeedsRediscovery в Go: единая точка истины, тестируемая без
	// БД. Кандидатов собираем целиком до постановки операций: pgx не даёт
	// выполнять новые запросы на соединении, пока открыт курсор rows.
	rows, err := tx.Query(ctx, `
		select c.id, c.status, c.last_discovery_at
		from connections c
		where c.status in ($1, $2)
		  and not exists (
			select 1 from operations o
			where o.connection_id = c.id
			  and o.kind = $3
			  and o.status in ($4, $5, $6)
		  )
		order by c.id`,
		connections.StatusActive, connections.StatusDegraded,
		jobs.KindConnectionDiscover,
		operations.StatusPendingApproval, operations.StatusPending, operations.StatusRunning,
	)
	if err != nil {
		return Stats{}, fmt.Errorf("rediscovery: select candidates: %w", err)
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.status, &c.lastDiscoveryAt); err != nil {
			rows.Close()
			return Stats{}, fmt.Errorf("rediscovery: scan candidate: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return Stats{}, fmt.Errorf("rediscovery: select candidates: %w", err)
	}

	now := time.Now()
	var stats Stats
	for i := range candidates {
		c := &candidates[i]
		if !NeedsRediscovery(c.status, c.lastDiscoveryAt, now, r.cfg.Interval) {
			continue
		}
		created, err := r.requestDiscovery(ctx, tx, c, now)
		if err != nil {
			return Stats{}, err
		}
		if created {
			stats.DiscoveriesRequested++
		} else {
			stats.Deduplicated++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Stats{}, fmt.Errorf("rediscovery: commit: %w", err)
	}
	return stats, nil
}

// requestDiscovery ставит операцию discovery для одного connection тем же
// путём, что refreshConnection в API: идемпотентное создание по ключу
// минутного окна, транзакционный enqueue и audit-событие. Если операция
// уже существует (created=false — гонка с ручным refresh в том же окне),
// повторный enqueue и audit не выполняются.
func (r *Runner) requestDiscovery(ctx context.Context, tx pgx.Tx, c *candidate, now time.Time) (bool, error) {
	key := jobs.DiscoverOperationKey(c.id, now)
	connectionID := c.id
	op, created, err := r.operations.Create(ctx, tx, operations.CreateParams{
		Kind:           jobs.KindConnectionDiscover,
		IdempotencyKey: &key,
		ConnectionID:   &connectionID,
		ActorType:      rediscoveryActorType,
		ActorID:        rediscoveryActorID,
		CorrelationID:  uuid.NewString(),
	})
	if err != nil {
		return false, fmt.Errorf("rediscovery: create discover operation for connection %s: %w", c.id, err)
	}
	if !created {
		return false, nil
	}
	if err := r.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return false, fmt.Errorf("rediscovery: enqueue discover operation for connection %s: %w", c.id, err)
	}
	if err := r.writeRequestedAudit(ctx, tx, c, op.ID); err != nil {
		return false, err
	}
	return true, nil
}

// writeRequestedAudit пишет audit-событие connection.autodiscovery_requested
// для поставленной операции. No-op, если Writer не задан. Metadata несёт
// причину постановки: возраст снимка относительно порога свежести.
func (r *Runner) writeRequestedAudit(ctx context.Context, tx pgx.Tx, c *candidate, opID uuid.UUID) error {
	if r.audit == nil {
		return nil
	}
	var lastDiscoveryAt any
	if c.lastDiscoveryAt != nil {
		lastDiscoveryAt = c.lastDiscoveryAt.UTC().Format(time.RFC3339Nano)
	}
	meta, err := json.Marshal(map[string]any{
		"reason":            "stale_snapshot",
		"last_discovery_at": lastDiscoveryAt,
		"stale_after":       r.cfg.Interval.String(),
	})
	if err != nil {
		return fmt.Errorf("rediscovery: marshal audit metadata for connection %s: %w", c.id, err)
	}
	connectionID := c.id
	operationID := opID
	event := audit.Event{
		ActorType:    rediscoveryActorType,
		ActorID:      rediscoveryActorID,
		Action:       auditActionAutodiscoveryRequested,
		ConnectionID: &connectionID,
		OperationID:  &operationID,
		Result:       audit.ResultSuccess,
		Metadata:     meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("rediscovery: write autodiscovery_requested audit for connection %s: %w", c.id, err)
	}
	return nil
}
