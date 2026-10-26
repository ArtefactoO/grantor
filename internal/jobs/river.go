package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"

	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

// Config — настройки River-диспетчера. Нулевые поля заполняются
// дефолтами (см. withDefaults).
type Config struct {
	// Queue — имя очереди River. Default: river.QueueDefault.
	Queue string
	// WorkerCount — максимум одновременных jobs. Default: 4.
	WorkerCount int
	// MaxAttempts — bounded retries: максимум попыток job, включая
	// первую; backoff/jitter — политика River. Default: 5.
	MaxAttempts int
	// JobTimeout — deadline одного выполнения job. Default: 5m.
	JobTimeout time.Duration
	// SnoozeOnLock — пауза перед повтором, когда connection lock занят
	// или операция ждёт approve. Snooze не расходует attempts.
	// Default: 5s.
	SnoozeOnLock time.Duration
}

// withDefaults возвращает копию конфигурации с заполненными дефолтами.
func (c Config) withDefaults() Config {
	if c.Queue == "" {
		c.Queue = river.QueueDefault
	}
	if c.WorkerCount <= 0 {
		c.WorkerCount = 4
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.JobTimeout <= 0 {
		c.JobTimeout = 5 * time.Minute
	}
	if c.SnoozeOnLock <= 0 {
		c.SnoozeOnLock = 5 * time.Second
	}
	return c
}

// River — реализация Dispatcher на River poller поверх PostgreSQL:
// durable jobs без внешнего broker (раздел 19 архитектуры).
type River struct {
	client *river.Client[pgx.Tx]
	cfg    Config
}

var _ Dispatcher = (*River)(nil)

// New собирает River-клиент с одним worker для OperationArgs.
func New(pool *pgxpool.Pool, store *operations.Store, exec Executor, cfg Config) (*River, error) {
	cfg = cfg.withDefaults()

	workers := river.NewWorkers()
	worker := &operationWorker{
		pool:  pool,
		store: store,
		exec:  exec,
		cfg:   cfg,
	}
	if err := river.AddWorkerSafely[OperationArgs](workers, worker); err != nil {
		return nil, fmt.Errorf("jobs: register operation worker: %w", err)
	}

	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Queues: map[string]river.QueueConfig{
			cfg.Queue: {MaxWorkers: cfg.WorkerCount},
		},
		Workers: workers,
	})
	if err != nil {
		return nil, fmt.Errorf("jobs: create river client: %w", err)
	}
	worker.enqueue = func(ctx context.Context, tx pgx.Tx, args OperationArgs) error {
		_, err := client.InsertTx(ctx, tx, args, &river.InsertOpts{
			Queue: cfg.Queue, MaxAttempts: cfg.MaxAttempts,
		})
		return err
	}
	return &River{client: client, cfg: cfg}, nil
}

// Start запускает обработку jobs.
func (r *River) Start(ctx context.Context) error {
	if err := r.client.Start(ctx); err != nil {
		return fmt.Errorf("jobs: start river client: %w", err)
	}
	return nil
}

// Stop мягко останавливает обработку: ждёт завершения активных jobs
// либо отмены ctx.
func (r *River) Stop(ctx context.Context) error {
	if err := r.client.Stop(ctx); err != nil {
		return fmt.Errorf("jobs: stop river client: %w", err)
	}
	return nil
}

// EnqueueOperationTx ставит job выполнения операции в переданной
// транзакции — той же, где создана строка operations (см. Dispatcher).
func (r *River) EnqueueOperationTx(ctx context.Context, tx pgx.Tx, operationID uuid.UUID) error {
	return r.EnqueueOperationSequenceTx(ctx, tx, operationID)
}

// EnqueueOperationSequenceTx сохраняет цепочку в аргументах первого job.
// Worker ставит следующий job в той же транзакции, где фиксирует success
// предыдущей операции. Поэтому параллельные workers не могут переставить
// account.create и зависящий от него access.grant местами.
func (r *River) EnqueueOperationSequenceTx(ctx context.Context, tx pgx.Tx, operationIDs ...uuid.UUID) error {
	if len(operationIDs) == 0 {
		return nil
	}
	_, err := r.client.InsertTx(ctx, tx, OperationArgs{
		OperationID:      operationIDs[0],
		NextOperationIDs: operationIDs[1:],
	}, &river.InsertOpts{
		Queue:       r.cfg.Queue,
		MaxAttempts: r.cfg.MaxAttempts,
	})
	if err != nil {
		return fmt.Errorf("jobs: enqueue operation %s: %w", operationIDs[0], err)
	}
	return nil
}

func (w *operationWorker) enqueueNext(ctx context.Context, tx pgx.Tx, operationIDs []uuid.UUID) error {
	if len(operationIDs) == 0 {
		return nil
	}
	if err := w.enqueue(ctx, tx, OperationArgs{
		OperationID: operationIDs[0], NextOperationIDs: operationIDs[1:],
	}); err != nil {
		return fmt.Errorf("jobs: enqueue dependent operation %s: %w", operationIDs[0], err)
	}
	return nil
}

// MigrateUp применяет миграции служебных таблиц River. Идемпотентно;
// используется тестами и будущим db-migrate Job.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return fmt.Errorf("jobs: create river migrator: %w", err)
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, nil); err != nil {
		return fmt.Errorf("jobs: apply river migrations: %w", err)
	}
	return nil
}

// operationWorker выполняет job "operation.execute".
//
// Семантика транзакций: весь Work — одна транзакция metadata database:
// advisory lock connection, переход в running, Execute и финальный
// переход коммитятся вместе. Так выбрано потому, что
// pg_advisory_xact_lock живёт ровно до конца транзакции — раздельные
// короткие транзакции отпустили бы lock до Execute и сломали гарантию
// «не более одной mutating operation на connection». Следствия:
//   - при падении worker посреди Execute транзакция откатывается,
//     операция остаётся в pending, lock освобождается сервером, River
//     повторяет job — durable без ручной очистки;
//   - при ошибке Execute транзакция коммитится со статусом failed
//     (не rollback!), чтобы ошибка и finished_at сохранились; затем
//     ошибка возвращается River для retry с backoff — кроме
//     детерминированных отказов (terminal.go), которые снимаются с
//     ретраев сразу через river.JobCancel;
//   - промежуточный статус running не виден снаружи до конца
//     транзакции. Для W0 это приемлемо; TODO(этап 1): перейти на
//     session-level advisory lock + отдельные короткие транзакции,
//     чтобы UI видел running живьём.
type operationWorker struct {
	river.WorkerDefaults[OperationArgs]

	pool    *pgxpool.Pool
	store   *operations.Store
	exec    Executor
	cfg     Config
	enqueue func(context.Context, pgx.Tx, OperationArgs) error
}

// Timeout ограничивает длительность одного выполнения job.
func (w *operationWorker) Timeout(*river.Job[OperationArgs]) time.Duration {
	return w.cfg.JobTimeout
}

// Work выполняет одну операцию. См. семантику транзакций в комментарии
// к operationWorker.
func (w *operationWorker) Work(ctx context.Context, job *river.Job[OperationArgs]) error {
	opID := job.Args.OperationID

	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: operation %s: begin tx: %w", opID, err)
	}
	// После успешного Commit откат — no-op с ErrTxClosed; ошибку
	// игнорируем сознательно.
	defer tx.Rollback(ctx) //nolint:errcheck

	op, err := w.store.Get(ctx, tx, opID)
	if err != nil {
		return fmt.Errorf("jobs: operation %s: load: %w", opID, err)
	}
	if op.ParentID != nil {
		parent, err := w.store.Get(ctx, tx, *op.ParentID)
		if err != nil {
			return err
		}
		if parent.Kind == KindDatabaseCreateWithRoles || parent.Kind == KindPostgresDatabaseCreateWithRolesV2 {
			// These children execute only inline under the root lock. A stale
			// or manually enqueued child must not bypass its durable receipts.
			return river.JobCancel(errors.New("database workflow children can only execute through their root operation"))
		}
	}

	switch {
	case op.Status.IsTerminal():
		// Повторная доставка job после уже завершённой операции
		// (например, retry после сбоя на записи результата job) —
		// идемпотентно выходим. Перед выходом добираем финализацию
		// parent: у детей, завершённых до появления финализации в коде
		// (или в окне деплоя), parent мог остаться в running.
		changed := false
		if op.Status == operations.StatusSuccess && len(job.Args.NextOperationIDs) > 0 {
			if err := w.enqueueNext(ctx, tx, job.Args.NextOperationIDs); err != nil {
				return fmt.Errorf("jobs: operation %s: continue sequence: %w", opID, err)
			}
			changed = true
		}
		if op.ParentID != nil {
			if _, _, err := w.store.FinalizeParent(ctx, tx, *op.ParentID); err != nil {
				return fmt.Errorf("jobs: operation %s: finalize parent: %w", opID, err)
			}
			changed = true
		}
		if changed {
			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("jobs: operation %s: commit terminal recovery: %w", opID, err)
			}
		}
		return nil
	case op.Status == operations.StatusPendingApproval:
		// Операция ждёт approve; job перепланируется, attempts не
		// расходуются.
		return river.JobSnooze(w.cfg.SnoozeOnLock)
	case op.Status == operations.StatusRunning:
		// running не коммитится как промежуточный статус, поэтому сюда
		// можно попасть только при внешнем вмешательстве. Не трогаем
		// операцию, ждём разрешения ситуации.
		// TODO(этап 1): восстановление зависших running операций.
		return river.JobSnooze(w.cfg.SnoozeOnLock)
	case op.Status == operations.StatusFailed && hasTerminalErrorText(op.Error):
		// Предыдущая попытка уже зафиксировала детерминированную причину
		// (см. terminal.go). Повторная доставка job не выполняет операцию
		// заново и не трогает строку: иначе новая попытка затёрла бы
		// исходный текст ошибки более поздним и менее точным. Ручной retry
		// сюда не попадает — он сам переводит операцию failed -> pending и
		// очищает error.
		return river.JobCancel(errors.New(op.Error))
	}

	// Не более одной mutating operation на connection одновременно:
	// transaction-scoped advisory lock по connection_id. Если lock
	// занят — перепланируем job без расхода attempts.
	if op.ConnectionID != nil {
		acquired, err := locks.TryAcquireTx(ctx, tx, *op.ConnectionID)
		if err != nil {
			return fmt.Errorf("jobs: operation %s: %w", opID, err)
		}
		if !acquired {
			return river.JobSnooze(w.cfg.SnoozeOnLock)
		}
		blocked, err := admincredentials.NewStore().BlocksOperation(ctx, tx, *op.ConnectionID, op.ID)
		if err != nil {
			return fmt.Errorf("jobs: operation %s: credential change fence: %w", opID, err)
		}
		if blocked {
			return river.JobSnooze(w.cfg.SnoozeOnLock)
		}
	}

	// failed/partial -> pending: retry (ручной из UI или автоматический
	// повтор River). Пустой TransitionOpts.Error очищает прошлую ошибку.
	if op.Status == operations.StatusFailed || op.Status == operations.StatusPartial {
		op, err = w.store.Transition(ctx, tx, opID, op.Status, operations.StatusPending, operations.TransitionOpts{})
		if err != nil {
			return fmt.Errorf("jobs: operation %s: reset for retry: %w", opID, err)
		}
		// Retry ребёнка bulk-операции возвращает финализированный parent
		// из partial/failed обратно в running: пока ребёнок выполняется
		// заново, итог parent неизвестен. При завершении последнего
		// ребёнка FinalizeParent ниже финализирует parent повторно.
		if op.ParentID != nil {
			if _, _, err := w.store.ReviveParent(ctx, tx, *op.ParentID); err != nil {
				return fmt.Errorf("jobs: operation %s: revive parent: %w", opID, err)
			}
		}
	}

	op, err = w.store.Transition(ctx, tx, opID, operations.StatusPending, operations.StatusRunning, operations.TransitionOpts{})
	if err != nil {
		return fmt.Errorf("jobs: operation %s: mark running: %w", opID, err)
	}

	execErr := w.exec.Execute(ctx, op)

	final := operations.StatusSuccess
	var opts operations.TransitionOpts
	// Sanitized plan/result, построенные executor во время Execute,
	// сохраняются при финальном переходе — атомарно со статусом. При
	// однотранзакционном Work это снаружи неотличимо от записи плана в
	// момент перехода в running: running не виден до конца транзакции.
	// Nil-поля оставляют прежние значения колонок (TransitionOpts).
	if src, ok := w.exec.(operationArtifactsSource); ok {
		artifacts := src.TakeOperationArtifacts(opID)
		opts.Plan = artifacts.Plan
		opts.Result = artifacts.Result
	}
	terminalErr := isTerminal(execErr)
	if execErr != nil {
		final = operations.StatusFailed
		opts.Error = execErr.Error()
		// Детерминированная причина помечается durable-маркером: он
		// сохраняет исходный текст и запрещает более поздней попытке
		// подменить его (см. terminal.go и ветку failed выше).
		if terminalErr {
			opts.Error = markTerminalErrorText(opts.Error)
		}
	}
	if _, err := w.store.Transition(ctx, tx, opID, operations.StatusRunning, final, opts); err != nil {
		return errors.Join(fmt.Errorf("jobs: operation %s: mark %s: %w", opID, final, err), execErr)
	}
	if execErr != nil && rolePolicyTransitionActionForKind(op.Kind) != "" &&
		shouldCancelDependents(terminalErr, job.Attempt, job.MaxAttempts) {
		if err := rolepolicies.NewStore().MarkRetryExhausted(ctx, tx, op.ID); err != nil {
			return errors.Join(fmt.Errorf("jobs: operation %s: finalize role policy retry ownership: %w", opID, err), execErr)
		}
	}
	if execErr != nil && (op.Kind == KindDatabaseCreateWithRoles || op.Kind == KindPostgresDatabaseCreateWithRolesV2) &&
		shouldCancelDependents(terminalErr, job.Attempt, job.MaxAttempts) {
		children, err := w.store.ListByParent(ctx, tx, op.ID)
		if err != nil {
			return err
		}
		for _, child := range children {
			if (child.Kind == KindRolePolicyCreateDatabase || child.Kind == KindPostgresRolePolicyCreateDatabaseV2) &&
				child.Status != operations.StatusSuccess {
				if err := rolepolicies.NewStore().MarkRetryExhausted(ctx, tx, child.ID); err != nil {
					return err
				}
			}
		}
	}
	if execErr == nil {
		if err := w.enqueueNext(ctx, tx, job.Args.NextOperationIDs); err != nil {
			return fmt.Errorf("jobs: operation %s: continue sequence: %w", opID, err)
		}
	} else if shouldCancelDependents(terminalErr, job.Attempt, job.MaxAttempts) {
		if err := w.cancelDependents(ctx, tx, opID, job.Args.NextOperationIDs); err != nil {
			return errors.Join(fmt.Errorf("jobs: operation %s: cancel dependents: %w", opID, err), execErr)
		}
	}
	// Терминальный итог ребёнка bulk-операции финализирует parent в той же
	// транзакции: когда завершился последний ребёнок, parent атомарно
	// переходит running -> success | partial | failed (FinalizeParent
	// сериализует конкурентные завершения row-level lock'ом parent).
	if op.ParentID != nil {
		if _, _, err := w.store.FinalizeParent(ctx, tx, *op.ParentID); err != nil {
			return errors.Join(fmt.Errorf("jobs: operation %s: finalize parent: %w", opID, err), execErr)
		}
	}
	// Fault boundary для restore crash-recovery: hook вызывается после
	// executor side-effect и финального Transition, но до commit outer tx.
	// Ошибка откатывает status/plan/result; durable restore metadata остаётся,
	// поэтому retry обязан восстановить артефакты из lifecycle state.
	if hook, ok := w.exec.(operationCommitHook); execErr == nil && ok {
		if err := hook.BeforeOperationCommit(ctx, op); err != nil {
			return errors.Join(fmt.Errorf("jobs: operation %s: before commit: %w", opID, err), execErr)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(fmt.Errorf("jobs: operation %s: commit: %w", opID, err), execErr)
	}
	if execErr != nil {
		// Статус failed уже закоммичен; возвращаем ошибку, чтобы River
		// повторил job по своей политике backoff в пределах MaxAttempts.
		err := fmt.Errorf("jobs: operation %s: execute: %w", opID, execErr)
		if terminalErr {
			// Детерминированный отказ: повтор даст тот же результат, а
			// пока он идёт, состояние вокруг операции может измениться и
			// подменить причину. JobCancel снимает job с ретраев сразу
			// (river_job переходит в cancelled, а не в retryable), поэтому
			// операция падает с первой попытки и с исходной причиной.
			return river.JobCancel(err)
		}
		return err
	}
	return nil
}

// shouldCancelDependents решает, отменять ли хвост последовательности после
// неуспешной попытки.
//
// Отменять нужно на ЛЮБОМ окончательном исходе: и когда попытки исчерпаны, и
// когда причина детерминированная. Второе условие обязательно и появилось не
// сразу: терминальная ошибка уходит через river.JobCancel уже на первой
// попытке, поэтому проверка attempt >= maxAttempts для неё не выполняется
// никогда. Пока её не было, зависимые операции оставались pending, а
// bulk-родитель — running навсегда, и починить это через API было нельзя.
func shouldCancelDependents(terminal bool, attempt, maxAttempts int) bool {
	return terminal || attempt >= maxAttempts
}

// cancelDependents завершает ещё не поставленный хвост последовательности,
// если prerequisite исчерпал автоматические попытки. Иначе bulk parent
// навсегда остался бы running из-за pending-операций без River jobs.
func (w *operationWorker) cancelDependents(ctx context.Context, tx pgx.Tx, prerequisite uuid.UUID, operationIDs []uuid.UUID) error {
	for _, id := range operationIDs {
		op, err := w.store.Get(ctx, tx, id)
		if err != nil {
			return err
		}
		if op.Status == operations.StatusPending || op.Status == operations.StatusPendingApproval {
			if _, err := w.store.Transition(ctx, tx, id, op.Status, operations.StatusCancelled, operations.TransitionOpts{
				Error: fmt.Sprintf("prerequisite operation %s failed", prerequisite),
			}); err != nil {
				return err
			}
		}
		if op.ParentID != nil {
			if _, _, err := w.store.FinalizeParent(ctx, tx, *op.ParentID); err != nil {
				return err
			}
		}
	}
	return nil
}
