package maintenance

import (
	"context"
	"log/slog"
	"time"
)

// Scheduler периодически запускает прогоны обслуживания (Runner.RunOnce)
// по тикеру. Singleton между репликами worker обеспечивает сам Runner
// через advisory lock, поэтому Scheduler можно запускать на каждой
// реплике без координации.
type Scheduler struct {
	runner   *Runner
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler собирает Scheduler. Нулевой interval заменяется дефолтом,
// nil logger — slog.Default().
func NewScheduler(runner *Runner, interval time.Duration, logger *slog.Logger) *Scheduler {
	if interval <= 0 {
		interval = defaultInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{runner: runner, interval: interval, logger: logger}
}

// Start запускает цикл обслуживания и блокирует до отмены ctx. Первый
// прогон выполняется сразу, далее — каждые interval. Отмена ctx (например,
// при shutdown worker) завершает цикл: прогон в процессе получает
// отменённый ctx, его транзакция откатывается, а следующий старт worker
// повторит идемпотентное обслуживание. Ошибки прогонов best-effort —
// логируются и не прерывают цикл.
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.Info("maintenance scheduler started", "interval", s.interval)

	if ctx.Err() == nil {
		s.runOnce(ctx)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("maintenance scheduler stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce выполняет один прогон и логирует итог. Пустой Stats (нечего
// делать либо lock удерживает другая реплика) логируется на Debug, чтобы
// не шуметь; непустой — на Info. Ошибка при отменённом ctx (shutdown) не
// логируется как сбой.
func (s *Scheduler) runOnce(ctx context.Context) {
	stats, err := s.runner.RunOnce(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.logger.Error("maintenance run failed", "error", err)
		return
	}
	if stats.IsZero() {
		s.logger.Debug("maintenance run: nothing to do")
		return
	}
	s.logger.Info("maintenance run completed",
		"missing_resources_deleted", stats.MissingResourcesDeleted,
		"operations_deleted", stats.OperationsDeleted,
		"bindings_expired", stats.BindingsExpired,
		"admin_credentials_aged", stats.AdminCredentialsAged,
		"principals_disabled", stats.PrincipalsDisabled,
		"offboarding_incomplete", stats.OffboardingIncomplete,
		"principals_purged", stats.PrincipalsPurged,
		"purge_deletes_enqueued", stats.PurgeDeletesEnqueued,
	)
}
