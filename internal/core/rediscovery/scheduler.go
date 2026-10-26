package rediscovery

import (
	"context"
	"log/slog"
	"time"
)

// Scheduler периодически запускает прогоны авто-rediscovery
// (Runner.RunOnce) по тикеру — устройство зеркалит maintenance.Scheduler.
// Singleton между репликами worker обеспечивает сам Runner через advisory
// lock, поэтому Scheduler можно запускать на каждой реплике без
// координации.
type Scheduler struct {
	runner   *Runner
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler собирает Scheduler. Interval берётся из Runner (он же
// порог свежести снимка) и обязан быть > 0 — проверяет cmd/worker; nil
// logger заменяется slog.Default().
func NewScheduler(runner *Runner, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{runner: runner, interval: runner.Interval(), logger: logger}
}

// Start запускает цикл авто-rediscovery и блокирует до отмены ctx. Первый
// прогон выполняется сразу, далее — каждые interval. Отмена ctx (например,
// при shutdown worker) завершает цикл: прогон в процессе получает
// отменённый ctx, его транзакция откатывается, а следующий старт worker
// повторит идемпотентную постановку. Ошибки прогонов best-effort —
// логируются и не прерывают цикл.
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.Info("rediscovery scheduler started", "interval", s.interval)

	if ctx.Err() == nil {
		s.runOnce(ctx)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("rediscovery scheduler stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce выполняет один прогон и логирует итог. Пустой Stats (все снимки
// свежие либо lock удерживает другая реплика) логируется на Debug, чтобы
// не шуметь; непустой — на Info. Ошибка при отменённом ctx (shutdown) не
// логируется как сбой.
func (s *Scheduler) runOnce(ctx context.Context) {
	stats, err := s.runner.RunOnce(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		s.logger.Error("rediscovery run failed", "error", err)
		return
	}
	if stats.IsZero() {
		s.logger.Debug("rediscovery run: nothing to do")
		return
	}
	s.logger.Info("rediscovery run completed",
		"discoveries_requested", stats.DiscoveriesRequested,
		"deduplicated", stats.Deduplicated,
	)
}
