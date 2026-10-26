package credentialcheck

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Scheduler периодически запускает прогоны сверки (Runner.RunOnce) по
// тикеру — устройство зеркалит rediscovery.Scheduler и maintenance.Scheduler.
// Singleton между репликами worker обеспечивает сам Runner через advisory
// lock, поэтому Scheduler можно запускать на каждой реплике без координации.
type Scheduler struct {
	runner   *Runner
	interval time.Duration
	logger   *slog.Logger
}

// NewScheduler собирает Scheduler. Interval берётся из Runner и обязан быть
// > 0 — проверяет cmd/worker; nil logger заменяется slog.Default().
func NewScheduler(runner *Runner, logger *slog.Logger) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{runner: runner, interval: runner.Interval(), logger: logger}
}

// Start запускает цикл сверки и блокирует до отмены ctx. Первый прогон
// выполняется сразу, далее — каждые interval. Ошибки прогонов best-effort:
// логируются и не прерывают цикл — расхождение подождёт следующего прогона,
// а падать из-за недоступного Vault планировщику незачем.
func (s *Scheduler) Start(ctx context.Context) {
	s.logger.Info("credential check scheduler started", "interval", s.interval)

	if ctx.Err() == nil {
		s.runOnce(ctx)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("credential check scheduler stopped")
			return
		case <-ticker.C:
			s.runOnce(ctx)
		}
	}
}

// runOnce выполняет один прогон и логирует итог. Пустой Stats (сверять
// нечего либо lock удерживает другая реплика) логируется на Debug, чтобы не
// шуметь. Ошибка при отменённом ctx (shutdown) сбоем не считается.
func (s *Scheduler) runOnce(ctx context.Context) {
	stats, err := s.runner.RunOnce(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			return
		}
		s.logger.Error("credential check run failed", "error", err)
		return
	}
	if stats.IsZero() {
		s.logger.Debug("credential check run: nothing to do")
		return
	}
	s.logger.Info("credential check run",
		"paths_checked", stats.PathsChecked,
		"accounts_checked", stats.AccountsChecked,
		"diverged", stats.Diverged,
		"newly_diverged", stats.NewlyDiverged,
		"paths_unavailable", stats.PathsUnavailable)
}
