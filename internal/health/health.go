// Package health — HTTP handlers для liveness/readiness probes
// (docs/architecture.md, раздел 27.7). Readiness агрегирует именованные
// проверки зависимостей; тексты их ошибок наружу не отдаются — в ответ
// попадают только имена отказавших checks, сами ошибки логируются slog.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// probeTimeout — максимальная длительность одного probe. Переменная,
// а не константа, чтобы тесты могли сократить ожидание.
var probeTimeout = 2 * time.Second

// Check — именованная проверка зависимости для readiness probe.
type Check struct {
	// Name — имя проверки; попадает в JSON-ответ при отказе.
	Name string
	// Probe возвращает nil, когда зависимость доступна. Обязан уважать
	// отмену ctx.
	Probe func(ctx context.Context) error
}

// readyResponse — тело ответа readiness handler.
type readyResponse struct {
	Status string   `json:"status"`
	Failed []string `json:"failed,omitempty"`
}

// Handler возвращает readiness handler: 200 при успехе всех checks,
// 503 с JSON {"status":"unavailable","failed":["name"]} при отказе.
// Каждый probe ограничен probeTimeout; проверки выполняются
// последовательно, порядок имён в failed совпадает с порядком checks.
func Handler(checks ...Check) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var failed []string
		for _, c := range checks {
			if err := runProbe(r.Context(), c); err != nil {
				slog.ErrorContext(r.Context(), "readiness check failed",
					"check", c.Name, "error", err)
				failed = append(failed, c.Name)
			}
		}

		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, readyResponse{
				Status: "unavailable",
				Failed: failed,
			})
			return
		}
		writeJSON(w, http.StatusOK, readyResponse{Status: "ok"})
	})
}

// LiveHandler возвращает liveness handler: всегда 200, пока процесс
// способен отвечать на HTTP.
func LiveHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, readyResponse{Status: "ok"})
	})
}

// runProbe выполняет один probe с таймаутом probeTimeout. Probe
// запускается в отдельной goroutine, поэтому даже зависший probe,
// игнорирующий ctx, не задержит ответ дольше таймаута (его goroutine
// доживёт до собственного завершения — утечка ограничена временем
// жизни зависшего вызова).
func runProbe(ctx context.Context, c Check) error {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Probe(ctx) }()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("health: check %s: %w", c.Name, ctx.Err())
	}
}

// writeJSON пишет JSON-ответ с заданным статусом. Ошибка записи не
// возвращается: ответ уже начат, повлиять на него нельзя.
func writeJSON(w http.ResponseWriter, status int, body readyResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("health: write response", "error", err)
	}
}
