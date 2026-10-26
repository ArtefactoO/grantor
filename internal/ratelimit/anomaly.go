package ratelimit

// AnomalyDetector — детекция аномально высокой частоты per-subject поверх
// того же PostgreSQL, что и token-bucket (docs/threat-model.md, разделы 24/
// 25; docs/adr/0011-security-findings-audit-metrics.md). Закрывает P1 «alert
// на аномальную частоту credential reveal/share».
//
// # Отличие от Limiter
//
// Limiter enforce-ит лимит (списывает токен, отклоняет запрос). Detector
// НЕ блокирует — он лишь считает события в скользящем окне и сообщает, когда
// субъект впервые за окно превысил порог. Сигнал (audit security.*) уходит в
// SIEM, запрос при этом не отклоняется (rate limiting — отдельный контур).
//
// # Почему PostgreSQL, а не память процесса
//
// api работает в нескольких репликах. Честный per-subject счёт и троттлинг
// сигнала «один на субъект за окно» между репликами требует общего
// состояния; координация и так в этой базе (как rate_limit_buckets).
//
// # Атомарность и троттлинг
//
// Одна строка на субъект (credential_reveal_windows). Инкремент и решение
// «сигналить ли» выполняются одним statement под row-lock: upsert крутит
// скользящее окно (сброс счётчика при выходе за window) и инкрементит, затем
// claim атомарно выставляет last_alerted_at, если порог достигнут и с
// прошлого сигнала прошло не меньше окна. Конкурентные вызовы одного субъекта
// сериализуются на строке, поэтому сигнал получает ровно один вызов за окно
// (throttled), даже с несколькими репликами.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AnomalyWindow — параметры окна детекции аномалии.
type AnomalyWindow struct {
	// Threshold — порог: сигнал возможен, когда число событий субъекта в
	// текущем окне достигает этого значения. Threshold <= 0 отключает
	// детекцию (см. Enabled).
	Threshold int
	// Window — длина скользящего окна счёта и одновременно интервал
	// троттлинга сигнала (не чаще одного на субъект за окно).
	Window time.Duration
}

// Enabled сообщает, включена ли детекция: нужны положительный порог и окно.
func (w AnomalyWindow) Enabled() bool {
	return w.Threshold > 0 && w.Window > 0
}

// AnomalyDetector считает per-subject события в скользящем окне (общий
// счётчик в PostgreSQL) и сообщает о первом за окно превышении порога.
type AnomalyDetector struct {
	pool *pgxpool.Pool
}

// NewAnomalyDetector возвращает AnomalyDetector поверх пула metadata
// database.
func NewAnomalyDetector(pool *pgxpool.Pool) *AnomalyDetector {
	return &AnomalyDetector{pool: pool}
}

// observeSQL атомарно крутит скользящее окно субъекта, инкрементит счётчик и
// решает, сигналить ли аномалию — одним INSERT ... ON CONFLICT DO UPDATE (без
// второго data-modifying CTE: два изменения одной строки в одном statement
// имеют неопределённую видимость снапшота в PostgreSQL).
//
// $1 key, $2 window (interval), $3 threshold. Новый субъект: строка с
// event_count=1 и last_alerted_at=now() только если порог уже 1. Существующий
// (ON CONFLICT DO UPDATE, алиас w — старая строка): если с window_start прошло
// не меньше окна — новое окно (window_start=now, count=1), иначе count+1. Все
// ветви SET читают старые значения w одновременно, поэтому согласованы.
// last_alerted_at выставляется в now() только когда новый count достиг порога
// И с прошлого сигнала прошло не меньше окна (троттлинг «один на окно»); иначе
// сохраняется. now() — transaction_timestamp, стабилен в statement, поэтому
// RETURNING (last_alerted_at = now()) истинно ровно у того вызова, что сейчас
// выставил сигнал. Под конкуренцией одного субъекта вызовы сериализуются
// row-lock ON CONFLICT (READ COMMITTED перечитывает актуальную строку),
// поэтому сигнал получает ровно один вызов за окно.
const observeSQL = `
insert into credential_reveal_windows as w (subject, window_start, event_count, last_alerted_at)
values ($1, now(), 1, case when 1 >= $3 then now() else null end)
on conflict (subject) do update
set window_start = case
        when now() - w.window_start >= $2::interval then now()
        else w.window_start end,
    event_count = case
        when now() - w.window_start >= $2::interval then 1
        else w.event_count + 1 end,
    last_alerted_at = case
        when (case when now() - w.window_start >= $2::interval then 1 else w.event_count + 1 end) >= $3
             and (w.last_alerted_at is null or now() - w.last_alerted_at >= $2::interval)
        then now()
        else w.last_alerted_at end
returning event_count, (last_alerted_at is not null and last_alerted_at = now()) as should_alert`

// Observe регистрирует одно событие субъекта key и возвращает текущий счётчик
// событий в окне и признак сигнала. alert == true ровно один раз за окно — у
// того вызова, что первым довёл счётчик до порога (throttled). При отключённой
// детекции (w.Enabled() == false) — no-op: (0, false, nil). Ошибка означает
// недоступность базы; вызывающий решает, как реагировать (api — логирует и не
// сигналит, не роняя основной путь reveal/share).
func (d *AnomalyDetector) Observe(ctx context.Context, key string, w AnomalyWindow) (count int, alert bool, err error) {
	if !w.Enabled() {
		return 0, false, nil
	}
	err = d.pool.QueryRow(ctx, observeSQL, key, w.Window, w.Threshold).Scan(&count, &alert)
	if err != nil {
		return 0, false, fmt.Errorf("ratelimit: observe anomaly %q: %w", key, err)
	}
	return count, alert, nil
}

// RevealAnomalyKey возвращает ключ окна аномалии reveal/share по subject.
// Использует тот же префикс, что и ведро reveal (RevealKey), но живёт в
// отдельной таблице credential_reveal_windows, поэтому коллизии с лимитером
// нет; общий префикс лишь помечает поверхность.
func RevealAnomalyKey(subject string) string { return keyPrefixReveal + subject }
