// Package ratelimit реализует общий (между репликами) token-bucket на
// PostgreSQL. Он закрывает P0 «rate limiting» из docs/threat-model.md
// (раздел 3.5) и ADR-0007: брутфорс логина, флуд credential reveal/share и
// мутирующих API-запросов.
//
// # Почему PostgreSQL, а не память процесса
//
// api работает в нескольких репликах за nginx. In-memory лимит на реплику
// даёт нечестный суммарный лимит (N реплик = N-кратный лимит) и не
// координируется. Метаданные и координация и так живут в PostgreSQL, а
// чувствительные вызовы (login/reveal/mutating) редки, поэтому нагрузка на
// базу незначительна. Один общий счётчик на ключ даёт честный лимит для
// всего кластера.
//
// # Алгоритм
//
// Классический token-bucket. У ключа есть ведро ёмкостью Burst, которое
// пополняется со скоростью Rate токенов в секунду (но не выше Burst). Каждый
// разрешённый запрос списывает один токен. При первом обращении ведро
// создаётся полным. refill считается по времени PostgreSQL (now()), а не Go,
// чтобы реплики видели согласованное время.
//
// # Атомарность
//
// Списание атомарно на строке: строка ведра существует (гарантируется
// INSERT ... ON CONFLICT DO NOTHING), затем один statement под row-lock
// (SELECT ... FOR UPDATE в CTE) пересчитывает уровень и списывает токен.
// Advisory lock не используется намеренно (дорого и глобально) — блокировки
// строки достаточно и она скоупится ключом. Конкурентные вызовы одного ключа
// сериализуются на этой строке, поэтому суммарно за интервал списывается не
// больше Burst + Rate*elapsed токенов.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Префиксы ключей ведра по поверхностям (см. package doc). Ключ = префикс +
// субъект: IP для login, IdP subject для reveal/mutating.
const (
	keyPrefixLogin    = "login:"
	keyPrefixReveal   = "reveal:"
	keyPrefixMutating = "mutating:"
)

// LoginKey возвращает ключ ведра логина по IP клиента (per-IP лимит).
func LoginKey(ip string) string { return keyPrefixLogin + ip }

// RevealKey возвращает ключ ведра credential reveal/share по subject
// (per-principal-subject лимит).
func RevealKey(subject string) string { return keyPrefixReveal + subject }

// MutatingKey возвращает ключ ведра мутирующих API-запросов по subject
// (per-session-subject лимит).
func MutatingKey(subject string) string { return keyPrefixMutating + subject }

// Limit — параметры одного ведра.
type Limit struct {
	// Rate — скорость пополнения, токенов в секунду.
	Rate float64
	// Burst — ёмкость ведра: сколько запросов допускается «залпом», пока
	// ведро полно.
	Burst float64
}

// Limiter — token-bucket поверх таблицы rate_limit_buckets.
type Limiter struct {
	pool *pgxpool.Pool
}

// New возвращает Limiter поверх пула metadata database.
func New(pool *pgxpool.Pool) *Limiter {
	return &Limiter{pool: pool}
}

// ensureBucketSQL создаёт строку ведра полной (Burst), если её ещё нет.
// Идемпотентно и не блокируется на конкурентах: DO NOTHING не берёт lock
// существующей строки, поэтому не мешает параллельному consumeSQL.
const ensureBucketSQL = `
insert into rate_limit_buckets (key, tokens, updated_at)
values ($1, $2, now())
on conflict (key) do nothing`

// consumeSQL атомарно пересчитывает уровень ведра и списывает один токен.
//
// cur берёт row-lock (FOR UPDATE): конкурентные вызовы одного ключа
// сериализуются, и под READ COMMITTED каждый видит уже зафиксированный
// уровень предыдущего. calc считает доступный уровень после refill:
// available = min(Burst, tokens + Rate*elapsed), elapsed по времени базы.
// upd пишет уровень после списания (available-1, если хватило токена) и
// сбрасывает updated_at в now(); RETURNING отдаёт доналоговый available из
// FROM-таблицы calc, по нему вызывающий вычисляет allowed и retryAfter.
const consumeSQL = `
with cur as (
    select tokens, updated_at
    from rate_limit_buckets
    where key = $1
    for update
),
calc as (
    select least($3, tokens + $2 * extract(epoch from now() - updated_at)) as available
    from cur
),
upd as (
    update rate_limit_buckets b
    set tokens = case when c.available >= 1 then c.available - 1 else c.available end,
        updated_at = now()
    from calc c
    where b.key = $1
    returning c.available
)
select available >= 1 as allowed, available from upd`

// Allow пытается списать один токен из ведра key с параметрами lim и
// сообщает, разрешён ли запрос. При отказе retryAfter — время до накопления
// одного токена; при allowed retryAfter == 0. Ошибка означает недоступность
// базы: вызывающий решает, fail-open или fail-closed (API — fail-open, см.
// internal/api).
//
// Списание атомарно (см. package doc): строка ведра гарантированно
// существует, затем один statement под row-lock пересчитывает уровень и
// списывает токен.
func (l *Limiter) Allow(ctx context.Context, key string, lim Limit) (allowed bool, retryAfter time.Duration, err error) {
	if _, err := l.pool.Exec(ctx, ensureBucketSQL, key, lim.Burst); err != nil {
		return false, 0, fmt.Errorf("ratelimit: ensure bucket: %w", err)
	}

	var available float64
	err = l.pool.QueryRow(ctx, consumeSQL, key, lim.Rate, lim.Burst).Scan(&allowed, &available)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Строка только что гарантированно вставлена ensureBucketSQL и
			// нигде не удаляется — отсутствие строки означает дефект.
			return false, 0, fmt.Errorf("ratelimit: bucket %q vanished after ensure", key)
		}
		return false, 0, fmt.Errorf("ratelimit: consume token: %w", err)
	}
	if allowed {
		return true, 0, nil
	}
	return false, retryAfterDuration(available, lim.Rate), nil
}

// retryAfterDuration — время до накопления одного токена при текущем уровне
// available (< 1) и скорости rate. Чистая функция (юнит-тест без базы).
// rate <= 0 (ведро без пополнения) даёт 0: осмысленного времени ожидания
// нет, вызывающий отдаёт Retry-After 0.
func retryAfterDuration(available, rate float64) time.Duration {
	if rate <= 0 || available >= 1 {
		return 0
	}
	seconds := (1 - available) / rate
	return time.Duration(seconds * float64(time.Second))
}

// RetryAfterSeconds округляет длительность вверх до целых секунд для
// заголовка Retry-After (HTTP требует целое число секунд). Неположительная
// длительность даёт 0. Чистая функция (юнит-тест без базы).
func RetryAfterSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(math.Ceil(d.Seconds()))
}
