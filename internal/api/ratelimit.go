package api

// Rate limiting API v1 (ADR-0007, docs/threat-model.md, раздел 3.5). Три
// поверхности с независимыми вёдрами token-bucket (internal/ratelimit,
// общий счётчик в PostgreSQL — честный лимит между репликами api):
//
//   - login — per-IP (брутфорс логина); навешивается на /auth/login в
//     cmd/api через LimitLoginHandler (login идёт мимо api.Server);
//   - reveal — per-subject (флуд credential reveal/share); точечная проверка
//     rateLimitReveal в share-эндпоинтах;
//   - mutating — per-subject (флуд мутирующих запросов); middleware
//     LimitMutating на весь /api mux, но списывает токен только на
//     мутирующих методах, поэтому hot read-path (GET list/get) не тратит
//     токены и не лимитируется.
//
// Все проверки fail-open: ошибка счётчика (недоступность базы) не роняет
// легитимный трафик — метаданные и так в этой базе, при её отказе API
// нерабочий и без лимитера. При отключённом лимитере (Limiter == nil,
// backward-compat для тестов и флага GRANTOR_RATE_LIMIT=false) проверки
// пропускаются.

import (
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
)

// RateLimitConfig — лимиты трёх поверхностей. Дефолты подобраны под редкие
// чувствительные вызовы: несколько попыток «залпом», затем медленный refill.
type RateLimitConfig struct {
	// Login — per-IP лимит логина.
	Login ratelimit.Limit
	// Reveal — per-subject лимит credential reveal/share.
	Reveal ratelimit.Limit
	// Mutating — per-subject лимит мутирующих API-запросов.
	Mutating ratelimit.Limit
}

// DefaultRateLimitConfig — дефолтные лимиты (ADR-0007):
//
//   - login: burst 5 попыток, затем 1 попытка в 5 с (Rate 0.2/s) — тормозит
//     брутфорс, но не мешает человеку с опечаткой пароля;
//   - reveal: burst 10, затем 1 в 10 с (Rate 0.1/s) — выдача credential редка;
//     ограничивает массовую эксфильтрацию через reveal/share (R2);
//   - mutating: burst 20, затем 2/s (Rate 2/s) — обычная работа оператора не
//     упирается, но флуд операций отсекается.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Login:    ratelimit.Limit{Rate: 0.2, Burst: 5},
		Reveal:   ratelimit.Limit{Rate: 0.1, Burst: 10},
		Mutating: ratelimit.Limit{Rate: 2, Burst: 20},
	}
}

// clientIP определяет IP клиента для per-IP лимита логина. За nginx реальный
// адрес приходит в X-Forwarded-For (первый элемент — исходный клиент, далее
// прокси); nginx этот заголовок переписывает сам (раздел 27.1), поэтому
// доверяем первому hop. Без заголовка берём host из r.RemoteAddr. Trust:
// заголовок осмыслен только за доверенным reverse-proxy — в production api
// всегда за nginx; при прямом доступе клиент мог бы подделать XFF, но такой
// топологии в проде нет.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// isMutatingMethod сообщает, меняет ли HTTP-метод состояние. Только такие
// методы тратят токен mutating-ведра, поэтому read-path не лимитируется.
func isMutatingMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// writeRateLimited пишет 429 с заголовком Retry-After (целые секунды) и телом
// {"error":"rate limit exceeded"}. Retry-After ставится до WriteHeader.
func writeRateLimited(w http.ResponseWriter, retryAfter time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfterSeconds(retryAfter)))
	respondError(w, http.StatusTooManyRequests, "rate limit exceeded")
}

// LimitMutating оборачивает /api mux: на мутирующих методах (POST/PUT/PATCH/
// DELETE) списывает токен mutating-ведра по subject сессии. GET/HEAD проходят
// без списания (hot read-path не лимитируется). Без сессии запрос пропускается
// — RequireRole сам вернёт 401. Лимитер nil → middleware прозрачен.
func (s *Server) LimitMutating(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimiter == nil || !isMutatingMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := auth.FromContext(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter, err := s.rateLimiter.Allow(r.Context(),
			ratelimit.MutatingKey(sess.Subject), s.rateLimits.Mutating)
		if err != nil {
			slog.ErrorContext(r.Context(), "api: mutating rate limit check failed; allowing", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			writeRateLimited(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitReveal применяет per-subject лимит credential reveal/share перед
// выдачей. При превышении пишет 429 и возвращает false; при отключённом
// лимитере или ошибке счётчика (fail-open) — true.
func (s *Server) rateLimitReveal(w http.ResponseWriter, r *http.Request, subject string) bool {
	if s.rateLimiter == nil {
		return true
	}
	allowed, retryAfter, err := s.rateLimiter.Allow(r.Context(),
		ratelimit.RevealKey(subject), s.rateLimits.Reveal)
	if err != nil {
		slog.ErrorContext(r.Context(), "api: reveal rate limit check failed; allowing", "error", err)
		return true
	}
	if !allowed {
		writeRateLimited(w, retryAfter)
		return false
	}
	return true
}

// LimitLoginHandler оборачивает handler /auth/login per-IP лимитом (login идёт
// в cmd/api напрямую на authn.LoginHandler, минуя api.Server, поэтому обёртка
// отдельная). limiter nil → handler прозрачен. При превышении — 429 с
// Retry-After.
func LimitLoginHandler(limiter *ratelimit.Limiter, lim ratelimit.Limit, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limiter == nil {
			next.ServeHTTP(w, r)
			return
		}
		allowed, retryAfter, err := limiter.Allow(r.Context(), ratelimit.LoginKey(clientIP(r)), lim)
		if err != nil {
			slog.ErrorContext(r.Context(), "api: login rate limit check failed; allowing", "error", err)
			next.ServeHTTP(w, r)
			return
		}
		if !allowed {
			writeRateLimited(w, retryAfter)
			return
		}
		next.ServeHTTP(w, r)
	})
}
