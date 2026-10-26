package api

// Scope enforcement для роли operator (ADR-0007; docs/threat-model.md, R2/R3,
// P0 scope policies). Решение и его границы:
//
//   - admin — всегда полный доступ (scope не ограничивает);
//   - viewer — read-only и менее опасен, поэтому scope к нему НЕ применяется:
//     viewer читает все connections (осознанное решение, ADR-0007);
//   - operator — scope применяется ко ВСЕМ операциям (чтение и запись) над
//     конкретным connection: operator видит и трогает только connections тех
//     окружений, на которые ему (или его service-принципалу) выданы политики;
//   - режим disabled (dev) — scope не применяется ни к кому.
//
// Deny-by-default: у operator без единой scope policy в режиме enforce нет
// доступа ни к одному connection (пустой список окружений, нет '*'). Нарушение
// scope отдаётся как 403 без раскрытия чужих окружений.
//
// API keys retain the owner's scope even when their issued role is read-only.
// An explicit key environment restriction intersects that scope for every role.

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/policy"
)

// errScopeForbidden — connection вне scope operator'а. Транслируется в 403
// forbidden без раскрытия окружения (respondScopeError).
var errScopeForbidden = errors.New("api: connection is out of operator scope")

// scopeAppliesTo сообщает, ограничивает ли scope сессию с ролью role в режиме
// mode: только роль operator при включённом enforcement. admin (покрывает всё)
// и viewer (не покрывает operator, read-only), а также режим disabled — scope
// не применяют. Чистая функция для юнит-тестов.
func scopeAppliesTo(mode policy.EnforcementMode, role auth.Role) bool {
	if !mode.Enforcing() {
		return false
	}
	if role.Allows(auth.RoleAdmin) || !role.Allows(auth.RoleOperator) {
		return false
	}
	return true
}

// environmentAllowed сообщает, разрешено ли окружение по набору разрешённых
// окружений и флагу allowAll. Чистая функция для юнит-тестов.
func environmentAllowed(allowed []string, allowAll bool, environment string) bool {
	return allowAll || slices.Contains(allowed, environment)
}

// scopeApplies сообщает, применяется ли scope-проверка к сессии текущего
// сервера (с учётом режима enforcement).
func (s *Server) scopeApplies(sess auth.Session) bool {
	if sess.APIKeyID != "" {
		return sess.OwnerRole == auth.RoleOperator || len(sess.Environments) != 0
	}
	return scopeAppliesTo(s.scopeEnforcement, sess.Role)
}

// servicePrincipalID возвращает id принципала для scope-проверки: для сессии
// service-принципала (аутентификация по токену) — его id (Subject), для
// человека — пустую строку (у человека нет grantor-принципала; действуют
// только role-политики).
func servicePrincipalID(sess auth.Session) string {
	if sess.Service {
		return sess.Subject
	}
	return ""
}

// allowedEnvironments читает окружения, разрешённые сессии operator (role- и
// principal-политики). Вызывается только когда scopeApplies=true.
func (s *Server) allowedEnvironments(ctx context.Context, sess auth.Session) (allowed []string, allowAll bool, err error) {
	role := sess.Role
	if sess.APIKeyID != "" {
		role = sess.OwnerRole
	}
	if role == auth.RoleOperator || sess.Service {
		allowed, allowAll, err = s.policy.AllowedEnvironments(ctx, s.pool, string(auth.RoleOperator), servicePrincipalID(sess))
		if err != nil {
			return nil, false, err
		}
	} else {
		allowAll = true
	}
	if len(sess.Environments) == 0 || slices.Contains(sess.Environments, "*") {
		return allowed, allowAll, nil
	}
	return intersectEnvironments(allowed, allowAll, sess.Environments), false, nil
}

func intersectEnvironments(allowed []string, allowAll bool, restriction []string) []string {
	if slices.Contains(restriction, "*") {
		return allowed
	}
	result := make([]string, 0, len(restriction))
	for _, env := range restriction {
		if environmentAllowed(allowed, allowAll, env) && !slices.Contains(result, env) {
			result = append(result, env)
		}
	}
	return result
}

// checkConnectionScope применяет scope policies к сессии по окружению
// connection. Возвращает nil, если доступ разрешён; errScopeForbidden, если
// окружение вне scope; иную ошибку — при сбое чтения политик. admin/viewer и
// режим disabled — всегда nil (scopeApplies=false). Deny-by-default: у
// operator без политик allowAll=false и envs пусты → errScopeForbidden.
func (s *Server) checkConnectionScope(ctx context.Context, sess auth.Session, environment string) error {
	if !s.scopeApplies(sess) {
		return nil
	}
	allowed, allowAll, err := s.allowedEnvironments(ctx, sess)
	if err != nil {
		return err
	}
	if environmentAllowed(allowed, allowAll, environment) {
		return nil
	}
	return errScopeForbidden
}

// checkConnectionScopeByID загружает окружение connection по id и применяет
// checkConnectionScope. Загрузка connection пропускается, если scope к сессии
// не применяется (admin/viewer/disabled), чтобы не делать лишний запрос.
func (s *Server) checkConnectionScopeByID(ctx context.Context, sess auth.Session, connectionID uuid.UUID) error {
	if !s.scopeApplies(sess) {
		return nil
	}
	environment, err := s.connections.GetEnvironment(ctx, s.pool, connectionID)
	if err != nil {
		return err
	}
	return s.checkConnectionScope(ctx, sess, environment)
}

// respondScopeError транслирует ошибку scope-проверки в HTTP-ответ и
// возвращает true, если ответ записан (err != nil). Нарушение scope —
// 403 forbidden без раскрытия окружения; ошибки stores (например ErrNotFound
// при загрузке connection) — через respondStoreError.
func (s *Server) respondScopeError(ctx context.Context, w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errScopeForbidden) {
		respondError(w, http.StatusForbidden, "forbidden")
		return true
	}
	respondStoreError(ctx, w, err)
	return true
}

// filterConnectionsByScope оставляет в списке только connections окружений,
// разрешённых сессии. Для admin/viewer/disabled список возвращается как есть.
func (s *Server) filterConnectionsByScope(ctx context.Context, sess auth.Session, conns []connections.Connection) ([]connections.Connection, error) {
	if !s.scopeApplies(sess) {
		return conns, nil
	}
	allowed, allowAll, err := s.allowedEnvironments(ctx, sess)
	if err != nil {
		return nil, err
	}
	if allowAll {
		return conns, nil
	}
	out := make([]connections.Connection, 0, len(conns))
	for i := range conns {
		if slices.Contains(allowed, conns[i].Environment) {
			out = append(out, conns[i])
		}
	}
	return out, nil
}
