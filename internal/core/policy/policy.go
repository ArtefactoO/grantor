// Package policy — scope policies и режим их enforcement (ADR-0007;
// docs/threat-model.md, P0 scope policies для operator). Scope policy
// ограничивает роль operator (и отдельных service-принципалов) окружениями
// connections: operator видит и меняет только connections тех окружений, на
// которые ему выдана политика.
//
// # Deny-by-default
//
// В режиме enforce у operator без единой scope policy нет доступа ни к одному
// connection: пустой набор окружений и отсутствие '*' означают отказ. Политики
// обязательны в production; для dev режим disabled отключает проверку, чтобы
// локальный контур не требовал их заведения. Управление политиками — операция
// admin (см. internal/api).
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Subject kinds scope policy. Значения совпадают с CHECK-ограничением колонки
// scope_policies.subject_kind (db/migrations/00004_scope_policies.sql).
const (
	// SubjectRole — политика на роль целиком; subject = имя роли ('operator').
	SubjectRole = "role"
	// SubjectPrincipal — политика на конкретного принципала; subject = его
	// uuid как текст.
	SubjectPrincipal = "principal"
)

// EnvironmentAll — значение environment, разрешающее все окружения.
const EnvironmentAll = "*"

// ScopePolicy зеркалит строку таблицы scope_policies.
type ScopePolicy struct {
	ID          uuid.UUID
	SubjectKind string
	Subject     string
	Environment string
	CreatedAt   time.Time
}

// ValidSubjectKind сообщает, входит ли значение в допустимые subject_kind.
func ValidSubjectKind(kind string) bool {
	switch kind {
	case SubjectRole, SubjectPrincipal:
		return true
	default:
		return false
	}
}

// EnforcementMode — режим применения scope policies.
type EnforcementMode string

const (
	// EnforcementEnforce — политики обязательны: operator без политики не
	// видит ни одного connection (deny-by-default). Режим production.
	EnforcementEnforce EnforcementMode = "enforce"
	// EnforcementDisabled — политики не применяются: operator видит все
	// connections. Режим dev, чтобы не ломать локальный контур.
	EnforcementDisabled EnforcementMode = "disabled"
)

// Enforcing сообщает, применяются ли scope policies. Пустое значение (режим
// не задан) трактуется как disabled — безопасный для dev дефолт.
func (m EnforcementMode) Enforcing() bool {
	return m == EnforcementEnforce
}

// ParseEnforcementMode разбирает режим enforcement из строки (env-флаг), без
// учёта регистра и пробелов по краям. Пустая строка → EnforcementDisabled
// (dev-дефолт). Неизвестное значение — ошибка, чтобы опечатка в
// security-флаге не проходила молча.
func ParseEnforcementMode(s string) (EnforcementMode, error) {
	switch m := EnforcementMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "", EnforcementDisabled:
		return EnforcementDisabled, nil
	case EnforcementEnforce:
		return EnforcementEnforce, nil
	default:
		return "", fmt.Errorf("policy: unknown enforcement mode %q (want enforce or disabled)", s)
	}
}

// resolveAllowed разбивает набор environment из scope policies на конкретные
// окружения и флаг allowAll. Значение EnvironmentAll ('*') в наборе означает
// доступ ко всем окружениям (allowAll=true) и не попадает в список конкретных.
// Чистая функция — тестируется без базы.
func resolveAllowed(environments []string) (allowed []string, allowAll bool) {
	for _, env := range environments {
		if env == EnvironmentAll {
			allowAll = true
			continue
		}
		allowed = append(allowed, env)
	}
	return allowed, allowAll
}
