package auth

import (
	"fmt"
	"strings"
)

// Role — роль пользователя control plane (docs/architecture.md, раздел 21).
type Role string

// Роли в порядке расширения привилегий: admin ⊃ operator ⊃ viewer.
const (
	// RoleViewer — просмотр connections/resources/audit без изменений и
	// без доступа к credentials.
	RoleViewer Role = "viewer"
	// RoleOperator — выдача/отзыв обычных permissions, работа с accounts
	// и credentials в пределах назначенных scope policies.
	RoleOperator Role = "operator"
	// RoleAdmin — всё доступное operator плюс управление connections,
	// dangerous permissions, policies и provisioning.
	RoleAdmin Role = "admin"
)

// rank возвращает численный уровень роли в иерархии; 0 — неизвестная роль.
func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// Allows сообщает, покрывает ли роль r требование required с учётом
// иерархии admin ⊃ operator ⊃ viewer. Неизвестная роль не покрывает
// ничего, и требование неизвестной роли не выполняется никем.
func (r Role) Allows(required Role) bool {
	own, req := r.rank(), required.rank()
	return own > 0 && req > 0 && own >= req
}

// ParseRole разбирает строку в Role: без учёта регистра, пробелы по краям
// игнорируются. Неизвестное значение — ошибка.
func ParseRole(s string) (Role, error) {
	switch r := Role(strings.ToLower(strings.TrimSpace(s))); r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return r, nil
	default:
		return "", fmt.Errorf("auth: unknown role %q", s)
	}
}
