package adapter

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInsufficientAdminPrivilege — sentinel: admin credential подключения не
// обладает минимальными привилегиями, необходимыми, чтобы управлять учётными
// записями, ролями и правами на движке (docs/threat-model.md, R4;
// docs/architecture.md, раздел 11). Возвращается из ValidateConnection ещё до
// первой мутации, чтобы отказ был ранним и понятным, а не всплывал в момент
// Apply. Проверять принадлежность через errors.Is.
var ErrInsufficientAdminPrivilege = errors.New("adapter: insufficient admin privileges")

// InsufficientPrivilegeError описывает провал проверки «матрицы минимальных
// привилегий admin credential» для конкретного движка. Сообщение называет
// движок, (безопасное) имя admin-учётки и отсутствующую привилегию, но НИКОГДА
// не содержит секрет: пароль сюда не передаётся. Тип единый для всех adapters,
// поэтому вызывающий код и UI видят однообразную, не утекающую формулировку и
// могут детектировать причину через errors.As/errors.Is
// (ErrInsufficientAdminPrivilege).
type InsufficientPrivilegeError struct {
	// Engine — движок (postgres/mysql/mongodb/rabbitmq).
	Engine string
	// Admin — имя admin-учётки (идентификатор, не секрет). Может быть пустым,
	// если движок не аутентифицирует по имени.
	Admin string
	// Missing — краткое имя отсутствующей привилегии/роли/тега, например
	// "CREATEROLE (or SUPERUSER)" или "the administrator tag".
	Missing string
	// Detail — необязательное человекочитаемое пояснение того, что требуется
	// выдать admin-учётке. Не содержит секретов.
	Detail string
}

// Error возвращает единообразное сообщение без секретов. Движок сюда не
// включается: adapters оборачивают ошибку префиксом "<engine>: validate
// connection: %w", поэтому имя движка и так присутствует в цепочке.
func (e *InsufficientPrivilegeError) Error() string {
	var b strings.Builder
	b.WriteString("admin ")
	if e.Admin != "" {
		fmt.Fprintf(&b, "%q ", e.Admin)
	}
	fmt.Fprintf(&b, "lacks %s required to manage accounts, roles and permissions", e.Missing)
	if e.Detail != "" {
		b.WriteString(": ")
		b.WriteString(e.Detail)
	}
	return b.String()
}

// Unwrap связывает конкретную ошибку с sentinel ErrInsufficientAdminPrivilege,
// чтобы errors.Is находил причину, не разбирая текст.
func (e *InsufficientPrivilegeError) Unwrap() error { return ErrInsufficientAdminPrivilege }
