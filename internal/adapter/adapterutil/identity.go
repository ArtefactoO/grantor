package adapterutil

import (
	"fmt"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// IdentityConflict — общий текст отказа account.create поверх уже
// существующей на target identity. Формулировка одна на все adapters
// намеренно: оператор видит одинаковую подсказку независимо от движка, а
// adapter.ErrExternalIdentityConflict делает отказ терминальным (см.
// jobs/terminal.go), потому что повтор не вправе присвоить чужую учётку.
//
// Пропускать такой шаг нельзя: grantor записал бы аккаунт себе, положив в
// Vault свежий пароль, тогда как на target остаётся прежний. Оператор
// получил бы через share мёртвый credential, а весь контур adopt
// (доказательство пароля, гейт на опасные bindings) был бы обойдён.
// Легальный путь для существующей identity — adopt, для восстановления
// своей же удалённой учётки — account.restore.
func IdentityConflict(kind, name string) error {
	return fmt.Errorf("%s %q already exists on the target: adopt it instead of creating a new one: %w",
		kind, name, adapter.ErrExternalIdentityConflict)
}
