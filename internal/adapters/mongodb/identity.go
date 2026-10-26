package mongodb

// Формирование engine identity MongoDB из базового имени принципала.
// Вынесено отдельным файлом: contract-часть
// (adapter.EngineIdentityFormatter) не связана с мутациями в mutations.go.

import (
	"errors"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

var _ adapter.EngineIdentityFormatter = (*Adapter)(nil)

// FormatEngineIdentity дописывает к базовому имени auth database MongoDB:
// 'app' превращается в 'app@admin' (или в auth_source из discovery_config
// подключения — ту же базу, в которой аутентифицируется admin credential).
// Имя, уже содержащее '@', считается заданным в форме user@authdb и
// возвращается без изменений — так явный engine_identity и исторические
// identity сохраняют приоритет, а повторный вызов идемпотентен.
func (a *Adapter) FormatEngineIdentity(cfg adapter.Connection, base string) (string, error) {
	if base == "" {
		return "", errors.New("mongodb: engine identity base is empty")
	}
	if strings.Contains(base, "@") {
		return base, nil
	}
	return base + "@" + authSource(cfg), nil
}
