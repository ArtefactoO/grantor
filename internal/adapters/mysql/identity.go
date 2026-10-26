package mysql

// Формирование engine identity MySQL из базового имени принципала.
// Вынесено отдельным файлом: contract-часть (adapter.EngineIdentityFormatter)
// не связана с мутациями и планами в mutations.go.

import (
	"errors"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// defaultAccountHost — host по умолчанию для создаваемых учётных записей.
// '%' означает «с любого хоста»: единственный выбор, при котором учётка
// принципала работает без знания топологии клиентов. Подключение может
// сузить его через discovery_config.default_account_host.
const defaultAccountHost = "%"

// attrDefaultAccountHost — ключ Attributes с host по умолчанию.
const attrDefaultAccountHost = "default_account_host"

var _ adapter.EngineIdentityFormatter = (*Adapter)(nil)

// FormatEngineIdentity дописывает к базовому имени host MySQL: 'app'
// превращается в 'app@%' (или в host из discovery_config подключения).
// Имя, уже содержащее '@', считается заданным в форме user@host и
// возвращается без изменений — так явный engine_identity и исторические
// identity сохраняют приоритет, а повторный вызов идемпотентен.
func (a *Adapter) FormatEngineIdentity(cfg adapter.Connection, base string) (string, error) {
	if base == "" {
		return "", errors.New("mysql: engine identity base is empty")
	}
	if strings.Contains(base, "@") {
		return base, nil
	}
	host := adapterutil.StringAttr(cfg.Attributes, attrDefaultAccountHost)
	if host == "" {
		host = defaultAccountHost
	}
	return base + "@" + host, nil
}
