// Package directory — порт внешнего identity directory (IdP) для
// offboarding-детекции (docs/threat-model.md, раздел 4.3 R1; docs/adr/
// 0012-idp-poll-offboarding.md). Планировщик обслуживания периодически
// опрашивает каталог о состоянии принципалов (poll, а не SCIM push) и
// помечает выключенных/исчезнувших принципалов disabled в состоянии
// grantor — детекция без авто-отзыва.
//
// # Точка расширения
//
// Provider — единственный контракт пакета: он спроектирован под polling
// (один batch-вызов на прогон обслуживания) и не привязан к протоколу.
// Референсная реализация — LDAP (см. NewLDAP): покрывает AD/FreeIPA/
// OpenLDAP. Провайдеры для Okta/Keycloak/Google Workspace и т.п.
// добавляются реализацией того же интерфейса (REST-поллинг их API) и
// новым значением GRANTOR_IDP_MODE в cmd/worker — потребитель
// (internal/core/maintenance) от протокола не зависит.
package directory

import "context"

// Status — состояние субъекта в identity directory с точки зрения
// offboarding-детекции.
type Status string

const (
	// StatusActive — субъект существует и активен.
	StatusActive Status = "active"
	// StatusDisabled — субъект существует, но выключен (заблокирован) в
	// каталоге.
	StatusDisabled Status = "disabled"
	// StatusMissing — субъект в каталоге не найден. Потребитель записывает
	// это как external identity deleted; это не локальный tombstone principal.
	StatusMissing Status = "missing"
)

// Provider — источник статусов субъектов в identity directory.
//
// Контракт Statuses: результат содержит запись для каждого запрошенного
// subject; неизвестный каталогу субъект — StatusMissing, а не ошибка.
// Ошибка возвращается только при недоступности/сбое самого каталога — в
// этом случае вызывающий не делает никаких выводов о субъектах (отказ
// каталога не должен приводить к ложным disable).
type Provider interface {
	Statuses(ctx context.Context, subjects []string) (map[string]Status, error)
}

// Entry — запись каталога, пригодная для заведения принципала.
//
// Subject — то, что попадёт в principals.external_subject: значение, по
// которому этот же каталог потом опрашивается о статусе. Поэтому Subject
// обязан быть тем же атрибутом, по которому ищет Provider.Statuses, иначе
// импортированный принципал сразу окажется missing.
type Entry struct {
	Subject     string
	DisplayName string
	Status      Status
}

// Searcher — дополнительный контракт провайдера: перечисление субъектов
// каталога. Нужен для заведения принципалов, тогда как Provider отвечает
// только на вопрос о состоянии уже известных.
//
// Контракт Search:
//   - пустой query перечисляет каталог целиком (в пределах limit) — это
//     режим массовой загрузки;
//   - непустой query отбирает записи по подстроке — режим поиска
//     конкретного человека при выдаче доступа;
//   - limit > 0 обязателен: каталог организации может содержать десятки
//     тысяч записей, и вызывающий должен явно ограничить выдачу;
//   - выключенные в каталоге записи возвращаются со StatusDisabled, а не
//     скрываются: решение, заводить ли их, принимает вызывающий.
//
// Провайдер без Searcher поддерживает только сверку: импорт для него
// недоступен, и это не ошибка вызывающего.
type Searcher interface {
	Search(ctx context.Context, query string, limit int) ([]Entry, error)
}

// APIIdentity is an independently verified control-plane identity. UID must
// survive username changes and must change if a deleted username is reassigned.
type APIIdentity struct {
	UID      string
	Username string
	Email    string
	Groups   []string
	Status   Status
}

// APIIdentityProvider is optional. Providers without immutable identity and
// group membership cannot keep personal API keys valid beyond a UI session.
type APIIdentityProvider interface {
	APIIdentity(context.Context, string) (APIIdentity, error)
}
