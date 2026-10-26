// Package principals — доменная модель принципалов grantor
// (docs/architecture.md, раздел 6): люди, сервисы и группы, которым
// принадлежат учётные записи целевых систем. Principal — сущность уровня
// control plane: в целевые системы он не провижинится, связь с ними идёт
// через accounts.principal_id. Статус принципала — тоже только
// метаданные: выключение принципала не блокирует его аккаунты
// автоматически, lifecycle аккаунтов управляется отдельными операциями.
package principals

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Type — тип принципала. Значения совпадают с CHECK-ограничением колонки
// principals.type в схеме (db/migrations/00001_core_schema.sql).
type Type string

const (
	// TypeHuman — человек.
	TypeHuman Type = "human"
	// TypeService — сервис или автоматизация.
	TypeService Type = "service"
	// TypeGroup — группа принципалов.
	TypeGroup Type = "group"
)

// Valid сообщает, входит ли значение в допустимые типы схемы.
func (t Type) Valid() bool {
	switch t {
	case TypeHuman, TypeService, TypeGroup:
		return true
	default:
		return false
	}
}

// Status — состояние принципала. Значения совпадают с CHECK-ограничением
// колонки principals.status.
type Status string

const (
	// StatusActive — принципал активен.
	StatusActive Status = "active"
	// StatusDisabled — принципал выключен администратором.
	StatusDisabled Status = "disabled"
	// StatusPendingPurge — принципал выведен из системы, но ещё не
	// уничтожен: доступ уже заблокирован обратимым каскадом disable, а
	// managed-аккаунты, bindings и общие секреты целы. До наступления
	// PurgeAfter принципал возвращается одной операцией; после — фоновая
	// задача обслуживания выполняет необратимое уничтожение. Выдача
	// доступа, ротация и share в этом статусе отклоняются: человек
	// выводится, новых прав он получать не должен.
	StatusPendingPurge Status = "pending_purge"
	// StatusDeleted — принципал необратимо offboarded (tombstone): его
	// managed-аккаунты отозваны и удалены, общие секреты вычищены из
	// Vault, а строка сохранена ради истории операций и audit. Из deleted
	// нет переходов: enable/disable, выдача доступа, ротация, share и
	// link для такого принципала отклоняются с 409.
	StatusDeleted Status = "deleted"
)

// Valid сообщает, входит ли значение в допустимые статусы схемы.
func (s Status) Valid() bool {
	switch s {
	case StatusActive, StatusDisabled, StatusPendingPurge, StatusDeleted:
		return true
	default:
		return false
	}
}

// ExternalIdentityStatus — последнее успешно полученное состояние внешней
// identity. Это зеркало каталога, а не локальный lifecycle principal.Status:
// deleted здесь означает, что directory больше не находит субъект, и не
// превращает principal в локальный tombstone.
type ExternalIdentityStatus string

const (
	ExternalIdentityActive   ExternalIdentityStatus = "active"
	ExternalIdentityDisabled ExternalIdentityStatus = "disabled"
	ExternalIdentityDeleted  ExternalIdentityStatus = "deleted"
)

// Valid сообщает, входит ли значение в допустимые статусы зеркала identity.
func (s ExternalIdentityStatus) Valid() bool {
	switch s {
	case ExternalIdentityActive, ExternalIdentityDisabled, ExternalIdentityDeleted:
		return true
	default:
		return false
	}
}

// Principal зеркалит строку таблицы principals. ExternalProvider и
// ExternalSubject связывают принципала с identity provider; у локального
// принципала оба поля пустые. Уникальность внешней identity обеспечивает
// частичный индекс схемы (оба поля непустые). ExternalIdentityStatus и
// временные метки — nullable-зеркало последнего успешного IdP poll; nil до
// первой сверки и у локальных принципалов. DisabledAt — момент перевода в
// disabled (nil у активного принципала); используется находкой
// security.offboarding_incomplete как disabled_since.
type Principal struct {
	ID                              uuid.UUID
	Type                            Type
	DisplayName                     string
	ExternalProvider                string
	ExternalSubject                 string
	ExternalIdentityStatus          *ExternalIdentityStatus
	ExternalIdentityCheckedAt       *time.Time
	ExternalIdentityStatusChangedAt *time.Time
	Status                          Status
	Attributes                      json.RawMessage
	DisabledAt                      *time.Time
	// PurgeAfter — момент, с которого принципал в pending_purge подлежит
	// необратимому уничтожению; nil у не выводимых из системы.
	PurgeAfter *time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ListItem — principal со счётчиком связанных учётных записей для
// спискового представления UI. Аккаунты в статусе deleted (строки,
// сохранённые ради истории операций) в счётчик не входят.
type ListItem struct {
	Principal
	AccountsCount int
}
