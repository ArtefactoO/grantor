// Package connections — доменная модель подключений grantor
// (docs/architecture.md, разделы 5 и 5.1). Connection описывает одну
// целевую систему (PostgreSQL, MongoDB, ...): endpoints, режим
// исполнения, несекретные параметры TLS и discovery, а также состояние
// жизненного цикла. Секреты в этой модели не хранятся никогда: admin
// credential живёт в Vault, в metadata остаётся только vault path.
package connections

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Режимы исполнения операций подключения. Значения совпадают с
// CHECK-ограничением колонки connections.execution_mode в схеме
// (db/migrations/00001_core_schema.sql).
const (
	// ExecutionModeDirect — worker выполняет adapter-операции сам,
	// подключаясь к целевой системе напрямую (путь по умолчанию).
	ExecutionModeDirect = "direct"
	// ExecutionModeConnector — целевая система живёт в изолированном
	// сегменте: операции исполняет execution connector, которому worker
	// диспетчеризует подписанные задания через gateway (ADR-0002, ADR-0006).
	ExecutionModeConnector = "connector"
)

// ValidExecutionMode сообщает, является ли mode допустимым режимом
// исполнения подключения.
func ValidExecutionMode(mode string) bool {
	return mode == ExecutionModeDirect || mode == ExecutionModeConnector
}

// Status — состояние подключения. Значения совпадают с CHECK-ограничением
// колонки connections.status в схеме (db/migrations/00001_core_schema.sql).
type Status string

const (
	// StatusDraft — подключение создано, но ещё не проверялось.
	StatusDraft Status = "draft"
	// StatusValidating — идёт проверка endpoint, TLS и authentication.
	StatusValidating Status = "validating"
	// StatusDiscovering — идёт первоначальный discovery.
	StatusDiscovering Status = "discovering"
	// StatusActive — подключение работает; snapshot актуален.
	StatusActive Status = "active"
	// StatusConnectionFailed — проверка подключения не прошла; допускает
	// retry validation после исправления параметров.
	StatusConnectionFailed Status = "connection_failed"
	// StatusDiscoveryFailed — первоначальный discovery завершился
	// ошибкой; допускает retry discovery.
	StatusDiscoveryFailed Status = "discovery_failed"
	// StatusDegraded — активное подключение перестало отвечать или
	// discovery на нём падает; возвращается в active после успешного
	// discovery.
	StatusDegraded Status = "degraded"
	// StatusDisabled — подключение выключено администратором.
	StatusDisabled Status = "disabled"
	// StatusCredentialUpdating — staged switch/self-rotation admin credential
	// owns the connection. Ordinary PATCH, refresh and target mutations are
	// blocked until the durable credential epoch completes or is safely
	// cancelled.
	StatusCredentialUpdating Status = "credential_updating"
)

// transitions — карта допустимых переходов статусов подключения
// (docs/architecture.md, раздел 5.1).
//
// Семантика:
//   - draft -> validating: сохранённое подключение отправлено на проверку;
//   - validating -> discovering: проверка прошла, начинается discovery;
//   - validating -> connection_failed: проверка не прошла;
//   - connection_failed -> validating: retry validation;
//   - discovering -> active: первоначальный discovery успешен;
//   - discovering -> discovery_failed: discovery завершился ошибкой;
//   - discovery_failed -> discovering: retry discovery;
//   - active -> degraded: периодический discovery на активном подключении
//     упал или целевая система недоступна;
//   - degraded -> active: успешный discovery вернул подключение в строй;
//   - active -> disabled: администратор выключил подключение;
//   - disabled -> active: администратор включил подключение обратно.
var transitions = map[Status]map[Status]bool{
	StatusDraft: {
		StatusValidating: true,
	},
	StatusValidating: {
		StatusDiscovering:      true,
		StatusConnectionFailed: true,
	},
	StatusDiscovering: {
		StatusActive:          true,
		StatusDiscoveryFailed: true,
	},
	StatusConnectionFailed: {
		StatusValidating: true,
	},
	StatusDiscoveryFailed: {
		StatusDiscovering: true,
	},
	StatusActive: {
		StatusDegraded: true,
		StatusDisabled: true,
	},
	StatusDegraded: {
		StatusActive: true,
	},
	StatusDisabled: {
		StatusActive: true,
	},
	// Credential transitions use their own versioned state machine and update
	// the connection status atomically with its journal. Generic Transition
	// must never enter or leave this state.
	StatusCredentialUpdating: {},
}

// CanTransition сообщает, допустим ли переход подключения из статуса from
// в статус to. Переход в тот же статус недопустим.
func CanTransition(from, to Status) bool {
	return transitions[from][to]
}

// CanEditMetadata сообщает, допускает ли текущее состояние изменение только
// описательных полей connection. validating/discovering являются переходными
// состояниями: PATCH в них запрещён, чтобы audit/CAS не описывали строку,
// которую прямо сейчас меняет worker. disabled остаётся стабильным состоянием
// и допускает переименование/теги.
func CanEditMetadata(status Status) bool {
	return status != StatusValidating && status != StatusDiscovering &&
		status != StatusCredentialUpdating && isKnownStatus(status)
}

// CanReconfigure сообщает, можно ли атомарно заменить operational-параметры и
// перевести connection в discovering. Это отдельный guarded-переход
// reconfigure, а не общий Transition: он одновременно сбрасывает сведения
// прошлого snapshot и обязан создавать новую discovery operation.
func CanReconfigure(status Status) bool {
	return CanEditMetadata(status) && status != StatusDisabled
}

func isKnownStatus(status Status) bool {
	_, ok := transitions[status]
	return ok
}

// Connection зеркалит строку таблицы connections. Jsonb-колонки со
// списками строк (tags, endpoints, capabilities) распакованы в []string;
// свободные jsonb-структуры (tls_config, discovery_config, topology)
// оставлены как json.RawMessage — их формат принадлежит вызывающему
// (executor discovery парсит их в свои типизированные структуры).
//
// TLSConfig содержит только несекретные параметры TLS; private material
// живёт в Vault. VaultAdminPath — относительный путь admin credential
// внутри KV mount; пустая строка означает отсутствие credential в Vault.
type Connection struct {
	ID                  uuid.UUID
	DisplayName         string
	Engine              string
	AuthMode            string
	Environment         string
	Tags                []string
	Endpoints           []string
	ExecutionMode       string
	TLSConfig           json.RawMessage
	AdminCredentialMode string
	VaultAdminPath      string
	Capabilities        []string
	DiscoveryConfig     json.RawMessage
	Status              Status
	ServerVersion       string
	Topology            json.RawMessage
	LastDiscoveryAt     *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
