// Package connector фиксирует контракт протокола execution connector
// (docs/architecture.md, разделы 4.3 и 24). В этапе 0 существует только
// контракт: типы заданий, каноничная подпись и версионирование. Runtime
// (сетевой gateway, connector-процесс, lease/heartbeat) реализуется в этапе
// 1c — см. ADR-0002 и ADR-0006.
//
// Модель доверия:
//
//   - Connector устанавливает исходящее mTLS-соединение к gateway control
//     plane. Входящее соединение в закрытую сеть не требуется (раздел 4.3).
//   - Connector принимает только типизированные подписанные задания (Envelope).
//     Произвольный SQL, shell и команды оператора запрещены: задание — это
//     одна из фиксированных операций JobKind, зеркалящих adapter contract
//     (раздел 10.1), а не строка кода.
//   - Секреты не передаются в Job. Payload — полностью секрет-free
//     descriptor операции; credentials целевой системы (admin credential
//     подключения, credential учётной записи) резолвит из Vault control
//     plane (worker) и доставляет connector'у отдельным кадром
//     wire.TypeCredentials поверх той же mTLS-сессии, сразу после кадра
//     задания (ADR-0014; см. credentials.go). Connector к Vault доступа не
//     имеет. Пароли, tokens и private keys никогда не попадают в job
//     payload, результаты и dedup (раздел 24: "No secrets in ... job
//     payload").
//   - Каждое задание подписано (canonical signing, см. signing.go) и несёт
//     ProtocolVersion; version negotiation отсекает несовместимые версии
//     (раздел 24: "Signed connector jobs и version negotiation"). Кадр
//     credentials не подписывается, но привязан к подписанному заданию по
//     JobID и Nonce.
//
// Adapter contract одинаков для direct worker и connector, поэтому набор
// JobKind повторяет операции adapter.Adapter и перенос исполнения в connector
// не меняет бизнес-логику операции.
package connector

import (
	"encoding/json"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// ProtocolVersion — версия контракта connector. Gateway и connector должны
// совпадать по этой строке; иначе задание отклоняется (см. VerifyEnvelope,
// ErrUnsupportedVersion). Несовместимые изменения увеличивают версию.
const ProtocolVersion = "v1"

// Capability — capability adapter, которую connector умеет исполнять.
// Значения переиспользуются из adapter (inventory.*, account.*, access.*,
// resource.*.<kind>, credential.rotate): connector исполняет те же adapters,
// что и direct worker, поэтому отдельного словаря capability нет.
type Capability = adapter.Capability

// Hello — приветствие, которым connector объявляет gateway свою версию
// протокола, идентичность и множество adapter capabilities, которые он умеет
// исполнять. Version negotiation: gateway принимает connector только при
// совпадении ProtocolVersion (раздел 24). Транспорт handshake — этап 1c;
// здесь фиксируется только форма сообщения.
type Hello struct {
	ProtocolVersion string       `json:"protocol_version"`
	ConnectorID     string       `json:"connector_id"`
	Capabilities    []Capability `json:"capabilities"`
	// Deployment — где агент себя обнаружил: "kubernetes", "vm" или пусто.
	// Поле необязательное и на приём заданий не влияет: это подсказка для
	// оператора, отличающая одинаковые с виду сегменты. Агенты прошлых
	// версий его не шлют, оператор может переопределить значение в UI.
	// Неизвестная строка трактуется как пустая — самообъявление connector'а
	// не должно попадать в интерфейс непроверенным.
	Deployment string `json:"deployment,omitempty"`
	// QuiescedSessionID подтверждает, что предыдущая fenced wire-сессия этого
	// Agent полностью остановила все target-вызовы перед reconnect.
	QuiescedSessionID string `json:"quiesced_session_id,omitempty"`
}

// Типы развёртывания connector'а.
const (
	DeploymentKubernetes = "kubernetes"
	DeploymentVM         = "vm"
	DeploymentOther      = "other"
)

// NormalizeDeployment приводит самообъявленное значение к известному набору;
// всё неизвестное — пустая строка («не сообщил»).
func NormalizeDeployment(value string) string {
	switch value {
	case DeploymentKubernetes, DeploymentVM, DeploymentOther:
		return value
	default:
		return ""
	}
}

// JobKind — тип задания connector. Каждое значение зеркалит одну операцию
// adapter.Adapter (раздел 10.1): discover/plan/apply/verify. Произвольных
// заданий не существует — это закрытое множество.
type JobKind string

const (
	// JobDiscover соответствует Adapter.Discover: снятие snapshot целевой
	// системы.
	JobDiscover JobKind = "job.discover"
	// JobPlan соответствует Adapter.Plan: построение детерминированного
	// плана из DesiredChange без изменения целевой системы.
	JobPlan JobKind = "job.plan"
	// JobApply соответствует Adapter.Apply: идемпотентное применение плана.
	JobApply JobKind = "job.apply"
	// JobVerify соответствует Adapter.Verify: read-back проверка после
	// применения.
	JobVerify JobKind = "job.verify"
	// JobRotateCredential соответствует Adapter.RotateCredential: применение
	// нового credential учётной записи к целевой системе. Сам секрет в
	// задании не передаётся: control plane записывает новую версию в Vault
	// ДО выпуска задания и доставляет конкретное значение отдельным кадром
	// TypeCredentials (ADR-0014); connector применяет его к target (этап 3;
	// множество остаётся закрытым и зеркалит adapter.Adapter). Connector
	// более ранней фазы отвечает на неизвестный вид типизированным
	// failed-результатом, не разрывая соединение, поэтому добавление вида
	// не требует повышения ProtocolVersion.
	JobRotateCredential JobKind = "job.rotate_credential"
	// JobProveCredential authenticates an existing login without changing it.
	JobProveCredential JobKind = "job.prove_credential"
	// JobAdminCredentialSwitch verifies a staged, ready-to-use connection
	// administrator credential and returns a full discovery snapshot. It never
	// mutates the target: canonical Vault promotion remains a control-plane
	// operation after the connector result has been accepted.
	JobAdminCredentialSwitch JobKind = "job.admin_credential_switch"
	// JobAdminCredentialRotate executes the dedicated, forward-only connection
	// administrator rotation contract. It is intentionally separate from
	// JobRotateCredential: an old agent rejects this unknown kind before target
	// access instead of falling back to ordinary account credential rotation.
	JobAdminCredentialRotate JobKind = "job.admin_credential_rotate"
)

// Job — типизированное задание, выдаваемое control plane connector. Поля
// фиксированы контрактом v1; их каноничное представление подписывается
// (см. CanonicalBytes). Секретный материал в Job не входит.
type Job struct {
	// ID — идентификатор задания, уникален в рамках control plane.
	ID string `json:"id"`
	// Kind — тип операции (см. JobKind).
	Kind JobKind `json:"kind"`
	// ConnectionID — целевое подключение; connector по нему выбирает Vault
	// paths и endpoints.
	ConnectionID string `json:"connection_id"`
	// Engine — движок целевой системы (postgres, mongodb, ...); определяет
	// adapter, который исполнит задание.
	Engine string `json:"engine"`
	// ProtocolVersion — версия контракта, под которую выпущено задание.
	// Проверяется при верификации (ErrUnsupportedVersion).
	ProtocolVersion string `json:"protocol_version"`
	// IssuedAt — момент выпуска задания, unix-секунды. Значение передаётся
	// извне (control plane), а не берётся из time.Now при подписи: подпись
	// обязана быть детерминированной для одного и того же Job.
	IssuedAt int64 `json:"issued_at"`
	// Deadline — крайний срок исполнения, unix-секунды; 0 — без явного
	// срока. Connector не начинает задание после Deadline.
	Deadline int64 `json:"deadline"`
	// IdempotencyKey — ключ дедупликации: повторная доставка того же задания
	// не должна выполнять операцию дважды (раздел 24, R5 duplicate execution).
	IdempotencyKey string `json:"idempotency_key"`
	// Payload — сериализованный секрет-free descriptor операции: для
	// discover — ConnectionRef, для plan/apply/verify/rotate — desired
	// change из несекретных ссылок (ConnectionRef/AccountRef). Сами
	// credentials в payload не входят и не адресуются из него: их
	// доставляет control plane отдельным кадром TypeCredentials
	// (ADR-0014). Payload обязан быть построен детерминированно
	// (json.Marshal Go-структур даёт стабильный порядок полей и
	// отсортированные ключи map) — от этого зависит подпись.
	Payload json.RawMessage `json:"payload,omitempty"`
	// Nonce — уникальное значение против повторного использования подписи
	// (anti-replay); генерируется control plane на задание.
	Nonce string `json:"nonce"`
}

// JobStatus — исход исполнения задания на стороне connector.
type JobStatus string

const (
	// JobSuccess — операция применена и (для apply) верифицирована.
	JobSuccess JobStatus = "success"
	// JobFailed — операция завершилась ошибкой; целевое состояние не
	// достигнуто.
	JobFailed JobStatus = "failed"
	// JobUnknown — исход не определён (частичный сбой, потеря связи после
	// применения); требует reconciliation, а не слепого повтора.
	JobUnknown JobStatus = "unknown"
)

// JobResult — результат исполнения задания, возвращаемый connector в gateway.
// Plan/Result зеркалят adapter.Plan и adapter.Result и не содержат секретов;
// Error — очищенное сообщение об ошибке (раздел 24: no secrets in logs/errors).
type JobResult struct {
	JobID      string          `json:"job_id"`
	Status     JobStatus       `json:"status"`
	Plan       json.RawMessage `json:"plan,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
	ErrorCode  string          `json:"error_code,omitempty"`
	ObservedAt int64           `json:"observed_at"`
}

// Envelope — подписанное задание в том виде, в каком оно передаётся connector.
// Signature — подпись каноничного представления Job (CanonicalBytes), а не
// всего Envelope: поэтому подпись не зависит от самого поля Signature и от
// KeyID. KeyID выбирает ключ верификации на стороне gateway/connector.
type Envelope struct {
	Job       Job    `json:"job"`
	Signature []byte `json:"signature"`
	KeyID     string `json:"key_id"`
}

// ConnectionRef — секрет-free проекция adapter.Connection для payload задания.
// Endpoints и TLS-материал (CA/клиентский сертификат) не секретны. Admin
// credential в payload не входит и не адресуется из него: его доставляет
// control plane кадром TypeCredentials (ADR-0014) — Vault-ссылки убраны из
// wire-контракта сознательно, чтобы connector структурно не мог ничего
// дереференсить в Vault.
type ConnectionRef struct {
	ID                string   `json:"id"`
	Engine            string   `json:"engine"`
	AuthMode          string   `json:"auth_mode,omitempty"`
	Endpoints         []string `json:"endpoints,omitempty"`
	ConfigIncarnation string   `json:"config_incarnation,omitempty"`
	NetworkGuard      string   `json:"network_guard,omitempty"`
}

// AccountRef — секрет-free ссылка на учётную запись целевой системы.
// EngineIdentity уникален в рамках connection (как в adapter.Account);
// AuthenticationScope зеркалит одноимённое несекретное поле adapter.Account
// (например, authdb mongo). Credential учётной записи в payload не входит:
// его доставляет кадр TypeCredentials (ADR-0014).
type AccountRef struct {
	Kind                string `json:"kind"`
	EngineIdentity      string `json:"engine_identity"`
	AuthenticationScope string `json:"authentication_scope,omitempty"`
}
