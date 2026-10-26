package connector

// Доставка credentials целевой системы connector'у control plane'ом (решение
// пользователя, ADR-0014): connector НЕ имеет доступа к Vault. Worker
// резолвит все секреты задания (admin credential подключения, credential
// учётной записи для account.create/rotate) из Vault сам и передаёт их
// connector'у отдельным кадром wire.TypeCredentials сразу после подписанного
// кадра задания, поверх уже установленной mTLS-сессии.
//
// Инварианты (раздел 24 архитектуры):
//
//   - Подписанный Job/payload, JobResult, durable dedup-строки, артефакты
//     операций, audit и логи по-прежнему НЕ несут секретов: кадр
//     TypeCredentials — единственный носитель, он существует только в
//     памяти процессов и mTLS-канале, никогда не персистится и не
//     логируется (структурно: DedupStore принимает только JobResult, а
//     типы Job/JobResult secret-free по TestWireTypesCarryNoSecrets;
//     рантайм-проверка — canary-тесты gateway/agent).
//   - Кадр привязан к заданию по JobID и Nonce (оба входят в подписанное
//     каноничное представление Job): agent отклоняет кадр с чужой
//     привязкой типизированным failed-результатом.
//   - Agent зануляет секретный материал после исполнения задания (в том
//     числе упавшего) — см. CredentialsFrame.Zero.

import (
	"github.com/ArtefactoO/grantor/internal/adapter"
)

// JobCredentials — секретный материал одного задания на стороне control
// plane. Worker заполняет его из Vault (и из только что сгенерированного
// секрета при per-account ротации) и передаёт в gateway.Dispatch; после
// возврата Dispatch вызывающий обязан занулить материал (Zero).
type JobCredentials struct {
	// Admin — admin credential подключения; nil, если у подключения нет
	// admin credential (пустой vault_admin_path).
	Admin *adapter.Credential
	// AdminCredentialIncarnation is the exact Vault KV version used for the
	// admin credential in this frame. It is non-secret and bound to the signed
	// job by JobID/Nonce, but never persisted with the job.
	AdminCredentialIncarnation int
	// Account — credential учётной записи (account.create — начальный
	// секрет, credential.rotate — НОВАЯ версия, которую control plane уже
	// записал в Vault); nil для заданий без секрета учётной записи.
	Account *adapter.Credential
	// AccountVaultVersion — версия Vault секрета учётной записи
	// (несекретна); connector возвращает её в RotateOutcome.
	AccountVaultVersion int
}

// Frame строит кадр TypeCredentials для задания job. Слайсы секретов не
// копируются: кадр разделяет память с JobCredentials, поэтому Zero одного
// зануляет материал обоих.
func (c JobCredentials) Frame(job Job) CredentialsFrame {
	return CredentialsFrame{
		JobID:                      job.ID,
		Nonce:                      job.Nonce,
		Admin:                      frameCredential(c.Admin),
		AdminCredentialIncarnation: c.AdminCredentialIncarnation,
		Account:                    frameCredential(c.Account),
		AccountVaultVersion:        c.AccountVaultVersion,
	}
}

// Zero зануляет секретный материал (байты паролей). Вызывается control
// plane'ом после Dispatch независимо от исхода задания.
func (c JobCredentials) Zero() {
	if c.Admin != nil {
		clear(c.Admin.Secret)
	}
	if c.Account != nil {
		clear(c.Account.Secret)
	}
}

// CredentialsFrame — тело кадра wire.TypeCredentials: секретный материал
// задания, привязанный к нему по JobID и Nonce. Никогда не персистится и не
// логируется; в подписанное каноничное представление Job не входит
// (подпись покрывает JobID/Nonce, по которым agent проверяет привязку).
type CredentialsFrame struct {
	JobID string `json:"job_id"`
	Nonce string `json:"nonce"`
	// Admin — admin credential подключения; nil = подключение без admin
	// credential.
	Admin *FrameCredential `json:"admin,omitempty"`
	// AdminCredentialIncarnation is the exact Vault KV version of Admin.
	AdminCredentialIncarnation int `json:"admin_credential_incarnation,omitempty"`
	// Account — credential учётной записи; nil = задание без секрета
	// учётной записи.
	Account *FrameCredential `json:"account,omitempty"`
	// AccountVaultVersion — несекретная версия Vault секрета учётной
	// записи (уходит в RotateOutcome).
	AccountVaultVersion int `json:"account_vault_version,omitempty"`
}

// Matches сообщает, привязан ли кадр к заданию job (JobID и Nonce).
func (f CredentialsFrame) Matches(job Job) bool {
	return f.JobID == job.ID && f.Nonce == job.Nonce
}

// Zero зануляет секретный материал кадра. Agent вызывает его после
// исполнения задания (включая упавшее) и для кадров, оставшихся без
// потребителя.
func (f *CredentialsFrame) Zero() {
	if f.Admin != nil {
		clear(f.Admin.Secret)
	}
	if f.Account != nil {
		clear(f.Account.Secret)
	}
}

// FrameCredential — сериализуемая форма adapter.Credential для кадра
// TypeCredentials. Отдельный тип с json-тегами, чтобы wire-формат кадра был
// зафиксирован контрактом, а не форматом чужого пакета.
type FrameCredential struct {
	Kind     string `json:"kind"`
	Username string `json:"username"`
	Secret   []byte `json:"secret"`
}

// Credential возвращает adapter.Credential поверх той же памяти секрета
// (без копии: Zero кадра зануляет и переданный adapter'у материал).
func (f *FrameCredential) Credential() adapter.Credential {
	return adapter.Credential{Kind: f.Kind, Username: f.Username, Secret: f.Secret}
}

// frameCredential конвертирует adapter.Credential в FrameCredential, разделяя
// память секрета; nil остаётся nil.
func frameCredential(c *adapter.Credential) *FrameCredential {
	if c == nil {
		return nil
	}
	return &FrameCredential{Kind: c.Kind, Username: c.Username, Secret: c.Secret}
}
