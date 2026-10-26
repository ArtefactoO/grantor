// Package adapter определяет контракт между ядром grantor и engine adapters
// (docs/architecture.md, раздел 10). Adapters компилируются в worker/connector
// как обычные Go packages; runtime plugins не используются.
package adapter

import (
	"context"
	"errors"
	"slices"
)

var (
	// ErrUnsupportedChange возвращается из Plan для ChangeKind, который
	// adapter не поддерживает.
	ErrUnsupportedChange = errors.New("adapter: unsupported change")
	// ErrNotFound возвращается, когда указанный account, permission или
	// resource не существует в целевой системе.
	ErrNotFound = errors.New("adapter: object not found")
	// ErrExternalIdentityConflict означает, что identity уже существует,
	// но adapter не доказал владение ею переданным credential. Restore не
	// вправе изменять такую identity.
	ErrExternalIdentityConflict = errors.New("adapter: external identity conflict")
	// ErrCredentialProofUnsupported означает, что движок/конфигурация не
	// позволяют доказать, что target действительно проверил этот credential.
	ErrCredentialProofUnsupported = errors.New("adapter: credential proof is unsupported")
	// Credentials cannot be checked because the login has no admitted database.
	// This is an authorization/HBA failure, not proof of a wrong password.
	ErrCredentialProofAccessDenied = errors.New("adapter: credential verification access denied")
	// ErrTargetIdentityConflict means the live target proven immediately
	// before a mutation is not the cluster pinned by the control plane.
	ErrTargetIdentityConflict = errors.New("adapter: target identity conflict")
)

// CredentialProver — общий security-контракт проверки credential после
// ротации и для account.restore. Adapter может объявить CapCredentialProve
// только реализуя этот интерфейс.
// Успех означает одновременное доказательство target identity и владения
// именно переданным credential; mismatch возвращает
// ErrExternalIdentityConflict, неоднозначная схема auth —
// ErrCredentialProofUnsupported, transport/unavailable — обычную ошибку.
type CredentialProver interface {
	ProveCredential(ctx context.Context, cfg Connection, account Account, credential Credential) error
}

// CredentialProofPreflighter checks whether a password-authenticated login
// can be attempted before a managed-link operation changes its password.
// It cannot fence subsequent external HBA/ACL changes.
type CredentialProofPreflighter interface {
	CheckCredentialProofAccess(context.Context, Connection, Account) error
}

// SupportsCredentialProof сообщает, что adapter не только реализует prover,
// но и явно объявляет capability. Это единый backend guard для API, worker и
// connector вместо engine-specific списков.
func SupportsCredentialProof(ad Adapter) bool {
	if ad == nil || !ad.Manifest().HasCapability(CapCredentialProve) {
		return false
	}
	_, ok := ad.(CredentialProver)
	return ok
}

// EngineIdentityFormatter — дополнительный контракт adapter для движков, у
// которых учётная запись адресуется не одним именем, а составной формой
// (mysql — user@host, mongodb — user@authdb). Ядро знает только базовое имя
// (external subject принципала или slug его display name) и обязано
// спросить adapter, как записать это имя в engine_identity конкретного
// подключения.
//
// Контракт метода:
//   - чистая функция от несекретных метаданных подключения: сети и target
//     не касается, поэтому работает одинаково в direct- и connector-режиме
//     и вызывается на API-слое до постановки account.create;
//   - идемпотентность: base, уже записанный в engine-специфичной форме,
//     возвращается без изменений. Это сохраняет приоритет явно переданного
//     engine_identity и не ломает исторические identity;
//   - недостающая часть берётся из Connection.Attributes (например
//     mysql default_account_host, mongodb auth_source), иначе — из
//     дефолта движка.
//
// Adapters движков, где identity — обычное имя (postgres, clickhouse,
// kafka, rabbitmq, redis), интерфейс не реализуют: FormatEngineIdentity
// возвращает base как есть.
type EngineIdentityFormatter interface {
	FormatEngineIdentity(cfg Connection, base string) (string, error)
}

// FormatEngineIdentity приводит базовое имя учётной записи к
// engine-специфичной форме подключения. Adapter без
// EngineIdentityFormatter оставляет base неизменным. Неизвестный engine
// (adapter не зарегистрирован в этом процессе) — не ошибка вызывающего:
// base возвращается как есть, поведение остаётся прежним.
func FormatEngineIdentity(cfg Connection, base string) (string, error) {
	if base == "" {
		return "", errors.New("adapter: engine identity base is empty")
	}
	a, err := New(cfg.Engine)
	if err != nil {
		return base, nil
	}
	f, ok := a.(EngineIdentityFormatter)
	if !ok {
		return base, nil
	}
	return f.FormatEngineIdentity(cfg, base)
}

// ConnectionCapabilityScoper — дополнительный контракт adapter для движков, у
// которых доступность операций зависит не только от движка, но и от
// конкретного подключения: kafka управляет учётными данными исключительно
// через SCRAM API, поэтому на PLAIN/mTLS-подключении account.create,
// account.delete и credential.rotate невозможны, а на кластере с выключенным
// ACL-авторизатором невозможны и access.grant/revoke.
//
// Manifest остаётся engine-wide максимумом (раздел 10.2 архитектуры), а этот
// контракт сужает его под подключение (раздел 10.3: capabilities включаются
// per-connection). Без сужения UI показывает действие, которое гарантированно
// упадёт на Apply, а API-гварды пропускают операцию до adapter.
//
// Контракт метода:
//   - чистая функция от несекретных метаданных: сети и target не касается,
//     поэтому одинаково работает в direct- и connector-режиме и вызывается на
//     API-слое;
//   - результат обязан быть подмножеством Manifest().Capabilities; лишние
//     значения ядро отбрасывает (см. CapabilitiesFor);
//   - topology — Snapshot.Topology последнего discovery, то есть то, что
//     записал сам adapter; nil означает «наблюдений ещё нет», и adapter обязан
//     деградировать до сужения по одной cfg. Ядро содержимое topology не
//     интерпретирует и engine-специфичных ключей не знает.
//
// Adapters движков, где доступность операций определяется только движком
// (postgres, mysql, mongodb, clickhouse, rabbitmq, redis), интерфейс не
// реализуют: эффективный набор равен манифесту.
type ConnectionCapabilityScoper interface {
	CapabilitiesFor(cfg Connection, topology map[string]any) []Capability
}

// CapabilitiesFor возвращает эффективные capabilities подключения: манифест
// движка, сужённый adapter'ом под cfg и наблюдаемую topology. Adapter без
// ConnectionCapabilityScoper возвращает манифест как есть.
//
// Результат всегда является подмножеством манифеста и сохраняет его порядок:
// adapter не может ни расширить свои возможности через этот путь, ни сделать
// хранимый набор недетерминированным. Неизвестный engine (adapter не
// зарегистрирован в этом процессе) — ошибка: вызывающий решает, чем
// деградировать.
func CapabilitiesFor(cfg Connection, topology map[string]any) ([]Capability, error) {
	a, err := New(cfg.Engine)
	if err != nil {
		return nil, err
	}
	manifest := a.Manifest().Capabilities
	s, ok := a.(ConnectionCapabilityScoper)
	if !ok {
		return slices.Clone(manifest), nil
	}
	scoped := s.CapabilitiesFor(cfg, topology)
	out := make([]Capability, 0, len(manifest))
	for _, c := range manifest {
		if slices.Contains(scoped, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// Adapter — общий интерфейс engine adapter (раздел 10.1 архитектуры).
//
// Все операции обязаны быть идемпотентными на уровне Apply: повторное
// применение того же Plan не должно менять итоговое состояние и не должно
// завершаться ошибкой. Секретные значения не должны попадать в Plan
// descriptions, Result и ошибки.
type Adapter interface {
	Manifest() Manifest
	ValidateConnection(ctx context.Context, cfg Connection) error
	Discover(ctx context.Context, cfg Connection) (*Snapshot, error)

	Plan(ctx context.Context, change DesiredChange) (*Plan, error)
	Apply(ctx context.Context, plan Plan) (*Result, error)
	Verify(ctx context.Context, plan Plan) (*Verification, error)

	GenerateCredential(ctx context.Context, policy CredentialPolicy) (*Credential, error)
	RotateCredential(ctx context.Context, cfg Connection, account Account, credential Credential) error
}
