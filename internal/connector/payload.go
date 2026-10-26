package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Схемы Payload по видам заданий (ADR-0006): DiscoverPayload для JobDiscover
// (этап 1), MutationPayload для JobPlan/JobApply/JobVerify и RotatePayload для
// JobRotateCredential (этап 3). Инвариант «без секретов» (раздел 24)
// сохраняется структурно: payload несёт только несекретные descriptors
// подключения/изменения, а credentials целевой системы доставляет control
// plane отдельным кадром TypeCredentials (ADR-0014) — connector Vault не
// использует и никаких ссылок на секреты в payload нет.

// TLSRef — несекретная проекция adapter.TLSConfig для payload задания. Режим,
// CA и клиентский сертификат не секретны и нужны connector, чтобы построить
// TLS-подключение к целевой системе. Приватный ключ клиента (ClientKeyPEM в
// adapter.TLSConfig) сюда НЕ входит: это секрет, он читается из Vault, а не
// передаётся в задании. Имена полей выбраны так, чтобы структурная проверка
// «без секретов» (TestWireTypesCarryNoSecrets) не находила секрет-подобных
// имён.
type TLSRef struct {
	Mode          string `json:"mode,omitempty"`
	CACertPEM     []byte `json:"ca_cert_pem,omitempty"`
	ClientCertPEM []byte `json:"client_cert_pem,omitempty"`
	// InsecureSkipVerify зеркалит одноимённый небезопасный режим adapter и
	// отображается как security finding; сам по себе секретом не является.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// DiscoverPayload — payload задания JobDiscover: секрет-free descriptor
// целевого подключения, достаточный, чтобы connector построил
// adapter.Connection и снял snapshot. Connection несёт идентификаторы и
// endpoints; TLS — несекретный TLS-материал; Attributes — engine-специфичные
// несекретные параметры (например, maintenance-база postgres в ключе
// "database"). Admin credential в payload не входит — его доставляет кадр
// TypeCredentials (ADR-0014).
//
// Payload обязан строиться детерминированно: json.Marshal сериализует поля
// структуры в порядке объявления и сортирует ключи map, поэтому каноничная
// подпись задания (CanonicalBytes) воспроизводима.
type DiscoverPayload struct {
	PostgresObjectACL bool           `json:"postgres_object_acl,omitempty"`
	SnapshotEncoding  string         `json:"snapshot_encoding,omitempty"`
	Connection        ConnectionRef  `json:"connection"`
	TLS               TLSRef         `json:"tls,omitempty"`
	Attributes        map[string]any `json:"attributes,omitempty"`
}

// Marshal сериализует DiscoverPayload в json.RawMessage для Job.Payload.
func (p DiscoverPayload) Marshal() (json.RawMessage, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal discover payload: %w", err)
	}
	return b, nil
}

// ParseDiscoverPayload разбирает Job.Payload задания JobDiscover. Пустой
// payload — ошибка: задание discover обязано нести descriptor подключения.
func ParseDiscoverPayload(raw json.RawMessage) (DiscoverPayload, error) {
	if len(raw) == 0 {
		return DiscoverPayload{}, fmt.Errorf("connector: discover payload is empty")
	}
	var p DiscoverPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return DiscoverPayload{}, fmt.Errorf("connector: parse discover payload: %w", err)
	}
	if p.SnapshotEncoding != "" && p.SnapshotEncoding != SnapshotGzipV1 {
		return DiscoverPayload{}, fmt.Errorf("connector: unsupported snapshot encoding")
	}
	if p.PostgresObjectACL && p.Connection.Engine != "postgres" {
		return DiscoverPayload{}, fmt.Errorf("connector: PostgreSQL ACL discovery requires engine postgres")
	}
	return p, nil
}

// ChangeRef — секрет-free проекция adapter.DesiredChange для payload
// мутирующих заданий (этап 3). Kind — строковое значение adapter.ChangeKind;
// Account — несекретная ссылка на учётную запись (начальный credential для
// account.create доставляет кадр TypeCredentials, ADR-0014). Permission и
// Scope — external id, как в DesiredChange. AccountPermissions — desired-набор
// назначаемых permissions аккаунта после изменения (см.
// adapter.DesiredChange.AccountPermissions); секретов не несёт, как и
// остальные поля.
//
// У AccountPermissions нет omitempty сознательно: пустой набор («после
// изменения у аккаунта не остаётся прав») и отсутствие поля («ядро
// desired-состояние не передало») — разные состояния контракта, и omitempty
// схлопнул бы первое во второе, переводя адаптер в деградированный режим ровно
// в тот момент, когда снимается последнее право.
type ChangeRef struct {
	Kind               string     `json:"kind"`
	Account            AccountRef `json:"account"`
	Permission         string     `json:"permission,omitempty"`
	Scope              string     `json:"scope,omitempty"`
	AccountPermissions []string   `json:"account_permissions"`
	// Attributes pins non-secret permission/template parameters selected by
	// the control plane. Old agents reject an unknown permission kind before
	// mutation; compatible agents forward these values to DesiredChange.
	Attributes map[string]any `json:"attributes,omitempty"`
	// RolePolicySpec is the immutable, structured policy selected by the
	// control plane. It contains neither SQL nor credentials.
	RolePolicySpec             *adapter.RolePolicySpec              `json:"role_policy_spec,omitempty"`
	StatsMembership            *adapter.PostgresStatsMembershipPins `json:"stats_membership,omitempty"`
	ObjectACL                  *adapter.PostgresObjectACLPins       `json:"object_acl,omitempty"`
	ExpectedAdminIdentity      string                               `json:"expected_admin_identity,omitempty"`
	ExpectedTargetIdentity     string                               `json:"expected_target_identity,omitempty"`
	ExpectedDatabaseOID        uint32                               `json:"expected_database_oid,omitempty"`
	ExpectedDatabaseOwner      string                               `json:"expected_database_owner,omitempty"`
	ExpectedDatabaseOwnerOID   uint32                               `json:"expected_database_owner_oid,omitempty"`
	ExpectedCatalogFingerprint string                               `json:"expected_catalog_fingerprint,omitempty"`
	Resource                   *adapter.ResourceSpec                `json:"resource,omitempty"`
}

// MutationPayload — payload заданий JobPlan/JobApply/JobVerify: descriptor
// целевого подключения (как в DiscoverPayload) плюс ChangeRef желаемого
// изменения. Секретов не несёт: admin credential и credential учётной записи
// доставляет кадр TypeCredentials (ADR-0014). Plan детерминирован по
// контракту adapter, поэтому connector строит его из ChangeRef сам —
// передавать план в задании не требуется, а Apply повторного плана
// идемпотентен (retry после потери связи безопасен).
type MutationPayload struct {
	Connection ConnectionRef  `json:"connection"`
	TLS        TLSRef         `json:"tls,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Change     ChangeRef      `json:"change"`
}

// Marshal сериализует MutationPayload в json.RawMessage для Job.Payload.
func (p MutationPayload) Marshal() (json.RawMessage, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal mutation payload: %w", err)
	}
	return b, nil
}

// ParseMutationPayload разбирает Job.Payload мутирующего задания. Пустой
// payload или пустой ChangeRef.Kind — ошибка: мутация без описания изменения
// не имеет смысла.
func ParseMutationPayload(raw json.RawMessage) (MutationPayload, error) {
	if len(raw) == 0 {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload is empty")
	}
	// The generic v1 payload remains forward-compatible: older connectors have
	// historically ignored fields added by newer control planes. PostgreSQL v2
	// is a new security boundary, so first read only its discriminator and then
	// decode the complete document as a closed-world schema. This rejects raw
	// SQL and every other unreviewed field at any typed nesting level without
	// breaking the established generic kinds for other engines.
	var discriminator struct {
		Change struct {
			Kind string `json:"kind"`
		} `json:"change"`
	}
	if err := json.Unmarshal(raw, &discriminator); err != nil {
		return MutationPayload{}, fmt.Errorf("connector: parse mutation payload: %w", err)
	}
	var p MutationPayload
	kind := adapter.ChangeKind(discriminator.Change.Kind)
	if isPostgresV2ChangeKind(kind) {
		if err := decodeClosedMutationPayload(raw, &p); err != nil {
			return MutationPayload{}, fmt.Errorf("connector: parse PostgreSQL v2 mutation payload: %w", err)
		}
		if err := validatePostgresV2JSONShape(raw, kind); err != nil {
			return MutationPayload{}, err
		}
	} else if err := json.Unmarshal(raw, &p); err != nil {
		return MutationPayload{}, fmt.Errorf("connector: parse mutation payload: %w", err)
	}
	if p.Change.Kind == "" {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload has empty change kind")
	}
	kind = adapter.ChangeKind(p.Change.Kind)
	switch kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
		adapter.ChangeAccountRestore, adapter.ChangeRoleCreate, adapter.ChangeRolePolicyApply,
		adapter.ChangeRolePolicyVerify, adapter.ChangeRolePolicyCreate,
		adapter.ChangeRolePolicyCreateDatabase, adapter.ChangeResourceCreate,
		adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresAccountRestoreV2,
		adapter.ChangePostgresRoleCreateV2,
		adapter.ChangePostgresDatabaseCreateV2,
		adapter.ChangePostgresRolePolicyApplyV2, adapter.ChangePostgresRolePolicyVerifyV2,
		adapter.ChangePostgresRolePolicyAdoptV2, adapter.ChangePostgresRolePolicyRepairV2,
		adapter.ChangePostgresRolePolicyCreateV2, adapter.ChangePostgresRolePolicyCreateDatabaseV2,
		adapter.ChangePostgresStatsMembershipGrantV1, adapter.ChangePostgresStatsMembershipRevokeV1,
		adapter.ChangePostgresObjectACLGrantV1, adapter.ChangePostgresObjectACLRevokeV1:
		// Closed allowlist: arbitrary/new mutation kinds never cross the
		// connector trust boundary without an explicit protocol review.
	default:
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q is not allowed", p.Change.Kind)
	}
	if isPostgresV2ChangeKind(kind) {
		if err := validatePostgresV2Change(p, kind); err != nil {
			return MutationPayload{}, err
		}
		return p, nil
	}
	if p.Change.StatsMembership != nil {
		return MutationPayload{}, fmt.Errorf("connector: statistics pins require a typed statistics membership kind")
	}
	if p.Change.ObjectACL != nil || (p.Connection.Engine == "postgres" && strings.HasPrefix(p.Change.Permission, adapter.PostgresObjectACLPrefix)) {
		return MutationPayload{}, adapter.ErrPostgresObjectACL
	}
	if p.Connection.Engine == "postgres" && (kind == adapter.ChangeGrant || kind == adapter.ChangeRevoke) &&
		p.Change.Permission == "role:pg_read_all_stats" {
		return MutationPayload{}, fmt.Errorf("connector: protected statistics membership requires its pinned v1 contract")
	}
	if kind == adapter.ChangeResourceCreate {
		if p.Connection.Engine != "postgres" || p.Change.Resource == nil || p.Change.Resource.Kind != "database" {
			return MutationPayload{}, fmt.Errorf("connector: resource.create requires a PostgreSQL database")
		}
		if p.Change.Resource.Name == "" || p.Change.Account != (AccountRef{}) ||
			p.Change.Permission != "" || p.Change.Scope != "" ||
			len(p.Change.AccountPermissions) != 0 || len(p.Change.Attributes) != 0 ||
			p.Change.RolePolicySpec != nil || p.Change.ExpectedDatabaseOID != 0 {
			return MutationPayload{}, fmt.Errorf("connector: resource.create does not accept account, access or policy attributes")
		}
	} else if p.Change.Resource != nil {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q must not carry resource", p.Change.Kind)
	}
	if kind == adapter.ChangeRoleCreate {
		// A bare role is only a named NOLOGIN container, never an alternative
		// route for account creation, membership grants or arbitrary attributes.
		if p.Change.Account.Kind != "group" || p.Change.Account.EngineIdentity == "" {
			return MutationPayload{}, fmt.Errorf("connector: role.create requires a named group account")
		}
		if p.Change.Account.AuthenticationScope != "" || p.Change.Permission != "" || p.Change.Scope != "" ||
			len(p.Change.AccountPermissions) != 0 || len(p.Change.Attributes) != 0 {
			return MutationPayload{}, fmt.Errorf("connector: role.create does not accept access or account attributes")
		}
	}
	isRolePolicy := kind == adapter.ChangeRolePolicyApply || kind == adapter.ChangeRolePolicyVerify ||
		kind == adapter.ChangeRolePolicyCreate || kind == adapter.ChangeRolePolicyCreateDatabase
	if isRolePolicy && p.Change.RolePolicySpec == nil {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q requires role_policy_spec", p.Change.Kind)
	}
	if isRolePolicy && p.Change.ExpectedTargetIdentity == "" {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q requires expected_target_identity", p.Change.Kind)
	}
	if (kind == adapter.ChangeRolePolicyCreate || kind == adapter.ChangeRolePolicyCreateDatabase) &&
		p.Change.RolePolicySpec.Engine != "postgres" {
		return MutationPayload{}, fmt.Errorf("connector: role.policy.create requires PostgreSQL")
	}
	if kind == adapter.ChangeRolePolicyCreateDatabase {
		if p.Connection.Engine != "postgres" {
			return MutationPayload{}, fmt.Errorf("connector: role.policy.create_database requires PostgreSQL")
		}
		if p.Change.ExpectedDatabaseOID == 0 {
			return MutationPayload{}, fmt.Errorf("connector: role.policy.create_database requires expected_database_oid")
		}
		if p.Change.Account != (AccountRef{}) || p.Change.Permission != "" || p.Change.Scope != "" ||
			len(p.Change.AccountPermissions) != 0 || len(p.Change.Attributes) != 0 {
			return MutationPayload{}, fmt.Errorf("connector: role.policy.create_database does not accept account or access attributes")
		}
	} else if p.Change.ExpectedDatabaseOID != 0 {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q must not carry expected_database_oid", p.Change.Kind)
	}
	if !isRolePolicy && p.Change.RolePolicySpec != nil {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q must not carry role_policy_spec", p.Change.Kind)
	}
	if !isRolePolicy && kind != adapter.ChangeResourceCreate && p.Change.ExpectedTargetIdentity != "" {
		return MutationPayload{}, fmt.Errorf("connector: mutation payload change kind %q must not carry expected_target_identity", p.Change.Kind)
	}
	return p, nil
}

func decodeClosedMutationPayload(raw json.RawMessage, dst *MutationPayload) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

// RotatePayload — payload задания JobRotateCredential: descriptor подключения
// и несекретная ссылка на учётную запись, чей секрет ротируется. Control
// plane (worker либо API-слой) записывает новую версию секрета в Vault ДО
// выпуска задания и доставляет конкретное значение (и номер версии) кадром
// TypeCredentials (ADR-0014); connector применяет его к целевой системе.
// Сам пароль в payload не передаётся.
type RotatePayload struct {
	Connection ConnectionRef  `json:"connection"`
	TLS        TLSRef         `json:"tls,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	Account    AccountRef     `json:"account"`
	// VerifyCredential требует доказать вход ровно применённым credential до
	// успешного ответа. Используется link-and-manage; секрет остаётся в frame.
	VerifyCredential bool `json:"verify_credential,omitempty"`
}

// Marshal сериализует RotatePayload в json.RawMessage для Job.Payload.
func (p RotatePayload) Marshal() (json.RawMessage, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal rotate payload: %w", err)
	}
	return b, nil
}

// ParseRotatePayload разбирает Job.Payload задания JobRotateCredential.
// Пустая ссылка на учётную запись — ошибка: без identity ротация
// неадресуема (сам новый секрет приходит кадром TypeCredentials и
// проверяется на исполнении).
func ParseRotatePayload(raw json.RawMessage) (RotatePayload, error) {
	if len(raw) == 0 {
		return RotatePayload{}, fmt.Errorf("connector: rotate payload is empty")
	}
	var p RotatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return RotatePayload{}, fmt.Errorf("connector: parse rotate payload: %w", err)
	}
	if p.Account.EngineIdentity == "" {
		return RotatePayload{}, fmt.Errorf("connector: rotate payload has no account identity")
	}
	return p, nil
}

// AdminCredentialMode is the signed intent discriminator for connection
// administrator credential operations. It is repeated next to the dedicated
// JobKind so a mismatched/tampered payload fails before target access.
type AdminCredentialMode string

const (
	AdminCredentialModeSwitch AdminCredentialMode = "switch"
	AdminCredentialModeRotate AdminCredentialMode = "rotate"
)

// AdminCredentialPayload is the complete secret-free descriptor for
// JobAdminCredentialSwitch and JobAdminCredentialRotate. The candidate secret
// and its exact staged Vault version travel only in CredentialsFrame.Account;
// an optional old canonical credential travels in CredentialsFrame.Admin.
type AdminCredentialPayload struct {
	Connection                   ConnectionRef       `json:"connection"`
	TLS                          TLSRef              `json:"tls,omitempty"`
	Attributes                   map[string]any      `json:"attributes,omitempty"`
	CandidateUsername            string              `json:"candidate_username"`
	CandidateAuthMode            string              `json:"candidate_auth_mode,omitempty"`
	Epoch                        int64               `json:"epoch"`
	Mode                         AdminCredentialMode `json:"mode"`
	ExpectedCanonicalIdentity    string              `json:"expected_canonical_identity,omitempty"`
	ExpectedAuthorityFingerprint string              `json:"expected_authority_fingerprint,omitempty"`
	ExpectedTargetIdentity       string              `json:"expected_target_identity,omitempty"`
}

func (p AdminCredentialPayload) validate() error {
	if p.CandidateAuthMode != "" && p.CandidateAuthMode != "password" && p.CandidateAuthMode != "none" {
		return fmt.Errorf("connector: unsupported candidate auth mode")
	}
	if p.CandidateAuthMode == "none" && (p.Connection.Engine != "redis" || p.CandidateUsername != "default" || p.Mode != AdminCredentialModeSwitch) {
		return fmt.Errorf("connector: invalid no-auth switch candidate")
	}
	switch {
	case p.Connection.ID == "":
		return fmt.Errorf("connector: admin credential payload connection id is empty")
	case p.Connection.Engine == "":
		return fmt.Errorf("connector: admin credential payload connection engine is empty")
	case p.CandidateUsername == "":
		return fmt.Errorf("connector: admin credential payload candidate username is empty")
	case p.Epoch <= 0:
		return fmt.Errorf("connector: admin credential payload epoch must be positive")
	}
	if _, err := p.JobKind(); err != nil {
		return err
	}
	if p.Mode == AdminCredentialModeRotate {
		if p.ExpectedCanonicalIdentity == "" || p.ExpectedAuthorityFingerprint == "" ||
			p.ExpectedTargetIdentity == "" {
			return fmt.Errorf("connector: admin credential rotate payload requires an exact pre-mutation proof fence")
		}
	} else if p.ExpectedCanonicalIdentity != "" || p.ExpectedAuthorityFingerprint != "" ||
		p.ExpectedTargetIdentity != "" {
		return fmt.Errorf("connector: admin credential switch payload must not carry a rotation proof fence")
	}
	return nil
}

// JobKind returns the only connector job kind valid for the signed mode.
func (p AdminCredentialPayload) JobKind() (JobKind, error) {
	switch p.Mode {
	case AdminCredentialModeSwitch:
		return JobAdminCredentialSwitch, nil
	case AdminCredentialModeRotate:
		return JobAdminCredentialRotate, nil
	default:
		return "", fmt.Errorf("connector: admin credential payload mode %q is not allowed", p.Mode)
	}
}

// Marshal serializes the payload only after its closed contract is valid.
func (p AdminCredentialPayload) Marshal() (json.RawMessage, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("connector: marshal admin credential payload: %w", err)
	}
	return b, nil
}

// ParseAdminCredentialPayload rejects incomplete and unknown-mode intents.
// The agent separately compares JobKind() with the signed Job.Kind before it
// resolves an adapter or calls the target.
func ParseAdminCredentialPayload(raw json.RawMessage) (AdminCredentialPayload, error) {
	if len(raw) == 0 {
		return AdminCredentialPayload{}, fmt.Errorf("connector: admin credential payload is empty")
	}
	var p AdminCredentialPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return AdminCredentialPayload{}, fmt.Errorf("connector: parse admin credential payload: %w", err)
	}
	if err := p.validate(); err != nil {
		return AdminCredentialPayload{}, err
	}
	return p, nil
}
