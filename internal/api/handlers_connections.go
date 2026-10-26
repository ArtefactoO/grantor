package api

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
	"github.com/ArtefactoO/grantor/internal/netguard"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

// driftJSON — сводка расхождений connection в ответах API.
type driftJSON struct {
	UnmanagedBindings       int `json:"unmanaged_bindings"`
	DriftBindings           int `json:"drift_bindings"`
	MissingManagedResources int `json:"missing_managed_resources"`
	// MissingManagedAccounts — managed-аккаунты, которых нет в целевой
	// системе: discovery их не нашёл либо account.create не подтвердился.
	MissingManagedAccounts int `json:"missing_managed_accounts"`
}

type adminCredentialChangeJSON struct {
	OperationID              uuid.UUID  `json:"operation_id"`
	Mode                     string     `json:"mode"`
	Phase                    string     `json:"phase"`
	Status                   string     `json:"status"`
	CancelAllowed            bool       `json:"cancel_allowed"`
	TargetSideEffectPossible bool       `json:"target_side_effect_possible"`
	Retryable                bool       `json:"retryable"`
	ErrorCode                *string    `json:"error_code"`
	StartedAt                *time.Time `json:"started_at"`
	UpdatedAt                time.Time  `json:"updated_at"`
}

// connectionJSON — представление connection в ответах API. Секретов не
// содержит: vault_admin_path — только путь в Vault, не значение.
type connectionJSON struct {
	ID                  uuid.UUID       `json:"id"`
	DisplayName         string          `json:"display_name"`
	Engine              string          `json:"engine"`
	AuthMode            string          `json:"auth_mode"`
	Environment         string          `json:"environment"`
	Tags                []string        `json:"tags"`
	Endpoints           []string        `json:"endpoints"`
	ExecutionMode       string          `json:"execution_mode"`
	TLSConfig           json.RawMessage `json:"tls_config"`
	AdminCredentialMode string          `json:"admin_credential_mode"`
	VaultAdminPath      string          `json:"vault_admin_path"`
	Capabilities        []string        `json:"capabilities"`
	DiscoveryConfig     json.RawMessage `json:"discovery_config"`
	Status              string          `json:"status"`
	ServerVersion       string          `json:"server_version"`
	Topology            json.RawMessage `json:"topology"`
	LastDiscoveryAt     *time.Time      `json:"last_discovery_at"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
	// OperationID присутствует только в 202-ответе operational PATCH.
	OperationID *uuid.UUID `json:"operation_id,omitempty"`
	// SecurityFindings — вычисляемые security-пометки connection по
	// эффективному режиму tls_config (tls_disabled, tls_no_cert_verify,
	// tls_available_but_disabled). Опускается в JSON, когда пусто.
	SecurityFindings []string `json:"security_findings,omitempty"`
	// Drift присутствует в list/detail ответах; nil в ответе создания:
	// у свежесозданного connection инвентаря ещё нет.
	Drift                         *driftJSON                               `json:"drift,omitempty"`
	AdminCredentialChange         *adminCredentialChangeJSON               `json:"admin_credential_change,omitempty"`
	PostgresProvisioningAuthority *adapter.ProvisioningAuthorityAssessment `json:"postgres_provisioning_authority,omitempty"`
}

func toAdminCredentialChangeJSON(change admincredentials.Change) *adminCredentialChangeJSON {
	var errorCode *string
	if change.ErrorCode != "" {
		code := change.ErrorCode
		errorCode = &code
	}
	return &adminCredentialChangeJSON{
		OperationID:              change.OperationID,
		Mode:                     string(change.Mode),
		Phase:                    string(change.Phase),
		Status:                   string(change.OperationStatus),
		CancelAllowed:            change.CancelAllowed(),
		TargetSideEffectPossible: change.TargetSideEffectPossible,
		Retryable:                change.Retryable(),
		ErrorCode:                errorCode,
		StartedAt:                change.StartedAt,
		UpdatedAt:                change.UpdatedAt,
	}
}

// patchField отличает отсутствующее поле PATCH от заданного zero value.
// Явный null отклоняется: partial DTO не использует null как удаление и не
// должен молча превращать его в пустой operational-параметр.
type patchField[T any] struct {
	Set   bool
	Value T
}

func (f *patchField[T]) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("null is not allowed")
	}
	var value T
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	f.Set = true
	f.Value = value
	return nil
}

// patchConnectionRequest — строгий partial DTO. Любое поле вне этого списка
// (в частности engine/execution_mode/capabilities/status/credential/Vault)
// отклоняется decoder-ом до бизнес-логики.
type patchConnectionRequest struct {
	UpdatedAt       patchField[time.Time]       `json:"updated_at"`
	DisplayName     patchField[string]          `json:"display_name"`
	Tags            patchField[[]string]        `json:"tags"`
	Environment     patchField[string]          `json:"environment"`
	Endpoints       patchField[[]string]        `json:"endpoints"`
	TLSConfig       patchField[json.RawMessage] `json:"tls_config"`
	DiscoveryConfig patchField[json.RawMessage] `json:"discovery_config"`
}

func (r patchConnectionRequest) hasEdit() bool {
	return r.DisplayName.Set || r.Tags.Set || r.Environment.Set || r.Endpoints.Set ||
		r.TLSConfig.Set || r.DiscoveryConfig.Set
}

func connectionPatchChangedFields(before connections.Connection, after connections.PatchParams) []string {
	fields := make([]string, 0, 6)
	if before.DisplayName != after.DisplayName {
		fields = append(fields, "display_name")
	}
	if !slices.Equal(before.Tags, after.Tags) {
		fields = append(fields, "tags")
	}
	if before.Environment != after.Environment {
		fields = append(fields, "environment")
	}
	if !slices.Equal(before.Endpoints, after.Endpoints) {
		fields = append(fields, "endpoints")
	}
	if !rawJSONEqual(before.TLSConfig, after.TLSConfig) {
		fields = append(fields, "tls_config")
	}
	if !rawJSONEqual(before.DiscoveryConfig, after.DiscoveryConfig) {
		fields = append(fields, "discovery_config")
	}
	return fields
}

func rawJSONEqual(a, b json.RawMessage) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
	}
	return reflect.DeepEqual(left, right)
}

func patchFieldsOperational(fields []string) bool {
	return slices.ContainsFunc(fields, func(field string) bool {
		return field == "environment" || field == "endpoints" ||
			field == "tls_config" || field == "discovery_config"
	})
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		respondError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

type editableTLSConfig struct {
	Mode               string `json:"mode"`
	CACertPEM          string `json:"ca_cert_pem"`
	ClientCertPEM      string `json:"client_cert_pem"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type editableDiscoveryConfig struct {
	Database         string `json:"database"`
	SASLMechanism    string `json:"sasl_mechanism"`
	SecurityProtocol string `json:"security_protocol"`
	// AuthSource (mongodb) и DefaultAccountHost (mysql) задают недостающую
	// часть составной engine identity этих движков: adapter собирает из
	// базового имени принципала "user@authdb" и "user@host" соответственно
	// (adapter.EngineIdentityFormatter). Пустые значения означают дефолт
	// движка — "admin" и "%".
	AuthSource         string `json:"auth_source"`
	DefaultAccountHost string `json:"default_account_host"`
	// ReplicaSet (mongodb) — имя replica set для опций клиента.
	ReplicaSet string `json:"replica_set"`
	// RabbitMQPermissionTemplates — admin-managed allowlist точных regex-троек.
	RabbitMQPermissionTemplates *[]rabbitmqconfig.PermissionTemplate `json:"rabbitmq_permission_templates,omitempty"`
	// PostgresRolePolicyTemplates — structured fixed-profile NOLOGIN roles.
	PostgresRolePolicyTemplates *[]postgresconfig.RolePolicyTemplate `json:"postgres_role_policy_templates,omitempty"`
	// MongoDBRolePolicyTemplates — typed custom roles without raw BSON.
	MongoDBRolePolicyTemplates *[]mongodbconfig.RolePolicyTemplate `json:"mongodb_role_policy_templates,omitempty"`
}

func decodeStrictObject(raw json.RawMessage, dst any, field string) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) || trimmed[0] != '{' {
		return fmt.Errorf("%s must be a JSON object", field)
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid %s", field)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("invalid %s", field)
	}
	return nil
}

func validateTLSConfig(raw json.RawMessage) (editableTLSConfig, error) {
	var cfg editableTLSConfig
	if err := decodeStrictObject(raw, &cfg, "tls_config"); err != nil {
		return cfg, err
	}
	switch cfg.Mode {
	case "", "disabled", "require", "verify-ca", "verify-full":
	default:
		return cfg, fmt.Errorf("tls_config.mode %q is not supported", cfg.Mode)
	}
	if cfg.CACertPEM != "" {
		if _, err := adapterutil.RootCAPool([]byte(cfg.CACertPEM)); err != nil {
			return cfg, errors.New("tls_config.ca_cert_pem is not a valid certificate")
		}
	}
	if cfg.ClientCertPEM != "" {
		block, rest := pem.Decode([]byte(cfg.ClientCertPEM))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return cfg, errors.New("tls_config.client_cert_pem is not a valid certificate")
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return cfg, errors.New("tls_config.client_cert_pem is not a valid certificate")
		}
	}
	return cfg, nil
}

func validateDiscoveryConfig(raw json.RawMessage, engine string, tls editableTLSConfig) error {
	var cfg editableDiscoveryConfig
	if err := decodeStrictObject(raw, &cfg, "discovery_config"); err != nil {
		return err
	}
	if engine != "kafka" && (cfg.SASLMechanism != "" || cfg.SecurityProtocol != "") {
		return errors.New("discovery_config SASL fields are supported only for kafka")
	}
	if cfg.AuthSource != "" && engine != "mongodb" {
		return errors.New("discovery_config.auth_source is supported only for mongodb")
	}
	if cfg.DefaultAccountHost != "" && engine != "mysql" {
		return errors.New("discovery_config.default_account_host is supported only for mysql")
	}
	if cfg.ReplicaSet != "" && engine != "mongodb" {
		return errors.New("discovery_config.replica_set is supported only for mongodb")
	}
	if cfg.RabbitMQPermissionTemplates != nil && engine != "rabbitmq" {
		return errors.New("discovery_config.rabbitmq_permission_templates is supported only for rabbitmq")
	}
	if cfg.RabbitMQPermissionTemplates != nil {
		if err := rabbitmqconfig.Validate(*cfg.RabbitMQPermissionTemplates); err != nil {
			return fmt.Errorf("discovery_config: %w", err)
		}
	}
	if cfg.PostgresRolePolicyTemplates != nil && engine != "postgres" {
		return errors.New("discovery_config.postgres_role_policy_templates is supported only for postgres")
	}
	if cfg.PostgresRolePolicyTemplates != nil {
		if err := postgresconfig.Validate(*cfg.PostgresRolePolicyTemplates); err != nil {
			return fmt.Errorf("discovery_config: %w", err)
		}
	}
	if cfg.MongoDBRolePolicyTemplates != nil && engine != "mongodb" {
		return errors.New("discovery_config.mongodb_role_policy_templates is supported only for mongodb")
	}
	if cfg.MongoDBRolePolicyTemplates != nil {
		if err := mongodbconfig.Validate(*cfg.MongoDBRolePolicyTemplates); err != nil {
			return fmt.Errorf("discovery_config: %w", err)
		}
	}
	if strings.ContainsAny(cfg.AuthSource, "@") || strings.ContainsAny(cfg.DefaultAccountHost, "@") {
		return errors.New("discovery_config identity parts must not contain '@'")
	}
	if engine != "kafka" {
		return nil
	}
	switch cfg.SASLMechanism {
	case "", "none", "plain", "scram-sha-256", "scram-sha-512":
	default:
		return fmt.Errorf("discovery_config.sasl_mechanism %q is not supported", cfg.SASLMechanism)
	}
	switch cfg.SecurityProtocol {
	case "", "plaintext", "sasl_plaintext", "sasl_ssl", "ssl":
	default:
		return fmt.Errorf("discovery_config.security_protocol %q is not supported", cfg.SecurityProtocol)
	}
	tlsOn := tls.Mode != "" && tls.Mode != "disabled"
	if (cfg.SecurityProtocol == "sasl_ssl" || cfg.SecurityProtocol == "ssl") && !tlsOn {
		return fmt.Errorf("discovery_config.security_protocol %q requires TLS", cfg.SecurityProtocol)
	}
	if (cfg.SecurityProtocol == "plaintext" || cfg.SecurityProtocol == "sasl_plaintext") && tlsOn {
		return fmt.Errorf("discovery_config.security_protocol %q conflicts with TLS", cfg.SecurityProtocol)
	}
	return nil
}

func postgresRolePolicySpecs(raw json.RawMessage) ([]adapter.RolePolicySpec, error) {
	var cfg editableDiscoveryConfig
	if err := decodeStrictObject(raw, &cfg, "discovery_config"); err != nil {
		return nil, err
	}
	if cfg.PostgresRolePolicyTemplates == nil {
		return nil, nil
	}
	if err := postgresconfig.Validate(*cfg.PostgresRolePolicyTemplates); err != nil {
		return nil, err
	}
	out := make([]adapter.RolePolicySpec, 0, len(*cfg.PostgresRolePolicyTemplates))
	for _, template := range *cfg.PostgresRolePolicyTemplates {
		template = postgresconfig.Normalize(template)
		out = append(out, adapter.RolePolicySpec{
			Engine: "postgres", Key: template.Key, Name: template.Name,
			Description: template.Description, RoleName: template.RoleName,
			Database: template.Database, Schemas: slices.Clone(template.Schemas),
			OwnerRoles:   slices.Clone(template.OwnerRoles),
			CreatorRoles: slices.Clone(template.CreatorRoles), Profile: template.Profile,
		})
	}
	return out, nil
}

func mongodbRolePolicySpecs(raw json.RawMessage) ([]adapter.RolePolicySpec, error) {
	var cfg editableDiscoveryConfig
	if err := decodeStrictObject(raw, &cfg, "discovery_config"); err != nil {
		return nil, err
	}
	if cfg.MongoDBRolePolicyTemplates == nil {
		return nil, nil
	}
	if err := mongodbconfig.Validate(*cfg.MongoDBRolePolicyTemplates); err != nil {
		return nil, err
	}
	out := make([]adapter.RolePolicySpec, 0, len(*cfg.MongoDBRolePolicyTemplates))
	for _, template := range *cfg.MongoDBRolePolicyTemplates {
		out = append(out, mongodbconfig.Spec(template))
	}
	return out, nil
}

// connectionListResponse — тело ответа GET /api/v1/connections.
type connectionListResponse struct {
	Connections []connectionJSON `json:"connections"`
}

// toConnectionJSON собирает connectionJSON из доменной модели; nil-слайсы
// заменяются пустыми, чтобы в JSON были [] вместо null.
func toConnectionJSON(c connections.Connection, drift *inventory.DriftCounters) connectionJSON {
	if c.AuthMode == "" {
		c.AuthMode = "password"
	}
	out := connectionJSON{
		ID:                            c.ID,
		DisplayName:                   c.DisplayName,
		Engine:                        c.Engine,
		AuthMode:                      c.AuthMode,
		Environment:                   c.Environment,
		Tags:                          emptyIfNil(c.Tags),
		Endpoints:                     emptyIfNil(c.Endpoints),
		ExecutionMode:                 c.ExecutionMode,
		TLSConfig:                     rawOrEmptyObject(c.TLSConfig),
		AdminCredentialMode:           c.AdminCredentialMode,
		VaultAdminPath:                c.VaultAdminPath,
		Capabilities:                  connectionCapabilitiesForProjection(c),
		DiscoveryConfig:               rawOrEmptyObject(c.DiscoveryConfig),
		Status:                        string(c.Status),
		ServerVersion:                 c.ServerVersion,
		Topology:                      connectionResponseTopology(c),
		LastDiscoveryAt:               c.LastDiscoveryAt,
		CreatedAt:                     c.CreatedAt,
		UpdatedAt:                     c.UpdatedAt,
		SecurityFindings:              securityFindings(c),
		PostgresProvisioningAuthority: postgresProvisioningAuthorityProjection(c),
	}
	if drift != nil {
		out.Drift = &driftJSON{
			UnmanagedBindings:       drift.UnmanagedBindings,
			DriftBindings:           drift.DriftBindings,
			MissingManagedResources: drift.MissingManagedResources,
			MissingManagedAccounts:  drift.MissingManagedAccounts,
		}
	}
	return out
}

func connectionCapabilitiesForProjection(c connections.Connection) []string {
	caps := connections.EffectiveCapabilities(c, c.Capabilities)
	if c.Engine == "postgres" {
		authority := postgresProvisioningAuthorityProjection(c)
		if authority != nil && authority.Status == adapter.ProvisioningAuthorityConfirmed &&
			authority.Reason == adapter.ProvisioningAuthoritySuperuserConfirmed &&
			c.Status == connections.StatusActive {
			return emptyIfNil(caps)
		}
		caps = slices.DeleteFunc(slices.Clone(caps), func(capability string) bool {
			if capability == string(adapter.ResourceCapability("create", resourceKindDatabase)) {
				return true
			}
			switch adapter.Capability(capability) {
			case adapter.CapAccountCreate,
				adapter.CapAccountRestore,
				adapter.CapRoleCreate,
				adapter.CapRolePolicyApply,
				adapter.CapRolePolicyCreate,
				adapter.CapPostgresSuperuserDirectV1,
				adapter.CapPostgresStatsMembershipV1, adapter.CapPostgresObjectACLV1:
				return true
			default:
				return false
			}
		})
	}
	return emptyIfNil(caps)
}

func postgresProvisioningAuthorityProjection(c connections.Connection) *adapter.ProvisioningAuthorityAssessment {
	if c.Engine != "postgres" {
		return nil
	}
	out := adapter.ProvisioningAuthorityAssessment{
		Status:            adapter.ProvisioningAuthorityUnknown,
		Reason:            adapter.ProvisioningAuthorityProbeFailed,
		ConfigIncarnation: connections.ConfigIncarnation(c),
	}
	var topology map[string]any
	if len(c.Topology) == 0 || json.Unmarshal(c.Topology, &topology) != nil {
		return &out
	}
	assessment, ok := adapter.ProvisioningAuthorityFromTopology(
		topology, adapter.PostgresProvisioningAuthorityTopologyKey,
	)
	if !ok {
		return &out
	}
	expectedIdentity := adapterutil.StringAttr(topology, "admin_credential_canonical_identity")
	if expectedIdentity == "" {
		expectedIdentity = assessment.ExpectedAdminIdentity
	}
	out = assessment.ValidateSnapshot(
		expectedIdentity, connections.ConfigIncarnation(c), c.LastDiscoveryAt,
	)
	if c.Status != connections.StatusActive {
		out.Status = adapter.ProvisioningAuthorityInvalidCurrentVersion
		out.Reason = adapter.ProvisioningAuthorityConnectionSnapshotNotActive
	}
	return &out
}

// emptyIfNil заменяет nil-слайс пустым для JSON [] вместо null.
func emptyIfNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// rawOrEmptyObject возвращает jsonb-документ или пустой объект, если
// документ не задан.
func rawOrEmptyObject(v json.RawMessage) json.RawMessage {
	if len(v) == 0 {
		return json.RawMessage("{}")
	}
	return v
}

// Security findings connection (docs/adr/0007-security-hardening-decisions.md).
// Исходят из ЭФФЕКТИВНОГО режима tls_config, а не из отдельного флага:
// небезопасный выбор подключения должен быть виден в API и audit, при этом
// БД без TLS продолжают работать (дефолт режима не меняется).
const (
	// findingTLSDisabled — соединение без шифрования: mode пустой или
	// "disabled". Дефолтное поведение (plaintext) сохраняется; finding лишь
	// делает выбор видимым.
	findingTLSDisabled = "tls_disabled"
	// findingTLSNoCertVerify — шифрование без проверки сертификата: mode
	// "require" без CA-сертификата, либо явный insecure_skip_verify.
	findingTLSNoCertVerify = "tls_no_cert_verify"
	// findingTLSAvailableButDisabled — сервер поддерживает TLS (по данным
	// discovery, topology.server_supports_tls), а connection настроен на
	// незашифрованный режим.
	findingTLSAvailableButDisabled = "tls_available_but_disabled"
	// findingAuthenticationDisabled — целевая система не аутентифицирует
	// клиентов вообще: любой, кто дотянулся до неё по сети, читает и пишет
	// данные без учётных данных. Управление правами на такой системе —
	// фикция: grantor записывает ACL, которые никто не спрашивает. Признак
	// приходит из discovery (adapterutil.AuthenticationKey), потому что знать
	// его может только adapter.
	findingAuthenticationDisabled = "authentication_disabled"
)

// tlsModeDisabled — режим tls_config без шифрования; пустой mode
// трактуется как disabled (см. effectiveTLSMode и adapter buildTLSConfig).
const tlsModeDisabled = "disabled"

// tlsModeRequire — режим tls_config с шифрованием, но без обязательной
// проверки сертификата (семантика libpq sslmode=require).
const tlsModeRequire = "require"

// tlsConfigView — подмножество connections.tls_config, читаемое API для
// вычисления security-findings и audit. Полный формат tls_config
// принадлежит executor discovery (internal/jobs); здесь берутся только
// поля, влияющие на безопасность подключения.
type tlsConfigView struct {
	Mode               string `json:"mode"`
	CACertPEM          string `json:"ca_cert_pem"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// parseTLSConfigView разбирает tls_config в tlsConfigView. Пустой или
// невалидный документ даёт нулевое значение (effectiveTLSMode трактует его
// как disabled): значения — подсказка для findings и audit, а не строгий
// инвариант (формат tls_config валидирует discovery).
func parseTLSConfigView(raw json.RawMessage) tlsConfigView {
	var v tlsConfigView
	if len(raw) == 0 {
		return v
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return tlsConfigView{}
	}
	return v
}

// effectiveTLSMode возвращает фактический режим подключения: пустой mode
// означает disabled (соединение без шифрования), как и в adapter.
func effectiveTLSMode(v tlsConfigView) string {
	if v.Mode == "" {
		return tlsModeDisabled
	}
	return v.Mode
}

// topologyView — подмножество connections.topology, читаемое API. Полный
// формат topology принадлежит discovery; здесь берётся только факт
// поддержки сервером TLS (opportunistic detection в postgres-адаптере).
type topologyView struct {
	// ServerSupportsTLS — nil, если discovery не определял поддержку TLS
	// (например по mode с шифрованием или до первого discovery).
	ServerSupportsTLS *bool `json:"server_supports_tls"`
	// AuthenticationEnabled — nil, если adapter про аутентификацию клиентов
	// ничего не сообщил (см. adapterutil.AuthenticationKey).
	AuthenticationEnabled *bool `json:"authentication_enabled"`
}

// serverSupportsTLS сообщает, зафиксировал ли discovery поддержку TLS у
// целевого сервера. Отсутствие ключа или невалидный документ трактуются
// как «не определено» (false).
func serverSupportsTLS(topology json.RawMessage) bool {
	if len(topology) == 0 {
		return false
	}
	var v topologyView
	if err := json.Unmarshal(topology, &v); err != nil {
		return false
	}
	return v.ServerSupportsTLS != nil && *v.ServerSupportsTLS
}

// authenticationDisabled сообщает, что adapter ЯВНО объявил отсутствие
// аутентификации клиентов. Отсутствие ключа — не сигнал: движок мог просто
// ничего не сообщить, и выдавать за это finding означало бы пугать оператора
// на ровном месте.
func authenticationDisabled(topology []byte) bool {
	var v topologyView
	if err := json.Unmarshal(topology, &v); err != nil {
		return false
	}
	return v.AuthenticationEnabled != nil && !*v.AuthenticationEnabled
}

// securityFindings вычисляет security-findings connection для ответов API
// и audit по эффективному режиму tls_config
// (docs/adr/0007-security-hardening-decisions.md, раздел 5.2 архитектуры):
//   - disabled/пустой mode -> tls_disabled (+ tls_available_but_disabled,
//     если discovery определил поддержку TLS сервером);
//   - require без CA или явный insecure_skip_verify -> tls_no_cert_verify;
//   - verify-ca/verify-full небезопасны только при insecure_skip_verify.
func securityFindings(c connections.Connection) []string {
	view := parseTLSConfigView(c.TLSConfig)
	var findings []string
	if c.AuthMode == "none" || authenticationDisabled(c.Topology) {
		findings = append(findings, findingAuthenticationDisabled)
	}
	switch effectiveTLSMode(view) {
	case tlsModeDisabled:
		findings = append(findings, findingTLSDisabled)
		if serverSupportsTLS(c.Topology) {
			findings = append(findings, findingTLSAvailableButDisabled)
		}
	case tlsModeRequire:
		if view.CACertPEM == "" || view.InsecureSkipVerify {
			findings = append(findings, findingTLSNoCertVerify)
		}
	default:
		// verify-ca / verify-full и прочие явные режимы шифруют и проверяют
		// сертификат; небезопасны только при insecure_skip_verify.
		if view.InsecureSkipVerify {
			findings = append(findings, findingTLSNoCertVerify)
		}
	}
	return findings
}

// listConnections — GET /api/v1/connections (viewer): видимые подключения
// с одной общей выборкой drift-счётчиков после scope-фильтра.
func (s *Server) listConnections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	conns, err := s.connections.List(ctx, s.pool)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope-фильтр: operator видит только connections своих окружений
	// (deny-by-default при пустых политиках). admin/viewer/disabled — все.
	conns, err = s.filterConnectionsByScope(ctx, sess, conns)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	connectionIDs := make([]uuid.UUID, 0, len(conns))
	for _, conn := range conns {
		connectionIDs = append(connectionIDs, conn.ID)
	}
	summaries, err := s.inventory.DriftSummaries(ctx, s.pool, connectionIDs)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]connectionJSON, 0, len(conns))
	for i := range conns {
		drift := summaries[conns[i].ID]
		item := toConnectionJSON(conns[i], &drift)
		if conns[i].Status == connections.StatusCredentialUpdating {
			change, changeErr := s.adminCredentialChanges.Active(ctx, s.pool, conns[i].ID)
			if errors.Is(changeErr, admincredentials.ErrNotFound) {
				// A partially rolled-back/manual metadata state must not freeze the
				// whole connections list. Surface the latest terminal receipt so UI
				// shows a blocked lifecycle instead of hiding every connection.
				change, changeErr = s.adminCredentialChanges.Latest(ctx, s.pool, conns[i].ID)
			}
			if changeErr != nil {
				respondStoreError(ctx, w, changeErr)
				return
			}
			item.AdminCredentialChange = toAdminCredentialChangeJSON(change)
		}
		out = append(out, item)
	}
	respondJSON(w, http.StatusOK, connectionListResponse{Connections: out})
}

// getConnection — GET /api/v1/connections/{id} (viewer): connection с
// drift-сводкой.
func (s *Server) getConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: operator видит connection, только если его окружение разрешено.
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	drift, err := s.inventory.DriftSummary(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := toConnectionJSON(conn, &drift)
	if r.URL.Query().Get("view") == "summary" && conn.Engine == "postgres" {
		out.Topology = compactPostgresTopology(out.Topology)
	}
	change, err := s.adminCredentialChanges.Latest(ctx, s.pool, id)
	if err == nil {
		out.AdminCredentialChange = toAdminCredentialChangeJSON(change)
	} else if !errors.Is(err, admincredentials.ErrNotFound) {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, out)
}

// patchConnection — PATCH /api/v1/connections/{id} (admin). DTO разделён
// на metadata-only и operational поля. Оба пути сериализованы тем же
// advisory lock, что worker mutations, и защищены updated_at CAS.
// Operational path дополнительно сбрасывает сведения старого snapshot,
// переводит connection в discovering и транзакционно ставит ровно одну
// connection.discover operation.
func (s *Server) patchConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req patchConnectionRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if !req.UpdatedAt.Set || req.UpdatedAt.Value.IsZero() {
		respondError(w, http.StatusBadRequest, "updated_at is required")
		return
	}
	if !req.hasEdit() {
		respondError(w, http.StatusBadRequest, "at least one editable field is required")
		return
	}
	if req.DisplayName.Set && strings.TrimSpace(req.DisplayName.Value) == "" {
		respondError(w, http.StatusBadRequest, "display_name must not be empty")
		return
	}
	if req.Environment.Set && strings.TrimSpace(req.Environment.Value) == "" {
		respondError(w, http.StatusBadRequest, "environment must not be empty")
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	if req.Environment.Set && s.respondScopeError(ctx, w, s.checkConnectionScope(ctx, sess, req.Environment.Value)) {
		return
	}
	// A delegated key must not redirect an already stored admin credential or
	// change the approved source's environment. Reapproval is interactive.
	if sess.APIKeyID != "" && (req.Environment.Set || req.Endpoints.Set || req.TLSConfig.Set || req.DiscoveryConfig.Set) {
		respondError(w, http.StatusForbidden, "connection target changes require an interactive admin session")
		return
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	before, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !before.UpdatedAt.Equal(req.UpdatedAt.Value) {
		respondStoreError(ctx, w, connections.ErrVersionConflict)
		return
	}
	params := connections.PatchParams{
		DisplayName:       before.DisplayName,
		Environment:       before.Environment,
		Tags:              slices.Clone(before.Tags),
		Endpoints:         slices.Clone(before.Endpoints),
		TLSConfig:         slices.Clone(before.TLSConfig),
		DiscoveryConfig:   slices.Clone(before.DiscoveryConfig),
		ExpectedUpdatedAt: req.UpdatedAt.Value,
		ExpectedStatus:    before.Status,
	}
	if req.DisplayName.Set {
		params.DisplayName = req.DisplayName.Value
	}
	if req.Tags.Set {
		params.Tags = slices.Clone(req.Tags.Value)
	}
	if req.Environment.Set {
		params.Environment = req.Environment.Value
	}
	if req.Endpoints.Set {
		params.Endpoints = slices.Clone(req.Endpoints.Value)
	}
	if req.TLSConfig.Set {
		params.TLSConfig = slices.Clone(req.TLSConfig.Value)
	}
	if req.DiscoveryConfig.Set {
		params.DiscoveryConfig = slices.Clone(req.DiscoveryConfig.Value)
	}
	changedFields := connectionPatchChangedFields(before, params)
	if len(changedFields) == 0 {
		respondError(w, http.StatusBadRequest, "patch does not change editable fields")
		return
	}
	operational := patchFieldsOperational(changedFields)
	params.Operational = operational
	if operational && !connections.CanReconfigure(before.Status) {
		respondError(w, http.StatusConflict,
			fmt.Sprintf("operational edit is not allowed for connection status %q", before.Status))
		return
	}
	templateCatalogChanged := before.Engine == "rabbitmq" && req.DiscoveryConfig.Set &&
		!rawJSONEqual(before.DiscoveryConfig, params.DiscoveryConfig)
	if templateCatalogChanged {
		var transitionBusy bool
		if err := tx.QueryRow(ctx, `
			select exists (
				select 1 from bindings b
				join accounts a on a.id = b.account_id
				where a.connection_id = $1 and b.transition_operation_id is not null
			)`, id).Scan(&transitionBusy); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if transitionBusy {
			respondError(w, http.StatusConflict,
				"connection has an unfinished access replacement; retry or reverse it before changing permission templates")
			return
		}
	}
	if !operational && !connections.CanEditMetadata(before.Status) {
		respondError(w, http.StatusConflict,
			fmt.Sprintf("metadata edit is not allowed for connection status %q", before.Status))
		return
	}

	if operational {
		if len(params.Endpoints) == 0 {
			respondError(w, http.StatusBadRequest, "endpoints must be a non-empty list")
			return
		}
		for _, endpoint := range params.Endpoints {
			if err := validateEndpoint(endpoint); err != nil {
				respondError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := checkEndpointPolicy(ctx, s.netPolicy, s.resolver, endpoint); err != nil {
				respondError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		tlsCfg, err := validateTLSConfig(params.TLSConfig)
		if err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := validateDiscoveryConfig(params.DiscoveryConfig, before.Engine, tlsCfg); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		if (before.Engine == "postgres" || before.Engine == "mongodb") && req.DiscoveryConfig.Set {
			var specs []adapter.RolePolicySpec
			var err error
			switch before.Engine {
			case "postgres":
				specs, err = postgresRolePolicySpecs(params.DiscoveryConfig)
			case "mongodb":
				specs, err = mongodbRolePolicySpecs(params.DiscoveryConfig)
			}
			if err != nil {
				respondError(w, http.StatusBadRequest, err.Error())
				return
			}
			if err := rolepolicies.NewStore().ValidateTemplateChange(ctx, tx, id, specs); err != nil {
				if errors.Is(err, rolepolicies.ErrConflict) ||
					errors.Is(err, rolepolicies.ErrUnsafeTemplateChange) {
					respondError(w, http.StatusConflict, err.Error())
				} else {
					respondStoreError(ctx, w, err)
				}
				return
			}
		}
	}

	after, err := s.connections.PatchCAS(ctx, tx, id, params)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	var operationID *uuid.UUID
	if operational {
		payload, err := json.Marshal(map[string]any{
			"reason":              "connection_reconfigured",
			"previous_updated_at": req.UpdatedAt.Value,
		})
		if err != nil {
			respondStoreError(ctx, w, fmt.Errorf("api: marshal connection reconfigure payload: %w", err))
			return
		}
		key := fmt.Sprintf("connection-reconfigure:%s:%d", id, req.UpdatedAt.Value.UnixMicro())
		op, created, err := s.operations.Create(ctx, tx, operations.CreateParams{
			Kind:           jobs.KindConnectionDiscover,
			IdempotencyKey: &key,
			ConnectionID:   &id,
			Payload:        payload,
			ActorType:      sess.ActorType(),
			ActorID:        sess.ActorID(),
			CorrelationID:  uuid.NewString(),
		})
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if !created {
			respondError(w, http.StatusConflict, "connection reconfigure already requested; reload current state")
			return
		}
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		operationID = &op.ID
	}

	auditEvent := audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionConnectionUpdated,
		ConnectionID: &id,
		OperationID:  operationID,
		Result:       audit.ResultSuccess,
	}
	// Audit фиксирует только имена изменённых полей и state/CAS-границы.
	// Значения tls_config/discovery_config и certificate material намеренно
	// не сериализуются даже несмотря на их несекретный контракт.
	if err := s.writeAudit(ctx, tx, auditEvent, map[string]any{
		"changed_fields":      changedFields,
		"operational":         operational,
		"previous_status":     before.Status,
		"status":              after.Status,
		"previous_updated_at": before.UpdatedAt,
		"updated_at":          after.UpdatedAt,
		"snapshot_reset":      operational,
		"discovery_queued":    operational,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit patch connection: %w", err))
		return
	}
	out := toConnectionJSON(after, nil)
	out.OperationID = operationID
	status := http.StatusOK
	if operational {
		status = http.StatusAccepted
	}
	respondJSON(w, status, out)
}

// adminCredentialRequest — admin credential в теле создания connection.
// Значения уходят только в Vault и не логируются.
type adminCredentialRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// createConnectionRequest — тело POST /api/v1/connections.
type createConnectionRequest struct {
	DisplayName string   `json:"display_name"`
	Engine      string   `json:"engine"`
	AuthMode    string   `json:"auth_mode"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags"`
	Endpoints   []string `json:"endpoints"`
	// ExecutionMode — режим исполнения операций подключения: "direct"
	// (по умолчанию, пустое значение) или "connector" (целевая система в
	// изолированном сегменте, операции идут через execution connector).
	ExecutionMode   string                  `json:"execution_mode"`
	TLSConfig       json.RawMessage         `json:"tls_config"`
	DiscoveryConfig json.RawMessage         `json:"discovery_config"`
	AdminCredential *adminCredentialRequest `json:"admin_credential"`
}

// validate проверяет тело создания connection. engines — допустимые
// значения engine (в runtime — adapter.Engines(); в unit-тестах —
// фиксированный список). Тексты ошибок уходят клиенту с кодом 400 и не
// содержат значений credential.
func (req *createConnectionRequest) validate(engines []string) error {
	if strings.TrimSpace(req.DisplayName) == "" {
		return errors.New("display_name is required")
	}
	if req.Engine == "" {
		return errors.New("engine is required")
	}
	if !slices.Contains(engines, req.Engine) {
		return fmt.Errorf("unknown engine %q (supported: %s)", req.Engine, strings.Join(engines, ", "))
	}
	if req.ExecutionMode != "" && !connections.ValidExecutionMode(req.ExecutionMode) {
		return fmt.Errorf("unknown execution_mode %q (supported: %s, %s)",
			req.ExecutionMode, connections.ExecutionModeDirect, connections.ExecutionModeConnector)
	}
	if len(req.Endpoints) == 0 {
		return errors.New("endpoints must be a non-empty list")
	}
	for _, ep := range req.Endpoints {
		if err := validateEndpoint(ep); err != nil {
			return err
		}
	}
	if err := validateConnectionAuthMode(req.Engine, req.AuthMode); err != nil {
		return err
	}
	if req.AuthMode == "none" {
		if req.AdminCredential != nil {
			return errors.New("admin_credential must be omitted in no-auth mode")
		}
		return nil
	}
	if req.AdminCredential == nil {
		return errors.New("admin_credential is required")
	}
	if req.AdminCredential.Username == "" {
		return errors.New("admin_credential.username is required")
	}
	if req.AdminCredential.Password == "" {
		return errors.New("admin_credential.password is required")
	}
	return nil
}

// validateEndpoint проверяет формат endpoint: "host" или "host:port"
// (IPv6 — в квадратных скобках, например "[::1]:5432"). Пустые значения
// и пробельные символы запрещены. Проверка формата отделена от сетевой
// политики (SSRF-guard): её выполняет checkEndpointPolicy.
func validateEndpoint(ep string) error {
	if ep == "" {
		return errors.New("endpoints must not contain empty values")
	}
	if strings.ContainsAny(ep, " \t") {
		return fmt.Errorf("endpoint %q must not contain whitespace", ep)
	}
	host, _, err := splitEndpoint(ep)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("endpoint %q: host is required", ep)
	}
	return nil
}

// splitEndpoint разбирает endpoint "host" или "host:port". Порт возвращается
// как 0, если он не указан. Пустой host допускается на этом уровне (его
// отвергает validateEndpoint); невалидный порт — ошибка.
func splitEndpoint(ep string) (host string, port int, err error) {
	if !strings.Contains(ep, ":") {
		return ep, 0, nil
	}
	h, p, err := net.SplitHostPort(ep)
	if err != nil {
		return "", 0, fmt.Errorf("endpoint %q: expected host or host:port", ep)
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("endpoint %q: invalid port", ep)
	}
	return h, n, nil
}

// checkEndpointPolicy применяет сетевую политику (SSRF-guard) к endpoint:
// разбирает host:port и вызывает policy.CheckEndpoint. Ошибка формулируется
// как «endpoint %q is not allowed: <причина>» и не раскрывает резолвленные
// IP. Функция чистая (без Server) — тестируется без БД.
func checkEndpointPolicy(ctx context.Context, policy netguard.Policy, resolver netguard.Resolver, ep string) error {
	host, port, err := splitEndpoint(ep)
	if err != nil {
		return err
	}
	if err := policy.CheckEndpoint(ctx, host, port, resolver); err != nil {
		return fmt.Errorf("endpoint %q is not allowed: %w", ep, err)
	}
	return nil
}

// createConnection — POST /api/v1/connections (admin): создаёт
// connection в статусе draft и кладёт admin credential в Vault.
//
// Порядок в одной транзакции metadata database: INSERT connection ->
// Vault Put по пути connections/<id>/admin -> UPDATE vault_admin_path ->
// audit -> COMMIT. Vault не транзакционен с PostgreSQL, поэтому:
//   - при ошибке Put транзакция откатывается — ни connection, ни секрета;
//   - при ошибке COMMIT после Put в Vault остаётся сиротский секрет по
//     пути с уже никем не занятым uuid — безвреден, TODO(этап 1b):
//     фоновая уборка сиротских путей.
//
// vault_admin_path пишется отдельным локальным UPDATE (а не через
// connections.Store): путь содержит id, который известен только после
// INSERT, а точечного update этого поля у store нет. Локальный SQL здесь
// — осознанное исключение из правила «SQL живёт в stores»: одна колонка,
// та же транзакция.
func (s *Server) createConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	var req createConnectionRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.respondScopeError(ctx, w, s.checkConnectionScope(ctx, sess, req.Environment)) {
		return
	}
	if err := req.validate(adapter.Engines()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Та же per-engine проверка, что у PATCH: мусор в discovery_config или
	// tls_config иначе всплыл бы только при первом discovery.
	tlsCfg := editableTLSConfig{}
	if len(bytes.TrimSpace(req.TLSConfig)) > 0 {
		var err error
		if tlsCfg, err = validateTLSConfig(req.TLSConfig); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if len(bytes.TrimSpace(req.DiscoveryConfig)) > 0 {
		if err := validateDiscoveryConfig(req.DiscoveryConfig, req.Engine, tlsCfg); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	// SSRF-guard: каждый endpoint проходит сетевую политику. Проверка
	// после формата и до обращения к Vault: заблокированный адрес — 400,
	// а не 503. Резолвленные IP наружу не отдаются.
	for _, ep := range req.Endpoints {
		if err := checkEndpointPolicy(ctx, s.netPolicy, s.resolver, ep); err != nil {
			respondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if req.AuthMode != "none" && s.vault == nil {
		respondError(w, http.StatusServiceUnavailable,
			"vault is not configured: cannot store admin credential; set GRANTOR_VAULT_ADDR")
		return
	}
	ad, err := adapter.New(req.Engine)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("engine %q is not supported by this control plane", req.Engine))
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// После успешного Commit откат — no-op с ErrTxClosed; ошибку
	// игнорируем сознательно.
	defer tx.Rollback(ctx) //nolint:errcheck

	conn, err := s.connections.Create(ctx, tx, connections.CreateParams{
		DisplayName:   req.DisplayName,
		Engine:        req.Engine,
		AuthMode:      req.AuthMode,
		Environment:   req.Environment,
		Tags:          req.Tags,
		Endpoints:     req.Endpoints,
		ExecutionMode: req.ExecutionMode,
		TLSConfig:     req.TLSConfig,
		// Engine-wide манифест — верхняя граница; store сужает его под
		// конфигурацию этого подключения (connections.EffectiveCapabilities),
		// а discovery и operational PATCH пересчитывают набор снова.
		Capabilities:    ad.Manifest().CapabilityNames(),
		DiscoveryConfig: req.DiscoveryConfig,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if req.AuthMode != "none" {
		path, err := vault.ConnectionAdminPath(conn.ID.String())
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if _, err := s.vault.Put(ctx, path, map[string]any{
			"username": req.AdminCredential.Username,
			"password": req.AdminCredential.Password,
		}); err != nil {
			// Ошибки vault-клиента содержат только операцию, mount и path.
			slog.ErrorContext(ctx, "api: store admin credential", "connection_id", conn.ID, "error", err)
			respondError(w, http.StatusBadGateway, "failed to store admin credential in vault")
			return
		}
		// admin_credential_set_at фиксирует момент записи admin credential в
		// Vault — источник истины возраста для aging finding (раздел 17.3, R12).
		// Проставляется здесь же (create — единственная точка записи admin
		// credential; отдельного flow ротации admin credential пока нет).
		if _, err := tx.Exec(ctx,
			`update connections set vault_admin_path = $2, admin_credential_set_at = now(), updated_at = now() where id = $1`,
			conn.ID, path,
		); err != nil {
			respondStoreError(ctx, w, fmt.Errorf("api: set vault admin path: %w", err))
			return
		}
		conn.VaultAdminPath = path
	}

	auditMetadata := map[string]any{
		"display_name": conn.DisplayName,
		"engine":       conn.Engine,
		"environment":  conn.Environment,
		"endpoints":    conn.Endpoints,
	}
	// Фиксируем в audit эффективный режим TLS и вычисленные security-findings
	// (без секретов): небезопасный выбор подключения должен оставлять след.
	// На момент создания topology ещё пуст, поэтому tls_available_but_disabled
	// здесь не появляется — он вычисляется после discovery.
	auditMetadata["tls_mode"] = effectiveTLSMode(parseTLSConfigView(conn.TLSConfig))
	if findings := securityFindings(conn); len(findings) > 0 {
		auditMetadata["security_findings"] = findings
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionConnectionCreated,
		ConnectionID: &conn.ID,
		Result:       audit.ResultSuccess,
	}, auditMetadata); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create connection: %w", err))
		return
	}
	respondJSON(w, http.StatusCreated, toConnectionJSON(conn, nil))
}

// refreshTransitions возвращает цепочку статусов, через которую
// connection нужно провести до постановки discovery, по карте переходов
// connections (docs/architecture.md, раздел 5.1):
//   - draft, connection_failed -> validating -> discovering;
//   - validating, discovery_failed -> discovering;
//   - discovering, active, degraded — без переходов: discovery выполняется
//     из этих статусов как есть;
//   - disabled — refresh недопустим (сначала включить connection).
func refreshTransitions(from connections.Status) ([]connections.Status, error) {
	switch from {
	case connections.StatusDraft, connections.StatusConnectionFailed:
		return []connections.Status{connections.StatusValidating, connections.StatusDiscovering}, nil
	case connections.StatusValidating, connections.StatusDiscoveryFailed:
		return []connections.Status{connections.StatusDiscovering}, nil
	case connections.StatusDiscovering, connections.StatusActive, connections.StatusDegraded:
		return nil, nil
	default:
		return nil, fmt.Errorf("refresh is not allowed for connection status %q", from)
	}
}

// refreshOperationKey возвращает idempotency key операции discovery —
// общий формат jobs.DiscoverOperationKey. Тем же ключом-окном пользуется
// периодический авто-rediscovery worker (internal/core/rediscovery),
// поэтому повторный refresh того же connection в пределах минуты — от
// человека или планировщика — возвращает уже созданную операцию вместо
// новой.
func refreshOperationKey(id uuid.UUID, now time.Time) string {
	return jobs.DiscoverOperationKey(id, now)
}

// refreshResponse — тело ответа POST /api/v1/connections/{id}/refresh.
type refreshResponse struct {
	OperationID uuid.UUID `json:"operation_id"`
	// Deduplicated сообщает, что новая операция НЕ создана: запрос попал в
	// окно дедупликации и вернул уже существующую (возможно, давно
	// завершённую) операцию.
	//
	// Без этого поля клиент не отличал «сходил и обновил» от «вернул прошлый
	// снимок»: ответ 202 с id операции в обоих случаях выглядел одинаково, и
	// оператор ждал свежих данных, которых не будет.
	Deduplicated bool `json:"deduplicated,omitempty"`
	// Status — статус возвращённой операции. Полезен именно в дедуплицированном
	// случае: success означает, что снимок уже сделан, running — что он ещё в
	// работе.
	Status string `json:"status"`
}

// refreshConnection — POST /api/v1/connections/{id}/refresh (operator):
// проводит connection к статусу discovering (см. refreshTransitions) и
// ставит операцию connection.discover в очередь worker.
//
// Всё выполняется одной транзакцией: переходы статусов, создание
// операции, enqueue job и audit-событие коммитятся вместе. Операция
// идемпотентна по ключу минутного окна: если она уже существует
// (created=false), повторный enqueue и повторное audit-событие не
// выполняются, в ответ уходит существующий operation_id.
func (s *Server) refreshConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	conn, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if conn.Status == connections.StatusCredentialUpdating {
		respondError(w, http.StatusConflict, "connection admin credential change is active; refresh is blocked")
		return
	}
	// Scope: operator обновляет только connections своих окружений.
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	chain, err := refreshTransitions(conn.Status)
	if err != nil {
		respondError(w, http.StatusConflict, err.Error())
		return
	}
	from := conn.Status
	for _, to := range chain {
		if _, err := s.connections.Transition(ctx, tx, id, from, to); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		from = to
	}

	key := refreshOperationKey(id, time.Now())
	op, created, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:           jobs.KindConnectionDiscover,
		IdempotencyKey: &key,
		ConnectionID:   &id,
		ActorType:      sess.ActorType(),
		ActorID:        sess.ActorID(),
		CorrelationID:  uuid.NewString(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if created {
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			ActorType:    sess.ActorType(),
			ActorID:      sess.ActorID(),
			Action:       auditActionRefreshRequested,
			ConnectionID: &id,
			OperationID:  &op.ID,
			Result:       audit.ResultSuccess,
		}); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit refresh: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, refreshResponse{
		OperationID:  op.ID,
		Deduplicated: !created,
		Status:       string(op.Status),
	})
}

// setConnectionStatus выполняет обратимый admin-only lifecycle-переход
// active <-> disabled. Переход сериализован тем же advisory lock, что
// discovery и reconfigure, и вместе с audit-событием коммитится одной
// транзакцией. Выключение не удаляет snapshot, credentials, accounts или
// bindings: оно лишь останавливает operational-действия до повторного enable.
func (s *Server) setConnectionStatus(w http.ResponseWriter, r *http.Request,
	from, to connections.Status, action string) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	before, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if before.Status != from {
		respondError(w, http.StatusConflict,
			fmt.Sprintf("connection status %q does not allow transition to %q", before.Status, to))
		return
	}
	after, err := s.connections.Transition(ctx, tx, id, from, to)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       action,
		ConnectionID: &id,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"display_name":    after.DisplayName,
		"previous_status": before.Status,
		"status":          after.Status,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit connection status: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, toConnectionJSON(after, nil))
}

// disableConnection выключает активное подключение без удаления данных.
func (s *Server) disableConnection(w http.ResponseWriter, r *http.Request) {
	s.setConnectionStatus(w, r, connections.StatusActive, connections.StatusDisabled,
		auditActionConnectionDisabled)
}

// enableConnection возвращает выключенное подключение в active. Сохранённый
// snapshot остаётся доступен; оператор при необходимости запускает Sync.
func (s *Server) enableConnection(w http.ResponseWriter, r *http.Request) {
	s.setConnectionStatus(w, r, connections.StatusDisabled, connections.StatusActive,
		auditActionConnectionEnabled)
}

// deleteConnectionGuard решает, можно ли удалить connection по числу его
// managed-аккаунтов и флагу force. Функция чистая (тестируется без БД):
// при наличии managed-аккаунтов и force=false удаление запрещается, а
// возвращённый текст объясняет последствие — реальные пользователи,
// созданные grantor в целевой системе, останутся осиротевшими (удаление
// затрагивает только metadata grantor и целевой кластер не трогает).
// force=true снимает запрет: администратор осознанно принимает орфанинг.
// allowed=false сопровождается непустым msg для ответа 409.
func deleteConnectionGuard(managedAccounts int, force bool) (msg string, allowed bool) {
	if managedAccounts > 0 && !force {
		return fmt.Sprintf(
			"connection has %d managed account(s): deleting removes them from grantor's inventory "+
				"but does NOT revoke or delete them on the target (they will be orphaned there). "+
				"Pass ?force=true to delete the metadata anyway.",
			managedAccounts), false
	}
	return "", true
}

// deleteResponse — тело ответа DELETE /api/v1/connections/{id}.
type deleteResponse struct {
	ID                uuid.UUID `json:"id"`
	Deleted           bool      `json:"deleted"`
	CascadedResources int       `json:"cascaded_resources"`
	CascadedAccounts  int       `json:"cascaded_accounts"`
	// OrphanedManagedAccounts — сколько managed-аккаунтов (реальных
	// пользователей grantor в целевой системе) забыто из инвентаря; они
	// остаются жить в целевом кластере. > 0 только при force=true.
	OrphanedManagedAccounts int `json:"orphaned_managed_accounts"`
}

// deleteConnection — DELETE /api/v1/connections/{id}?force=<bool> (admin):
// удаляет ТОЛЬКО metadata grantor. Строка connections удаляется вместе с
// её инвентарём через FK-каскад схемы (resources / accounts / bindings /
// permission_definitions), operations.connection_id обнуляется, а
// audit_events переживают удаление. Целевой кластер (PostgreSQL /
// RabbitMQ / ...) не трогается вообще: endpoint не вызывает adapter, не
// ставит операций в worker и не выполняет revoke/drop — это чистое
// удаление метаданных. Поэтому удаление работает и для подключения, чей
// target недоступен: до него никто не идёт.
//
// Guard: если у подключения есть managed-аккаунты (ownership='managed',
// не deleted) — реальные пользователи, созданные grantor в целевой
// системе, — удаление по умолчанию отклоняется (409): забыв их из
// инвентаря, grantor оставит их осиротевшими на целевом кластере.
// ?force=true снимает запрет (администратор принимает орфанинг), но и
// тогда target не трогается — забываются только метаданные.
//
// Vault admin credential подключения намеренно НЕ удаляется: это учётка
// целевой системы (принадлежит владельцу target, не managed-секретам
// grantor), оставшийся KV-путь безвреден, а его удаление — вне scope
// этого endpoint.
//
// Идемпотентность: несуществующий id — 404; повторное удаление — тоже
// 404.
func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	force := r.URL.Query().Get("force") == "true"

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	conn, err := s.connections.Get(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if conn.Status == connections.StatusCredentialUpdating {
		respondError(w, http.StatusConflict, "connection admin credential change is active; deletion is blocked")
		return
	}
	counts, err := s.inventory.CountConnectionInventory(ctx, tx, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if msg, allowed := deleteConnectionGuard(counts.ManagedAccounts, force); !allowed {
		respondError(w, http.StatusConflict, msg)
		return
	}

	if err := s.connections.Delete(ctx, tx, id); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	orphaned := 0
	if force {
		orphaned = counts.ManagedAccounts
	}
	// Audit фиксирует, что удаление было metadata-only (target не тронут) и
	// сколько managed-аккаунтов осиротело при force. Секретов нет.
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionConnectionDeleted,
		ConnectionID: &conn.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"display_name":              conn.DisplayName,
		"engine":                    conn.Engine,
		"environment":               conn.Environment,
		"cascaded_resources":        counts.Resources,
		"cascaded_accounts":         counts.Accounts,
		"managed_accounts":          counts.ManagedAccounts,
		"orphaned_managed_accounts": orphaned,
		"force":                     force,
		"target_untouched":          true,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit delete connection: %w", err))
		return
	}
	respondJSON(w, http.StatusOK, deleteResponse{
		ID:                      conn.ID,
		Deleted:                 true,
		CascadedResources:       counts.Resources,
		CascadedAccounts:        counts.Accounts,
		OrphanedManagedAccounts: orphaned,
	})
}

func validateConnectionAuthMode(engine, mode string) error {
	if mode == "" || mode == "password" {
		return nil
	}
	if mode == "none" && engine == "redis" {
		return nil
	}
	return errors.New("auth_mode must be password, or none for Redis")
}
