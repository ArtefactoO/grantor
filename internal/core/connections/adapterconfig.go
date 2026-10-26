package connections

// Проекция строки connections в adapter.Connection. Живёт в этом пакете, а
// не в internal/jobs: формат jsonb-колонок tls_config и discovery_config
// принадлежит доменной модели подключения, и читают его теперь оба слоя —
// worker (исполнение операций) и API (форматирование engine identity через
// adapter.FormatEngineIdentity до постановки account.create).

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/mongodbconfig"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
	"github.com/ArtefactoO/grantor/internal/rabbitmqconfig"
)

// tlsConfigJSON — формат jsonb-колонки connections.tls_config. Только
// несекретные поля: client key — секрет и в metadata не хранится.
// TODO(этап 1): читать client key из Vault для mTLS-подключений.
type tlsConfigJSON struct {
	Mode               string `json:"mode"`
	CACertPEM          string `json:"ca_cert_pem"`
	ClientCertPEM      string `json:"client_cert_pem"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// discoveryConfigJSON — формат jsonb-колонки connections.discovery_config.
type discoveryConfigJSON struct {
	// Database — maintenance-база служебных подключений adapter (postgres/mysql).
	Database string `json:"database"`
	// SASLMechanism / SecurityProtocol — per-connection auth kafka adapter
	// (none|plain|scram-sha-256|scram-sha-512 и plaintext|sasl_plaintext|
	// sasl_ssl|ssl). Несекретны; сам adapter валидирует их согласованность.
	SASLMechanism    string `json:"sasl_mechanism"`
	SecurityProtocol string `json:"security_protocol"`
	// AuthSource — auth database MongoDB: база, в которой аутентифицируется
	// admin credential и в которой заводятся учётки принципалов
	// (engine identity "user@authdb"). Пусто — "admin".
	AuthSource string `json:"auth_source"`
	// DefaultAccountHost — host MySQL для создаваемых учётных записей
	// (engine identity "user@host"). Пусто — "%".
	DefaultAccountHost string `json:"default_account_host"`
	// ReplicaSet — имя replica set MongoDB для опций клиента. Пусто — без
	// явного replica set.
	ReplicaSet string `json:"replica_set"`
	// DatabaseCreate — allowlists создания баз (architecture §11.2).
	// Отсутствие секции означает самый узкий режим: шаблон и tablespace
	// задавать нельзя вовсе, владельцем допустима любая существующая
	// не-superuser роль. Список — явное расширение, а не сужение.
	DatabaseCreate              *databaseCreateConfigJSON           `json:"database_create,omitempty"`
	RabbitMQPermissionTemplates []rabbitmqconfig.PermissionTemplate `json:"rabbitmq_permission_templates,omitempty"`
	PostgresRolePolicyTemplates []postgresconfig.RolePolicyTemplate `json:"postgres_role_policy_templates,omitempty"`
	MongoDBRolePolicyTemplates  []mongodbconfig.RolePolicyTemplate  `json:"mongodb_role_policy_templates,omitempty"`
}

// databaseCreateConfigJSON — allowlists опций создания базы. Значения
// несекретны и уходят в adapter как есть.
type databaseCreateConfigJSON struct {
	Templates   []string `json:"templates"`
	Owners      []string `json:"owners"`
	Tablespaces []string `json:"tablespaces"`
}

// AdapterConfig строит adapter.Connection из строки connections без admin
// credential (его добавляет вызывающий — worker читает секрет из Vault).
//
// Разделение конфигурации: tls_config относится только к TLS и парсится в
// adapter.TLSConfig; engine-специфичные несекретные параметры подключения
// (maintenance database, auth source, host учёток) живут в discovery_config
// и передаются adapter через Attributes. Складывать их в tls_config или
// хранить attributes «как есть» в tls_config было бы смешением зон
// ответственности.
func AdapterConfig(conn Connection) (adapter.Connection, error) {
	var tlsCfg tlsConfigJSON
	if len(conn.TLSConfig) > 0 {
		if err := json.Unmarshal(conn.TLSConfig, &tlsCfg); err != nil {
			return adapter.Connection{}, fmt.Errorf("connection %s: parse tls config: %w", conn.ID, err)
		}
	}
	var discoveryCfg discoveryConfigJSON
	if len(conn.DiscoveryConfig) > 0 {
		if err := json.Unmarshal(conn.DiscoveryConfig, &discoveryCfg); err != nil {
			return adapter.Connection{}, fmt.Errorf("connection %s: parse discovery config: %w", conn.ID, err)
		}
	}
	attributes := map[string]any{}
	for key, value := range map[string]string{
		"database":             discoveryCfg.Database,
		"sasl_mechanism":       discoveryCfg.SASLMechanism,
		"security_protocol":    discoveryCfg.SecurityProtocol,
		"auth_source":          discoveryCfg.AuthSource,
		"default_account_host": discoveryCfg.DefaultAccountHost,
		"replica_set":          discoveryCfg.ReplicaSet,
	} {
		if value != "" {
			attributes[key] = value
		}
	}
	if discoveryCfg.DatabaseCreate != nil {
		// Пустые allowlists семантически эквивалентны отсутствующим и не
		// должны превращаться в JSON null в connector payload. Непустые
		// списки уходят как есть: авторитетная проверка живёт в Plan.
		if len(discoveryCfg.DatabaseCreate.Templates) > 0 {
			attributes[adapter.AttrDatabaseCreateTemplates] = discoveryCfg.DatabaseCreate.Templates
		}
		if len(discoveryCfg.DatabaseCreate.Owners) > 0 {
			attributes[adapter.AttrDatabaseCreateOwners] = discoveryCfg.DatabaseCreate.Owners
		}
		if len(discoveryCfg.DatabaseCreate.Tablespaces) > 0 {
			attributes[adapter.AttrDatabaseCreateTablespaces] = discoveryCfg.DatabaseCreate.Tablespaces
		}
	}
	if len(discoveryCfg.RabbitMQPermissionTemplates) > 0 {
		attributes[rabbitmqconfig.AttributePermissionTemplates] =
			slices.Clone(discoveryCfg.RabbitMQPermissionTemplates)
	}
	if len(discoveryCfg.PostgresRolePolicyTemplates) > 0 {
		attributes[postgresconfig.AttributeRolePolicyTemplates] =
			slices.Clone(discoveryCfg.PostgresRolePolicyTemplates)
	}
	if len(discoveryCfg.MongoDBRolePolicyTemplates) > 0 {
		attributes[mongodbconfig.AttributeRolePolicyTemplates] =
			slices.Clone(discoveryCfg.MongoDBRolePolicyTemplates)
	}
	return adapter.Connection{
		ID:                conn.ID.String(),
		ConfigIncarnation: ConfigIncarnation(conn),
		Engine:            conn.Engine,
		AuthMode:          conn.AuthMode,
		Endpoints:         conn.Endpoints,
		TLS: adapter.TLSConfig{
			Mode:               tlsCfg.Mode,
			CACertPEM:          pemBytes(tlsCfg.CACertPEM),
			ClientCertPEM:      pemBytes(tlsCfg.ClientCertPEM),
			InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		},
		Attributes: attributes,
	}, nil
}

// pemBytes переводит PEM-строку в байты; пустая строка остаётся nil.
func pemBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return []byte(s)
}

// EffectiveCapabilities возвращает эффективные capabilities подключения:
// engine-wide манифест adapter, сужённый под саму строку connection —
// её discovery_config/tls_config и topology последнего snapshot
// (adapter.CapabilitiesFor). Именно этот набор хранится в колонке
// capabilities: его читают UI и API-гварды, поэтому набор обязан отражать
// конкретное подключение, а не движок вообще (kafka: на PLAIN-подключении
// нет SCRAM-lifecycle, на кластере без ACL-авторизатора — нет grant/revoke).
//
// Набор — производное значение, а не пользовательский ввод, и пересчитывается
// на каждой записи строки: при создании, при operational PATCH
// (discovery_config/tls_config) и по результату discovery (см. Store).
//
// Деградация вместо отказа: незарегистрированный в этом процессе engine или
// нечитаемый tls_config/discovery_config — не повод менять права подключения,
// возвращается fallback (обычно engine-wide манифест или уже сохранённый
// набор). Ошибка разбора конфигурации проявится там, где она действительно
// мешает, — на ValidateConnection и discovery.
func EffectiveCapabilities(conn Connection, fallback []string) []string {
	cfg, err := AdapterConfig(conn)
	if err != nil {
		return fallback
	}
	var topology map[string]any
	if len(conn.Topology) > 0 {
		if err := json.Unmarshal(conn.Topology, &topology); err != nil {
			topology = nil
		}
	}
	caps, err := adapter.CapabilitiesFor(cfg, topology)
	if err != nil {
		return fallback
	}
	return adapter.CapabilityNames(caps)
}

// EngineIdentity приводит базовое имя учётной записи принципала к
// engine-специфичной форме подключения (mysql user@host, mongodb
// user@authdb). Тонкая обёртка над adapter.FormatEngineIdentity: избавляет
// вызывающих от ручной сборки adapter.Connection.
func EngineIdentity(conn Connection, base string) (string, error) {
	cfg, err := AdapterConfig(conn)
	if err != nil {
		return "", err
	}
	return adapter.FormatEngineIdentity(cfg, base)
}
