// Package kafka реализует engine adapter для Apache Kafka и Redpanda
// (docs/architecture.md, раздел 10). Один adapter покрывает оба движка:
// Redpanda реализует те же Kafka Admin API (SCRAM через
// Describe/AlterUserScramCredentials, ACL через Describe/Create/DeleteAcls),
// поэтому совместимость с Apache Kafka обеспечивается на уровне протокола.
// Требования к версии целевой системы: user SCRAM API (KIP-554) есть в
// Apache Kafka 2.7+ и Redpanda 25.2+ (более старая Redpanda отвечает на эти
// запросы UNSUPPORTED_VERSION); live-тесты CI гоняются на одноузловой
// Redpanda, совместимость с Apache Kafka — по протоколу.
//
// Транспорт — Kafka wire protocol через franz-go (kgo) с admin-обвязкой kadm.
//
// # Аутентификация (per-connection)
//
// Механизм SASL и security protocol задаются на каждое подключение отдельно
// (разные кластеры аутентифицируются по-разному) через несекретные атрибуты
// connection.discovery_config, попадающие в adapter.Connection.Attributes (тем
// же путём, что postgres читает Attributes["database"]):
//
//   - sasl_mechanism: none | plain | scram-sha-256 | scram-sha-512.
//     Не задан -> scram-sha-256 (обратная совместимость: до появления
//     per-connection auth adapter всегда ходил SASL/SCRAM-SHA-256, поэтому
//     существующие подключения работают без изменений). GSSAPI/OAUTHBEARER вне
//     области поддержки и отклоняются с явной ошибкой.
//   - security_protocol: plaintext | sasl_plaintext | sasl_ssl | ssl (mTLS).
//     Не задан -> выводится из механизма и TLS-режима (SASL + TLS -> sasl_ssl,
//     SASL без TLS -> sasl_plaintext, без SASL + TLS -> ssl, иначе plaintext).
//     Несогласованные комбинации отклоняются (sasl_ssl/ssl требуют TLS !=
//     disabled; sasl_plaintext/plaintext требуют TLS disabled; sasl_* требуют
//     механизм, plaintext/ssl требуют его отсутствия).
//
// TLS-режимы повторяют остальные adapters (disabled/require/verify-ca/
// verify-full) и используются для ssl/sasl_ssl. Admin username/password берутся
// из admin credential (secret.Value) и обязательны только при активном SASL;
// mTLS/none аутентифицируются клиентским сертификатом без логина. Пароль
// раскрывается лишь при построении SASL-механизма и в тексты ошибок/логи не
// попадает.
//
// # Матрица механизмов и capabilities
//
// SCRAM API (Describe/AlterUserScramCredentials) — единственный способ, которым
// adapter создаёт и ротирует пользователей, — доступен только на
// SCRAM-подключениях. Поэтому на не-SCRAM кластерах lifecycle учёток
// недоступен, а grantor работает в режиме инвентаризации и управления ACL:
//
//	механизм         validate: SCRAM API   inventory  access.grant/revoke  disable/enable  account.create/delete  credential.rotate
//	scram-sha-256/512  требуется            да         да                   да              да                     да
//	plain / none(mTLS) не требуется         да         да                   да              нет                    нет
//
// На не-SCRAM подключении account.create/account.delete и credential.rotate
// не входят в эффективный набор capabilities подключения (CapabilitiesFor:
// ядро пересчитывает набор при discovery и при изменении discovery_config,
// поэтому UI такое действие не предлагает) и дополнительно отклоняются на
// этапе Plan/Rotate как adapter.ErrUnsupportedChange — заявление и исполнение
// не расходятся. disable/enable остаются: это чистые ACL DENY-маркеры, не
// зависящие от SCRAM. account.delete считается SCRAM-lifecycle: на не-SCRAM
// кластере идентичность живёт вне Kafka, а её ACL снимаются revoke bundles.
//
// # Вариант: ACL-авторизатор выключен (auth-on / authz-off)
//
// Кластер может аутентифицировать (SASL/mTLS), но не иметь настроенного ACL-
// авторизатора. Тогда DescribeAcls отвечает SECURITY_DISABLED (kerr code 54,
// «Security features are disabled»). Это легитимный вариант конфигурации, а не
// ошибка: adapter его терпит и переходит в режим только-инвентаризации.
// Состояние authorizer определяется рантайм-ответом брокера (в отличие от
// механизма, который задаётся статически в connection), поэтому отклонение
// ACL-операций выполняется в начале соответствующего шага Apply, до любой
// мутации, при первом же DescribeAcls (см. aclAdminUnavailable):
//
//	состояние authorizer  inventory  access.grant/revoke  disable/enable  SCRAM lifecycle (если SCRAM)
//	включён                да         да                   да              да
//	выключен (SECURITY_..)  да         нет                  нет             да
//
// При выключенном authorizer ACL-операции (access.grant/access.revoke и
// account.disable/account.enable, которые тоже создают DENY-маркерные ACL)
// отклоняются как adapter.ErrUnsupportedChange с явным сообщением. Отметку
// authorizer discovery сохраняет в Snapshot.Topology, поэтому после первого же
// discovery эти capabilities уходят и из эффективного набора подключения
// (CapabilitiesFor) — UI перестаёт предлагать заведомо падающее действие.
// Discovery и credential lifecycle (SCRAM create/rotate/delete на
// SCRAM-подключении) не зависят от authorizer и остаются доступны. Комбинация
// non-SCRAM + authz-off (частый живой случай: PLAIN без ACL) корректна:
// инвентарь даёт только topics (ACL-principals нет), а все мутации отклоняются
// до Apply — ACL-операции по причине «authorizer disabled», SCRAM-lifecycle по
// причине «requires a SCRAM mechanism».
//
// # Доменная модель
//
//   - account — SCRAM principal (User:<name>). EngineIdentity — имя без
//     префикса "User:". Discovery перечисляет пользователей через
//     DescribeUserScramCredentials; principals, у которых есть ACL, но нет
//     SCRAM credential (например, mTLS-идентичности), тоже попадают в
//     инвентарь с атрибутом has_scram_credential=false. Superusers задаются
//     статической конфигурацией брокера, через API не управляются и adapter
//     ими не управляет (admin-учётка сама может быть superuser — это
//     нормально). ACL с wildcard principal (User:*) и не-User principals к
//     аккаунтам не привязываются.
//   - resource — topic. ExternalID — "topic:<name>". Служебные topics
//     (__consumer_offsets, _schemas, __redpanda* и прочие internal)
//     пропускаются. Consumer groups ресурсами сознательно не считаются: их
//     список эфемерен и раздувал бы инвентарь.
//   - permission — назначаемый bundle ACL-записей (стиль rabbitmq):
//     topic-produce:<topic> (WRITE+DESCRIBE на topic),
//     topic-consume:<topic> (READ+DESCRIBE на topic + READ на group "*"),
//     cluster-admin (ALL на cluster; опасная). Наблюдаемые ACL, не
//     совпавшие ни с одним bundle, публикуются как неназначаемые observed
//     permissions "acl:<type>:<pattern>:<name>:<op>:<allow|deny>" с
//     bindings — так сырые гранты видны, но не управляются.
//   - binding — наличие у principal полного набора ACL-записей bundle
//     (DescribeAcls — наблюдение, CreateAcls/DeleteAcls — мутации).
//
// # Опасные привилегии
//
// Опасны cluster-ACL с операциями ALL/ALTER/CLUSTER_ACTION/IDEMPOTENT_WRITE
// (ALTER на cluster — это администрирование ACL и SCRAM) и ALL на wildcard
// topic "*". См. dangerousEntry. Permission cluster-admin помечена опасной.
//
// # Модель disable/enable
//
// Нативной блокировки у Kafka нет, а удалять SCRAM credential нельзя:
// contract ядра не передаёт credential на account.enable, восстановить
// пароль было бы нечем. Disable моделируется DENY-маркером: тройка ACL
// DENY ALL на topic "*", group "*" и cluster для principal (deny в Kafka
// всегда сильнее allow). Логин по SASL остаётся возможным, но каждая
// операция отклоняется авторизацией; существующие ALLOW ACL не трогаются,
// поэтому enable (удаление тройки DENY) полностью обратим без потерь и без
// участия reconciliation. Обе операции идемпотентны; discovery считает
// аккаунт disabled при полном наборе маркера (см. markerEntries).
// Trade-off: аутентификация не блокируется (только авторизация), а маркер
// виден в ACL-инвентаре любому стороннему инструменту.
//
// # Топология
//
// Число брокеров из Metadata: один — standalone, больше — cluster
// (+ controller id и список брокеров в Snapshot.Topology, см.
// topologyFromMetadata). ServerVersion — best-effort догадка по
// ApiVersions (kversion.VersionGuess); Redpanda сообщает версию
// эквивалентного Kafka-протокола.
package kafka

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/secret"
)

// Engine — имя движка Kafka adapter (Apache Kafka и Redpanda).
const Engine = "kafka"

const (
	// defaultPort — Kafka-порт по умолчанию для endpoint без порта.
	defaultPort = 9092
	// requestTimeout ограничивает один admin-запрос к кластеру.
	requestTimeout = 20 * time.Second
	// clusterResourceName — имя единственного cluster-ресурса Kafka.
	clusterResourceName = "kafka-cluster"
	// wildcardName — wildcard-имя ресурса в ACL.
	wildcardName = "*"
	// scramIterations — число итераций PBKDF2 для SCRAM-SHA-256 (минимум
	// протокола — 4096).
	scramIterations = 4096
	// topologyACLAuthorizerKey и aclAuthorizerDisabledValue — отметка в
	// Snapshot.Topology о том, что ACL-авторизатор на кластере не включён
	// (брокер ответил SECURITY_DISABLED). Её пишет Discover и читает
	// CapabilitiesFor, сужая ACL-операции подключения.
	topologyACLAuthorizerKey   = "acl_authorizer"
	aclAuthorizerDisabledValue = "disabled"
)

// Adapter реализует adapter.Adapter для Kafka/Redpanda. Постоянных
// подключений не держит: каждый вызов открывает короткоживущий клиент.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var (
	_ adapter.Adapter                    = (*Adapter)(nil)
	_ adapter.CredentialProver           = (*Adapter)(nil)
	_ adapter.ConnectionCapabilityScoper = (*Adapter)(nil)
)

// New возвращает Kafka adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь
// topics/accounts/permissions/bindings, grant/revoke permission bundles,
// lifecycle аккаунтов (create/disable/enable/delete) и ротацию SCRAM-паролей.
// Манифест — общий (engine-wide) максимум: фактическая доступность на
// подключении зависит от механизма и состояния ACL-авторизатора (Capabilities
// включаются per-connection, раздел 10.3 архитектуры). Сужение под конкретное
// подключение выполняет CapabilitiesFor (см. доменный doc-комментарий пакета,
// «Матрица механизмов» и «ACL-авторизатор выключен»).
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"topic",
		},
		Capabilities: []adapter.Capability{
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.CapAccountCreate,
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
		},
		ConnectionSchema: "kafka-connection-v1",
	}
}

// CapabilitiesFor сужает engine-wide манифест под конкретное подключение
// (adapter.ConnectionCapabilityScoper). Обе матрицы doc-комментария пакета
// становятся исполняемыми, а не только рантайм-отказом в Apply:
//
//   - механизм подключения (статически известен из discovery_config):
//     SCRAM-lifecycle (account.create/account.delete/credential.rotate, а
//     вместе с ними credential.prove) живёт только на SCRAM-подключении,
//     потому что единственный способ управлять учётными данными и доказать
//     владение ими — SCRAM API (см. requireScramLifecycle и ProveCredential);
//   - состояние ACL-авторизатора (рантайм-факт, который discovery записал в
//     Snapshot.Topology): при SECURITY_DISABLED недоступны ACL-операции —
//     access.grant/revoke и account.disable/enable, которые тоже создают
//     DENY-маркерные ACL (см. aclAdminUnavailable).
//
// Inventory остаётся всегда: и не-SCRAM подключение, и кластер без authorizer
// пригодны для инвентаризации.
//
// Нераспознанная auth-конфигурация (parseAuthConfig вернул ошибку) трактуется
// как не-SCRAM: заявлять lifecycle, не доказав SCRAM, нельзя, а само
// подключение с несогласованной конфигурацией не пройдёт ValidateConnection.
// topology == nil (discovery ещё не было) означает «authorizer считаем
// включённым»: до наблюдения нет оснований отнимать ACL-операции, а после
// discovery набор пересчитается.
func (a *Adapter) CapabilitiesFor(cfg adapter.Connection, topology map[string]any) []adapter.Capability {
	auth, err := parseAuthConfig(cfg)
	scram := err == nil && auth.managesScram()
	aclAdmin := !aclAuthorizerDisabled(topology)

	manifest := a.Manifest().Capabilities
	out := make([]adapter.Capability, 0, len(manifest))
	for _, c := range manifest {
		switch c {
		case adapter.CapAccountCreate, adapter.CapAccountDelete,
			adapter.CapCredentialRotate, adapter.CapCredentialProve:
			if !scram {
				continue
			}
		case adapter.CapAccessGrant, adapter.CapAccessRevoke,
			adapter.CapAccountDisable, adapter.CapAccountEnable:
			if !aclAdmin {
				continue
			}
		}
		out = append(out, c)
	}
	return adapter.ScopeAdminCredentialCapabilities(out, topology)
}

// aclAuthorizerDisabled читает в topology последнего snapshot отметку
// выключенного ACL-авторизатора, которую туда положил Discover этого же
// adapter. Значение проходит через jsonb, поэтому сравнивается как строка.
func aclAuthorizerDisabled(topology map[string]any) bool {
	v, ok := topology[topologyACLAuthorizerKey].(string)
	return ok && v == aclAuthorizerDisabledValue
}

// ValidateConnection проверяет доступ к целевой системе по механизму
// подключения. Всегда: Metadata (связность и аутентификация) и DescribeAcls
// (право администрировать ACL). Дополнительно, ТОЛЬКО для SCRAM-подключений:
// DescribeUserScramCredentials — право управлять учётными данными. На
// PLAIN/mTLS/none-кластере SCRAM API не проверяется и не требуется: lifecycle
// учёток (create/delete/rotate) там недоступен by design (см. managesScram и
// доменный doc-комментарий пакета).
//
// Толерантность к выключенному ACL-авторизатору: если DescribeAcls отвечает
// SECURITY_DISABLED (аутентификация есть, но authorizer на брокере не включён —
// легитимный вариант конфигурации), подключение считается валидным для
// инвентаризации. Связность и аутентификация уже доказаны Metadata; ACL-
// администрирование на таком кластере просто недоступно (grant/revoke/disable/
// enable отклоняются до Apply). Отказ авторизации (CLUSTER_AUTHORIZATION_FAILED)
// — это, наоборот, нехватка прав у admin, а не выключенный authorizer: он
// превращается в единый adapter.InsufficientPrivilegeError. Пароль в тексты
// ошибок не попадает.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("kafka: validate connection: %w", err)
	}
	defer client.close()

	if err := func() error {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()
		_, err := client.adm.BrokerMetadata(reqCtx)
		return err
	}(); err != nil {
		return fmt.Errorf("kafka: validate connection: %w", err)
	}

	if _, _, err := client.describeACLsTolerant(ctx); err != nil {
		return fmt.Errorf("kafka: validate connection: %w", privilegeOrRawError(err, cfg))
	}
	if client.auth.managesScram() {
		if err := func() error {
			reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
			defer cancel()
			_, err := client.adm.DescribeUserSCRAMs(reqCtx)
			return err
		}(); err != nil {
			return fmt.Errorf("kafka: validate connection: %w", privilegeOrRawError(err, cfg))
		}
	}
	return nil
}

// privilegeOrRawError превращает CLUSTER_AUTHORIZATION_FAILED в единый
// adapter.InsufficientPrivilegeError; остальные ошибки возвращает как есть.
func privilegeOrRawError(err error, cfg adapter.Connection) error {
	if !errors.Is(err, kerr.ClusterAuthorizationFailed) {
		return err
	}
	return &adapter.InsufficientPrivilegeError{
		Engine:  Engine,
		Admin:   cfg.AdminCredential.Username,
		Missing: "ALTER/DESCRIBE on cluster (ACL and SCRAM administration)",
		Detail: "grant ALLOW ALL on the cluster resource to the admin principal " +
			"or list it in the broker superusers",
	}
}

// adminClient — короткоживущий admin-клиент Kafka. Секрет admin credential
// хранится в secret.Value и раскрывается только при построении
// SASL-механизма, поэтому fmt/json самого клиента выводят "[REDACTED]".
type adminClient struct {
	kcl      *kgo.Client
	adm      *kadm.Client
	username string
	secret   secret.Value
	auth     authConfig
	// describeACLsFn выполняет DescribeAcls целевого кластера. Вынесено в поле
	// (а не прямой вызов adm.DescribeACLs), чтобы юнит-тесты подменяли ответ
	// брокера — в частности SECURITY_DISABLED (выключенный ACL-авторизатор) —
	// без живого кластера. В проде всегда указывает на adm.DescribeACLs.
	describeACLsFn func(context.Context, *kadm.ACLBuilder) (kadm.DescribeACLsResults, error)
}

// newClient строит adminClient из cfg: seed brokers из endpoints (порт по
// умолчанию 9092), SASL-механизм и security protocol из per-connection
// auth-конфигурации (см. parseAuthConfig), TLS по режиму. Секрет и логин в
// тексты ошибок не попадают. Подключение ленивое: kgo не ходит в сеть до
// первого запроса.
func newClient(cfg adapter.Connection) (*adminClient, error) {
	return newClientWithDialer(cfg, adapterutil.DefaultDialContext)
}

func (a *Adapter) newClient(cfg adapter.Connection) (*adminClient, error) {
	return newClientWithDialer(cfg, a.dialContext)
}

func newClientWithDialer(cfg adapter.Connection, dial adapterutil.DialContextFunc) (*adminClient, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("no endpoints configured")
	}
	auth, err := parseAuthConfig(cfg)
	if err != nil {
		return nil, err
	}
	// Логин и пароль обязательны только при активном SASL: mTLS/none
	// аутентифицируются без credential.
	if auth.usesSASL() {
		if cfg.AdminCredential.Username == "" {
			return nil, errors.New("admin credential username is empty")
		}
		if len(cfg.AdminCredential.Secret) == 0 {
			return nil, errors.New("admin credential secret is empty")
		}
	}

	seeds := make([]string, 0, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		host, port, err := adapterutil.SplitEndpoint(endpoint, defaultPort)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, net.JoinHostPort(host, strconv.Itoa(int(port))))
	}

	sec := secret.New(cfg.AdminCredential.Secret)
	if auth.usesTLS() {
		// TLS оборачивает guarded TCP dial, сохраняя исходный broker hostname
		// для SNI/verify-full и не возвращая DNS resolution обратно kgo.
		tlsCfg, err := adapterutil.BuildTLSConfig(cfg.TLS, "")
		if err != nil {
			return nil, err
		}
		dial = adapterutil.TLSDialContext(dial, tlsCfg)
	}
	opts := []kgo.Opt{
		kgo.SeedBrokers(seeds...),
		kgo.DialTimeout(adapterutil.DefaultDialTimeout),
		kgo.Dialer(dial),
	}
	if saslOpt, ok := auth.saslOpt(cfg.AdminCredential.Username, sec); ok {
		opts = append(opts, saslOpt)
	}
	kcl, err := kgo.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("create kafka client: %w", err)
	}
	adm := kadm.NewClient(kcl)
	return &adminClient{
		kcl:            kcl,
		adm:            adm,
		username:       cfg.AdminCredential.Username,
		secret:         sec,
		auth:           auth,
		describeACLsFn: adm.DescribeACLs,
	}, nil
}

// close закрывает подключения клиента. kcl может быть nil в юнит-тестах,
// собирающих adminClient напрямую (без newClient).
func (c *adminClient) close() {
	if c.kcl != nil {
		c.kcl.Close()
	}
}
