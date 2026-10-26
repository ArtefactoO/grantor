// Package redis реализует engine adapter для Redis 6.2+ (docs/architecture.md,
// раздел 10; движок из плана — Redis). Транспорт — RESP через go-redis/v9;
// аутентификация — admin credential (username может быть пустым: тогда AUTH
// идёт от имени пользователя default, как при requirepass). TLS-режимы
// повторяют остальные adapters (disabled/require/verify-ca/verify-full).
//
// # Доменная модель
//
//   - account — ACL-пользователь (ACL LIST / ACL SETUSER). EngineIdentity —
//     имя пользователя (уникально в пределах узла). Пользователь default в
//     managed-инвентарь сознательно не попадает: это bootstrap-поверхность
//     администратора (при requirepass именно default — admin-учётка самого
//     grantor), его блокировка или удаление сломали бы управление узлом.
//     Adapter отказывается выполнять любые мутации над default.
//
//   - resource — ресурсов нет. У Redis нет объекта уровня «база»/«vhost»,
//     которым можно управлять через ACL: логические БД (SELECT 0..15)
//     недоступны в cluster mode и не имеют own-ACL, а придумывать фиктивный
//     ресурс «инстанс» ради галочки — значит врать инвентарю. ResourceKinds
//     пуст, permissions и bindings — cluster-wide (scope пуст).
//
//   - permission — назначаемый bundle ACL-правил (стиль rabbitmq/kafka):
//     read  -> ~* &* +@read -@dangerous;
//     write -> ~* &* +@write -@dangerous;
//     monitoring -> INFO, PING, HELLO and CLIENT SETNAME/SETINFO only;
//     admin -> ~* &* +@all (опасная).
//     Bundles read и write композируются независимо (read-write-доступ =
//     оба bundle сразу); -@dangerous исключает опасные команды внутри
//     категорий (@read содержит KEYS, @write — FLUSHALL и MIGRATE).
//     Monitoring alone has no key or Pub/Sub channel patterns. Combining it
//     with read/write requires those separate explicit permission bindings.
//
//     Важно: read и write НЕ дизъюнктны по наблюдаемости данных. Категория
//     @write содержит команды, возвращающие текущее значение (GETSET,
//     GETDEL, LPOP, RPOP, SPOP, RENAME, `SET ... GET`), поэтому выдача
//     одного write не ограничивает чтение keyspace. Разделить это в модели
//     категорий Redis нельзя: команда классифицируется по эффекту, а не по
//     тому, что она возвращает. Оговорка показывается в карточке права
//     (см. bundleCaveats), чтобы оператор видел её до выдачи. Опасной
//     bundle write при этом не считается: иначе базовый сценарий движка стал
//     бы недоступен роли operator.
//
//   - binding — соответствие полного набора правил пользователя одной из
//     managed-форм (подмножество bundles). Redis 7 selectors remain observed
//     only and never become managed forms. Правила, не совпавшие ни с одной
//     формой, публикуются как неназначаемая observed permission
//     "acl:<rules>" с binding — сырые гранты видны, но не управляются, и
//     grant/revoke на таком пользователе отклоняется, чтобы не затирать
//     чужие правила.
//
// # Почему admin не комбинируется с read/write
//
// Bundle admin — это +@all, а +@all канонизирует описание правил пользователя
// до единственного токена: read и write, выданные вместе с admin, исчезают из
// движка физически, и восстановить исходный набор из такого ACL невозможно.
// Поэтому сочетание admin с read/write отклоняется явной ошибкой
// (ErrBundleCombination) на этапе плана и повторно при применении — вместо
// молчаливой потери прав. Семантически запрет ничего не отнимает: +@all —
// строгое надмножество read и write; чтобы получить admin, лишние bundles
// нужно сначала отозвать.
//
// # Почему grant/revoke опираются на desired state
//
// ACL Redis — не набор независимых грантов, а один набор правил: снять одно
// право можно только переписав набор целиком (ACL SETUSER применяет список
// атомарно). Целевой набор bundles берётся из
// adapter.DesiredChange.AccountPermissions — desired-состояния bindings
// grantor, — а не реконструируется из текущего ACL: реконструкция переносит в
// результат любое расхождение состояния движка, и revoke одного bundle
// сносит остальные права аккаунта. Побочный эффект желаемый: любая операция
// доступа приводит правила аккаунта к desired-состоянию целиком, поэтому
// расхождение чинится штатным grant/revoke, а не пересозданием binding. Если
// ядро desired-состояние не передало (AccountPermissions == nil), adapter
// деградирует до реконструкции из движка; непредставимый набор при этом
// по-прежнему отклоняется.
//
// Verify для grant/revoke проверяет не только наличие/отсутствие изменяемого
// bundle, но и то, что правила остались managed-формой, а наблюдаемый набор
// bundles совпал с desired: иначе снос остальных прав аккаунта прошёл бы как
// успешная операция.
//
// Discovery читает ACL LIST — каноническую сериализацию содержимого
// ACL GETUSER (тот же формат, что aclfile): один запрос на всех
// пользователей, один парсер (commands/keys/channels/selectors) и никакой
// зависимости от формы ответа RESP2/RESP3, которой страдает ACL GETUSER.
//
// # Опасные привилегии
//
// Опасны правила, эффективно разрешающие команды классов ACL/CONFIG/
// FLUSHALL/SHUTDOWN (см. dangerousProbeCommands): классификатор прогоняет
// последовательный порядко-зависимый евалюатор правил, поэтому «+@write
// -@dangerous» безопасно, а «+@write» без вычета — нет (FLUSHALL входит в
// @write). Категории @all/@admin/@dangerous/@slow разрешают команду acl
// (проверено на живом Redis: +@slow действительно даёт ACL). Bundle admin
// помечен опасным статически.
//
// # Модель disable/enable
//
// У Redis есть нативный флаг: ACL SETUSER <name> off / on. Off блокирует
// аутентификацию (AUTH отвечает WRONGPASS), при этом правила и пароли
// полностью сохраняются, поэтому пара тривиально обратима и идемпотентна
// без участия reconciliation. Discovery отражает off в
// ObservedAccount.Disabled.
//
// # Ротация credential
//
// Rotate выполняется одной атомарной командой ACL SETUSER <name> resetpass
// ><new>: SETUSER применяет все правила в одном вызове на копии пользователя
// и подменяет её целиком, поэтому аккаунт не остаётся ни без пароля, ни с
// двумя действующими паролями. Вариант «>new, затем <old» не подходит: ядро
// не передаёт старый пароль в RotateCredential (см. internal/jobs), а окно с
// двумя паролями противоречит семантике ротации.
//
// # Топология
//
// INFO server/replication даёт redis_mode (standalone|cluster|sentinel) и
// роль; для cluster добавляются поля CLUSTER INFO (best-effort). Живые тесты
// CI гоняются на standalone; выбор режима по canned INFO покрыт юнитом.
// Ограничение (документированное): ACL-команды в cluster mode действуют
// только на узле, принявшем команду, — Redis не реплицирует ACL по кластеру.
// Управление кластером требует отдельного connection на каждый узел (adapter
// подключается к первому endpoint) либо централизованного aclfile.
//
// # Персистентность ACL
//
// Runtime-изменения ACL живут в памяти и теряются при рестарте сервера, если
// не настроен aclfile (или CONFIG REWRITE для redis.conf). После успешной
// мутации adapter best-effort выполняет ACL SAVE, если CONFIG GET aclfile
// возвращает непустой путь; без aclfile (dev/ephemeral) шаг молча
// пропускается. Ответственность за настройку персистентности — на владельце
// целевой системы.
package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/secret"
)

// Engine — имя движка Redis adapter.
const Engine = "redis"

const (
	// defaultPort — Redis-порт по умолчанию для endpoint без порта.
	defaultPort = 6379
	// requestTimeout ограничивает одну команду к серверу.
	requestTimeout = 15 * time.Second
	// defaultUserName — встроенный bootstrap-пользователь Redis. Он не
	// managed: adapter не показывает его в инвентаре аккаунтов и отказывается
	// его менять.
	defaultUserName = "default"
)

// Adapter реализует adapter.Adapter для Redis. Постоянных подключений не
// держит: каждый вызов открывает короткоживущий клиент.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)

// New возвращает Redis adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь
// accounts/permissions/bindings (ресурсов у Redis нет — см. doc-комментарий
// пакета), grant/revoke permission bundles, lifecycle аккаунтов
// (create/disable/enable/delete) и ротацию паролей.
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		Capabilities: []adapter.Capability{
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.CapAccountCreate,
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			adapter.CapCredentialProve,
			adapter.CapCredentialRotate,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
		},
		ConnectionSchema: "redis-connection-v1",
	}
}

// ValidateConnection проверяет связность (PING) и «матрицу минимальных
// привилегий» admin credential: пользователь обязан уметь администрировать
// ACL (полная команда acl через +@admin/+@all/+@slow/+@dangerous или +acl,
// либо весь необходимый набор subcommands — whoami/list/getuser/setuser/
// deluser). Правила читаются через ACL WHOAMI + ACL LIST и оцениваются
// евалюатором aclAdminAllowed; NOPERM на любом шаге также означает нехватку
// привилегий. Провал превращается в adapter.InsufficientPrivilegeError;
// пароль в тексты ошибок не попадает.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("redis: validate connection: %w", err)
	}
	defer client.close()

	if err := client.ping(ctx); err != nil {
		return fmt.Errorf("redis: validate connection: %w", privilegeOrRawError(err, cfg, ""))
	}
	me, err := client.whoAmI(ctx)
	if err != nil {
		return fmt.Errorf("redis: validate connection: %w", privilegeOrRawError(err, cfg, ""))
	}
	users, err := client.aclListUsers(ctx)
	if err != nil {
		return fmt.Errorf("redis: validate connection: %w", privilegeOrRawError(err, cfg, me))
	}
	self, ok := findUser(users, me)
	if !ok {
		return fmt.Errorf("redis: validate connection: authenticated user %q not present in ACL LIST", me)
	}
	if !aclAdminAllowed(self) {
		return fmt.Errorf("redis: validate connection: %w", insufficientPrivilege(cfg, me))
	}
	_, err = a.proveConnectionAdminCredential(ctx, cfg, cfg.AdminCredential)
	return err
}

// privilegeOrRawError превращает NOPERM-ответ сервера в единый
// adapter.InsufficientPrivilegeError; остальные ошибки возвращает как есть.
func privilegeOrRawError(err error, cfg adapter.Connection, whoami string) error {
	if !goredis.HasErrorPrefix(err, "NOPERM") {
		return err
	}
	return insufficientPrivilege(cfg, whoami)
}

// insufficientPrivilege строит InsufficientPrivilegeError с безопасным именем
// admin-учётки (username подключения либо результат ACL WHOAMI).
func insufficientPrivilege(cfg adapter.Connection, whoami string) error {
	admin := cfg.AdminCredential.Username
	if admin == "" {
		admin = whoami
	}
	return &adapter.InsufficientPrivilegeError{
		Engine:  Engine,
		Admin:   admin,
		Missing: "+@admin (or +acl) required for ACL administration",
		Detail: "grant the admin user full access to the ACL command, for example " +
			"ACL SETUSER <admin> +@admin, or authenticate as a user with +@all",
	}
}

// adminClient — короткоживущий admin-клиент Redis. Секрет admin credential
// хранится в secret.Value, поэтому fmt/json обёртки выводят "[REDACTED]".
type adminClient struct {
	rdb                  *goredis.Client
	username             string
	secret               secret.Value
	legacyCatalog        map[string][]string
	legacyCatalogChecked bool
}

// newClient строит adminClient из cfg: адрес — первый endpoint (порт по
// умолчанию 6379; ACL в cluster mode per-node, поэтому каждый узел — свой
// connection), учётные данные — admin credential (пустой username = default),
// TLS по режиму. Секрет в тексты ошибок не попадает.
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
	if err := validateAuthenticationConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.AuthMode != "none" && len(cfg.AdminCredential.Secret) == 0 {
		return nil, errors.New("admin credential secret is empty")
	}
	host, port, err := adapterutil.SplitEndpoint(cfg.Endpoints[0], defaultPort)
	if err != nil {
		return nil, err
	}

	sec := secret.New(cfg.AdminCredential.Secret)
	username := cfg.AdminCredential.Username
	if cfg.AuthMode == "none" {
		username = ""
	}
	opts := &goredis.Options{
		Addr:         net.JoinHostPort(host, strconv.Itoa(int(port))),
		Dialer:       dial,
		Username:     username,
		Password:     sec.RevealString(),
		DialTimeout:  adapterutil.DefaultDialTimeout,
		ReadTimeout:  requestTimeout,
		WriteTimeout: requestTimeout,
	}
	if cfg.TLS.Mode != "" && cfg.TLS.Mode != "disabled" {
		tlsCfg, err := adapterutil.BuildTLSConfig(cfg.TLS, host)
		if err != nil {
			return nil, err
		}
		opts.TLSConfig = tlsCfg
	}
	return &adminClient{
		rdb:      goredis.NewClient(opts),
		username: cfg.AdminCredential.Username,
		secret:   sec,
	}, nil
}

// close закрывает подключения клиента.
func (c *adminClient) close() { _ = c.rdb.Close() }

// ping проверяет связность и аутентификацию.
func (c *adminClient) ping(ctx context.Context) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.rdb.Ping(reqCtx).Err()
}

// whoAmI возвращает имя аутентифицированного ACL-пользователя.
func (c *adminClient) whoAmI(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.rdb.ACLWhoAmI(reqCtx).Result()
}
