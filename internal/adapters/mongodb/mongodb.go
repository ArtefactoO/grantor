// Package mongodb реализует engine adapter для MongoDB
// (docs/architecture.md, раздел 12).
//
// Adapter выполняет инвентаризацию (databases, collections, views, indexes,
// users, built-in и custom roles, role assignments) и мутации управления
// доступом: grant/revoke ролей, lifecycle SCRAM-аккаунтов (create/delete) и
// ротацию паролей. Мутации идемпотентны на уровне Apply; секреты не попадают
// в plan descriptions, результаты, verification details и тексты ошибок.
//
// # Особенности MongoDB
//
//   - account идентифицируется парой (username, auth_database). Одинаковый
//     username в разных auth database — это РАЗНЫЕ аккаунты. EngineIdentity
//     кодирует пару как "username@authdb".
//   - role assignment — пары {role, db}; один account может иметь права на
//     несколько databases (multi-db).
//   - роли scoped к database: built-in (read, readWrite, dbAdmin, root, ...)
//     и custom. External id роли — "role:<db>.<name>".
//   - topology (standalone / replica_set / sharded) определяется по admin
//     команде hello и пишется в Snapshot.Topology.
//
// # Почему нет disable/enable
//
// MongoDB не имеет нативного механизма отключения пользователя (нет аналога
// NOLOGIN). Поэтому adapter сознательно НЕ объявляет capabilities
// account.disable / account.enable: contract suite их не требует, а ядро не
// предложит операцию, которую движок не может выполнить безопасно и
// обратимо. Временное лишение доступа выражается через revoke ролей.
package mongodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/mongo/driver"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Engine — имя движка MongoDB adapter.
const Engine = "mongodb"

const (
	// defaultPort — порт MongoDB по умолчанию для endpoint без порта.
	defaultPort = 27017
	// defaultAuthSource — база аутентификации admin credential по умолчанию.
	defaultAuthSource = "admin"
	// adminDatabase — служебная база для admin-команд (hello, listDatabases,
	// usersInfo forAllDBs).
	adminDatabase = "admin"
)

// Adapter реализует adapter.Adapter для MongoDB. Постоянных подключений не
// держит: каждый вызов открывает короткоживущий клиент к целевой системе.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)

// New возвращает MongoDB adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь,
// grant/revoke ролей, managed custom-role policies, lifecycle SCRAM-аккаунтов
// (create/delete) и ротацию паролей. account.disable / account.enable не
// объявляются (см. doc-комментарий пакета); создание пустой database — тоже
// (planned namespace, раздел 12.2).
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"database",
			"collection",
			"view",
			"index",
		},
		Capabilities: []adapter.Capability{
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.CapRolePolicyApply,
			adapter.CapAccountCreate,
			adapter.CapAccountDelete,
			adapter.CapCredentialProve,
			adapter.CapCredentialRotate,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
		},
		ConnectionSchema: "mongodb-connection-v1",
	}
}

// ProveCredential доказывает SCRAM-аутентификацию точной парой
// username@authDB и supplied password. connectionStatus подтверждает identity,
// а обязательная отрицательная проба исключает auth-disabled/неоднозначную
// конфигурацию, принимающую произвольный пароль.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	user, authDB, err := parseEngineIdentity(account.EngineIdentity)
	if err != nil || len(credential.Secret) == 0 {
		return errors.New("mongodb: prove credential: valid account identity and password are required")
	}
	// Core historically fills Credential.Username with EngineIdentity
	// (user@authDB); adapter-native callers may pass the raw Mongo username.
	if credential.Username != "" && credential.Username != user && credential.Username != account.EngineIdentity {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: %w", user, authDB, adapter.ErrExternalIdentityConflict)
	}
	probe := credentialConnection(cfg, user, authDB, credential.Secret)
	if err := a.proveAuthenticatedIdentity(ctx, probe, user, authDB); err != nil {
		return err
	}
	wrong, err := mongodbProbePassword()
	if err != nil {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: generate negative probe: %w", user, authDB, err)
	}
	defer clear(wrong)
	negative := credentialConnection(cfg, user, authDB, wrong)
	err = a.proveAuthenticatedIdentity(ctx, negative, user, authDB)
	if err == nil {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: target accepts an unrelated password: %w", user, authDB, adapter.ErrCredentialProofUnsupported)
	}
	if !errors.Is(err, adapter.ErrExternalIdentityConflict) {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: negative probe is ambiguous: %w", user, authDB, adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

func credentialConnection(cfg adapter.Connection, user, authDB string, password []byte) adapter.Connection {
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: user, Secret: password}
	probe.Attributes = make(map[string]any, len(cfg.Attributes)+1)
	for k, v := range cfg.Attributes {
		probe.Attributes[k] = v
	}
	probe.Attributes["auth_source"] = authDB
	return probe
}

func (a *Adapter) proveAuthenticatedIdentity(ctx context.Context, cfg adapter.Connection, user, authDB string) error {
	client, err := a.connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: target unavailable", user, authDB)
	}
	defer disconnect(client)
	var status struct {
		AuthInfo struct {
			AuthenticatedUsers []struct {
				User string `bson:"user"`
				DB   string `bson:"db"`
			} `bson:"authenticatedUsers"`
		} `bson:"authInfo"`
	}
	err = client.Database(adminDatabase).RunCommand(ctx, bson.D{{Key: "connectionStatus", Value: 1}}).Decode(&status)
	if err != nil {
		if isMongoAuthenticationFailure(err) {
			return fmt.Errorf("mongodb: prove credential for user %q on db %q: %w", user, authDB, adapter.ErrExternalIdentityConflict)
		}
		if isMongoServerReply(err) {
			return fmt.Errorf("mongodb: prove credential for user %q on db %q: authentication response is ambiguous: %w", user, authDB, adapter.ErrCredentialProofUnsupported)
		}
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: target unavailable", user, authDB)
	}
	users := status.AuthInfo.AuthenticatedUsers
	if len(users) == 0 {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: authentication identity is absent: %w", user, authDB, adapter.ErrCredentialProofUnsupported)
	}
	if len(users) != 1 {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: authentication identity is ambiguous: %w", user, authDB, adapter.ErrCredentialProofUnsupported)
	}
	if users[0].User != user || users[0].DB != authDB {
		return fmt.Errorf("mongodb: prove credential for user %q on db %q: authenticated as another identity: %w", user, authDB, adapter.ErrExternalIdentityConflict)
	}
	return nil
}

func mongodbProbePassword() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	out := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(out, raw)
	return out, nil
}

func isMongoAuthenticationFailure(err error) bool {
	var commandErr mongo.CommandError
	if errors.As(err, &commandErr) && commandErr.Code == 18 {
		return true
	}
	var driverErr driver.Error
	return errors.As(err, &driverErr) && driverErr.Code == 18
}

func isMongoServerReply(err error) bool {
	var commandErr mongo.CommandError
	if errors.As(err, &commandErr) {
		return true
	}
	var driverErr driver.Error
	return errors.As(err, &driverErr)
}

// ValidateConnection проверяет доступ к целевой системе: подключается под
// admin credential, выполняет Ping, admin-команду hello и убеждается, что
// аутентифицированная учётка обладает минимальными привилегиями для управления
// пользователями (createUser/dropUser/grantRole/revokeRole/changePassword —
// матрица минимальных привилегий, docs/threat-model.md, R4; роли уровня
// userAdmin/userAdminAnyDatabase/root их дают). Проверка выполняется здесь, а
// не в момент Apply, чтобы отказ был ранним и понятным. Пароль не попадает в
// тексты ошибок: он передаётся полем options.Credential, а не строкой URI.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	client, err := a.connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mongodb: validate connection: %w", err)
	}
	defer disconnect(client)

	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		return fmt.Errorf("mongodb: validate connection: ping: %w", err)
	}
	if _, err := runHello(ctx, client); err != nil {
		return fmt.Errorf("mongodb: validate connection: %w", err)
	}
	// Без аутентификации (сервер с выключенным auth) проверять привилегии
	// нечего и не у кого: подключение и так имеет полный доступ.
	if cfg.AdminCredential.Username != "" {
		if err := checkAdminPrivileges(ctx, client, cfg.AdminCredential.Username); err != nil {
			return fmt.Errorf("mongodb: validate connection: %w", err)
		}
	}
	return nil
}

// runHello выполняет admin-команду hello и возвращает её ответ как документ.
func runHello(ctx context.Context, client *mongo.Client) (bson.M, error) {
	var hello bson.M
	err := client.Database(adminDatabase).
		RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).
		Decode(&hello)
	if err != nil {
		return nil, fmt.Errorf("run hello: %w", err)
	}
	return hello, nil
}

// userManagementActions — действия MongoDB, которые нужны grantor, чтобы
// создавать/удалять локальные SCRAM-аккаунты, менять их пароли и выдавать/
// отзывать роли. Все они входят в built-in роль userAdmin (а значит и в
// userAdminAnyDatabase и root).
var userManagementActions = []string{
	"createUser",
	"dropUser",
	"grantRole",
	"revokeRole",
	"changePassword",
}

// checkAdminPrivileges выполняет `connectionStatus` с showPrivileges и
// убеждается, что аутентифицированная учётка обладает всеми
// userManagementActions (хотя бы на одном resource). Команда читает
// собственный статус подключения и доступна даже read-only пользователю,
// поэтому проверка не требует лишних прав и ничего не меняет.
func checkAdminPrivileges(ctx context.Context, client *mongo.Client, adminName string) error {
	var status struct {
		AuthInfo struct {
			AuthenticatedUserPrivileges []struct {
				Actions []string `bson:"actions"`
			} `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	cmd := bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}
	if err := client.Database(adminDatabase).RunCommand(ctx, cmd).Decode(&status); err != nil {
		return fmt.Errorf("read authenticated user privileges: %w", err)
	}

	granted := map[string]bool{}
	for _, p := range status.AuthInfo.AuthenticatedUserPrivileges {
		for _, a := range p.Actions {
			granted[a] = true
		}
	}
	var missing []string
	for _, a := range userManagementActions {
		if !granted[a] {
			missing = append(missing, a)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &adapter.InsufficientPrivilegeError{
		Engine:  Engine,
		Admin:   adminName,
		Missing: "user-management privileges (" + strings.Join(missing, ", ") + ")",
		Detail:  "grant a role such as userAdminAnyDatabase or root to the admin user",
	}
}

// authSource возвращает базу аутентификации admin credential:
// Attributes["auth_source"] либо "admin" по умолчанию.
func authSource(cfg adapter.Connection) string {
	if v := adapterutil.StringAttr(cfg.Attributes, "auth_source"); v != "" {
		return v
	}
	return defaultAuthSource
}

// connect собирает клиент MongoDB из cfg и открывает подключение. Хосты,
// имя пользователя, пароль и параметры TLS задаются полями options и не
// конкатенируются в строку URI, поэтому не попадают ни в логи, ни в тексты
// ошибок драйвера.
func (a *Adapter) connect(ctx context.Context, cfg adapter.Connection) (*mongo.Client, error) {
	return connectWithDialer(ctx, cfg, a.dialContext)
}

func connectWithDialer(ctx context.Context, cfg adapter.Connection, dial adapterutil.DialContextFunc) (*mongo.Client, error) {
	opts, err := clientOptionsWithDialer(cfg, dial)
	if err != nil {
		return nil, err
	}
	client, err := mongo.Connect(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("connect to %v: %w", cfg.Endpoints, err)
	}
	return client, nil
}

// clientOptions строит *options.ClientOptions из cfg. Пароль передаётся полем
// options.Credential (а не в URI), поэтому не попадает в ConnString и тексты
// ошибок. replica_set из Attributes включает detection primary через SDAM.
func clientOptions(cfg adapter.Connection) (*options.ClientOptions, error) {
	return clientOptionsWithDialer(cfg, adapterutil.DefaultDialContext)
}

func clientOptionsWithDialer(cfg adapter.Connection, dial adapterutil.DialContextFunc) (*options.ClientOptions, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("no endpoints configured")
	}
	hosts := make([]string, 0, len(cfg.Endpoints))
	for _, ep := range cfg.Endpoints {
		hp, err := normalizeEndpoint(ep)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, hp)
	}

	tlsConfig, err := adapterutil.BuildTLSConfig(cfg.TLS, firstHost(hosts))
	if err != nil {
		return nil, err
	}

	opts := options.Client().
		SetHosts(hosts).
		SetAppName("grantor").
		SetDialer(dial).
		SetConnectTimeout(adapterutil.DefaultDialTimeout).
		SetServerSelectionTimeout(adapterutil.DefaultDialTimeout)
	// Пустой username — подключение без аутентификации (сервер без включённого
	// auth). С непустым — SCRAM через options.Credential, чтобы пароль не попал
	// в ConnString/тексты ошибок.
	if cfg.AdminCredential.Username != "" {
		opts.SetAuth(options.Credential{
			AuthSource: authSource(cfg),
			Username:   cfg.AdminCredential.Username,
			Password:   string(cfg.AdminCredential.Secret),
		})
	}
	if rs := adapterutil.StringAttr(cfg.Attributes, "replica_set"); rs != "" {
		opts.SetReplicaSet(rs)
	}
	if tlsConfig != nil {
		opts.SetTLSConfig(tlsConfig)
	}
	return opts, nil
}

// normalizeEndpoint приводит endpoint host[:port] к каноничному "host:port"
// с портом по умолчанию 27017.
func normalizeEndpoint(endpoint string) (string, error) {
	host, port, err := adapterutil.SplitEndpoint(endpoint, defaultPort)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// firstHost возвращает host без порта из первого элемента списка "host:port"
// для использования как ServerName в verify-full.
func firstHost(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	if host, _, err := net.SplitHostPort(hosts[0]); err == nil {
		return host
	}
	return hosts[0]
}

// disconnect закрывает клиент, игнорируя ошибку: соединение короткоживущее и
// не переиспользуется. Отдельный фоновый контекст с таймаутом гарантирует, что
// disconnect не зависнет, даже если родительский ctx уже отменён.
func disconnect(client *mongo.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), adapterutil.DefaultDialTimeout)
	defer cancel()
	_ = client.Disconnect(ctx)
}
