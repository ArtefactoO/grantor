// Package postgres реализует engine adapter для PostgreSQL
// (docs/architecture.md, раздел 11).
//
// Adapter выполняет инвентаризацию (databases, schemas, relations, indexes,
// roles, memberships) и мутации управления доступом: grant/revoke ролей,
// lifecycle LOGIN-аккаунтов (create/disable/enable/delete) и ротацию
// паролей. Мутации идемпотентны на уровне Apply; секреты не попадают в plan
// descriptions, результаты, verification details и тексты ошибок.
package postgres

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Engine — имя движка PostgreSQL adapter.
const Engine = "postgres"

const (
	// defaultPort — порт PostgreSQL по умолчанию для endpoint без порта.
	defaultPort = 5432
	// defaultMaintenanceDatabase — база служебных подключений, если
	// connection attributes не задают другую.
	defaultMaintenanceDatabase = "postgres"
)

// Adapter реализует adapter.Adapter для PostgreSQL. Постоянных подключений
// не держит: каждый вызов открывает короткоживущие подключения к целевой
// системе.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)
var _ adapter.CredentialProofPreflighter = (*Adapter)(nil)

// New возвращает PostgreSQL adapter.
func New() *Adapter { return &Adapter{} }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь,
// grant/revoke ролей, lifecycle LOGIN-аккаунтов и ротацию паролей.
// resource.create.database пока не объявляется (создание баз — отдельный
// этап).
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"database",
			"schema",
			"table",
			"view",
			"materialized_view",
			"sequence",
			"index",
		},
		Capabilities: []adapter.Capability{
			adapter.CapPostgresSuperuserDirectV1,
			adapter.CapPostgresAccountCreationV1,
			adapter.CapPostgresStatsMembershipV1,
			adapter.CapPostgresObjectACLV1,
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.CapRolePolicyApply,
			adapter.CapRolePolicyCreate,
			adapter.CapAccountCreate,
			adapter.CapRoleCreate,
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			adapter.CapAccountRestore,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
			adapter.ResourceCapability("create", resourceKindDatabase),
		},
		ConnectionSchema: "postgres-connection-v1",
	}
}

// randomProbePassword возвращает случайный ASCII пароль. Сырые random bytes
// нельзя передавать PostgreSQL как password: NUL/невалидный UTF-8 превращают
// отрицательную пробу в protocol/SASL error вместо ожидаемого auth SQLSTATE.
func randomProbePassword() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	encoded := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(encoded, raw)
	return encoded, nil
}

// isAuthenticationFailure accepts only invalid_password, never HBA/authorization denial. Transport/timeouts остаются unavailable/ambiguous и никогда
// не превращаются в identity conflict.
func isAuthenticationFailure(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "28P01"
}

// ValidateConnection проверяет доступ к целевой системе: подключается к
// первому endpoint под admin credential к maintenance-базе, выполняет
// `select version()` и убеждается, что admin-роль обладает минимальными
// привилегиями для управления учётными записями и ролями (SUPERUSER либо
// CREATEROLE — матрица минимальных привилегий, docs/threat-model.md, R4).
// Проверка привилегий выполняется здесь, а не в момент Apply, чтобы отказ был
// ранним и понятным. Пароль не попадает в тексты ошибок: он передаётся полем
// конфигурации, а не в строке DSN.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	conn, err := a.connect(ctx, cfg, maintenanceDatabase(cfg))
	if err != nil {
		return fmt.Errorf("postgres: validate connection: %w", err)
	}
	defer closeQuietly(ctx, conn)

	var version string
	if err := conn.QueryRow(ctx, `select version()`).Scan(&version); err != nil {
		return fmt.Errorf("postgres: validate connection: select version(): %w", err)
	}
	if err := checkAdminPrivileges(ctx, conn, cfg.AdminCredential.Username); err != nil {
		return fmt.Errorf("postgres: validate connection: %w", err)
	}
	return nil
}

// checkAdminPrivileges убеждается, что текущая admin-роль может управлять
// учётными записями и ролями: она должна быть SUPERUSER либо иметь атрибут
// CREATEROLE. Атрибуты роли (в отличие от привилегий) не наследуются через
// membership, поэтому достаточно прочитать флаги самой current_user из
// pg_roles. ADMIN OPTION на конкретные управляемые роли (требование
// PostgreSQL 16 для non-superuser) проверяется отдельно в момент GRANT
// (describeMembershipError): его нельзя проверить заранее, не зная целевой
// роли. Запрос только читает каталог и ничего не меняет.
func checkAdminPrivileges(ctx context.Context, conn *pgx.Conn, adminName string) error {
	var isSuper, canCreateRole bool
	err := conn.QueryRow(ctx,
		`select rolsuper, rolcreaterole from pg_roles where rolname = current_user`).
		Scan(&isSuper, &canCreateRole)
	if err != nil {
		return fmt.Errorf("read admin role attributes: %w", err)
	}
	if isSuper || canCreateRole {
		return nil
	}
	return &adapter.InsufficientPrivilegeError{
		Engine:  Engine,
		Admin:   adminName,
		Missing: "CREATEROLE (or SUPERUSER)",
		Detail:  "grant it with ALTER ROLE ... CREATEROLE, or use a superuser admin credential",
	}
}

// maintenanceDatabase возвращает базу для служебных подключений:
// Attributes["database"] либо "postgres" по умолчанию.
func maintenanceDatabase(cfg adapter.Connection) string {
	if db := adapterutil.StringAttr(cfg.Attributes, "database"); db != "" {
		return db
	}
	return defaultMaintenanceDatabase
}

// connect открывает подключение к указанной базе через первый endpoint.
// Секреты в тексты ошибок не попадают: pgx формирует сообщения из полей
// конфигурации без пароля, а собственные ошибки adapter не содержат DSN.
func (a *Adapter) connect(ctx context.Context, cfg adapter.Connection, database string) (*pgx.Conn, error) {
	return connectWithDialer(ctx, cfg, database, a.dialContext)
}

func connectWithDialer(ctx context.Context, cfg adapter.Connection, database string, dial adapterutil.DialContextFunc) (*pgx.Conn, error) {
	cc, err := connConfigWithDialer(cfg, database, dial)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return nil, fmt.Errorf("connect to database %q at %q: %w", database, cfg.Endpoints[0], err)
	}
	return conn, nil
}

// connConfig строит конфигурацию pgx для первого endpoint. Пароль, имя базы
// и имя пользователя задаются полями структуры после pgx.ParseConfig и не
// попадают в строку DSN (и, соответственно, в ConnString()).
func connConfig(cfg adapter.Connection, database string) (*pgx.ConnConfig, error) {
	return connConfigWithDialer(cfg, database, nil)
}

func connConfigWithDialer(cfg adapter.Connection, database string, dial adapterutil.DialContextFunc) (*pgx.ConnConfig, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("no endpoints configured")
	}
	if cfg.AdminCredential.Username == "" {
		return nil, errors.New("admin credential username is empty")
	}
	if database == "" {
		return nil, errors.New("database name is empty")
	}
	host, port, err := adapterutil.SplitEndpoint(cfg.Endpoints[0], defaultPort)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := adapterutil.BuildTLSConfig(cfg.TLS, host)
	if err != nil {
		return nil, err
	}

	// sslmode=disable в строке нужен только для того, чтобы pgx не добавлял
	// fallback-конфигурации и не включал собственную обработку TLS;
	// фактический режим TLS задаётся полем TLSConfig ниже.
	dsn := fmt.Sprintf("host=%s port=%d sslmode=disable", quoteDSNValue(host), port)
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse connection config for endpoint %q: %w", cfg.Endpoints[0], err)
	}
	cc.Database = database
	cc.User = cfg.AdminCredential.Username
	cc.Password = string(cfg.AdminCredential.Secret)
	cc.TLSConfig = tlsConfig
	cc.ConnectTimeout = adapterutil.DefaultDialTimeout
	if dial != nil {
		// pgconn otherwise resolves before DialFunc and hides the original
		// hostname from the transport's canonical DNS and rebinding checks.
		cc.LookupFunc = func(_ context.Context, host string) ([]string, error) {
			return []string{host}, nil
		}
	} else {
		dial = adapterutil.DefaultDialContext
	}
	cc.DialFunc = pgconn.DialFunc(dial)
	cc.RuntimeParams["application_name"] = "grantor"
	return cc, nil
}

// quoteDSNValue экранирует значение для keyword/value строки подключения
// libpq: значения с пробелами, кавычками и обратными слэшами оборачиваются
// в одинарные кавычки.
func quoteDSNValue(v string) string {
	if v != "" && !strings.ContainsAny(v, ` '\`) {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(v) + "'"
}

// sslRequestCode — код SSLRequest во frontend-протоколе PostgreSQL: пакет
// длиной 8 (int32 длины и int32 кода), на который сервер отвечает одним
// байтом 'S' (TLS поддерживается) или 'N' (нет). Значение фиксировано
// протоколом (1234 << 16 | 5679).
const sslRequestCode = 80877103

// serverSupportsTLS по лучшему усилию определяет, принимает ли сервер
// PostgreSQL TLS: открывает TCP-соединение к endpoint, отправляет
// SSLRequest и читает односимвольный ответ. Фактический режим подключения
// не меняется — это только детект для security finding
// tls_available_but_disabled.
//
// Возвращает (supported, ok): ok=false означает «определить не удалось»
// (недоступность, таймаут, неожиданный ответ). Вызывающий не должен
// трактовать ok=false как отсутствие TLS: это лучшее усилие, а не
// инвариант.
func serverSupportsTLS(ctx context.Context, endpoint string) (supported, ok bool) {
	return serverSupportsTLSWithDialer(ctx, endpoint, adapterutil.DefaultDialContext)
}

func (a *Adapter) serverSupportsTLS(ctx context.Context, endpoint string) (supported, ok bool) {
	return serverSupportsTLSWithDialer(ctx, endpoint, a.dialContext)
}

func serverSupportsTLSWithDialer(ctx context.Context, endpoint string, dial adapterutil.DialContextFunc) (supported, ok bool) {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	host, port, err := adapterutil.SplitEndpoint(endpoint, defaultPort)
	if err != nil {
		return false, false
	}
	dialCtx, cancel := context.WithTimeout(ctx, adapterutil.DefaultDialTimeout)
	defer cancel()

	conn, err := dial(dialCtx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return false, false
	}
	defer func() { _ = conn.Close() }()

	if deadline, has := dialCtx.Deadline(); has {
		// Ошибку установки deadline игнорируем: при её отсутствии probe
		// ограничен родительским ctx и таймаутом соединения.
		_ = conn.SetDeadline(deadline)
	}

	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], uint32(len(req)))
	binary.BigEndian.PutUint32(req[4:8], sslRequestCode)
	if _, err := conn.Write(req[:]); err != nil {
		return false, false
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return false, false
	}
	switch resp[0] {
	case 'S':
		return true, true
	case 'N':
		return false, true
	default:
		return false, false
	}
}

// closeQuietly закрывает соединение, игнорируя ошибку закрытия: данные уже
// получены, а соединение короткоживущее и не переиспользуется.
func closeQuietly(ctx context.Context, conn *pgx.Conn) {
	_ = conn.Close(ctx)
}
