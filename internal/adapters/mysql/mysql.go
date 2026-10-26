// Package mysql реализует engine adapter для MySQL (docs/architecture.md,
// раздел 13).
//
// Adapter выполняет инвентаризацию (databases, tables, views, indexes,
// accounts, roles, role memberships) и мутации управления доступом:
// grant/revoke ролей, lifecycle аккаунтов (create/disable/enable/delete) и
// ротацию паролей. Мутации идемпотентны на уровне Apply; секреты не попадают
// в plan descriptions, результаты, verification details и тексты ошибок.
//
// Ключевые особенности модели MySQL, отражённые в adapter:
//
//   - account идентифицируется парой user@host: 'app'@'10.%' и
//     'app'@'localhost' — разные аккаунты, поэтому EngineIdentity кодирует
//     обе части ("user@host") и нормализация только до username недопустима.
//   - roles поддерживаются с MySQL 8.0; на MariaDB и MySQL < 8.0 семантика
//     ролей иная, поэтому grant/revoke по ролям gate'ится по версии сервера,
//     а discovery ролей на неподдерживающих серверах просто пропускается.
//   - выданная роль сама по себе не даёт доступа: при
//     activate_all_roles_on_login=OFF (значение по умолчанию) она активируется
//     на логине, только если входит в mysql.default_roles. Поэтому grant
//     дополнительно делает роль default role, revoke убирает её оттуда, а
//     Verify проверяет активацию, а не только наличие ребра role_edges.
//   - disable/enable аккаунта реализуются через ACCOUNT LOCK / ACCOUNT
//     UNLOCK.
package mysql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Engine — имя движка MySQL adapter.
const Engine = "mysql"

// defaultPort — порт MySQL по умолчанию для endpoint без порта.
const defaultPort = 3306

// Adapter реализует adapter.Adapter для MySQL. Постоянных подключений не
// держит: каждый вызов открывает короткоживущий пул к целевой системе.
type Adapter struct {
	dialContext   adapterutil.DialContextFunc
	identityProbe func(context.Context, adapter.Connection) (string, error)
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)

// New возвращает MySQL adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	a := &Adapter{dialContext: dial}
	a.identityProbe = a.probeCurrentUser
	return a
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь,
// grant/revoke ролей, lifecycle аккаунтов и ротацию паролей. Наличие
// access.grant в манифесте не означает, что grant по ролям доступен на любом
// сервере: MySQL < 8.0 и MariaDB отклоняются на этапе Plan (см. supportsRoles).
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"database",
			"table",
			"view",
			"index",
		},
		Capabilities: []adapter.Capability{
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccountCreate,
			// disable/enable отображаются на ACCOUNT LOCK / ACCOUNT UNLOCK.
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			// Restore разрешён, потому что adapter реализует CredentialProver
			// (см. ProveCredential): пересозданная учётка активируется только
			// после доказательства владения зарезервированным паролем.
			adapter.CapAccountRestore,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
		},
		ConnectionSchema: "mysql-connection-v1",
	}
}

// Коды ошибок MySQL, означающие именно отказ аутентификации.
const (
	// erAccessDenied — ER_ACCESS_DENIED_ERROR (неверный пароль либо нет такой
	// учётной записи).
	erAccessDenied = 1045
	// erAccessDeniedNoPassword — ER_ACCESS_DENIED_NO_PASSWORD_ERROR (отказ при
	// подключении без пароля).
	erAccessDeniedNoPassword = 1698
)

// ProveCredential проверяет, что target принимает supplied password именно
// для указанной учётной записи, а заведомо неверный случайный password
// отвергает как authentication failure. Отрицательная проба обязательна: при
// auth-плагине, не проверяющем пароль (например auth_socket или
// mysql_no_login), внешне успешное соединение не доказывает владение
// паролем, и restore в такой конфигурации fail-closed с
// ErrCredentialProofUnsupported.
//
// Ограничение модели MySQL: учётка адресуется парой user@host, и сервер
// сопоставляет соединению ту строку mysql.user, чей host-шаблон покрывает
// адрес клиента. Поэтому доказать credential можно только для учётки, чей
// host-шаблон покрывает адрес самого control plane; для учётки вида
// user@localhost, недостижимой с хоста grantor, проба честно завершается
// identity conflict, а не ложным успехом.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	target, err := parseUserHost(account.EngineIdentity)
	if err != nil {
		return fmt.Errorf("mysql: prove credential: %w", err)
	}
	if len(credential.Secret) == 0 {
		return errors.New("mysql: prove credential: account password is required")
	}

	current, err := a.probeIdentity(ctx, cfg, target.user, credential.Secret)
	if err != nil {
		if isAuthenticationFailure(err) {
			return fmt.Errorf("mysql: prove credential for account %q: %w",
				target.String(), adapter.ErrExternalIdentityConflict)
		}
		return fmt.Errorf("mysql: prove credential for account %q: target unavailable", target.String())
	}
	if current != target.String() {
		return fmt.Errorf("mysql: prove credential for account %q: authenticated as another identity: %w",
			target.String(), adapter.ErrExternalIdentityConflict)
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return fmt.Errorf("mysql: prove credential for account %q: generate negative probe: %w",
			target.String(), err)
	}
	defer clear(wrong)
	if _, err := a.probeIdentity(ctx, cfg, target.user, wrong); err == nil {
		return fmt.Errorf("mysql: prove credential for account %q: target accepts an unrelated password: %w",
			target.String(), adapter.ErrCredentialProofUnsupported)
	} else if !isAuthenticationFailure(err) {
		return fmt.Errorf("mysql: prove credential for account %q: negative probe is ambiguous: %w",
			target.String(), adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

// negativeProbePasswordLength — длина случайного пароля отрицательной пробы.
// Алфавит [a-zA-Z0-9] совпадает с генерируемыми credentials, поэтому проба не
// упирается в политику сложности паролей сервера и не превращается в
// неоднозначную ошибку валидации.
const negativeProbePasswordLength = 32

// probeIdentity открывает подключение под указанными user/password и
// возвращает CURRENT_USER() — ту строку mysql.user, которой сервер сопоставил
// соединение. Служебная база сознательно не выбирается: у проверяемой учётки
// может не быть доступа к ней, и отказ авторизации базы исказил бы пробу.
// Само подключение выполняет identityProbe: в продакшене это
// probeCurrentUser, в unit-тестах — подменённый seam, позволяющий проверить
// fail-closed логику без живого сервера.
func (a *Adapter) probeIdentity(ctx context.Context, cfg adapter.Connection, user string, secret []byte) (string, error) {
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: user, Secret: secret}
	return a.identityProbe(ctx, probe)
}

// probeCurrentUser открывает подключение под учётными данными cfg и читает
// CURRENT_USER(). Служебная база сознательно не выбирается: у проверяемой
// учётки может не быть доступа к ней, и отказ авторизации базы исказил бы
// пробу.
func (a *Adapter) probeCurrentUser(ctx context.Context, cfg adapter.Connection) (string, error) {
	db, err := a.open(ctx, cfg, "")
	if err != nil {
		return "", err
	}
	defer closeQuietly(db)

	var current string
	if err := db.QueryRowContext(ctx, `SELECT CURRENT_USER()`).Scan(&current); err != nil {
		return "", fmt.Errorf("read current identity: %w", err)
	}
	return current, nil
}

// isAuthenticationFailure классифицирует только отказ аутентификации MySQL.
// Транспорт, таймауты, блокировка учётки и отказ доступа к базе остаются
// unavailable/ambiguous и никогда не превращаются в identity conflict.
func isAuthenticationFailure(err error) bool {
	var myErr *mysqldriver.MySQLError
	return errors.As(err, &myErr) &&
		(myErr.Number == erAccessDenied || myErr.Number == erAccessDeniedNoPassword)
}

// ValidateConnection проверяет доступ к целевой системе: подключается к
// первому endpoint под admin credential, выполняет `SELECT VERSION()` и
// убеждается, что admin-учётка обладает минимальными привилегиями для
// управления аккаунтами (CREATE USER для create/drop/set-password и GRANT
// OPTION для grant/revoke — матрица минимальных привилегий,
// docs/threat-model.md, R4). Проверка привилегий выполняется здесь, а не в
// момент Apply, чтобы отказ был ранним и понятным. Пароль не попадает в тексты
// ошибок: он передаётся полем конфигурации (mysqldriver.Config.Passwd), а не в
// строке DSN, и adapter не собирает DSN через FormatDSN, чтобы секрет вообще не
// оказывался в строке.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	db, err := a.open(ctx, cfg, defaultDatabase(cfg))
	if err != nil {
		return fmt.Errorf("mysql: validate connection: %w", err)
	}
	defer closeQuietly(db)

	var version string
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		return fmt.Errorf("mysql: validate connection: select version: %w", err)
	}
	if err := checkAdminPrivileges(ctx, db, cfg.AdminCredential.Username); err != nil {
		return fmt.Errorf("mysql: validate connection: %w", err)
	}
	return nil
}

// checkAdminPrivileges читает `SHOW GRANTS FOR CURRENT_USER()` и убеждается,
// что admin-учётка имеет глобальные (ON *.*) привилегии CREATE USER (нужна для
// CREATE/DROP USER, смены чужого пароля и SET DEFAULT ROLE для чужой учётки) и
// GRANT OPTION (нужна для GRANT/REVOKE). ALL PRIVILEGES ON *.* покрывает
// CREATE USER. Запрос только читает собственные гранты и ничего не меняет.
//
// Разбираются гранты, выданные учётке напрямую: роли MySQL 8.0 через
// `USING <role>` не разворачиваются (admin-учётка ожидаемо держит привилегии
// напрямую, как это делает root).
func checkAdminPrivileges(ctx context.Context, db *sql.DB, adminName string) error {
	rows, err := db.QueryContext(ctx, `SHOW GRANTS FOR CURRENT_USER()`)
	if err != nil {
		return fmt.Errorf("read admin grants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var lines []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return fmt.Errorf("scan admin grant row: %w", err)
		}
		lines = append(lines, line)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read admin grants: %w", err)
	}

	caps := adminGrantCapabilities(lines)
	if caps.canCreateUser && caps.hasGrantOption {
		return nil
	}
	return &adapter.InsufficientPrivilegeError{
		Engine:  Engine,
		Admin:   adminName,
		Missing: missingMySQLPrivileges(caps),
		Detail:  "grant with GRANT CREATE USER ON *.* TO <admin> WITH GRANT OPTION (or ALL PRIVILEGES ON *.* WITH GRANT OPTION)",
	}
}

// adminGrants — итог разбора SHOW GRANTS: держит ли учётка глобальные (ON *.*)
// привилегии CREATE USER и GRANT OPTION.
type adminGrants struct {
	canCreateUser  bool
	hasGrantOption bool
}

// adminGrantCapabilities сводит строки SHOW GRANTS к признакам adminGrants.
// Учитываются только глобальные гранты (ON *.*): привилегии на конкретные базы
// не позволяют создавать учётки и управлять ролями.
func adminGrantCapabilities(lines []string) adminGrants {
	var g adminGrants
	for _, line := range lines {
		privs, scope, grantOption, ok := parseGrantStatement(line)
		if !ok || scope != "*.*" {
			continue
		}
		if privs["ALL PRIVILEGES"] || privs["CREATE USER"] {
			g.canCreateUser = true
		}
		// GRANT OPTION приходит суффиксом WITH GRANT OPTION, но на всякий
		// случай учитываем и представление привилегией в списке.
		if grantOption || privs["GRANT OPTION"] {
			g.hasGrantOption = true
		}
	}
	return g
}

// parseGrantStatement разбирает одну строку SHOW GRANTS вида
//
//	GRANT <privileges> ON <scope> TO <user> [WITH GRANT OPTION]
//
// Возвращает множество привилегий в верхнем регистре, scope как записан
// ("*.*", "`db`.*", ...), признак WITH GRANT OPTION и ok=false для строк без
// части " ON " (например GRANT `role`@`h` TO `u`@`h` — назначение роли, а не
// привилегий).
func parseGrantStatement(line string) (privs map[string]bool, scope string, grantOption, ok bool) {
	s := strings.TrimSpace(line)
	const prefix = "GRANT "
	if !strings.HasPrefix(s, prefix) {
		return nil, "", false, false
	}
	rest := s[len(prefix):]
	onIdx := strings.Index(rest, " ON ")
	if onIdx < 0 {
		return nil, "", false, false
	}
	afterOn := rest[onIdx+len(" ON "):]
	toIdx := strings.Index(afterOn, " TO ")
	if toIdx < 0 {
		return nil, "", false, false
	}
	scope = strings.TrimSpace(afterOn[:toIdx])
	after := strings.ToUpper(strings.TrimSpace(afterOn[toIdx+len(" TO "):]))
	grantOption = strings.HasSuffix(after, "WITH GRANT OPTION")
	return parsePrivilegeList(rest[:onIdx]), scope, grantOption, true
}

// parsePrivilegeList разбирает список привилегий, разделённых запятыми, в
// множество токенов верхнего регистра. Column-level гранты (со скобками) на
// глобальном scope *.* не встречаются, поэтому наивного split по запятой
// достаточно.
func parsePrivilegeList(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.ToUpper(strings.TrimSpace(part)); p != "" {
			out[p] = true
		}
	}
	return out
}

// missingMySQLPrivileges формулирует, какой минимальной привилегии не хватает.
func missingMySQLPrivileges(g adminGrants) string {
	switch {
	case !g.canCreateUser && !g.hasGrantOption:
		return "the global CREATE USER privilege and GRANT OPTION"
	case !g.canCreateUser:
		return "the global CREATE USER privilege"
	default:
		return "the global GRANT OPTION"
	}
}

// defaultDatabase возвращает базу для служебного подключения: MySQL не
// требует выбранной базы для чтения information_schema и mysql.*, поэтому по
// умолчанию подключение открывается без default database. Attributes["database"]
// позволяет задать её явно.
func defaultDatabase(cfg adapter.Connection) string {
	return adapterutil.StringAttr(cfg.Attributes, "database")
}

// open открывает короткоживущий пул к целевой системе и проверяет его через
// PingContext. Конфигурация строится полями структуры (пароль — в поле
// Passwd), а подключение создаётся через NewConnector/OpenDB, минуя
// FormatDSN: секрет никогда не оказывается в строке DSN.
func (a *Adapter) open(ctx context.Context, cfg adapter.Connection, database string) (*sql.DB, error) {
	return openWithDialer(ctx, cfg, database, a.dialContext)
}

func openWithDialer(ctx context.Context, cfg adapter.Connection, database string, dial adapterutil.DialContextFunc) (*sql.DB, error) {
	cc, err := connConfig(cfg, database)
	if err != nil {
		return nil, err
	}
	cc.DialFunc = dial
	connector, err := mysqldriver.NewConnector(cc)
	if err != nil {
		return nil, fmt.Errorf("build connector for endpoint %q: %w", cfg.Endpoints[0], err)
	}
	db := sql.OpenDB(connector)
	// Мутации на connection и без того сериализованы ядром; ограничиваем пул,
	// чтобы не открывать лишних подключений к целевой системе.
	db.SetMaxOpenConns(4)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		closeQuietly(db)
		return nil, fmt.Errorf("connect to %q: %w", cfg.Endpoints[0], err)
	}
	return db, nil
}

// connConfig строит конфигурацию go-sql-driver для первого endpoint. Пароль,
// имя базы и имя пользователя задаются полями структуры и не конкатенируются
// в строку DSN.
func connConfig(cfg adapter.Connection, database string) (*mysqldriver.Config, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("no endpoints configured")
	}
	if cfg.AdminCredential.Username == "" {
		return nil, errors.New("admin credential username is empty")
	}
	host, port, err := adapterutil.SplitEndpoint(cfg.Endpoints[0], defaultPort)
	if err != nil {
		return nil, err
	}
	tlsName, err := tlsConfigName(cfg.TLS, host)
	if err != nil {
		return nil, err
	}

	cc := mysqldriver.NewConfig()
	cc.User = cfg.AdminCredential.Username
	cc.Passwd = string(cfg.AdminCredential.Secret)
	cc.Net = "tcp"
	cc.Addr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	cc.DBName = database
	cc.TLSConfig = tlsName
	cc.Timeout = adapterutil.DefaultDialTimeout
	cc.Loc = time.UTC
	cc.CheckConnLiveness = true
	// InterpolateParams оставляем выключенным: параметризованные запросы
	// discovery уходят как prepared statements, DDL мутаций собирается через
	// экранирование идентификаторов и quoteLiteral.
	return cc, nil
}

// tlsConfigName возвращает имя TLS-конфигурации для go-sql-driver: "false"
// для незашифрованного режима либо детерминированное имя ранее
// зарегистрированного tls.Config. Имя выводится из содержимого настроек,
// поэтому одинаковые параметры переиспользуют одну запись в глобальном
// реестре драйвера.
func tlsConfigName(t adapter.TLSConfig, host string) (string, error) {
	conf, err := adapterutil.BuildTLSConfig(t, host)
	if err != nil {
		return "", err
	}
	if conf == nil {
		return "false", nil
	}
	name := "grantor-mysql-" + tlsConfigHash(t, host)
	if err := mysqldriver.RegisterTLSConfig(name, conf); err != nil {
		return "", fmt.Errorf("register tls config: %w", err)
	}
	return name, nil
}

// tlsConfigHash строит стабильный ключ TLS-конфигурации по режиму, host,
// CA и клиентскому сертификату.
func tlsConfigHash(t adapter.TLSConfig, host string) string {
	h := sha256.New()
	for _, part := range []string{t.Mode, host, strconv.FormatBool(t.InsecureSkipVerify)} {
		h.Write([]byte(part))
		h.Write([]byte{0x1f})
	}
	h.Write(t.CACertPEM)
	h.Write([]byte{0x1f})
	h.Write(t.ClientCertPEM)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// closeQuietly закрывает пул, игнорируя ошибку закрытия: данные уже получены,
// а пул короткоживущий и не переиспользуется.
func closeQuietly(db *sql.DB) {
	_ = db.Close()
}

// redactExecError возвращает безопасный текст ошибки statement, содержащего
// секрет: сообщение сервера может включать фрагмент запроса, поэтому от
// MySQLError остаётся только код ошибки. Ошибки транспорта текст запроса не
// содержат и возвращаются как есть.
func redactExecError(err error) string {
	var myErr *mysqldriver.MySQLError
	if errors.As(err, &myErr) {
		return fmt.Sprintf("server rejected statement (error %d)", myErr.Number)
	}
	return err.Error()
}
