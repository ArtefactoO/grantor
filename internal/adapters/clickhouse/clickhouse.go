// Package clickhouse реализует engine adapter для ClickHouse
// (docs/architecture.md, раздел 10; движок из плана — ClickHouse).
//
// Транспорт — родной HTTP-интерфейс ClickHouse (по умолчанию порт 8123):
// запрос отправляется телом POST, аутентификация — заголовками
// X-ClickHouse-User / X-ClickHouse-Key (секрет никогда не попадает в URL),
// табличные ответы читаются в FORMAT JSON. Отдельный клиентский драйвер
// сознательно не используется: DDL управления доступом (CREATE/ALTER/DROP
// USER, GRANT/REVOKE) и чтение системных таблиц полностью покрываются
// HTTP-интерфейсом (net/http + encoding/json, ноль новых зависимостей;
// прецедент — rabbitmq adapter поверх Management API).
//
// # Доменная модель
//
//   - account — пользователь ClickHouse (system.users). EngineIdentity — имя
//     пользователя (уникально в пределах сервера), kind login. В атрибутах —
//     storage (local_directory / users_xml / replicated), способы
//     аутентификации и host-ограничения.
//   - resource — база данных (system.databases). ExternalID — "db:<name>";
//     служебные базы system / INFORMATION_SCHEMA / information_schema
//     исключаются.
//   - permission двух видов:
//     1. роль (system.roles) — первоклассная назначаемая permission,
//     ExternalID "role:<name>", scope пустой (роли cluster-wide);
//     2. прямой privilege-грант пользователя (system.grants) — наблюдаемая,
//     НЕ назначаемая permission: "priv:<ACCESS TYPE>" для глобальных грантов
//     и "priv:<ACCESS TYPE>:db:<db>" для грантов уровня базы. Управляемая
//     единица выдачи доступа — роль (как в postgres/mysql); прямые гранты
//     видны в инвентаре и drift, но adapter их не выдаёт. Гранты уровня
//     таблицы/колонки и partial revokes в инвентарь не попадают: ресурсная
//     модель ограничена базами данных.
//   - binding — назначение роли пользователю (system.role_grants; admin
//     option и default role — в атрибутах binding) либо прямой
//     privilege-грант (system.grants; grant option — в атрибутах binding).
//     Рёбра роль→роль не отражаются: аккаунтами считаются только
//     пользователи.
//
// # Опасные привилегии
//
// Опасными помечаются привилегия ACCESS MANAGEMENT (полный контроль над
// пользователями, ролями и грантами), глобальный ALL ON *.* и роли, чьё
// определение содержит такие привилегии или любой грант WITH GRANT OPTION.
// Grant option прямых грантов и admin option ролевых грантов дополнительно
// отражаются в атрибутах bindings (см. dangerousAccessType, roleDangerous).
//
// # Модель disable/enable
//
// Нативной блокировки аккаунта (аналога ACCOUNT LOCK) у ClickHouse нет.
// Disable моделируется host-ограничениями: ALTER USER ... HOST NONE
// запрещает подключение откуда бы то ни было, при этом пароль и все гранты
// пользователя полностью сохраняются; enable выполняет ALTER USER ... HOST
// ANY. Пара обратима и идемпотентна; discovery определяет
// ObservedAccount.Disabled по пустому набору host-ограничений в system.users
// (HOST NONE — единственное состояние, в котором все четыре списка пусты;
// HOST ANY отображается как host_ip ['::/0']). Ограничение модели: если у
// пользователя было нестандартное host-ограничение (например HOST IP
// '10.0.0.0/8'), после цикла disable/enable оно заменится на HOST ANY;
// учётки, созданные grantor, всегда создаются с HOST ANY, поэтому для
// managed-аккаунтов модель точна.
//
// # Топология и кластерные DDL
//
// standalone vs cluster определяется по system.clusters: сервер считается
// участником кластера, если существует кластер, в котором он — локальная
// реплика И присутствует хотя бы один удалённый хост (см.
// topologyFromClusters). Демо-кластеры дефолтного конфига, целиком
// состоящие из локальных реплик, топологией cluster не считаются. Мутации
// выполняются single-node DDL без ON CLUSTER: при replicated-хранилище
// access entities изменения распространяет сам ClickHouse, а координация
// DDL через ON CLUSTER для кластеров с local-хранилищем пользователей —
// документированное продолжение, которое adapter пока не выполняет.
package clickhouse

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/secret"
)

// Engine — имя движка ClickHouse adapter.
const Engine = "clickhouse"

const (
	// defaultPort — порт HTTP-интерфейса по умолчанию для endpoint без порта.
	defaultPort = 8123
	// requestTimeout ограничивает один HTTP-запрос.
	requestTimeout = 30 * time.Second
	// errBodyLimit — верхняя граница фрагмента тела ответа в тексте ошибки.
	errBodyLimit = 512
)

// Adapter реализует adapter.Adapter для ClickHouse. Постоянных подключений не
// держит: каждый вызов открывает короткоживущий HTTP-клиент.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)

// New возвращает ClickHouse adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь
// databases/accounts/permissions/bindings, grant/revoke ролей, lifecycle
// аккаунтов (create/disable/enable/delete) и ротацию паролей.
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"database",
		},
		Capabilities: []adapter.Capability{
			adapter.CapInventoryResources,
			adapter.CapInventoryAccounts,
			adapter.CapInventoryPermissions,
			adapter.CapInventoryBindings,
			adapter.CapAccessGrant,
			adapter.CapAccessRevoke,
			adapter.CapAccountCreate,
			// disable/enable отображаются на ALTER USER ... HOST NONE/ANY
			// (см. doc-комментарий пакета).
			adapter.CapAccountDisable,
			adapter.CapAccountEnable,
			adapter.CapAccountDelete,
			// Restore разрешён, потому что adapter реализует CredentialProver
			// (см. ProveCredential): пересозданный пользователь активируется
			// только после доказательства владения зарезервированным паролем.
			adapter.CapAccountRestore,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
		},
		ConnectionSchema: "clickhouse-connection-v1",
	}
}

// negativeProbePasswordLength — длина случайного пароля отрицательной пробы.
// Алфавит [a-zA-Z0-9] совпадает с генерируемыми credentials, поэтому проба не
// упирается в политику сложности паролей сервера.
const negativeProbePasswordLength = 32

// ProveCredential проверяет, что target принимает supplied password именно
// для указанного пользователя, а заведомо неверный случайный password
// отвергает как authentication failure. Отрицательная проба обязательна:
// пользователь с IDENTIFIED WITH no_password (или сервер, где учётка описана
// в users.xml без пароля) принял бы любое значение, и restore в такой
// конфигурации fail-closed с ErrCredentialProofUnsupported.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" || len(credential.Secret) == 0 {
		return errors.New("clickhouse: prove credential: account identity and password are required")
	}

	current, err := a.probeIdentity(ctx, cfg, name, credential.Secret)
	if err != nil {
		if isAuthenticationFailure(err) {
			return fmt.Errorf("clickhouse: prove credential for user %q: %w",
				name, adapter.ErrExternalIdentityConflict)
		}
		return fmt.Errorf("clickhouse: prove credential for user %q: target unavailable", name)
	}
	if current != name {
		return fmt.Errorf("clickhouse: prove credential for user %q: authenticated as another identity: %w",
			name, adapter.ErrExternalIdentityConflict)
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return fmt.Errorf("clickhouse: prove credential for user %q: generate negative probe: %w", name, err)
	}
	defer clear(wrong)
	if _, err := a.probeIdentity(ctx, cfg, name, wrong); err == nil {
		return fmt.Errorf("clickhouse: prove credential for user %q: target accepts an unrelated password: %w",
			name, adapter.ErrCredentialProofUnsupported)
	} else if !isAuthenticationFailure(err) {
		return fmt.Errorf("clickhouse: prove credential for user %q: negative probe is ambiguous: %w",
			name, adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

// probeIdentity выполняет запрос под указанными user/password и возвращает
// currentUser() — учётную запись, которой сервер сопоставил соединение.
func (a *Adapter) probeIdentity(ctx context.Context, cfg adapter.Connection, name string, secret []byte) (string, error) {
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: name, Secret: secret}
	client, err := a.newClient(probe)
	if err != nil {
		return "", err
	}
	rows, err := client.query(ctx, `SELECT currentUser() AS user`, nil)
	if err != nil {
		return "", err
	}
	if len(rows) != 1 {
		return "", fmt.Errorf("currentUser() returned %d rows, want 1", len(rows))
	}
	raw, ok := rows[0]["user"]
	if !ok {
		return "", errors.New("currentUser() response has no user column")
	}
	var current string
	if err := json.Unmarshal(raw, &current); err != nil {
		return "", fmt.Errorf("decode currentUser(): %w", err)
	}
	return current, nil
}

// ValidateConnection проверяет доступ к целевой системе: выполняет SELECT
// version() (связность и аутентификация), затем разбирает SHOW GRANTS
// текущего пользователя и убеждается, что admin-учётка держит ACCESS
// MANAGEMENT (или ALL) ON *.* — минимальную привилегию, необходимую для
// управления пользователями, ролями и грантами (матрица минимальных
// привилегий, docs/threat-model.md, R4). Проверка выполняется здесь, а не в
// момент Apply, чтобы отказ был ранним и понятным. Роли админа через ролевые
// назначения не разворачиваются: admin ожидаемо держит привилегии напрямую.
// Пароль не попадает в тексты ошибок: он передаётся заголовком
// X-ClickHouse-Key, а не в URL.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("clickhouse: validate connection: %w", err)
	}

	if _, err := client.serverVersion(ctx); err != nil {
		return fmt.Errorf("clickhouse: validate connection: %w", err)
	}

	rows, err := client.query(ctx, `SHOW GRANTS`, nil)
	if err != nil {
		return fmt.Errorf("clickhouse: validate connection: read admin grants: %w", err)
	}
	if !adminHasAccessManagement(grantLines(rows)) {
		return fmt.Errorf("clickhouse: validate connection: %w", &adapter.InsufficientPrivilegeError{
			Engine:  Engine,
			Admin:   cfg.AdminCredential.Username,
			Missing: "the ACCESS MANAGEMENT privilege (or ALL ON *.*)",
			Detail:  "grant with GRANT ACCESS MANAGEMENT ON *.* TO <admin>",
		})
	}
	return nil
}

// grantLines извлекает строки грантов из ответа SHOW GRANTS FORMAT JSON.
// Имя единственной колонки зависит от имени пользователя ("GRANTS FOR ..."),
// поэтому значения читаются независимо от ключа.
func grantLines(rows []map[string]json.RawMessage) []string {
	var out []string
	for _, row := range rows {
		for _, raw := range row {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// adminHasAccessManagement сводит строки SHOW GRANTS к признаку «admin держит
// ACCESS MANAGEMENT»: учитываются только глобальные гранты (ON *.*), которые
// содержат ACCESS MANAGEMENT либо покрывающий его ALL.
func adminHasAccessManagement(lines []string) bool {
	for _, line := range lines {
		privs, scope, _, ok := parseGrantStatement(line)
		if !ok || scope != "*.*" {
			continue
		}
		if privs["ALL"] || privs["ALL PRIVILEGES"] || privs["ACCESS MANAGEMENT"] {
			return true
		}
	}
	return false
}

// parseGrantStatement разбирает одну строку SHOW GRANTS вида
//
//	GRANT <privileges> ON <scope> TO <grantee> [WITH GRANT OPTION]
//
// Возвращает множество привилегий в верхнем регистре, scope как записан
// ("*.*", "db.*", ...), признак WITH GRANT OPTION и ok=false для строк без
// части " ON " (например GRANT role TO user — назначение роли, а не
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

// chClient — HTTP-клиент к ClickHouse. Секрет admin credential хранится в
// secret.Value и раскрывается только при установке заголовка X-ClickHouse-Key,
// поэтому fmt/json самого клиента выводят "[REDACTED]".
type chClient struct {
	baseURL  string
	username string
	secret   secret.Value
	hc       *http.Client
}

// newClient строит chClient из cfg: baseURL из первого endpoint (scheme
// определяется TLS-режимом), учётные данные — из admin credential. Секрет и
// логин в URL не попадают.
func newClient(cfg adapter.Connection) (*chClient, error) {
	return newClientWithDialer(cfg, adapterutil.DefaultDialContext)
}

func (a *Adapter) newClient(cfg adapter.Connection) (*chClient, error) {
	return newClientWithDialer(cfg, a.dialContext)
}

func newClientWithDialer(cfg adapter.Connection, dial adapterutil.DialContextFunc) (*chClient, error) {
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

	scheme := "http"
	var tlsCfg *tls.Config
	if cfg.TLS.Mode != "" && cfg.TLS.Mode != "disabled" {
		scheme = "https"
		tlsCfg, err = adapterutil.BuildTLSConfig(cfg.TLS, host)
		if err != nil {
			return nil, err
		}
	}

	transport := adapterutil.NewHTTPTransportWithDialer(tlsCfg, adapterutil.DefaultDialTimeout, dial)
	return &chClient{
		baseURL:  scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(port))),
		username: cfg.AdminCredential.Username,
		secret:   secret.New(cfg.AdminCredential.Secret),
		hc:       &http.Client{Transport: transport},
	}, nil
}

// queryResponse — разобранный табличный ответ FORMAT JSON.
type queryResponse struct {
	Data []map[string]json.RawMessage `json:"data"`
}

// query выполняет SELECT/SHOW и возвращает строки результата. Значения
// именованных параметров передаются URL-параметрами param_<name>
// (в запросе — {name:String}); секреты через параметры не передаются.
func (c *chClient) query(ctx context.Context, query string, params map[string]string) ([]map[string]json.RawMessage, error) {
	body, err := c.do(ctx, query, params, false)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	var res queryResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("decode query response: %w", err)
	}
	return res.Data, nil
}

// exec выполняет DDL/DML statement. containsSecret=true означает, что текст
// statement содержит секрет (пароль): ошибка сервера в этом случае строится
// только из HTTP-статуса и кода исключения, без тела ответа.
func (c *chClient) exec(ctx context.Context, stmt string, containsSecret bool) error {
	_, err := c.do(ctx, stmt, nil, containsSecret)
	return err
}

// do отправляет один запрос телом POST и возвращает тело ответа.
// wait_end_of_query=1 заставляет сервер буферизовать ответ, чтобы ошибка
// выполнения всегда приходила корректным HTTP-статусом. Для statements с
// секретом ошибка редуцируется до кода исключения ClickHouse
// (X-ClickHouse-Exception-Code): сервер цитирует текст запроса в сообщении
// об ошибке, и тело ответа могло бы содержать пароль.
func (c *chClient) do(ctx context.Context, query string, params map[string]string, containsSecret bool) ([]byte, error) {
	q := url.Values{}
	q.Set("default_format", "JSON")
	q.Set("wait_end_of_query", "1")
	for k, v := range params {
		q.Set("param_"+k, v)
	}

	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.baseURL+"/?"+q.Encode(), strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-ClickHouse-User", c.username)
	req.Header.Set("X-ClickHouse-Key", c.secret.RevealString())
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")

	resp, err := c.hc.Do(req)
	if err != nil {
		// Транспортная ошибка не содержит тела запроса, поэтому безопасна и
		// для statements с секретом.
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		code := resp.Header.Get("X-ClickHouse-Exception-Code")
		if containsSecret {
			return nil, secretStatementError(resp.StatusCode, code)
		}
		return nil, statusError(resp.StatusCode, code, body)
	}
	return body, nil
}

// httpStatusError — не-2xx ответ ClickHouse. Хранит HTTP-статус и код
// исключения отдельно от текста, чтобы вызывающий мог классифицировать отказ
// (например AUTHENTICATION_FAILED) не разбирая сообщение. Текст остаётся
// прежним, включая редактированный вариант для statements с секретом.
type httpStatusError struct {
	status  int
	code    string
	message string
}

func (e *httpStatusError) Error() string { return e.message }

// secretStatementError строит ошибку statement, содержащего секрет: только
// HTTP-статус и код исключения ClickHouse, без тела ответа (оно может
// цитировать statement вместе с паролём).
func secretStatementError(status int, code string) error {
	msg := fmt.Sprintf("server rejected statement (status %d)", status)
	if code != "" {
		msg = fmt.Sprintf("server rejected statement (exception code %s)", code)
	}
	return &httpStatusError{status: status, code: code, message: msg}
}

// statusError строит ошибку неожиданного статуса с фрагментом тела ответа.
// Используется только для запросов без секретов: тело может цитировать текст
// запроса.
func statusError(status int, code string, body []byte) error {
	msg := fmt.Sprintf("unexpected status %d: %s", status, bodySnippet(body))
	if code != "" {
		msg = fmt.Sprintf("unexpected status %d (exception code %s): %s", status, code, bodySnippet(body))
	}
	return &httpStatusError{status: status, code: code, message: msg}
}

// authFailedExceptionCodes — коды исключений ClickHouse, означающие именно
// отказ аутентификации: 516 AUTHENTICATION_FAILED (современные версии), 192
// UNKNOWN_USER и 193 WRONG_PASSWORD (исторические). Отказ авторизации
// (497 ACCESS_DENIED) сюда не входит: он означает, что учётка уже прошла
// аутентификацию.
var authFailedExceptionCodes = map[string]bool{"516": true, "192": true, "193": true}

// isAuthenticationFailure классифицирует только отказ аутентификации.
// Транспорт, таймауты и прочие статусы остаются unavailable/ambiguous и
// никогда не превращаются в identity conflict.
func isAuthenticationFailure(err error) bool {
	var se *httpStatusError
	if !errors.As(err, &se) {
		return false
	}
	if se.code != "" {
		return authFailedExceptionCodes[se.code]
	}
	// Ответ без кода исключения: у HTTP-интерфейса ClickHouse отказ
	// аутентификации — единственный источник 403 Forbidden.
	return se.status == http.StatusForbidden
}

// bodySnippet возвращает усечённый до errBodyLimit фрагмент тела ответа.
func bodySnippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > errBodyLimit {
		return s[:errBodyLimit] + "..."
	}
	return s
}
