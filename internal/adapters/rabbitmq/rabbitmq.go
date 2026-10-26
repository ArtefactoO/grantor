// Package rabbitmq реализует engine adapter для RabbitMQ
// (docs/architecture.md, раздел 10; движок из плана — RabbitMQ).
//
// Транспорт — RabbitMQ Management HTTP API (по умолчанию порт 15672) под
// HTTP Basic auth с admin credential. Тяжёлый AMQP-клиент сознательно не
// используется: управление пользователями, permissions и топологией
// полностью покрывается Management API (net/http + encoding/json).
//
// # Доменная модель
//
//   - account — пользователь RabbitMQ (GET /api/users). EngineIdentity —
//     имя пользователя (оно уникально в пределах кластера, дизамбигуация не
//     нужна). Все аккаунты — kind login.
//   - resource — virtual host (GET /api/vhosts). ExternalID — "vhost:<name>".
//   - permission (назначаемая «роль») бывает двух видов:
//     1. tag-permission — cluster-wide тег пользователя
//     (administrator/monitoring/management/policymaker). ExternalID —
//     "tag:<name>", scope пустой.
//     2. vhost-permission — один взаимоисключающий assignment slot на user+vhost:
//     legacy "vhost-access:<vhost>" оставляет полный доступ .*/.*/.*, а
//     builtin "vhost-monitoring:<vhost>" denies configure/write/read with
//     ^$/^$/^$; admin-configured "rabbitmq-template:<key>" pins its exact tuple.
//     All share assignment key "rabbitmq:vhost:<vhost>". The monitoring tag
//     is granted separately and is not implied by vhost visibility.
//   - binding — назначение permission аккаунту: тег в наборе тегов
//     пользователя либо запись permission на vhost (/api/permissions).
//
// # Опасные привилегии
//
// Опасными помечаются тег administrator и template с dangerous=true. Ширина
// regex-тройки вычисляется отдельно: broad=true, если хотя бы одно измерение
// очевидно unrestricted в безопасном subset; legacy full access broad, но
// сохраняется non-dangerous для обратной совместимости operator-сценария.
//
// # Модель disable/enable
//
// У RabbitMQ нет нативной блокировки пользователя. Disable моделируется как
// снятие всей авторизации: удаляются все permissions пользователя на всех
// vhost и его теги заменяются служебным маркером grantor_disabled (пароль
// сохраняется через password_hash, аккаунт продолжает существовать). Такой
// пользователь не может ни работать с брокером (нет доступа к vhost), ни
// пользоваться Management API (нет функциональных тегов). Пароль при этом
// остаётся валидным: движок не умеет блокировать саму аутентификацию, и
// disable снимает именно авторизацию. Маркер даёт discovery признак
// ObservedAccount.Disabled.
//
// Enable снимает маркер, но сам по себе прав не возвращает: они уничтожены
// на target и восстановить их из целевой системы нечем. Поэтому manifest
// объявляет AccountDisableEffect = DisableClearsAccess: ядро после enable
// восстанавливает права обычным grant-потоком по каждому binding аккаунта с
// desired='present', а после disable фиксирует их observed='absent'. Порядок
// обязателен и обеспечивается ядром: сначала снимается маркер, затем
// возвращаются права — обратный порядок дал бы vhost-доступ ещё
// заблокированной учётной записи. Обе операции идемпотентны: повторный
// disable/enable и повторный grant уже присутствующего права дают skipped.
//
// # Топология
//
// standalone (один узел) vs cluster (несколько узлов) определяется по
// GET /api/nodes и пишется в Snapshot.Topology (см. topologyFromNodes).
package rabbitmq

import (
	"bytes"
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

// Engine — имя движка RabbitMQ adapter.
const Engine = "rabbitmq"

const (
	// defaultPort — порт Management API по умолчанию для endpoint без порта.
	defaultPort = 15672
	// requestTimeout ограничивает один HTTP-запрос к Management API.
	requestTimeout = 15 * time.Second
	// errBodyLimit — верхняя граница фрагмента тела ответа в тексте ошибки.
	errBodyLimit = 512
)

// Функциональные теги RabbitMQ, управляющие доступом к Management API и
// администрированием кластера.
const (
	tagAdministrator = "administrator"
	tagMonitoring    = "monitoring"
	tagManagement    = "management"
	tagPolicymaker   = "policymaker"
	// disabledMarkerTag — служебный тег, которым adapter помечает
	// отключённый (disabled) аккаунт. Он не входит в набор функциональных
	// тегов RabbitMQ, поэтому не даёт никаких прав.
	disabledMarkerTag = "grantor_disabled"
)

// knownTags — функциональные теги, для которых adapter публикует назначаемые
// tag-permissions. Прочие (custom) теги в bindings не отражаются.
var knownTags = []string{tagAdministrator, tagManagement, tagMonitoring, tagPolicymaker}

// Adapter реализует adapter.Adapter для RabbitMQ. Постоянных подключений не
// держит: каждый вызов открывает короткоживущий HTTP-клиент к Management API.
type Adapter struct {
	dialContext adapterutil.DialContextFunc
}

var _ adapter.Adapter = (*Adapter)(nil)
var _ adapter.CredentialProver = (*Adapter)(nil)

// New возвращает RabbitMQ adapter.
func New() *Adapter { return NewWithDialer(adapterutil.DefaultDialContext) }

// NewWithDialer возвращает adapter с transport hook для dial-time policy.
func NewWithDialer(dial adapterutil.DialContextFunc) *Adapter {
	if dial == nil {
		dial = adapterutil.DefaultDialContext
	}
	return &Adapter{dialContext: dial}
}

// Manifest объявляет discovery и мутационные возможности adapter: инвентарь
// vhost/accounts/permissions/bindings, grant/revoke tag- и vhost-permissions,
// lifecycle аккаунтов (create/disable/enable/delete) и ротацию паролей.
func (a *Adapter) Manifest() adapter.Manifest {
	return adapter.Manifest{
		Engine:  Engine,
		Version: "v1",
		ResourceKinds: []string{
			"vhost",
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
			// Restore разрешён, потому что adapter реализует CredentialProver
			// (см. ProveCredential): пересозданный пользователь активируется
			// только после доказательства владения зарезервированным паролем.
			adapter.CapAccountRestore,
			adapter.CapCredentialRotate,
			adapter.CapCredentialProve,
			adapter.CapConnectionAdminCredentialSwitch,
			adapter.CapConnectionAdminCredentialRotate,
		},
		// Disable снимает саму авторизацию (см. doc-комментарий пакета):
		// права уничтожаются на target, поэтому ядро обязано вернуть их
		// после enable из desired state и не считать bindings synced,
		// пока учётная запись отключена.
		AccountDisableEffect: adapter.DisableClearsAccess,
		ConnectionSchema:     "rabbitmq-connection-v1",
	}
}

// ValidateConnection проверяет доступ к целевой системе: читает
// GET /api/overview (подтверждает связность и аутентификацию) и GET
// /api/whoami, убеждаясь, что admin credential имеет тег administrator,
// необходимый для управления пользователями. Пароль не попадает в тексты
// ошибок: он передаётся заголовком Authorization, а не в URL.
func (a *Adapter) ValidateConnection(ctx context.Context, cfg adapter.Connection) error {
	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("rabbitmq: validate connection: %w", err)
	}

	var overview apiOverview
	if _, err := client.getJSON(ctx, "/api/overview", &overview); err != nil {
		return fmt.Errorf("rabbitmq: validate connection: %w", err)
	}

	var who apiWhoami
	if _, err := client.getJSON(ctx, "/api/whoami", &who); err != nil {
		return fmt.Errorf("rabbitmq: validate connection: %w", err)
	}
	if !hasTag(parseTags(who.Tags), tagAdministrator) {
		return fmt.Errorf("rabbitmq: validate connection: %w", &adapter.InsufficientPrivilegeError{
			Engine:  Engine,
			Admin:   cfg.AdminCredential.Username,
			Missing: "the " + tagAdministrator + " tag",
			Detail:  "grant it via PUT /api/users/<name> with tags including " + tagAdministrator,
		})
	}
	return nil
}

// probeResult — итог пробы аутентификации через Management API.
type probeResult int

const (
	// probeRejected — target отверг credential (аутентификация не прошла).
	probeRejected probeResult = iota
	// probeAuthenticated — target принял credential.
	probeAuthenticated
	// probeAmbiguous — классифицировать ответ не удалось; вызывающий обязан
	// трактовать это как невозможность доказательства, а не как успех.
	probeAmbiguous
)

// negativeProbePasswordLength — длина случайного пароля отрицательной пробы.
const negativeProbePasswordLength = 32

// ProveCredential проверяет, что target принимает supplied password именно для
// указанного пользователя, а заведомо неверный случайный password отвергает.
// Отрицательная проба обязательна и защищает не только от беспарольных
// конфигураций: она же страхует классификацию ответов Management API — если бы
// признак «аутентифицирован» ошибочно срабатывал на любом ответе, случайный
// пароль тоже «прошёл» бы, и restore fail-closed с
// ErrCredentialProofUnsupported.
//
// Проба выполняется по GET /api/whoami. У RabbitMQ нет отдельного endpoint
// «проверить пароль», а сам whoami требует management-тега, которого у
// созданной grantor учётки нет. Различаются два вида отказа: 401 c
// error "not_authorised" / reason "Not management user" означает, что
// credential ПРИНЯТ и не хватило лишь тега (аутентификация прошла), любой
// другой 401/403 — отказ аутентификации.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" || len(credential.Secret) == 0 {
		return errors.New("rabbitmq: prove credential: account identity and password are required")
	}

	res, identity, err := a.probeCredential(ctx, cfg, name, credential.Secret)
	if err != nil {
		return fmt.Errorf("rabbitmq: prove credential for user %q: target unavailable", name)
	}
	switch res {
	case probeRejected:
		return fmt.Errorf("rabbitmq: prove credential for user %q: %w", name, adapter.ErrExternalIdentityConflict)
	case probeAmbiguous:
		return fmt.Errorf("rabbitmq: prove credential for user %q: authentication result is ambiguous: %w",
			name, adapter.ErrCredentialProofUnsupported)
	}
	// identity непусто только когда Management API вернул whoami: имена
	// пользователей RabbitMQ точные, поэтому расхождение означает подмену.
	if identity != "" && identity != name {
		return fmt.Errorf("rabbitmq: prove credential for user %q: authenticated as another identity: %w",
			name, adapter.ErrExternalIdentityConflict)
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return fmt.Errorf("rabbitmq: prove credential for user %q: generate negative probe: %w", name, err)
	}
	defer clear(wrong)
	res, _, err = a.probeCredential(ctx, cfg, name, wrong)
	if err != nil {
		return fmt.Errorf("rabbitmq: prove credential for user %q: negative probe: target unavailable", name)
	}
	if res != probeRejected {
		return fmt.Errorf("rabbitmq: prove credential for user %q: target accepts an unrelated password: %w",
			name, adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

// probeCredential выполняет одну пробу аутентификации под указанными
// user/password. identity непусто только при полном ответе whoami.
func (a *Adapter) probeCredential(ctx context.Context, cfg adapter.Connection, name string, secret []byte) (probeResult, string, error) {
	probe := cfg
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: name, Secret: secret}
	client, err := a.newClient(probe)
	if err != nil {
		return probeAmbiguous, "", err
	}
	status, body, err := client.do(ctx, http.MethodGet, "/api/whoami", nil)
	if err != nil {
		return probeAmbiguous, "", err
	}
	switch status {
	case http.StatusOK:
		var who apiWhoami
		if err := json.Unmarshal(body, &who); err != nil {
			return probeAmbiguous, "", fmt.Errorf("decode /api/whoami response: %w", err)
		}
		return probeAuthenticated, who.Name, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		if isManagementAccessDenied(body) {
			return probeAuthenticated, "", nil
		}
		return probeRejected, "", nil
	default:
		return probeAmbiguous, "", statusError(http.MethodGet, "/api/whoami", status, body)
	}
}

// apiAuthError — тело отказа Management API.
type apiAuthError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

// isManagementAccessDenied сообщает, что отказ вызван отсутствием
// management-тега, а не отказом аутентификации: RabbitMQ отвечает на это
// error "not_authorised" (authorisation) с reason "Not management user", тогда
// как отказ аутентификации приходит как "not_authorized". Разбор
// консервативен: непонятное тело считается отказом аутентификации, то есть
// fail-closed.
func isManagementAccessDenied(body []byte) bool {
	var e apiAuthError
	if err := json.Unmarshal(body, &e); err != nil {
		return false
	}
	return e.Error == "not_authorised" || strings.Contains(strings.ToLower(e.Reason), "management user")
}

// mgmtClient — HTTP-клиент к Management API. Секрет admin credential хранится
// в secret.Value и раскрывается только при установке Authorization-заголовка,
// поэтому fmt/json самого клиента выводят "[REDACTED]".
type mgmtClient struct {
	baseURL  string
	username string
	secret   secret.Value
	hc       *http.Client
}

// newClient строит mgmtClient из cfg: baseURL из первого endpoint (scheme
// определяется TLS-режимом), Basic auth из admin credential. Секрет и логин в
// URL не попадают.
func newClient(cfg adapter.Connection) (*mgmtClient, error) {
	return newClientWithDialer(cfg, adapterutil.DefaultDialContext)
}

func (a *Adapter) newClient(cfg adapter.Connection) (*mgmtClient, error) {
	return newClientWithDialer(cfg, a.dialContext)
}

func newClientWithDialer(cfg adapter.Connection, dial adapterutil.DialContextFunc) (*mgmtClient, error) {
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
	return &mgmtClient{
		baseURL:  scheme + "://" + net.JoinHostPort(host, strconv.Itoa(int(port))),
		username: cfg.AdminCredential.Username,
		secret:   secret.New(cfg.AdminCredential.Secret),
		hc:       &http.Client{Transport: transport},
	}, nil
}

// getJSON выполняет GET и декодирует тело в out. Возвращает found=false при
// 404 (out не трогается). Прочие не-2xx — ошибка.
func (c *mgmtClient) getJSON(ctx context.Context, path string, out any) (found bool, err error) {
	status, body, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	if status == http.StatusNotFound {
		return false, nil
	}
	if status < 200 || status >= 300 {
		return false, statusError(http.MethodGet, path, status, body)
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return true, fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return true, nil
}

// send выполняет мутирующий запрос (PUT/DELETE) с JSON-телом body (nil — без
// тела). Возвращает статус. Тело запроса может содержать пароль, но оно нигде
// не логируется, а тексты ошибок формируются только из method/path/статуса и
// тела ОТВЕТА, которое submitted-пароль не цитирует.
func (c *mgmtClient) send(ctx context.Context, method, path string, body any) (int, error) {
	status, respBody, err := c.do(ctx, method, path, body)
	if err != nil {
		return status, err
	}
	if status < 200 || status >= 300 {
		return status, statusError(method, path, status, respBody)
	}
	return status, nil
}

// do отправляет один запрос и возвращает статус и прочитанное тело ответа.
// 404 не считается транспортной ошибкой: статус возвращается вызывающему.
func (c *mgmtClient) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal %s %s body: %w", method, path, err)
		}
		reader = bytes.NewReader(raw)
	}

	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, fmt.Errorf("build %s %s request: %w", method, path, err)
	}
	req.SetBasicAuth(c.username, c.secret.RevealString())
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	return resp.StatusCode, data, nil
}

// statusError строит ошибку неожиданного статуса с безопасным фрагментом тела
// ответа (RabbitMQ не цитирует в ответах отправленный пароль).
func statusError(method, path string, status int, body []byte) error {
	return fmt.Errorf("%s %s: unexpected status %d: %s", method, path, status, bodySnippet(body))
}

// bodySnippet возвращает усечённый до errBodyLimit фрагмент тела ответа.
func bodySnippet(body []byte) string {
	s := strings.TrimSpace(string(body))
	if len(s) > errBodyLimit {
		return s[:errBodyLimit] + "..."
	}
	return s
}

// escapePath экранирует один сегмент пути Management API. Имя vhost "/"
// кодируется как %2F, как того требует RabbitMQ.
func escapePath(segment string) string {
	return url.PathEscape(segment)
}
