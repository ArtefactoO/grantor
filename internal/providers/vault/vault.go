// Package vault реализует secrets provider поверх HashiCorp Vault KV v2
// (docs/architecture.md, раздел 17). В metadata database хранятся только
// mount/path, версия и несекретные метаданные; сами секреты живут в Vault
// и в памяти процесса.
//
// Инвариант безопасности (раздел 24): ошибки пакета содержат только
// операцию, mount и path — никогда значения секретов и никогда Vault token.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/hashicorp/vault/api"
)

// DefaultTimeout — HTTP timeout клиента Vault по умолчанию.
const DefaultTimeout = 10 * time.Second

// Режимы аутентификации клиента (Config.Auth).
const (
	// AuthToken — статический токен (Config.Token). Прежнее поведение и
	// значение по умолчанию для пустого Config.Auth.
	AuthToken = "token"
	// AuthKubernetes — Kubernetes auth central Vault: login JWT'ом
	// ServiceAccount процесса в auth mount (Config.K8sAuthPath) с фоновым
	// продлением выданного client token (см. kubernetes.go и StartAuth).
	AuthKubernetes = "kubernetes"
)

// DefaultK8sJWTPath — путь к projected JWT ServiceAccount по умолчанию.
const DefaultK8sJWTPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// ErrNotFound возвращается, когда секрет или запрошенная версия отсутствуют
// в Vault. Ошибки клиента поддерживают errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("vault: secret not found")

// Config — настройки подключения к Vault.
type Config struct {
	// Address — URL Vault, например https://vlt.example.com. Обязателен.
	Address string
	// Auth — режим аутентификации: "" или AuthToken (статический токен,
	// по умолчанию) либо AuthKubernetes (login JWT'ом ServiceAccount).
	Auth string
	// Token — Vault token; обязателен в token-режиме, в kubernetes-режиме
	// игнорируется. Не логируется и не попадает в тексты ошибок.
	Token string
	// Mount — KV v2 mount; по умолчанию DefaultMount.
	Mount string
	// Namespace — namespace Vault Enterprise; опционален.
	Namespace string
	// Timeout — HTTP timeout запросов; по умолчанию DefaultTimeout.
	Timeout time.Duration

	// K8sAuthPath — auth mount Kubernetes-аутентификации (например,
	// "kubernetes-test"); обязателен в kubernetes-режиме.
	K8sAuthPath string
	// K8sRole — имя роли auth mount; обязательна в kubernetes-режиме.
	K8sRole string
	// K8sJWTPath — файл с JWT ServiceAccount; по умолчанию
	// DefaultK8sJWTPath. Файл перечитывается при каждом login: projected
	// token ротируется kubelet'ом.
	K8sJWTPath string
	// Logger — логгер фонового продления токена; nil — slog.Default().
	// Значения токена и JWT не логируются ни на одном уровне.
	Logger *slog.Logger
}

// withDefaults возвращает копию конфигурации с заполненными значениями по
// умолчанию для Mount, Timeout, K8sJWTPath и Logger.
func (cfg Config) withDefaults() Config {
	if cfg.Mount == "" {
		cfg.Mount = DefaultMount
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.K8sJWTPath == "" {
		cfg.K8sJWTPath = DefaultK8sJWTPath
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return cfg
}

// Client — обёртка над Vault KV v2 для одного mount. Безопасен для
// конкурентного использования: token swap kubernetes-режима укрыт RWMutex
// самого api.Client (SetToken/Token), поэтому KV-чтения во время продления
// или re-login не рвутся.
type Client struct {
	api   *api.Client
	kv    *api.KVv2
	mount string
	// k8s — состояние Kubernetes-аутентификации; nil в token-режиме.
	k8s *kubernetesAuth
}

// New создаёт клиента Vault. Подключение не проверяется: для проверки
// доступности используйте Ping. В kubernetes-режиме до вызова StartAuth
// клиент не аутентифицирован.
func New(cfg Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, errors.New("vault: config: address is required")
	}
	switch cfg.Auth {
	case "", AuthToken:
		if cfg.Token == "" {
			return nil, errors.New("vault: config: token is required")
		}
	case AuthKubernetes:
		if cfg.K8sAuthPath == "" {
			return nil, errors.New("vault: config: kubernetes auth path is required")
		}
		if cfg.K8sRole == "" {
			return nil, errors.New("vault: config: kubernetes role is required")
		}
	default:
		return nil, fmt.Errorf("vault: config: unknown auth method %q (supported: %q, %q)",
			cfg.Auth, AuthToken, AuthKubernetes)
	}
	cfg = cfg.withDefaults()

	apiCfg := api.DefaultConfig()
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("vault: default config: %w", apiCfg.Error)
	}
	apiCfg.Address = cfg.Address
	apiCfg.Timeout = cfg.Timeout

	client, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("vault: new client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	c := &Client{
		api:   client,
		kv:    client.KVv2(cfg.Mount),
		mount: cfg.Mount,
	}
	if cfg.Auth == AuthKubernetes {
		c.k8s = &kubernetesAuth{
			api:      client,
			authPath: cfg.K8sAuthPath,
			role:     cfg.K8sRole,
			jwtPath:  cfg.K8sJWTPath,
			log:      cfg.Logger,
		}
	} else {
		client.SetToken(cfg.Token)
	}
	return c, nil
}

// StartAuth выполняет начальную аутентификацию клиента и запускает её
// фоновое сопровождение. В token-режиме — no-op (токен статичен). В
// kubernetes-режиме выполняется login JWT'ом ServiceAccount, после чего
// фоновая горутина продлевает client token на ~2/3 lease; отмена ctx
// останавливает сопровождение (clean shutdown вместе с процессом).
func (c *Client) StartAuth(ctx context.Context) error {
	if c.k8s == nil {
		return nil
	}
	renewable, lease, err := c.k8s.login(ctx)
	if err != nil {
		return err
	}
	if lease <= 0 {
		// Токен без TTL (нестандартная конфигурация роли): продлевать нечего.
		c.k8s.log.Info("vault: kubernetes login returned a token without ttl; renewal loop is not started")
		return nil
	}
	go c.k8s.renewLoop(ctx, renewable, lease)
	return nil
}

// Mount возвращает используемый KV v2 mount.
func (c *Client) Mount() string {
	return c.mount
}

// Put записывает данные по относительному пути внутри mount и возвращает
// номер созданной версии секрета.
func (c *Client) Put(ctx context.Context, path string, data map[string]any) (int, error) {
	sec, err := c.kv.Put(ctx, path, data)
	if err != nil {
		return 0, c.wrapErr("put", path, err)
	}
	if sec == nil || sec.VersionMetadata == nil {
		return 0, fmt.Errorf("vault: put %s/%s: missing version metadata", c.mount, path)
	}
	return sec.VersionMetadata.Version, nil
}

// PutCAS writes a KV v2 value only when the canonical path is still at the
// expected version (0 means the path must not exist). It is the sole promotion
// primitive for connection admin credential changes. A caller must treat any
// returned error as ambiguous and read the canonical value back: the HTTP
// response can be lost after Vault committed the write.
func (c *Client) PutCAS(ctx context.Context, path string, data map[string]any, expectedVersion int) (int, error) {
	if expectedVersion < 0 {
		return 0, errors.New("vault: put cas: expected version must be non-negative")
	}
	secret, err := c.api.Logical().WriteWithContext(ctx,
		fmt.Sprintf("%s/data/%s", c.mount, path),
		map[string]any{
			"data": data,
			"options": map[string]any{
				"cas": expectedVersion,
			},
		},
	)
	if err != nil {
		return 0, c.wrapErr("put cas", path, err)
	}
	if secret == nil || secret.Data == nil {
		return 0, fmt.Errorf("vault: put cas %s/%s: missing version metadata", c.mount, path)
	}
	version, err := vaultVersion(secret.Data["version"])
	if err != nil {
		return 0, fmt.Errorf("vault: put cas %s/%s: %w", c.mount, path, err)
	}
	return version, nil
}

func vaultVersion(value any) (int, error) {
	switch v := value.(type) {
	case int:
		if v > 0 {
			return v, nil
		}
	case int64:
		if v > 0 && v <= int64(^uint(0)>>1) {
			return int(v), nil
		}
	case float64:
		if v > 0 && v == float64(int(v)) {
			return int(v), nil
		}
	case json.Number:
		n, err := strconv.Atoi(v.String())
		if err == nil && n > 0 {
			return n, nil
		}
	}
	return 0, fmt.Errorf("missing or invalid version")
}

// Get читает последнюю версию секрета и возвращает данные вместе с номером
// версии. Для отсутствующего секрета ошибка удовлетворяет
// errors.Is(err, ErrNotFound).
func (c *Client) Get(ctx context.Context, path string) (map[string]any, int, error) {
	sec, err := c.kv.Get(ctx, path)
	if err != nil {
		return nil, 0, c.wrapErr("get", path, err)
	}
	version := 0
	if sec.VersionMetadata != nil {
		version = sec.VersionMetadata.Version
	}
	return sec.Data, version, nil
}

// GetVersion читает конкретную версию секрета. Для отсутствующей версии
// ошибка удовлетворяет errors.Is(err, ErrNotFound); для destroyed версии
// Vault возвращает пустые данные без ошибки.
func (c *Client) GetVersion(ctx context.Context, path string, version int) (map[string]any, error) {
	sec, err := c.kv.GetVersion(ctx, path, version)
	if err != nil {
		return nil, c.wrapErr("get version", path, err)
	}
	return sec.Data, nil
}

// VersionMeta — несекретные метаданные одной версии секрета.
type VersionMeta struct {
	CreatedAt time.Time
	Destroyed bool
	// DeletionTime — момент soft-delete версии; nil, если версия не
	// удалялась.
	DeletionTime *time.Time
}

// Metadata — несекретные метаданные секрета KV v2; только их допустимо
// сохранять в metadata database (раздел 17.2 архитектуры).
type Metadata struct {
	CurrentVersion int
	Versions       map[int]VersionMeta
}

// Metadata возвращает метаданные секрета, не читая секретных данных.
func (c *Client) Metadata(ctx context.Context, path string) (*Metadata, error) {
	md, err := c.kv.GetMetadata(ctx, path)
	if err != nil {
		return nil, c.wrapErr("metadata", path, err)
	}

	out := &Metadata{
		CurrentVersion: md.CurrentVersion,
		Versions:       make(map[int]VersionMeta, len(md.Versions)),
	}
	for raw, vm := range md.Versions {
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("vault: metadata %s/%s: parse version %q: %w", c.mount, path, raw, err)
		}
		meta := VersionMeta{
			CreatedAt: vm.CreatedTime,
			Destroyed: vm.Destroyed,
		}
		if !vm.DeletionTime.IsZero() {
			dt := vm.DeletionTime
			meta.DeletionTime = &dt
		}
		out.Versions[n] = meta
	}
	return out, nil
}

// DestroyVersions необратимо уничтожает данные перечисленных версий секрета,
// сохраняя метаданные версий. Пустой список версий — no-op.
func (c *Client) DestroyVersions(ctx context.Context, path string, versions []int) error {
	if len(versions) == 0 {
		return nil
	}
	if err := c.kv.Destroy(ctx, path, versions); err != nil {
		return c.wrapErr("destroy versions", path, err)
	}
	return nil
}

// DeleteMetadata удаляет секрет целиком: все версии и метаданные
// (DELETE {mount}/metadata/{path}). Используется зачисткой собственного
// креда аккаунта после успешного account.delete.
func (c *Client) DeleteMetadata(ctx context.Context, path string) error {
	if err := c.kv.DeleteMetadata(ctx, path); err != nil {
		return c.wrapErr("delete metadata", path, err)
	}
	return nil
}

// Ping проверяет доступность Vault через sys/health и возвращает ошибку,
// если Vault недоступен, не инициализирован или sealed.
func (c *Client) Ping(ctx context.Context) error {
	health, err := c.api.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("vault: ping: %w", err)
	}
	if !health.Initialized {
		return errors.New("vault: ping: not initialized")
	}
	if health.Sealed {
		return errors.New("vault: ping: sealed")
	}
	return nil
}

// wrapErr оборачивает ошибку Vault, добавляя только операцию, mount и path;
// значения секретов и token в текст не попадают. api.ErrSecretNotFound
// заменяется на локальный ErrNotFound, чтобы вызывающие не зависели от
// клиентской библиотеки.
func (c *Client) wrapErr(op, path string, err error) error {
	if errors.Is(err, api.ErrSecretNotFound) {
		err = ErrNotFound
	}
	return fmt.Errorf("vault: %s %s/%s: %w", op, c.mount, path, err)
}
