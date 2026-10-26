// Package yopass реализует канал одноразовой доставки секрета человеку
// поверх self-hosted Yopass (docs/architecture.md, раздел 18). Vault
// остаётся источником истины: Yopass получает только шифртекст, ключ
// расшифровки живёт во фрагменте браузерной ссылки и на сервер Yopass
// не отправляется.
//
// Инварианты безопасности (раздел 18):
//   - шифрование выполняется в backend до отправки: сервер Yopass видит
//     только PGP-шифртекст;
//   - полная ссылка, ключ и содержимое сообщения не попадают в ошибки,
//     логи, audit или metadata database — ссылка возвращается вызывающему
//     ровно один раз;
//   - one_time и TTL задаёт вызывающий; сервер Yopass принимает только
//     TTL 1h/1d/1w.
package yopass

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	yopassapi "github.com/jhaals/yopass/pkg/yopass"
)

// DefaultTimeout — HTTP timeout запросов к Yopass API по умолчанию.
const DefaultTimeout = 10 * time.Second

// Пути создания секрета двух поколений Yopass API. Новые сборки (в том числе
// bundled jhaals/yopass dev-контура) принимают POST /create/secret; более
// старые инсталляции (общий инстанс организации) знают только классический
// POST /secret и отвечают на новый путь 404. Формат тела и ответа одинаков.
const (
	storePathModern = "/create/secret"
	storePathLegacy = "/secret"
)

// errStorePathUnsupported — типизированный признак «сервер не знает этот
// путь» (404/405): триггер fallback на классический путь, а не ошибка
// доставки.
var errStorePathUnsupported = errors.New("yopass: store path is not supported by the server")

// Config — настройки клиента Yopass.
type Config struct {
	// APIURL — server-side адрес Yopass API, например http://yopass:1337.
	// Обязателен.
	APIURL string
	// PublicURL — браузерная база ссылок, например http://localhost:58090:
	// адрес, по которому Yopass web доступен получателю секрета. Обязателен.
	PublicURL string
	// Timeout — HTTP timeout запросов; по умолчанию DefaultTimeout.
	Timeout time.Duration
}

// Client — клиент Yopass для выдачи одноразовых ссылок. Безопасен для
// конкурентного использования. Поддерживает оба поколения API: первый
// успешный запрос определяет рабочий путь создания секрета, и решение
// кешируется на всё время жизни клиента (без повторных проб на каждый вызов).
type Client struct {
	apiURL    string
	publicURL string
	http      *http.Client

	// mu защищает storePath — выбранный путь создания секрета; пустая
	// строка = ещё не определён (первый вызов пробует storePathModern и на
	// 404/405 повторяет на storePathLegacy).
	mu        sync.Mutex
	storePath string
}

// New проверяет конфигурацию и возвращает клиента Yopass.
func New(cfg Config) (*Client, error) {
	if cfg.APIURL == "" {
		return nil, errors.New("yopass: config: api url is required")
	}
	if cfg.PublicURL == "" {
		return nil, errors.New("yopass: config: public url is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		apiURL:    strings.TrimSuffix(cfg.APIURL, "/"),
		publicURL: strings.TrimSuffix(cfg.PublicURL, "/"),
		http:      &http.Client{Timeout: timeout},
	}, nil
}

// storeRequest — тело запроса создания секрета Yopass API (одинаково для
// обоих путей: POST /create/secret и классического POST /secret).
type storeRequest struct {
	Expiration int32  `json:"expiration"`
	Message    string `json:"message"`
	OneTime    bool   `json:"one_time"`
}

// storeResponse — ответ Yopass API: message содержит id секрета.
type storeResponse struct {
	Message string `json:"message"`
}

// Share шифрует message случайным ключом, отправляет шифртекст в Yopass
// и возвращает браузерную ссылку вида <PublicURL>/#/s/<id>/<key>
// (формат ссылок Yopass web). ttlSeconds обязан быть одним из значений,
// поддерживаемых сервером Yopass: 3600 (1h), 86400 (1d), 604800 (1w).
//
// Ошибки не содержат содержимого message, ключа и готовой ссылки.
func (c *Client) Share(ctx context.Context, message []byte, ttlSeconds int, oneTime bool) (string, error) {
	if len(message) == 0 {
		return "", errors.New("yopass: share: message is empty")
	}
	if !yopassapi.ValidExpirationSeconds(int32(ttlSeconds)) {
		return "", fmt.Errorf("yopass: share: unsupported ttl %d seconds (allowed: 3600, 86400, 604800)", ttlSeconds)
	}

	key, err := yopassapi.GenerateKey()
	if err != nil {
		return "", fmt.Errorf("yopass: share: generate key: %w", err)
	}
	// Классический формат вместо yopassapi.Encrypt (AEAD): см. encrypt.go —
	// старые web-клиенты Yopass не расшифровывают AEAD-сообщения.
	ciphertext, err := encryptClassic(message, key)
	if err != nil {
		return "", fmt.Errorf("yopass: share: encrypt message: %w", err)
	}

	id, err := c.store(ctx, storeRequest{
		Expiration: int32(ttlSeconds),
		Message:    ciphertext,
		OneTime:    oneTime,
	})
	if err != nil {
		return "", err
	}
	return yopassapi.SecretURL(c.publicURL, id, key, false, false), nil
}

// store отправляет шифртекст на Yopass API и возвращает id секрета.
// Рабочий путь создания определяется первым вызовом: сначала пробуется
// современный /create/secret; ответ 404/405 (сервер старого поколения)
// приводит к повтору того же запроса на классический /secret. Успешный путь
// кешируется на всё время жизни клиента — последующие вызовы делают ровно
// один запрос. Тело ответа сервера при ошибке в текст ошибки не включается:
// там может оказаться echo полей запроса.
func (c *Client) store(ctx context.Context, body storeRequest) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("yopass: share: marshal request: %w", err)
	}

	if path := c.cachedStorePath(); path != "" {
		return c.postSecret(ctx, path, payload)
	}
	id, err := c.postSecret(ctx, storePathModern, payload)
	if err == nil {
		c.rememberStorePath(storePathModern)
		return id, nil
	}
	if !errors.Is(err, errStorePathUnsupported) {
		return "", err
	}
	// Старое поколение Yopass: тот же запрос на классический путь.
	id, err = c.postSecret(ctx, storePathLegacy, payload)
	if err != nil {
		return "", err
	}
	c.rememberStorePath(storePathLegacy)
	return id, nil
}

// cachedStorePath возвращает закешированный путь создания секрета ("" — ещё
// не определён).
func (c *Client) cachedStorePath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.storePath
}

// rememberStorePath кеширует рабочий путь создания секрета (first write wins).
func (c *Client) rememberStorePath(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storePath == "" {
		c.storePath = path
	}
}

// postSecret выполняет один POST на указанный путь создания секрета. Ответ
// 404/405 возвращается как errStorePathUnsupported (признак сервера другого
// поколения API); прочие не-200 — ошибка без тела ответа.
func (c *Client) postSecret(ctx context.Context, path string, payload []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+path, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("yopass: share: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("yopass: share: post secret: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return "", fmt.Errorf("yopass: share: %w (POST %s: %s)", errStorePathUnsupported, path, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("yopass: share: server responded %s", resp.Status)
	}
	var out storeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("yopass: share: decode response: %w", err)
	}
	if out.Message == "" {
		return "", errors.New("yopass: share: server response has empty secret id")
	}
	return out.Message, nil
}
