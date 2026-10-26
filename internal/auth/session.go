package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SessionCookieName — имя cookie с подписанным session token.
const SessionCookieName = "grantor_session"

// Ошибки разбора session tokens.
var (
	// ErrInvalidToken — токен повреждён или подпись не совпала.
	ErrInvalidToken = errors.New("auth: invalid session token")
	// ErrTokenExpired — подпись верна, но срок действия истёк.
	ErrTokenExpired = errors.New("auth: session token expired")
)

// Session — аутентифицированная сессия пользователя UI/API.
type Session struct {
	// Identity is taken from the verified ID token, independently of target principals.
	Issuer          string    `json:"iss,omitempty"`
	Username        string    `json:"username,omitempty"`
	AuthenticatedAt time.Time `json:"iat,omitempty"`
	// Subject — стабильный идентификатор пользователя у IdP (claim sub); для
	// сессии service-принципала (аутентификация по service-токену) — id
	// принципала.
	Subject string `json:"sub"`
	// Email — email пользователя; по нему выполняется маппинг ролей.
	Email string `json:"email"`
	// Role — роль control plane (docs/architecture.md, раздел 21).
	Role Role `json:"role"`
	// ExpiresAt — момент истечения сессии.
	ExpiresAt time.Time `json:"exp"`
	// Service marks the actor as a service principal. Personal bearer keys
	// retain a human actor; CSRF depends on the authentication transport.
	// У cookie-сессий человека всегда false;
	// omitempty сохраняет прежний формат session token.
	Service bool `json:"svc,omitempty"`
	// Bearer request metadata must never enter a signed browser session.
	APIKeyID     string   `json:"-"`
	APIUserID    string   `json:"-"`
	OwnerRole    Role     `json:"-"`
	Environments []string `json:"-"`
	Permissions  []string `json:"-"`
}

// Actor-типы для audit-событий и операций.
const (
	actorTypeUser    = "user"
	actorTypeService = "service"
)

// ActorType возвращает actor_type для audit/operations: "service" для сессии
// service-принципала, иначе "user".
func (s Session) ActorType() string {
	if s.Service {
		return actorTypeService
	}
	return actorTypeUser
}

// ActorID возвращает actor_id для audit/operations: для service-принципала —
// его id (Subject), для человека — email (стабильнее subject IdP для чтения
// журнала человеком).
func (s Session) ActorID() string {
	if s.Service {
		return s.Subject
	}
	return s.Email
}

// Codec подписывает и проверяет компактные session tokens формата
// base64url(JSON) + "." + base64url(HMAC-SHA256(secret, JSON)).
// Внешних зависимостей и server-side хранилища сессий нет: вся сессия
// целиком лежит в подписанной cookie, logout — удаление cookie.
type Codec struct {
	secret []byte
}

// NewCodec возвращает Codec с копией секрета подписи. Пустой секрет —
// ошибка; рекомендуемая длина — не меньше 32 байт.
func NewCodec(secret []byte) (Codec, error) {
	if len(secret) == 0 {
		return Codec{}, errors.New("auth: empty session secret")
	}
	c := make([]byte, len(secret))
	copy(c, secret)
	return Codec{secret: c}, nil
}

// Encode сериализует сессию в подписанный токен.
func (c Codec) Encode(s Session) string {
	payload, err := json.Marshal(s)
	if err != nil {
		// Session состоит из всегда сериализуемых полей; ошибка возможна
		// только при порче типа и является программной.
		panic(fmt.Sprintf("auth: marshal session: %v", err))
	}
	return c.sign(payload)
}

// Decode проверяет подпись токена (сравнение constant-time) и срок
// действия, затем возвращает сессию.
func (c Codec) Decode(token string) (Session, error) {
	payload, err := c.verify(token)
	if err != nil {
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return Session{}, fmt.Errorf("%w: bad payload", ErrInvalidToken)
	}
	if s.ExpiresAt.IsZero() {
		return Session{}, fmt.Errorf("%w: missing expiry", ErrInvalidToken)
	}
	if time.Now().After(s.ExpiresAt) {
		return Session{}, ErrTokenExpired
	}
	return s, nil
}

// CSRFToken возвращает CSRF token сессии: hex(HMAC-SHA256(secret,
// "csrf:"+subject)). Токен детерминирован для subject в пределах жизни
// секрета, поэтому его не нужно хранить: сервер пересчитывает и сравнивает
// значение constant-time. UI получает токен из GET /auth/me и передаёт его
// в заголовке X-Grantor-CSRF каждого мутирующего запроса.
func (c Codec) CSRFToken(s Session) string {
	m := hmac.New(sha256.New, c.secret)
	_, _ = m.Write([]byte("csrf:" + s.Subject))
	return hex.EncodeToString(m.Sum(nil))
}

// sign возвращает подписанный токен для произвольного payload.
func (c Codec) sign(payload []byte) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString(payload) + "." + enc.EncodeToString(c.mac(payload))
}

// verify проверяет подпись токена (constant-time) и возвращает payload.
func (c Codec) verify(token string) ([]byte, error) {
	payloadPart, sigPart, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("%w: malformed", ErrInvalidToken)
	}
	enc := base64.RawURLEncoding
	payload, err := enc.DecodeString(payloadPart)
	if err != nil {
		return nil, fmt.Errorf("%w: bad payload encoding", ErrInvalidToken)
	}
	sig, err := enc.DecodeString(sigPart)
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrInvalidToken)
	}
	if !hmac.Equal(sig, c.mac(payload)) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	return payload, nil
}

// mac считает HMAC-SHA256 payload на секрете Codec.
func (c Codec) mac(payload []byte) []byte {
	m := hmac.New(sha256.New, c.secret)
	_, _ = m.Write(payload)
	return m.Sum(nil)
}

// SetCookie устанавливает session cookie: HttpOnly, SameSite=Lax, Path=/.
// secure включает флаг Secure (в production за TLS — обязательно).
func SetCookie(w http.ResponseWriter, value string, ttl time.Duration, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie удаляет session cookie (logout).
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
