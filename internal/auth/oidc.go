// Package auth реализует аутентификацию UI/API grantor через OIDC
// Authorization Code + PKCE и RBAC middleware (docs/architecture.md,
// разделы 21 и 24). Код не привязан к конкретному IdP: в dev-контуре
// используется Dex из docker-compose, в production — корпоративный IdP.
//
// # Сессии
//
// Сессия — компактный подписанный token в cookie grantor_session:
// base64url(JSON) + "." + base64url(HMAC-SHA256(secret, JSON)). Подпись
// проверяется constant-time; server-side хранилища сессий нет, logout —
// удаление cookie. См. Codec в session.go.
//
// # CSRF
//
// Session cookie ограничена SameSite=Lax, поэтому браузер не отправит её
// в cross-site POST. Дополнительно каждый мутирующий запрос
// (POST/PUT/PATCH/DELETE) обязан нести заголовок X-Grantor-CSRF со
// значением hex(HMAC-SHA256(secret, "csrf:"+subject)). UI получает токен
// из GET /auth/me и подставляет его в мутирующие запросы. Атакующий сайт
// не может прочитать ответ /auth/me (same-origin policy) и не знает
// секрета сервера, поэтому подделать заголовок не может. Проверку
// выполняет RequireRole; значение выдаёт CSRFToken.
//
// # Dev-контур: issuer rewrite
//
// В docker-compose API обращается к Dex по внутреннему адресу
// http://dex:5556/dex (discovery, token exchange), а браузер пользователя
// достаёт Dex только через проброшенный host-порт http://localhost:55557.
// Чтобы redirect на авторизацию работал с хоста, LoginHandler переписывает
// префикс browser-facing auth URL по Config.BrowserIssuerRewrite
// (env GRANTOR_OIDC_PUBLIC_URL_REWRITE="http://dex:5556=http://localhost:55557",
// wiring в cmd/api). Token exchange остаётся server-side по внутреннему
// адресу, поэтому rewrite не влияет на проверку issuer в ID token.
// В production, где IdP доступен по единому URL, rewrite не задаётся.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// CSRFHeader — заголовок с CSRF token для мутирующих запросов.
const CSRFHeader = "X-Grantor-CSRF"

// defaultSessionTTL — срок жизни сессии, если Config.SessionTTL не задан.
const defaultSessionTTL = 12 * time.Hour

// stateCookieName — короткоживущая cookie, переносящая OAuth2 state и
// PKCE verifier между /auth/login и /auth/callback.
const stateCookieName = "grantor_oidc_state"

// stateTTL — срок жизни state cookie: время, за которое пользователь
// должен завершить авторизацию у IdP.
const stateTTL = 10 * time.Minute

// URLRewrite — замена префикса в browser-facing URL авторизации.
// Нужна только для dev-контура compose, где IdP доступен API по
// внутреннему адресу сети, а браузеру — по проброшенному порту хоста
// (см. package doc, раздел "Dev-контур: issuer rewrite"). Нулевое
// значение отключает rewrite.
type URLRewrite struct {
	// From — префикс внутреннего адреса IdP, например "http://dex:5556".
	From string
	// To — публичный префикс для браузера, например "http://localhost:55557".
	To string
}

// Apply возвращает u с заменённым префиксом From -> To; без совпадения
// префикса или при пустом From возвращает u без изменений.
func (rw URLRewrite) Apply(u string) string {
	if rw.From == "" || !strings.HasPrefix(u, rw.From) {
		return u
	}
	return rw.To + strings.TrimPrefix(u, rw.From)
}

// Config — конфигурация Authenticator.
type Config struct {
	// IssuerURL — базовый URL OIDC issuer; по нему выполняется discovery.
	IssuerURL string
	// ClientID — идентификатор OAuth2 client.
	ClientID string
	// ClientSecret — секрет OAuth2 client.
	ClientSecret string
	// RedirectURL — публичный URL callback, например
	// "http://localhost:58080/auth/callback".
	RedirectURL string
	// SessionSecret — секрет подписи session cookie и CSRF tokens;
	// обязателен, рекомендуется не меньше 32 байт.
	SessionSecret []byte
	// SessionTTL — срок жизни сессии; по умолчанию defaultSessionTTL (12h).
	SessionTTL time.Duration
	// SecureCookies включает флаг Secure у cookies (production за TLS).
	SecureCookies bool
	// AdminEmails — emails с ролью admin (без учёта регистра).
	AdminEmails []string
	// OperatorEmails — emails с ролью operator (без учёта регистра).
	OperatorEmails []string
	// ViewerEmails — emails с явно выданной ролью viewer (без учёта
	// регистра). Нужен, когда DefaultRole пуст: иначе роль viewer выдать
	// некому.
	ViewerEmails []string
	// AdminGroups/OperatorGroups/ViewerGroups — группы IdP, дающие роль
	// (без учёта регистра). Нужны там, где доступом управляют группами, а
	// не перечислением людей: в Authentik группы приходят claim-ом groups,
	// в том числе синхронизированные из Windows AD.
	//
	// Списки email при этом остаются и имеют приоритет: они адресуют
	// конкретного человека, тогда как группа описывает набор. Явное
	// назначение персоне должно побеждать её членство.
	AdminGroups    []string
	OperatorGroups []string
	ViewerGroups   []string
	// DefaultRole — роль аутентифицированного пользователя, не попавшего ни
	// в один из списков выше: RoleViewer (историческое поведение) либо ""
	// (deny-by-default: вход запрещается с 403 "no role assigned" — доступ
	// в grantor только по явному назначению; рекомендованный production-
	// режим). Другие значения отклоняются в New.
	DefaultRole Role
	// BrowserIssuerRewrite — замена префикса в browser-facing auth URL
	// для dev-контура; см. URLRewrite.
	BrowserIssuerRewrite URLRewrite
	// TokenAuth — опциональная аутентификация по Grantor service token/API key
	// (Authorization: Bearer). nil отключает token-auth: запросы аутентифи-
	// цируются только session cookie. Реализация живёт вне auth (api-слой +
	// internal/core/servicetoken), чтобы пакет auth не зависел от ядра.
	TokenAuth TokenAuthenticator
	// A failed observer must not extend API key authorization or prevent UI login.
	SessionObserver func(context.Context, Session) error
}

// TokenAuthenticator authenticates a Grantor service token or personal API key.
// AuthenticateToken возвращает сессию и ok=true при успешной
// проверке токена; при любой ошибке — ok=false (без различения причины, чтобы
// не давать оракул). Реализация предоставляется извне (см. Config.TokenAuth).
type TokenAuthenticator interface {
	AuthenticateToken(ctx context.Context, token string) (Session, bool)
}

// Authenticator держит OIDC provider, session codec и маппинг ролей;
// выдаёт HTTP handlers login flow и RBAC middleware.
type Authenticator struct {
	oauth     oauth2.Config
	verifier  *oidc.IDTokenVerifier
	codec     Codec
	ttl       time.Duration
	secure    bool
	rewrite   URLRewrite
	admins    map[string]bool
	operators map[string]bool
	viewers   map[string]bool
	// Группы держатся отдельными наборами: маппинг по группам применяется
	// после списков email и до DefaultRole.
	adminGroups    map[string]bool
	operatorGroups map[string]bool
	viewerGroups   map[string]bool
	// requestGroups — запрашивать ли scope groups. Включается только когда
	// группы реально настроены: лишний scope у IdP без групп приводит к
	// отказу в выдаче токена.
	requestGroups   bool
	defaultRole     Role
	tokenAuth       TokenAuthenticator
	issuer          string
	sessionObserver func(context.Context, Session) error
}

// New выполняет OIDC discovery по cfg.IssuerURL и возвращает готовый
// Authenticator. ctx ограничивает discovery-запрос.
func New(ctx context.Context, cfg Config) (*Authenticator, error) {
	if cfg.IssuerURL == "" {
		return nil, errors.New("auth: issuer URL is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("auth: client ID is required")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("auth: redirect URL is required")
	}
	// Роль по умолчанию — только viewer либо пусто (deny-by-default):
	// operator/admin «всем аутентифицированным» — заведомо опасная
	// конфигурация, отклоняем на старте.
	if cfg.DefaultRole != "" && cfg.DefaultRole != RoleViewer {
		return nil, fmt.Errorf("auth: unsupported default role %q (allowed: empty or %q)",
			cfg.DefaultRole, RoleViewer)
	}
	codec, err := NewCodec(cfg.SessionSecret)
	if err != nil {
		return nil, err
	}
	ttl := cfg.SessionTTL
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: discover OIDC provider: %w", err)
	}

	return &Authenticator{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes(cfg),
		},
		verifier:        provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		codec:           codec,
		ttl:             ttl,
		secure:          cfg.SecureCookies,
		rewrite:         cfg.BrowserIssuerRewrite,
		admins:          emailSet(cfg.AdminEmails),
		operators:       emailSet(cfg.OperatorEmails),
		viewers:         emailSet(cfg.ViewerEmails),
		adminGroups:     emailSet(cfg.AdminGroups),
		operatorGroups:  emailSet(cfg.OperatorGroups),
		viewerGroups:    emailSet(cfg.ViewerGroups),
		requestGroups:   len(cfg.AdminGroups)+len(cfg.OperatorGroups)+len(cfg.ViewerGroups) > 0,
		defaultRole:     cfg.DefaultRole,
		tokenAuth:       cfg.TokenAuth,
		issuer:          cfg.IssuerURL,
		sessionObserver: cfg.SessionObserver,
	}, nil
}

// CSRFToken возвращает CSRF token сессии; схема описана в package doc и
// у Codec.CSRFToken.
func (a *Authenticator) CSRFToken(s Session) string {
	return a.codec.CSRFToken(s)
}

// loginState — payload короткоживущей state cookie между login и callback.
type loginState struct {
	// State — anti-CSRF значение OAuth2 state.
	State string `json:"state"`
	// Verifier — PKCE code verifier для обмена authorization code.
	Verifier string `json:"verifier"`
	// ExpiresAt — истечение попытки login.
	ExpiresAt time.Time `json:"exp"`
}

// LoginHandler возвращает handler GET /auth/login: генерирует state и
// PKCE verifier, сохраняет их в короткоживущей подписанной cookie и
// переадресует браузер на страницу авторизации IdP с S256 challenge.
// Перед redirect к auth URL применяется BrowserIssuerRewrite (dev-контур).
func (a *Authenticator) LoginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, err := randomToken()
		if err != nil {
			slog.ErrorContext(r.Context(), "auth: generate state", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		verifier := oauth2.GenerateVerifier()

		payload, err := json.Marshal(loginState{
			State:     state,
			Verifier:  verifier,
			ExpiresAt: time.Now().Add(stateTTL),
		})
		if err != nil {
			slog.ErrorContext(r.Context(), "auth: marshal login state", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     stateCookieName,
			Value:    a.codec.sign(payload),
			Path:     "/auth",
			MaxAge:   int(stateTTL.Seconds()),
			HttpOnly: true,
			Secure:   a.secure,
			SameSite: http.SameSiteLaxMode,
		})

		authURL := a.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, a.rewrite.Apply(authURL), http.StatusFound)
	})
}

// CallbackHandler возвращает handler GET /auth/callback: проверяет state,
// обменивает authorization code с PKCE verifier, верифицирует ID token,
// извлекает email/sub, назначает роль по спискам AdminEmails/OperatorEmails/
// ViewerEmails либо DefaultRole (без учёта регистра; при пустом DefaultRole
// пользователь вне списков получает 403 "no role assigned" — deny-by-default),
// устанавливает session cookie и переадресует на "/".
//
// Если ID token содержит claim email_verified и он == false, вход
// отклоняется (403): доверять маппингу роли по неподтверждённому email
// нельзя. Отсутствие claim не блокирует вход — не все IdP его шлют (см.
// разбор claims в теле).
func (a *Authenticator) CallbackHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st, err := a.consumeLoginState(w, r)
		if err != nil {
			slog.WarnContext(r.Context(), "auth: invalid login state", "error", err)
			writeError(w, http.StatusBadRequest, "invalid login state")
			return
		}

		query := r.URL.Query()
		if errCode := query.Get("error"); errCode != "" {
			slog.WarnContext(r.Context(), "auth: IdP returned error",
				"error", errCode, "description", query.Get("error_description"))
			writeError(w, http.StatusUnauthorized, "authorization failed")
			return
		}
		if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(st.State)) != 1 {
			writeError(w, http.StatusBadRequest, "state mismatch")
			return
		}
		code := query.Get("code")
		if code == "" {
			writeError(w, http.StatusBadRequest, "missing authorization code")
			return
		}

		token, err := a.oauth.Exchange(r.Context(), code, oauth2.VerifierOption(st.Verifier))
		if err != nil {
			slog.ErrorContext(r.Context(), "auth: token exchange failed", "error", err)
			writeError(w, http.StatusBadGateway, "token exchange failed")
			return
		}
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok || rawIDToken == "" {
			writeError(w, http.StatusBadGateway, "no id_token in token response")
			return
		}
		idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			slog.WarnContext(r.Context(), "auth: ID token verification failed", "error", err)
			writeError(w, http.StatusUnauthorized, "invalid ID token")
			return
		}

		var claims struct {
			Email    string `json:"email"`
			Username string `json:"preferred_username"`
			// EmailVerified — указатель, чтобы отличить отсутствие claim
			// (nil) от явного false. Не все IdP шлют его; Dev-Dex шлёт
			// email_verified=true. См. проверку ниже.
			EmailVerified *bool `json:"email_verified"`
			// Groups — членство пользователя в группах IdP. Authentik шлёт
			// его при scope groups, в том числе для групп, синхронизированных
			// из Windows AD. Отсутствие claim не ошибка: маппинг по группам
			// может быть не настроен.
			Groups []string `json:"groups"`
		}
		if err := idToken.Claims(&claims); err != nil {
			slog.ErrorContext(r.Context(), "auth: parse ID token claims", "error", err)
			writeError(w, http.StatusBadGateway, "invalid ID token claims")
			return
		}
		if claims.Email == "" {
			writeError(w, http.StatusForbidden, "email claim is required")
			return
		}
		// email_verified: если IdP прислал claim и он == false, отказываем
		// (email не подтверждён — доверять маппингу роли по нему нельзя).
		// Отсутствие claim (nil) не блокирует вход: не все IdP его шлют, и
		// это сохраняет текущее поведение Dev-Dex и других IdP без claim.
		if !emailVerificationAllowed(claims.EmailVerified) {
			slog.WarnContext(r.Context(), "auth: email is not verified", "email", claims.Email)
			writeError(w, http.StatusForbidden, "email is not verified")
			return
		}

		role, ok := a.roleFor(claims.Email, claims.Groups)
		if !ok {
			// Deny-by-default: аутентификация в IdP прошла, но роль в
			// grantor не назначена — сессия не создаётся.
			slog.WarnContext(r.Context(), "auth: no role assigned, login denied",
				"subject", idToken.Subject, "email", claims.Email)
			writeError(w, http.StatusForbidden, "no role assigned")
			return
		}
		sess := Session{
			Issuer:          a.issuer,
			Username:        claims.Username,
			AuthenticatedAt: time.Now(),
			Subject:         idToken.Subject,
			Email:           claims.Email,
			Role:            role,
			ExpiresAt:       time.Now().Add(a.ttl),
		}
		if a.sessionObserver != nil {
			if err := a.sessionObserver(r.Context(), sess); err != nil {
				slog.ErrorContext(r.Context(), "auth: record API key owner", "error", err)
			}
		}
		SetCookie(w, a.codec.Encode(sess), a.ttl, a.secure)
		slog.InfoContext(r.Context(), "auth: user logged in",
			"subject", sess.Subject, "email", sess.Email, "role", sess.Role)
		http.Redirect(w, r, "/", http.StatusFound)
	})
}

// LoggedOutPath — экран «вы вышли»; UI по нему не начинает вход сам.
// Возврат на "/" немедленно проходил бы вход заново: сессия у IdP жива.
const LoggedOutPath = "/logged-out"

// LogoutHandler возвращает handler /auth/logout: удаляет session cookie и
// переадресует на LoggedOutPath. Logout локальный: RP-initiated завершил
// бы сессию во всех приложениях организации.
func (a *Authenticator) LogoutHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ClearCookie(w)
		http.Redirect(w, r, LoggedOutPath, http.StatusFound)
	})
}

// meResponse — тело ответа GET /auth/me.
type meResponse struct {
	Email string `json:"email"`
	Role  Role   `json:"role"`
	// CSRFToken — значение заголовка CSRF для мутирующих запросов UI.
	CSRFToken string `json:"csrf_token"`
	// CSRFHeader — имя заголовка, в котором UI обязан слать CSRFToken
	// (CSRFHeader, сейчас X-Grantor-CSRF). Отдаётся из бэкенда, чтобы UI
	// не хардкодил имя заголовка и оно не расходилось с сервером.
	CSRFHeader string `json:"csrf_header"`
}

// MeHandler возвращает handler GET /auth/me: JSON {email, role, csrf_token,
// csrf_header} текущей сессии для UI; 401 без валидной сессии. UI шлёт
// csrf_token в заголовке с именем csrf_header на каждом мутирующем запросе.
func (a *Authenticator) MeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := a.sessionFromRequest(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		writeJSON(w, http.StatusOK, meResponse{
			Email:      sess.Email,
			Role:       sess.Role,
			CSRFToken:  a.codec.CSRFToken(sess),
			CSRFHeader: CSRFHeader,
		})
	})
}

// ctxKey — приватный тип ключа context для Session.
type ctxKey struct{}

// serviceAuthKey — приватный маркер: сессия установлена по service-токену
// (Authorization: Bearer), а не по cookie. Такой запрос освобождается от
// CSRF-проверки в RequireRole.
type serviceAuthKey struct{}

// Middleware аутентифицирует запрос (service-токен, затем session cookie) и
// кладёт валидную Session в context запроса. Запросы без валидной аутентифи-
// кации проходят дальше без сессии: отказом управляет RequireRole на
// конкретных endpoints.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess, service, ok := a.resolveSession(r); ok {
			r = r.WithContext(contextWithSession(r.Context(), sess, service))
		}
		next.ServeHTTP(w, r)
	})
}

// contextWithSession кладёт сессию в context и, для token-аутентификации,
// маркер service-auth (снимает требование CSRF в RequireRole).
func contextWithSession(ctx context.Context, sess Session, service bool) context.Context {
	ctx = context.WithValue(ctx, ctxKey{}, sess)
	if service {
		ctx = context.WithValue(ctx, serviceAuthKey{}, true)
	}
	return ctx
}

// isServiceAuth сообщает, аутентифицирован ли запрос по service-токену.
func isServiceAuth(ctx context.Context) bool {
	v, _ := ctx.Value(serviceAuthKey{}).(bool)
	return v
}

// IsBearerAuth reports the authentication transport, independently of actor type.
func IsBearerAuth(ctx context.Context) bool {
	return isServiceAuth(ctx)
}

// IsTokenAuth is the transport guard for browser-only credential management.
func IsTokenAuth(ctx context.Context) bool {
	return isServiceAuth(ctx)
}

// SetSessionObserver wires owner persistence after the authenticator is created.
func (a *Authenticator) SetSessionObserver(observer func(context.Context, Session) error) {
	a.sessionObserver = observer
}

// RoleFor uses the same configured role policy as OIDC login.
func (a *Authenticator) RoleFor(email string, groups []string) (Role, bool) {
	return a.roleFor(email, groups)
}

// FromContext возвращает Session, положенную Middleware или RequireRole.
func FromContext(ctx context.Context) (Session, bool) {
	sess, ok := ctx.Value(ctxKey{}).(Session)
	return sess, ok
}

// RequireRole возвращает middleware, требующий аутентифицированную сессию
// с ролью не ниже required: 401 {"error":"unauthorized"} без сессии,
// 403 {"error":"forbidden"} при недостаточной роли. Для мутирующих методов
// (POST/PUT/PATCH/DELETE) сессии, аутентифицированной cookie, дополнительно
// требуется заголовок X-Grantor-CSRF с валидным CSRF token (см. CSRFToken);
// иначе 403. Сессия service-принципала (аутентификация по service-токену)
// освобождается от CSRF: cookie не участвует, cross-site риска нет.
func (a *Authenticator) RequireRole(required Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, ok := FromContext(r.Context())
			service := isServiceAuth(r.Context())
			if !ok {
				// Middleware отсутствует (или не установил сессию): аутентифи-
				// цируем напрямую и кладём результат в context для downstream.
				var svc bool
				sess, svc, ok = a.resolveSession(r)
				if !ok {
					writeError(w, http.StatusUnauthorized, "unauthorized")
					return
				}
				service = svc
				r = r.WithContext(contextWithSession(r.Context(), sess, service))
			}
			if !a.sessionIssuerAllowed(sess) {
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !sess.Role.Allows(required) {
				writeError(w, http.StatusForbidden, "forbidden")
				return
			}
			if isMutating(r.Method) && !service && !a.validCSRF(r, sess) {
				writeError(w, http.StatusForbidden, "invalid csrf token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveSession определяет сессию запроса и способ аутентификации. Сначала
// Any Authorization header selects bearer authentication, including malformed
// or unsupported schemes. Such a request never falls back to a cookie:
// невалидный токен —
// «не аутентифицирован». service=true помечает token-аутентификацию (снимает
// требование CSRF, см. RequireRole).
func (a *Authenticator) resolveSession(r *http.Request) (sess Session, service, ok bool) {
	if raw, has := bearerToken(r); has {
		if raw != "" && a.tokenAuth != nil {
			if s, valid := a.tokenAuth.AuthenticateToken(r.Context(), raw); valid {
				return s, true, true
			}
		}
		return Session{}, false, false
	}
	s, valid := a.cookieSession(r)
	if !valid {
		return Session{}, false, false
	}
	if s.Issuer == "" && a.issuer != "" {
		// Legacy signed cookies remain trusted for their original lifetime.
		// The observer must not extend their authorization on repeated requests.
		s.Issuer = a.issuer
		if a.sessionObserver != nil {
			if err := a.sessionObserver(r.Context(), s); err != nil {
				slog.ErrorContext(r.Context(), "auth: record legacy API key owner", "error", err)
			}
		}
	}
	return s, false, true
}

// Issuer-less cookies predate the namespace binding and remain valid only for
// their existing signed lifetime. A populated issuer must match this instance.
func (a *Authenticator) sessionIssuerAllowed(sess Session) bool {
	return sess.Issuer == "" || sess.Issuer == a.issuer
}

func (a *Authenticator) cookieSession(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, false
	}
	sess, err := a.codec.Decode(cookie.Value)
	if err != nil || !a.sessionIssuerAllowed(sess) {
		return Session{}, false
	}
	return sess, true
}

// sessionFromRequest достаёт сессию из context (после Middleware) или
// напрямую из cookie. Используется MeHandler (UI, только cookie).
func (a *Authenticator) sessionFromRequest(r *http.Request) (Session, bool) {
	// /auth/me is a browser endpoint. An explicit Authorization header must
	// not make an invalid API credential appear authenticated via a cookie.
	if raw, present := bearerToken(r); present {
		if raw != "" && isServiceAuth(r.Context()) {
			sess, ok := FromContext(r.Context())
			return sess, ok && a.sessionIssuerAllowed(sess)
		}
		return Session{}, false
	}
	if sess, ok := FromContext(r.Context()); ok {
		return sess, a.sessionIssuerAllowed(sess)
	}
	return a.cookieSession(r)
}

// bearerToken returns the valid bearer value and header presence independently.
// A present but malformed, empty, duplicated or unsupported header returns an
// empty token and present=true, so it cannot select browser-cookie fallback.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	var values []string
	present := false
	for name, headerValues := range r.Header {
		if strings.EqualFold(name, "Authorization") {
			present = true
			values = append(values, headerValues...)
		}
	}
	if !present {
		return "", false
	}
	if len(values) != 1 {
		return "", true
	}
	h := values[0]
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", true
	}
	token := h[len(prefix):]
	if strings.IndexFunc(token, func(r rune) bool {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', strings.ContainsRune("-._~+/=", r):
			return false
		default:
			return true
		}
	}) >= 0 {
		return "", true
	}
	return token, true
}

// consumeLoginState читает state cookie, сразу гасит её (state одноразовый)
// и проверяет подпись и срок действия.
func (a *Authenticator) consumeLoginState(w http.ResponseWriter, r *http.Request) (loginState, error) {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil {
		return loginState{}, fmt.Errorf("auth: read state cookie: %w", err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     "/auth",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	payload, err := a.codec.verify(cookie.Value)
	if err != nil {
		return loginState{}, err
	}
	var st loginState
	if err := json.Unmarshal(payload, &st); err != nil {
		return loginState{}, fmt.Errorf("%w: bad state payload", ErrInvalidToken)
	}
	if time.Now().After(st.ExpiresAt) {
		return loginState{}, ErrTokenExpired
	}
	return st, nil
}

// validCSRF сравнивает заголовок CSRFHeader с ожидаемым token constant-time.
func (a *Authenticator) validCSRF(r *http.Request, sess Session) bool {
	got := r.Header.Get(CSRFHeader)
	if got == "" {
		return false
	}
	want := a.codec.CSRFToken(sess)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// emailVerificationAllowed решает, допускать ли вход по claim
// email_verified из ID token: nil (claim отсутствует) — допускать (не все
// IdP шлют claim; поведение как раньше, Dev-Dex не ломается); явный false —
// отказ; явный true — допускать.
func emailVerificationAllowed(verified *bool) bool {
	return verified == nil || *verified
}

// roleFor возвращает роль пользователя по его адресу и группам IdP.
//
// Порядок разрешения:
//  1. списки email — они адресуют конкретного человека, поэтому явное
//     назначение персоне побеждает её членство в группе;
//  2. группы IdP — от старшей роли к младшей: человек в нескольких группах
//     получает наибольшую из них;
//  3. DefaultRole; при пустом DefaultRole роли нет (ok=false) — вход
//     запрещается (deny-by-default, доступ только по явному назначению).
func (a *Authenticator) roleFor(email string, groups []string) (role Role, ok bool) {
	e := strings.ToLower(strings.TrimSpace(email))
	switch {
	case a.admins[e]:
		return RoleAdmin, true
	case a.operators[e]:
		return RoleOperator, true
	case a.viewers[e]:
		return RoleViewer, true
	}
	switch {
	case anyGroup(a.adminGroups, groups):
		return RoleAdmin, true
	case anyGroup(a.operatorGroups, groups):
		return RoleOperator, true
	case anyGroup(a.viewerGroups, groups):
		return RoleViewer, true
	case a.defaultRole != "":
		return a.defaultRole, true
	default:
		return "", false
	}
}

// anyGroup сообщает, входит ли пользователь хотя бы в одну из групп набора.
// Сравнение без учёта регистра: имена групп в AD регистронезависимы, и
// требовать точного совпадения регистра значило бы плодить незаметные
// ошибки конфигурации.
func anyGroup(set map[string]bool, groups []string) bool {
	if len(set) == 0 {
		return false
	}
	for _, g := range groups {
		if set[strings.ToLower(strings.TrimSpace(g))] {
			return true
		}
	}
	return false
}

// scopes собирает запрашиваемые scopes. groups добавляется только когда
// маппинг по группам настроен: IdP без такого scope отказал бы в выдаче
// токена, и вход сломался бы у всех.
func scopes(cfg Config) []string {
	base := []string{oidc.ScopeOpenID, "profile", "email"}
	if len(cfg.AdminGroups)+len(cfg.OperatorGroups)+len(cfg.ViewerGroups) > 0 {
		base = append(base, "groups")
	}
	return base
}

// emailSet нормализует список emails в set: lowercase, без пустых значений.
func emailSet(emails []string) map[string]bool {
	s := make(map[string]bool, len(emails))
	for _, e := range emails {
		e = strings.ToLower(strings.TrimSpace(e))
		if e != "" {
			s[e] = true
		}
	}
	return s
}

// isMutating сообщает, меняет ли HTTP-метод состояние (требует CSRF token).
func isMutating(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// randomToken возвращает 32 криптослучайных байта в base64url.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// errorResponse — единый формат JSON-ошибок auth endpoints.
type errorResponse struct {
	Error string `json:"error"`
}

// writeError пишет JSON-ошибку {"error": msg} с заданным статусом.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

// writeJSON пишет JSON-ответ. Ошибка записи не возвращается: ответ уже
// начат, повлиять на него нельзя.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Error("auth: write response", "error", err)
	}
}
