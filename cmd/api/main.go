// Command grantor-api запускает HTTP API control plane.
//
// Этап 1a: REST API v1 (read-only инвентарь, создание connections,
// запуск discovery) за OIDC-аутентификацией с RBAC (internal/auth),
// health probes и metrics (docs/architecture.md, разделы 20, 21 и 27.7).
//
// # Окружение
//
//   - GRANTOR_DB_DSN — DSN metadata database; обязателен.
//   - GRANTOR_HTTP_ADDR — адрес HTTP-сервера; по умолчанию ":8080".
//   - GRANTOR_VAULT_ADDR/TOKEN/MOUNT — Vault; опционален: без него API
//     работает read-only, а создание connection с admin credential
//     отвечает 503.
//   - GRANTOR_VAULT_AUTH — режим аутентификации Vault: "" | "token"
//     (по умолчанию, статический GRANTOR_VAULT_TOKEN) | "kubernetes"
//     (login JWT'ом ServiceAccount в auth mount центрального Vault с
//     фоновым продлением client token; см. internal/providers/vault).
//   - GRANTOR_VAULT_K8S_AUTH_PATH — auth mount Kubernetes-аутентификации
//     (например, "kubernetes-test"); обязателен в режиме kubernetes.
//   - GRANTOR_VAULT_K8S_ROLE — имя роли auth mount; обязательна в режиме
//     kubernetes.
//   - GRANTOR_VAULT_K8S_JWT_PATH — файл JWT ServiceAccount; по умолчанию
//     /var/run/secrets/kubernetes.io/serviceaccount/token.
//   - GRANTOR_YOPASS_API_URL — server-side адрес Yopass API (например
//     http://yopass:1337); опционален: без него одноразовая выдача
//     credentials (POST /api/v1/accounts/{id}/share) отвечает 503.
//   - GRANTOR_YOPASS_PUBLIC_URL — браузерная база ссылок Yopass
//     (например http://localhost:58090); по умолчанию равна API URL.
//   - GRANTOR_OIDC_ISSUER_URL — OIDC issuer. Если пуст, аутентификация
//     отключена и все /api/*, /auth/* отвечают 503
//     "authentication is not configured"; живыми остаются только
//     /health/live, /health/ready и /metrics. Так процесс безопасен по
//     умолчанию: без IdP API не отдаёт данные анонимно.
//   - GRANTOR_OIDC_CLIENT_ID/CLIENT_SECRET/REDIRECT_URL — OAuth2 client.
//   - GRANTOR_SESSION_SECRET — секрет подписи сессий; обязателен при
//     включённом OIDC.
//   - GRANTOR_SECURE_COOKIES — bool; выставлять ли флаг Secure у session и
//     state cookies. По умолчанию false, чтобы dev-контур compose по http
//     не ломал вход. В production (за TLS) ОБЯЗАТЕЛЬНО выставить true.
//   - GRANTOR_OIDC_PUBLIC_URL_REWRITE — "from=to" rewrite browser-facing
//     auth URL для dev-контура compose (см. internal/auth).
//   - GRANTOR_RBAC_ADMIN_GROUPS/GRANTOR_RBAC_OPERATOR_GROUPS/
//     GRANTOR_RBAC_VIEWER_GROUPS — csv-списки групп IdP, дающих роль.
//     Группы приходят claim-ом groups (scope groups запрашивается только
//     когда хотя бы один список непуст). В Authentik сюда попадают и
//     группы, синхронизированные из Windows AD. Списки emails имеют
//     приоритет над группами: явное назначение персоне побеждает членство.
//   - GRANTOR_RBAC_ADMIN_EMAILS/GRANTOR_RBAC_OPERATOR_EMAILS/
//     GRANTOR_RBAC_VIEWER_EMAILS — csv-списки emails ролей
//     admin/operator/viewer (явное назначение).
//   - GRANTOR_RBAC_DEFAULT_ROLE — роль аутентифицированного пользователя вне
//     списков: "none" (по умолчанию; deny-by-default — вход без явно
//     назначенной роли отклоняется с 403 "no role assigned") либо "viewer"
//     (историческое поведение «все аутентифицированные — viewer»).
//     Deny-by-default выбран дефолтом сознательно: доступ в grantor — только
//     по явному назначению (email-списки сейчас, группы IdP — позже);
//     dev-контур compose выдаёт viewer явно через VIEWER_EMAILS.
//   - GRANTOR_ENDPOINT_ALLOWED_CIDRS — csv разрешённых CIDR endpoint
//     connection (SSRF allowlist); опционален, пусто = разрешено всё, кроме
//     жёстких блоков (cloud-metadata, loopback и т.п.).
//   - GRANTOR_ENDPOINT_ALLOWED_PORTS — csv разрешённых портов endpoint;
//     опционален, пусто = любой порт.
//   - GRANTOR_ENDPOINT_ALLOWED_DNS_SUFFIXES — csv разрешённых DNS-суффиксов
//     endpoint; опционален, пусто = любой host (после жёстких блоков).
//   - GRANTOR_AUDIT_LOG — bool; дублировать ли audit-события в structured
//     log stream stdout для экспорта в ELK/SIEM (ADR-0007). По умолчанию
//     true; источник истины остаётся таблица audit_events.
//   - GRANTOR_RATE_LIMIT — bool; включён ли общий token-bucket rate limiting
//     на login (per-IP), credential reveal/share (per-subject) и мутирующих
//     API (per-subject); счётчик общий между репликами в PostgreSQL
//     (ADR-0007, internal/ratelimit). По умолчанию true; false отключает
//     лимиты полностью.
//   - GRANTOR_REVEAL_SHARE_ALERT_THRESHOLD — int; порог детекции аномальной
//     частоты credential reveal/share на субъект в окне (разделы 24/25,
//     ADR-0011). При достижении порога эмитится audit
//     security.reveal_rate_anomaly (throttled: один сигнал на субъект за
//     окно). НЕ блокирует запрос (это делает rate limiting). По умолчанию 20;
//     <=0 отключает детекцию.
//   - GRANTOR_REVEAL_SHARE_ALERT_WINDOW — duration; окно счёта и троттлинга
//     детекции аномалии reveal/share. По умолчанию 1h.
//   - GRANTOR_SCOPE_ENFORCEMENT — режим scope policies operator (ADR-0007):
//     "enforce" (operator видит только connections своих окружений,
//     deny-by-default) или "disabled" (scope не применяется). По умолчанию
//     disabled, чтобы не ломать dev-контур compose; в production — enforce.
//   - GRANTOR_APPROVAL_REQUIRED — bool; включён ли approval workflow опасных
//     грантов (ADR-0010): опасный (dangerous) грант создаётся в
//     pending_approval и выполняется только после того, как admin явно его
//     подтвердит (approve). Это confirmation gate одного admin, не four-eyes:
//     подтвердить может тот же admin, что и запросил (self-approval — штатный
//     случай). По умолчанию false — как у GRANTOR_SCOPE_ENFORCEMENT: в
//     dev-контуре compose лишний ручной approve на каждый опасный грант мешает,
//     а безопасность dev не критична. Поскольку self-approval разрешён,
//     включённый gate не создаёт deadlock даже с единственным admin. В
//     production — true.
//   - GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD — int; порог массового отзыва
//     (расширение ADR-0010). Если одно применение access manifest отзывает
//     БОЛЬШЕ threshold bindings, все revoke-операции этого применения
//     создаются в pending_approval и не выполняются, пока admin явно их не
//     подтвердит (approve/approve-children) — защита от массового offboarding
//     по ошибке (fat-finger манифест). Работает НЕЗАВИСИМО от
//     GRANTOR_APPROVAL_REQUIRED: тот гейтит опасные привилегии (направление
//     «выдать больше прав»), этот — масштаб отзыва; достаточно выставить
//     threshold > 0. Одиночный revoke (DELETE /bindings/{id}) и применения не
//     выше порога под gate не попадают. По умолчанию 0 — gate выключен
//     (безопасно обратно совместимо, как и другие approval/scope флаги). В
//     production рекомендуется задать (например, 10).
//   - GRANTOR_ROTATION_CONFIRM_THRESHOLD — int; порог осознанного
//     подтверждения ротации ОБЩЕГО секрета принципала (ADR-0008: один пароль
//     на пару principal+environment). Если POST /principals/{id}/rotate
//     меняет пароль БОЛЬШЕ чем threshold аккаунтам, запрос обязан нести
//     {"confirm":true}, иначе — 409 с кодом rotation_requires_confirm и
//     числом затронутых аккаунтов. Тот же порог возвращается в контексте 409
//     shared_credential_requires_choice (ротация одного аккаунта на общем
//     секрете), чтобы UI показал подтверждение в том же диалоге. Это НЕ
//     approval-workflow: подтверждение — флаг того же запроса, второго
//     администратора он не ждёт (ротацию часто делают в инциденте, и
//     блокировать её ожиданием опаснее самой ротации). По умолчанию 2;
//     значение <= 0 выключает gate.
//
// # Service tokens
//
// Машинный доступ к API (ADR-0007, R10): запрос с заголовком
// Authorization: Bearer grt_... аутентифицируется как service-принципал с
// ролью operator (см. internal/api, internal/core/servicetoken). Выпуск/отзыв
// токенов — операция admin через API; scope policies применяются к
// service-принципалу так же, как к человеку-operator.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
	"github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/directoryimport"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/health"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/yopass"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
	"github.com/ArtefactoO/grantor/internal/serverutil"
)

const (
	// shutdownTimeout — предел graceful shutdown HTTP-сервера.
	shutdownTimeout = 10 * time.Second
	// oidcDiscoveryTimeout — сколько всего ждать успешного OIDC discovery
	// на старте: в compose Dex может подняться позже API.
	oidcDiscoveryTimeout = 60 * time.Second
	// oidcDiscoveryRetryDelay — пауза между попытками discovery.
	oidcDiscoveryRetryDelay = 2 * time.Second
	// defaultRevealAnomalyThreshold и defaultRevealAnomalyWindow — дефолты
	// детекции аномальной частоты credential reveal/share (разделы 24/25):
	// 20 выдач на субъект за час эмитят security.reveal_rate_anomaly. Порог
	// заметно ниже теоретического потолка reveal-лимитера, но выше типичной
	// операторской работы, чтобы ловить массовую эксфильтрацию, не блокируя.
	defaultRevealAnomalyThreshold = 20
	defaultRevealAnomalyWindow    = time.Hour
	// defaultRotationConfirmThreshold — дефолт порога подтверждения ротации
	// общего секрета принципала: ротация, меняющая пароль больше чем двум
	// аккаунтам, требует явного confirm. В отличие от approval-порогов дефолт
	// НЕ выключен: подтверждение здесь — флаг того же запроса, оно не ждёт
	// второго человека и потому ничего не блокирует, а цена молчаливой смены
	// общего пароля в нескольких системах сразу выше цены одного чекбокса.
	defaultRotationConfirmThreshold = 2
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("grantor-api: fatal", "error", err)
		os.Exit(1)
	}
}

// run собирает зависимости из окружения и держит HTTP-сервер до сигнала
// остановки или ошибки listen.
func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("GRANTOR_DB_DSN")
	if dsn == "" {
		return errors.New("GRANTOR_DB_DSN is required")
	}
	addr := serverutil.EnvOr("GRANTOR_HTTP_ADDR", ":8080")

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()
	checks := []health.Check{{Name: "postgres", Probe: pool.Ping}}

	// Vault опционален: без него создание connection с admin credential
	// отвечает 503, read-only endpoints работают. Краткая недоступность
	// зависимости роняет readiness, а не процесс (раздел 27.7).
	var vaultClient *vault.Client
	if vaultAddr := os.Getenv("GRANTOR_VAULT_ADDR"); vaultAddr != "" {
		vaultClient, err = vault.New(vault.Config{
			Address:     vaultAddr,
			Auth:        os.Getenv("GRANTOR_VAULT_AUTH"),
			Token:       os.Getenv("GRANTOR_VAULT_TOKEN"),
			Mount:       serverutil.EnvOr("GRANTOR_VAULT_MOUNT", vault.DefaultMount),
			K8sAuthPath: os.Getenv("GRANTOR_VAULT_K8S_AUTH_PATH"),
			K8sRole:     os.Getenv("GRANTOR_VAULT_K8S_ROLE"),
			K8sJWTPath:  os.Getenv("GRANTOR_VAULT_K8S_JWT_PATH"),
			Logger:      slog.Default().With("component", "vault-auth"),
		})
		if err != nil {
			return fmt.Errorf("create vault client: %w", err)
		}
		// Kubernetes-режим: начальный login и фоновое продление токена до
		// отмены сигнального ctx; token-режим — no-op.
		if err := vaultClient.StartAuth(ctx); err != nil {
			return fmt.Errorf("vault auth: %w", err)
		}
		checks = append(checks, health.Check{Name: "vault", Probe: vaultClient.Ping})
	} else {
		slog.Info("grantor-api: GRANTOR_VAULT_ADDR is empty; " +
			"connection creation with admin credential is unavailable")
	}

	// Yopass опционален: без него share-endpoint отвечает 503, остальной
	// API работает.
	var yopassClient *yopass.Client
	if yopassAPIURL := os.Getenv("GRANTOR_YOPASS_API_URL"); yopassAPIURL != "" {
		yopassClient, err = yopass.New(yopass.Config{
			APIURL:    yopassAPIURL,
			PublicURL: serverutil.EnvOr("GRANTOR_YOPASS_PUBLIC_URL", yopassAPIURL),
		})
		if err != nil {
			return fmt.Errorf("create yopass client: %w", err)
		}
	} else {
		slog.Info("grantor-api: GRANTOR_YOPASS_API_URL is empty; " +
			"one-time credential links are unavailable")
	}

	// Регистрация adapters — явно в main (как в worker): API использует
	// registry для валидации engine в POST /connections и генерации
	// credentials в POST /accounts.
	adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	adapter.Register(mongodb.Engine, func() adapter.Adapter { return mongodb.New() })
	adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.New() })
	adapter.Register(rabbitmq.Engine, func() adapter.Adapter { return rabbitmq.New() })
	adapter.Register(clickhouse.Engine, func() adapter.Adapter { return clickhouse.New() })
	adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.New() })
	adapter.Register(redis.Engine, func() adapter.Adapter { return redis.New() })

	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		return fmt.Errorf("create insert-only river dispatcher: %w", err)
	}

	// Scope policies (ограничение operator по окружениям) и service tokens
	// (машинный доступ к API), ADR-0007. Режим enforcement — из env
	// (default disabled для dev-контура).
	scopeEnforcement, err := policy.ParseEnforcementMode(os.Getenv("GRANTOR_SCOPE_ENFORCEMENT"))
	if err != nil {
		return fmt.Errorf("parse scope enforcement mode: %w", err)
	}
	policyStore := policy.NewStore()
	serviceTokenStore := servicetoken.NewStore()
	apiKeyStore := apikey.NewStore()
	var directoryProvider directory.Provider
	if os.Getenv("GRANTOR_OIDC_ISSUER_URL") != "" {
		directoryProvider, err = directory.FromEnv()
		if err != nil {
			return fmt.Errorf("grantor-api: identity directory: %w", err)
		}
	}
	identityProvider, _ := directoryProvider.(directory.APIIdentityProvider)
	apiKeyIdentity := api.NewAPIKeyIdentityManager(pool, apiKeyStore, identityProvider, api.DefaultAPIKeyIdentityFreshness)
	apiKeyIdentity.SetIssuer(os.Getenv("GRANTOR_OIDC_ISSUER_URL"))

	// Token-auth: запрос с Authorization: Bearer grt_... аутентифицируется
	// как service-принципал. Прокидывается в Authenticator (см. Middleware).
	tokenAuth := api.ChainTokenAuthenticators(api.NewServiceTokenAuth(pool, serviceTokenStore), api.NewPersonalKeyAuth(pool, apiKeyStore, os.Getenv("GRANTOR_OIDC_ISSUER_URL")))

	authn, err := newAuthenticator(ctx, tokenAuth, apiKeyIdentity.ObserveSession)
	if err != nil {
		return err
	}

	// SSRF-guard: allowlist проверки endpoint connection. Пустые env =
	// пустая политика (разрешено всё, кроме жёстких блоков).
	netPolicy, err := serverutil.EndpointPolicyFromEnv()
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/health/live", health.LiveHandler())
	mux.Handle("/health/ready", health.Handler(checks...))
	mux.Handle("/metrics", serverutil.MetricsHandler())

	if authn != nil {
		apiKeyIdentity.SetRoleResolver(authn.RoleFor)
		go apiKeyIdentity.Run(ctx, time.Minute)
		auditWriter := audit.NewWriter()
		if serverutil.EnvBool("GRANTOR_AUDIT_LOG", true) {
			auditWriter = auditWriter.WithLogger(slog.Default().With("component", "audit"))
		} else {
			slog.Info("grantor-api: GRANTOR_AUDIT_LOG is disabled; " +
				"audit events are not duplicated to stdout for ELK/SIEM export")
		}

		// Rate limiting: общий token-bucket в PostgreSQL. Флаг выключает его
		// целиком (limiter nil = лимиты не применяются). login/reveal/mutating
		// поверхности — см. internal/api/ratelimit.go.
		var limiter *ratelimit.Limiter
		rateLimits := api.DefaultRateLimitConfig()
		if serverutil.EnvBool("GRANTOR_RATE_LIMIT", true) {
			limiter = ratelimit.New(pool)
		} else {
			slog.Info("grantor-api: GRANTOR_RATE_LIMIT is disabled; " +
				"login, credential reveal/share and mutating API are not rate limited")
		}

		approvalRequired := serverutil.EnvBool("GRANTOR_APPROVAL_REQUIRED", false)
		if !approvalRequired {
			slog.Info("grantor-api: GRANTOR_APPROVAL_REQUIRED is disabled; " +
				"dangerous grants are dispatched without second-admin approval (enable in production)")
		}
		massRevokeThreshold := serverutil.EnvInt("GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD", 0)
		if massRevokeThreshold <= 0 {
			slog.Info("grantor-api: GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD is disabled; " +
				"mass revokes via manifest apply are dispatched without approval (set > 0 in production)")
		}
		rotationConfirmThreshold := serverutil.EnvInt("GRANTOR_ROTATION_CONFIRM_THRESHOLD", defaultRotationConfirmThreshold)
		if rotationConfirmThreshold <= 0 {
			slog.Info("grantor-api: GRANTOR_ROTATION_CONFIRM_THRESHOLD is disabled; " +
				"rotating a shared principal credential needs no explicit confirm regardless of scale")
		}

		// Детекция аномальной частоты credential reveal/share (разделы 24/25,
		// ADR-0011): per-subject окно в PostgreSQL, честно между репликами. Не
		// блокирует запрос — сигнал уходит в audit security.reveal_rate_anomaly.
		anomalyWindow := ratelimit.AnomalyWindow{
			Threshold: serverutil.EnvInt("GRANTOR_REVEAL_SHARE_ALERT_THRESHOLD", defaultRevealAnomalyThreshold),
			Window:    serverutil.EnvDuration("GRANTOR_REVEAL_SHARE_ALERT_WINDOW", defaultRevealAnomalyWindow),
		}
		var anomalyDetector *ratelimit.AnomalyDetector
		if anomalyWindow.Enabled() {
			anomalyDetector = ratelimit.NewAnomalyDetector(pool)
		} else {
			slog.Info("grantor-api: reveal/share anomaly detection is disabled " +
				"(GRANTOR_REVEAL_SHARE_ALERT_THRESHOLD <= 0)")
		}

		// Каталог для заведения принципалов (Authentik/AD). Пустой
		// GRANTOR_IDP_MODE = каталог не подключён: сервис остаётся nil, и
		// endpoints импорта отвечают 501, не мешая работе без каталога.
		var directoryService *directoryimport.Service
		if directoryProvider != nil {
			directoryService = directoryimport.New(pool, directoryProvider, directory.ProviderNameFromEnv())
			slog.Info("grantor-api: identity directory configured",
				"import_enabled", directoryService.Enabled())
		}

		server, err := api.New(api.Config{
			Pool:                pool,
			Connections:         connections.NewStore(),
			Inventory:           inventory.NewStore(),
			Operations:          operations.NewStore(),
			Audit:               auditWriter,
			Vault:               vaultClient,
			Credentials:         credentials.NewService(vaultClient, yopassClient),
			Directory:           directoryService,
			Dispatcher:          dispatcher,
			Auth:                authn,
			NetPolicy:           netPolicy,
			RateLimiter:         limiter,
			RateLimits:          rateLimits,
			AnomalyDetector:     anomalyDetector,
			AnomalyWindow:       anomalyWindow,
			Policy:              policyStore,
			ScopeEnforcement:    scopeEnforcement,
			ServiceTokens:       serviceTokenStore,
			APIKeys:             apiKeyStore,
			APIKeyIdentity:      apiKeyIdentity,
			ApprovalRequired:    approvalRequired,
			MassRevokeThreshold: massRevokeThreshold,

			RotationConfirmThreshold: rotationConfirmThreshold,
		})
		if err != nil {
			return fmt.Errorf("create api server: %w", err)
		}

		apiMux := http.NewServeMux()
		server.Routes(apiMux)
		// LimitMutating списывает токен только на мутирующих методах, поэтому
		// GET list/get не тратят токены и не лимитируются. Middleware внутри
		// Authenticator.Middleware: session subject уже в context.
		mux.Handle("/api/", authn.Middleware(server.LimitMutating(apiMux)))
		// login лимитируется per-IP отдельной обёрткой (идёт мимо api.Server).
		mux.Handle("GET /auth/login", api.LimitLoginHandler(limiter, rateLimits.Login, authn.LoginHandler()))
		mux.Handle("GET /auth/callback", authn.CallbackHandler())
		mux.Handle("/auth/logout", authn.LogoutHandler())
		mux.Handle("GET /auth/me", authn.MeHandler())
	} else {
		// OIDC не настроен: весь API недоступен, кроме health/metrics.
		// 503, а не 200 без auth: данные не должны быть доступны анонимно
		// из-за незаполненного окружения.
		unavailable := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"authentication is not configured"}` + "\n"))
		})
		mux.Handle("/api/", unavailable)
		mux.Handle("/auth/", unavailable)
	}

	srv := serverutil.NewHTTPServer(addr, mux)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	slog.Info("grantor-api: listening", "addr", addr, "auth_enabled", authn != nil)

	select {
	case <-ctx.Done():
		slog.Info("grantor-api: shutdown signal received")
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	slog.Info("grantor-api: stopped")
	return nil
}

// newAuthenticator собирает Authenticator из окружения. Пустой
// GRANTOR_OIDC_ISSUER_URL — не ошибка: возвращается nil, аутентификация
// отключена (см. package doc). Discovery повторяется до
// oidcDiscoveryTimeout, потому что IdP (Dex в compose) может стартовать
// позже API. tokenAuth включает аутентификацию по service-токену
// (Authorization: Bearer) дополнительно к session cookie.
func newAuthenticator(ctx context.Context, tokenAuth auth.TokenAuthenticator, observers ...func(context.Context, auth.Session) error) (*auth.Authenticator, error) {
	issuer := os.Getenv("GRANTOR_OIDC_ISSUER_URL")
	if issuer == "" {
		slog.Warn("grantor-api: GRANTOR_OIDC_ISSUER_URL is empty; " +
			"authentication is disabled and all API endpoints respond 503")
		return nil, nil
	}
	secret := os.Getenv("GRANTOR_SESSION_SECRET")
	if secret == "" {
		return nil, errors.New("GRANTOR_SESSION_SECRET is required when GRANTOR_OIDC_ISSUER_URL is set")
	}

	cfg := auth.Config{
		IssuerURL:      issuer,
		ClientID:       os.Getenv("GRANTOR_OIDC_CLIENT_ID"),
		ClientSecret:   os.Getenv("GRANTOR_OIDC_CLIENT_SECRET"),
		RedirectURL:    os.Getenv("GRANTOR_OIDC_REDIRECT_URL"),
		SessionSecret:  []byte(secret),
		SecureCookies:  serverutil.EnvBool("GRANTOR_SECURE_COOKIES", false),
		AdminEmails:    serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_ADMIN_EMAILS")),
		OperatorEmails: serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_OPERATOR_EMAILS")),
		ViewerEmails:   serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_VIEWER_EMAILS")),
		AdminGroups:    serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_ADMIN_GROUPS")),
		OperatorGroups: serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_OPERATOR_GROUPS")),
		ViewerGroups:   serverutil.SplitCSV(os.Getenv("GRANTOR_RBAC_VIEWER_GROUPS")),
		TokenAuth:      tokenAuth,
	}
	if len(observers) != 0 {
		cfg.SessionObserver = observers[0]
	}
	switch mode := strings.TrimSpace(os.Getenv("GRANTOR_RBAC_DEFAULT_ROLE")); mode {
	case "", "none":
		// Deny-by-default: роль только по явному назначению.
		cfg.DefaultRole = ""
		slog.Info("grantor-api: GRANTOR_RBAC_DEFAULT_ROLE is none; " +
			"authenticated users without an assigned role are denied (403 no role assigned)")
	case "viewer":
		cfg.DefaultRole = auth.RoleViewer
	default:
		return nil, fmt.Errorf("unknown GRANTOR_RBAC_DEFAULT_ROLE %q (supported: \"none\", \"viewer\")", mode)
	}
	if !cfg.SecureCookies {
		slog.Warn("grantor-api: GRANTOR_SECURE_COOKIES is not enabled; " +
			"session cookies are sent without the Secure flag (set true in production behind TLS)")
	}
	if rw := os.Getenv("GRANTOR_OIDC_PUBLIC_URL_REWRITE"); rw != "" {
		from, to, ok := strings.Cut(rw, "=")
		if !ok || from == "" || to == "" {
			return nil, fmt.Errorf("GRANTOR_OIDC_PUBLIC_URL_REWRITE must be \"from=to\", got %q", rw)
		}
		cfg.BrowserIssuerRewrite = auth.URLRewrite{From: from, To: to}
	}

	deadline := time.Now().Add(oidcDiscoveryTimeout)
	for {
		authn, err := auth.New(ctx, cfg)
		if err == nil {
			return authn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("configure OIDC authenticator: %w", err)
		}
		slog.Warn("grantor-api: OIDC discovery failed; retrying", "error", err)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("configure OIDC authenticator: %w", ctx.Err())
		case <-time.After(oidcDiscoveryRetryDelay):
		}
	}
}
