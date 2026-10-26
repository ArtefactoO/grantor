// Command grantor-worker выполняет discovery, reconciliation и mutating
// operations через engine adapters.
//
// Jobs берутся из очереди River и исполняются MainExecutor (сейчас —
// connection.discover через зарегистрированные adapters); health probes
// и metrics — по разделу 27.7 архитектуры. Параллельно River работает
// планировщик обслуживания (internal/core/maintenance): retention/GC
// устаревшего состояния и TTL enforcement bindings, singleton между
// репликами через advisory lock.
//
// # Окружение
//
//   - GRANTOR_AUDIT_LOG — bool; дублировать ли audit-события в structured
//     log stream stdout для экспорта в ELK/SIEM (ADR-0007). По умолчанию
//     true; источник истины остаётся таблица audit_events.
//
//   - GRANTOR_VAULT_AUTH — режим аутентификации Vault: "" | "token"
//     (по умолчанию, статический GRANTOR_VAULT_TOKEN) | "kubernetes"
//     (login JWT'ом ServiceAccount в auth mount центрального Vault с
//     фоновым продлением client token; см. internal/providers/vault).
//
//   - GRANTOR_VAULT_K8S_AUTH_PATH — auth mount Kubernetes-аутентификации
//     (например, "kubernetes-test"); обязателен в режиме kubernetes.
//
//   - GRANTOR_VAULT_K8S_ROLE — имя роли auth mount; обязательна в режиме
//     kubernetes.
//
//   - GRANTOR_VAULT_K8S_JWT_PATH — файл JWT ServiceAccount; по умолчанию
//     /var/run/secrets/kubernetes.io/serviceaccount/token.
//
//   - GRANTOR_CONNECTOR_LISTEN — адрес mTLS-listener встроенного connector
//     gateway (этап 2, ADR-0002/ADR-0006): worker принимает исходящие
//     соединения execution connectors и маршрутизирует операции подключений
//     с execution_mode='connector' через них. Пусто (по умолчанию) = gateway
//     выключен; операция на connector-подключении тогда падает с ошибкой
//     "connector gateway is not configured". При включении обязательны
//     TLS/подпись из переменных GRANTOR_CONNECTOR_GATEWAY_TLS_CERT /
//     _TLS_KEY / _CLIENT_CA / _SIGN_KEY (+ опциональный _KEY_ID) — те же,
//     что у standalone cmd/connector-gateway (общий загрузчик
//     internal/connector/gateway). Durable-дедупликация заданий живёт в
//     таблице connector_job_dedup metadata DB.
//
//   - GRANTOR_MAINTENANCE — bool; включён ли планировщик обслуживания
//     (retention/GC + TTL enforcement bindings). По умолчанию true.
//
//   - GRANTOR_MAINTENANCE_INTERVAL — duration; период прогонов
//     обслуживания ("1h", "30m"). По умолчанию 1h.
//
//   - GRANTOR_CREDENTIAL_CHECK_INTERVAL — duration; период сверки версий
//     credential с Vault (internal/core/credentialcheck). 0 или не задан —
//     сверка выключена, и пароли, изменённые мимо grantor, не выявляются.
//
//   - GRANTOR_CREDENTIAL_CHECK_MAX_PATHS — int; предел обращений к Vault за
//     один прогон сверки. 0 — без ограничения.
//
//   - GRANTOR_DISCOVERY_INTERVAL — duration; период авто-rediscovery
//     подключений (internal/core/rediscovery): connections в статусах
//     active/degraded, чей снимок (last_discovery_at) старше интервала,
//     получают операцию connection.discover — ту же, что кнопка
//     «Синхронизировать» в UI, с общим idempotency key минутного окна,
//     поэтому ручной и автоматический синк не дублируются. Singleton
//     между репликами — advisory lock, как у maintenance. По умолчанию
//     0 = выключено; рекомендуемое значение "1h".
//
//   - GRANTOR_WEBHOOK_URL — URL generic webhook-уведомлений (JSON POST):
//     операции в pending_approval и падения (failed/partial). Пусто =
//     выключено. GRANTOR_WEBHOOK_INTERVAL — период опроса (по умолчанию
//     1m), GRANTOR_WEBHOOK_TIMEOUT — HTTP timeout отправки (10s).
//     Уведомления best-effort: события даунтайма worker'а не досылаются.
//
//   - GRANTOR_ENDPOINT_ALLOWED_CIDRS / GRANTOR_ENDPOINT_ALLOWED_PORTS /
//     GRANTOR_ENDPOINT_ALLOWED_DNS_SUFFIXES — тот же endpoint allowlist, что
//     использует API. Worker применяет его при каждом direct dial; connector-
//     подключения исполняются удалённым connector и этим dialer не затронуты.
//
//   - GRANTOR_ADMIN_CREDENTIAL_MAX_AGE — duration; порог старения admin
//     credential подключения (раздел 17.3, R12). Активные подключения, чей
//     admin credential старше порога, отмечаются security finding
//     (audit security.admin_credential_aged + метрика
//     grantor_connection_admin_credential_age_seconds). Эвалуация — в
//     планировщике обслуживания. По умолчанию 0 = выключено (политика
//     возраста org-специфична; до её установки finding не эмитим), например
//     "2160h" (~90 суток).
//
//   - GRANTOR_CONNECTOR_CERT_WARNING — duration; за сколько предупреждать об
//     истечении клиентского сертификата connector'а (finding
//     security.connector_certificate_expiring). 0 или не задан — проверка
//     выключена. Истечение обрывает mTLS бесповоротно, поэтому предупреждение
//     — единственный способ узнать о нём заранее.
//
//   - GRANTOR_IDP_MODE — режим поллинга identity directory для offboarding-
//     детекции (раздел 31, R1; ADR-0012): "" (по умолчанию) = поллинг
//     выключен; "ldap" = периодическая сверка не удалённых human-принципалов
//     с LDAP-каталогом в планировщике обслуживания (покрывает ванильную
//     AD напрямую и Authentik через его LDAP outpost); "authentik" = та же
//     сверка через REST API Authentik, без outpost'а; "static" =
//     mock-провайдер без каталога для dev-контура/стендов (статусы из
//     GRANTOR_IDP_STATIC_*). Успешный poll обновляет отдельное зеркало
//     external identity (active|disabled|deleted; отсутствие = deleted).
//     Локальный active principal при внешнем disabled/deleted помечается
//     disabled (audit principal.disabled, source: idp_poll); обратный
//     внешний переход в active не включает его автоматически. Accounts/
//     bindings НЕ отзываются автоматически. Finding security.offboarding_incomplete
//     (disabled-принципал с ещё активными accounts/bindings) эвалуируется
//     каждым прогоном обслуживания независимо от режима.
//
//   - GRANTOR_IDP_STATIC_DISABLED, GRANTOR_IDP_STATIC_MISSING — csv-списки
//     external_subject для режима static: первые считаются выключенными в
//     «каталоге», вторые — отсутствующими (missing приоритетнее при
//     пересечении); все прочие — активны. Только для dev/стендов.
//
//   - GRANTOR_IDP_PROVIDER — значение principals.external_provider,
//     принципалы которого сверяются с каталогом. По умолчанию пусто = все
//     не удалённые human-принципалы с непустым external_subject.
//
//   - GRANTOR_IDP_MISSING_IS_DISABLED — bool; считать ли отсутствие
//     субъекта в каталоге сигналом локального offboarding. Внешнее зеркало
//     всё равно получает deleted; при false локальный principal не
//     выключается. По умолчанию true.
//
//   - GRANTOR_IDP_LDAP_URL — адрес каталога, ldap:// или ldaps://.
//     Обязателен при GRANTOR_IDP_MODE=ldap.
//
//   - GRANTOR_IDP_LDAP_BIND_DN, GRANTOR_IDP_LDAP_BIND_PASSWORD — сервисная
//     учётка bind. Пустой DN = anonymous bind. Пароль не логируется ни в
//     одном представлении (internal/secret).
//
//   - GRANTOR_IDP_LDAP_BASE_DN — база поиска субъектов. Обязательна при
//     GRANTOR_IDP_MODE=ldap.
//
//   - GRANTOR_IDP_LDAP_USER_FILTER — шаблон фильтра поиска субъекта с одним
//     %s (подставляется экранированный external_subject принципала). По
//     умолчанию "(mail=%s)".
//
//   - GRANTOR_IDP_LDAP_DISABLED_FILTER — фильтр, которому удовлетворяют
//     заблокированные записи каталога, например AD:
//     "(userAccountControl:1.2.840.113556.1.4.803:=2)". По умолчанию пусто =
//     детекция только по отсутствию записи.
//
//   - GRANTOR_IDP_LDAP_CA_FILE — путь к PEM-бандлу доверенных CA для ldaps.
//     По умолчанию пусто = системные корни.
//
//   - GRANTOR_IDP_AUTHENTIK_URL — корень инсталляции Authentik, например
//     "https://atk.example.com". Обязателен при GRANTOR_IDP_MODE=authentik.
//
//   - GRANTOR_IDP_AUTHENTIK_TOKEN — API-токен Authentik; достаточно прав на
//     чтение пользователей. Обязателен при GRANTOR_IDP_MODE=authentik, не
//     логируется ни в одном представлении (internal/secret).
//
//   - GRANTOR_IDP_AUTHENTIK_GROUP — имя группы Authentik, которой
//     ограничивается ПЕРЕЧИСЛЕНИЕ каталога при заведении принципалов. На
//     сверку статусов не влияет: исключение человека из группы не означает
//     его исчезновения из каталога. По умолчанию пусто = весь каталог.
//
//   - GRANTOR_IDP_AUTHENTIK_CA_FILE — путь к PEM-бандлу доверенных CA.
//     По умолчанию пусто = системные корни.
//
//     Субъектом в режиме authentik служит username, поэтому OIDC-провайдер
//     той же инсталляции должен отдавать claim sub в режиме user_username:
//     иначе вошедший человек не сойдётся с собственной записью каталога.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/adapters/clickhouse"
	"github.com/ArtefactoO/grantor/internal/adapters/kafka"
	"github.com/ArtefactoO/grantor/internal/adapters/mongodb"
	"github.com/ArtefactoO/grantor/internal/adapters/mysql"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
	"github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
	"github.com/ArtefactoO/grantor/internal/core/credentialcheck"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/maintenance"
	"github.com/ArtefactoO/grantor/internal/core/notify"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rediscovery"
	"github.com/ArtefactoO/grantor/internal/directory"
	"github.com/ArtefactoO/grantor/internal/health"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/netguard"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/providers/webhook"
	"github.com/ArtefactoO/grantor/internal/serverutil"
)

const (
	// riverStopTimeout — предел graceful stop River: ждём завершения
	// активных jobs (раздел 27.7 архитектуры).
	riverStopTimeout = 30 * time.Second
	// httpShutdownTimeout — предел graceful shutdown HTTP-сервера.
	httpShutdownTimeout = 10 * time.Second
	// maintenanceStopTimeout — предел ожидания завершения планировщика
	// обслуживания при shutdown.
	maintenanceStopTimeout = 10 * time.Second
	// workerCount — максимум одновременных jobs River.
	workerCount = 4
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("grantor-worker: fatal", "error", err)
		os.Exit(1)
	}
}

// run запускает River-диспетчер и HTTP-сервер probes/metrics, держит их
// до сигнала остановки и останавливает в порядке: сначала River (ждём
// активные jobs), затем HTTP.

// connectorSessionObserver сохраняет наблюдения gateway о connector'ах.
//
// Запись идёт вне сессии агента: сбой metadata database не должен рвать
// установленное соединение — наблюдение вторично по отношению к работе.
type connectorSessionObserver struct {
	ctx   context.Context
	store *connectorstate.Store
}

func newConnectorSessionObserver(ctx context.Context, store *connectorstate.Store) *connectorSessionObserver {
	return &connectorSessionObserver{ctx: ctx, store: store}
}

func (o *connectorSessionObserver) ObserveSession(state gateway.SessionState) {
	capabilities := make([]string, 0, len(state.Capabilities))
	for _, c := range state.Capabilities {
		capabilities = append(capabilities, string(c))
	}
	err := o.store.Observe(o.ctx, connectorstate.Session{
		ConnectorID:         state.ConnectorID,
		ConnectedAt:         state.ConnectedAt,
		LastSeenAt:          state.LastSeenAt,
		CertificateNotAfter: state.CertificateNotAfter,
		Capabilities:        capabilities,
		ProtocolVersion:     state.ProtocolVersion,
		Deployment:          state.Deployment,
	})
	if err != nil {
		slog.Warn("grantor-worker: store connector session failed",
			"connector_id", state.ConnectorID, "error", err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	dsn := os.Getenv("GRANTOR_DB_DSN")
	if dsn == "" {
		return errors.New("GRANTOR_DB_DSN is required")
	}
	addr := serverutil.EnvOr("GRANTOR_WORKER_HTTP_ADDR", ":8081")
	netPolicy, err := serverutil.EndpointPolicyFromEnv()
	if err != nil {
		return err
	}
	guardedDialer := netguard.NewGuardedDialer(netPolicy, nil, adapterutil.DefaultDialTimeout)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("parse postgres dsn: %w", err)
	}
	// Executor открывает собственную транзакцию поверх транзакции job
	// operationWorker — активный job удерживает до двух соединений.
	// Пул меньше 2*workerCount + запас на служебные запросы River и
	// readiness probe рискует deadlock-ом на исчерпании пула, поэтому
	// поднимаем нижнюю границу (большее значение из DSN сохраняется).
	if minConns := int32(2*workerCount + 4); poolCfg.MaxConns < minConns {
		poolCfg.MaxConns = minConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("create postgres pool: %w", err)
	}
	defer pool.Close()

	// Регистрация adapters — явно в main, а не в init пакетов adapters:
	// состав engines этого worker виден в одном месте.
	adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(mongodb.Engine, func() adapter.Adapter { return mongodb.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(mysql.Engine, func() adapter.Adapter { return mysql.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(rabbitmq.Engine, func() adapter.Adapter { return rabbitmq.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(clickhouse.Engine, func() adapter.Adapter { return clickhouse.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(kafka.Engine, func() adapter.Adapter { return kafka.NewWithDialer(guardedDialer.DialContext) })
	adapter.Register(redis.Engine, func() adapter.Adapter { return redis.NewWithDialer(guardedDialer.DialContext) })

	// Vault опционален: без GRANTOR_VAULT_ADDR discovery работает только
	// для connections с пустым vault_admin_path, а мутации credentials
	// (account.create, credential.rotate) возвращают понятную ошибку.
	// vaultClient остаётся конкретным типом: он нужен и как VaultReader
	// discovery, и целиком для credentials.Service; nil-указатель в
	// интерфейс VaultReader не заворачивается сознательно.
	var vaultReader jobs.VaultReader
	var vaultClient *vault.Client
	if vaultAddr := os.Getenv("GRANTOR_VAULT_ADDR"); vaultAddr != "" {
		vaultClient, err = vault.New(vault.Config{
			Address:     vaultAddr,
			Auth:        os.Getenv("GRANTOR_VAULT_AUTH"),
			Token:       os.Getenv("GRANTOR_VAULT_TOKEN"),
			Mount:       os.Getenv("GRANTOR_VAULT_MOUNT"),
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
		vaultReader = vaultClient
	} else {
		slog.Info("grantor-worker: GRANTOR_VAULT_ADDR is empty; " +
			"discovery is available only for connections without vault admin path")
	}

	// Поллинг identity directory (offboarding-детекция, ADR-0012).
	// Провайдер собирается и валидируется на старте: ошибка конфигурации
	// (включая неизвестный режим) роняет worker сразу, а не первый прогон.
	dirProvider, err := directory.FromEnv()
	if err != nil {
		return err
	}

	auditWriter := audit.NewWriter()
	if serverutil.EnvBool("GRANTOR_AUDIT_LOG", true) {
		auditWriter = auditWriter.WithLogger(slog.Default().With("component", "audit"))
	} else {
		slog.Info("grantor-worker: GRANTOR_AUDIT_LOG is disabled; " +
			"audit events are not duplicated to stdout for ELK/SIEM export")
	}

	// Yopass worker не нужен: одноразовая выдача ссылок живёт в API.
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connections.NewStore(),
		Inventory:   inventory.NewStore(),
		Audit:       auditWriter,
		Vault:       vaultReader,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{
		Credentials: credentials.NewService(vaultClient, nil),
	})

	// Встроенный connector gateway (этапы 2-3): GRANTOR_CONNECTOR_LISTEN
	// включает mTLS-listener, через который операции подключений с
	// execution_mode='connector' — discovery и все мутирующие виды —
	// исполняются execution connector'ами (lease/heartbeat и параллельная
	// выдача — см. internal/connector/gateway).
	connectorStates := connectorstate.NewStore(pool)

	// Дедупликация заданий — durable, в таблице connector_job_dedup того же
	// metadata DB. Пустой адрес = gateway выключен; connector-операции тогда
	// падают с типизированной ошибкой (см. internal/jobs).
	var connectorGW *gateway.Server
	var connectorLn net.Listener
	if listen := os.Getenv("GRANTOR_CONNECTOR_LISTEN"); listen != "" {
		// Наблюдения о connector'ах уходят в metadata database: иначе о
		// состоянии агента и сроке его сертификата нельзя узнать снаружи.
		connectorGW, err = gateway.NewServerFromEnv(
			slog.Default().With("component", "connector-gateway"),
			connectorjobs.NewStore(pool, 0),
			newConnectorSessionObserver(ctx, connectorStates),
		)
		if err != nil {
			return fmt.Errorf("create connector gateway: %w", err)
		}
		connectorLn, err = net.Listen("tcp", listen)
		if err != nil {
			return fmt.Errorf("listen connector gateway on %s: %w", listen, err)
		}
		go func() {
			if err := connectorGW.Serve(connectorLn); err != nil {
				slog.Error("grantor-worker: connector gateway serve failed", "error", err)
			}
		}()
		executor.WithConnector(jobs.ConnectorDeps{Dispatcher: connectorGW})
		slog.Info("grantor-worker: connector gateway listening", "listen", listen)
	} else {
		slog.Info("grantor-worker: GRANTOR_CONNECTOR_LISTEN is empty; connector gateway is disabled " +
			"(operations on connector-mode connections will fail until it is configured)")
	}

	dispatcher, err := jobs.New(pool, operations.NewStore(), executor, jobs.Config{WorkerCount: workerCount})
	if err != nil {
		return fmt.Errorf("create river dispatcher: %w", err)
	}

	// Start получает фоновый контекст: отмена сигнального ctx не должна
	// жёстко обрывать выполняющиеся jobs — мягкую остановку с ожиданием
	// делает Stop ниже (тот же паттерн, что в river_integration_test).
	if err := dispatcher.Start(context.Background()); err != nil {
		return fmt.Errorf("start river dispatcher: %w", err)
	}
	slog.Info("grantor-worker: river dispatcher started")

	// Планировщик обслуживания: retention/GC устаревшего состояния и TTL
	// enforcement bindings (internal/core/maintenance). Singleton между
	// репликами обеспечивает сам Runner через advisory lock. Отдельный
	// maintCtx (не сигнальный ctx) позволяет остановить планировщик в
	// нужный момент shutdown, не завися от пути завершения run.
	var maintCancel context.CancelFunc
	var maintDone chan struct{}
	if serverutil.EnvBool("GRANTOR_MAINTENANCE", true) {
		maintCfg := maintenance.Config{
			Interval:                    serverutil.EnvDuration("GRANTOR_MAINTENANCE_INTERVAL", 0),
			AdminCredentialMaxAge:       serverutil.EnvDuration("GRANTOR_ADMIN_CREDENTIAL_MAX_AGE", 0),
			ConnectorCertificateWarning: serverutil.EnvDuration("GRANTOR_CONNECTOR_CERT_WARNING", 0),
		}
		if maintCfg.AdminCredentialMaxAge <= 0 {
			slog.Info("grantor-worker: GRANTOR_ADMIN_CREDENTIAL_MAX_AGE is not set; " +
				"admin credential aging findings are disabled")
		}
		// TTL enforcement обязан реально отзывать доступ, а не только
		// помечать desired=absent: без revoker право остаётся на целевой
		// системе после истечения срока.
		runner := maintenance.New(pool, maintCfg).WithAudit(auditWriter).
			WithRevoke(jobs.NewExpiryRevoker(dispatcher, maintenance.ActorType, maintenance.ActorID)).
			// Финальная фаза offboarding: по истечении purge_after ставятся
			// account.delete, зачищаются общие секреты и принципал становится
			// deleted. Без Vault credentials.Service отвечает
			// ErrVaultNotConfigured — шаг трактует это как «секретов нет».
			WithPurge(
				jobs.NewPrincipalPurger(dispatcher, maintenance.ActorType, maintenance.ActorID),
				credentials.NewService(vaultClient, nil),
			).
			WithConnectors(connectorStates)
		// Terminal admin-credential stages are deleted synchronously first;
		// this durable maintenance retry closes Vault outage/process-crash
		// windows without retaining candidate passwords indefinitely.
		if vaultClient != nil {
			runner = runner.WithAdminCredentialStageCleanup(vaultClient)
		}
		if dirProvider != nil {
			runner = runner.WithDirectoryPoll(maintenance.DirectoryPoll{
				Provider:          dirProvider,
				ProviderName:      os.Getenv("GRANTOR_IDP_PROVIDER"),
				MissingIsDisabled: serverutil.EnvBool("GRANTOR_IDP_MISSING_IS_DISABLED", true),
			})
		} else {
			slog.Info("grantor-worker: GRANTOR_IDP_MODE is empty; identity directory poll " +
				"is disabled (offboarding findings are still evaluated from local principal status)")
		}
		scheduler := maintenance.NewScheduler(runner, runner.Interval(),
			slog.Default().With("component", "maintenance"))

		var maintCtx context.Context
		maintCtx, maintCancel = context.WithCancel(context.Background())
		maintDone = make(chan struct{})
		go func() {
			defer close(maintDone)
			scheduler.Start(maintCtx)
		}()
		slog.Info("grantor-worker: maintenance scheduler started", "interval", runner.Interval())
	} else {
		slog.Info("grantor-worker: GRANTOR_MAINTENANCE is disabled; " +
			"retention/GC and TTL enforcement are off")
	}

	// Планировщик авто-rediscovery: периодическая постановка discovery
	// подключениям с устаревшим снимком (internal/core/rediscovery) — та же
	// операция и тот же idempotency key, что у ручного refresh в API.
	// Singleton между репликами обеспечивает сам Runner через advisory
	// lock; отдельный ctx — по той же причине, что у maintenance выше.
	var rediscoveryCancel context.CancelFunc
	var rediscoveryDone chan struct{}
	if interval := serverutil.EnvDuration("GRANTOR_DISCOVERY_INTERVAL", 0); interval > 0 {
		runner := rediscovery.New(pool, rediscovery.Config{Interval: interval}, dispatcher).
			WithAudit(auditWriter)
		scheduler := rediscovery.NewScheduler(runner,
			slog.Default().With("component", "rediscovery"))

		var rediscoveryCtx context.Context
		rediscoveryCtx, rediscoveryCancel = context.WithCancel(context.Background())
		rediscoveryDone = make(chan struct{})
		go func() {
			defer close(rediscoveryDone)
			scheduler.Start(rediscoveryCtx)
		}()
		slog.Info("grantor-worker: rediscovery scheduler started", "interval", interval)
	} else {
		slog.Info("grantor-worker: GRANTOR_DISCOVERY_INTERVAL is not set; " +
			"periodic auto-rediscovery is disabled (snapshots refresh only manually)")
	}

	// Webhook-уведомления: поллер операций best-effort шлёт события
	// pending_approval и падений на GRANTOR_WEBHOOK_URL. Один поллер вместо
	// хуков в местах создания: событие ловится независимо от того, какой
	// путь API/worker его породил.
	var notifyCancel context.CancelFunc
	var notifyDone chan struct{}
	if webhookURL := os.Getenv("GRANTOR_WEBHOOK_URL"); webhookURL != "" {
		runner := &notify.Runner{
			Store:    operations.NewStore(),
			Pool:     pool,
			Client:   webhook.New(webhookURL, serverutil.EnvDuration("GRANTOR_WEBHOOK_TIMEOUT", 0)),
			Interval: serverutil.EnvDuration("GRANTOR_WEBHOOK_INTERVAL", 0),
			Log:      slog.Default().With("component", "notify"),
		}
		var notifyCtx context.Context
		notifyCtx, notifyCancel = context.WithCancel(context.Background())
		notifyDone = make(chan struct{})
		go func() {
			defer close(notifyDone)
			runner.Run(notifyCtx)
		}()
		slog.Info("grantor-worker: webhook notifications started")
	}

	// Сверка версий credential с Vault: singleton через свой advisory lock,
	// отдельный ctx — по той же причине, что у maintenance и rediscovery
	// выше. Требует Vault: без него сверять не с чем.
	var credentialCheckCancel context.CancelFunc
	var credentialCheckDone chan struct{}
	if interval := serverutil.EnvDuration("GRANTOR_CREDENTIAL_CHECK_INTERVAL", 0); interval > 0 {
		if vaultClient == nil {
			slog.Warn("grantor-worker: GRANTOR_CREDENTIAL_CHECK_INTERVAL is set but Vault is not " +
				"configured; credential divergence detection is disabled")
		} else {
			runner := credentialcheck.New(pool, vaultClient, credentialcheck.Config{
				Interval:       interval,
				MaxPathsPerRun: serverutil.EnvInt("GRANTOR_CREDENTIAL_CHECK_MAX_PATHS", 0),
			}).WithAudit(auditWriter)
			scheduler := credentialcheck.NewScheduler(runner,
				slog.Default().With("component", "credentialcheck"))

			var credentialCheckCtx context.Context
			credentialCheckCtx, credentialCheckCancel = context.WithCancel(context.Background())
			credentialCheckDone = make(chan struct{})
			go func() {
				defer close(credentialCheckDone)
				scheduler.Start(credentialCheckCtx)
			}()
			slog.Info("grantor-worker: credential check scheduler started", "interval", interval)
		}
	} else {
		slog.Info("grantor-worker: GRANTOR_CREDENTIAL_CHECK_INTERVAL is not set; " +
			"passwords changed outside grantor are not detected")
	}

	mux := http.NewServeMux()
	mux.Handle("/health/live", health.LiveHandler())
	mux.Handle("/health/ready", health.Handler(
		health.Check{Name: "postgres", Probe: pool.Ping},
	))
	mux.Handle("/metrics", serverutil.MetricsHandler())

	srv := serverutil.NewHTTPServer(addr, mux)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	slog.Info("grantor-worker: listening", "addr", addr)

	var runErr error
	select {
	case <-ctx.Done():
		slog.Info("grantor-worker: shutdown signal received")
	case err := <-errCh:
		runErr = fmt.Errorf("http server: %w", err)
		slog.Error("grantor-worker: http server failed", "error", err)
	}

	// Останавливаем планировщик обслуживания: не даём стартовать новый
	// прогон во время дренажа. Прогон в процессе получает отменённый ctx
	// и откатывает транзакцию (обслуживание идемпотентно).
	if maintCancel != nil {
		maintCancel()
		select {
		case <-maintDone:
		case <-time.After(maintenanceStopTimeout):
			slog.Warn("grantor-worker: maintenance scheduler stop timed out")
		}
	}

	// Планировщик авто-rediscovery останавливается по тем же правилам:
	// прогон в процессе получает отменённый ctx и откатывает транзакцию
	// (постановка discovery идемпотентна по минутному окну).
	if rediscoveryCancel != nil {
		rediscoveryCancel()
		select {
		case <-rediscoveryDone:
		case <-time.After(maintenanceStopTimeout):
			slog.Warn("grantor-worker: rediscovery scheduler stop timed out")
		}
	}

	if credentialCheckCancel != nil {
		credentialCheckCancel()
		select {
		case <-credentialCheckDone:
		case <-time.After(maintenanceStopTimeout):
			slog.Warn("grantor-worker: credential check scheduler stop timed out")
		}
	}

	if notifyCancel != nil {
		notifyCancel()
		select {
		case <-notifyDone:
		case <-time.After(maintenanceStopTimeout):
			slog.Warn("grantor-worker: webhook notifier stop timed out")
		}
	}

	// Сначала River: перестаём брать новые jobs и ждём активные, HTTP
	// (readiness/metrics) в это время ещё жив.
	stopCtx, cancelStop := context.WithTimeout(context.Background(), riverStopTimeout)
	defer cancelStop()
	if err := dispatcher.Stop(stopCtx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("stop river dispatcher: %w", err))
	}

	// Connector gateway останавливается после River: активные jobs могли
	// ждать результатов заданий. Сначала Close (Serve на закрытом listener
	// завершится штатно, без ложной ошибки accept), затем сам listener.
	if connectorGW != nil {
		if err := connectorGW.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close connector gateway: %w", err))
		}
	}
	if connectorLn != nil {
		if err := connectorLn.Close(); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close connector gateway listener: %w", err))
		}
	}

	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancelShutdown()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		runErr = errors.Join(runErr, fmt.Errorf("http shutdown: %w", err))
	}

	if runErr != nil {
		return runErr
	}
	slog.Info("grantor-worker: stopped")
	return nil
}
