// Package api — HTTP API v1 control plane grantor (этапы 1a и 1b:
// инвентарь, создание connections и запуск discovery, мутирующие
// операции доступа и учётных записей, а также разделы UI «Пользователи»
// (principals) и «Дрифт»; docs/architecture.md, раздел 20).
//
// # Формат
//
// Все endpoints отдают JSON; ошибки — {"error": "message"} с
// соответствующим HTTP-статусом (respond.go). Ошибки stores
// транслируются в статусы: not found -> 404, конфликт статуса,
// недопустимый переход или занятый уникальный ключ -> 409, ошибки
// валидации тела/параметров -> 400. Мутирующие endpoints отвечают 202 с
// operation_id: работу выполняет worker, статус доступен в
// GET /api/v1/operations/{id}.
//
// # Авторизация
//
// Каждый endpoint обёрнут в auth.RequireRole: чтение — viewer,
// grant/revoke, операции над accounts, principals и adopt — operator,
// создание и удаление connections, удаление accounts и dangerous
// permissions — admin. Мутирующие методы
// дополнительно требуют CSRF token (проверяет RequireRole; см.
// internal/auth). Session кладёт в context auth.Middleware в cmd/api
// либо сам RequireRole.
//
// # Секреты
//
// Admin credential из POST /api/v1/connections и пароли accounts уходят
// только в Vault; в metadata database, ответы, audit metadata и логи
// секреты не попадают никогда (docs/architecture.md, раздел 24).
// Единственное исключение — одноразовая ссылка Yopass из
// POST /api/v1/accounts/{id}/share: она возвращается один раз и нигде не
// сохраняется.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/directoryimport"
	"github.com/ArtefactoO/grantor/internal/core/environments"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/core/servicetoken"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/netguard"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/ratelimit"
)

// DefaultPurgeRetention — срок хранения выведенного из системы принципала
// до необратимого уничтожения. Тридцать дней — окно, за которое ошибочный
// вывод замечают и отменяют, а осознанный успевает пройти согласование.
const DefaultPurgeRetention = 30 * 24 * time.Hour

// actor_type операций и audit-событий определяется сессией
// (auth.Session.ActorType): "user" для человека, "service" для
// service-принципала (аутентификация по service-токену).

// Audit actions API.
const (
	auditActionConnectionCreated  = "connection.created"
	auditActionConnectionUpdated  = "connection.updated"
	auditActionConnectionDisabled = "connection.disabled"
	auditActionConnectionEnabled  = "connection.enabled"
	auditActionConnectionDeleted  = "connection.deleted"
	auditActionRefreshRequested   = "connection.refresh_requested"
)

// Config — зависимости Server. Все поля, кроме Vault, обязательны.
type Config struct {
	// Pool — пул соединений metadata database; используется и как
	// Querier для read-only запросов, и для транзакций мутаций.
	Pool *pgxpool.Pool
	// Connections/Inventory/Operations/Audit — stores ядра.
	Connections *connections.Store
	Inventory   *inventory.Store
	Operations  *operations.Store
	Audit       *audit.Writer
	// Vault — клиент секретов; может быть nil: тогда создание
	// connection с admin credential отвечает 503 с понятной ошибкой.
	Vault *vault.Client
	// Credentials — lifecycle секретов учётных записей (Vault + Yopass).
	// Обязателен; сервис с несконфигурированными клиентами внутри
	// переводится в 503 на соответствующих endpoints.
	Credentials *credentials.Service
	// Directory — сервис заведения принципалов из внешнего identity
	// directory. nil = импорт выключен: endpoints каталога отвечают 501, а
	// интерфейс скрывает соответствующие действия.
	Directory *directoryimport.Service
	// Dispatcher ставит операции в очередь worker (insert-only River).
	Dispatcher jobs.Dispatcher
	// Auth выдаёт RBAC middleware для endpoints.
	Auth *auth.Authenticator
	// NetPolicy — сетевая политика проверки endpoint connection
	// (SSRF-guard, internal/netguard). Zero value = пустая политика:
	// разрешено всё, кроме жёстких блоков (cloud-metadata, loopback,
	// link-local, unspecified, multicast).
	NetPolicy netguard.Policy
	// Resolver резолвит DNS-имена endpoint при проверке NetPolicy.
	// nil → netguard.DefaultResolver().
	Resolver netguard.Resolver
	// RateLimiter — общий token-bucket (internal/ratelimit) для login/
	// reveal/mutating поверхностей. nil = лимиты выключены (backward-compat
	// для тестов и флага GRANTOR_RATE_LIMIT=false).
	RateLimiter *ratelimit.Limiter
	// RateLimits — параметры вёдер. Zero value → DefaultRateLimitConfig().
	RateLimits RateLimitConfig
	// AnomalyDetector — детектор аномальной частоты credential reveal/share
	// (per-subject окно в PostgreSQL, разделы 24/25). nil = детекция
	// выключена (эмитятся только базовые reveal/share метрики). Не блокирует
	// запрос — сигнал уходит в audit security.reveal_rate_anomaly.
	AnomalyDetector *ratelimit.AnomalyDetector
	// AnomalyWindow — порог и окно детекции аномалии. Zero value (или
	// Threshold<=0) отключает детекцию даже при заданном AnomalyDetector.
	AnomalyWindow ratelimit.AnomalyWindow
	// Policy — стор scope policies (ограничение operator по окружениям).
	// nil → policy.NewStore() (стор бесстейтовый).
	Policy *policy.Store
	// ScopeEnforcement — режим enforcement scope policies (enforce|disabled).
	// Пустое значение трактуется как disabled — dev-безопасный дефолт.
	ScopeEnforcement policy.EnforcementMode
	// ServiceTokens — стор service tokens (машинный доступ к API).
	// nil → servicetoken.NewStore() (стор бесстейтовый).
	ServiceTokens  *servicetoken.Store
	APIKeys        *apikey.Store
	APIKeyIdentity *APIKeyIdentityManager
	// ApprovalRequired включает approval workflow (ADR-0010, флаг
	// GRANTOR_APPROVAL_REQUIRED): опасный (dangerous) грант создаётся в
	// pending_approval и выполняется только после того, как admin явно его
	// подтвердит (approve). Confirmation gate одного admin, не four-eyes:
	// подтвердить может тот же admin, что и запросил (self-approval — норма).
	// false (dev-дефолт) — грант ставится сразу, как раньше. Дефолт disabled,
	// как у scope enforcement: лишний ручной approve в dev-контуре мешает, а
	// безопасность dev не критична. Self-approval разрешён, поэтому включённый
	// gate не деадлочит даже с единственным admin.
	ApprovalRequired bool
	// MassRevokeThreshold — порог массового отзыва (флаг
	// GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD): если одно применение манифеста
	// или offboard принципала отзывает БОЛЬШЕ threshold bindings, все
	// children этого parent (у offboard — включая account.delete) создаются
	// в pending_approval и ждут явного approve (защита от массового
	// offboarding по ошибке). 0 (дефолт) — gate выключен, revoke ставится
	// сразу, как раньше. Работает НЕЗАВИСИМО от ApprovalRequired: тот гейтит
	// опасные привилегии, этот — масштаб отзыва (approval.RequiresMassRevoke).
	MassRevokeThreshold int
	// PurgeRetention — срок, в течение которого выведенный из системы
	// принципал остаётся восстановимым (GRANTOR_PRINCIPAL_PURGE_RETENTION).
	// Zero value → DefaultPurgeRetention.
	PurgeRetention time.Duration
	// RotationConfirmThreshold — порог осознанного подтверждения ротации
	// общего секрета принципала (флаг GRANTOR_ROTATION_CONFIRM_THRESHOLD):
	// если новый пароль получают БОЛЬШЕ threshold аккаунтов,
	// POST /principals/{id}/rotate требует явного confirm=true в теле
	// (rotationRequiresConfirm). Это обычный флаг запроса, а НЕ
	// approval-workflow со вторым админом: ротацию часто делают в инциденте,
	// и блокировать её ожиданием второго человека опаснее самой ротации.
	// 0 (дефолт api.Config) — gate выключен; cmd/api задаёт свой дефолт.
	RotationConfirmThreshold int
	// BeforeAdminCredentialStage is a fault-injection hook after the durable
	// preparing reservation and connection lock, immediately before Vault IO.
	// Production leaves it nil.
	BeforeAdminCredentialStage func(context.Context, uuid.UUID) error
}

// Server — HTTP API v1. Создаётся через New; handlers регистрируются
// Routes.
type Server struct {
	pool                   *pgxpool.Pool
	connections            *connections.Store
	adminCredentialChanges *admincredentials.Store
	inventory              *inventory.Store
	operations             *operations.Store
	// principals создаётся внутри New: store бесстейтовый (zero value
	// работоспособен), поэтому в Config и wiring cmd/api не выносится.
	principals *principals.Store
	// directory — заведение принципалов из внешнего каталога. nil или
	// сервис без каталога = импорт выключен, соответствующие endpoints
	// отвечают 501.
	directory   *directoryimport.Service
	audit       *audit.Writer
	vault       *vault.Client
	credentials *credentials.Service
	// connectors — наблюдения gateway о сегментах; nil = control plane без
	// gateway, список пуст.
	connectors *connectorstate.Store
	dispatcher jobs.Dispatcher
	auth       *auth.Authenticator
	// netPolicy и resolver — SSRF-guard проверки endpoint при создании
	// connection (см. validateEndpoint в handlers_connections.go).
	netPolicy netguard.Policy
	resolver  netguard.Resolver
	// rateLimiter и rateLimits — token-bucket поверхностей login/reveal/
	// mutating (см. ratelimit.go). rateLimiter nil = лимиты выключены.
	rateLimiter *ratelimit.Limiter
	rateLimits  RateLimitConfig
	// anomalyDetector и anomalyWindow — детекция аномальной частоты reveal/
	// share (см. security_anomaly.go). anomalyDetector nil или
	// !anomalyWindow.Enabled() = детекция выключена.
	anomalyDetector *ratelimit.AnomalyDetector
	anomalyWindow   ratelimit.AnomalyWindow
	// policy и scopeEnforcement — scope policies operator (см. scope.go).
	policy           *policy.Store
	scopeEnforcement policy.EnforcementMode
	// environments — реестр окружений (см. handlers_environments.go).
	environments *environments.Store
	// purgeRetention — срок хранения выведенного из системы принципала до
	// необратимого уничтожения (см. handlers_principals_offboard.go).
	purgeRetention time.Duration
	// serviceTokens — управление service tokens (см. handlers_tokens.go).
	serviceTokens           *servicetoken.Store
	apiKeys                 *apikey.Store
	apiKeyIdentity          *APIKeyIdentityManager
	connectionRegistrations *connectionregistration.Store
	// approvalRequired — включён ли approval workflow опасных грантов
	// (см. handlers_approvals.go, createGrant).
	approvalRequired bool
	// massRevokeThreshold — порог массового отзыва: применение манифеста,
	// отзывающее больше threshold bindings, создаёт revoke-children в
	// pending_approval (см. handlers_access_manifest.go). 0 = выключено.
	massRevokeThreshold int
	// rotationConfirmThreshold — порог подтверждения ротации общего секрета
	// принципала: ротация, меняющая пароль больше чем threshold аккаунтам,
	// требует confirm=true в теле запроса (см. handlers_principal_access.go
	// и rotationRequiresConfirm). 0 = выключено.
	rotationConfirmThreshold   int
	beforeAdminCredentialStage func(context.Context, uuid.UUID) error
}

// New проверяет обязательные зависимости и возвращает Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Pool == nil:
		return nil, errors.New("api: pool is required")
	case cfg.Connections == nil:
		return nil, errors.New("api: connections store is required")
	case cfg.Inventory == nil:
		return nil, errors.New("api: inventory store is required")
	case cfg.Operations == nil:
		return nil, errors.New("api: operations store is required")
	case cfg.Audit == nil:
		return nil, errors.New("api: audit writer is required")
	case cfg.Credentials == nil:
		return nil, errors.New("api: credentials service is required")
	case cfg.Dispatcher == nil:
		return nil, errors.New("api: dispatcher is required")
	case cfg.Auth == nil:
		return nil, errors.New("api: authenticator is required")
	}
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = netguard.DefaultResolver()
	}
	limits := cfg.RateLimits
	if limits == (RateLimitConfig{}) {
		limits = DefaultRateLimitConfig()
	}
	scopePolicy := cfg.Policy
	if scopePolicy == nil {
		scopePolicy = policy.NewStore()
	}
	serviceTokens := cfg.ServiceTokens
	if serviceTokens == nil {
		serviceTokens = servicetoken.NewStore()
	}
	apiKeys := cfg.APIKeys
	if apiKeys == nil {
		apiKeys = apikey.NewStore()
	}
	purgeRetention := cfg.PurgeRetention
	if purgeRetention <= 0 {
		purgeRetention = DefaultPurgeRetention
	}
	return &Server{
		pool:        cfg.Pool,
		connections: cfg.Connections,
		inventory:   cfg.Inventory,
		operations:  cfg.Operations,
		principals:  principals.NewStore(),
		// Store бесстейтовый, как principals: наблюдения читаются из того же
		// пула и в Config не выносятся.
		connectors:              connectorstate.NewStore(cfg.Pool),
		adminCredentialChanges:  admincredentials.NewStore(),
		environments:            environments.NewStore(),
		purgeRetention:          purgeRetention,
		audit:                   cfg.Audit,
		vault:                   cfg.Vault,
		credentials:             cfg.Credentials,
		directory:               cfg.Directory,
		dispatcher:              cfg.Dispatcher,
		auth:                    cfg.Auth,
		netPolicy:               cfg.NetPolicy,
		resolver:                resolver,
		rateLimiter:             cfg.RateLimiter,
		rateLimits:              limits,
		anomalyDetector:         cfg.AnomalyDetector,
		anomalyWindow:           cfg.AnomalyWindow,
		policy:                  scopePolicy,
		scopeEnforcement:        cfg.ScopeEnforcement,
		serviceTokens:           serviceTokens,
		apiKeys:                 apiKeys,
		apiKeyIdentity:          cfg.APIKeyIdentity,
		connectionRegistrations: connectionregistration.NewStore(),
		approvalRequired:        cfg.ApprovalRequired,
		massRevokeThreshold:     cfg.MassRevokeThreshold,

		rotationConfirmThreshold:   cfg.RotationConfirmThreshold,
		beforeAdminCredentialStage: cfg.BeforeAdminCredentialStage,
	}, nil
}

// Routes регистрирует endpoints API v1 на mux. Каждый handler обёрнут в
// RequireRole; pattern-роутинг ServeMux (метод + {id}) отдаёт 405/404 на
// неподдерживаемые методы и пути сам.
func (s *Server) Routes(mux *http.ServeMux) {
	viewer := s.managementRole(auth.RoleViewer)
	operator := s.managementRole(auth.RoleOperator)
	admin := s.managementRole(auth.RoleAdmin)
	mux.Handle("GET /api/v1/me", viewer(http.HandlerFunc(s.getAPIIdentity)))

	mux.Handle("GET /api/v1/me/api-keys", viewer(http.HandlerFunc(s.listAPIKeys)))
	mux.Handle("POST /api/v1/me/api-keys", viewer(http.HandlerFunc(s.createAPIKey)))
	mux.Handle("DELETE /api/v1/me/api-keys/{id}", viewer(http.HandlerFunc(s.revokeAPIKey)))
	mux.Handle("GET /api/v1/me/favorite-connections", viewer(http.HandlerFunc(s.listFavoriteConnections)))
	mux.Handle("PUT /api/v1/me/favorite-connections/{id}", viewer(http.HandlerFunc(s.setFavoriteConnection)))
	mux.Handle("DELETE /api/v1/me/favorite-connections/{id}", viewer(http.HandlerFunc(s.setFavoriteConnection)))
	mux.Handle("POST /api/v1/connection-registrations", operator(http.HandlerFunc(s.createConnectionRegistration)))
	mux.Handle("GET /api/v1/connection-registrations", viewer(http.HandlerFunc(s.listConnectionRegistrations)))
	mux.Handle("GET /api/v1/connection-registrations/{id}", viewer(http.HandlerFunc(s.getConnectionRegistration)))
	mux.Handle("DELETE /api/v1/connection-registrations/{id}", operator(http.HandlerFunc(s.deleteConnectionRegistration)))
	mux.Handle("POST /api/v1/connection-credential-sources", admin(http.HandlerFunc(s.createConnectionCredentialSource)))
	mux.Handle("GET /api/v1/connection-credential-sources", admin(http.HandlerFunc(s.listConnectionCredentialSources)))
	mux.Handle("DELETE /api/v1/connection-credential-sources/{id}", admin(http.HandlerFunc(s.deleteConnectionCredentialSource)))

	mux.Handle("GET /api/v1/connections", viewer(http.HandlerFunc(s.listConnections)))
	mux.Handle("POST /api/v1/connections", admin(http.HandlerFunc(s.createConnection)))
	mux.Handle("GET /api/v1/connections/{id}", viewer(http.HandlerFunc(s.getConnection)))
	mux.Handle("PATCH /api/v1/connections/{id}", admin(http.HandlerFunc(s.patchConnection)))
	mux.Handle("POST /api/v1/connections/{id}/disable", admin(http.HandlerFunc(s.disableConnection)))
	mux.Handle("POST /api/v1/connections/{id}/enable", admin(http.HandlerFunc(s.enableConnection)))
	mux.Handle("DELETE /api/v1/connections/{id}", admin(http.HandlerFunc(s.deleteConnection)))
	mux.Handle("POST /api/v1/connections/{id}/refresh", operator(http.HandlerFunc(s.refreshConnection)))
	mux.Handle("POST /api/v1/connections/{id}/admin-credential/switch", admin(http.HandlerFunc(s.switchConnectionAdminCredential)))
	mux.Handle("POST /api/v1/connections/{id}/admin-credential/rotate", admin(http.HandlerFunc(s.rotateConnectionAdminCredential)))
	mux.Handle("POST /api/v1/connections/{id}/admin-credential/cancel", admin(http.HandlerFunc(s.cancelConnectionAdminCredential)))
	mux.Handle("GET /api/v1/connections/{id}/resources", viewer(http.HandlerFunc(s.listConnectionResources)))
	mux.Handle("GET /api/v1/connections/{id}/accounts", viewer(http.HandlerFunc(s.listConnectionAccounts)))
	mux.Handle("GET /api/v1/connections/{id}/permissions", viewer(http.HandlerFunc(s.listConnectionPermissions)))
	mux.Handle("GET /api/v1/connections/{id}/role-policies", viewer(http.HandlerFunc(s.listRolePolicies)))
	mux.Handle("POST /api/v1/connections/{id}/role-policies/{key}/apply", admin(http.HandlerFunc(s.applyRolePolicy)))
	mux.Handle("POST /api/v1/connections/{id}/role-policies/{key}/create", admin(http.HandlerFunc(s.createRolePolicy)))
	mux.Handle("POST /api/v1/connections/{id}/role-policies/{key}/adopt", admin(http.HandlerFunc(s.adoptRolePolicy)))
	mux.Handle("POST /api/v1/connections/{id}/role-policies/{key}/repair", admin(http.HandlerFunc(s.repairRolePolicy)))
	mux.Handle("GET /api/v1/connections/{id}/hba", viewer(http.HandlerFunc(s.listConnectionHBA)))
	mux.Handle("GET /api/v1/connections/{id}/object-privilege-targets", viewer(http.HandlerFunc(s.listObjectPrivilegeTargets)))
	mux.Handle("GET /api/v1/accounts/{id}/object-privileges", viewer(http.HandlerFunc(s.listAccountObjectPrivileges)))
	mux.Handle("GET /api/v1/accounts/{id}/default-privileges", viewer(http.HandlerFunc(s.listAccountDefaultPrivileges)))
	mux.Handle("GET /api/v1/accounts/{id}/postgres/access-diagnostics", viewer(http.HandlerFunc(s.getPostgresAccessDiagnostics)))
	mux.Handle("POST /api/v1/connections/{id}/postgres/access-profiles", admin(http.HandlerFunc(s.configurePostgresProfiles)))
	mux.Handle("POST /api/v1/accounts/{id}/credential/verify", operator(http.HandlerFunc(s.verifyManagedCredential)))
	mux.Handle("GET /api/v1/accounts/{id}/credential-verification", viewer(http.HandlerFunc(s.getCredentialVerification)))
	mux.Handle("POST /api/v1/connections/{id}/roles", operator(http.HandlerFunc(s.createRole)))
	mux.Handle("POST /api/v1/connections/{id}/resources", admin(http.HandlerFunc(s.createResource)))
	mux.Handle("POST /api/v1/connections/{id}/resources/database-with-roles", admin(http.HandlerFunc(s.createDatabaseWithRoles)))
	// Карточка учётной записи по её id: без него аккаунт читался только
	// списком по connection, а у аккаунта, найденного через принципала или
	// операцию, connection заранее неизвестен.
	mux.Handle("GET /api/v1/accounts/{id}", viewer(http.HandlerFunc(s.getAccount)))
	mux.Handle("GET /api/v1/accounts/{id}/provisioning", viewer(http.HandlerFunc(s.getAccountProvisioning)))
	mux.Handle("POST /api/v1/accounts/{id}/verify-creation", operator(http.HandlerFunc(s.verifyAccountCreation)))
	mux.Handle("POST /api/v1/accounts/{id}/recover-provisioning", admin(http.HandlerFunc(s.recoverAccountProvisioning)))
	mux.Handle("GET /api/v1/accounts/{id}/bindings", viewer(http.HandlerFunc(s.listAccountBindings)))
	mux.Handle("GET /api/v1/resources/{id}", viewer(http.HandlerFunc(s.getResource)))
	mux.Handle("GET /api/v1/resources/{id}/bindings", viewer(http.HandlerFunc(s.listResourceBindings)))
	mux.Handle("GET /api/v1/operations", viewer(http.HandlerFunc(s.listOperations)))
	mux.Handle("GET /api/v1/operations/{id}", viewer(http.HandlerFunc(s.getOperation)))
	// Ручной retry неуспешных детей bulk parent (partial/failed): дети
	// сбрасываются в pending и заново ставятся в очередь, parent оживает в
	// running до повторной финализации. Scope operator проверяется внутри
	// handler по connections ретраящихся детей.
	mux.Handle("POST /api/v1/operations/{id}/retry", operator(http.HandlerFunc(s.retryOperation)))
	mux.Handle("POST /api/v1/operations/{id}/resolve", operator(http.HandlerFunc(s.resolveOperation)))
	mux.Handle("GET /api/v1/audit", viewer(http.HandlerFunc(s.listAudit)))

	// Approval workflow (ADR-0010): список ожидающих подтверждения операций и
	// решения approve/reject — admin. Confirmation gate одного admin, не
	// four-eyes: self-approval разрешён (проверки «approver != requester» нет),
	// факт self-approval лишь фиксируется в audit. approve-children/
	// reject-children решают все pending_approval дети parent одним действием
	// (пачка bulk/manifest, массовый ревок) с теми же per-child семантикой и
	// audit.
	mux.Handle("GET /api/v1/approvals", admin(http.HandlerFunc(s.listApprovals)))
	mux.Handle("POST /api/v1/operations/{id}/approve", admin(http.HandlerFunc(s.approveOperation)))
	mux.Handle("POST /api/v1/operations/{id}/reject", admin(http.HandlerFunc(s.rejectOperation)))
	mux.Handle("POST /api/v1/operations/{id}/approve-children", admin(http.HandlerFunc(s.approveChildren)))
	mux.Handle("POST /api/v1/operations/{id}/reject-children", admin(http.HandlerFunc(s.rejectChildren)))

	// Мутации доступа и учётных записей (этап 1b). Dangerous permissions
	// дополнительно проверяются внутри handlers: базовая роль — operator,
	// dangerous grant требует admin и явного confirm.
	mux.Handle("POST /api/v1/bindings", operator(http.HandlerFunc(s.createBinding)))
	mux.Handle("POST /api/v1/bindings/bulk", operator(http.HandlerFunc(s.bulkCreateBindings)))
	mux.Handle("POST /api/v1/accounts/{id}/roles", operator(http.HandlerFunc(s.manageAccountRoles)))
	mux.Handle("POST /api/v1/accounts/{id}/object-privileges", operator(http.HandlerFunc(s.manageObjectPrivileges)))
	mux.Handle("DELETE /api/v1/bindings/{id}", operator(http.HandlerFunc(s.deleteBinding)))
	mux.Handle("POST /api/v1/accounts", operator(http.HandlerFunc(s.createAccount)))
	mux.Handle("POST /api/v1/accounts/{id}/disable", operator(http.HandlerFunc(s.disableAccount)))
	mux.Handle("POST /api/v1/accounts/{id}/enable", operator(http.HandlerFunc(s.enableAccount)))
	mux.Handle("DELETE /api/v1/accounts/{id}", admin(http.HandlerFunc(s.deleteAccount)))
	mux.Handle("DELETE /api/v1/accounts/{id}/purge", admin(http.HandlerFunc(s.purgeAccount)))
	// Restore — отдельная admin-only мутация: tombstone не является
	// disabled account, а новая identity активируется только после проверки
	// владения свежим credential на target.
	mux.Handle("POST /api/v1/accounts/{id}/restore", admin(http.HandlerFunc(s.restoreAccount)))
	// Ротация credential аккаунта. На аккаунте, сидящем на общем секрете
	// принципала, ротация без явного {"detach":true} отвечает 409 с кодом
	// shared_credential_requires_choice: молча увести такой аккаунт с общего
	// пароля нельзя (ADR-0008). Обратное намерение — {"attach":true}:
	// вернуть отвязанный аккаунт на общий пароль его принципала.
	mux.Handle("POST /api/v1/accounts/{id}/rotate", operator(http.HandlerFunc(s.rotateAccount)))
	mux.Handle("POST /api/v1/accounts/{id}/share", operator(http.HandlerFunc(s.shareAccount)))
	// Принятие unmanaged-аккаунта под управление: metadata-режим отвечает
	// 200 (без операции, как link/adopt binding); generate и set_password
	// ставят credential.rotate с флагом adopt (пароль учётки МЕНЯЕТСЯ), а
	// verify_password — account.adopt_verify (пароль только подтверждается,
	// целевая система не мутируется); все три отвечают 202. Dangerous bindings
	// в adopt_bindings дополнительно требуют admin внутри handler.
	mux.Handle("POST /api/v1/accounts/{id}/adopt", operator(http.HandlerFunc(s.adoptAccount)))
	// Явный безопасный переход существующего unmanaged account в principal-
	// centric модель. В отличие от /link, меняет target credential и только
	// после rotate+proof атомарно фиксирует managed ownership и principal.
	mux.Handle("POST /api/v1/accounts/{id}/link-and-manage", operator(http.HandlerFunc(s.linkAndManageAccount)))

	// Разделы UI «Пользователи» (principals) и «Дрифт». Привязка
	// accounts к principals и adopt меняют только метаданные: операции в
	// worker не ставятся, поэтому эти endpoints отвечают 200/201, а не 202.
	// disable/enable каскадны: при наличии managed-аккаунтов создаётся bulk
	// parent с детьми account.disable/account.enable (202); без них —
	// прежний metadata-only ответ 200. offboard — необратимый каскад
	// (admin, confirm=true): revoke+delete всех managed-аккаунтов, зачистка
	// общих секретов, tombstone status=deleted.
	mux.Handle("GET /api/v1/principals", viewer(http.HandlerFunc(s.listPrincipals)))
	mux.Handle("POST /api/v1/principals", operator(http.HandlerFunc(s.createPrincipal)))
	mux.Handle("GET /api/v1/principals/{id}", viewer(http.HandlerFunc(s.getPrincipal)))
	mux.Handle("POST /api/v1/principals/{id}/disable", operator(http.HandlerFunc(s.disablePrincipal)))
	mux.Handle("POST /api/v1/principals/{id}/enable", operator(http.HandlerFunc(s.enablePrincipal)))
	mux.Handle("POST /api/v1/principals/{id}/offboard", admin(http.HandlerFunc(s.offboardPrincipal)))
	mux.Handle("POST /api/v1/principals/{id}/restore", admin(http.HandlerFunc(s.restorePrincipal)))
	mux.Handle("DELETE /api/v1/principals/{id}/purge", admin(http.HandlerFunc(s.purgePrincipal)))
	// Principal-centric выдача доступа: создаёт managed-аккаунты с общим
	// секретом принципала и ставит операции, поэтому отвечает 202/201.
	mux.Handle("POST /api/v1/principals/{id}/access", operator(http.HandlerFunc(s.grantPrincipalAccess)))
	mux.Handle("GET /api/v1/principals/{id}/credentials", viewer(http.HandlerFunc(s.listPrincipalCredentials)))
	mux.Handle("POST /api/v1/principals/{id}/credentials", operator(http.HandlerFunc(s.createPrincipalCredential)))
	mux.Handle("POST /api/v1/principals/{id}/rotate", operator(http.HandlerFunc(s.rotatePrincipalCredentials)))
	mux.Handle("POST /api/v1/principals/{id}/share", operator(http.HandlerFunc(s.sharePrincipalCredential)))
	mux.Handle("POST /api/v1/accounts/{id}/link", operator(http.HandlerFunc(s.linkAccount)))
	mux.Handle("POST /api/v1/accounts/{id}/unlink", operator(http.HandlerFunc(s.unlinkAccount)))
	// Каталог: поиск людей для точечного добавления при выдаче доступа и
	// импорт. Массовая загрузка (all) внутри обработчика требует admin.
	mux.Handle("GET /api/v1/directory/users", operator(http.HandlerFunc(s.searchDirectory)))
	mux.Handle("POST /api/v1/directory/import", operator(http.HandlerFunc(s.importDirectory)))
	mux.Handle("GET /api/v1/drift", viewer(http.HandlerFunc(s.listDrift)))
	// Baseline находок: принять как ожидаемое / вернуть в дрифт (operator,
	// scope окружения проверяется в handler).
	mux.Handle("POST /api/v1/drift/baselines", operator(http.HandlerFunc(s.createDriftBaseline)))
	mux.Handle("DELETE /api/v1/drift/baselines/{id}", operator(http.HandlerFunc(s.deleteDriftBaseline)))
	// Наблюдаемое состояние execution connector'ов: кто на связи и когда
	// истекают их сертификаты.
	mux.Handle("GET /api/v1/connectors", viewer(http.HandlerFunc(s.listConnectors)))
	// Имя и тип развёртывания — представление, а не идентичность: сам
	// connector_id остаётся CN сертификата. Удаление разрешено только для
	// offline (см. forgetConnector).
	mux.Handle("PATCH /api/v1/connectors/{id}", admin(http.HandlerFunc(s.updateConnectorProfile)))
	mux.Handle("DELETE /api/v1/connectors/{id}", admin(http.HandlerFunc(s.forgetConnector)))
	mux.Handle("POST /api/v1/bindings/{id}/adopt", operator(http.HandlerFunc(s.adoptBinding)))

	// Декларативный access manifest (ADR-0009): plan (dry-run diff) и apply
	// (массовые grant/revoke/create) — operator, dangerous среди действий
	// требует admin и confirm; export текущего managed-состояния — viewer.
	mux.Handle("POST /api/v1/access/plan", operator(http.HandlerFunc(s.planAccessManifest)))
	mux.Handle("POST /api/v1/access/apply", operator(http.HandlerFunc(s.applyAccessManifest)))
	mux.Handle("GET /api/v1/access/export", viewer(http.HandlerFunc(s.exportAccessManifest)))

	// Scope policies (ограничение operator по окружениям): управление — admin.
	// Runtime-config раскрывает только безопасные эффективные режимы, нужные
	// этому admin-экрану; env, credentials и внутренние адреса не возвращаются.
	mux.Handle("GET /api/v1/runtime-config", admin(http.HandlerFunc(s.getRuntimeConfig)))
	mux.Handle("GET /api/v1/environments", viewer(http.HandlerFunc(s.listEnvironments)))
	mux.Handle("GET /api/v1/engines", viewer(http.HandlerFunc(s.listEngines)))
	mux.Handle("POST /api/v1/environments", admin(http.HandlerFunc(s.createEnvironment)))

	mux.Handle("GET /api/v1/scope-policies", admin(http.HandlerFunc(s.listScopePolicies)))
	mux.Handle("POST /api/v1/scope-policies", admin(http.HandlerFunc(s.createScopePolicy)))
	mux.Handle("DELETE /api/v1/scope-policies/{id}", admin(http.HandlerFunc(s.deleteScopePolicy)))

	// Service tokens (машинный доступ к API): выпуск/список — по принципалу,
	// отзыв — по id токена. Все — admin. Выпуск возможен только для
	// принципала type=service; plaintext-токен возвращается один раз.
	mux.Handle("POST /api/v1/principals/{id}/tokens", admin(http.HandlerFunc(s.createServiceToken)))
	mux.Handle("GET /api/v1/principals/{id}/tokens", admin(http.HandlerFunc(s.listServiceTokens)))
	mux.Handle("DELETE /api/v1/tokens/{id}", admin(http.HandlerFunc(s.revokeServiceToken)))
}
