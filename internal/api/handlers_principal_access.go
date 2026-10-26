package api

// Principal-centric выдача доступа (UI «Пользователи»): оператор выбирает
// подключения и роли, а сервис создаёт где надо локальные managed-аккаунты
// с ОБЩИМ паролем принципала и выдаёт роли. Работа «от пользователя»
// против пер-аккаунтных endpoints handlers_accounts.go / handlers_bindings.go.
//
// Credential-модель (AGENTS.md, ADR-0007): пароль общий на пару
// (principal, environment) — Vault path principals/<id>/environments/<env>/
// credential. Аккаунты принципала в подключениях одного окружения делят
// один пароль (credential_mode=existing_vault_ref, vault_path указывает на
// общий секрет), в разных окружениях пароли независимы. Кластерный
// external identity (LDAP/AD) не используется: всегда создаётся локальная
// роль с паролем.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/metrics"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// Audit actions раздела principal-centric.
const (
	auditActionPrincipalAccessGranted = "principal.access_granted"
	auditActionPrincipalRotateRequest = "principal.rotate_requested"
)

// credentialModeExistingVaultRef — режим managed-аккаунта, ссылающегося на
// существующий общий секрет принципала (раздел 17.1 архитектуры). Значение —
// доменная константа inventory: её же пишет и читает executor.
const credentialModeExistingVaultRef = inventory.CredentialModeExistingVaultRef

// defaultEnvironment — окружение по умолчанию для подключения без
// заданного Environment: общий секрет принципала всё равно скоупится
// окружением, поэтому нужен непустой сегмент пути.
const defaultEnvironment = "default"

// slugIdentity строит engine_identity из display name принципала: нижний
// регистр, символы вне [a-z0-9] заменяются на '_', ведущие/хвостовые '_'
// обрезаются. Пустой результат заменяется на "principal", чтобы identity
// всегда была непустой и валидной для целевых движков.
func slugIdentity(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	slug := strings.Trim(b.String(), "_")
	if slug == "" {
		return "principal"
	}
	return slug
}

// accountIdentityBase выбирает базовое имя создаваемого аккаунта: явный
// override из тела запроса, иначе external subject принципала, иначе slug
// его display name. Engine-специфичную форму из него делает
// accountIdentity.
//
// Из выведенного имени '@' вырезается: у mysql и mongodb engine identity сама
// имеет форму user@host и user@authdb, и adapter считает уже содержащее '@'
// имя готовой identity (идемпотентность повторного форматирования). Subject
// вида "ivan@corp.com" тогда превращался бы в учётку на хосте "corp.com" —
// то есть каталог молча задавал бы часть engine identity. Явный override
// такому вырезанию не подвергается: там оператор пишет identity сам и знает
// форму движка.
func accountIdentityBase(p principals.Principal, override string) string {
	switch {
	case override != "":
		return override
	case p.ExternalSubject != "":
		if local := localPart(p.ExternalSubject); local != "" {
			return local
		}
		return slugIdentity(p.DisplayName)
	default:
		return slugIdentity(p.DisplayName)
	}
}

// localPart возвращает часть строки до первого '@'. Строка без '@'
// возвращается целиком; строка, начинающаяся с '@', — пустой результат
// (осмысленного локального имени в ней нет).
func localPart(s string) string {
	before, _, found := strings.Cut(s, "@")
	if !found {
		return s
	}
	return before
}

// accountIdentity строит engine_identity создаваемого аккаунта для
// конкретного подключения: базовое имя (см. accountIdentityBase) приводится
// к форме движка через adapter (mysql user@host, mongodb user@authdb).
//
// Без этого шага identity, выведенная из принципала, была бы просто slug
// вида "e2e_global", а mysql и mongodb такие имена отвергают — обычный
// сценарий «выдать доступ пользователю» на этих движках падал бы всегда,
// пока оператор не задаст engine_identity руками.
//
// Явный override сохраняет приоритет: форматирование идемпотентно и имя,
// уже записанное в engine-форме, не меняет.
func accountIdentity(conn connections.Connection, p principals.Principal, override string) (string, error) {
	return connections.EngineIdentity(conn, accountIdentityBase(p, override))
}

// environmentOf возвращает окружение подключения; пустое значение
// заменяется defaultEnvironment.
func environmentOf(conn connections.Connection) string {
	if conn.Environment == "" {
		return defaultEnvironment
	}
	return conn.Environment
}

// principalEnvironmentLogins возвращает логины, под которыми принципал
// подключается в окружении: уникальные engine identities его аккаунтов в
// connections этого окружения. Пока аккаунтов нет (credential подготовлен
// заранее), возвращается выводимое базовое имя — под ним аккаунты и будут
// созданы при выдаче доступа.
func (s *Server) principalEnvironmentLogins(ctx context.Context, principal principals.Principal, environment string) ([]string, error) {
	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, principal.ID)
	if err != nil {
		return nil, err
	}
	conns, err := s.connections.List(ctx, s.pool)
	if err != nil {
		return nil, err
	}
	envByConnection := make(map[uuid.UUID]string, len(conns))
	for i := range conns {
		envByConnection[conns[i].ID] = environmentOf(conns[i])
	}
	seen := make(map[string]bool)
	logins := make([]string, 0, 1)
	for i := range accounts {
		identity := accounts[i].EngineIdentity
		if envByConnection[accounts[i].ConnectionID] != environment || seen[identity] {
			continue
		}
		seen[identity] = true
		logins = append(logins, identity)
	}
	if len(logins) == 0 {
		if base := accountIdentityBase(principal, ""); base != "" {
			logins = append(logins, base)
		}
	}
	return logins, nil
}

// principalAccessItem — один запрос доступа: роль в подключении с
// опциональным scope. Незаданный ScopeResourceID означает «область берётся
// из permission-определения» (inventory.EffectiveBindingScope), а не
// «connection-wide»: у kafka/mongodb/rabbitmq assignable-права неотделимы от
// своего topic/базы/vhost, и грант без вывода области дал бы вечный ложный
// drift. Клиенту (в том числе UI) поэтому не нужно знать про scope.
type principalAccessItem struct {
	ConnectionID    uuid.UUID  `json:"connection_id"`
	PermissionID    uuid.UUID  `json:"permission_id"`
	ScopeResourceID *uuid.UUID `json:"scope_resource_id"`
}

// validate проверяет обязательные идентификаторы элемента.
func (it *principalAccessItem) validate() error {
	if it.ConnectionID == uuid.Nil {
		return errors.New("connection_id is required")
	}
	if it.PermissionID == uuid.Nil {
		return errors.New("permission_id is required")
	}
	return nil
}

// principalAccessRequest — тело POST /api/v1/principals/{id}/access.
type principalAccessRequest struct {
	Items []principalAccessItem `json:"items"`
	// EngineIdentity переопределяет identity создаваемых аккаунтов; пусто —
	// identity выводится из принципала (см. accountIdentity).
	EngineIdentity string `json:"engine_identity"`
	// Confirm — подтверждение выдачи dangerous permission (роль admin).
	Confirm bool `json:"confirm"`
	// ExpiresAt — срок действия ВСЕХ выдаваемых прав запроса: по истечении
	// maintenance отзывает их автоматически (binding.expired). Один срок на
	// запрос, а не на элемент: выдача — одно решение оператора, и дробные
	// сроки в одном действии читались бы как ошибка ввода. nil — бессрочно.
	ExpiresAt *time.Time `json:"expires_at"`
}

// validate проверяет размер списка и каждый элемент.
func (req *principalAccessRequest) validate() error {
	if len(req.Items) == 0 {
		return errors.New("items must be a non-empty list")
	}
	if req.ExpiresAt != nil && !req.ExpiresAt.After(time.Now()) {
		return errors.New("expires_at must be in the future")
	}
	if len(req.Items) > maxBulkItems {
		return fmt.Errorf("items must contain at most %d elements", maxBulkItems)
	}
	for i := range req.Items {
		if err := req.Items[i].validate(); err != nil {
			return fmt.Errorf("items[%d]: %w", i, err)
		}
	}
	return nil
}

// principalGrantTarget — загруженные и проверенные сущности одного элемента
// principal-centric запроса: подключение, роль и опциональный scope.
type principalGrantTarget struct {
	connection connections.Connection
	permission inventory.Permission
	scope      *inventory.Resource
}

// loadPrincipalGrantTarget загружает connection/permission/scope элемента и
// проверяет согласованность (активное подключение, permission из этого же
// подключения и assignable). При ошибке пишет ответ и возвращает ok=false.
func (s *Server) loadPrincipalGrantTarget(w http.ResponseWriter, r *http.Request, item principalAccessItem) (principalGrantTarget, bool) {
	ctx := r.Context()

	conn, err := s.connections.Get(ctx, s.pool, item.ConnectionID)
	if err != nil {
		if errors.Is(err, connections.ErrNotFound) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("connection %s not found", item.ConnectionID))
			return principalGrantTarget{}, false
		}
		respondStoreError(ctx, w, err)
		return principalGrantTarget{}, false
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection %s status %q does not allow provisioning; discover it first", conn.ID, conn.Status))
		return principalGrantTarget{}, false
	}
	sess, ok := s.session(w, r)
	if !ok {
		return principalGrantTarget{}, false
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return principalGrantTarget{}, false
	}
	if err := requireConnectionCapability(conn, adapter.CapAccessGrant); err != nil {
		respondStoreError(ctx, w, err)
		return principalGrantTarget{}, false
	}
	perm, scope, ok := s.loadGrantPermissionScope(w, r, conn.ID, conn.ID.String(), item.PermissionID, item.ScopeResourceID)
	if !ok {
		return principalGrantTarget{}, false
	}
	if err := requireStatsMembershipConnection(conn, perm); err != nil {
		respondStoreError(ctx, w, err)
		return principalGrantTarget{}, false
	}
	return principalGrantTarget{connection: conn, permission: perm, scope: scope}, true
}

// principalAccessChild — один результат выдачи в ответе.
type principalAccessChild struct {
	ConnectionID             uuid.UUID  `json:"connection_id"`
	Environment              string     `json:"environment"`
	AccountID                uuid.UUID  `json:"account_id"`
	CredentialMode           string     `json:"credential_mode"`
	AccountCreated           bool       `json:"account_created"`
	AccountCreateOperationID *uuid.UUID `json:"account_create_operation_id,omitempty"`
	GrantOperationID         uuid.UUID  `json:"grant_operation_id"`
	BindingID                uuid.UUID  `json:"binding_id"`
}

// grantPrincipalAccess — POST /api/v1/principals/{id}/access (operator;
// dangerous среди items — admin с confirm): principal-centric выдача.
//
// Оркестрация в одной транзакции metadata database: parent-операция
// bulk.principal_access (сразу running) группирует дочерние. По каждому
// item: обеспечивается общий секрет принципала для окружения подключения
// (Vault); если managed-аккаунт принципала в этом подключении ещё не
// существует — он создаётся синхронно в metadata (credential_mode=
// existing_vault_ref, vault_path = путь общего секрета) и ставится дочерняя
// операция account.create для провижининга роли в целевой БД; затем
// EnsureBinding(present) + дочерняя access.grant.
//
// Порядок account.create -> access.grant по одному подключению задаётся
// явной последовательностью River jobs: grant появляется в очереди только
// после success provisioning. Один advisory-lock сериализует мутации, но сам
// по себе не задаёт порядок, в котором параллельные workers возьмут jobs.
func (s *Server) grantPrincipalAccess(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req principalAccessRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	principal, err := s.principals.Get(ctx, s.pool, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Deleted-принципал — tombstone после offboard, disabled — временно
	// отключённый: выдача доступа запрещена обоим.
	//
	// Про disabled: каскад деактивации гасит существующие учётки принципала,
	// но выдача создавала НОВУЮ рабочую учётку с общим паролем окружения —
	// тем самым, который отключённый пользователь уже знает. Отключение
	// переставало быть отключением. Прочие пути секретов (share, rotate,
	// adopt) блокируют disabled с самого начала; выдача была единственной
	// дырой в этом ряду.
	if msg := principalStatusBlocks(principal.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}

	targets := make([]principalGrantTarget, 0, len(req.Items))
	anyDangerous := false
	for i := range req.Items {
		target, ok := s.loadPrincipalGrantTarget(w, r, req.Items[i])
		if !ok {
			return
		}
		// Scope: operator выдаёт доступ только в connections своих окружений.
		if err := s.checkConnectionScope(ctx, sess, target.connection.Environment); err != nil {
			s.respondScopeError(ctx, w, err)
			return
		}
		anyDangerous = anyDangerous || target.permission.Dangerous
		targets = append(targets, target)
	}
	if anyDangerous {
		if status, msg := dangerousGrantCheck(sess.Role, req.Confirm); status != 0 {
			respondError(w, status, msg)
			return
		}
	}

	s.runBulkParent(w, r, sess, bulkParent{
		kind:             jobs.KindBulkPrincipalAccess,
		principalID:      &principal.ID,
		payload:          map[string]any{"items": len(targets), "confirmed": req.Confirm},
		payloadErrPrefix: "api: marshal principal access payload",
		auditAction:      auditActionPrincipalAccessGranted,
		commitErrPrefix:  "api: commit principal access",
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		connectionsToLock := make([]connections.Connection, 0, len(targets))
		for i := range targets {
			connectionsToLock = append(connectionsToLock, targets[i].connection)
		}
		if err := lockProvisioningConnections(ctx, tx, connectionsToLock); err != nil {
			respondStoreError(ctx, w, err)
			return nil, nil, false
		}
		// Кэши в пределах запроса: общий секрет по окружению и созданный/
		// переиспользованный аккаунт по подключению.
		envPaths := map[string]string{}
		accountByConn := map[uuid.UUID]inventory.Account{}
		provisionByConn := map[uuid.UUID]uuid.UUID{}
		out := make([]principalAccessChild, 0, len(targets))
		accountsCreated := 0

		for i := range targets {
			child, created, ok := s.grantPrincipalAccessItem(w, r, tx, sess, principal, req, targets[i], &parentID, envPaths, accountByConn, provisionByConn)
			if !ok {
				return nil, nil, false
			}
			if created {
				accountsCreated++
			}
			out = append(out, child)
		}
		return out, map[string]any{
			"accounts_created": accountsCreated,
			"grants":           len(out),
		}, true
	})
}

// grantPrincipalAccessItem применяет один item principal-centric выдачи в
// транзакции tx под parent parentID: обеспечивает общий секрет принципала для
// окружения подключения, находит/создаёт managed-аккаунт (с постановкой
// дочерней account.create при создании) и ставит дочернюю access.grant.
// Возвращает описание ребёнка, created=true для свежесозданного аккаунта и
// ok=false, если ответ уже записан (транзакцию откатывает вызывающий).
func (s *Server) grantPrincipalAccessItem(w http.ResponseWriter, r *http.Request, tx pgx.Tx, sess auth.Session,
	principal principals.Principal, req principalAccessRequest, target principalGrantTarget, parentID *uuid.UUID,
	envPaths map[string]string, accountByConn map[uuid.UUID]inventory.Account, provisionByConn map[uuid.UUID]uuid.UUID) (principalAccessChild, bool, bool) {
	ctx := r.Context()
	env := environmentOf(target.connection)
	identity, err := accountIdentity(target.connection, principal, req.EngineIdentity)
	if err != nil {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"cannot derive account identity for connection %s: %s", target.connection.ID, err))
		return principalAccessChild{}, false, false
	}
	if ok := s.preflightPrincipalAccountProvisioning(w, r, tx, target.connection, identity); !ok {
		return principalAccessChild{}, false, false
	}
	sharedPath, ok := s.ensurePrincipalEnvCredential(w, r, principal.ID, env, envPaths)
	if !ok {
		return principalAccessChild{}, false, false
	}
	acct, created, needsProvision, ok := s.ensurePrincipalAccount(w, r, tx, principal, target.connection, identity, sharedPath, accountByConn)
	if !ok {
		return principalAccessChild{}, false, false
	}

	child := principalAccessChild{
		ConnectionID:   target.connection.ID,
		Environment:    env,
		AccountID:      acct.ID,
		CredentialMode: credentialModeExistingVaultRef,
		AccountCreated: created,
	}
	if needsProvision {
		opID, err := s.createAccountProvision(r, tx, sess, acct, sharedPath, parentID, false)
		if err != nil {
			respondStoreError(ctx, w, err)
			return principalAccessChild{}, false, false
		}
		child.AccountCreateOperationID = &opID
		provisionByConn[target.connection.ID] = opID
	} else if opID, pending := provisionByConn[target.connection.ID]; pending {
		child.AccountCreateOperationID = &opID
	}

	_, waitsForProvision := provisionByConn[target.connection.ID]
	creationID := uuid.Nil
	if waitsForProvision && jobs.IsPostgresStatsPermission(target.permission) {
		creationID = provisionByConn[target.connection.ID]
	}
	grant, err := s.createGrantOperation(r, tx, sess,
		grantTarget{account: acct, permission: target.permission, scope: target.scope, creationOperationID: creationID},
		req.ExpiresAt, req.Confirm, parentID, !waitsForProvision)
	if err != nil {
		respondStoreError(ctx, w, err)
		return principalAccessChild{}, false, false
	}
	child.GrantOperationID = grant.OperationID
	child.BindingID = grant.BindingID
	if provisionID, pending := provisionByConn[target.connection.ID]; pending {
		if err := s.dispatcher.EnqueueOperationSequenceTx(ctx, tx, provisionID, grant.OperationID); err != nil {
			respondStoreError(ctx, w, err)
			return principalAccessChild{}, false, false
		}
	}
	return child, created, true
}

// ensurePrincipalEnvCredential обеспечивает общий секрет принципала для
// окружения (кэшируется в cache на время запроса) и возвращает его путь.
// При ошибке пишет ответ (503 без Vault, 502 на ошибку Vault) и возвращает
// ok=false.
func (s *Server) ensurePrincipalEnvCredential(w http.ResponseWriter, r *http.Request, principalID uuid.UUID, env string, cache map[string]string) (string, bool) {
	if path, ok := cache[env]; ok {
		return path, true
	}
	ctx := r.Context()
	path, _, err := s.credentials.EnsurePrincipalCredential(ctx, principalID, env, func() ([]byte, error) {
		return credentials.GeneratePassword(credentials.DefaultPasswordLength)
	})
	if err != nil {
		if errors.Is(err, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot store principal credential; set GRANTOR_VAULT_ADDR")
			return "", false
		}
		// Ошибка vault-клиента содержит только операцию, mount и path.
		slog.ErrorContext(ctx, "api: ensure principal credential",
			"principal_id", principalID, "environment", env, "error", err)
		respondError(w, http.StatusBadGateway, "failed to prepare principal credential in vault")
		return "", false
	}
	cache[env] = path
	return path, true
}

// ensurePrincipalAccount находит или создаёт managed-аккаунт принципала в
// подключении. Возвращает аккаунт, created=true для свежесозданной строки,
// needsProvision=true когда учётки в целевой системе (ещё) нет и требуется
// account.create, и ok=false, если ответ уже записан.
//
// Новая строка создаётся в статусе provisioning: до подтверждённого
// account.create она лишь резервирует identity. Найденный аккаунт в
// provisioning (предыдущая попытка не дошла до target) или missing
// (discovery не нашёл учётку) переиспользуется и провижинится заново — так
// повторный запрос доступа чинит ситуацию вместо создания второй строки.
// Живой аккаунт (active/disabled) переиспользуется как есть.
//
// Identity, занятая unmanaged- или deleted-аккаунтом, — конфликт
// (link/adopt выполняется отдельно).
func (s *Server) ensurePrincipalAccount(w http.ResponseWriter, r *http.Request, tx pgx.Tx, principal principals.Principal, conn connections.Connection, identity, sharedPath string, cache map[uuid.UUID]inventory.Account) (inventory.Account, bool, bool, bool) {
	ctx := r.Context()
	if acct, ok := cache[conn.ID]; ok {
		return acct, false, false, true
	}

	existing, err := s.inventory.FindAccountByIdentity(ctx, tx, conn.ID, identity)
	switch {
	case err == nil:
		if existing.Ownership != inventory.OwnershipManaged || existing.Status == inventory.AccountDeleted {
			restorable := slices.Contains(conn.Capabilities, string(adapter.CapAccountRestore))
			respondError(w, http.StatusConflict,
				inventory.IdentityConflictReason(identity, conn.ID, existing, restorable))
			return inventory.Account{}, false, false, false
		}
		// Совпадение identity ещё не делает account аккаунтом выбранного
		// принципала. Молчаливое переиспользование отвязанной или чужой строки
		// выдало бы роли target-логину, который затем отсутствует в профиле
		// пользователя. Такой конфликт разрешается только явным link flow.
		if existing.PrincipalID == nil || *existing.PrincipalID != principal.ID {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"identity %q in connection %s belongs to another or unlinked managed account; link it to this principal first",
				identity, conn.ID))
			return inventory.Account{}, false, false, false
		}
		if existing.CredentialMode == nil ||
			*existing.CredentialMode != credentialModeExistingVaultRef ||
			existing.VaultPath != sharedPath {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"identity %q in connection %s is not using this principal credential; link and manage it first",
				identity, conn.ID))
			return inventory.Account{}, false, false, false
		}
		if conn.Engine == "postgres" && existing.Status == inventory.AccountProvisioning {
			if err := guardAccountCreationReceipt(ctx, tx, existing.ID); err != nil {
				respondAccountCreationGuardError(ctx, w, err)
				return inventory.Account{}, false, false, false
			}
		}
		needsProvision := !inventory.IsLiveAccountStatus(existing.Status)
		if needsProvision && !connectionCanCreateAccount(conn) {
			respondAccountCreateUnavailable(w, conn)
			return inventory.Account{}, false, false, false
		}
		cache[conn.ID] = existing
		return existing, false, needsProvision, true
	case !errors.Is(err, inventory.ErrNotFound):
		respondStoreError(ctx, w, err)
		return inventory.Account{}, false, false, false
	}
	if !connectionCanCreateAccount(conn) {
		respondAccountCreateUnavailable(w, conn)
		return inventory.Account{}, false, false, false
	}

	acct, err := s.inventory.CreateProvisioningAccount(ctx, tx, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: identity,
		PrincipalID:    &principal.ID,
		CredentialMode: credentialModeExistingVaultRef,
		VaultPath:      sharedPath,
	})
	if err != nil {
		if errors.Is(err, inventory.ErrAlreadyExists) {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"account %q already exists in connection %s", identity, conn.ID))
			return inventory.Account{}, false, false, false
		}
		respondStoreError(ctx, w, err)
		return inventory.Account{}, false, false, false
	}
	cache[conn.ID] = acct
	return acct, true, true, true
}

func connectionCanCreateAccount(conn connections.Connection) bool {
	if conn.Status != connections.StatusActive ||
		!slices.Contains(connectionCapabilitiesForProjection(conn), string(adapter.CapAccountCreate)) {
		return false
	}
	if conn.Engine != "postgres" {
		return true
	}
	_, err := requirePostgresProvisioningAuthority(conn, adapter.CapAccountCreate)
	return err == nil
}

func respondAccountCreateUnavailable(w http.ResponseWriter, conn connections.Connection) {
	respondError(w, http.StatusConflict, fmt.Sprintf(
		"%s is unavailable for connection %s; link an existing live account or refresh discovery and verify provisioning authority",
		adapter.CapAccountCreate, conn.ID))
}

// preflightPrincipalAccountProvisioning prevents an implicit principal grant
// or manifest apply from materializing a shared credential before it learns
// that this connection cannot create the missing target account. Existing
// live accounts remain usable: membership grant/revoke has its own authority
// contract and must not inherit the SUPERUSER requirement.
func (s *Server) preflightPrincipalAccountProvisioning(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	conn connections.Connection, identity string,
) bool {
	if conn.Engine == "postgres" && postgres.ProtectedRole(identity) {
		respondError(w, http.StatusBadRequest, "system PostgreSQL identities cannot be provisioned or managed")
		return false
	}
	existing, err := s.inventory.FindAccountByIdentity(r.Context(), tx, conn.ID, identity)
	accountErr := err
	needsProvision := errors.Is(accountErr, inventory.ErrNotFound) ||
		(err == nil && existing.Ownership == inventory.OwnershipManaged &&
			!inventory.IsLiveAccountStatus(existing.Status))
	if needsProvision || conn.Engine == "redis" {
		refreshed, loadErr := s.connections.Get(r.Context(), tx, conn.ID)
		if loadErr != nil {
			respondStoreError(r.Context(), w, loadErr)
			return false
		}
		conn = refreshed
	}
	if conn.AuthMode == "none" {
		respondError(w, http.StatusConflict, "authentication_disabled: access provisioning is unavailable")
		return false
	}
	if accountErr == nil && conn.Engine == "postgres" && existing.Ownership == inventory.OwnershipManaged && !inventory.IsLiveAccountStatus(existing.Status) {
		if err := guardAccountCreationReceipt(r.Context(), tx, existing.ID); err != nil {
			respondAccountCreationGuardError(r.Context(), w, err)
			return false
		}
	}
	switch {
	case errors.Is(accountErr, inventory.ErrNotFound):
		if !connectionCanCreateAccount(conn) {
			respondAccountCreateUnavailable(w, conn)
			return false
		}
		return true
	case accountErr != nil:
		respondStoreError(r.Context(), w, accountErr)
		return false
	case existing.Ownership == inventory.OwnershipManaged &&
		!inventory.IsLiveAccountStatus(existing.Status) && !connectionCanCreateAccount(conn):
		respondAccountCreateUnavailable(w, conn)
		return false
	default:
		return true
	}
}

// enqueueAccountProvision создаёт дочернюю операцию account.create для
// провижининга роли в целевой БД и ставит её в очередь. Пароль читается
// worker из общего секрета принципала по sharedPath.
//
// Ожидаемый статус берётся из самого аккаунта, а не фиксируется active:
// свежая строка и неудавшаяся прошлая попытка находятся в provisioning,
// исчезнувшая с target учётка — в missing. Успешный create переводит
// любой из них в active (SetAccountStatusGuarded в executor).
func (s *Server) enqueueAccountProvision(r *http.Request, tx pgx.Tx, sess auth.Session, acct inventory.Account, sharedPath string, parentID *uuid.UUID) (uuid.UUID, error) {
	return s.createAccountProvision(r, tx, sess, acct, sharedPath, parentID, true)
}

func (s *Server) createAccountProvision(r *http.Request, tx pgx.Tx, sess auth.Session, acct inventory.Account, sharedPath string, parentID *uuid.UUID, enqueue bool) (uuid.UUID, error) {
	ctx := r.Context()
	conn, err := s.connections.Get(ctx, tx, acct.ConnectionID)
	if err != nil {
		return uuid.Nil, err
	}
	var postgresPins postgresProvisioningPins
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, adapter.CapAccountCreate)
	}
	if err != nil || !connectionCanCreateAccount(conn) {
		return uuid.Nil, fmt.Errorf("%s is unavailable for connection %s: %w",
			adapter.CapAccountCreate, conn.ID, connections.ErrStatusConflict)
	}
	if conn.Engine == "postgres" && acct.Status == inventory.AccountProvisioning {
		if err := guardAccountCreationReceipt(ctx, tx, acct.ID); err != nil {
			return uuid.Nil, err
		}
	}
	var credentialVersion int
	if conn.Engine == "postgres" {
		_, password, version, readErr := s.credentials.GetAccountCredentialSnapshot(ctx, sharedPath, acct.EngineIdentity)
		clear(password)
		if readErr != nil {
			return uuid.Nil, readErr
		}
		credentialVersion = version
	}
	reserved, err := s.inventory.ReserveAccountLifecycle(ctx, tx, acct.ID, acct.Status)
	if err != nil {
		return uuid.Nil, err
	}
	if conn.Engine == "postgres" && acct.Status == inventory.AccountMissing {
		if err := s.inventory.SetAccountStatusGuarded(ctx, tx, acct.ID, inventory.AccountMissing, inventory.AccountProvisioning, reserved.LifecycleVersion); err != nil {
			return uuid.Nil, err
		}
		acct.Status = inventory.AccountProvisioning
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, SharedCredentialPath: sharedPath, CredentialVaultVersion: credentialVersion,
		ExpectedStatus: acct.Status, ExpectedLifecycleVersion: reserved.LifecycleVersion,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedTargetIdentity:        postgresPins.TargetIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("api: marshal account payload: %w", err)
	}
	operationKind := jobs.KindAccountCreate
	if conn.Engine == "postgres" {
		operationKind = jobs.KindPostgresAccountProvisionV1
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:          operationKind,
		ParentID:      parentID,
		ConnectionID:  &acct.ConnectionID,
		AccountID:     &acct.ID,
		Payload:       payload,
		ActorType:     sess.ActorType(),
		ActorID:       sess.ActorID(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		return uuid.Nil, err
	}
	if enqueue {
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			return uuid.Nil, err
		}
	}
	return op.ID, nil
}

// principalRotateChild — одна дочерняя ротация в ответе.
type principalRotateChild struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	Environment  string    `json:"environment"`
	AccountID    uuid.UUID `json:"account_id"`
	OperationID  uuid.UUID `json:"operation_id"`
}

// groupRotatablePrincipalAccounts группирует по окружению их подключения
// managed-аккаунты принципала на общем секрете (accountRotatableOnSharedCredential:
// existing_vault_ref, свой principal-scoped путь, статус active) — только они
// подлежат ротации. onlyEnv != ""
// ограничивает выборку одним окружением. Порядок окружений детерминирован
// (envOrder — порядок первого появления). По каждому затронутому окружению
// проверяется scope operator: отказ — 403 на весь запрос. При ошибке (scope
// или чтение connection) пишет ответ и возвращает ok=false.
func (s *Server) groupRotatablePrincipalAccounts(w http.ResponseWriter, r *http.Request, sess auth.Session,
	accounts []inventory.Account, onlyEnv string) (map[string][]inventory.Account, []string, bool) {
	ctx := r.Context()
	byEnv := map[string][]inventory.Account{}
	envOrder := make([]string, 0)
	connEnv := map[uuid.UUID]string{}
	connectionByID := map[uuid.UUID]connections.Connection{}
	for i := range accounts {
		acct := accounts[i]
		// Защита в глубину: указатель обязан вести в раздел ИМЕННО этого
		// принципала. Аккаунт с чужим principal-scoped путём по определению
		// не сидит на общем секрете этого принципала — ротация записала бы
		// ему пароль из чужого раздела. Исключаем из группы и сигналим:
		// отказывать всему запросу нельзя, ротация остальных аккаунтов —
		// как раз то, ради чего её вызвали.
		if inventory.AccountCredentialPointerForeign(acct) {
			slog.WarnContext(ctx, "api: skip account with foreign principal credential reference",
				"account_id", acct.ID, "principal_id", acct.PrincipalID)
			continue
		}
		// Тот же предикат, которым ротация одного аккаунта решает, нужен ли
		// оператору осознанный выбор (handlers_accounts.go): набор
		// затронутых аккаунтов в 409-контексте обязан совпадать с тем, что
		// эта ручка реально ротирует.
		if !accountRotatableOnSharedCredential(acct) {
			continue
		}
		env, ok := connEnv[acct.ConnectionID]
		if !ok {
			conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			env = environmentOf(conn)
			connEnv[acct.ConnectionID] = env
			connectionByID[acct.ConnectionID] = conn
		}
		if onlyEnv != "" && env != onlyEnv {
			continue
		}

		// Scope: operator ротирует секреты только в своих окружениях. Отказ
		// по любому затрагиваемому окружению — 403 на весь запрос.
		if err := s.checkConnectionScope(ctx, sess, env); err != nil {
			s.respondScopeError(ctx, w, err)
			return nil, nil, false
		}
		if err := requireConnectionCapability(connectionByID[acct.ConnectionID], adapter.CapCredentialRotate); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return nil, nil, false
		}
		if _, seen := byEnv[env]; !seen {
			envOrder = append(envOrder, env)
		}
		byEnv[env] = append(byEnv[env], acct)
	}
	return byEnv, envOrder, true
}

// principalRotateRequest — необязательное тело POST /principals/{id}/rotate.
type principalRotateRequest struct {
	// Confirm — подтверждение масштаба ротации. Обязательно, когда новый
	// пароль получают больше GRANTOR_ROTATION_CONFIRM_THRESHOLD аккаунтов
	// (rotationRequiresConfirm): смена общего пароля разом ломает соединения
	// во всех этих системах, и оператор должен увидеть их число до, а не
	// после. Именно флаг запроса, а не approval-workflow: ротацию часто
	// делают в инциденте.
	Confirm bool `json:"confirm"`
}

// principalRotateScopeJSON — масштаб отклонённой ротации: сколько аккаунтов
// и в каких окружениях она затронет.
type principalRotateScopeJSON struct {
	AffectedAccounts int      `json:"affected_accounts"`
	Environments     []string `json:"environments"`
	ConfirmThreshold int      `json:"confirm_threshold"`
}

// principalRotateConfirmJSON — 409-ответ «ротация не подтверждена».
type principalRotateConfirmJSON struct {
	Error    string                   `json:"error"`
	Code     string                   `json:"code"`
	Rotation principalRotateScopeJSON `json:"rotation"`
}

// rotatePrincipalCredentials — POST /api/v1/principals/{id}/rotate
// (operator): ротация общего секрета принципала по окружениям. Для каждого
// окружения, где у принципала есть managed-аккаунты на общем секрете,
// пишется новая версия пароля в Vault и ставится по одной операции
// credential.rotate на аккаунт (best-effort: недоступный кластер остаётся
// на старом пароле до retry). Query-параметр environment ограничивает
// ротацию одним окружением.
//
// Масштабная ротация (больше GRANTOR_ROTATION_CONFIRM_THRESHOLD аккаунтов)
// требует явного {"confirm":true} в теле и иначе отвечает 409 с кодом
// rotation_requires_confirm и числом затронутых аккаунтов.
func (s *Server) rotatePrincipalCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req principalRotateRequest
	if !decodeOptionalJSON(w, r, &req) {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	onlyEnv := r.URL.Query().Get("environment")

	principal, err := s.principals.Get(ctx, s.pool, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Ротация выключенного или offboarded-принципала запрещена: секрет
	// выключенного не должен обновляться (и тем более выдаваться), у
	// deleted секретов уже нет.
	if msg := principalStatusBlocks(principal.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}
	accounts, err := s.inventory.ListAccountsByPrincipal(ctx, s.pool, principal.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}

	byEnv, envOrder, ok := s.groupRotatablePrincipalAccounts(w, r, sess, accounts, onlyEnv)
	if !ok {
		return
	}
	if len(envOrder) == 0 {
		msg := "principal has no managed shared credentials to rotate"
		if onlyEnv != "" {
			msg = fmt.Sprintf("%s in environment %q", msg, onlyEnv)
		}
		respondError(w, http.StatusConflict, msg)
		return
	}

	affected := 0
	for _, env := range envOrder {
		affected += len(byEnv[env])
	}
	if !req.Confirm && rotationRequiresConfirm(s.rotationConfirmThreshold, affected) {
		respondJSON(w, http.StatusConflict, principalRotateConfirmJSON{
			Error: fmt.Sprintf(
				"rotating the shared credential replaces the password of %d accounts in environment(s) %s: "+
					"repeat with {\"confirm\":true} to confirm the scope",
				affected, strings.Join(envOrder, ", ")),
			Code: errCodeRotationRequiresConfirm,
			Rotation: principalRotateScopeJSON{
				AffectedAccounts: affected,
				Environments:     envOrder,
				ConfirmThreshold: s.rotationConfirmThreshold,
			},
		})
		return
	}

	s.runBulkParent(w, r, sess, bulkParent{
		kind:             jobs.KindBulkPrincipalRotate,
		principalID:      &principal.ID,
		payload:          map[string]any{"environments": envOrder, "confirmed": req.Confirm},
		payloadErrPrefix: "api: marshal principal rotate payload",
		auditAction:      auditActionPrincipalRotateRequest,
		commitErrPrefix:  "api: commit principal rotate",
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		selected := make([]inventory.Account, 0, len(accounts))
		for _, env := range envOrder {
			selected = append(selected, byEnv[env]...)
		}
		if !s.lockCredentialConnections(w, r, tx, selected, adapter.CapCredentialRotate) {
			return nil, nil, false
		}

		out := make([]principalRotateChild, 0, len(accounts))
		for _, env := range envOrder {
			reserved, ok := s.reserveRotationAccounts(w, r, tx, byEnv[env])
			if !ok {
				return nil, nil, false
			}
			envChildren, ok := s.rotatePrincipalEnvChildren(w, r, tx, sess, principal, env, reserved, &parentID)
			if !ok {
				return nil, nil, false
			}
			out = append(out, envChildren...)
		}
		return out, map[string]any{
			"environments": envOrder,
			"accounts":     len(out),
		}, true
	})
}

// reserveRotationAccounts резервирует следующее поколение lifecycle каждому
// аккаунту и возвращает перечитанные строки. Резерв обязан быть РОВНО ОДИН
// на аккаунт в пределах транзакции: каждый вызов двигает версию, а дети
// пинят ту, что видели при постановке, — второй резерв обесценил бы
// операции, поставленные после первого, и они упали бы с lifecycle
// conflict. Поэтому каскад, ставящий аккаунту несколько разных операций,
// резервирует его сам и передаёт готовые строки сюда.
func (s *Server) reserveRotationAccounts(w http.ResponseWriter, r *http.Request, tx pgx.Tx,
	accts []inventory.Account) ([]inventory.Account, bool) {
	ctx := r.Context()
	reserved := make([]inventory.Account, 0, len(accts))
	for i := range accts {
		if accts[i].Status == inventory.AccountDeleted {
			respondError(w, http.StatusConflict, "deleted account credential cannot be rotated")
			return nil, false
		}
		acct, err := s.inventory.ReserveAccountLifecycle(ctx, tx, accts[i].ID, accts[i].Status)
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, false
		}
		reserved = append(reserved, acct)
	}
	return reserved, true
}

// rotatePrincipalEnvChildren ротирует общий секрет принципала для одного
// окружения и ставит по одной дочерней credential.rotate на каждый его
// аккаунт под parent parentID. Аккаунты обязаны быть УЖЕ зарезервированы
// вызывающим (см. reserveRotationAccounts): дети пинят ту версию lifecycle,
// которую несут переданные строки. Новая версия секрета пишется в Vault до
// постановки операций, чтобы worker прочитал уже обновлённый пароль
// (best-effort: недоступный кластер остаётся на старом пароле до retry).
// Пишет ответ (503/502 при отказе Vault, store-ошибки) и возвращает
// ok=false при ошибке; транзакцию откатывает вызывающий.
func (s *Server) rotatePrincipalEnvChildren(w http.ResponseWriter, r *http.Request, tx pgx.Tx, sess auth.Session,
	principal principals.Principal, env string, reservedAccounts []inventory.Account, parentID *uuid.UUID) ([]principalRotateChild, bool) {
	ctx := r.Context()
	for _, account := range reservedAccounts {
		conn, loadErr := s.connections.Get(ctx, tx, account.ConnectionID)
		if loadErr != nil {
			respondStoreError(ctx, w, loadErr)
			return nil, false
		}
		if err := requireConnectionCapability(conn, adapter.CapCredentialRotate); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return nil, false
		}
	}
	newPassword, genErr := credentials.GeneratePassword(credentials.DefaultPasswordLength)
	if genErr != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: generate principal password: %w", genErr))
		return nil, false
	}
	_, rotErr := s.credentials.RotatePrincipalCredential(ctx, principal.ID, env, newPassword)
	clear(newPassword)
	if rotErr != nil {
		if errors.Is(rotErr, credentials.ErrVaultNotConfigured) {
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot rotate principal credential; set GRANTOR_VAULT_ADDR")
			return nil, false
		}
		slog.ErrorContext(ctx, "api: rotate principal credential",
			"principal_id", principal.ID, "environment", env, "error", rotErr)
		respondError(w, http.StatusBadGateway, "failed to rotate principal credential in vault")
		return nil, false
	}
	sharedPath, pathErr := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), env)
	if pathErr != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: principal credential path: %w", pathErr))
		return nil, false
	}

	children := make([]principalRotateChild, 0, len(reservedAccounts))
	for _, acct := range reservedAccounts {
		payload, err := json.Marshal(jobs.AccountPayload{
			AccountID: acct.ID, SharedCredentialPath: sharedPath,
			ExpectedStatus: acct.Status, ExpectedLifecycleVersion: acct.LifecycleVersion,
		})
		if err != nil {
			respondStoreError(ctx, w, fmt.Errorf("api: marshal account payload: %w", err))
			return nil, false
		}
		op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
			Kind:          jobs.KindCredentialRotate,
			ParentID:      parentID,
			ConnectionID:  &acct.ConnectionID,
			AccountID:     &acct.ID,
			PrincipalID:   &principal.ID,
			Payload:       payload,
			ActorType:     sess.ActorType(),
			ActorID:       sess.ActorID(),
			CorrelationID: uuid.NewString(),
		})
		if err != nil {
			respondStoreError(ctx, w, err)
			return nil, false
		}
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			respondStoreError(ctx, w, err)
			return nil, false
		}
		children = append(children, principalRotateChild{
			ConnectionID: acct.ConnectionID,
			Environment:  env,
			AccountID:    acct.ID,
			OperationID:  op.ID,
		})
	}
	return children, true
}

// sharePrincipalCredential — POST /api/v1/principals/{id}/share?environment=
// (operator): одноразовая выдача общего пароля принципала для окружения
// через Yopass (раздел 18). Ссылка возвращается ровно один раз; в audit
// пишется только факт выдачи — без ссылки и без пароля.
func (s *Server) sharePrincipalCredential(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	principalID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	// Per-subject лимит credential reveal/share (ADR-0007, R2) + метрика
	// попытки и детекция аномальной частоты (разделы 24/25). При превышении
	// лимита — 429.
	if !s.guardReveal(w, r, sess, metrics.OperationPrincipalShare) {
		return
	}
	env := r.URL.Query().Get("environment")
	if env == "" {
		respondError(w, http.StatusBadRequest, "environment query parameter is required")
		return
	}
	// Scope: operator выдаёт секрет только для своих окружений.
	if err := s.checkConnectionScope(ctx, sess, env); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}

	principal, err := s.principals.Get(ctx, s.pool, principalID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Секрет выключенного принципала не выдаётся (каскад disable отключил
	// его аккаунты); у deleted секретов уже нет.
	if msg := principalStatusBlocks(principal.Status, true); msg != "" {
		respondError(w, http.StatusConflict, msg)
		return
	}

	logins, err := s.principalEnvironmentLogins(ctx, principal, env)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	link, err := s.credentials.SharePrincipalCredential(ctx, principal.ID, principal.DisplayName, logins, env, shareTTLHours*time.Hour)
	if err != nil {
		switch {
		case errors.Is(err, credentials.ErrYopassNotConfigured):
			respondError(w, http.StatusServiceUnavailable,
				"yopass is not configured: one-time credential links are unavailable; set GRANTOR_YOPASS_API_URL")
		case errors.Is(err, credentials.ErrVaultNotConfigured):
			respondError(w, http.StatusServiceUnavailable,
				"vault is not configured: cannot read principal credential; set GRANTOR_VAULT_ADDR")
		case errors.Is(err, vault.ErrNotFound):
			respondError(w, http.StatusNotFound,
				fmt.Sprintf("principal has no shared credential in environment %q", env))
		default:
			// Ошибка не содержит секретов и ссылки (контракты vault/yopass).
			slog.ErrorContext(ctx, "api: share principal credential",
				"principal_id", principal.ID, "environment", env, "error", err)
			respondError(w, http.StatusBadGateway, "failed to create one-time credential link")
		}
		return
	}

	if err := s.writeAudit(ctx, s.pool, audit.Event{
		ActorType:   sess.ActorType(),
		ActorID:     sess.ActorID(),
		Action:      auditActionCredentialShared,
		PrincipalID: &principal.ID,
		Result:      audit.ResultSuccess,
	}, map[string]any{
		"channel":          "yopass",
		"subject":          "principal",
		"environment":      env,
		"expires_in_hours": shareTTLHours,
		"one_time":         true,
	}); err != nil {
		// Выдача без audit-события недопустима: ссылка не возвращается,
		// одноразовый секрет в Yopass истечёт по TTL.
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusCreated, map[string]any{
		"link":             link,
		"expires_in_hours": shareTTLHours,
		"one_time":         true,
	})
}
