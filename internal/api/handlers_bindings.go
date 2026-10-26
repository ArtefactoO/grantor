package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/approval"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// checkGrantTargetsScope проверяет, что все connections целей grant входят в
// окружения operator (scope policies). Дедупликация по connection_id: у bulk
// повторяющиеся connections проверяются один раз. Возвращает nil, если scope к
// сессии не применяется (admin/viewer/disabled).
func (s *Server) checkGrantTargetsScope(ctx context.Context, sess auth.Session, targets []grantTarget) error {
	if !s.scopeApplies(sess) {
		return nil
	}
	seen := make(map[uuid.UUID]bool, len(targets))
	for i := range targets {
		connID := targets[i].account.ConnectionID
		if seen[connID] {
			continue
		}
		seen[connID] = true
		if err := s.checkConnectionScopeByID(ctx, sess, connID); err != nil {
			return err
		}
	}
	return nil
}

// Audit actions мутирующих запросов bindings.
const (
	auditActionGrantRequested        = "access.grant_requested"
	auditActionBulkGrantRequested    = "bulk.grant_requested"
	auditActionAccountRolesRequested = "bulk.account_roles_requested"
	auditActionObjectACLRequested    = "bulk.object_acl_requested"
	auditActionRevokeRequested       = "access.revoke_requested"
)

// maxBulkItems — предел элементов одного bulk-запроса: защита от
// случайной постановки тысяч операций одним запросом.
const maxBulkItems = 100

// dangerousGrantCheck применяет правило dangerous permissions (раздел
// 7.3 архитектуры): выдача требует роли admin и явного подтверждения.
// Возвращает HTTP-статус и сообщение; статус 0 — проверка пройдена.
// Чистая функция для юнит-тестов.
func dangerousGrantCheck(role auth.Role, confirmed bool) (int, string) {
	if !role.Allows(auth.RoleAdmin) {
		return http.StatusForbidden, "granting dangerous permission requires admin role"
	}
	if !confirmed {
		return http.StatusBadRequest, "granting dangerous permission requires confirm=true"
	}
	return 0, ""
}

// weakAuthGrantCheck требует явного подтверждения для выдачи права учётной
// записи, которая принимает ЛЮБОЙ пароль (Redis ACL nopass).
//
// Признак лежал только в атрибутах инвентаря: доступ такой учётке выдавался
// молча, а фактически он выдавался всем, кто знает имя пользователя.
// Подтверждение здесь — не бюрократия, а единственное место, где оператор
// узнаёт об этом до выдачи. Роль admin не требуется: слабая аутентификация —
// свойство учётки, а не эскалация прав (ср. dangerousGrantCheck).
//
// Проверка стоит в общей точке всех путей выдачи (одиночной, bulk,
// principal-centric и манифеста): гейт, закрывающий одну дверь из четырёх,
// не гейт.
func weakAuthGrantCheck(acct inventory.Account, confirmed bool) error {
	if confirmed || !adapter.AttrBool(decodeAttributes(acct.Attributes), "nopass") {
		return nil
	}
	return fmt.Errorf("%w: account %s accepts any password (nopass); pass confirm=true to grant access to it",
		errWeakAuthNotConfirmed, acct.EngineIdentity)
}

// errWeakAuthNotConfirmed — отказ выдачи на учётку без пароля. Отдельная
// ошибка нужна, чтобы вызывающий ответил 400, а не 500.
var errWeakAuthNotConfirmed = errors.New("weak account authentication is not confirmed")

// bulkBindingItem — один элемент bulk-запроса (и запроса одного grant:
// createBindingRequest переиспользует поля). Незаданный ScopeResourceID
// означает «область берётся из permission-определения»
// (inventory.EffectiveBindingScope), а не «connection-wide».
type bulkBindingItem struct {
	AccountID       uuid.UUID  `json:"account_id"`
	PermissionID    uuid.UUID  `json:"permission_id"`
	ScopeResourceID *uuid.UUID `json:"scope_resource_id"`
}

// validate проверяет обязательные идентификаторы элемента.
func (it *bulkBindingItem) validate() error {
	if it.AccountID == uuid.Nil {
		return errors.New("account_id is required")
	}
	if it.PermissionID == uuid.Nil {
		return errors.New("permission_id is required")
	}
	return nil
}

// createBindingRequest — тело POST /api/v1/bindings.
type createBindingRequest struct {
	AccountID       uuid.UUID  `json:"account_id"`
	PermissionID    uuid.UUID  `json:"permission_id"`
	ScopeResourceID *uuid.UUID `json:"scope_resource_id"`
	ExpiresAt       *time.Time `json:"expires_at"`
	// Confirm — явное подтверждение выдачи dangerous permission.
	Confirm bool `json:"confirm"`
}

// validateExpiresAt проверяет срок действия binding: он обязан быть в
// будущем.
//
// Момент в прошлом принимался молча: грант применялся, получал synced и
// только следующий прогон обслуживания (раз в час) обнаруживал истёкший
// срок. То есть запрос «дай доступ до вчера» выдавал рабочий доступ на
// неопределённое время вместо отказа. nil — бессрочный binding, это
// нормальный случай.
func validateExpiresAt(expiresAt *time.Time, now time.Time) error {
	if expiresAt == nil {
		return nil
	}
	if !expiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}
	return nil
}

// bulkCreateBindingsRequest — тело POST /api/v1/bindings/bulk.
type bulkCreateBindingsRequest struct {
	Items   []bulkBindingItem `json:"items"`
	Confirm bool              `json:"confirm"`
}

// manageAccountRolesRequest описывает дельту набора ролей одного аккаунта.
// Добавления задаются permission id без scope (как прежний drawer выдачи),
// удаления — конкретными binding id, чтобы не терять гранулярность.
type manageAccountRolesRequest struct {
	AddPermissionIDs []uuid.UUID `json:"add_permission_ids"`
	RemoveBindingIDs []uuid.UUID `json:"remove_binding_ids"`
	Confirm          bool        `json:"confirm"`
}

func (req *manageAccountRolesRequest) validate() error {
	total := len(req.AddPermissionIDs) + len(req.RemoveBindingIDs)
	if total == 0 {
		return errors.New("at least one role change is required")
	}
	if total > maxBulkItems {
		return fmt.Errorf("role changes must contain at most %d elements", maxBulkItems)
	}
	seenPermissions := make(map[uuid.UUID]struct{}, len(req.AddPermissionIDs))
	for i, id := range req.AddPermissionIDs {
		if id == uuid.Nil {
			return fmt.Errorf("add_permission_ids[%d] is required", i)
		}
		if _, exists := seenPermissions[id]; exists {
			return fmt.Errorf("add_permission_ids[%d] is duplicated", i)
		}
		seenPermissions[id] = struct{}{}
	}
	seenBindings := make(map[uuid.UUID]struct{}, len(req.RemoveBindingIDs))
	for i, id := range req.RemoveBindingIDs {
		if id == uuid.Nil {
			return fmt.Errorf("remove_binding_ids[%d] is required", i)
		}
		if _, exists := seenBindings[id]; exists {
			return fmt.Errorf("remove_binding_ids[%d] is duplicated", i)
		}
		seenBindings[id] = struct{}{}
	}
	return nil
}

// validate проверяет размер списка и каждый элемент.
func (req *bulkCreateBindingsRequest) validate() error {
	if len(req.Items) == 0 {
		return errors.New("items must be a non-empty list")
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

// grantTarget — загруженные и проверенные сущности одного grant.
type grantTarget struct {
	account             inventory.Account
	permission          inventory.Permission
	scope               *inventory.Resource
	creationOperationID uuid.UUID
}

// lockAccountLifecycleSnapshot сериализует enqueue access.* с lifecycle
// reservation того же account. Payload получает incarnation, существовавшую
// в момент создания операции; после delete+restore такой job fail-closed до
// любого target side effect.
func lockAccountLifecycleSnapshot(ctx context.Context, tx pgx.Tx, accountID uuid.UUID,
	allowedParentID *uuid.UUID, allowConnectionAdmin bool,
) (inventory.AccountStatus, int64, error) {
	var status inventory.AccountStatus
	var version int64
	var attributes json.RawMessage
	err := tx.QueryRow(ctx, `
		select status, lifecycle_version, attributes from accounts where id = $1 for update`, accountID,
	).Scan(&status, &version, &attributes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", 0, fmt.Errorf("inventory: account %s: %w", accountID, inventory.ErrNotFound)
		}
		return "", 0, fmt.Errorf("api: lock account lifecycle %s: %w", accountID, err)
	}
	if connectionAdmin, _ := decodeAttributes(attributes)[adapter.AttrConnectionAdmin].(bool); connectionAdmin && !allowConnectionAdmin {
		return status, version, fmt.Errorf(
			"account %s is the connection admin identity and its access cannot be changed through ordinary binding APIs: %w",
			accountID, inventory.ErrBindingTransitionConflict)
	}
	var policyKey string
	err = tx.QueryRow(ctx, `select template_key from role_policies where account_id=$1`, accountID).Scan(&policyKey)
	if err == nil {
		return status, version, fmt.Errorf(
			"account %s is the dedicated identity of role policy %q; its memberships are managed only by the policy lifecycle: %w",
			accountID, policyKey, inventory.ErrBindingTransitionConflict)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return status, version, fmt.Errorf("api: inspect role-policy account %s: %w", accountID, err)
	}
	if status == inventory.AccountDeleted {
		return status, version, fmt.Errorf("account %s is deleted: %w", accountID, inventory.ErrAccountStatusConflict)
	}
	var busy bool
	if err := tx.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and status in ('pending_approval', 'pending', 'running')
			  and (kind like 'account.%' or kind in ('role.create', 'credential.rotate'))
			  and ($2::uuid is null or parent_id is distinct from $2)
		)`, accountID, allowedParentID).Scan(&busy); err != nil {
		return "", 0, fmt.Errorf("api: inspect account lifecycle %s: %w", accountID, err)
	}
	if busy {
		return status, version, fmt.Errorf("account %s lifecycle operation is pending: %w",
			accountID, inventory.ErrAccountLifecycleBusy)
	}
	return status, version, nil
}

// structuralRolePolicyBinding identifies a legacy delegation edge: the
// connection admin is a direct member of the
// managed policy role WITH ADMIN OPTION. It is infrastructure needed to keep
// Apply/Repair possible, not a user access assignment. Ordinary memberships
// fail at least one of these three independently discovered predicates and
// remain mutable through the normal binding lifecycle.
func structuralRolePolicyBinding(acct inventory.Account, permission inventory.Permission, binding inventory.Binding) bool {
	permissionAttrs := decodeAttributes(permission.Attributes)
	policyKey, _ := permissionAttrs["role_policy_key"].(string)
	accountAttrs := decodeAttributes(acct.Attributes)
	connectionAdmin, _ := accountAttrs[adapter.AttrConnectionAdmin].(bool)
	bindingAttrs := decodeAttributes(binding.ObservedAttributes)
	adminOption, _ := bindingAttrs["admin_option"].(bool)
	return policyKey != "" && connectionAdmin && adminOption
}

func requireMutableRolePolicyBinding(acct inventory.Account, permission inventory.Permission, binding inventory.Binding) error {
	if !structuralRolePolicyBinding(acct, permission, binding) {
		return nil
	}
	return fmt.Errorf(
		"binding %s is structural PostgreSQL role-policy delegation and cannot be changed through access APIs: %w",
		binding.ID, inventory.ErrBindingTransitionConflict)
}

// loadGrantTarget загружает account/permission/scope элемента и
// проверяет их согласованность (одно connection, permission assignable) плюс
// поддержку выдачи прав движком подключения. При ошибке пишет ответ и
// возвращает ok=false.
func (s *Server) loadGrantTarget(w http.ResponseWriter, r *http.Request, item bulkBindingItem) (grantTarget, bool) {
	ctx := r.Context()

	acct, err := s.inventory.GetAccount(ctx, s.pool, item.AccountID)
	if err != nil {
		if errors.Is(err, inventory.ErrNotFound) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("account %s not found", item.AccountID))
			return grantTarget{}, false
		}
		respondStoreError(ctx, w, err)
		return grantTarget{}, false
	}
	// Статус принципала блокирует выдачу и здесь, а не только на
	// principal-centric пути (grantPrincipalAccess): аккаунт-центричная
	// выдача ведёт к тому же результату — отключённый или offboarded
	// пользователь получает новое работающее право. Проверка одна на оба
	// пути, иначе гейт закрывает одну дверь и оставляет открытой соседнюю.
	if acct.PrincipalID != nil {
		p, err := s.principals.Get(ctx, s.pool, *acct.PrincipalID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return grantTarget{}, false
		}
		if msg := principalStatusBlocks(p.Status, true); msg != "" {
			respondError(w, http.StatusConflict, fmt.Sprintf("account %s: %s", acct.ID, msg))
			return grantTarget{}, false
		}
	}
	// Движок без access.grant отклонил бы изменение уже в adapter
	// (adapter.ErrUnsupportedChange). Отказ детерминирован, поэтому честнее
	// ответить 409 здесь, чем создавать заведомо обречённую операцию (тот же
	// приём — у account.restore). Проверка идёт по manifest, без обращения к
	// целевой системе.
	conn, err := s.connections.Get(ctx, s.pool, acct.ConnectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return grantTarget{}, false
	}
	sess, ok := s.session(w, r)
	if !ok {
		return grantTarget{}, false
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return grantTarget{}, false
	}
	if err := requireConnectionCapability(conn, adapter.CapAccessGrant); err != nil {
		respondStoreError(ctx, w, err)
		return grantTarget{}, false
	}
	perm, scope, ok := s.loadGrantPermissionScope(w, r, acct.ConnectionID,
		fmt.Sprintf("account %s", acct.ID), item.PermissionID, item.ScopeResourceID)
	if !ok {
		return grantTarget{}, false
	}
	if err := requireStatsMembershipConnection(conn, perm); err != nil {
		respondStoreError(ctx, w, err)
		return grantTarget{}, false
	}
	return grantTarget{account: acct, permission: perm, scope: scope}, true
}

// loadGrantPermissionScope загружает permission грант-запроса и проверяет его
// согласованность с подключением connectionID (та же принадлежность,
// assignable) плюс опциональный scope-resource того же подключения. subject —
// человекочитаемая привязка для сообщений об ошибке принадлежности: "account
// <id>" у per-account запроса (loadGrantTarget) и id подключения у
// principal-centric/manifest (loadPrincipalGrantTarget). Единый источник этой
// валидации для обоих connection-source (account-entry vs connection-entry).
// При ошибке пишет ответ и возвращает ok=false.
//
// Незаданный scope здесь НЕ подставляется: область действия выводится из
// permission-определения единственной точкой постановки грантов (createGrant,
// inventory.EffectiveBindingScope), чтобы manifest apply и API получили
// одинаковый binding. Явно заданная область, противоречащая собственной
// области permission, отклоняется: такой binding заведомо не совпал бы с
// observed-состоянием (см. doc-комментарий inventory/scope.go).
func (s *Server) loadGrantPermissionScope(w http.ResponseWriter, r *http.Request, connectionID uuid.UUID,
	subject string, permissionID uuid.UUID, scopeResourceID *uuid.UUID) (inventory.Permission, *inventory.Resource, bool) {
	ctx := r.Context()

	perm, err := s.inventory.GetPermission(ctx, s.pool, permissionID)
	if err != nil {
		if errors.Is(err, inventory.ErrNotFound) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("permission %s not found", permissionID))
			return inventory.Permission{}, nil, false
		}
		respondStoreError(ctx, w, err)
		return inventory.Permission{}, nil, false
	}
	if perm.ConnectionID != connectionID {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"permission %s belongs to another connection than %s", perm.ID, subject))
		return inventory.Permission{}, nil, false
	}
	if !perm.Assignable {
		respondError(w, http.StatusBadRequest, fmt.Sprintf("permission %q is not assignable", perm.ExternalID))
		return inventory.Permission{}, nil, false
	}
	// 409, а не 400: запрос корректен, конфликтует наблюдаемое состояние —
	// права в целевой системе больше нет. Раньше такая выдача уходила в
	// очередь и падала уже в worker.
	if perm.Status == inventory.PermissionMissing {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"permission %q is missing from the target system", perm.ExternalID))
		return inventory.Permission{}, nil, false
	}
	if scopeResourceID == nil {
		return perm, nil, true
	}
	if inventory.ScopeConflicts(perm, scopeResourceID) {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"permission %q is defined on its own scope resource %s; scope_resource_id %s contradicts it",
			perm.ExternalID, *perm.ScopeResourceID, *scopeResourceID))
		return inventory.Permission{}, nil, false
	}

	res, err := s.inventory.GetResource(ctx, s.pool, *scopeResourceID)
	if err != nil {
		if errors.Is(err, inventory.ErrNotFound) {
			respondError(w, http.StatusNotFound, fmt.Sprintf("scope resource %s not found", *scopeResourceID))
			return inventory.Permission{}, nil, false
		}
		respondStoreError(ctx, w, err)
		return inventory.Permission{}, nil, false
	}
	if res.ConnectionID != connectionID {
		respondError(w, http.StatusBadRequest, fmt.Sprintf(
			"scope resource %s belongs to another connection than %s", res.ID, subject))
		return inventory.Permission{}, nil, false
	}
	return perm, &res, true
}

// grantChild — созданная пара binding + операция в ответах grant.
type grantChild struct {
	OperationID  uuid.UUID `json:"operation_id"`
	BindingID    uuid.UUID `json:"binding_id"`
	AccountID    uuid.UUID `json:"account_id"`
	PermissionID uuid.UUID `json:"permission_id"`
	// Status — статус созданной операции: pending (сразу в очередь) или
	// pending_approval (опасный грант при включённом approval gate ждёт явного
	// approve от admin, self-approval разрешён, ADR-0010).
	Status operations.Status `json:"status"`
}

// createGrant создаёт binding (desired present) и операцию access.grant
// с enqueue в переданной транзакции. parentID != nil делает операцию
// дочерней bulk parent.
//
// Область действия binding нормализуется здесь, а не в каждом вызывающем:
// createGrant — единственная точка постановки грантов (одиночный/bulk/
// principal-centric/manifest), поэтому вывод scope из permission-определения
// (inventory.EffectiveBindingScope) применяется ко всем путям сразу и API, UI
// и манифест дают один и тот же binding.
func (s *Server) createGrant(r *http.Request, tx pgx.Tx, sess auth.Session, target grantTarget, expiresAt *time.Time, confirmed bool, parentID *uuid.UUID) (grantChild, error) {
	return s.createGrantOperation(r, tx, sess, target, expiresAt, confirmed, parentID, true)
}

// createGrantOperation создаёт desired binding и operation. enqueue=false
// используется только явной последовательностью account.create ->
// access.grant: job гранта поставит worker после успешного provisioning.
func (s *Server) createGrantOperation(r *http.Request, tx pgx.Tx, sess auth.Session, target grantTarget, expiresAt *time.Time, confirmed bool, parentID *uuid.UUID, enqueue bool) (grantChild, error) {
	ctx := r.Context()
	conn, err := s.connections.Get(ctx, tx, target.account.ConnectionID)
	if err != nil {
		return grantChild{}, err
	}
	if err := requireConnectionCapability(conn, adapter.CapAccessGrant); err != nil {
		return grantChild{}, err
	}
	if err := weakAuthGrantCheck(target.account, confirmed); err != nil {
		return grantChild{}, err
	}
	_, lifecycleVersion, err := lockAccountLifecycleSnapshot(ctx, tx, target.account.ID, parentID, false)
	if err != nil {
		return grantChild{}, err
	}
	var statsPins *postgres.StatsMembershipPins
	var objectPins *adapter.PostgresObjectACLPins
	operationKind := jobs.KindAccessGrant
	if jobs.IsPostgresObjectPermission(target.permission) {
		operationKind = jobs.KindPostgresObjectACLGrantV1
		objectPins, err = jobs.BuildObjectACLPins(conn, target.account, target.permission, nil)
		if err != nil {
			return grantChild{}, err
		}
	}
	if jobs.IsPostgresStatsPermission(target.permission) {
		if err := requireStatsMembershipConnection(conn, target.permission); err != nil {
			return grantChild{}, err
		}
		current, err := s.inventory.GetAccount(ctx, tx, target.account.ID)
		if err != nil {
			return grantChild{}, err
		}
		statsPins, err = jobs.BuildStatsMembershipPins(ctx, tx, conn, current, target.permission, target.creationOperationID)
		if err != nil {
			return grantChild{}, err
		}
		operationKind = jobs.KindPostgresStatsGrantV1
	}

	var requestedScopeID *uuid.UUID
	if target.scope != nil {
		requestedScopeID = &target.scope.ID
	}
	scopeID := inventory.EffectiveBindingScope(target.permission, requestedScopeID)
	// Прежнее желаемое состояние нужно запомнить ДО upsert: reject операции
	// обязан вернуть binding туда, где он был (в том числе в unmanaged), а
	// EnsureBinding это состояние затирает.
	priorDesired, err := s.priorBindingDesired(ctx, tx, target.account.ID, target.permission.ID, scopeID)
	if err != nil {
		return grantChild{}, err
	}
	// Повтор уже выданного права отсекаем только у живого аккаунта. У
	// аккаунта в provisioning/missing грант заведомо не применился: сам
	// account.create ещё не прошёл, и его повторный запуск обязан заново
	// протащить за собой тот же access.grant. Иначе неудавшийся provisioning
	// становился бы невосстановимым — desired binding уже есть, а операции,
	// которая его выполнит, больше не поставить.
	if inventory.IsLiveAccountStatus(target.account.Status) {
		existingBindings, err := s.inventory.ListBindingsByAccount(ctx, tx, target.account.ID)
		if err != nil {
			return grantChild{}, err
		}
		for i := range existingBindings {
			binding := existingBindings[i]
			if binding.PermissionDefinitionID != target.permission.ID ||
				!uuidPointersEqual(binding.ScopeResourceID, scopeID) {
				continue
			}
			if binding.DesiredState == nil || *binding.DesiredState != inventory.BindingPresent {
				continue
			}
			// Дубликат — только право, про которое не известно, что оно
			// сломано. Binding с доказанной поломкой (снят снаружи либо
			// выдан, но не действует) повторной выдачей как раз и чинится:
			// иначе grantor показывает расхождение и не даёт его устранить,
			// а единственным выходом остаётся удаление binding с реальным
			// отзывом — то есть окно без доступа там, где его и так нет.
			if !inventory.BindingNeedsRepair(binding) {
				return grantChild{}, fmt.Errorf("api: grant account %s permission %s: %w",
					target.account.ID, target.permission.ID, inventory.ErrBindingAlreadyPresent)
			}
		}
	}
	binding, created, err := s.inventory.EnsureBinding(ctx, tx, inventory.EnsureBindingParams{
		AccountID:       target.account.ID,
		PermissionID:    target.permission.ID,
		ScopeResourceID: scopeID,
		DesiredState:    inventory.BindingPresent,
		Source:          string(inventory.BindingSourceService),
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		return grantChild{}, err
	}

	priorState := ""
	if priorDesired != nil {
		priorState = string(*priorDesired)
	}
	payload, err := json.Marshal(jobs.AccessPayload{
		ObjectACL:       objectPins,
		StatsMembership: statsPins, StatsCreationOperationID: target.creationOperationID,
		BindingID:                       binding.ID,
		ExpectedPermissionDefinitionID:  target.permission.ID,
		ExpectedDesiredState:            string(inventory.BindingPresent),
		Confirmed:                       confirmed,
		ExpectedAccountLifecycleVersion: lifecycleVersion,
		PriorDesiredState:               priorState,
		BindingCreated:                  created,
		PermissionAttributes:            pinnedAccessAttributes(target.permission),
	})
	if err != nil {
		return grantChild{}, fmt.Errorf("api: marshal grant payload: %w", err)
	}
	// Approval workflow (ADR-0010): опасный грант при включённом gate
	// создаётся в pending_approval и не выполнится, пока второй admin его не
	// подтвердит. Job всё равно ставится в очередь — worker снимет snooze,
	// как только approve переведёт операцию в pending. createGrant —
	// единственная точка постановки грантов (одиночный/bulk/manifest/
	// principal-centric), поэтому gate применяется здесь один раз.
	requiresApproval := approval.Requires(s.approvalRequired, target.permission.Dangerous)
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:             operationKind,
		ParentID:         parentID,
		ConnectionID:     &target.account.ConnectionID,
		AccountID:        &target.account.ID,
		BindingID:        &binding.ID,
		Payload:          payload,
		ActorType:        sess.ActorType(),
		ActorID:          sess.ActorID(),
		CorrelationID:    uuid.NewString(),
		RequiresApproval: requiresApproval,
	})
	if err != nil {
		return grantChild{}, err
	}
	if enqueue {
		if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
			return grantChild{}, err
		}
	}
	return grantChild{
		OperationID:  op.ID,
		BindingID:    binding.ID,
		AccountID:    target.account.ID,
		PermissionID: target.permission.ID,
		Status:       op.Status,
	}, nil
}

func uuidPointersEqual(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

// createBinding — POST /api/v1/bindings (operator; dangerous — admin с
// confirm): выдача permission аккаунту через операцию access.grant.
func (s *Server) createBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req createBindingRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item := bulkBindingItem{AccountID: req.AccountID, PermissionID: req.PermissionID, ScopeResourceID: req.ScopeResourceID}
	if err := item.validate(); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateExpiresAt(req.ExpiresAt, time.Now()); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	target, ok := s.loadGrantTarget(w, r, item)
	if !ok {
		return
	}
	// Scope: operator выдаёт доступ только в connections своих окружений.
	if err := s.checkConnectionScopeByID(ctx, sess, target.account.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if target.permission.Dangerous {
		if status, msg := dangerousGrantCheck(sess.Role, req.Confirm); status != 0 {
			respondError(w, status, msg)
			return
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	child, err := s.createGrant(r, tx, sess, target, req.ExpiresAt, req.Confirm, nil)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionGrantRequested,
		ConnectionID: &target.account.ConnectionID,
		AccountID:    &target.account.ID,
		OperationID:  &child.OperationID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"binding_id": child.BindingID,
		"permission": target.permission.ExternalID,
		"dangerous":  target.permission.Dangerous,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit create binding: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"operation_id": child.OperationID,
		"binding_id":   child.BindingID,
	})
}

// bulkCreateBindings — POST /api/v1/bindings/bulk (operator; dangerous в
// списке — admin с confirm): parent-операция bulk.grant с дочерними
// access.grant (раздел 19.1 архитектуры). Все children создаются и
// ставятся в очередь одной транзакцией; выполняются независимо, итоговый
// статус parent финализируется в базе при завершении последнего ребёнка
// (detail-ответ дополнительно отдаёт вычисляемый aggregate_status).
func (s *Server) bulkCreateBindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req bulkCreateBindingsRequest
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

	targets := make([]grantTarget, 0, len(req.Items))
	anyDangerous := false
	for i := range req.Items {
		target, ok := s.loadGrantTarget(w, r, req.Items[i])
		if !ok {
			return
		}
		anyDangerous = anyDangerous || target.permission.Dangerous
		targets = append(targets, target)
	}
	// Scope: каждое затрагиваемое connection должно быть в окружениях operator.
	if err := s.checkGrantTargetsScope(ctx, sess, targets); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if anyDangerous {
		if status, msg := dangerousGrantCheck(sess.Role, req.Confirm); status != 0 {
			respondError(w, status, msg)
			return
		}
	}

	s.runBulkParent(w, r, sess, bulkParent{
		kind:             jobs.KindBulkGrant,
		payload:          map[string]any{"items": len(targets), "confirmed": req.Confirm},
		payloadErrPrefix: "api: marshal bulk payload",
		auditAction:      auditActionBulkGrantRequested,
		commitErrPrefix:  "api: commit bulk grant",
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		out := make([]grantChild, 0, len(targets))
		for i := range targets {
			child, err := s.createGrant(r, tx, sess, targets[i], nil, req.Confirm, &parentID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, child)
		}
		return out, map[string]any{"items": len(out), "dangerous": anyDangerous}, true
	})
}

type accountRoleRemoval struct {
	binding    inventory.Binding
	permission inventory.Permission
}

type accountRoleReplacement struct {
	from accountRoleRemoval
	to   grantTarget
}

// partitionAccountRoleChanges канонизирует только ЯВНУЮ пару remove A + add
// B одного non-empty assignment key. Add B при уже занятом слоте без remove A
// отклоняется: угадывать replacement из императивной delta-ручки нельзя.
func partitionAccountRoleChanges(current []inventory.Binding, additions []grantTarget,
	removals []accountRoleRemoval) ([]grantTarget, []accountRoleRemoval, []accountRoleReplacement, error) {
	addByKey := make(map[string][]int)
	removeByKey := make(map[string][]int)
	activeByKey := make(map[string][]inventory.Binding)
	for i := range additions {
		if key := additions[i].permission.AssignmentKey; key != "" {
			addByKey[key] = append(addByKey[key], i)
		}
	}
	for i := range removals {
		if key := removals[i].permission.AssignmentKey; key != "" {
			removeByKey[key] = append(removeByKey[key], i)
		}
	}
	for i := range current {
		b := current[i]
		if b.AssignmentKey == "" || b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			continue
		}
		activeByKey[b.AssignmentKey] = append(activeByKey[b.AssignmentKey], b)
	}

	pairedAdds := make(map[int]bool)
	pairedRemovals := make(map[int]bool)
	replacements := make([]accountRoleReplacement, 0)
	processedKeys := make(map[string]bool, len(addByKey))
	for additionIndex := range additions {
		key := additions[additionIndex].permission.AssignmentKey
		if key == "" || processedKeys[key] {
			continue
		}
		processedKeys[key] = true
		addIndexes := addByKey[key]
		if len(addIndexes) > 1 {
			return nil, nil, nil, fmt.Errorf("assignment %q has multiple added permissions; replacement is ambiguous", key)
		}
		removeIndexes := removeByKey[key]
		if len(removeIndexes) > 1 {
			return nil, nil, nil, fmt.Errorf("assignment %q has multiple removed bindings; replacement is ambiguous", key)
		}
		addIndex := addIndexes[0]
		if len(removeIndexes) == 1 {
			removeIndex := removeIndexes[0]
			pairedAdds[addIndex] = true
			pairedRemovals[removeIndex] = true
			replacements = append(replacements, accountRoleReplacement{
				from: removals[removeIndex],
				to:   additions[addIndex],
			})
			continue
		}

		for _, b := range activeByKey[key] {
			if b.PermissionDefinitionID != additions[addIndex].permission.ID {
				return nil, nil, nil, fmt.Errorf(
					"assignment %q is occupied by binding %s; include it in remove_binding_ids to replace it",
					key, b.ID)
			}
		}
	}

	standaloneAdditions := make([]grantTarget, 0, len(additions)-len(pairedAdds))
	for i := range additions {
		if !pairedAdds[i] {
			standaloneAdditions = append(standaloneAdditions, additions[i])
		}
	}
	standaloneRemovals := make([]accountRoleRemoval, 0, len(removals)-len(pairedRemovals))
	for i := range removals {
		if !pairedRemovals[i] {
			standaloneRemovals = append(standaloneRemovals, removals[i])
		}
	}
	return standaloneAdditions, standaloneRemovals, replacements, nil
}

type accountRoleChangeChild struct {
	OperationID  uuid.UUID         `json:"operation_id"`
	BindingID    uuid.UUID         `json:"binding_id"`
	PermissionID uuid.UUID         `json:"permission_id"`
	Action       string            `json:"action"`
	Status       operations.Status `json:"status"`
}

// manageAccountRoles — POST /api/v1/accounts/{id}/roles. Один запрос
// фиксирует дельту ролей аккаунта и создаёт parent bulk.account_roles с
// дочерними access.grant/access.revoke. Это не "replace all": unmanaged и
// scoped bindings, которых нет в remove_binding_ids, не затрагиваются.
func (s *Server) manageAccountRoles(w http.ResponseWriter, r *http.Request) {
	s.manageAccountAccessDelta(w, r, false)
}

func (s *Server) manageObjectPrivileges(w http.ResponseWriter, r *http.Request) {
	s.manageAccountAccessDelta(w, r, true)
}

func (s *Server) manageAccountAccessDelta(w http.ResponseWriter, r *http.Request, direct bool) {
	ctx := r.Context()
	accountID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	var req manageAccountRolesRequest
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
	acct, err := s.inventory.GetAccount(ctx, s.pool, accountID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}

	additions := make([]grantTarget, 0, len(req.AddPermissionIDs))
	var objectSet []inventory.Permission
	addedPermissions := make(map[uuid.UUID]struct{}, len(req.AddPermissionIDs))
	anyDangerousAddition := false
	for _, permissionID := range req.AddPermissionIDs {
		target, loaded := s.loadGrantTarget(w, r, bulkBindingItem{
			AccountID: accountID, PermissionID: permissionID,
		})
		if !loaded {
			return
		}
		if jobs.IsPostgresObjectPermission(target.permission) != direct {
			respondError(w, http.StatusBadRequest, "role memberships and object privileges use separate endpoints")
			return
		}
		if direct {
			objectSet = append(objectSet, target.permission)
		}
		additions = append(additions, target)
		addedPermissions[permissionID] = struct{}{}
		anyDangerousAddition = anyDangerousAddition || target.permission.Dangerous
	}

	removals := make([]accountRoleRemoval, 0, len(req.RemoveBindingIDs))
	anyDangerousRemoval := false
	for _, bindingID := range req.RemoveBindingIDs {
		binding, err := s.inventory.GetBinding(ctx, s.pool, bindingID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if binding.AccountID != accountID {
			respondError(w, http.StatusBadRequest, fmt.Sprintf(
				"binding %s belongs to another account", binding.ID))
			return
		}
		if (binding.DesiredState == nil || *binding.DesiredState != inventory.BindingPresent) && !direct {
			respondError(w, http.StatusConflict, fmt.Sprintf(
				"binding %s is not an active managed role", binding.ID))
			return
		}
		if _, both := addedPermissions[binding.PermissionDefinitionID]; both {
			respondError(w, http.StatusBadRequest, fmt.Sprintf(
				"permission %s cannot be added and removed in one request",
				binding.PermissionDefinitionID))
			return
		}
		permission, err := s.inventory.GetPermission(ctx, s.pool, binding.PermissionDefinitionID)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		if jobs.IsPostgresObjectPermission(permission) != direct || (direct && binding.Source == string(inventory.BindingSourceInherited)) {
			respondError(w, http.StatusBadRequest, "only direct object grants may be removed through this endpoint")
			return
		}
		if direct {
			objectSet = append(objectSet, permission)
		}
		removals = append(removals, accountRoleRemoval{
			binding: binding, permission: permission,
		})
		anyDangerousRemoval = anyDangerousRemoval || permission.Dangerous
	}
	if direct {
		var expected adapter.PostgresObjectPrivilege
		for i, permission := range objectSet {
			p, err := adapter.ParsePostgresObjectPrivilege(permission.ExternalID)
			if err != nil || p.Kind == "column" {
				respondError(w, http.StatusBadRequest, "unsupported object privilege")
				return
			}
			p.Privilege = ""
			if i == 0 {
				expected = p
			} else if p != expected {
				respondError(w, http.StatusBadRequest, "one object is required per privilege change")
				return
			}
		}
	}

	if anyDangerousAddition {
		if status, msg := dangerousGrantCheck(sess.Role, req.Confirm); status != 0 {
			respondError(w, status, msg)
			return
		}
	}
	if anyDangerousRemoval && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden, "managing dangerous permission requires admin role")
		return
	}
	currentBindings, err := s.inventory.ListBindingsByAccount(ctx, s.pool, acct.ID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	additions, removals, replacements, err := partitionAccountRoleChanges(currentBindings, additions, removals)
	if err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	parentKind := jobs.KindBulkAccountRoles
	auditAction := auditActionAccountRolesRequested
	if direct {
		parentKind = jobs.KindBulkObjectACL
		auditAction = auditActionObjectACLRequested
	}
	s.runBulkParent(w, r, sess, bulkParent{
		kind:         parentKind,
		connectionID: &acct.ConnectionID,
		accountID:    &acct.ID,
		payload: map[string]any{
			"add": len(additions), "remove": len(removals),
			"replace": len(replacements), "confirmed": req.Confirm,
		},
		payloadErrPrefix: "api: marshal account roles payload",
		auditAction:      auditAction,
		commitErrPrefix:  "api: commit account roles",
	}, func(tx pgx.Tx, parentID uuid.UUID) (children, metadata any, ok bool) {
		out := make([]accountRoleChangeChild, 0, len(additions)+len(removals)+len(replacements))
		for i := range additions {
			child, err := s.createGrant(r, tx, sess, additions[i], nil, req.Confirm, &parentID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, accountRoleChangeChild{
				OperationID:  child.OperationID,
				BindingID:    child.BindingID,
				PermissionID: child.PermissionID,
				Action:       "grant",
				Status:       child.Status,
			})
		}
		for i := range replacements {
			child, err := s.createAccessReplacement(r, tx, sess, replacements[i], req.Confirm, &parentID)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, child)
		}
		for i := range removals {
			op, err := s.createRevoke(r, tx, sess, removals[i].binding, acct, &parentID, false)
			if err != nil {
				respondStoreError(ctx, w, err)
				return nil, nil, false
			}
			out = append(out, accountRoleChangeChild{
				OperationID:  op.ID,
				BindingID:    removals[i].binding.ID,
				PermissionID: removals[i].permission.ID,
				Action:       "revoke",
				Status:       op.Status,
			})
		}
		return out, map[string]any{
			"account":  acct.EngineIdentity,
			"added":    len(additions),
			"removed":  len(removals),
			"replaced": len(replacements),
		}, true
	})
}

func (s *Server) createAccessReplacement(r *http.Request, tx pgx.Tx, sess auth.Session,
	replacement accountRoleReplacement, confirmed bool, parentID *uuid.UUID) (accountRoleChangeChild, error) {
	ctx := r.Context()
	from := replacement.from
	to := replacement.to
	if err := weakAuthGrantCheck(to.account, confirmed); err != nil {
		return accountRoleChangeChild{}, err
	}
	if from.binding.AccountID != to.account.ID || from.permission.ID == to.permission.ID {
		return accountRoleChangeChild{}, fmt.Errorf("api: invalid access replacement: %w", inventory.ErrBindingTransitionConflict)
	}
	if err := requireMutableRolePolicyBinding(to.account, from.permission, from.binding); err != nil {
		return accountRoleChangeChild{}, err
	}
	assignmentKey := to.permission.AssignmentKey
	if assignmentKey == "" || from.permission.AssignmentKey != assignmentKey ||
		from.binding.AssignmentKey != assignmentKey {
		return accountRoleChangeChild{}, fmt.Errorf("api: replacement assignment mismatch: %w", inventory.ErrBindingTransitionConflict)
	}
	toScope := inventory.EffectiveBindingScope(to.permission, nil)
	if !uuidPointersEqual(from.binding.ScopeResourceID, toScope) {
		return accountRoleChangeChild{}, fmt.Errorf("api: replacement scope mismatch: %w", inventory.ErrBindingTransitionConflict)
	}
	_, lifecycleVersion, err := lockAccountLifecycleSnapshot(ctx, tx, to.account.ID, parentID, false)
	if err != nil {
		return accountRoleChangeChild{}, err
	}
	expectedVersion := from.binding.Version + 1
	var reverseOf uuid.UUID
	var convergeAttributes map[string]any
	var reverseTargetIdentity string
	if from.binding.TransitionOperationID != nil {
		old, err := s.operations.Get(ctx, tx, *from.binding.TransitionOperationID)
		if err != nil {
			return accountRoleChangeChild{}, err
		}
		if old.Status != operations.StatusFailed || old.Kind != jobs.KindAccessReplace {
			return accountRoleChangeChild{}, fmt.Errorf(
				"api: access replacement is still active: %w", inventory.ErrBindingTransitionConflict)
		}
		var oldPayload jobs.AccessReplacePayload
		if err := json.Unmarshal(old.Payload, &oldPayload); err != nil {
			return accountRoleChangeChild{}, fmt.Errorf("api: decode failed access replacement: %w", err)
		}
		if oldPayload.FromPermissionDefinitionID != to.permission.ID ||
			oldPayload.ToPermissionDefinitionID != from.permission.ID {
			return accountRoleChangeChild{}, fmt.Errorf(
				"api: only an exact reverse of the failed replacement is allowed: %w",
				inventory.ErrBindingTransitionConflict)
		}
		if from.permission.Dangerous && !oldPayload.Confirmed {
			return accountRoleChangeChild{}, fmt.Errorf(
				"api: failed replacement did not carry confirmation for dangerous permission: %w",
				inventory.ErrBindingTransitionConflict)
		}
		reverseOf = old.ID
		reverseTargetIdentity = oldPayload.ExpectedTargetIdentity
		convergeAttributes = oldPayload.PermissionAttributes
		if convergeAttributes == nil {
			convergeAttributes = pinnedAccessAttributes(from.permission)
		}
	}
	connection, err := s.connections.Get(ctx, tx, to.account.ConnectionID)
	if err != nil {
		return accountRoleChangeChild{}, err
	}
	for _, capability := range []adapter.Capability{adapter.CapAccessGrant, adapter.CapAccessRevoke} {
		if err := requireConnectionCapability(connection, capability); err != nil {
			return accountRoleChangeChild{}, err
		}
	}
	expectedTargetIdentity := connections.TargetIdentity(connection)
	if reverseTargetIdentity != "" {
		if expectedTargetIdentity != reverseTargetIdentity {
			return accountRoleChangeChild{}, fmt.Errorf(
				"api: failed replacement belongs to target %q, current target is %q: %w",
				reverseTargetIdentity, expectedTargetIdentity, inventory.ErrBindingTransitionConflict)
		}
		expectedTargetIdentity = reverseTargetIdentity
	}
	if connection.Engine == "rabbitmq" && expectedTargetIdentity == "" {
		return accountRoleChangeChild{}, fmt.Errorf(
			"api: RabbitMQ discovery did not prove cluster_name target identity: %w",
			inventory.ErrBindingTransitionConflict)
	}
	payload, err := json.Marshal(jobs.AccessReplacePayload{
		BindingID:                       from.binding.ID,
		FromPermissionDefinitionID:      from.permission.ID,
		ToPermissionDefinitionID:        to.permission.ID,
		AssignmentKey:                   assignmentKey,
		ExpectedBindingVersion:          expectedVersion,
		ExpectedAccountLifecycleVersion: lifecycleVersion,
		Confirmed:                       confirmed,
		PermissionAttributes:            pinnedAccessAttributes(to.permission),
		ReverseOfOperationID:            reverseOf,
		ConvergePermissionAttributes:    convergeAttributes,
		ExpectedTargetIdentity:          expectedTargetIdentity,
	})
	if err != nil {
		return accountRoleChangeChild{}, fmt.Errorf("api: marshal access replacement payload: %w", err)
	}
	requiresApproval := approval.Requires(s.approvalRequired, to.permission.Dangerous)
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:             jobs.KindAccessReplace,
		ParentID:         parentID,
		ConnectionID:     &to.account.ConnectionID,
		AccountID:        &to.account.ID,
		BindingID:        &from.binding.ID,
		Payload:          payload,
		ActorType:        sess.ActorType(),
		ActorID:          sess.ActorID(),
		CorrelationID:    uuid.NewString(),
		RequiresApproval: requiresApproval,
	})
	if err != nil {
		return accountRoleChangeChild{}, err
	}
	if _, err := s.inventory.ReserveAccessReplacement(ctx, tx, inventory.AccessReplacementTransition{
		BindingID:        from.binding.ID,
		OperationID:      op.ID,
		FromPermissionID: from.permission.ID,
		ToPermissionID:   to.permission.ID,
		AssignmentKey:    assignmentKey,
		ExpectedVersion:  expectedVersion,
	}); err != nil {
		return accountRoleChangeChild{}, err
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return accountRoleChangeChild{}, err
	}
	return accountRoleChangeChild{
		OperationID: op.ID, BindingID: from.binding.ID,
		PermissionID: to.permission.ID, Action: "replace", Status: op.Status,
	}, nil
}

// createRevoke переводит binding в desired absent и создаёт операцию
// access.revoke с постановкой в очередь в переданной транзакции —
// единая точка отзыва (одиночный DELETE /bindings/{id}, manifest apply,
// offboard принципала). parentID != nil делает операцию дочерней bulk
// parent; requiresApproval создаёт её в pending_approval (mass-revoke
// gate, GRANTOR_APPROVAL_MASS_REVOKE_THRESHOLD) — job всё равно ставится
// в очередь, worker снузит его до approve, ровно как у опасных грантов
// (ADR-0010).
func (s *Server) createRevoke(r *http.Request, tx pgx.Tx, sess auth.Session, binding inventory.Binding,
	acct inventory.Account, parentID *uuid.UUID, requiresApproval bool) (operations.Operation, error) {
	ctx := r.Context()
	conn, err := s.connections.Get(ctx, tx, acct.ConnectionID)
	if err != nil {
		return operations.Operation{}, err
	}
	if err := requireConnectionCapability(conn, adapter.CapAccessRevoke); err != nil {
		return operations.Operation{}, err
	}
	permission, err := s.inventory.GetPermission(ctx, tx, binding.PermissionDefinitionID)
	if err != nil {
		return operations.Operation{}, err
	}
	var statsPins *postgres.StatsMembershipPins
	var objectPins *adapter.PostgresObjectACLPins
	operationKind := jobs.KindAccessRevoke
	if jobs.IsPostgresObjectPermission(permission) {
		operationKind = jobs.KindPostgresObjectACLRevokeV1
		objectPins, err = jobs.BuildObjectACLPins(conn, acct, permission, &binding)
		if err != nil {
			return operations.Operation{}, err
		}
	}
	if jobs.IsPostgresStatsPermission(permission) {
		statsPins, err = jobs.BuildStatsMembershipPins(ctx, tx, conn, acct, permission, uuid.Nil)
		if err != nil {
			return operations.Operation{}, err
		}
		operationKind = jobs.KindPostgresStatsRevokeV1
	}
	if err := requireMutableRolePolicyBinding(acct, permission, binding); err != nil {
		return operations.Operation{}, err
	}
	_, lifecycleVersion, err := lockAccountLifecycleSnapshot(ctx, tx, acct.ID, parentID, false)
	if err != nil {
		return operations.Operation{}, err
	}

	_, err = s.inventory.SetBindingDesired(ctx, tx, binding.ID, inventory.BindingAbsent)
	if err != nil {
		return operations.Operation{}, err
	}
	payload, err := json.Marshal(jobs.AccessPayload{
		ObjectACL:                       objectPins,
		StatsMembership:                 statsPins,
		BindingID:                       binding.ID,
		ExpectedPermissionDefinitionID:  binding.PermissionDefinitionID,
		ExpectedDesiredState:            string(inventory.BindingAbsent),
		ExpectedAccountLifecycleVersion: lifecycleVersion,
		PermissionAttributes:            pinnedAccessAttributes(permission),
	})
	if err != nil {
		return operations.Operation{}, fmt.Errorf("api: marshal revoke payload: %w", err)
	}
	op, _, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind:             operationKind,
		ParentID:         parentID,
		ConnectionID:     &acct.ConnectionID,
		AccountID:        &acct.ID,
		BindingID:        &binding.ID,
		Payload:          payload,
		ActorType:        sess.ActorType(),
		ActorID:          sess.ActorID(),
		CorrelationID:    uuid.NewString(),
		RequiresApproval: requiresApproval,
	})
	if err != nil {
		return operations.Operation{}, err
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		return operations.Operation{}, err
	}
	return op, nil
}

// pinnedAccessAttributes фиксирует только template/exclusive definitions:
// обычные роли не интерпретируются через mutable connection catalog, а их
// произвольные discovery-атрибуты не должны делать старые операции stale.
func pinnedAccessAttributes(permission inventory.Permission) map[string]any {
	if permission.AssignmentKey == "" && !jobs.IsPostgresStatsPermission(permission) && !jobs.IsPostgresObjectPermission(permission) {
		return nil
	}
	return decodeAttributes(permission.Attributes)
}

// deleteBinding — DELETE /api/v1/bindings/{id} (operator; dangerous —
// admin): перевод binding в desired absent и операция access.revoke.
// Подтверждение не требуется: отзыв — безопасное направление.
func (s *Server) deleteBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}

	binding, err := s.inventory.GetBinding(ctx, s.pool, id)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	acct, err := s.inventory.GetAccount(ctx, s.pool, binding.AccountID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Scope: operator отзывает доступ только в connections своих окружений.
	if err := s.checkConnectionScopeByID(ctx, sess, acct.ConnectionID); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	perm, err := s.inventory.GetPermission(ctx, s.pool, binding.PermissionDefinitionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if perm.Dangerous && !sess.Role.Allows(auth.RoleAdmin) {
		respondError(w, http.StatusForbidden, "managing dangerous permission requires admin role")
		return
	}
	// Унаследованное право отзыву не поддаётся: прямого ребра в целевой
	// системе нет, команда отзыва не находит что снимать и завершается
	// no-op, а Verify — той же проверкой — подтверждает «снято». Оператор
	// получал success при живом доступе. Отзывать нужно роль, через которую
	// право пришло.
	if binding.Source == string(inventory.BindingSourceInherited) {
		respondError(w, http.StatusConflict,
			"permission is inherited through a role and cannot be revoked directly: "+
				"revoke the role that grants it")
		return
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	op, err := s.createRevoke(r, tx, sess, binding, acct, nil, false)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.writeAudit(ctx, tx, audit.Event{
		ActorType:    sess.ActorType(),
		ActorID:      sess.ActorID(),
		Action:       auditActionRevokeRequested,
		ConnectionID: &acct.ConnectionID,
		AccountID:    &acct.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
	}, map[string]any{
		"binding_id": binding.ID,
		"permission": perm.ExternalID,
		"dangerous":  perm.Dangerous,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: commit delete binding: %w", err))
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{
		"operation_id": op.ID,
		"binding_id":   binding.ID,
	})
}

// priorBindingDesired возвращает желаемое состояние существующего binding до
// выдачи: nil — строки нет либо она unmanaged (desired NULL). Ключ тот же,
// что и у EnsureBinding: аккаунт, permission и область.
func (s *Server) priorBindingDesired(ctx context.Context, tx pgx.Tx, accountID, permissionID uuid.UUID, scopeID *uuid.UUID) (*inventory.BindingState, error) {
	existing, err := s.inventory.ListBindingsByAccount(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	for i := range existing {
		binding := existing[i]
		if binding.PermissionDefinitionID != permissionID ||
			!uuidPointersEqual(binding.ScopeResourceID, scopeID) {
			continue
		}
		return binding.DesiredState, nil
	}
	return nil, nil
}
