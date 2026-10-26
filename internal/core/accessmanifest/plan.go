package accessmanifest

// Вычисление плана (dry-run diff) между желаемым состоянием манифеста и
// текущим состоянием инвентаря. Plan только читает и ничего не применяет:
// apply переиспользует те же actions (см. internal/api/handlers_access_manifest.go).
//
// Диаграмма решений для одной записи (scope у манифеста нет — сравнение идёт
// по managed binding в собственной области permission-определения, см.
// inventory.EffectiveBindingScope: NULL у cluster-wide прав, конкретный
// resource у прав, неотделимых от него):
//
//	present + нет managed-аккаунта      -> create_account + grant
//	present + аккаунт есть, нет binding -> grant
//	present + binding уже present       -> ничего (идемпотентно)
//	absent  + managed binding present   -> revoke
//	absent  + ничего                    -> ничего
//	конфликт identity / не резолвится   -> Unresolved (в план не попадает)
//
// Prune (полная реконсиляция): для принципалов, у которых в манифесте есть
// хотя бы одна present-запись, managed present bindings в собственной области
// permission, не покрытые present-записями, добавляются в revoke. Bindings,
// суженные оператором до чужого ресурса, prune не трогает. Принципалы, встречающиеся
// только в absent-записях, prune не затрагивает. Unmanaged bindings
// (desired_state IS NULL) prune не отзывает никогда.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// Виды действий плана. Совпадают с ветвями apply-оркестрации.
const (
	// ActionGrant — выдать роль (EnsureBinding present + access.grant).
	ActionGrant = "grant"
	// ActionRevoke — отозвать роль (SetBindingDesired absent + access.revoke).
	ActionRevoke = "revoke"
	// ActionReplace — заменить permission одного exclusive assignment slot
	// без промежуточного revoke (одна access.replace операция).
	ActionReplace = "replace"
	// ActionCreateAccount — создать managed-аккаунт принципала перед выдачей
	// (CreateManagedAccount + account.create). Всегда сопровождается grant.
	ActionCreateAccount = "create_account"
)

// Querier — минимальный контракт выполнения запросов pgx; ему удовлетворяют
// и *pgxpool.Pool, и pgx.Tx. Объявлен локально (как в пакетах ядра), чтобы
// пакет не зависел от конкретного типа пула: структурная типизация делает
// его взаимозаменяемым с Querier сторов.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ResolveError означает, что ссылка манифеста не разрешается в сущность
// инвентаря (не найдена, неоднозначна или конфликтует). computePlan
// складывает такие записи в Plan.Unresolved и не прерывает построение плана;
// прочие ошибки (сбой чтения БД) прерывают Plan.
type ResolveError struct {
	// Reason — человекочитаемая причина, попадающая в Unresolved.Reason.
	Reason string
}

// Error реализует error.
func (e *ResolveError) Error() string { return "accessmanifest: " + e.Reason }

// ErrConnectionScopeMismatch означает, что connection-scoped plan/apply
// получил запись другого подключения. Это hard error, а не Unresolved:
// выбранный connection является safety boundary всего запроса, включая prune.
var ErrConnectionScopeMismatch = errors.New("manifest contains entry outside requested connection")

// ErrAmbiguousReplacement означает, что манифест одновременно требует два
// разных permission одного exclusive assignment slot. Выбирать один из них
// по порядку entries небезопасно.
var ErrAmbiguousReplacement = errors.New("manifest contains ambiguous exclusive assignment replacement")

// resolveErr — конструктор ResolveError с форматированием причины.
func resolveErr(format string, args ...any) error {
	return &ResolveError{Reason: fmt.Sprintf(format, args...)}
}

// AccountLookup — результат поиска managed-аккаунта принципала в подключении.
// Found — есть готовый managed-аккаунт принципала; Conflict — identity занята
// unmanaged/deleted-аккаунтом или аккаунтом другого принципала (в план не
// идёт, запись становится Unresolved).
type AccountLookup struct {
	Account        inventory.Account
	Found          bool
	Conflict       bool
	ConflictReason string
}

// Source — доступ к инвентарю для вычисления плана и экспорта. Методы не
// принимают Querier: конкретная реализация (storeSource) связывает его при
// создании, а юнит-тесты подставляют фейк без БД. Ошибки резолва имён
// возвращаются как *ResolveError; сбои чтения — как обычные ошибки.
type Source interface {
	// ResolvePrincipal резолвит principal по external_subject, display_name
	// или id (UUID).
	ResolvePrincipal(ctx context.Context, ref string) (principals.Principal, error)
	// ResolveConnection резолвит connection по display_name или id (UUID).
	ResolveConnection(ctx context.Context, ref string) (connections.Connection, error)
	// ResolvePermission резолвит permission подключения по external_id или name.
	ResolvePermission(ctx context.Context, connectionID uuid.UUID, ref string) (inventory.Permission, error)

	// Principal/Connection/Permission — точечная загрузка по id (для prune и
	// export, где сущности уже известны по ссылкам инвентаря).
	Principal(ctx context.Context, id uuid.UUID) (principals.Principal, error)
	Connection(ctx context.Context, id uuid.UUID) (connections.Connection, error)
	Permission(ctx context.Context, id uuid.UUID) (inventory.Permission, error)

	// ManagedAccount возвращает managed-аккаунт принципала в подключении по
	// его engine identity (та же identity, что использует apply).
	ManagedAccount(ctx context.Context, connectionID, principalID uuid.UUID, identity string) (AccountLookup, error)
	// AccountBindings возвращает bindings аккаунта.
	AccountBindings(ctx context.Context, accountID uuid.UUID) ([]inventory.Binding, error)
	// PrincipalAccounts возвращает не-deleted аккаунты принципала по всем
	// подключениям (для prune).
	PrincipalAccounts(ctx context.Context, principalID uuid.UUID) ([]inventory.Account, error)

	// Connections/ConnectionAccounts — обход инвентаря для export.
	Connections(ctx context.Context) ([]connections.Connection, error)
	ConnectionAccounts(ctx context.Context, connectionID uuid.UUID) ([]inventory.Account, error)
}

// ResolvedRefs — резолвленные сущности action для применения. В JSON не
// сериализуется (json:"-"): plan-ответ API несёт только имена, а apply
// использует эти ссылки напрямую, не резолвя повторно и не дублируя
// diff-логику.
type ResolvedRefs struct {
	Principal   principals.Principal
	Connection  connections.Connection
	Permission  inventory.Permission
	Environment string
	// Account — существующий managed-аккаунт (grant при существующем
	// аккаунте, revoke). Nil для create_account: аккаунт создаётся на apply.
	Account *inventory.Account
	// Binding — существующий binding для revoke; nil для grant/create_account.
	Binding *inventory.Binding
}

// Action — одно действие плана. Строковые поля Principal/Connection/Role
// денормализованы для отображения; Resolved несёт сущности для apply.
type Action struct {
	Kind                  string        `json:"kind"`
	Principal             string        `json:"principal"`
	Connection            string        `json:"connection"`
	Role                  string        `json:"role"`
	FromRole              string        `json:"from_role,omitempty"`
	AccountEngineIdentity string        `json:"account_engine_identity,omitempty"`
	Dangerous             bool          `json:"dangerous"`
	Reason                string        `json:"reason,omitempty"`
	Resolved              *ResolvedRefs `json:"-"`
}

// Unresolved — запись манифеста, которая не резолвится, с причиной. Несёт
// исходную запись (встроенную) плюс Reason для отображения оператору.
type Unresolved struct {
	Entry
	Reason string `json:"reason"`
}

// Plan — результат dry-run: список действий и нерезолвящихся записей.
type Plan struct {
	Actions    []Action     `json:"actions"`
	Unresolved []Unresolved `json:"unresolved"`
}

// Planner вычисляет план и экспортирует манифест поверх сторов ядра.
type Planner struct {
	Connections *connections.Store
	Principals  *principals.Store
	Inventory   *inventory.Store
}

// Plan вычисляет dry-run diff манифеста относительно текущего инвентаря.
// Ничего не применяет.
func (p Planner) Plan(ctx context.Context, q Querier, m Manifest) (Plan, error) {
	return computePlan(ctx, p.source(q), m)
}

// PlanForConnection вычисляет план строго внутри одного подключения. Ссылки
// entries могут использовать UUID или display_name, но после резолва обязаны
// указывать на connectionID. Prune также ограничивается этим connection.
func (p Planner) PlanForConnection(ctx context.Context, q Querier, m Manifest, connectionID uuid.UUID) (Plan, error) {
	return computePlanForConnection(ctx, p.source(q), m, connectionID)
}

// ResolveConnection резолвит подключение по id (UUID) или display_name — для
// scope-фильтра экспорта. Неизвестное или неоднозначное подключение
// возвращается как *ResolveError (обработчик отвечает 404).
func (p Planner) ResolveConnection(ctx context.Context, q Querier, ref string) (connections.Connection, error) {
	return p.source(q).ResolveConnection(ctx, ref)
}

// source связывает сторы Planner с Querier запроса.
func (p Planner) source(q Querier) Source {
	return &storeSource{connections: p.Connections, principals: p.Principals, inventory: p.Inventory, q: q}
}

// coverageKey — ключ покрытия present-записью (для идемпотентности и prune).
type coverageKey struct {
	principal  uuid.UUID
	connection uuid.UUID
	permission uuid.UUID
}

// connPrincipalKey — ключ (principal, connection) для дедупликации
// create_account: несколько ролей нового аккаунта дают один create_account.
type connPrincipalKey struct {
	principal  uuid.UUID
	connection uuid.UUID
}

type manifestAssignmentKey struct {
	principal  uuid.UUID
	connection uuid.UUID
	assignment string
}

// computePlan — чистая diff-логика поверх Source. Тестируется на фейковом
// Source без БД.
func computePlan(ctx context.Context, src Source, m Manifest) (Plan, error) {
	return computePlanScoped(ctx, src, m, uuid.Nil)
}

func computePlanForConnection(ctx context.Context, src Source, m Manifest, connectionID uuid.UUID) (Plan, error) {
	return computePlanScoped(ctx, src, m, connectionID)
}

func computePlanScoped(ctx context.Context, src Source, m Manifest, connectionID uuid.UUID) (Plan, error) {
	plan := Plan{Actions: []Action{}, Unresolved: []Unresolved{}}
	// covered — (principal, connection, permission) present-записей: и
	// дедупликация повторов, и защита present-грантов от prune.
	covered := map[coverageKey]bool{}
	// pendingCreate — (principal, connection), для которых create_account уже
	// добавлен: несколько ролей нового аккаунта дают один create_account.
	pendingCreate := map[connPrincipalKey]bool{}
	// prunePrincipals — принципалы, встречающиеся в present-записях: только их
	// prune реконсилирует полностью.
	prunePrincipals := map[uuid.UUID]principals.Principal{}
	// scheduledRevoke — id bindings, уже запланированных к отзыву (absent или
	// prune): защита от дублей.
	scheduledRevoke := map[uuid.UUID]bool{}
	// requestedAssignments запрещает два target permissions одного exclusive
	// slot даже если один из них уже выдан: такой манифест не имеет однозначного
	// физического состояния.
	requestedAssignments := map[manifestAssignmentKey]uuid.UUID{}

	for i := range m.Entries {
		entry := m.Entries[i]

		principal, err := src.ResolvePrincipal(ctx, entry.Principal)
		if err != nil {
			if addUnresolved(&plan, entry, err) {
				continue
			}
			return Plan{}, err
		}
		conn, err := src.ResolveConnection(ctx, entry.Connection)
		if err != nil {
			if addUnresolved(&plan, entry, err) {
				continue
			}
			return Plan{}, err
		}
		if connectionID != uuid.Nil && conn.ID != connectionID {
			return Plan{}, ErrConnectionScopeMismatch
		}
		if m.Environment != "" && conn.Environment != m.Environment {
			plan.Unresolved = append(plan.Unresolved, Unresolved{Entry: entry, Reason: fmt.Sprintf(
				"connection %q is in environment %q, manifest targets %q", entry.Connection, conn.Environment, m.Environment)})
			continue
		}
		perm, err := src.ResolvePermission(ctx, conn.ID, entry.Role)
		if err != nil {
			if addUnresolved(&plan, entry, err) {
				continue
			}
			return Plan{}, err
		}

		identity, err := accountEngineIdentity(conn, principal)
		if err != nil {
			return Plan{}, err
		}
		base := Action{
			Principal:             entry.Principal,
			Connection:            entry.Connection,
			Role:                  entry.Role,
			AccountEngineIdentity: identity,
			Dangerous:             perm.Dangerous,
			Resolved: &ResolvedRefs{
				Principal:   principal,
				Connection:  conn,
				Permission:  perm,
				Environment: conn.Environment,
			},
		}

		state := entry.stateOrDefault()
		if state == StatePresent && perm.AssignmentKey != "" {
			key := manifestAssignmentKey{principal.ID, conn.ID, perm.AssignmentKey}
			if prior, exists := requestedAssignments[key]; exists && prior != perm.ID {
				return Plan{}, fmt.Errorf("%w: principal %s connection %s assignment %q",
					ErrAmbiguousReplacement, principal.ID, conn.ID, perm.AssignmentKey)
			}
			requestedAssignments[key] = perm.ID
		}

		switch state {
		case StatePresent:
			if !perm.Assignable {
				plan.Unresolved = append(plan.Unresolved, Unresolved{Entry: entry, Reason: fmt.Sprintf(
					"permission %q is not assignable", entry.Role)})
				continue
			}
			// Права в целевой системе больше нет: планировать выдачу
			// заведомо провальной операции нечестно — запись остаётся
			// нерешённой, и оператор видит причину.
			if perm.Status == inventory.PermissionMissing {
				plan.Unresolved = append(plan.Unresolved, Unresolved{Entry: entry, Reason: fmt.Sprintf(
					"permission %q is missing from the target system", entry.Role)})
				continue
			}
			covKey := coverageKey{principal.ID, conn.ID, perm.ID}
			if covered[covKey] {
				continue // дубликат present-записи
			}
			covered[covKey] = true
			prunePrincipals[principal.ID] = principal

			look, err := src.ManagedAccount(ctx, conn.ID, principal.ID, identity)
			if err != nil {
				return Plan{}, err
			}
			if look.Conflict {
				plan.Unresolved = append(plan.Unresolved, Unresolved{Entry: entry, Reason: look.ConflictReason})
				continue
			}
			if !look.Found {
				pcKey := connPrincipalKey{principal.ID, conn.ID}
				if !pendingCreate[pcKey] {
					pendingCreate[pcKey] = true
					create := base
					create.Kind = ActionCreateAccount
					create.Reason = "no managed account for principal in connection"
					plan.Actions = append(plan.Actions, create)
				}
				grant := base
				grant.Kind = ActionGrant
				grant.Reason = "account will be created and role granted"
				plan.Actions = append(plan.Actions, grant)
				continue
			}

			acct := look.Account
			base.Resolved.Account = &acct
			bindings, err := src.AccountBindings(ctx, acct.ID)
			if err != nil {
				return Plan{}, err
			}
			if _, ok := findSatisfiedBinding(bindings, perm); ok {
				continue // идемпотентно: роль уже выдана и действует
			}
			replacementBinding, fromPermission, replace, err := findExclusiveReplacement(ctx, src, bindings, perm)
			if err != nil {
				if addUnresolved(&plan, entry, err) {
					continue
				}
				return Plan{}, err
			}
			if replace {
				removeScheduledRevoke(&plan, replacementBinding.ID)
				scheduledRevoke[replacementBinding.ID] = true
				binding := replacementBinding
				base.Resolved.Binding = &binding
				action := base
				action.Kind = ActionReplace
				action.FromRole = fromPermission.ExternalID
				action.Dangerous = action.Dangerous || fromPermission.Dangerous
				action.Reason = "exclusive assignment changes without revoking the slot"
				plan.Actions = append(plan.Actions, action)
				continue
			}
			grant := base
			grant.Kind = ActionGrant
			grant.Reason = "role is not granted yet"
			plan.Actions = append(plan.Actions, grant)

		case StateAbsent:
			look, err := src.ManagedAccount(ctx, conn.ID, principal.ID, identity)
			if err != nil {
				return Plan{}, err
			}
			if !look.Found {
				continue // нечего отзывать (нет managed-аккаунта или конфликт)
			}
			acct := look.Account
			bindings, err := src.AccountBindings(ctx, acct.ID)
			if err != nil {
				return Plan{}, err
			}
			b, ok := findManagedPresentBinding(bindings, perm)
			if !ok {
				continue
			}
			if scheduledRevoke[b.ID] {
				continue // дубликат absent-записи
			}
			base.Resolved.Account = &acct
			binding := b
			base.Resolved.Binding = &binding
			revoke := base
			revoke.Kind = ActionRevoke
			revoke.Reason = "role removed by manifest"
			plan.Actions = append(plan.Actions, revoke)
			scheduledRevoke[b.ID] = true
		}
	}

	if m.Prune {
		if err := appendPruneActions(ctx, src, m, connectionID, &plan, prunePrincipals, covered, scheduledRevoke); err != nil {
			return Plan{}, err
		}
	}
	return plan, nil
}

// appendPruneActions добавляет revoke-действия для managed present bindings в
// собственной области их permission, принадлежащих принципалам из
// present-записей, но не покрытых манифестом. Порядок принципалов
// детерминирован (по id).
func appendPruneActions(ctx context.Context, src Source, m Manifest, connectionID uuid.UUID, plan *Plan,
	prunePrincipals map[uuid.UUID]principals.Principal, covered map[coverageKey]bool, scheduledRevoke map[uuid.UUID]bool) error {
	ids := make([]uuid.UUID, 0, len(prunePrincipals))
	for id := range prunePrincipals {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })

	for _, pid := range ids {
		principal := prunePrincipals[pid]
		accounts, err := src.PrincipalAccounts(ctx, pid)
		if err != nil {
			return err
		}
		for ai := range accounts {
			acct := accounts[ai]
			if connectionID != uuid.Nil && acct.ConnectionID != connectionID {
				continue
			}
			if acct.Ownership != inventory.OwnershipManaged || acct.Status == inventory.AccountDeleted {
				continue
			}
			bindings, err := src.AccountBindings(ctx, acct.ID)
			if err != nil {
				return err
			}
			for bi := range bindings {
				b := bindings[bi]
				if !isManagedPresent(b) {
					continue // unmanaged — prune не трогает
				}
				if scheduledRevoke[b.ID] {
					continue
				}
				if covered[coverageKey{pid, acct.ConnectionID, b.PermissionDefinitionID}] {
					continue // покрыто present-записью манифеста
				}
				perm, err := src.Permission(ctx, b.PermissionDefinitionID)
				if err != nil {
					return err
				}
				// Область действия читается до решения об отзыве: манифесту
				// принадлежит binding в собственной области permission, а
				// суженный оператором до чужого ресурса — нет.
				if !inventory.BindingHasPermissionScope(b, perm) {
					continue
				}
				conn, err := src.Connection(ctx, acct.ConnectionID)
				if err != nil {
					return err
				}
				if m.Environment != "" && conn.Environment != m.Environment {
					continue
				}
				acctCopy := acct
				binding := b
				plan.Actions = append(plan.Actions, Action{
					Kind:                  ActionRevoke,
					Principal:             principalRef(principal),
					Connection:            conn.DisplayName,
					Role:                  perm.ExternalID,
					AccountEngineIdentity: acct.EngineIdentity,
					Dangerous:             perm.Dangerous,
					Reason:                "managed role not present in manifest (prune)",
					Resolved: &ResolvedRefs{
						Principal:   principal,
						Connection:  conn,
						Permission:  perm,
						Environment: conn.Environment,
						Account:     &acctCopy,
						Binding:     &binding,
					},
				})
				scheduledRevoke[b.ID] = true
			}
		}
	}
	return nil
}

// addUnresolved добавляет запись в Unresolved, если ошибка — *ResolveError, и
// возвращает true. Прочие ошибки не поглощаются (возвращается false).
func addUnresolved(plan *Plan, entry Entry, err error) bool {
	var re *ResolveError
	if errors.As(err, &re) {
		plan.Unresolved = append(plan.Unresolved, Unresolved{Entry: entry, Reason: re.Reason})
		return true
	}
	return false
}

// findExclusiveReplacement находит ровно один managed-present binding того
// же physical assignment slot. Он становится source A для атомарного replace
// в B; несколько строк одного slot — неоднозначный inventory и fail-closed.
func findExclusiveReplacement(ctx context.Context, src Source, bindings []inventory.Binding,
	target inventory.Permission) (inventory.Binding, inventory.Permission, bool, error) {
	if target.AssignmentKey == "" {
		return inventory.Binding{}, inventory.Permission{}, false, nil
	}
	var foundBinding inventory.Binding
	var foundPermission inventory.Permission
	found := false
	for i := range bindings {
		b := bindings[i]
		if !isManagedPresent(b) || b.PermissionDefinitionID == target.ID {
			continue
		}
		current, err := src.Permission(ctx, b.PermissionDefinitionID)
		if err != nil {
			return inventory.Binding{}, inventory.Permission{}, false, err
		}
		assignmentKey := b.AssignmentKey
		if assignmentKey == "" {
			assignmentKey = current.AssignmentKey
		}
		if assignmentKey != target.AssignmentKey {
			continue
		}
		if b.TransitionOperationID != nil {
			return inventory.Binding{}, inventory.Permission{}, false, resolveErr(
				"assignment %q is already transitioning", target.AssignmentKey)
		}
		if !inventory.BindingHasPermissionScope(b, current) ||
			!inventory.BindingHasPermissionScope(b, target) {
			return inventory.Binding{}, inventory.Permission{}, false, resolveErr(
				"assignment %q has incompatible permission scopes", target.AssignmentKey)
		}
		if found {
			return inventory.Binding{}, inventory.Permission{}, false, resolveErr(
				"assignment %q has multiple active bindings", target.AssignmentKey)
		}
		foundBinding = b
		foundPermission = current
		found = true
	}
	return foundBinding, foundPermission, found, nil
}

// removeScheduledRevoke убирает revoke того же source binding, если explicit
// absent находился в манифесте раньше present B. Так порядок entries не меняет
// канонический результат: остаётся один replace.
func removeScheduledRevoke(plan *Plan, bindingID uuid.UUID) {
	for i := range plan.Actions {
		action := plan.Actions[i]
		if action.Kind != ActionRevoke || action.Resolved == nil ||
			action.Resolved.Binding == nil || action.Resolved.Binding.ID != bindingID {
			continue
		}
		plan.Actions = append(plan.Actions[:i], plan.Actions[i+1:]...)
		return
	}
}

// findManagedPresentBinding возвращает binding, который grantor ТРЕБУЕТ
// присутствующим (desired_state = present), независимо от того, применён он
// сейчас или ушёл в дрифт. Нужен ветке отзыва: снимать требование надо и с
// расходящегося binding, иначе он навсегда остался бы desired present.
func findManagedPresentBinding(bindings []inventory.Binding, perm inventory.Permission) (inventory.Binding, bool) {
	for i := range bindings {
		b := bindings[i]
		if b.PermissionDefinitionID == perm.ID && inventory.BindingHasPermissionScope(b, perm) &&
			isManagedPresent(b) {
			return b, true
		}
	}
	return inventory.Binding{}, false
}

// findSatisfiedBinding возвращает binding, требование которого уже
// удовлетворено, — на указанный permission в его
// собственной области действия (см. inventory.EffectiveBindingScope). У
// cluster-wide прав это прежний binding без scope; у прав, неотделимых от
// ресурса (kafka topic, база mongodb, vhost rabbitmq) — binding на этом
// ресурсе. Bindings, суженные оператором до чужой области, манифесту
// по-прежнему не принадлежат.
//
// Учитывается не одно лишь desired_state: право, про которое discovery
// достоверно знает, что оно не работает (снято снаружи либо выдано, но не
// действует), удовлетворённым не считается — иначе план давал бы ноль
// действий, и декларативный путь не чинил бы реальный дрифт. Ровно на это
// жаловался аудит: access/plan и access/apply против расхождения возвращали
// пустой diff.
//
// Свежий грант с observed_state='unknown' удовлетворённым СЧИТАЕТСЯ: он
// затребован, поломка не доказана, и предлагать выдать его повторно значило
// бы ломать идемпотентность манифеста до первого discovery.
func findSatisfiedBinding(bindings []inventory.Binding, perm inventory.Permission) (inventory.Binding, bool) {
	for i := range bindings {
		b := bindings[i]
		if b.PermissionDefinitionID == perm.ID && inventory.BindingHasPermissionScope(b, perm) &&
			isManagedPresent(b) && !inventory.BindingNeedsRepair(b) {
			return b, true
		}
	}
	return inventory.Binding{}, false
}

// isManagedPresent сообщает, что binding под управлением сервиса и должен
// присутствовать (desired_state = present). Unmanaged (desired IS NULL) и
// absent сюда не входят.
func isManagedPresent(b inventory.Binding) bool {
	return b.DesiredState != nil && *b.DesiredState == inventory.BindingPresent
}

// accountEngineIdentity выводит engine identity managed-аккаунта принципала
// в конкретном подключении: базовое имя (external_subject, иначе slug
// display name) приводится к форме движка через adapter — mysql user@host,
// mongodb user@authdb. Совпадает с accountIdentity principal-centric flow в
// internal/api (override здесь не применяется), иначе план искал бы аккаунт
// по одной identity, а apply создавал бы его по другой.
func accountEngineIdentity(conn connections.Connection, p principals.Principal) (string, error) {
	base := p.ExternalSubject
	if base == "" {
		base = slugIdentity(p.DisplayName)
	}
	return connections.EngineIdentity(conn, base)
}

// principalRef выбирает читаемую ссылку на принципала для export/prune:
// external_subject, иначе display_name.
func principalRef(p principals.Principal) string {
	if p.ExternalSubject != "" {
		return p.ExternalSubject
	}
	return p.DisplayName
}

// slugIdentity строит идентификатор из display name: нижний регистр, символы
// вне [a-z0-9] заменяются на '_', ведущие/хвостовые '_' обрезаются, пустой
// результат заменяется на "principal".
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
