package kafka

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kerr"
	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана Kafka adapter.
const (
	stepGrantPermission  = "grant-permission"
	stepRevokePermission = "revoke-permission"
	stepCreateUser       = "create-user"
	stepDisableUser      = "disable-user"
	stepEnableUser       = "enable-user"
	stepDeleteUser       = "delete-user"
)

// Виды permission bundle (см. parsePermission).
const (
	bundleProduce      = "topic-produce"
	bundleConsume      = "topic-consume"
	bundleClusterAdmin = "cluster-admin"
)

// Plan строит детерминированный типизированный план для DesiredChange.
// Descriptions и attributes шагов не содержат секретных значений. Валидации
// существования на этапе плана нет: её выполняет идемпотентный Apply.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return planAccess(change)
	case adapter.ChangeAccountCreate:
		return a.planAccountCreate(ctx, change)
	case adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		return planDisableEnable(change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	default:
		return nil, fmt.Errorf("kafka: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planAccess строит план grant/revoke permission bundle. Вид bundle
// определяется по external id (см. parsePermission). Если ядро передало
// desired-состояние прав аккаунта (change.AccountPermissions), его
// согласованность с изменением проверяется здесь же: внятная ошибка до
// применения лучше отказа в середине Apply.
func planAccess(change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	user := change.Account.EngineIdentity
	if user == "" {
		return nil, fmt.Errorf("kafka: plan %s: account engine identity is empty", op)
	}
	kind, topic, err := parsePermission(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("kafka: plan %s: %w", op, err)
	}
	revoke := change.Kind == adapter.ChangeRevoke

	var desc string
	attrs := map[string]any{"user": user, "bundle": kind}
	if _, hasDesired, err := desiredEntries(change, user); err != nil {
		return nil, fmt.Errorf("kafka: plan %s: %w", op, err)
	} else if hasDesired {
		attrs["target_permissions"] = desiredPermissionList(change)
	}
	switch kind {
	case bundleProduce:
		attrs["topic"] = topic
		desc = fmt.Sprintf("grant produce access (WRITE+DESCRIBE) on topic %q to user %q", topic, user)
		if revoke {
			desc = fmt.Sprintf("revoke produce access on topic %q from user %q"+
				" (shared DESCRIBE is kept while consume access remains)", topic, user)
		}
	case bundleConsume:
		attrs["topic"] = topic
		attrs["group"] = wildcardName
		desc = fmt.Sprintf("grant consume access (READ+DESCRIBE on topic, READ on group %q) on topic %q to user %q",
			wildcardName, topic, user)
		if revoke {
			desc = fmt.Sprintf("revoke consume access on topic %q from user %q"+
				" (shared DESCRIBE and group READ are kept while still needed)", topic, user)
		}
	default: // bundleClusterAdmin
		attrs["cluster"] = clusterResourceName
		desc = fmt.Sprintf("grant cluster admin (ALL on cluster) to user %q", user)
		if revoke {
			desc = fmt.Sprintf("revoke cluster admin (ALL on cluster) from user %q", user)
		}
	}
	stepKind := stepGrantPermission
	if revoke {
		stepKind = stepRevokePermission
	}
	return adapterutil.SingleStepPlan(change, stepKind, desc, attrs), nil
}

// planAccountCreate строит план создания SCRAM credential пользователя.
// Пароль обязателен и берётся из change.Credential; в план он не попадает —
// только факт его наличия. На не-SCRAM подключении capability недоступна:
// единственный способ создать пользователя — SCRAM API (см. requireScramLifecycle).
// Credential не должен существовать: existing identity отклоняется здесь, до
// резервирования пароля (см. adapterutil.IdentityConflict).
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("kafka: plan account.create: account engine identity is empty")
	}
	if err := requireScramLifecycle(change.Connection, "account.create"); err != nil {
		return nil, err
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("kafka: plan account.create: password credential is required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("kafka: plan account.create: %w", err)
	}
	defer client.close()
	exists, err := client.scramExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("kafka: plan account.create: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("kafka: plan account.create: %w",
			adapterutil.IdentityConflict("SCRAM credential for user", name))
	}
	return accountCreatePlan(change), nil
}

// accountCreatePlan собирает сам план создания — без обращения к кластеру.
// Отделено от planAccountCreate, чтобы форму плана (шаг, атрибуты, отсутствие
// секрета в description) можно было проверять без поднятого Kafka.
func accountCreatePlan(change adapter.DesiredChange) *adapter.Plan {
	name := change.Account.EngineIdentity
	return adapterutil.SingleStepPlan(change, stepCreateUser,
		fmt.Sprintf("create SCRAM-SHA-256 credential for user %q", name),
		map[string]any{"user": name, "with_password": true, "mechanism": "SCRAM-SHA-256"})
}

// planDisableEnable строит план disable/enable. Disable добавляет DENY-маркер
// (см. doc-комментарий пакета), enable его снимает.
func planDisableEnable(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, fmt.Errorf("kafka: plan %s: account engine identity is empty", change.Kind)
	}
	if change.Kind == adapter.ChangeAccountDisable {
		return adapterutil.SingleStepPlan(change, stepDisableUser,
			fmt.Sprintf("disable user %q: add DENY ALL marker ACLs on topic %q, group %q and the cluster"+
				" (existing ALLOW ACLs are kept)", name, wildcardName, wildcardName),
			map[string]any{"user": name, "marker": "deny-all"}), nil
	}
	return adapterutil.SingleStepPlan(change, stepEnableUser,
		fmt.Sprintf("enable user %q: remove the DENY ALL marker ACLs", name),
		map[string]any{"user": name, "marker": "deny-all"}), nil
}

// planAccountDelete строит план удаления пользователя: SCRAM credentials и
// все его ACL удаляются вместе. На не-SCRAM подключении capability недоступна:
// идентичность живёт вне Kafka (SCRAM API нет), а её ACL снимаются revoke
// bundles (см. requireScramLifecycle).
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("kafka: plan account.delete: account engine identity is empty")
	}
	if err := requireScramLifecycle(change.Connection, "account.delete"); err != nil {
		return nil, err
	}
	return adapterutil.SingleStepPlan(change, stepDeleteUser,
		fmt.Sprintf("delete user %q: remove its SCRAM credentials and all its ACLs", name),
		map[string]any{"user": name}), nil
}

// Apply применяет план через один admin-клиент. Каждый шаг идемпотентен:
// если состояние уже целевое — StepSkipped. Ошибка шага помечает его
// StepFailed (текст без секретов), оставшиеся шаги получают StepUnknown и не
// выполняются. Клиент закрывается по defer после прогона всех шагов.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	client, err := a.newClient(plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("kafka: apply %s: %w", plan.Change.Kind, err)
	}
	defer client.close()

	return adapterutil.ApplySteps(ctx, plan, client, applyStep), nil
}

// applyStep выполняет один шаг плана.
func applyStep(ctx context.Context, c *adminClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrantPermission:
		return applyGrant(ctx, c, change)
	case stepRevokePermission:
		return applyRevoke(ctx, c, change)
	case stepCreateUser:
		return applyCreateUser(ctx, c, change)
	case stepDisableUser:
		return applyDisableUser(ctx, c, change)
	case stepEnableUser:
		return applyEnableUser(ctx, c, change)
	case stepDeleteUser:
		return applyDeleteUser(ctx, c, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyGrant создаёт недостающие ACL bundle; полный набор уже на месте —
// StepSkipped. Существование SCRAM credential не требуется: ACL в Kafka
// привязаны к имени principal, а не к учётной записи.
func applyGrant(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	kind, topic, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	current, err := c.principalACLs(ctx, user)
	if err != nil {
		return adapter.StepFailed, aclAdminUnavailable("access.grant", err)
	}
	want := bundleEntries(kind, user, topic)
	if containsAll(current, want) {
		return adapter.StepSkipped, nil
	}
	for _, b := range grantBuilders(kind, user, topic) {
		if err := c.createACLs(ctx, b); err != nil {
			return adapter.StepFailed, fmt.Errorf("grant %s to user %q: %w", change.Permission, user, err)
		}
	}
	return adapter.StepApplied, nil
}

// applyRevoke удаляет ACL bundle, сохраняя записи, которые нужны другим
// правам этого principal: DESCRIBE topic разделяют produce и consume, READ на
// group "*" — все consume. Что именно сохранить, решает desired-состояние
// ядра (см. revokeEntries), а не реконструкция из движка. Отсутствие
// удаляемых записей — StepSkipped.
func applyRevoke(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	kind, topic, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	desired, hasDesired, err := desiredEntries(change, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	current, err := c.principalACLs(ctx, user)
	if err != nil {
		return adapter.StepFailed, aclAdminUnavailable("access.revoke", err)
	}
	toDelete := revokeEntries(kind, user, topic, current, desired, hasDesired)
	if len(toDelete) == 0 {
		return adapter.StepSkipped, nil
	}
	for _, e := range toDelete {
		if err := c.deleteACLEntry(ctx, e); err != nil {
			return adapter.StepFailed, fmt.Errorf("revoke %s from user %q: %w", change.Permission, user, err)
		}
	}
	return adapter.StepApplied, nil
}

// revokeEntries вычисляет записи bundle, подлежащие удалению.
//
// Что должно пережить отзыв, определяется desired-состоянием ядра
// (change.AccountPermissions, развёрнутым в desired): запись, входящая в
// набор ACL любого другого желаемого права аккаунта, не удаляется — независимо
// от того, что сейчас ответил брокер. Реконструкция «оставить то, что видно в
// движке» опасна: неполный ответ DescribeAcls тихо превращается в удаление
// чужого права (тот же класс дефекта, что был у redis-адаптера).
//
// Исключение — записи, разделяемые МЕЖДУ scope: READ на group "*" нужен
// consume-bundle ЛЮБОГО topic, а ядро передаёт desired-набор только того же
// scope (internal/jobs, accountPermissionsAfter). Для неё desired-состояние
// заведомо неполно, поэтому решение по-прежнему принимается по наблюдаемому
// состоянию (hasOtherTopicRead), а Verify отдельно проверяет, что consume
// других topics не осталось без group READ.
//
// Если ядро desired-состояние не передало (nil), адаптер деградирует до
// прежней реконструкции из движка.
func revokeEntries(kind, user, topic string, current, desired []aclEntry, hasDesired bool) []aclEntry {
	has := func(e aclEntry) bool { return slices.Contains(current, e) }
	// shared сообщает, нужна ли запись оставшимся правам аккаунта: по
	// desired-состоянию, если оно передано, иначе — по наблюдаемому.
	shared := func(e aclEntry, observed bool) bool {
		if hasDesired {
			return slices.Contains(desired, e)
		}
		return observed
	}
	write := allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpWrite)
	describe := allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpDescribe)
	read := allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpRead)
	groupRead := allowLiteral(user, kmsg.ACLResourceTypeGroup, wildcardName, kadm.OpRead)

	var out []aclEntry
	remove := func(e aclEntry, keep bool) {
		if has(e) && !keep {
			out = append(out, e)
		}
	}
	switch kind {
	case bundleProduce:
		remove(write, shared(write, false))
		// DESCRIBE остаётся, пока его требует consume того же topic (тот же
		// scope — решает desired); без desired — пока наблюдается READ.
		remove(describe, shared(describe, has(read)))
	case bundleConsume:
		remove(read, shared(read, false))
		// DESCRIBE остаётся, пока его требует produce того же topic.
		remove(describe, shared(describe, has(write)))
		// READ на group "*" — cross-scope: остаётся, пока у principal есть
		// READ на другие topics, и пока его требует desired-состояние.
		remove(groupRead, shared(groupRead, false) || hasOtherTopicRead(current, user, topic))
	case bundleClusterAdmin:
		all := clusterAdminEntries(user)[0]
		remove(all, shared(all, false))
	}
	return out
}

// desiredEntries разворачивает desired-набор прав аккаунта
// (change.AccountPermissions) в набор ACL-записей, которые аккаунт обязан
// иметь ПОСЛЕ применения изменения. Второе значение — было ли desired-
// состояние передано ядром вообще (nil означает «не передано», см.
// adapter.DesiredChange).
//
// Неназначаемые observed permissions ("acl:...") в наборе игнорируются: они
// описывают unmanaged-правила движка, которыми grantor не управляет.
// Несогласованность с самим изменением (revoke, после которого отзываемое
// право всё ещё желаемо, или grant без выдаваемого) — ошибка: применять такой
// набор нельзя.
func desiredEntries(change adapter.DesiredChange, user string) ([]aclEntry, bool, error) {
	if change.AccountPermissions == nil {
		return nil, false, nil
	}
	switch {
	case change.Kind == adapter.ChangeRevoke && slices.Contains(change.AccountPermissions, change.Permission):
		return nil, false, fmt.Errorf(
			"desired account permissions still contain the revoked permission %q", change.Permission)
	case change.Kind == adapter.ChangeGrant && !slices.Contains(change.AccountPermissions, change.Permission):
		return nil, false, fmt.Errorf(
			"desired account permissions do not contain the granted permission %q", change.Permission)
	}

	var out []aclEntry
	for _, p := range change.AccountPermissions {
		kind, topic, err := parsePermission(p)
		if err != nil {
			continue
		}
		for _, e := range bundleEntries(kind, user, topic) {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out, true, nil
}

// desiredPermissionList возвращает отсортированную копию desired-набора прав
// аккаунта для attributes плана (секретов не содержит).
func desiredPermissionList(change adapter.DesiredChange) []string {
	out := slices.Clone(change.AccountPermissions)
	slices.Sort(out)
	return slices.Compact(out)
}

// hasOtherTopicRead сообщает, есть ли у principal ALLOW READ (literal,
// host "*") на какой-либо topic, кроме указанного.
func hasOtherTopicRead(entries []aclEntry, user, topic string) bool {
	for _, e := range entries {
		if e.resourceType == kmsg.ACLResourceTypeTopic &&
			e.pattern == kadm.ACLPatternLiteral &&
			e.perm == kmsg.ACLPermissionTypeAllow &&
			e.op == kadm.OpRead &&
			e.host == wildcardName &&
			e.principal == userPrincipal(user) &&
			e.name != topic {
			return true
		}
	}
	return false
}

// applyCreateUser создаёт SCRAM-SHA-256 credential пользователя. Существующий
// credential — не «уже сделано», а ErrExternalIdentityConflict: Plan видел его
// отсутствие, значит учётку создал кто-то другой между Plan и Apply (см.
// adapterutil.IdentityConflict). Пароль передаётся в тело запроса и нигде не
// логируется; ошибки не содержат секрета.
func applyCreateUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("password credential is required to create a user")
	}
	exists, err := c.scramExists(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if exists {
		return adapter.StepFailed, adapterutil.IdentityConflict("SCRAM credential for user", name)
	}
	if err := c.upsertSCRAM(ctx, name, string(change.Credential.Secret)); err != nil {
		return adapter.StepFailed, fmt.Errorf("create user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDisableUser добавляет DENY-маркер principal; полный маркер уже на
// месте — StepSkipped. Существующие ALLOW ACL не трогаются, поэтому enable
// полностью обратим.
func applyDisableUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	// DENY-маркер — чистый ACL и работает для любого principal. Проверку
	// существования SCRAM credential делаем только на SCRAM-подключении (там
	// она даёт понятный ErrNotFound); на не-SCRAM кластере SCRAM API нет, а
	// principal определяется его ACL.
	if c.auth.managesScram() {
		exists, err := c.scramExists(ctx, name)
		if err != nil {
			return adapter.StepFailed, err
		}
		if !exists {
			return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
		}
	}
	current, err := c.principalACLs(ctx, name)
	if err != nil {
		return adapter.StepFailed, aclAdminUnavailable("account.disable", err)
	}
	if containsAll(current, markerEntries(name)) {
		return adapter.StepSkipped, nil
	}
	if err := c.createACLs(ctx, markerBuilder(name)); err != nil {
		return adapter.StepFailed, fmt.Errorf("disable user %q: create deny marker: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyEnableUser снимает DENY-маркер; отсутствие любого следа маркера —
// StepSkipped. Частично созданный маркер тоже удаляется целиком.
func applyEnableUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	// Симметрично applyDisableUser: снятие DENY-маркера — чистый ACL, проверку
	// SCRAM credential делаем только на SCRAM-подключении.
	if c.auth.managesScram() {
		exists, err := c.scramExists(ctx, name)
		if err != nil {
			return adapter.StepFailed, err
		}
		if !exists {
			return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
		}
	}
	current, err := c.principalACLs(ctx, name)
	if err != nil {
		return adapter.StepFailed, aclAdminUnavailable("account.enable", err)
	}
	if !containsAny(current, markerEntries(name)) {
		return adapter.StepSkipped, nil
	}
	if err := c.deleteACLs(ctx, markerBuilder(name)); err != nil {
		return adapter.StepFailed, fmt.Errorf("enable user %q: remove deny marker: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDeleteUser удаляет SCRAM credentials (все механизмы) и все ACL
// principal; полное отсутствие следов — StepSkipped.
func applyDeleteUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	mechs, found, err := c.scramMechanisms(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	// account.delete — SCRAM-lifecycle: он должен снять учётку и на кластере с
	// выключенным authorizer (там ACL нет — снимаем только SCRAM credential).
	current, err := c.principalACLsTolerant(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found && len(current) == 0 {
		return adapter.StepSkipped, nil
	}
	if found {
		if err := c.deleteSCRAM(ctx, name, mechs); err != nil {
			return adapter.StepFailed, fmt.Errorf("delete user %q: remove scram credentials: %w", name, err)
		}
	}
	if len(current) > 0 {
		if err := c.deleteACLs(ctx, principalAnyBuilder(name)); err != nil {
			return adapter.StepFailed, fmt.Errorf("delete user %q: remove acls: %w", name, err)
		}
	}
	return adapter.StepApplied, nil
}

// Verify выполняет read-back проверку итогового состояния плана. Details не
// содержат секретов.
func (a *Adapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	change := plan.Change
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete:
	default:
		return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
	}
	defer client.close()
	name := change.Account.EngineIdentity

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return verifyAccess(ctx, client, change)
	case adapter.ChangeAccountCreate:
		exists, err := client.scramExists(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(exists, fmt.Sprintf("user %q has a SCRAM credential", name)), nil
	case adapter.ChangeAccountDisable:
		current, err := client.principalACLs(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
		}
		ok := containsAll(current, markerEntries(name))
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q is disabled (full deny marker present)", name)), nil
	case adapter.ChangeAccountEnable:
		current, err := client.principalACLs(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
		}
		ok := !containsAny(current, markerEntries(name))
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q is enabled (no deny marker)", name)), nil
	default: // adapter.ChangeAccountDelete
		exists, err := client.scramExists(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
		}
		// Симметрично applyDeleteUser: при выключенном authorizer ACL нет,
		// проверяем только отсутствие SCRAM credential.
		current, err := client.principalACLsTolerant(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
		}
		ok := !exists && len(current) == 0
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q is absent (no scram credential, no acls)", name)), nil
	}
}

// verifyAccess проверяет итоговое состояние grant/revoke permission bundle.
//
// Для grant требуется полный набор записей bundle. Grant только создаёт ACL,
// снять чужое право он не может, поэтому дополнительных проверок не требует.
//
// Для revoke отсутствия ключевой записи (WRITE для produce, READ для consume,
// ALL для cluster-admin) НЕДОСТАТОЧНО: revoke удаляет записи, а часть из них
// разделяется с другими правами аккаунта, и неудачное/избыточное удаление
// снимает чужой доступ, оставляя проверку «отозванного нет» зелёной. Поэтому
// дополнительно проверяются:
//
//   - сохранность desired-состояния: все ACL-записи прав, которые аккаунт
//     обязан иметь после отзыва, на месте (если ядро передало набор);
//   - инвариант consume: у principal не должно остаться READ на topic без
//     READ на group "*". Он ловит именно cross-scope потерю group READ, для
//     которой desired-набор ядра неполон (см. revokeEntries).
func verifyAccess(ctx context.Context, client *adminClient, change adapter.DesiredChange) (*adapter.Verification, error) {
	user := change.Account.EngineIdentity
	kind, topic, err := parsePermission(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
	}
	desired, hasDesired, err := desiredEntries(change, user)
	if err != nil {
		return adapterutil.VerifyResult(false, fmt.Sprintf(
			"desired account permissions for user %q are inconsistent", user)), nil
	}
	current, err := client.principalACLs(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("kafka: verify %s: %w", change.Kind, err)
	}

	if change.Kind == adapter.ChangeGrant {
		ok := containsAll(current, bundleEntries(kind, user, topic))
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q has %s", user, change.Permission)), nil
	}

	details := fmt.Sprintf("no %s for user %q", change.Permission, user)
	ok := !slices.Contains(current, keyEntry(kind, user, topic))
	switch {
	case !ok:
	case hasDesired && !containsAll(current, desired):
		ok = false
		details = fmt.Sprintf("%s, but acls of other desired permissions of user %q are missing", details, user)
	case kind == bundleConsume && groupReadLost(current, user):
		ok = false
		details = fmt.Sprintf("%s, but consume access of other topics lost read on group %q", details, wildcardName)
	case hasDesired:
		details = fmt.Sprintf("%s; acls of its remaining permissions are intact", details)
	}
	return adapterutil.VerifyResult(ok, details), nil
}

// groupReadLost сообщает, что у principal остался ALLOW READ на какой-нибудь
// topic, но READ на group "*" отсутствует: такой consume нерабочий, а
// единственный, кто мог снять эту разделяемую запись, — revoke.
func groupReadLost(entries []aclEntry, user string) bool {
	// Пустое имя topic не совпадает ни с одним реальным, поэтому вызов
	// означает «есть READ на любой topic».
	if !hasOtherTopicRead(entries, user, "") {
		return false
	}
	return !slices.Contains(entries, allowLiteral(user, kmsg.ACLResourceTypeGroup, wildcardName, kadm.OpRead))
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32).
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего пользователя через upsert
// SCRAM-SHA-256 credential. ACL пользователя не затрагиваются. Managed
// grantor-аккаунты создаются только с SCRAM-SHA-256, поэтому upsert этого
// механизма полностью инвалидирует старый пароль. Пароль не попадает в логи
// и тексты ошибок. Возвращает adapter.ErrNotFound, если пользователя нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" {
		return errors.New("kafka: rotate credential: account engine identity is empty")
	}
	if err := requireScramLifecycle(cfg, "credential.rotate"); err != nil {
		return err
	}
	if len(credential.Secret) == 0 {
		return errors.New("kafka: rotate credential: credential secret is empty")
	}

	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("kafka: rotate credential: %w", err)
	}
	defer client.close()

	exists, err := client.scramExists(ctx, name)
	if err != nil {
		return fmt.Errorf("kafka: rotate credential: %w", err)
	}
	if !exists {
		return fmt.Errorf("kafka: rotate credential: user %q: %w", name, adapter.ErrNotFound)
	}
	if err := client.upsertSCRAM(ctx, name, string(credential.Secret)); err != nil {
		return fmt.Errorf("kafka: rotate credential: set password for user %q: %w", name, err)
	}
	return nil
}

// --- Помощники уровня SCRAM и ACL ---

// scramMechanisms возвращает SCRAM-механизмы пользователя; found=false, если
// credential нет (в том числе RESOURCE_NOT_FOUND от брокера).
func (c *adminClient) scramMechanisms(ctx context.Context, name string) ([]kadm.ScramMechanism, bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	described, err := c.adm.DescribeUserSCRAMs(reqCtx, name)
	if err != nil {
		return nil, false, fmt.Errorf("describe scram user %q: %w", name, err)
	}
	res, ok := described[name]
	if !ok {
		return nil, false, nil
	}
	if res.Err != nil {
		if errors.Is(res.Err, kerr.ResourceNotFound) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("describe scram user %q: %w", name, res.Err)
	}
	if len(res.CredInfos) == 0 {
		return nil, false, nil
	}
	mechs := make([]kadm.ScramMechanism, 0, len(res.CredInfos))
	for _, ci := range res.CredInfos {
		mechs = append(mechs, ci.Mechanism)
	}
	return mechs, true, nil
}

// scramExists сообщает, есть ли у пользователя хотя бы один SCRAM credential.
func (c *adminClient) scramExists(ctx context.Context, name string) (bool, error) {
	_, found, err := c.scramMechanisms(ctx, name)
	return found, err
}

// upsertSCRAM создаёт/обновляет SCRAM-SHA-256 credential пользователя.
func (c *adminClient) upsertSCRAM(ctx context.Context, name, password string) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	altered, err := c.adm.AlterUserSCRAMs(reqCtx, nil, []kadm.UpsertSCRAM{{
		User:       name,
		Mechanism:  kadm.ScramSha256,
		Iterations: scramIterations,
		Password:   password,
	}})
	if err != nil {
		return err
	}
	return altered.Error()
}

// deleteSCRAM удаляет указанные SCRAM-механизмы пользователя.
func (c *adminClient) deleteSCRAM(ctx context.Context, name string, mechs []kadm.ScramMechanism) error {
	del := make([]kadm.DeleteSCRAM, 0, len(mechs))
	for _, m := range mechs {
		del = append(del, kadm.DeleteSCRAM{User: name, Mechanism: m})
	}
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	altered, err := c.adm.AlterUserSCRAMs(reqCtx, del, nil)
	if err != nil {
		return err
	}
	return altered.Error()
}

// createACLs создаёт ACL по builder и проверяет результат каждой записи.
// Создание уже существующей записи в Kafka — no-op, поэтому вызов идемпотентен.
func (c *adminClient) createACLs(ctx context.Context, b *kadm.ACLBuilder) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	results, err := c.adm.CreateACLs(reqCtx, b)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("create acl %s %s %s: %w",
				lower(r.Type.String()), r.Name, lower(r.Operation.String()), r.Err)
		}
	}
	return nil
}

// deleteACLs удаляет ACL по builder и проверяет результат каждого фильтра.
func (c *adminClient) deleteACLs(ctx context.Context, b *kadm.ACLBuilder) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	results, err := c.adm.DeleteACLs(reqCtx, b)
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Err != nil {
			return fmt.Errorf("delete acls filter: %w", r.Err)
		}
		for _, d := range r.Deleted {
			if d.Err != nil {
				return fmt.Errorf("delete acl %s %s %s: %w",
					lower(d.Type.String()), d.Name, lower(d.Operation.String()), d.Err)
			}
		}
	}
	return nil
}

// deleteACLEntry удаляет одну точную ACL-запись (literal-фильтр по всем
// компонентам записи).
func (c *adminClient) deleteACLEntry(ctx context.Context, e aclEntry) error {
	b := kadm.NewACLs().
		ResourcePatternType(e.pattern).
		Operations(e.op)
	switch e.resourceType {
	case kmsg.ACLResourceTypeTopic:
		b = b.Topics(e.name)
	case kmsg.ACLResourceTypeGroup:
		b = b.Groups(e.name)
	case kmsg.ACLResourceTypeCluster:
		b = b.Clusters()
	case kmsg.ACLResourceTypeTransactionalId:
		b = b.TransactionalIDs(e.name)
	default:
		return fmt.Errorf("unsupported acl resource type %q", e.resourceType.String())
	}
	if e.perm == kmsg.ACLPermissionTypeDeny {
		b = b.Deny(e.principal).DenyHosts(e.host)
	} else {
		b = b.Allow(e.principal).AllowHosts(e.host)
	}
	return c.deleteACLs(ctx, b)
}

// grantBuilders возвращает builders создания ACL bundle. Builder перемножает
// ресурсы и операции, поэтому bundle с разными наборами операций на разных
// типах ресурсов (consume) собирается из двух builders.
func grantBuilders(kind, user, topic string) []*kadm.ACLBuilder {
	p := userPrincipal(user)
	base := func() *kadm.ACLBuilder {
		return kadm.NewACLs().Allow(p).AllowHosts(wildcardName).
			ResourcePatternType(kadm.ACLPatternLiteral)
	}
	switch kind {
	case bundleProduce:
		return []*kadm.ACLBuilder{
			base().Topics(topic).Operations(kadm.OpWrite, kadm.OpDescribe),
		}
	case bundleConsume:
		return []*kadm.ACLBuilder{
			base().Topics(topic).Operations(kadm.OpRead, kadm.OpDescribe),
			base().Groups(wildcardName).Operations(kadm.OpRead),
		}
	default: // bundleClusterAdmin
		return []*kadm.ACLBuilder{
			base().Clusters().Operations(kadm.OpAll),
		}
	}
}

// markerBuilder возвращает builder DENY-маркера disable (см. markerEntries).
func markerBuilder(user string) *kadm.ACLBuilder {
	return kadm.NewACLs().
		Deny(userPrincipal(user)).DenyHosts(wildcardName).
		ResourcePatternType(kadm.ACLPatternLiteral).
		Topics(wildcardName).Groups(wildcardName).Clusters().
		Operations(kadm.OpAll)
}

// principalAnyBuilder возвращает фильтр всех ACL principal (allow и deny,
// любые ресурсы, patterns, операции и hosts) для полного удаления.
func principalAnyBuilder(user string) *kadm.ACLBuilder {
	p := userPrincipal(user)
	return kadm.NewACLs().
		AnyResource().
		ResourcePatternType(kadm.ACLPatternAny).
		Operations(kadm.OpAny).
		Allow(p).AllowHosts().
		Deny(p).DenyHosts()
}

// --- Чистые помощники ---

// parsePermission разбирает external id permission bundle на вид и topic:
// "topic-produce:<t>" -> (bundleProduce, t); "topic-consume:<t>" ->
// (bundleConsume, t); "cluster-admin" -> (bundleClusterAdmin, ""). Observed
// acl-permissions ("acl:...") не назначаемы и отклоняются.
func parsePermission(perm string) (kind, topic string, err error) {
	if perm == clusterAdminPermission {
		return bundleClusterAdmin, "", nil
	}
	if v, ok := strings.CutPrefix(perm, producePermissionPrefix); ok {
		if v == "" {
			return "", "", fmt.Errorf("permission %q has empty topic name", perm)
		}
		return bundleProduce, v, nil
	}
	if v, ok := strings.CutPrefix(perm, consumePermissionPrefix); ok {
		if v == "" {
			return "", "", fmt.Errorf("permission %q has empty topic name", perm)
		}
		return bundleConsume, v, nil
	}
	return "", "", fmt.Errorf("permission %q is not an assignable kafka permission (want %q, %q or %q)",
		perm, producePermissionPrefix+"<topic>", consumePermissionPrefix+"<topic>", clusterAdminPermission)
}

// bundleEntries возвращает канонический набор ACL-записей bundle.
func bundleEntries(kind, user, topic string) []aclEntry {
	switch kind {
	case bundleProduce:
		return produceEntries(user, topic)
	case bundleConsume:
		return consumeEntries(user, topic)
	default: // bundleClusterAdmin
		return clusterAdminEntries(user)
	}
}

// keyEntry возвращает ключевую запись bundle — ту, отсутствие которой
// означает отсутствие binding (WRITE для produce, READ для consume, ALL для
// cluster-admin).
func keyEntry(kind, user, topic string) aclEntry {
	switch kind {
	case bundleProduce:
		return allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpWrite)
	case bundleConsume:
		return allowLiteral(user, kmsg.ACLResourceTypeTopic, topic, kadm.OpRead)
	default: // bundleClusterAdmin
		return clusterAdminEntries(user)[0]
	}
}

// containsAll сообщает, содержит ли have все записи want.
func containsAll(have, want []aclEntry) bool {
	for _, e := range want {
		if !slices.Contains(have, e) {
			return false
		}
	}
	return true
}

// containsAny сообщает, содержит ли have хотя бы одну запись want.
func containsAny(have, want []aclEntry) bool {
	for _, e := range want {
		if slices.Contains(have, e) {
			return true
		}
	}
	return false
}

// aclAdminUnavailable распознаёт в ошибке DescribeAcls выключенный ACL-
// авторизатор (SECURITY_DISABLED) и превращает её в
// adapter.ErrUnsupportedChange с явным сообщением: ACL-мутации (grant/revoke и
// disable/enable через DENY-маркеры) на таком кластере невозможны. Состояние
// authorizer — рантайм-свойство кластера (в отличие от механизма SASL,
// известного статически), поэтому downgrade выполняется не на Plan, а в начале
// шага Apply, при первом же DescribeAcls, до любой мутации; вызывающий
// распознаёт отказ через errors.Is (симметрично requireScramLifecycle).
// Ошибка не про authorizer (в т.ч. nil) пробрасывается как есть.
func aclAdminUnavailable(op string, err error) error {
	if isSecurityDisabled(err) {
		return fmt.Errorf("kafka: %s: %w: ACL authorizer disabled on this cluster; grant/revoke/disable/enable unavailable",
			op, adapter.ErrUnsupportedChange)
	}
	return err
}

// requireScramLifecycle отклоняет SCRAM-lifecycle операции (account.create/
// account.delete/credential.rotate) на не-SCRAM подключении: единственный
// способ управлять учётными данными — SCRAM API, которого там нет. Ошибка
// оборачивает adapter.ErrUnsupportedChange, чтобы вызывающий распознал
// недоступность capability через errors.Is ещё до Apply. Ошибка конфигурации
// (несогласованный auth) возвращается как есть.
func requireScramLifecycle(cfg adapter.Connection, op string) error {
	auth, err := parseAuthConfig(cfg)
	if err != nil {
		return fmt.Errorf("kafka: plan %s: %w", op, err)
	}
	if !auth.managesScram() {
		return fmt.Errorf("kafka: %s: %w: requires a SCRAM mechanism, connection uses sasl mechanism %q",
			op, adapter.ErrUnsupportedChange, auth.mechanism)
	}
	return nil
}
