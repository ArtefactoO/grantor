package rabbitmq

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана RabbitMQ adapter.
const (
	stepGrantTag    = "grant-tag"
	stepRevokeTag   = "revoke-tag"
	stepGrantVhost  = "grant-vhost-permission"
	stepRevokeVhost = "revoke-vhost-permission"
	stepCreateUser  = "create-user"
	stepRestoreUser = "restore-user"
	stepDisableUser = "disable-user"
	stepEnableUser  = "enable-user"
	stepDeleteUser  = "delete-user"
)

// Виды permission-определений (см. parsePermission).
const (
	permKindTag   = "tag"
	permKindVhost = "vhost"
)

// userTagsPayload — тело PUT /api/users/{name}, меняющее только теги: пароль
// сохраняется через password_hash + hashing_algorithm (иначе PUT сбросил бы
// его). Поля без omitempty: пустой password_hash — валидное состояние
// (беспарольный пользователь), которое нужно сохранить как есть.
type userTagsPayload struct {
	PasswordHash     string `json:"password_hash"`
	HashingAlgorithm string `json:"hashing_algorithm"`
	Tags             string `json:"tags"`
}

// userPasswordPayload — тело PUT /api/users/{name}, задающее новый пароль
// (RabbitMQ хеширует его на стороне сервера) и набор тегов.
type userPasswordPayload struct {
	Password string `json:"password"`
	Tags     string `json:"tags"`
}

// permissionPayload — тело PUT /api/permissions/{vhost}/{user}.
type permissionPayload struct {
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

// Plan строит детерминированный типизированный план для DesiredChange.
// Descriptions и attributes шагов не содержат секретных значений. Валидации
// существования на этапе плана нет (её выполняет идемпотентный Apply) — кроме
// account.restore, где существующая identity обязана быть подтверждена
// credential proof до применения плана.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return planAccess(change)
	case adapter.ChangeAccountCreate:
		return a.planAccountCreate(ctx, change)
	case adapter.ChangeAccountRestore:
		return a.planAccountRestore(ctx, change)
	case adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		return planDisableEnable(change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	default:
		return nil, fmt.Errorf("rabbitmq: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planAccess строит план grant/revoke tag- или vhost-permission. Вид permission
// определяется по external id (см. parsePermission).
func planAccess(change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	user := change.Account.EngineIdentity
	if user == "" {
		return nil, fmt.Errorf("rabbitmq: plan %s: account engine identity is empty", op)
	}
	kind, value, err := parsePermission(change.Permission)
	target, template := permissionTuple{}, false
	monitoring := strings.HasPrefix(change.Permission, vhostMonitoringPermissionPrefix)
	if strings.HasPrefix(change.Permission, templatePermissionPrefix) || monitoring {
		target, template, err = permissionTarget(change)
		kind, value = permKindVhost, target.Vhost
	}
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: plan %s: %w", op, err)
	}
	revoke := change.Kind == adapter.ChangeRevoke

	switch kind {
	case permKindTag:
		// Тег RabbitMQ действует на весь кластер: сузить его до vhost нельзя.
		// Молча проигнорировать scope хуже, чем отказать: binding записался бы
		// с scope_resource_id, и control plane показывал бы кластерное право
		// как ограниченное одним vhost.
		if change.Scope != "" {
			return nil, fmt.Errorf("rabbitmq: plan %s: tag %q is cluster-wide and cannot be scoped to %q: %w",
				op, value, change.Scope, adapter.ErrUnsupportedChange)
		}
		stepKind, desc := stepGrantTag, fmt.Sprintf("grant tag %q to user %q", value, user)
		if revoke {
			stepKind, desc = stepRevokeTag, fmt.Sprintf("revoke tag %q from user %q", value, user)
		}
		return adapterutil.SingleStepPlan(change, stepKind, desc, map[string]any{"user": user, "tag": value}), nil
	case permKindVhost:
		// Область vhost-permission — сам vhost из его external id. Явно
		// заданная область допустима только как повторение этого же vhost
		// (её подставляет EffectiveBindingScope); чужой resource означал бы
		// право не на том vhost, чем оно на самом деле является.
		if change.Scope != "" && change.Scope != vhostExternalID(value) {
			return nil, fmt.Errorf(
				"rabbitmq: plan %s: permission on vhost %q cannot be scoped to %q: %w",
				op, value, change.Scope, adapter.ErrUnsupportedChange)
		}
		accessName := "full access"
		if template {
			accessName = fmt.Sprintf("template %q", strings.TrimPrefix(change.Permission, templatePermissionPrefix))
		} else if monitoring {
			accessName = "monitoring visibility"
		}
		stepKind, desc := stepGrantVhost, fmt.Sprintf("grant %s on vhost %q to user %q", accessName, value, user)
		if revoke {
			stepKind, desc = stepRevokeVhost, fmt.Sprintf("revoke %s on vhost %q from user %q", accessName, value, user)
		}
		attrs := map[string]any{"user": user, "vhost": value}
		if template {
			attrs["template_key"] = strings.TrimPrefix(change.Permission, templatePermissionPrefix)
		}
		if template || monitoring {
			attrs["configure"], attrs["write"], attrs["read"] = target.Configure, target.Write, target.Read
		}
		return adapterutil.SingleStepPlan(change, stepKind, desc, attrs), nil
	default:
		return nil, fmt.Errorf("rabbitmq: plan %s: %w", op, adapter.ErrUnsupportedChange)
	}
}

// planAccountCreate строит план создания пользователя с паролем. Пароль
// обязателен и берётся из change.Credential; в план он не попадает — только
// факт его наличия. Пользователь не должен существовать: existing identity
// отклоняется здесь, до резервирования credential (см.
// adapterutil.IdentityConflict).
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("rabbitmq: plan account.create: account engine identity is empty")
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("rabbitmq: plan account.create: password credential is required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: plan account.create: %w", err)
	}
	if _, found, err := client.getUser(ctx, name); err != nil {
		return nil, fmt.Errorf("rabbitmq: plan account.create: %w", err)
	} else if found {
		return nil, fmt.Errorf("rabbitmq: plan account.create: %w", adapterutil.IdentityConflict("user", name))
	}
	return accountCreatePlan(change), nil
}

// accountCreatePlan собирает сам план создания — без обращения к target.
// Отделено от planAccountCreate, чтобы форму плана (шаг, атрибуты, отсутствие
// секрета в description) можно было проверять без поднятого RabbitMQ.
func accountCreatePlan(change adapter.DesiredChange) *adapter.Plan {
	name := change.Account.EngineIdentity
	return adapterutil.SingleStepPlan(change, stepCreateUser,
		fmt.Sprintf("create user %q and set its password", name),
		map[string]any{"user": name, "with_password": true})
}

// planAccountRestore различает absent и present identity. Absent создаётся с
// новым credential. Present допустима только как recovery retry после
// доказательства точного credential; обычный account.create здесь никогда не
// используется, поэтому чужой существующий пользователь не перезаписывается —
// это критично именно для RabbitMQ, где PUT /api/users перезаписал бы пароль
// и теги существующей учётки.
func (a *Adapter) planAccountRestore(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" || !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("rabbitmq: plan account.restore: account identity and credential are required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: plan account.restore: %w", err)
	}
	_, found, err := client.getUser(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: plan account.restore: %w", err)
	}
	if !found {
		return adapterutil.SingleStepPlan(change, stepRestoreUser,
			fmt.Sprintf("restore user %q with a fresh credential", name),
			map[string]any{"user": name, "recovery": false}), nil
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return nil, fmt.Errorf("rabbitmq: plan account.restore: existing user %q: %w", name, err)
	}
	return adapterutil.SingleStepPlan(change, stepRestoreUser,
		fmt.Sprintf("recover already restored user %q after credential proof", name),
		map[string]any{"user": name, "recovery": true}), nil
}

// planDisableEnable строит план disable/enable. Disable снимает всю
// авторизацию (см. doc-комментарий пакета), enable снимает маркер.
func planDisableEnable(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, fmt.Errorf("rabbitmq: plan %s: account engine identity is empty", change.Kind)
	}
	if change.Kind == adapter.ChangeAccountDisable {
		return adapterutil.SingleStepPlan(change, stepDisableUser,
			fmt.Sprintf("disable user %q: remove all vhost permissions and replace tags with the %q marker",
				name, disabledMarkerTag),
			map[string]any{"user": name, "marker": disabledMarkerTag}), nil
	}
	return adapterutil.SingleStepPlan(change, stepEnableUser,
		fmt.Sprintf("enable user %q: remove the %q marker tag; its permissions are restored "+
			"by the core from the desired state of its bindings", name, disabledMarkerTag),
		map[string]any{"user": name, "marker": disabledMarkerTag}), nil
}

// planAccountDelete строит план удаления пользователя. Description
// предупреждает, что вместе с пользователем исчезнут его permissions и теги.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("rabbitmq: plan account.delete: account engine identity is empty")
	}
	return adapterutil.SingleStepPlan(change, stepDeleteUser,
		fmt.Sprintf("delete user %q; its permissions and tags disappear with it", name),
		map[string]any{"user": name}), nil
}

// Apply применяет план через один HTTP-клиент. Каждый шаг идемпотентен: если
// состояние уже целевое — StepSkipped. Ошибка шага помечает его StepFailed
// (текст без секретов), оставшиеся шаги получают StepUnknown и не выполняются.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	client, err := a.newClient(plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: apply %s: %w", plan.Change.Kind, err)
	}

	return adapterutil.ApplySteps(ctx, plan, client, applyStep), nil
}

// applyStep выполняет один шаг плана.
func applyStep(ctx context.Context, c *mgmtClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrantTag:
		return applyGrantTag(ctx, c, change)
	case stepRevokeTag:
		return applyRevokeTag(ctx, c, change)
	case stepGrantVhost:
		return applyGrantVhost(ctx, c, change)
	case stepRevokeVhost:
		return applyRevokeVhost(ctx, c, change)
	case stepCreateUser:
		return applyCreateUser(ctx, c, change)
	case stepRestoreUser:
		return applyRestoreUser(ctx, c, change, step)
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

// applyGrantTag добавляет тег пользователю; уже присутствующий тег —
// StepSkipped. Пароль пользователя не трогается (PUT сохраняет password_hash).
func applyGrantTag(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	_, tag, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	u, found, err := c.getUser(ctx, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", user, adapter.ErrNotFound)
	}
	tags := parseTags(u.Tags)
	if hasTag(tags, tag) {
		return adapter.StepSkipped, nil
	}
	if err := c.putUserTags(ctx, u, withTag(tags, tag)); err != nil {
		return adapter.StepFailed, fmt.Errorf("grant tag %q to user %q: %w", tag, user, err)
	}
	return adapter.StepApplied, nil
}

// applyRevokeTag снимает тег с пользователя; отсутствующий тег или пользователь
// — StepSkipped.
func applyRevokeTag(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	_, tag, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	u, found, err := c.getUser(ctx, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	tags := parseTags(u.Tags)
	if !found || !hasTag(tags, tag) {
		return adapter.StepSkipped, nil
	}
	if err := c.putUserTags(ctx, u, withoutTag(tags, tag)); err != nil {
		return adapter.StepFailed, fmt.Errorf("revoke tag %q from user %q: %w", tag, user, err)
	}
	return adapter.StepApplied, nil
}

// applyGrantVhost приводит единственный permission slot user+vhost к точной
// тройке legacy full access либо выбранного template.
func applyGrantVhost(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	target, _, err := permissionTarget(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	_, found, err := c.getUser(ctx, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", user, adapter.ErrNotFound)
	}
	p, has, err := c.getPermission(ctx, target.Vhost, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	if has && tupleMatches(p, target) {
		return adapter.StepSkipped, nil
	}
	if err := c.setPermission(ctx, target.Vhost, user, permissionPayload{
		Configure: target.Configure, Write: target.Write, Read: target.Read,
	}); err != nil {
		return adapter.StepFailed, fmt.Errorf("grant access on vhost %q to user %q: %w", target.Vhost, user, err)
	}
	return adapter.StepApplied, nil
}

// applyRevokeVhost удаляет permission пользователя на vhost; отсутствующая
// запись — StepSkipped.
func applyRevokeVhost(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	target, _, err := permissionTarget(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	_, has, err := c.getPermission(ctx, target.Vhost, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !has {
		return adapter.StepSkipped, nil
	}
	if err := c.deletePermission(ctx, target.Vhost, user); err != nil {
		return adapter.StepFailed, fmt.Errorf("revoke access on vhost %q from user %q: %w", target.Vhost, user, err)
	}
	return adapter.StepApplied, nil
}

// applyCreateUser создаёт пользователя с паролем и без тегов. Существующий
// пользователь — не «уже сделано», а ErrExternalIdentityConflict: Plan видел
// его отсутствие, значит учётку создал кто-то другой между Plan и Apply (см.
// adapterutil.IdentityConflict). Это критично именно для RabbitMQ, где PUT
// перезаписал бы пароль и теги живой учётки. Пароль передаётся в теле запроса
// и нигде не логируется; ошибка не содержит секрета.
func applyCreateUser(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("password credential is required to create a user")
	}
	_, found, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if found {
		return adapter.StepFailed, adapterutil.IdentityConflict("user", name)
	}
	if err := c.putUserPassword(ctx, name, string(change.Credential.Secret), nil); err != nil {
		return adapter.StepFailed, fmt.Errorf("create user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyRestoreUser пересоздаёт пользователя с зарезервированным паролем и без
// тегов одним запросом PUT /api/users/{name}. Отдельная атомарная обёртка (как
// транзакция в postgres adapter) не нужна: RabbitMQ задаёт пароль тем же
// запросом, поэтому identity не может появиться без зарезервированного
// credential.
//
// Существующая identity допустима только как recovery retry — её credential
// доказан на этапе Plan, и шаг даёт StepSkipped. Это принципиально: PUT
// перезаписал бы пароль и теги живой учётки. Identity, появившаяся между Plan
// и Apply, — ErrExternalIdentityConflict.
func applyRestoreUser(ctx context.Context, c *mgmtClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("credential is required to restore a user")
	}
	_, found, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if found {
		if recovery, _ := step.Attributes["recovery"].(bool); recovery {
			return adapter.StepSkipped, nil
		}
		return adapter.StepFailed, fmt.Errorf("user %q appeared after planning: %w",
			name, adapter.ErrExternalIdentityConflict)
	}
	if err := c.putUserPassword(ctx, name, string(change.Credential.Secret), nil); err != nil {
		return adapter.StepFailed, fmt.Errorf("restore user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDisableUser снимает всю авторизацию пользователя: удаляет все его
// permissions и заменяет теги маркером grantor_disabled (пароль сохраняется).
// Уже отключённый пользователь (только маркер и без permissions) — StepSkipped.
func applyDisableUser(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	u, found, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
	}

	perms, err := c.listUserPermissions(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	changed := false
	for _, p := range perms {
		if err := c.deletePermission(ctx, p.Vhost, name); err != nil {
			return adapter.StepFailed, fmt.Errorf("disable user %q: remove permission on vhost %q: %w", name, p.Vhost, err)
		}
		changed = true
	}
	if !isDisabledTagSet(parseTags(u.Tags)) {
		if err := c.putUserTags(ctx, u, []string{disabledMarkerTag}); err != nil {
			return adapter.StepFailed, fmt.Errorf("disable user %q: set marker tag: %w", name, err)
		}
		changed = true
	}
	if changed {
		return adapter.StepApplied, nil
	}
	return adapter.StepSkipped, nil
}

// applyEnableUser снимает маркер grantor_disabled; пользователь без маркера —
// StepSkipped. Конкретные permissions этот шаг НЕ возвращает: их уничтожил
// disable, а источник истины для восстановления — desired state bindings
// ядра. Ядро выполняет его отдельными grant-изменениями сразу после этого
// шага (manifest объявляет AccountDisableEffect = DisableClearsAccess).
func applyEnableUser(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	u, found, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
	}
	tags := parseTags(u.Tags)
	if !hasTag(tags, disabledMarkerTag) {
		return adapter.StepSkipped, nil
	}
	if err := c.putUserTags(ctx, u, withoutTag(tags, disabledMarkerTag)); err != nil {
		return adapter.StepFailed, fmt.Errorf("enable user %q: remove marker tag: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDeleteUser удаляет пользователя; отсутствующий пользователь —
// StepSkipped.
func applyDeleteUser(ctx context.Context, c *mgmtClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	_, found, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepSkipped, nil
	}
	if err := c.deleteUser(ctx, name); err != nil {
		return adapter.StepFailed, fmt.Errorf("delete user %q: %w", name, err)
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
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
		adapter.ChangeAccountRestore:
	default:
		return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
	}
	name := change.Account.EngineIdentity

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return verifyAccess(ctx, client, change)
	case adapter.ChangeAccountCreate:
		_, found, err := client.getUser(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(found, fmt.Sprintf("user %q exists", name)), nil
	case adapter.ChangeAccountRestore:
		return a.verifyRestored(ctx, client, change)
	case adapter.ChangeAccountDisable:
		return verifyDisabled(ctx, client, name)
	case adapter.ChangeAccountEnable:
		u, found, err := client.getUser(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		ok := found && !hasTag(parseTags(u.Tags), disabledMarkerTag)
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q is enabled (no %q marker)", name, disabledMarkerTag)), nil
	default: // adapter.ChangeAccountDelete
		_, found, err := client.getUser(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(!found, fmt.Sprintf("user %q is absent", name)), nil
	}
}

// verifyAccess проверяет итоговое состояние grant/revoke tag- или
// vhost-permission.
func verifyAccess(ctx context.Context, client *mgmtClient, change adapter.DesiredChange) (*adapter.Verification, error) {
	name := change.Account.EngineIdentity
	kind, value, err := parsePermission(change.Permission)
	if strings.HasPrefix(change.Permission, templatePermissionPrefix) {
		target, _, targetErr := permissionTarget(change)
		if targetErr != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, targetErr)
		}
		kind, value, err = permKindVhost, target.Vhost, nil
	}
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
	}
	grant := change.Kind == adapter.ChangeGrant

	switch kind {
	case permKindTag:
		u, found, err := client.getUser(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		has := found && hasTag(parseTags(u.Tags), value)
		what := fmt.Sprintf("user %q has tag %q", name, value)
		if grant {
			return adapterutil.VerifyResult(has, what), nil
		}
		return adapterutil.VerifyResult(!has, "no "+what), nil
	case permKindVhost:
		target, _, err := permissionTarget(change)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		actual, has, err := client.getPermission(ctx, value, name)
		if err != nil {
			return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, err)
		}
		exact := has && tupleMatches(actual, target)
		what := fmt.Sprintf("user %q has exact permission on vhost %q", name, value)
		if grant {
			return adapterutil.VerifyResult(exact, what), nil
		}
		return adapterutil.VerifyResult(!has, "no permission in assignment slot for "+what), nil
	default:
		return nil, fmt.Errorf("rabbitmq: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// verifyRestored проверяет, что пользователь восстановлен: существует, не
// помечен маркером disabled и реально пускает по зарезервированному паролю.
// Наличия записи в /api/users недостаточно, поэтому read-back дополняется
// credential proof (тем же, что и на этапе Plan).
func (a *Adapter) verifyRestored(ctx context.Context, client *mgmtClient, change adapter.DesiredChange) (*adapter.Verification, error) {
	name := change.Account.EngineIdentity
	u, found, err := client.getUser(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: verify account.restore: %w", err)
	}
	if !found || hasTag(parseTags(u.Tags), disabledMarkerTag) {
		return adapterutil.VerifyResult(false, fmt.Sprintf(
			"user %q exists and can log in with the reserved credential", name)), nil
	}
	if change.Credential == nil {
		return nil, errors.New("rabbitmq: verify account.restore: credential is required")
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return nil, fmt.Errorf("rabbitmq: verify account.restore: %w", err)
	}
	return adapterutil.VerifyResult(true, fmt.Sprintf(
		"user %q exists and the reserved credential is proved", name)), nil
}

// verifyDisabled проверяет, что пользователь отключён: существует, помечен
// маркером и не имеет ни одного permission.
func verifyDisabled(ctx context.Context, client *mgmtClient, name string) (*adapter.Verification, error) {
	u, found, err := client.getUser(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: verify account.disable: %w", err)
	}
	if !found {
		return adapterutil.VerifyResult(false, fmt.Sprintf("user %q is absent", name)), nil
	}
	perms, err := client.listUserPermissions(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("rabbitmq: verify account.disable: %w", err)
	}
	ok := hasTag(parseTags(u.Tags), disabledMarkerTag) && len(perms) == 0
	return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q is disabled (marker set, no permissions)", name)), nil
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32).
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего пользователя, сохраняя его теги
// (PUT перезаписал бы их). Пароль не попадает в логи и тексты ошибок. Возвращает
// adapter.ErrNotFound, если пользователя нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" {
		return errors.New("rabbitmq: rotate credential: account engine identity is empty")
	}
	if len(credential.Secret) == 0 {
		return errors.New("rabbitmq: rotate credential: credential secret is empty")
	}

	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("rabbitmq: rotate credential: %w", err)
	}
	u, found, err := client.getUser(ctx, name)
	if err != nil {
		return fmt.Errorf("rabbitmq: rotate credential: %w", err)
	}
	if !found {
		return fmt.Errorf("rabbitmq: rotate credential: user %q: %w", name, adapter.ErrNotFound)
	}
	if err := client.putUserPassword(ctx, name, string(credential.Secret), parseTags(u.Tags)); err != nil {
		return fmt.Errorf("rabbitmq: rotate credential: set password for user %q: %w", name, err)
	}
	return nil
}

// --- HTTP-помощники уровня пользователей и permissions ---

// getUser читает пользователя; found=false при 404.
func (c *mgmtClient) getUser(ctx context.Context, name string) (apiUser, bool, error) {
	var u apiUser
	found, err := c.getJSON(ctx, "/api/users/"+escapePath(name), &u)
	if err != nil {
		return apiUser{}, false, fmt.Errorf("read user %q: %w", name, err)
	}
	return u, found, nil
}

// listUserPermissions читает все permissions пользователя; отсутствующий
// пользователь (404) даёт пустой список без ошибки.
func (c *mgmtClient) listUserPermissions(ctx context.Context, name string) ([]apiPermission, error) {
	var perms []apiPermission
	if _, err := c.getJSON(ctx, "/api/users/"+escapePath(name)+"/permissions", &perms); err != nil {
		return nil, fmt.Errorf("read permissions of user %q: %w", name, err)
	}
	return perms, nil
}

// getPermission читает permission пользователя на vhost; found=false при 404.
func (c *mgmtClient) getPermission(ctx context.Context, vhost, user string) (apiPermission, bool, error) {
	var p apiPermission
	found, err := c.getJSON(ctx, "/api/permissions/"+escapePath(vhost)+"/"+escapePath(user), &p)
	if err != nil {
		return apiPermission{}, false, fmt.Errorf("read permission of user %q on vhost %q: %w", user, vhost, err)
	}
	return p, found, nil
}

// putUserTags меняет теги пользователя, сохраняя его пароль.
func (c *mgmtClient) putUserTags(ctx context.Context, u apiUser, tags []string) error {
	payload := userTagsPayload{
		PasswordHash:     u.PasswordHash,
		HashingAlgorithm: u.HashingAlgorithm,
		Tags:             joinTags(tags),
	}
	_, err := c.send(ctx, http.MethodPut, "/api/users/"+escapePath(u.Name), payload)
	return err
}

// putUserPassword создаёт/обновляет пользователя с заданным паролем и тегами.
func (c *mgmtClient) putUserPassword(ctx context.Context, name, password string, tags []string) error {
	payload := userPasswordPayload{Password: password, Tags: joinTags(tags)}
	_, err := c.send(ctx, http.MethodPut, "/api/users/"+escapePath(name), payload)
	return err
}

// deleteUser удаляет пользователя.
func (c *mgmtClient) deleteUser(ctx context.Context, name string) error {
	_, err := c.send(ctx, http.MethodDelete, "/api/users/"+escapePath(name), nil)
	return err
}

// setPermission writes the exact configure/write/read tuple for one user/vhost
// assignment slot.
func (c *mgmtClient) setPermission(ctx context.Context, vhost, user string, payload permissionPayload) error {
	_, err := c.send(ctx, http.MethodPut, "/api/permissions/"+escapePath(vhost)+"/"+escapePath(user), payload)
	return err
}

// deletePermission удаляет permission пользователя на vhost.
func (c *mgmtClient) deletePermission(ctx context.Context, vhost, user string) error {
	_, err := c.send(ctx, http.MethodDelete, "/api/permissions/"+escapePath(vhost)+"/"+escapePath(user), nil)
	return err
}

// --- Чистые помощники ---

// parsePermission разбирает external id permission на вид и значение:
// "tag:<name>" -> (permKindTag, name); vhost access/monitoring prefixes ->
// (permKindVhost, vhost).
func parsePermission(perm string) (kind, value string, err error) {
	if v, ok := strings.CutPrefix(perm, tagPermissionPrefix); ok {
		if v == "" {
			return "", "", fmt.Errorf("permission %q has empty tag name", perm)
		}
		return permKindTag, v, nil
	}
	for _, prefix := range []string{vhostPermissionPrefix, vhostMonitoringPermissionPrefix} {
		if v, ok := strings.CutPrefix(perm, prefix); ok {
			if v == "" {
				return "", "", fmt.Errorf("permission %q has empty vhost name", perm)
			}
			return permKindVhost, v, nil
		}
	}
	return "", "", fmt.Errorf("permission %q is not a rabbitmq permission (want %q, %q or %q prefix)",
		perm, tagPermissionPrefix, vhostPermissionPrefix, vhostMonitoringPermissionPrefix)
}

// isFullAccess сообщает, даёт ли permission полный доступ (.*/.*/.*).
func isFullAccess(p apiPermission) bool {
	return p.Configure == fullAccessRegex && p.Write == fullAccessRegex && p.Read == fullAccessRegex
}

// isDisabledTagSet сообщает, что набор тегов состоит ровно из маркера
// grantor_disabled (целевое состояние disabled-пользователя по тегам).
func isDisabledTagSet(tags []string) bool {
	return len(tags) == 1 && tags[0] == disabledMarkerTag
}

// withTag возвращает копию tags с добавленным tag, если его ещё нет.
func withTag(tags []string, tag string) []string {
	if slices.Contains(tags, tag) {
		return slices.Clone(tags)
	}
	return append(slices.Clone(tags), tag)
}

// withoutTag возвращает копию tags без всех вхождений tag.
func withoutTag(tags []string, tag string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if t != tag {
			out = append(out, t)
		}
	}
	return out
}

// joinTags превращает набор тегов в детерминированную строку через запятую
// (отсортированные уникальные значения) для тела запроса Management API.
func joinTags(tags []string) string {
	uniq := slices.Clone(tags)
	slices.Sort(uniq)
	uniq = slices.Compact(uniq)
	return strings.Join(uniq, ",")
}
