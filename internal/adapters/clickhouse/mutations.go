package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана ClickHouse adapter.
const (
	stepGrantRole   = "grant-role"
	stepRevokeRole  = "revoke-role"
	stepCreateUser  = "create-user"
	stepRestoreUser = "restore-user"
	stepDisableUser = "disable-user"
	stepEnableUser  = "enable-user"
	stepDropUser    = "drop-user"
)

// Plan строит детерминированный типизированный план для DesiredChange.
// Descriptions и attributes шагов не содержат секретных значений. Валидации
// существования на этапе плана нет (её выполняет идемпотентный Apply) —
// кроме account.restore, где существующая identity обязана быть подтверждена
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
		return a.planDisableEnable(ctx, change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	default:
		return nil, fmt.Errorf("clickhouse: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planAccess строит план grant/revoke роли. Назначаемая единица — только
// роль ("role:<name>"); прямые privilege-гранты ("priv:...") наблюдаемые и
// через Plan не выдаются. Роли ClickHouse cluster-wide, поэтому непустой
// scope не поддерживается.
func planAccess(change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	user := change.Account.EngineIdentity
	if user == "" {
		return nil, fmt.Errorf("clickhouse: plan %s: account engine identity is empty", op)
	}
	role, err := parsePermission(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: plan %s: %w", op, err)
	}
	if change.Scope != "" {
		return nil, fmt.Errorf("clickhouse: plan %s: scoped role grant is not supported: %w",
			op, adapter.ErrUnsupportedChange)
	}

	if change.Kind == adapter.ChangeRevoke {
		return adapterutil.SingleStepPlan(change, stepRevokeRole,
			fmt.Sprintf("revoke role %q from user %q", role, user),
			map[string]any{"user": user, "role": role}), nil
	}
	return adapterutil.SingleStepPlan(change, stepGrantRole,
		fmt.Sprintf("grant role %q to user %q", role, user),
		map[string]any{"user": user, "role": role}), nil
}

// planAccountCreate строит план создания пользователя с паролем
// (sha256_password). Пароль обязателен и берётся из change.Credential; в план
// он не попадает — только факт его наличия. Пользователь не должен
// существовать: existing identity отклоняется здесь, до резервирования
// credential (см. adapterutil.IdentityConflict).
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("clickhouse: plan account.create: account engine identity is empty")
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("clickhouse: plan account.create: password credential is required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: plan account.create: %w", err)
	}
	found, err := client.userExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: plan account.create: %w", err)
	}
	if found {
		return nil, fmt.Errorf("clickhouse: plan account.create: %w", adapterutil.IdentityConflict("user", name))
	}
	return accountCreatePlan(change), nil
}

// accountCreatePlan собирает сам план создания — без обращения к target.
// Отделено от planAccountCreate, чтобы форму плана (шаг, атрибуты, отсутствие
// секрета в description) можно было проверять без поднятого ClickHouse.
func accountCreatePlan(change adapter.DesiredChange) *adapter.Plan {
	name := change.Account.EngineIdentity
	return adapterutil.SingleStepPlan(change, stepCreateUser,
		fmt.Sprintf("create user %q with password (sha256_password)", name),
		map[string]any{"user": name, "with_password": true})
}

// planAccountRestore различает absent и present identity. Absent создаётся с
// новым credential. Present допустима только как recovery retry после
// доказательства точного credential; обычный account.create здесь никогда не
// используется, поэтому чужой существующий пользователь не перезаписывается.
func (a *Adapter) planAccountRestore(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" || !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("clickhouse: plan account.restore: account identity and credential are required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: plan account.restore: %w", err)
	}
	found, err := client.userExists(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: plan account.restore: %w", err)
	}
	if !found {
		return adapterutil.SingleStepPlan(change, stepRestoreUser,
			fmt.Sprintf("restore user %q with a fresh credential (sha256_password)", name),
			map[string]any{"user": name, "recovery": false}), nil
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return nil, fmt.Errorf("clickhouse: plan account.restore: existing user %q: %w", name, err)
	}
	return adapterutil.SingleStepPlan(change, stepRestoreUser,
		fmt.Sprintf("recover already restored user %q after credential proof", name),
		map[string]any{"user": name, "recovery": true}), nil
}

// planDisableEnable строит план disable/enable. Disable запрещает подключение
// через ALTER USER ... HOST NONE (гранты и пароль сохраняются), enable
// восстанавливает HOST ANY (см. doc-комментарий пакета).
//
// Пользователь с суженным списком хостов (HOST IP, HOST NAME, ...) под эту
// пару не подходит: HOST NONE стёр бы ограничение, а enable вернул бы не его,
// а HOST ANY — то есть отключение и включение РАСШИРИЛО бы сетевой доступ
// учётки. Восстановить исходный список adapter не может: своего состояния у
// него нет, а в ClickHouse хранить его негде. Поэтому такой disable
// отклоняется с называнием того, что было бы потеряно.
func (a *Adapter) planDisableEnable(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, fmt.Errorf("clickhouse: plan %s: account engine identity is empty", change.Kind)
	}
	if change.Kind == adapter.ChangeAccountDisable {
		client, err := a.newClient(change.Connection)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: plan %s: %w", change.Kind, err)
		}
		hosts, err := client.userHosts(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: plan %s: %w", change.Kind, err)
		}
		if len(hosts) > 0 {
			return nil, fmt.Errorf(
				"clickhouse: plan %s: user %q is restricted to hosts %s; disabling would replace them with HOST NONE "+
					"and enabling would restore HOST ANY, widening network access: %w",
				change.Kind, name, strings.Join(hosts, ", "), adapter.ErrUnsupportedChange)
		}
	}
	return disableEnablePlan(change), nil
}

// disableEnablePlan собирает сам план — без обращения к target. Отделено от
// planDisableEnable, чтобы форму плана можно было проверять без поднятого
// ClickHouse.
func disableEnablePlan(change adapter.DesiredChange) *adapter.Plan {
	name := change.Account.EngineIdentity
	if change.Kind == adapter.ChangeAccountDisable {
		return adapterutil.SingleStepPlan(change, stepDisableUser,
			fmt.Sprintf("disable user %q: forbid connections with ALTER USER ... HOST NONE (grants and password preserved)", name),
			map[string]any{"user": name, "mechanism": "host-none"})
	}
	return adapterutil.SingleStepPlan(change, stepEnableUser,
		fmt.Sprintf("enable user %q: restore connections with ALTER USER ... HOST ANY", name),
		map[string]any{"user": name, "mechanism": "host-none"})
}

// planAccountDelete строит план удаления пользователя. Description
// предупреждает, что вместе с пользователем исчезнут его гранты.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("clickhouse: plan account.delete: account engine identity is empty")
	}
	return adapterutil.SingleStepPlan(change, stepDropUser,
		fmt.Sprintf("drop user %q; its role grants and privileges disappear with it", name),
		map[string]any{"user": name}), nil
}

// Apply применяет план через один HTTP-клиент. Каждый шаг идемпотентен: если
// состояние уже целевое — StepSkipped. Ошибка шага помечает его StepFailed
// (текст без секретов), оставшиеся шаги получают StepUnknown и не выполняются.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	client, err := a.newClient(plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: apply %s: %w", plan.Change.Kind, err)
	}

	return adapterutil.ApplySteps(ctx, plan, client, applyStep), nil
}

// applyStep выполняет один шаг плана.
func applyStep(ctx context.Context, c *chClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrantRole:
		return applyGrantRole(ctx, c, change)
	case stepRevokeRole:
		return applyRevokeRole(ctx, c, change)
	case stepCreateUser:
		return applyCreateUser(ctx, c, change)
	case stepRestoreUser:
		return applyRestoreUser(ctx, c, change, step)
	case stepDisableUser:
		return applyDisableUser(ctx, c, change)
	case stepEnableUser:
		return applyEnableUser(ctx, c, change)
	case stepDropUser:
		return applyDropUser(ctx, c, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyGrantRole выдаёт роль пользователю; существующее назначение —
// StepSkipped. Отсутствующие пользователь или роль — ErrNotFound.
func applyGrantRole(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	role, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	found, err := c.userExists(ctx, user)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", user, adapter.ErrNotFound)
	}
	found, err = c.roleExists(ctx, role)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("role %q: %w", role, adapter.ErrNotFound)
	}
	has, err := c.hasRoleGrant(ctx, user, role)
	if err != nil {
		return adapter.StepFailed, err
	}
	if has {
		return adapter.StepSkipped, nil
	}
	if err := c.exec(ctx, "GRANT "+quoteIdent(role)+" TO "+quoteIdent(user), false); err != nil {
		return adapter.StepFailed, fmt.Errorf("grant role %q to user %q: %w", role, user, err)
	}
	return adapter.StepApplied, nil
}

// applyRevokeRole отзывает роль у пользователя; отсутствующее назначение (или
// пользователь) — StepSkipped.
func applyRevokeRole(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user := change.Account.EngineIdentity
	role, err := parsePermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	has, err := c.hasRoleGrant(ctx, user, role)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !has {
		return adapter.StepSkipped, nil
	}
	if err := c.exec(ctx, "REVOKE "+quoteIdent(role)+" FROM "+quoteIdent(user), false); err != nil {
		return adapter.StepFailed, fmt.Errorf("revoke role %q from user %q: %w", role, user, err)
	}
	return adapter.StepApplied, nil
}

// applyCreateUser создаёт пользователя с паролем sha256_password и HOST ANY.
// Существующий пользователь — не «уже сделано», а ErrExternalIdentityConflict:
// Plan видел его отсутствие, значит учётку создал кто-то другой между Plan и
// Apply (см. adapterutil.IdentityConflict). Пароль попадает в statement как
// literal, собранный quoteLiteral; statement нигде не логируется, а ошибка
// сервера редуцируется до кода исключения (см. chClient.exec с
// containsSecret=true).
func applyCreateUser(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("password credential is required to create a user")
	}
	found, err := c.userExists(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if found {
		return adapter.StepFailed, adapterutil.IdentityConflict("user", name)
	}
	lit, err := quoteLiteral(string(change.Credential.Secret))
	if err != nil {
		return adapter.StepFailed, fmt.Errorf("password for user %q: %w", name, err)
	}
	stmt := "CREATE USER " + quoteIdent(name) + " IDENTIFIED WITH sha256_password BY " + lit
	if err := c.exec(ctx, stmt, true); err != nil {
		return adapter.StepFailed, fmt.Errorf("create user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyRestoreUser пересоздаёт пользователя с зарезервированным паролем одним
// statement CREATE USER ... IDENTIFIED WITH sha256_password BY. Отдельная
// атомарная обёртка (как транзакция в postgres adapter) не нужна: ClickHouse
// задаёт пароль тем же DDL, поэтому identity не может появиться без
// зарезервированного credential.
//
// Существующая identity допустима только как recovery retry — её credential
// доказан на этапе Plan, и шаг даёт StepSkipped, не трогая пароль. Identity,
// появившаяся между Plan и Apply, — ErrExternalIdentityConflict.
func applyRestoreUser(ctx context.Context, c *chClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("credential is required to restore a user")
	}
	found, err := c.userExists(ctx, name)
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
	lit, err := quoteLiteral(string(change.Credential.Secret))
	if err != nil {
		return adapter.StepFailed, fmt.Errorf("password for user %q: %w", name, err)
	}
	stmt := "CREATE USER " + quoteIdent(name) + " IDENTIFIED WITH sha256_password BY " + lit
	if err := c.exec(ctx, stmt, true); err != nil {
		return adapter.StepFailed, fmt.Errorf("restore user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDisableUser запрещает подключение пользователя (ALTER USER ... HOST
// NONE); уже отключённый пользователь — StepSkipped, отсутствующий —
// ErrNotFound.
func applyDisableUser(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	noHosts, found, err := c.userHostState(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
	}
	if noHosts {
		return adapter.StepSkipped, nil
	}
	if err := c.exec(ctx, "ALTER USER "+quoteIdent(name)+" HOST NONE", false); err != nil {
		return adapter.StepFailed, fmt.Errorf("disable user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyEnableUser восстанавливает подключение пользователя (ALTER USER ...
// HOST ANY); уже включённый пользователь — StepSkipped, отсутствующий —
// ErrNotFound.
func applyEnableUser(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	noHosts, found, err := c.userHostState(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
	}
	if !noHosts {
		return adapter.StepSkipped, nil
	}
	if err := c.exec(ctx, "ALTER USER "+quoteIdent(name)+" HOST ANY", false); err != nil {
		return adapter.StepFailed, fmt.Errorf("enable user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDropUser удаляет пользователя; отсутствующий пользователь — StepSkipped.
func applyDropUser(ctx context.Context, c *chClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	found, err := c.userExists(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepSkipped, nil
	}
	if err := c.exec(ctx, "DROP USER "+quoteIdent(name), false); err != nil {
		return adapter.StepFailed, fmt.Errorf("drop user %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// Verify выполняет read-back проверку итогового состояния плана по системным
// таблицам. Details не содержат секретов.
func (a *Adapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	change := plan.Change
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
		adapter.ChangeAccountRestore:
	default:
		return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
	}
	name := change.Account.EngineIdentity

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		role, err := parsePermission(change.Permission)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		has, err := client.hasRoleGrant(ctx, name, role)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		what := fmt.Sprintf("user %q has role %q", name, role)
		if change.Kind == adapter.ChangeGrant {
			return adapterutil.VerifyResult(has, what), nil
		}
		return adapterutil.VerifyResult(!has, "no "+what), nil
	case adapter.ChangeAccountCreate:
		found, err := client.userExists(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(found, fmt.Sprintf("user %q exists", name)), nil
	case adapter.ChangeAccountRestore:
		// Наличия строки в system.users недостаточно: восстановленный
		// пользователь обязан реально пускать по зарезервированному паролю,
		// поэтому read-back дополняется credential proof (тем же, что и на
		// этапе Plan). HOST NONE означает, что подключение запрещено.
		noHosts, found, err := client.userHostState(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		if !found || noHosts {
			return adapterutil.VerifyResult(false, fmt.Sprintf(
				"user %q exists and can log in with the reserved credential", name)), nil
		}
		if change.Credential == nil {
			return nil, errors.New("clickhouse: verify account.restore: credential is required")
		}
		if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
			return nil, fmt.Errorf("clickhouse: verify account.restore: %w", err)
		}
		return adapterutil.VerifyResult(true, fmt.Sprintf(
			"user %q exists and the reserved credential is proved", name)), nil
	case adapter.ChangeAccountDisable:
		noHosts, found, err := client.userHostState(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(found && noHosts,
			fmt.Sprintf("user %q exists and is disabled (HOST NONE)", name)), nil
	case adapter.ChangeAccountEnable:
		noHosts, found, err := client.userHostState(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(found && !noHosts,
			fmt.Sprintf("user %q exists and is enabled (hosts allowed)", name)), nil
	default: // adapter.ChangeAccountDelete
		found, err := client.userExists(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(!found, fmt.Sprintf("user %q is absent", name)), nil
	}
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32). Спецсимволы сознательно не используются
// для совместимости с клиентами и строками подключения.
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего пользователя через ALTER USER
// ... IDENTIFIED WITH sha256_password BY. Пароль экранируется quoteLiteral и
// не попадает в логи и тексты ошибок (ошибка сервера редуцируется до кода
// исключения). Возвращает adapter.ErrNotFound, если пользователя нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	name := account.EngineIdentity
	if name == "" {
		return errors.New("clickhouse: rotate credential: account engine identity is empty")
	}
	if len(credential.Secret) == 0 {
		return errors.New("clickhouse: rotate credential: credential secret is empty")
	}

	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("clickhouse: rotate credential: %w", err)
	}
	found, err := client.userExists(ctx, name)
	if err != nil {
		return fmt.Errorf("clickhouse: rotate credential: %w", err)
	}
	if !found {
		return fmt.Errorf("clickhouse: rotate credential: user %q: %w", name, adapter.ErrNotFound)
	}
	lit, err := quoteLiteral(string(credential.Secret))
	if err != nil {
		return fmt.Errorf("clickhouse: rotate credential: password for user %q: %w", name, err)
	}
	stmt := "ALTER USER " + quoteIdent(name) + " IDENTIFIED WITH sha256_password BY " + lit
	if err := client.exec(ctx, stmt, true); err != nil {
		return fmt.Errorf("clickhouse: rotate credential: set password for user %q: %w", name, err)
	}
	return nil
}

// --- HTTP-помощники уровня пользователей и ролей ---

// userExists проверяет существование пользователя в system.users.
func (c *chClient) userExists(ctx context.Context, name string) (bool, error) {
	rows, err := c.query(ctx, `SELECT name FROM system.users WHERE name = {name:String}`,
		map[string]string{"name": name})
	if err != nil {
		return false, fmt.Errorf("check user %q: %w", name, err)
	}
	return len(rows) > 0, nil
}

// roleExists проверяет существование роли в system.roles.
func (c *chClient) roleExists(ctx context.Context, name string) (bool, error) {
	rows, err := c.query(ctx, `SELECT name FROM system.roles WHERE name = {name:String}`,
		map[string]string{"name": name})
	if err != nil {
		return false, fmt.Errorf("check role %q: %w", name, err)
	}
	return len(rows) > 0, nil
}

// hasRoleGrant проверяет наличие назначения роли пользователю в
// system.role_grants.
func (c *chClient) hasRoleGrant(ctx context.Context, user, role string) (bool, error) {
	rows, err := c.query(ctx,
		`SELECT granted_role_name FROM system.role_grants
WHERE user_name = {user:String} AND granted_role_name = {role:String}`,
		map[string]string{"user": user, "role": role})
	if err != nil {
		return false, fmt.Errorf("check role %q for user %q: %w", role, user, err)
	}
	return len(rows) > 0, nil
}

// userHostState читает host-ограничения пользователя: noHosts=true означает
// состояние HOST NONE (подключение запрещено отовсюду), found=false —
// пользователя нет.
func (c *chClient) userHostState(ctx context.Context, name string) (noHosts, found bool, err error) {
	rows, err := c.query(ctx,
		`SELECT name, host_ip, host_names, host_names_regexp, host_names_like
FROM system.users WHERE name = {name:String}`,
		map[string]string{"name": name})
	if err != nil {
		return false, false, fmt.Errorf("read host state of user %q: %w", name, err)
	}
	if len(rows) == 0 {
		return false, false, nil
	}
	return hostNone(parseUser(rows[0])), true, nil
}

// userHosts возвращает непустые host-ограничения пользователя. Пустой
// результат означает HOST ANY (ограничений нет) либо HOST NONE (пользователь
// уже отключён) — в обоих случаях терять нечего.
func (c *chClient) userHosts(ctx context.Context, name string) ([]string, error) {
	rows, err := c.query(ctx,
		`SELECT name, host_ip, host_names, host_names_regexp, host_names_like
FROM system.users WHERE name = {name:String}`,
		map[string]string{"name": name})
	if err != nil {
		return nil, fmt.Errorf("read host state of user %q: %w", name, err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	u := parseUser(rows[0])
	// HOST ANY отображается как host_ip ['::/0'] — это не ограничение.
	if len(u.HostIP) == 1 && u.HostIP[0] == "::/0" &&
		len(u.HostNames) == 0 && len(u.HostRegexp) == 0 && len(u.HostLike) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(u.HostIP)+len(u.HostNames)+len(u.HostRegexp)+len(u.HostLike))
	out = append(out, u.HostIP...)
	out = append(out, u.HostNames...)
	out = append(out, u.HostRegexp...)
	out = append(out, u.HostLike...)
	return out, nil
}

// --- Чистые помощники ---

// parsePermission разбирает external id permission: "role:<name>" -> name.
// Прямые privilege-гранты ("priv:...") наблюдаемые и назначению не подлежат.
func parsePermission(perm string) (string, error) {
	if v, ok := strings.CutPrefix(perm, rolePermissionPrefix); ok {
		if v == "" {
			return "", fmt.Errorf("permission %q has empty role name", perm)
		}
		return v, nil
	}
	if strings.HasPrefix(perm, privPermissionPrefix) {
		return "", fmt.Errorf("permission %q is an observed direct privilege grant; only roles are assignable: %w",
			perm, adapter.ErrUnsupportedChange)
	}
	return "", fmt.Errorf("permission %q is not a clickhouse permission (want %q prefix)",
		perm, rolePermissionPrefix)
}

// quoteIdent собирает идентификатор ClickHouse в backticks с экранированием
// обратного слэша и backtick.
func quoteIdent(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`")
	return "`" + r.Replace(s) + "`"
}

// quoteLiteral собирает string literal ClickHouse для DDL с секретом
// (пароли): одинарные кавычки, экранирование обратного слэша и кавычки.
// Отвергает нулевые байты: их экранирование ненадёжно, а в паролях они не
// встречаются.
func quoteLiteral(s string) (string, error) {
	if strings.ContainsRune(s, '\x00') {
		return "", errors.New("string literal must not contain NUL bytes")
	}
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'", nil
}
