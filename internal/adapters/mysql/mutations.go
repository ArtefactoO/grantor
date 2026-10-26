package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана MySQL adapter.
const (
	stepGrant       = "grant"
	stepRevoke      = "revoke"
	stepCreateUser  = "create-user"
	stepRestoreUser = "restore-user"
	stepLockAccount = "lock-account"
	stepDropUser    = "drop-user"
)

// Plan строит детерминированный типизированный план для DesiredChange.
// Для grant/revoke предварительно проверяется, что сервер поддерживает роли
// (MySQL 8.0+, не MariaDB) и что роль и account существуют. Descriptions
// шагов не содержат секретных значений.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return a.planMembership(ctx, change)
	case adapter.ChangeAccountCreate:
		return a.planAccountCreate(ctx, change)
	case adapter.ChangeAccountRestore:
		return a.planAccountRestore(ctx, change)
	case adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		return planLockAccount(change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	default:
		return nil, fmt.Errorf("mysql: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planMembership строит план grant/revoke роли. Роли MySQL cluster-wide,
// поэтому непустой scope не поддерживается. Для grant роль и account
// проверяются на существование коротким подключением; revoke валидации не
// требует: отсутствие ребра обрабатывается идемпотентным Apply как
// StepSkipped.
func (a *Adapter) planMembership(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	role, err := parseUserHost(rolePermissionIdentity(change.Permission))
	if err != nil {
		return nil, fmt.Errorf("mysql: plan %s: %w", op, err)
	}
	member, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan %s: account: %w", op, err)
	}
	if change.Scope != "" {
		return nil, fmt.Errorf("mysql: plan %s: scoped role membership is not supported: %w",
			op, adapter.ErrUnsupportedChange)
	}

	db, err := a.open(ctx, change.Connection, defaultDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("mysql: plan %s: %w", op, err)
	}
	defer closeQuietly(db)

	if err := ensureRolesSupported(ctx, db); err != nil {
		return nil, fmt.Errorf("mysql: plan %s: %w", op, err)
	}

	if change.Kind == adapter.ChangeGrant {
		if err := checkMembershipObjects(ctx, db, role, member); err != nil {
			return nil, fmt.Errorf("mysql: plan %s: %w", op, err)
		}
		return adapterutil.SingleStepPlan(change, stepGrant,
			fmt.Sprintf("grant role %q to account %q and activate it as a default role",
				role.String(), member.String()),
			map[string]any{"role": role.String(), "member": member.String()}), nil
	}
	return adapterutil.SingleStepPlan(change, stepRevoke,
		fmt.Sprintf("revoke role %q from account %q and drop it from the account default roles",
			role.String(), member.String()),
		map[string]any{"role": role.String(), "member": member.String()}), nil
}

// checkMembershipObjects проверяет, что и роль, и account существуют в
// целевой системе.
func checkMembershipObjects(ctx context.Context, db *sql.DB, role, member userHost) error {
	exists, err := userExists(ctx, db, role)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("role %q: %w", role.String(), adapter.ErrNotFound)
	}
	exists, err = userExists(ctx, db, member)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("account %q: %w", member.String(), adapter.ErrNotFound)
	}
	return nil
}

// planAccountCreate строит план создания аккаунта. Аккаунт не должен
// существовать. change.Credential может быть nil или без секрета — тогда
// аккаунт создаётся без пароля (external identity / auth-плагин). Description
// сообщает только факт наличия пароля, но не его значение.
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.create: %w", err)
	}

	db, err := a.open(ctx, change.Connection, defaultDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.create: %w", err)
	}
	defer closeQuietly(db)

	exists, err := userExists(ctx, db, account)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.create: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("mysql: plan account.create: %w",
			adapterutil.IdentityConflict("account", account.String()))
	}

	withPassword := adapterutil.HasPasswordSecret(change.Credential)
	desc := fmt.Sprintf("create account %q without password (external identity)", account.String())
	if withPassword {
		desc = fmt.Sprintf("create account %q with password", account.String())
	}
	return adapterutil.SingleStepPlan(change, stepCreateUser, desc,
		map[string]any{"account": account.String(), "with_password": withPassword}), nil
}

// planAccountRestore различает absent и present identity. Absent создаётся с
// новым credential. Present допустима только как recovery retry после
// доказательства точного credential; обычный account.create здесь никогда не
// используется, поэтому чужая существующая учётка не перезаписывается.
func (a *Adapter) planAccountRestore(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.restore: %w", err)
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("mysql: plan account.restore: account identity and credential are required")
	}

	db, err := a.open(ctx, change.Connection, defaultDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.restore: %w", err)
	}
	exists, err := userExists(ctx, db, account)
	closeQuietly(db)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.restore: %w", err)
	}
	if !exists {
		return adapterutil.SingleStepPlan(change, stepRestoreUser,
			fmt.Sprintf("restore account %q with a fresh credential", account.String()),
			map[string]any{"account": account.String(), "recovery": false}), nil
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return nil, fmt.Errorf("mysql: plan account.restore: existing account %q: %w", account.String(), err)
	}
	return adapterutil.SingleStepPlan(change, stepRestoreUser,
		fmt.Sprintf("recover already restored account %q after credential proof", account.String()),
		map[string]any{"account": account.String(), "recovery": true}), nil
}

// planLockAccount строит план блокировки/разблокировки аккаунта
// (ACCOUNT LOCK / ACCOUNT UNLOCK). Валидации на этапе плана нет: текущее
// состояние проверяет идемпотентный Apply.
func planLockAccount(change adapter.DesiredChange) (*adapter.Plan, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan %s: %w", change.Kind, err)
	}
	unlock := change.Kind == adapter.ChangeAccountEnable
	desc := fmt.Sprintf("disable account %q (ALTER USER ... ACCOUNT LOCK)", account.String())
	if unlock {
		desc = fmt.Sprintf("enable account %q (ALTER USER ... ACCOUNT UNLOCK)", account.String())
	}
	return adapterutil.SingleStepPlan(change, stepLockAccount, desc,
		map[string]any{"account": account.String(), "unlock": unlock}), nil
}

// planAccountDelete строит план удаления аккаунта. Description предупреждает,
// что вместе с аккаунтом исчезнут его role bindings и privileges.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: plan account.delete: %w", err)
	}
	return adapterutil.SingleStepPlan(change, stepDropUser,
		fmt.Sprintf(
			"drop account %q; warning: all role grants and privileges of this account disappear with it",
			account.String()),
		map[string]any{"account": account.String()}), nil
}

// Apply применяет план через одно подключение. Каждый шаг идемпотентен: если
// состояние уже целевое — StepSkipped. Ошибка шага помечает его StepFailed
// (текст без секретов), оставшиеся шаги получают StepUnknown и не выполняются.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	db, err := a.open(ctx, plan.Change.Connection, defaultDatabase(plan.Change.Connection))
	if err != nil {
		return nil, fmt.Errorf("mysql: apply %s: %w", plan.Change.Kind, err)
	}
	defer closeQuietly(db)

	return adapterutil.ApplySteps(ctx, plan, db, applyStep), nil
}

// applyStep выполняет один шаг плана. Все имена объектов экранируются как
// account references ('user'@'host'); тексты ошибок не содержат секретов.
func applyStep(ctx context.Context, db *sql.DB, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrant:
		return applyGrant(ctx, db, change)
	case stepRevoke:
		return applyRevoke(ctx, db, change)
	case stepCreateUser:
		return applyCreateUser(ctx, db, change)
	case stepRestoreUser:
		return applyRestoreUser(ctx, db, change, step)
	case stepLockAccount:
		return applyLockAccount(ctx, db, change)
	case stepDropUser:
		return applyDropUser(ctx, db, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyGrant выдаёт роль аккаунту и делает её default role. Одного
// GRANT недостаточно: при значении по умолчанию
// activate_all_roles_on_login=OFF выданная роль не активируется при логине
// (CURRENT_ROLE() = NONE) и доступа фактически нет, хотя SHOW GRANTS роль
// показывает. Шаг идемпотентен и покомпонентен: уже существующее ребро не
// перевыдаётся, но недостающая запись в mysql.default_roles дописывается,
// поэтому шаг чинит и аккаунты, которым роль выдали до этого исправления.
// StepSkipped — только когда целевыми являются обе части.
func applyGrant(ctx context.Context, db *sql.DB, change adapter.DesiredChange) (adapter.StepStatus, error) {
	role, member, err := membershipTargets(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	changed := false
	has, err := hasRoleEdge(ctx, db, role, member)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !has {
		stmt := "GRANT " + role.quoted() + " TO " + member.quoted()
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return adapter.StepFailed, fmt.Errorf("grant role %q to %q: %w", role.String(), member.String(), err)
		}
		changed = true
	}
	updated, err := syncDefaultRole(ctx, db, role, member, true)
	if err != nil {
		return adapter.StepFailed, err
	}
	if changed || updated {
		return adapter.StepApplied, nil
	}
	return adapter.StepSkipped, nil
}

// applyRevoke отзывает роль у аккаунта и убирает её из default roles. MySQL
// 8.0 чистит mysql.default_roles сам при REVOKE, но состояние всё равно
// пересчитывается: это делает шаг независимым от версии сервера и чинит
// аккаунты, у которых запись default role осталась от предыдущего поведения.
// StepSkipped — только когда нет ни ребра, ни записи default role.
func applyRevoke(ctx context.Context, db *sql.DB, change adapter.DesiredChange) (adapter.StepStatus, error) {
	role, member, err := membershipTargets(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	changed := false
	has, err := hasRoleEdge(ctx, db, role, member)
	if err != nil {
		return adapter.StepFailed, err
	}
	if has {
		stmt := "REVOKE " + role.quoted() + " FROM " + member.quoted()
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return adapter.StepFailed, fmt.Errorf("revoke role %q from %q: %w", role.String(), member.String(), err)
		}
		changed = true
	}
	updated, err := syncDefaultRole(ctx, db, role, member, false)
	if err != nil {
		return adapter.StepFailed, err
	}
	if changed || updated {
		return adapter.StepApplied, nil
	}
	return adapter.StepSkipped, nil
}

// syncDefaultRole приводит запись роли в mysql.default_roles аккаунта к
// целевому состоянию: include=true — роль обязана быть default role,
// include=false — обязана отсутствовать. Возвращает признак того, что
// потребовался SET DEFAULT ROLE.
//
// MySQL не умеет добавлять и удалять отдельную default role: SET DEFAULT ROLE
// перезаписывает набор целиком, поэтому текущий набор вычитывается и
// переписывается вместе с изменением. Чужие (не управляемые grantor) default
// roles аккаунта сохраняются — набор не подменяется на ALL, чтобы не
// активировать роли, которые владелец аккаунта сознательно оставил
// неактивными по умолчанию.
func syncDefaultRole(ctx context.Context, db *sql.DB, role, member userHost, include bool) (bool, error) {
	current, err := defaultRoles(ctx, db, member)
	if err != nil {
		return false, err
	}
	if slices.Contains(current, role) == include {
		return false, nil
	}
	granted, err := grantedRoles(ctx, db, member)
	if err != nil {
		return false, err
	}
	next := nextDefaultRoles(current, granted, role, include)
	if _, err := db.ExecContext(ctx, setDefaultRoleStatement(member, next)); err != nil {
		return false, fmt.Errorf("set default roles of %q: %w", member.String(), err)
	}
	return true, nil
}

// nextDefaultRoles строит новый набор default roles аккаунта: role
// добавляется (include) или удаляется, а из остальных отбрасываются роли,
// которые аккаунту уже не выданы. Отбрасывание обязательно, а не
// косметическое: SET DEFAULT ROLE перезаписывает набор целиком и отвергает
// statement целиком (ER_ROLE_NOT_GRANTED), если в нём есть невыданная роль,
// поэтому оставшаяся от постороннего изменения запись иначе заблокировала бы
// операцию. Результат детерминированно отсортирован и не содержит дублей.
func nextDefaultRoles(current, granted []userHost, role userHost, include bool) []userHost {
	grantedSet := make(map[userHost]struct{}, len(granted))
	for _, g := range granted {
		grantedSet[g] = struct{}{}
	}
	next := make([]userHost, 0, len(current)+1)
	seen := make(map[userHost]struct{}, len(current)+1)
	keep := func(r userHost) {
		if _, dup := seen[r]; dup {
			return
		}
		seen[r] = struct{}{}
		next = append(next, r)
	}
	for _, c := range current {
		if c == role {
			continue
		}
		if _, ok := grantedSet[c]; !ok {
			continue
		}
		keep(c)
	}
	if include {
		if _, ok := grantedSet[role]; ok {
			keep(role)
		}
	}
	slices.SortFunc(next, func(a, b userHost) int {
		if c := strings.Compare(a.user, b.user); c != 0 {
			return c
		}
		return strings.Compare(a.host, b.host)
	})
	return next
}

// setDefaultRoleStatement собирает SET DEFAULT ROLE для аккаунта. Пустой
// набор — NONE: у MySQL нет способа записать «ни одной default role» через
// перечисление.
func setDefaultRoleStatement(member userHost, roles []userHost) string {
	if len(roles) == 0 {
		return "SET DEFAULT ROLE NONE TO " + member.quoted()
	}
	quoted := make([]string, 0, len(roles))
	for _, r := range roles {
		quoted = append(quoted, r.quoted())
	}
	return "SET DEFAULT ROLE " + strings.Join(quoted, ", ") + " TO " + member.quoted()
}

// applyCreateUser создаёт аккаунт. Существующий аккаунт — не «уже сделано», а
// ErrExternalIdentityConflict: Plan видел его отсутствие, значит учётку создал
// кто-то другой между Plan и Apply (см. adapterutil.IdentityConflict). Пароль
// подставляется как quoteLiteral, а ошибка сервера редуцируется до кода:
// сообщение MySQL может цитировать фрагмент statement.
func applyCreateUser(ctx context.Context, db *sql.DB, change adapter.DesiredChange) (adapter.StepStatus, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	exists, err := userExists(ctx, db, account)
	if err != nil {
		return adapter.StepFailed, err
	}
	if exists {
		return adapter.StepFailed, adapterutil.IdentityConflict("account", account.String())
	}
	stmt := "CREATE USER " + account.quoted()
	secret := false
	if adapterutil.HasPasswordSecret(change.Credential) {
		lit, litErr := quoteLiteral(string(change.Credential.Secret))
		if litErr != nil {
			return adapter.StepFailed, fmt.Errorf("password for account %q: %w", account.String(), litErr)
		}
		stmt += " IDENTIFIED BY " + lit
		secret = true
	}
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		if secret {
			// Statement содержит пароль: не оборачиваем исходную ошибку через
			// %w, а редуцируем до кода MySQL.
			return adapter.StepFailed, fmt.Errorf("create account %q: %s", account.String(), redactExecError(err))
		}
		return adapter.StepFailed, fmt.Errorf("create account %q: %w", account.String(), err)
	}
	return adapter.StepApplied, nil
}

// applyRestoreUser пересоздаёт учётную запись с зарезервированным паролем
// одним statement CREATE USER ... IDENTIFIED BY. Отдельная атомарная обёртка
// (как транзакция в postgres adapter) не нужна: MySQL задаёт пароль тем же
// DDL, поэтому identity не может появиться без зарезервированного credential,
// а retry никогда не встречает половинчатое состояние.
//
// Существующая identity допустима только как recovery retry — её credential
// доказан на этапе Plan, и шаг даёт StepSkipped, не трогая пароль. Identity,
// появившаяся между Plan и Apply, — ErrExternalIdentityConflict.
func applyRestoreUser(ctx context.Context, db *sql.DB, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("credential is required to restore an account")
	}
	exists, err := userExists(ctx, db, account)
	if err != nil {
		return adapter.StepFailed, err
	}
	if exists {
		if recovery, _ := step.Attributes["recovery"].(bool); recovery {
			return adapter.StepSkipped, nil
		}
		return adapter.StepFailed, fmt.Errorf("account %q appeared after planning: %w",
			account.String(), adapter.ErrExternalIdentityConflict)
	}
	lit, err := quoteLiteral(string(change.Credential.Secret))
	if err != nil {
		return adapter.StepFailed, fmt.Errorf("password for account %q: %w", account.String(), err)
	}
	// Statement содержит пароль: исходная ошибка не оборачивается через %w, а
	// редуцируется до кода MySQL.
	if _, err := db.ExecContext(ctx, "CREATE USER "+account.quoted()+" IDENTIFIED BY "+lit); err != nil {
		return adapter.StepFailed, fmt.Errorf("restore account %q: %s", account.String(), redactExecError(err))
	}
	return adapter.StepApplied, nil
}

// applyLockAccount блокирует/разблокирует аккаунт; совпадающее состояние —
// StepSkipped, отсутствующий аккаунт — ошибка ErrNotFound.
func applyLockAccount(ctx context.Context, db *sql.DB, change adapter.DesiredChange) (adapter.StepStatus, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	unlock := change.Kind == adapter.ChangeAccountEnable
	locked, found, err := accountLocked(ctx, db, account)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("account %q: %w", account.String(), adapter.ErrNotFound)
	}
	// Цель disable — locked; цель enable — unlocked. Совпадение с текущим
	// состоянием — StepSkipped.
	targetLocked := !unlock
	if locked == targetLocked {
		return adapter.StepSkipped, nil
	}
	clause := " ACCOUNT LOCK"
	if unlock {
		clause = " ACCOUNT UNLOCK"
	}
	if _, err := db.ExecContext(ctx, "ALTER USER "+account.quoted()+clause); err != nil {
		return adapter.StepFailed, fmt.Errorf("alter account %q lock state: %w", account.String(), err)
	}
	return adapter.StepApplied, nil
}

// applyDropUser удаляет аккаунт; отсутствующий аккаунт — StepSkipped.
func applyDropUser(ctx context.Context, db *sql.DB, change adapter.DesiredChange) (adapter.StepStatus, error) {
	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	exists, err := userExists(ctx, db, account)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !exists {
		return adapter.StepSkipped, nil
	}
	if _, err := db.ExecContext(ctx, "DROP USER "+account.quoted()); err != nil {
		return adapter.StepFailed, fmt.Errorf("drop account %q: %w", account.String(), err)
	}
	return adapter.StepApplied, nil
}

// Verify выполняет read-back проверку итогового состояния плана по системным
// каталогам. Details не содержат секретов.
func (a *Adapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	change := plan.Change
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
		adapter.ChangeAccountRestore:
	default:
		return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	db, err := a.open(ctx, change.Connection, defaultDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
	}
	defer closeQuietly(db)

	account, err := parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
	}

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		role, err := parseUserHost(rolePermissionIdentity(change.Permission))
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		has, err := hasRoleEdge(ctx, db, role, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		// Наличие ребра role_edges само по себе не означает доступа: при
		// activate_all_roles_on_login=OFF (значение по умолчанию) роль
		// активируется на логине, только если она есть в mysql.default_roles.
		// Поэтому проверяется активация, а не только выдача.
		current, err := defaultRoles(ctx, db, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		isDefault := slices.Contains(current, role)
		if change.Kind == adapter.ChangeGrant {
			activateAll, err := activateAllRolesOnLogin(ctx, db)
			if err != nil {
				return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
			}
			return adapterutil.VerifyResult(has && (isDefault || activateAll),
				fmt.Sprintf("account %q has role %q and activates it on login",
					account.String(), role.String())), nil
		}
		return adapterutil.VerifyResult(!has && !isDefault,
			fmt.Sprintf("account %q lacks role %q and does not have it as a default role",
				account.String(), role.String())), nil
	case adapter.ChangeAccountCreate:
		exists, err := userExists(ctx, db, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(exists, fmt.Sprintf("account %q exists", account.String())), nil
	case adapter.ChangeAccountRestore:
		// Наличия строки в mysql.user недостаточно: восстановленная учётка
		// обязана реально пускать по зарезервированному паролю, поэтому
		// read-back дополняется credential proof (тем же, что и на этапе Plan).
		locked, found, err := accountLocked(ctx, db, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		if !found || locked {
			return adapterutil.VerifyResult(false, fmt.Sprintf(
				"account %q exists and can log in with the reserved credential", account.String())), nil
		}
		if change.Credential == nil {
			return nil, errors.New("mysql: verify account.restore: credential is required")
		}
		if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
			return nil, fmt.Errorf("mysql: verify account.restore: %w", err)
		}
		return adapterutil.VerifyResult(true, fmt.Sprintf(
			"account %q exists and the reserved credential is proved", account.String())), nil
	case adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		locked, found, err := accountLocked(ctx, db, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		if change.Kind == adapter.ChangeAccountDisable {
			return adapterutil.VerifyResult(found && locked, fmt.Sprintf("account %q exists and is locked", account.String())), nil
		}
		return adapterutil.VerifyResult(found && !locked, fmt.Sprintf("account %q exists and is unlocked", account.String())), nil
	default: // adapter.ChangeAccountDelete
		exists, err := userExists(ctx, db, account)
		if err != nil {
			return nil, fmt.Errorf("mysql: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(!exists, fmt.Sprintf("account %q absent", account.String())), nil
	}
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32). Спецсимволы сознательно не используются
// для совместимости с клиентами и строками подключения.
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего аккаунта через ALTER USER ...
// IDENTIFIED BY. Пароль экранируется quoteLiteral и не попадает в логи и
// тексты ошибок. Возвращает adapter.ErrNotFound, если аккаунта нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	target, err := parseUserHost(account.EngineIdentity)
	if err != nil {
		return fmt.Errorf("mysql: rotate credential: %w", err)
	}
	if len(credential.Secret) == 0 {
		return errors.New("mysql: rotate credential: credential secret is empty")
	}

	db, err := a.open(ctx, cfg, defaultDatabase(cfg))
	if err != nil {
		return fmt.Errorf("mysql: rotate credential: %w", err)
	}
	defer closeQuietly(db)

	exists, err := userExists(ctx, db, target)
	if err != nil {
		return fmt.Errorf("mysql: rotate credential: %w", err)
	}
	if !exists {
		return fmt.Errorf("mysql: rotate credential: account %q: %w", target.String(), adapter.ErrNotFound)
	}
	if err := setAccountPassword(ctx, db, target, credential.Secret); err != nil {
		return fmt.Errorf("mysql: rotate credential: %w", err)
	}
	return nil
}

// setAccountPassword выполняет ALTER USER ... IDENTIFIED BY. Пароль попадает
// в SQL как literal, собранный quoteLiteral; statement нигде не логируется, а
// ошибка сервера редуцируется до кода MySQL, потому что сообщение сервера
// может цитировать текст запроса.
func setAccountPassword(ctx context.Context, db *sql.DB, account userHost, secret []byte) error {
	lit, err := quoteLiteral(string(secret))
	if err != nil {
		return fmt.Errorf("password for account %q: %w", account.String(), err)
	}
	// Ошибка сознательно передаётся через %s без %w: исходная цепочка может
	// содержать фрагменты statement с паролем.
	if _, err := db.ExecContext(ctx, "ALTER USER "+account.quoted()+" IDENTIFIED BY "+lit); err != nil {
		return fmt.Errorf("set password for account %q: %s", account.String(), redactExecError(err))
	}
	return nil
}

// userHost — распарсенная пара user@host аккаунта или роли MySQL.
type userHost struct {
	user string
	host string
}

// String возвращает каноническое EngineIdentity "user@host".
func (u userHost) String() string { return u.user + "@" + u.host }

// quoted возвращает account reference MySQL 'user'@'host' с экранированием.
func (u userHost) quoted() string {
	return quoteString(u.user) + "@" + quoteString(u.host)
}

// parseUserHost разбирает EngineIdentity "user@host". Split выполняется по
// последнему '@': '@' допустим внутри username (редко), но host обязателен и
// идёт после последнего '@'. host может быть пустым, '%', '10.%' или
// 'localhost'. Строка без '@' — ошибка (host обязателен).
func parseUserHost(identity string) (userHost, error) {
	if identity == "" {
		return userHost{}, errors.New("account engine identity is empty")
	}
	idx := strings.LastIndex(identity, "@")
	if idx < 0 {
		return userHost{}, fmt.Errorf("account engine identity %q must be in user@host form", identity)
	}
	user := identity[:idx]
	if user == "" {
		return userHost{}, fmt.Errorf("account engine identity %q has empty user part", identity)
	}
	return userHost{user: user, host: identity[idx+1:]}, nil
}

// membershipTargets извлекает роль и account из change для grant/revoke.
func membershipTargets(change adapter.DesiredChange) (role, member userHost, err error) {
	role, err = parseUserHost(rolePermissionIdentity(change.Permission))
	if err != nil {
		return userHost{}, userHost{}, err
	}
	member, err = parseUserHost(change.Account.EngineIdentity)
	if err != nil {
		return userHost{}, userHost{}, err
	}
	return role, member, nil
}

// rolePermissionIdentity извлекает EngineIdentity роли из external id
// permission вида "role:<user>@<host>" (см. rolePermissionID). Если префикса
// нет, строка возвращается как есть — parseUserHost затем даст осмысленную
// ошибку.
func rolePermissionIdentity(permission string) string {
	if id, ok := strings.CutPrefix(permission, "role:"); ok {
		return id
	}
	return permission
}

// quoteString собирает SQL string literal '...' с экранированием одинарной
// кавычки и обратного слэша (в MySQL по умолчанию backslash — escape-символ).
func quoteString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`)
	return "'" + r.Replace(s) + "'"
}

// quoteLiteral собирает SQL string literal для DDL с секретом (пароли).
// Отвергает нулевые байты: MySQL не допускает их в парольных строках, а их
// экранирование ненадёжно между режимами сервера.
func quoteLiteral(s string) (string, error) {
	if strings.ContainsRune(s, '\x00') {
		return "", errors.New("string literal must not contain NUL bytes")
	}
	return quoteString(s), nil
}

// userExists проверяет существование аккаунта/роли в mysql.user. Результат
// EXISTS сканируется в int64 (а не bool): для параметризованных запросов
// go-sql-driver отдаёт значение бинарным протоколом как целое, и int64 —
// самое надёжное представление.
func userExists(ctx context.Context, db *sql.DB, account userHost) (bool, error) {
	var exists int64
	const q = `SELECT EXISTS(SELECT 1 FROM mysql.user WHERE User = ? AND Host = ?)`
	if err := db.QueryRowContext(ctx, q, account.user, account.host).Scan(&exists); err != nil {
		return false, fmt.Errorf("check account %q: %w", account.String(), err)
	}
	return exists != 0, nil
}

// accountLocked возвращает признак блокировки аккаунта (account_locked='Y');
// found=false, если аккаунта нет.
func accountLocked(ctx context.Context, db *sql.DB, account userHost) (locked, found bool, err error) {
	var flag string
	const q = `SELECT account_locked FROM mysql.user WHERE User = ? AND Host = ?`
	err = db.QueryRowContext(ctx, q, account.user, account.host).Scan(&flag)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read lock state of account %q: %w", account.String(), err)
	}
	return strings.EqualFold(flag, "Y"), true, nil
}

// defaultRoles читает текущий набор default roles аккаунта из
// mysql.default_roles (порядок строк MySQL не гарантирует).
func defaultRoles(ctx context.Context, db *sql.DB, member userHost) ([]userHost, error) {
	const q = `SELECT DEFAULT_ROLE_USER, DEFAULT_ROLE_HOST
FROM mysql.default_roles
WHERE USER = ? AND HOST = ?`
	roles, err := queryUserHosts(ctx, db, q, member.user, member.host)
	if err != nil {
		return nil, fmt.Errorf("read default roles of %q: %w", member.String(), err)
	}
	return roles, nil
}

// grantedRoles читает роли, выданные аккаунту, из mysql.role_edges.
func grantedRoles(ctx context.Context, db *sql.DB, member userHost) ([]userHost, error) {
	const q = `SELECT FROM_USER, FROM_HOST
FROM mysql.role_edges
WHERE TO_USER = ? AND TO_HOST = ?`
	roles, err := queryUserHosts(ctx, db, q, member.user, member.host)
	if err != nil {
		return nil, fmt.Errorf("read roles granted to %q: %w", member.String(), err)
	}
	return roles, nil
}

// queryUserHosts выполняет запрос, возвращающий пары (user, host).
func queryUserHosts(ctx context.Context, db *sql.DB, query string, args ...any) ([]userHost, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []userHost
	for rows.Next() {
		var r userHost
		if err := rows.Scan(&r.user, &r.host); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// activateAllRolesOnLogin читает глобальную переменную
// activate_all_roles_on_login: при ON сервер активирует все выданные роли на
// логине независимо от mysql.default_roles. Серверы без этой переменной
// (MySQL < 8.0, MariaDB) трактуются как OFF; grant/revoke ролей на них и так
// отсекаются на этапе Plan.
func activateAllRolesOnLogin(ctx context.Context, db *sql.DB) (bool, error) {
	var flag int64
	err := db.QueryRowContext(ctx, `SELECT @@GLOBAL.activate_all_roles_on_login`).Scan(&flag)
	if err != nil {
		var myErr *mysqldriver.MySQLError
		if errors.As(err, &myErr) && myErr.Number == erUnknownSystemVariable {
			return false, nil
		}
		return false, fmt.Errorf("read activate_all_roles_on_login: %w", err)
	}
	return flag != 0, nil
}

// erUnknownSystemVariable — код MySQL ER_UNKNOWN_SYSTEM_VARIABLE.
const erUnknownSystemVariable = 1193

// hasRoleEdge проверяет наличие ребра role -> member в mysql.role_edges.
func hasRoleEdge(ctx context.Context, db *sql.DB, role, member userHost) (bool, error) {
	const q = `SELECT EXISTS(
	SELECT 1 FROM mysql.role_edges
	WHERE FROM_USER = ? AND FROM_HOST = ? AND TO_USER = ? AND TO_HOST = ?
)`
	var exists int64
	if err := db.QueryRowContext(ctx, q, role.user, role.host, member.user, member.host).Scan(&exists); err != nil {
		return false, fmt.Errorf("check role %q for %q: %w", role.String(), member.String(), err)
	}
	return exists != 0, nil
}

// ensureRolesSupported подтверждает, что сервер поддерживает роли MySQL 8.0.
// На MariaDB и MySQL < 8.0 grant/revoke по ролям невозможен: возвращается
// ошибка, оборачивающая ErrUnsupportedChange.
func ensureRolesSupported(ctx context.Context, db *sql.DB) error {
	var version string
	if err := db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		return fmt.Errorf("read server version: %w", err)
	}
	if !supportsRoles(version) {
		return fmt.Errorf("server %q does not support MySQL 8.0 roles: %w", version, adapter.ErrUnsupportedChange)
	}
	return nil
}

// supportsRoles сообщает, поддерживает ли сервер роли MySQL 8.0. MariaDB
// имеет иную семантику ролей и отсекается по маркеру в строке версии; для
// MySQL требуется major-версия >= 8.
func supportsRoles(version string) bool {
	if version == "" {
		return false
	}
	if strings.Contains(strings.ToLower(version), "mariadb") {
		return false
	}
	major := leadingMajorVersion(version)
	return major >= 8
}

// leadingMajorVersion извлекает major-компонент из строки версии вида
// "8.0.36-...". Возвращает -1, если разобрать не удалось.
func leadingMajorVersion(version string) int {
	end := strings.IndexFunc(version, func(r rune) bool { return r < '0' || r > '9' })
	digits := version
	if end >= 0 {
		digits = version[:end]
	}
	if digits == "" {
		return -1
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return -1
	}
	return n
}
