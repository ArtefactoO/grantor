package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана PostgreSQL adapter.
const (
	stepGrant          = "grant"
	stepRevoke         = "revoke"
	stepCreateRole     = "create-role"
	stepCreateGroup    = "create-group-role"
	stepAlterLogin     = "alter-login"
	stepDropRole       = "drop-role"
	stepRestoreRole    = "restore-role"
	stepCreateDatabase = "create-database"
)

// pgCodeInsufficientPrivilege — SQLSTATE 42501 (insufficient_privilege).
const pgCodeInsufficientPrivilege = "42501"

// pgCodeDuplicateObject — SQLSTATE 42710: роль с таким именем уже есть.
// Возникает в гонке между проверкой и CREATE ROLE.
const pgCodeDuplicateObject = "42710"

// pgCodeDuplicateDatabase — SQLSTATE 42P04: база уже существует. Возникает в
// гонке между проверкой и CREATE DATABASE.
const pgCodeDuplicateDatabase = "42P04"

// resourceKindDatabase — вид ресурса, создание которого поддерживает adapter.
const resourceKindDatabase = "database"

// maxIdentifierBytes — NAMEDATALEN-1: имена длиннее PostgreSQL молча
// обрезает, и обрезанное имя разошлось бы с записанным в инвентарь.
const maxIdentifierBytes = 63

// Plan строит детерминированный типизированный план для DesiredChange.
// Для grant предварительно проверяется существование роли и account; для
// account.create — что роли ещё нет. Descriptions шагов не содержат
// секретных значений.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	if adapter.IsPostgresObjectACLChange(change.Kind) {
		return a.planObjectACL(ctx, change)
	}
	if change.ObjectACL != nil || strings.HasPrefix(change.Permission, adapter.PostgresObjectACLPrefix) {
		return nil, adapter.ErrPostgresObjectACL
	}
	if adapter.IsPostgresStatsMembershipChange(change.Kind) {
		return a.planStatsMembership(ctx, change)
	}
	if change.StatsMembership != nil {
		return nil, ErrStatsMembershipUnsupported
	}
	if ProtectedRole(change.Account.EngineIdentity) {
		return nil, fmt.Errorf("postgres: protected system role cannot be managed: %w", adapter.ErrUnsupportedChange)
	}
	if isDirectRolePolicyChange(change.Kind) {
		return a.planRolePolicy(ctx, change)
	}
	if isDirectProvisioningChange(change.Kind) {
		return a.planDirectProvisioning(ctx, change)
	}
	if adapter.IsLegacyPostgresCreationChange(change.Kind) || adapter.IsPostgresSuperuserDirectChange(change.Kind) {
		return nil, fmt.Errorf("postgres: plan %s: managed creation is disabled until the SUPERUSER-direct executor is available: %w",
			change.Kind, adapter.ErrUnsupportedChange)
	}
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return a.planMembership(ctx, change)
	case adapter.ChangeAccountCreate:
		return a.planAccountCreate(ctx, change)
	case adapter.ChangeRoleCreate:
		return a.planRoleCreate(ctx, change)
	case adapter.ChangeAccountRestore:
		return a.planAccountRestore(ctx, change)
	case adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		return planAlterLogin(change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	case adapter.ChangeResourceCreate:
		return a.planResourceCreate(ctx, change)
	case adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify, adapter.ChangeRolePolicyCreate,
		adapter.ChangeRolePolicyCreateDatabase:
		return a.planRolePolicy(ctx, change)
	default:
		return nil, fmt.Errorf("postgres: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planAccountRestore различает absent и present identity. Absent создаётся
// с новым credential. Present допустима только как recovery retry после
// доказательства точного credential; обычный account.create здесь никогда
// не используется, поэтому чужая существующая роль не перезаписывается.
func (a *Adapter) planAccountRestore(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" || change.Credential == nil || len(change.Credential.Secret) == 0 {
		return nil, errors.New("postgres: plan account.restore: account identity and credential are required")
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: plan account.restore: %w", err)
	}
	exists, err := roleExists(ctx, conn, name)
	closeQuietly(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan account.restore: %w", err)
	}
	if !exists {
		return adapterutil.SingleStepPlan(change, stepRestoreRole,
			fmt.Sprintf("restore login role %q with a fresh credential", name),
			map[string]any{"role": name, "recovery": false}), nil
	}
	if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
		return nil, fmt.Errorf("postgres: plan account.restore: existing role %q: %w", name, err)
	}
	return adapterutil.SingleStepPlan(change, stepRestoreRole,
		fmt.Sprintf("recover already restored login role %q after credential proof", name),
		map[string]any{"role": name, "recovery": true}), nil
}

// planMembership строит план grant/revoke membership. Роли PostgreSQL
// cluster-wide, поэтому непустой scope не поддерживается. Для grant роль и
// account проверяются на существование коротким подключением; revoke
// валидации не требует: отсутствие membership обрабатывается идемпотентным
// Apply как StepSkipped.
func (a *Adapter) planMembership(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	role, err := roleNameFromPermission(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan %s: %w", op, err)
	}
	if ProtectedRole(role) {
		return nil, ErrStatsMembershipUnsupported
	}
	member := change.Account.EngineIdentity
	if member == "" {
		return nil, fmt.Errorf("postgres: plan %s: account engine identity is empty", op)
	}
	if change.Scope != "" {
		return nil, fmt.Errorf("postgres: plan %s: scoped role membership is not supported: %w",
			op, adapter.ErrUnsupportedChange)
	}

	if change.Kind == adapter.ChangeGrant {
		if err := a.checkMembershipObjects(ctx, change.Connection, role, member); err != nil {
			return nil, fmt.Errorf("postgres: plan %s: %w", op, err)
		}
		return adapterutil.SingleStepPlan(change, stepGrant,
			fmt.Sprintf("grant role %q to %q", role, member),
			map[string]any{"role": role, "member": member}), nil
	}
	return adapterutil.SingleStepPlan(change, stepRevoke,
		fmt.Sprintf("revoke role %q from %q", role, member),
		map[string]any{"role": role, "member": member}), nil
}

// checkMembershipObjects проверяет коротким подключением, что и роль, и
// account существуют в целевой системе.
func (a *Adapter) checkMembershipObjects(ctx context.Context, cfg adapter.Connection, role, member string) error {
	conn, err := a.connect(ctx, cfg, maintenanceDatabase(cfg))
	if err != nil {
		return err
	}
	defer closeQuietly(ctx, conn)

	exists, err := roleExists(ctx, conn, role)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("role %q: %w", role, adapter.ErrNotFound)
	}
	exists, err = roleExists(ctx, conn, member)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("account %q: %w", member, adapter.ErrNotFound)
	}
	return nil
}

// planAccountCreate строит план создания LOGIN-аккаунта. Роль не должна
// существовать. change.Credential может быть nil или без секрета — тогда
// роль создаётся без пароля (external identity: аутентификация внешними
// механизмами pg_hba). Description сообщает только факт наличия пароля,
// но не его значение.
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("postgres: plan account.create: account engine identity is empty")
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: plan account.create: %w", err)
	}
	defer closeQuietly(ctx, conn)

	exists, err := roleExists(ctx, conn, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan account.create: %w", err)
	}
	if exists {
		return nil, fmt.Errorf("postgres: plan account.create: %w", adapterutil.IdentityConflict("role", name))
	}

	withPassword := adapterutil.HasPasswordSecret(change.Credential)
	desc := fmt.Sprintf("create login role %q without password (external identity)", name)
	if withPassword {
		desc = fmt.Sprintf("create login role %q and set its password", name)
	}
	return adapterutil.SingleStepPlan(change, stepCreateRole, desc,
		map[string]any{"role": name, "with_password": withPassword}), nil
}

// planRoleCreate строит план создания роли-контейнера без логина. От
// account.create отличается тем, что роль не аутентифицируется: пароля у неё
// нет и быть не должно, а смысл её существования — выдаваться другим учётным
// записям как право.
func (a *Adapter) planRoleCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("postgres: plan role.create: role name is empty")
	}
	// Префикс pg_ зарезервирован PostgreSQL под системные роли: CREATE ROLE
	// с ним отвергает сам сервер, и понятный отказ лучше SQLSTATE из Apply.
	if strings.HasPrefix(strings.ToLower(name), "pg_") {
		return nil, fmt.Errorf("postgres: plan role.create: role name %q uses the reserved pg_ prefix", name)
	}
	if change.Credential != nil {
		return nil, errors.New("postgres: plan role.create: a role without login takes no credential")
	}
	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: plan role.create: %w", err)
	}
	defer closeQuietly(ctx, conn)

	exists, err := roleExists(ctx, conn, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan role.create: %w", err)
	}
	// Тот же контракт, что у account.create: существующая роль не
	// присваивается молча, иначе grantor «принял бы под управление» чужой
	// объект в обход review, который делает adopt.
	if exists {
		return nil, fmt.Errorf("postgres: plan role.create: %w", adapterutil.IdentityConflict("role", name))
	}
	return adapterutil.SingleStepPlan(change, stepCreateGroup,
		fmt.Sprintf("create group role %q (nologin)", name),
		map[string]any{"role": name, "login": false}), nil
}

// planAlterLogin строит план включения/выключения LOGIN. Валидации на этапе
// плана нет: текущее состояние роли проверяет идемпотентный Apply.
func planAlterLogin(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, fmt.Errorf("postgres: plan %s: account engine identity is empty", change.Kind)
	}
	login := change.Kind == adapter.ChangeAccountEnable
	desc := fmt.Sprintf("disable login for role %q (ALTER ROLE ... NOLOGIN)", name)
	if login {
		desc = fmt.Sprintf("enable login for role %q (ALTER ROLE ... LOGIN)", name)
	}
	return adapterutil.SingleStepPlan(change, stepAlterLogin, desc,
		map[string]any{"role": name, "login": login}), nil
}

// planAccountDelete строит план удаления роли. Description явно
// предупреждает, что вместе с ролью исчезнут все её memberships.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if name == "" {
		return nil, errors.New("postgres: plan account.delete: account engine identity is empty")
	}
	return adapterutil.SingleStepPlan(change, stepDropRole,
		fmt.Sprintf(
			"drop role %q; warning: all role memberships granted to and through this role disappear with it",
			name),
		map[string]any{"role": name}), nil
}

// Apply применяет план через одно подключение к maintenance database. Каждый
// шаг идемпотентен: если состояние уже целевое — StepSkipped. Ошибка шага
// помечает его StepFailed (текст без секретов), оставшиеся шаги получают
// StepUnknown и не выполняются.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if adapter.IsPostgresObjectACLChange(plan.Change.Kind) {
		return a.applyObjectACL(ctx, plan)
	}
	if plan.Change.ObjectACL != nil || strings.HasPrefix(plan.Change.Permission, adapter.PostgresObjectACLPrefix) {
		return nil, adapter.ErrPostgresObjectACL
	}
	if adapter.IsPostgresStatsMembershipChange(plan.Change.Kind) {
		return a.applyStatsMembership(ctx, plan)
	}
	if plan.Change.StatsMembership != nil {
		return nil, ErrStatsMembershipUnsupported
	}
	if ProtectedRole(plan.Change.Account.EngineIdentity) {
		return nil, ErrStatsMembershipUnsupported
	}
	if role, err := roleNameFromPermission(plan.Change.Permission); err == nil && ProtectedRole(role) {
		return nil, ErrStatsMembershipUnsupported
	}
	if isDirectRolePolicyMutation(plan.Change.Kind) {
		return a.applyRolePolicy(ctx, plan)
	}
	if isDirectRolePolicyReadOnly(plan.Change.Kind) {
		return nil, fmt.Errorf("postgres: apply %s: read-only policy plans must not mutate target: %w",
			plan.Change.Kind, adapter.ErrUnsupportedChange)
	}
	if isDirectProvisioningChange(plan.Change.Kind) {
		return a.applyDirectProvisioning(ctx, plan)
	}
	if adapter.IsLegacyPostgresCreationChange(plan.Change.Kind) || adapter.IsPostgresSuperuserDirectChange(plan.Change.Kind) {
		return nil, fmt.Errorf("postgres: apply %s: managed creation is disabled until the SUPERUSER-direct executor is available: %w",
			plan.Change.Kind, adapter.ErrUnsupportedChange)
	}
	if plan.Change.Kind == adapter.ChangeRolePolicyApply || isRolePolicyCreate(plan.Change.Kind) {
		return a.applyRolePolicy(ctx, plan)
	}
	if plan.Change.Kind == adapter.ChangeRolePolicyVerify {
		return nil, fmt.Errorf("postgres: apply %s: verify-only plans must not mutate target: %w",
			plan.Change.Kind, adapter.ErrUnsupportedChange)
	}
	conn, err := a.connect(ctx, plan.Change.Connection, maintenanceDatabase(plan.Change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: apply %s: %w", plan.Change.Kind, err)
	}
	defer closeQuietly(ctx, conn)
	if plan.Change.Kind == adapter.ChangeAccountRestore {
		return applyRestoreAtomic(ctx, conn, plan)
	}

	return adapterutil.ApplySteps(ctx, plan, conn, applyStep), nil
}

// applyStep выполняет один шаг плана. Все имена объектов экранируются через
// pgx.Identifier; тексты ошибок не содержат секретов.
func applyStep(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrant:
		return applyGrant(ctx, conn, change)
	case stepRevoke:
		return applyRevoke(ctx, conn, change)
	case stepCreateRole:
		return applyCreateRole(ctx, conn, change)
	case stepCreateGroup:
		return applyCreateGroupRole(ctx, conn, change)
	case stepCreateDatabase:
		return applyCreateDatabase(ctx, conn, change)
	case stepRestoreRole:
		return adapter.StepFailed, errors.New("restore-role must be applied atomically")
	case stepAlterLogin:
		return applyAlterLogin(ctx, conn, change)
	case stepDropRole:
		return applyDropRole(ctx, conn, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyRestoreAtomic делает CREATE ROLE + PASSWORD одной PostgreSQL
// транзакцией. Crash/ошибка между statements откатывает роль целиком, поэтому
// retry никогда не встречает identity без зарезервированного credential.
func applyRestoreAtomic(ctx context.Context, conn *pgx.Conn, plan adapter.Plan) (*adapter.Result, error) {
	if len(plan.Steps) != 1 || plan.Steps[0].Kind != stepRestoreRole {
		return nil, errors.New("postgres: apply account.restore: invalid restore plan")
	}
	change := plan.Change
	step := plan.Steps[0]
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("postgres: apply account.restore: begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	if err := tx.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`,
		change.Account.EngineIdentity).Scan(&exists); err != nil {
		return nil, fmt.Errorf("postgres: apply account.restore: check role: %w", err)
	}
	status := adapter.StepSkipped
	if exists {
		recovery, _ := step.Attributes["recovery"].(bool)
		if !recovery {
			return nil, fmt.Errorf("postgres: apply account.restore: role %q appeared after planning: %w",
				change.Account.EngineIdentity, adapter.ErrExternalIdentityConflict)
		}
	} else {
		name := change.Account.EngineIdentity
		if _, err := tx.Exec(ctx, "create role "+sanitizeIdent(name)+" login"); err != nil {
			return nil, fmt.Errorf("postgres: apply account.restore: create role %q: %w", name, err)
		}
		if change.Credential == nil {
			return nil, errors.New("postgres: apply account.restore: credential is required")
		}
		if err := setRolePassword(ctx, tx, name, change.Credential.Secret); err != nil {
			return nil, fmt.Errorf("postgres: apply account.restore: %w", err)
		}
		status = adapter.StepApplied
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("postgres: apply account.restore: commit: %w", err)
	}
	return &adapter.Result{Steps: []adapter.StepResult{{Step: step, Status: status}}}, nil
}

// applyGrant выдаёт membership; существующий membership — StepSkipped.
func applyGrant(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	role, err := roleNameFromPermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	member := change.Account.EngineIdentity
	has, err := hasMembership(ctx, conn, role, member)
	if err != nil {
		return adapter.StepFailed, err
	}
	if has {
		return adapter.StepSkipped, nil
	}
	if _, err := conn.Exec(ctx, "grant "+sanitizeIdent(role)+" to "+sanitizeIdent(member)); err != nil {
		return adapter.StepFailed, describeMembershipError("grant", role, member, err)
	}
	return adapter.StepApplied, nil
}

// applyRevoke отзывает membership; отсутствующий membership — StepSkipped
// (в том числе когда роли или account уже нет).
func applyRevoke(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	role, err := roleNameFromPermission(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	member := change.Account.EngineIdentity
	has, err := hasMembership(ctx, conn, role, member)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !has {
		return adapter.StepSkipped, nil
	}
	if _, err := conn.Exec(ctx, "revoke "+sanitizeIdent(role)+" from "+sanitizeIdent(member)); err != nil {
		return adapter.StepFailed, describeMembershipError("revoke", role, member, err)
	}
	return adapter.StepApplied, nil
}

// applyCreateRole создаёт LOGIN-роль. Существующая роль — не «уже сделано», а
// ErrExternalIdentityConflict: Plan видел её отсутствие, значит роль создал
// кто-то другой между Plan и Apply (см. adapterutil.IdentityConflict).
//
// Создание и установка пароля идут одной транзакцией — по той же причине, что
// и в applyRestoreAtomic. CREATE ROLE не содержит секретов, пароль задаётся
// отдельным ALTER ROLE, и без транзакции обрыв между ними оставил бы
// беспарольную LOGIN-роль, которую повтор уже не смог бы отличить от чужой.
func applyCreateRole(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	tx, err := conn.Begin(ctx)
	if err != nil {
		return adapter.StepFailed, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	if err := tx.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, name).Scan(&exists); err != nil {
		return adapter.StepFailed, fmt.Errorf("check role %q: %w", name, err)
	}
	if exists {
		return adapter.StepFailed, adapterutil.IdentityConflict("role", name)
	}
	if _, err := tx.Exec(ctx, "create role "+sanitizeIdent(name)+" login"); err != nil {
		return adapter.StepFailed, fmt.Errorf("create role %q: %w", name, err)
	}
	if adapterutil.HasPasswordSecret(change.Credential) {
		if err := setRolePassword(ctx, tx, name, change.Credential.Secret); err != nil {
			return adapter.StepFailed, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return adapter.StepFailed, fmt.Errorf("commit create role %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyCreateGroupRole создаёт роль без логина. Пароль не задаётся никогда:
// у роли-контейнера его нет по определению. Повторная проверка существования
// закрывает окно между Plan и Apply, гонку добивает SQLSTATE 42710.
func applyCreateGroupRole(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	exists, err := roleExists(ctx, conn, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if exists {
		return adapter.StepFailed, adapterutil.IdentityConflict("role", name)
	}
	if _, err := conn.Exec(ctx, "create role "+sanitizeIdent(name)+" nologin"); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgCodeDuplicateObject {
			return adapter.StepFailed, adapterutil.IdentityConflict("role", name)
		}
		return adapter.StepFailed, fmt.Errorf("create group role %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyAlterLogin включает/выключает LOGIN; совпадающее состояние —
// StepSkipped, отсутствующая роль — ошибка ErrNotFound.
func applyAlterLogin(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	want := change.Kind == adapter.ChangeAccountEnable
	current, found, err := roleLogin(ctx, conn, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("role %q: %w", name, adapter.ErrNotFound)
	}
	if current == want {
		return adapter.StepSkipped, nil
	}
	attr := " nologin"
	if want {
		attr = " login"
	}
	if _, err := conn.Exec(ctx, "alter role "+sanitizeIdent(name)+attr); err != nil {
		return adapter.StepFailed, fmt.Errorf("alter role %q login flag: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// applyDropRole удаляет роль; отсутствующая роль — StepSkipped.
func applyDropRole(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	exists, err := roleExists(ctx, conn, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !exists {
		return adapter.StepSkipped, nil
	}
	if _, err := conn.Exec(ctx, "drop role "+sanitizeIdent(name)); err != nil {
		return adapter.StepFailed, fmt.Errorf("drop role %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// Verify выполняет read-back проверку итогового состояния плана по системным
// каталогам. Details не содержат секретов.
func (a *Adapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	if adapter.IsPostgresObjectACLChange(plan.Change.Kind) {
		return a.verifyObjectACL(ctx, plan)
	}
	if plan.Change.ObjectACL != nil || strings.HasPrefix(plan.Change.Permission, adapter.PostgresObjectACLPrefix) {
		return nil, adapter.ErrPostgresObjectACL
	}
	if adapter.IsPostgresStatsMembershipChange(plan.Change.Kind) {
		return a.verifyStatsMembership(ctx, plan)
	}
	change := plan.Change
	if change.StatsMembership != nil || ProtectedRole(change.Account.EngineIdentity) {
		return nil, ErrStatsMembershipUnsupported
	}
	if role, err := roleNameFromPermission(change.Permission); err == nil && ProtectedRole(role) {
		return nil, ErrStatsMembershipUnsupported
	}
	if isDirectRolePolicyChange(change.Kind) {
		return a.verifyRolePolicy(ctx, plan)
	}
	if isDirectProvisioningChange(change.Kind) {
		return a.verifyDirectProvisioning(ctx, plan)
	}
	if adapter.IsLegacyPostgresCreationChange(change.Kind) || adapter.IsPostgresSuperuserDirectChange(change.Kind) {
		return nil, fmt.Errorf("postgres: verify %s: managed creation is disabled until the SUPERUSER-direct executor is available: %w",
			change.Kind, adapter.ErrUnsupportedChange)
	}
	if change.Kind == adapter.ChangeRolePolicyApply || change.Kind == adapter.ChangeRolePolicyVerify ||
		isRolePolicyCreate(change.Kind) {
		return a.verifyRolePolicy(ctx, plan)
	}
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeRoleCreate,
		adapter.ChangeAccountDisable,
		adapter.ChangeAccountEnable, adapter.ChangeAccountDelete,
		adapter.ChangeAccountRestore, adapter.ChangeResourceCreate:
	default:
		return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
	}
	defer closeQuietly(ctx, conn)

	if change.Kind == adapter.ChangeResourceCreate {
		verification, err := verifyDatabaseCreated(ctx, conn, change)
		return verification, err
	}
	name := change.Account.EngineIdentity
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		role, err := roleNameFromPermission(change.Permission)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		has, err := hasMembership(ctx, conn, role, name)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		if change.Kind == adapter.ChangeGrant {
			return adapterutil.VerifyResult(has, fmt.Sprintf("membership of %q in role %q present", name, role)), nil
		}
		return adapterutil.VerifyResult(!has, fmt.Sprintf("membership of %q in role %q absent", name, role)), nil
	case adapter.ChangeAccountCreate, adapter.ChangeAccountDisable, adapter.ChangeAccountEnable:
		canLogin, found, err := roleLogin(ctx, conn, name)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		if change.Kind == adapter.ChangeAccountDisable {
			return adapterutil.VerifyResult(found && !canLogin, fmt.Sprintf("role %q exists and cannot log in", name)), nil
		}
		return adapterutil.VerifyResult(found && canLogin, fmt.Sprintf("role %q exists and can log in", name)), nil
	case adapter.ChangeRoleCreate:
		canLogin, found, err := roleLogin(ctx, conn, name)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		// Роль обязана существовать И не иметь логина: учётка с логином под
		// тем же именем означала бы, что применилось не то, что планировалось.
		return adapterutil.VerifyResult(found && !canLogin,
			fmt.Sprintf("role %q exists and cannot log in (group role)", name)), nil
	case adapter.ChangeAccountRestore:
		canLogin, found, err := roleLogin(ctx, conn, name)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		if !found || !canLogin {
			return adapterutil.VerifyResult(false, fmt.Sprintf("role %q exists and can log in with the reserved credential", name)), nil
		}
		if change.Credential == nil {
			return nil, errors.New("postgres: verify account.restore: credential is required")
		}
		if err := a.ProveCredential(ctx, change.Connection, change.Account, *change.Credential); err != nil {
			return nil, fmt.Errorf("postgres: verify account.restore: %w", err)
		}
		return adapterutil.VerifyResult(true, fmt.Sprintf("role %q exists and reserved credential is proved", name)), nil
	default: // adapter.ChangeAccountDelete
		exists, err := roleExists(ctx, conn, name)
		if err != nil {
			return nil, fmt.Errorf("postgres: verify %s: %w", change.Kind, err)
		}
		return adapterutil.VerifyResult(!exists, fmt.Sprintf("role %q absent", name)), nil
	}
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32). Спецсимволы сознательно не используются
// для совместимости с клиентами и строками подключения.
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующей роли через ALTER ROLE ...
// PASSWORD. Пароль экранируется quoteLiteral и не попадает в логи и тексты
// ошибок. Возвращает adapter.ErrNotFound, если роли нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	if ProtectedRole(account.EngineIdentity) {
		return ErrStatsMembershipUnsupported
	}
	name := account.EngineIdentity
	if name == "" {
		return errors.New("postgres: rotate credential: account engine identity is empty")
	}
	if len(credential.Secret) == 0 {
		return errors.New("postgres: rotate credential: credential secret is empty")
	}

	conn, err := a.connect(ctx, cfg, maintenanceDatabase(cfg))
	if err != nil {
		return fmt.Errorf("postgres: rotate credential: %w", err)
	}
	defer closeQuietly(ctx, conn)

	exists, err := roleExists(ctx, conn, name)
	if err != nil {
		return fmt.Errorf("postgres: rotate credential: %w", err)
	}
	if !exists {
		return fmt.Errorf("postgres: rotate credential: role %q: %w", name, adapter.ErrNotFound)
	}
	if err := setRolePassword(ctx, conn, name, credential.Secret); err != nil {
		return fmt.Errorf("postgres: rotate credential: %w", err)
	}
	return nil
}

// setRolePassword выполняет ALTER ROLE ... PASSWORD. Пароль попадает в SQL
// как literal, собранный quoteLiteral; сам statement нигде не логируется, а
// ошибка сервера редуцируется до SQLSTATE, потому что сообщение сервера может
// цитировать текст запроса.
type statementExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func setRolePassword(ctx context.Context, conn statementExecutor, role string, secret []byte) error {
	lit, err := quoteLiteral(string(secret))
	if err != nil {
		return fmt.Errorf("password for role %q: %w", role, err)
	}
	// quoteLiteral рассчитан на literal-семантику '...' без backslash
	// escapes: фиксируем её на уровне сессии независимо от конфигурации
	// сервера.
	if _, err := conn.Exec(ctx, "set standard_conforming_strings = on"); err != nil {
		return fmt.Errorf("prepare session for password change of role %q: %w", role, err)
	}
	// Ошибка сознательно передаётся через %s без %w: исходная цепочка может
	// содержать фрагменты statement с паролем.
	if _, err := conn.Exec(ctx, "alter role "+sanitizeIdent(role)+" password "+lit); err != nil {
		return fmt.Errorf("set password for role %q: %s", role, redactExecError(err))
	}
	return nil
}

// redactExecError возвращает безопасный текст ошибки statement, содержащего
// секрет: сообщение сервера может включать фрагмент запроса (например, при
// syntax error), поэтому от PgError остаётся только SQLSTATE. Ошибки
// транспорта текст запроса не содержат и возвращаются как есть.
func redactExecError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return "server rejected statement (SQLSTATE " + pgErr.Code + ")"
	}
	return err.Error()
}

// describeMembershipError оборачивает ошибку GRANT/REVOKE. Для SQLSTATE
// 42501 (insufficient_privilege) добавляется подсказка про семантику
// PostgreSQL 16: non-superuser администратор (CREATEROLE) может управлять
// membership только тех ролей, на которые сам имеет ADMIN OPTION.
//
// Общий признак «SUPERUSER либо CREATEROLE» проверяется заранее в
// ValidateConnection (checkAdminPrivileges, матрица минимальных привилегий,
// docs/threat-model.md R4). ADMIN OPTION же зависит от конкретной управляемой
// роли, поэтому проверяется только здесь, в момент GRANT.
func describeMembershipError(op, role, member string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgCodeInsufficientPrivilege {
		return fmt.Errorf(
			"%s role %q for %q: %s: admin role lacks ADMIN OPTION on %q (required by PostgreSQL 16+ for non-superuser administrators)",
			op, role, member, pgErr.Message, role)
	}
	return fmt.Errorf("%s role %q for %q: %w", op, role, member, err)
}

// quoteLiteral собирает SQL string literal для DDL statements, где
// параметризация невозможна (ALTER ROLE ... PASSWORD): одинарные кавычки
// удваиваются, нулевые байты запрещены (PostgreSQL не допускает их в
// строках). Результат корректен при standard_conforming_strings = on;
// setRolePassword фиксирует этот режим на уровне сессии.
func quoteLiteral(s string) (string, error) {
	if strings.ContainsRune(s, '\x00') {
		return "", errors.New("string literal must not contain NUL bytes")
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'", nil
}

// roleNameFromPermission извлекает имя роли из external id permission вида
// "role:<name>" (см. rolePermissionID).
func roleNameFromPermission(permission string) (string, error) {
	name, ok := strings.CutPrefix(permission, "role:")
	if !ok || name == "" {
		return "", fmt.Errorf("permission %q is not a role permission (want \"role:<name>\")", permission)
	}
	return name, nil
}

// sanitizeIdent экранирует имя объекта для конкатенации в DDL.
func sanitizeIdent(name string) string {
	return pgx.Identifier{name}.Sanitize()
}

// roleExists проверяет существование роли в pg_roles.
func roleExists(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_roles where rolname = $1)`, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check role %q: %w", name, err)
	}
	return exists, nil
}

// roleLogin возвращает rolcanlogin роли; found=false, если роли нет.
func roleLogin(ctx context.Context, conn *pgx.Conn, name string) (canLogin, found bool, err error) {
	err = conn.QueryRow(ctx,
		`select rolcanlogin from pg_roles where rolname = $1`, name).Scan(&canLogin)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read login flag of role %q: %w", name, err)
	}
	return canLogin, true, nil
}

// hasMembership проверяет наличие прямого membership member -> role в
// pg_auth_members.
func hasMembership(ctx context.Context, conn *pgx.Conn, role, member string) (bool, error) {
	const q = `
select exists (
	select 1
	from pg_auth_members am
	join pg_roles r on r.oid = am.roleid
	join pg_roles m on m.oid = am.member
	where r.rolname = $1 and m.rolname = $2
)`
	var exists bool
	if err := conn.QueryRow(ctx, q, role, member).Scan(&exists); err != nil {
		return false, fmt.Errorf("check membership of %q in role %q: %w", member, role, err)
	}
	return exists, nil
}

// databaseSpec — разобранные опции создания базы. Строгий разбор: неизвестный
// ключ отвергается, потому что молча проигнорированная опция означает базу с
// не теми параметрами, а отката у создания нет.
type databaseSpec struct {
	Owner           string
	Template        string
	Encoding        string
	Locale          string
	Tablespace      string
	ConnectionLimit *int
}

// parseDatabaseSpec разбирает Resource.Attributes в типизированную спеку.
func parseDatabaseSpec(attrs map[string]any) (databaseSpec, error) {
	var spec databaseSpec
	strFields := map[string]*string{
		"owner":      &spec.Owner,
		"template":   &spec.Template,
		"encoding":   &spec.Encoding,
		"locale":     &spec.Locale,
		"tablespace": &spec.Tablespace,
	}
	for key, value := range attrs {
		if target, ok := strFields[key]; ok {
			s, ok := value.(string)
			if !ok {
				return databaseSpec{}, fmt.Errorf("option %q must be a string", key)
			}
			*target = strings.TrimSpace(s)
			continue
		}
		if key != "connection_limit" {
			return databaseSpec{}, fmt.Errorf("unknown database option %q", key)
		}
		// JSON-числа приезжают float64; принимаем и int из Go-вызовов.
		var limit int
		switch v := value.(type) {
		case float64:
			if v != float64(int(v)) {
				return databaseSpec{}, errors.New("option \"connection_limit\" must be an integer")
			}
			limit = int(v)
		case int:
			limit = v
		default:
			return databaseSpec{}, errors.New("option \"connection_limit\" must be an integer")
		}
		if limit < -1 {
			return databaseSpec{}, errors.New("option \"connection_limit\" must be -1 or greater")
		}
		spec.ConnectionLimit = &limit
	}
	return spec, nil
}

// allowedList читает allowlist из атрибутов подключения. Отсутствие ключа и
// пустой список одинаково означают «опция запрещена»: расширение возможностей
// должно быть явным решением оператора (architecture §11.2).
func allowedList(cfg adapter.Connection, key string) []string {
	raw, ok := cfg.Attributes[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// checkAllowed отвергает значение, которого нет в allowlist подключения.
func checkAllowed(cfg adapter.Connection, key, option, value string) error {
	if value == "" {
		return nil
	}
	allowed := allowedList(cfg, key)
	if len(allowed) == 0 {
		return fmt.Errorf("option %q is not allowed for this connection: no %s allowlist is configured", option, option)
	}
	if !slices.Contains(allowed, value) {
		return fmt.Errorf("%s %q is not in the connection allowlist", option, value)
	}
	return nil
}

// planResourceCreate строит план создания базы. Все опции проверяются здесь:
// Plan — единственная точка, работающая одинаково в direct и connector
// режимах, а отката у создания базы нет (architecture §11.2).
func (a *Adapter) planResourceCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	if change.Resource == nil || change.Resource.Kind != resourceKindDatabase {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", adapter.ErrUnsupportedChange)
	}
	name := strings.TrimSpace(change.Resource.Name)
	if name == "" {
		return nil, errors.New("postgres: plan resource.create: database name is empty")
	}
	if len(name) > maxIdentifierBytes {
		return nil, fmt.Errorf("postgres: plan resource.create: database name %q is longer than %d bytes",
			name, maxIdentifierBytes)
	}
	spec, err := parseDatabaseSpec(change.Resource.Attributes)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}
	// Шаблон и tablespace задают, откуда база берёт содержимое и где лежит:
	// оба выходят за пределы «завести пустую базу», поэтому без явного
	// allowlist подключения запрещены.
	if err := checkAllowed(change.Connection, adapter.AttrDatabaseCreateTemplates, "template", spec.Template); err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}
	if err := checkAllowed(change.Connection, adapter.AttrDatabaseCreateTablespaces, "tablespace", spec.Tablespace); err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}

	conn, err := a.connect(ctx, change.Connection, maintenanceDatabase(change.Connection))
	if err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}
	defer closeQuietly(ctx, conn)

	// CREATEDB проверяется заранее: без права сервер отвергнет создание уже
	// в Apply, а ранний понятный отказ экономит операцию.
	if err := checkCreateDatabasePrivilege(ctx, conn); err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}
	exists, err := databaseExists(ctx, conn, name)
	if err != nil {
		return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
	}
	// Существующая база не присваивается: отката нет, и «принять» чужую базу
	// в инвентарь как свою значило бы записать себе чужие данные.
	if exists {
		return nil, fmt.Errorf("postgres: plan resource.create: %w",
			adapterutil.IdentityConflict("database", name))
	}
	if spec.Owner != "" {
		if err := checkAllowed(change.Connection, adapter.AttrDatabaseCreateOwners, "owner", spec.Owner); err != nil &&
			len(allowedList(change.Connection, adapter.AttrDatabaseCreateOwners)) > 0 {
			return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
		}
		if err := checkDatabaseOwner(ctx, conn, spec.Owner); err != nil {
			return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
		}
	}
	if spec.Template != "" {
		ok, err := templateExists(ctx, conn, spec.Template)
		if err != nil {
			return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("postgres: plan resource.create: template %q does not exist", spec.Template)
		}
	}
	if spec.Tablespace != "" {
		ok, err := tablespaceExists(ctx, conn, spec.Tablespace)
		if err != nil {
			return nil, fmt.Errorf("postgres: plan resource.create: %w", err)
		}
		if !ok {
			return nil, fmt.Errorf("postgres: plan resource.create: tablespace %q does not exist", spec.Tablespace)
		}
	}
	attrs := map[string]any{"database": name}
	for key, value := range map[string]string{
		"owner": spec.Owner, "template": spec.Template,
		"encoding": spec.Encoding, "locale": spec.Locale, "tablespace": spec.Tablespace,
	} {
		if value != "" {
			attrs[key] = value
		}
	}
	if spec.ConnectionLimit != nil {
		attrs["connection_limit"] = *spec.ConnectionLimit
	}
	return adapterutil.SingleStepPlan(change, stepCreateDatabase,
		fmt.Sprintf("create database %q", name), attrs), nil
}

// createDatabaseSQL собирает CREATE DATABASE. Идентификаторы экранируются
// pgx.Identifier, литералы — quoteLiteral, предел соединений печатается из
// уже разобранного int: подстановки параметров CREATE DATABASE не принимает.
func createDatabaseSQL(name string, spec databaseSpec) (string, error) {
	var b strings.Builder
	b.WriteString("create database " + sanitizeIdent(name))
	if spec.Owner != "" {
		b.WriteString(" owner " + sanitizeIdent(spec.Owner))
	}
	if spec.Template != "" {
		b.WriteString(" template " + sanitizeIdent(spec.Template))
	}
	if spec.Encoding != "" {
		encoding, err := quoteLiteral(spec.Encoding)
		if err != nil {
			return "", fmt.Errorf("encoding: %w", err)
		}
		b.WriteString(" encoding " + encoding)
	}
	if spec.Locale != "" {
		locale, err := quoteLiteral(spec.Locale)
		if err != nil {
			return "", fmt.Errorf("locale: %w", err)
		}
		b.WriteString(" locale " + locale)
	}
	if spec.Tablespace != "" {
		b.WriteString(" tablespace " + sanitizeIdent(spec.Tablespace))
	}
	if spec.ConnectionLimit != nil {
		b.WriteString(" connection limit " + strconv.Itoa(*spec.ConnectionLimit))
	}
	return b.String(), nil
}

// applyCreateDatabase создаёт базу. Транзакции нет намеренно: CREATE DATABASE
// не выполняется внутри транзакционного блока. Гонку между проверкой и
// созданием добивает SQLSTATE 42P04.
func applyCreateDatabase(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (adapter.StepStatus, error) {
	if change.Resource == nil {
		return adapter.StepFailed, errors.New("resource spec is required")
	}
	name := strings.TrimSpace(change.Resource.Name)
	spec, err := parseDatabaseSpec(change.Resource.Attributes)
	if err != nil {
		return adapter.StepFailed, err
	}
	exists, err := databaseExists(ctx, conn, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if exists {
		return adapter.StepFailed, adapterutil.IdentityConflict("database", name)
	}
	stmt, err := createDatabaseSQL(name, spec)
	if err != nil {
		return adapter.StepFailed, err
	}
	if _, err := conn.Exec(ctx, stmt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgCodeDuplicateDatabase {
			return adapter.StepFailed, adapterutil.IdentityConflict("database", name)
		}
		return adapter.StepFailed, fmt.Errorf("create database %q: %w", name, err)
	}
	return adapter.StepApplied, nil
}

// databaseExists сообщает, есть ли база с таким именем.
func databaseExists(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_database where datname = $1)`, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check database %q: %w", name, err)
	}
	return exists, nil
}

// checkCreateDatabasePrivilege проверяет, что текущая роль вообще может
// создавать базы.
func checkCreateDatabasePrivilege(ctx context.Context, conn *pgx.Conn) error {
	var allowed bool
	if err := conn.QueryRow(ctx,
		`select rolsuper or rolcreatedb from pg_roles where rolname = current_user`).Scan(&allowed); err != nil {
		return fmt.Errorf("check createdb privilege: %w", err)
	}
	if !allowed {
		return &adapter.InsufficientPrivilegeError{Engine: Engine, Missing: "CREATEDB (or SUPERUSER)"}
	}
	return nil
}

// checkDatabaseOwner требует существующую не-superuser роль: назначив
// владельцем суперпользователя, grantor отдал бы базу под учётку, которой и
// так всё можно, и потерял бы смысл владения.
func checkDatabaseOwner(ctx context.Context, conn *pgx.Conn, owner string) error {
	var superuser bool
	err := conn.QueryRow(ctx,
		`select rolsuper from pg_roles where rolname = $1`, owner).Scan(&superuser)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("owner role %q does not exist", owner)
	}
	if err != nil {
		return fmt.Errorf("check owner role %q: %w", owner, err)
	}
	if superuser {
		return fmt.Errorf("owner role %q is a superuser", owner)
	}
	return nil
}

// templateExists сообщает, есть ли база-шаблон с таким именем.
func templateExists(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_database where datname = $1 and datistemplate)`,
		name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check template %q: %w", name, err)
	}
	return exists, nil
}

// tablespaceExists сообщает, есть ли tablespace с таким именем.
func tablespaceExists(ctx context.Context, conn *pgx.Conn, name string) (bool, error) {
	var exists bool
	if err := conn.QueryRow(ctx,
		`select exists (select 1 from pg_tablespace where spcname = $1)`, name).Scan(&exists); err != nil {
		return false, fmt.Errorf("check tablespace %q: %w", name, err)
	}
	return exists, nil
}

// verifyDatabaseCreated подтверждает создание базы и, если владелец был задан,
// что он действительно назначен: несовпадение владельца означает базу, которой
// управляет не тот, кто planировался.
func verifyDatabaseCreated(ctx context.Context, conn *pgx.Conn, change adapter.DesiredChange) (*adapter.Verification, error) {
	if change.Resource == nil {
		return nil, fmt.Errorf("postgres: verify resource.create: %w", adapter.ErrUnsupportedChange)
	}
	name := strings.TrimSpace(change.Resource.Name)
	spec, err := parseDatabaseSpec(change.Resource.Attributes)
	if err != nil {
		return nil, fmt.Errorf("postgres: verify resource.create: %w", err)
	}
	var owner, systemIdentifier string
	var databaseOID, ownerOID uint32
	err = conn.QueryRow(ctx,
		`select d.oid,owner_role.rolname,owner_role.oid
		 from pg_catalog.pg_database d join pg_catalog.pg_roles owner_role on owner_role.oid=d.datdba
		 where d.datname=$1`, name).Scan(&databaseOID, &owner, &ownerOID)
	if errors.Is(err, pgx.ErrNoRows) {
		return adapterutil.VerifyResult(false, fmt.Sprintf("database %q exists", name)), nil
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: verify resource.create: check database %q: %w", name, err)
	}
	if spec.Owner != "" && owner != spec.Owner {
		return adapterutil.VerifyResult(false,
			fmt.Sprintf("database %q is owned by %q, want %q", name, owner, spec.Owner)), nil
	}
	if value, ok := discoverSystemIdentifier(ctx, conn); ok {
		systemIdentifier = value
	}
	verification := adapterutil.VerifyResult(true, fmt.Sprintf("database %q exists", name))
	verification.Observed = map[string]any{
		"database_name": name, "database_oid": databaseOID,
		"database_owner": owner, "database_owner_oid": ownerOID,
		"target_identity": "postgres:system:" + systemIdentifier,
	}
	return verification, nil
}
