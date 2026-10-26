package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана MongoDB adapter.
const (
	stepGrant      = "grant"
	stepRevoke     = "revoke"
	stepCreateUser = "create-user"
	stepDropUser   = "drop-user"
)

// Plan строит детерминированный типизированный план для DesiredChange.
// Descriptions и attributes шагов не содержат секретных значений.
//
// account.disable / account.enable сознательно не поддерживаются: у MongoDB
// нет нативного отключения пользователя (см. doc-комментарий пакета), и
// adapter не объявляет соответствующие capabilities.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		return planAccess(change)
	case adapter.ChangeRolePolicyApply, adapter.ChangeRolePolicyVerify:
		return a.planMongoRolePolicy(ctx, change)
	case adapter.ChangeAccountCreate:
		return a.planAccountCreate(ctx, change)
	case adapter.ChangeAccountDelete:
		return planAccountDelete(change)
	default:
		return nil, fmt.Errorf("mongodb: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// planAccess строит план grant/revoke роли пользователю. Роль и её database
// извлекаются из permission external id ("role:<db>.<name>"); account и его
// auth database — из EngineIdentity ("user@authdb"). Идемпотентность
// обеспечивает Apply, поэтому валидации существования на этапе плана нет.
func planAccess(change adapter.DesiredChange) (*adapter.Plan, error) {
	op := string(change.Kind)
	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", op, err)
	}
	roleDB, roleName, err := parseRolePermission(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan %s: %w", op, err)
	}

	kind := stepGrant
	verb := "grant"
	if change.Kind == adapter.ChangeRevoke {
		kind = stepRevoke
		verb = "revoke"
	}
	desc := fmt.Sprintf("%s role %q on db %q %s user %q on db %q",
		verb, roleName, roleDB, grantPreposition(change.Kind), user, authDB)
	return adapterutil.SingleStepPlan(change, kind, desc, map[string]any{
		"user":    user,
		"auth_db": authDB,
		"role":    roleName,
		"role_db": roleDB,
	}), nil
}

// grantPreposition возвращает предлог для человекочитаемого описания.
func grantPreposition(kind adapter.ChangeKind) string {
	if kind == adapter.ChangeRevoke {
		return "from"
	}
	return "to"
}

// planAccountCreate строит план создания SCRAM-аккаунта. Пароль обязателен
// (MongoDB SCRAM-пользователь не может существовать без него) и берётся из
// change.Credential; в план он не попадает — только факт его наличия.
// Пользователь не должен существовать: existing identity отклоняется здесь, до
// резервирования credential (см. adapterutil.IdentityConflict).
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan account.create: %w", err)
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("mongodb: plan account.create: password credential is required")
	}
	client, err := a.connect(ctx, change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan account.create: %w", err)
	}
	defer disconnect(client)
	if _, found, err := fetchUser(ctx, client, user, authDB); err != nil {
		return nil, fmt.Errorf("mongodb: plan account.create: %w", err)
	} else if found {
		return nil, fmt.Errorf("mongodb: plan account.create: %w",
			adapterutil.IdentityConflict("user", change.Account.EngineIdentity))
	}
	return adapterutil.SingleStepPlan(change, stepCreateUser,
		fmt.Sprintf("create user %q on db %q and set its password", user, authDB),
		map[string]any{
			"user":          user,
			"auth_db":       authDB,
			"with_password": true,
		}), nil
}

// planAccountDelete строит план удаления пользователя.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mongodb: plan account.delete: %w", err)
	}
	return adapterutil.SingleStepPlan(change, stepDropUser,
		fmt.Sprintf("drop user %q on db %q; its role assignments disappear with it", user, authDB),
		map[string]any{
			"user":    user,
			"auth_db": authDB,
		}), nil
}

// Apply применяет план через один клиент. Каждый шаг идемпотентен: если
// состояние уже целевое — StepSkipped. Ошибка шага помечает его StepFailed
// (текст без секретов), оставшиеся шаги получают StepUnknown и не выполняются.
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if plan.Change.Kind == adapter.ChangeRolePolicyApply {
		return a.applyMongoRolePolicy(ctx, plan)
	}
	client, err := a.connect(ctx, plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: apply %s: %w", plan.Change.Kind, err)
	}
	defer disconnect(client)

	return adapterutil.ApplySteps(ctx, plan, client, applyStep), nil
}

// applyStep выполняет один шаг плана.
func applyStep(ctx context.Context, client *mongo.Client, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrant:
		return applyGrant(ctx, client, change)
	case stepRevoke:
		return applyRevoke(ctx, client, change)
	case stepCreateUser:
		return applyCreateUser(ctx, client, change)
	case stepDropUser:
		return applyDropUser(ctx, client, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyGrant назначает роль пользователю; уже назначенная роль — StepSkipped.
func applyGrant(ctx context.Context, client *mongo.Client, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user, authDB, roleDB, roleName, err := accessTargets(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	u, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepFailed, fmt.Errorf("user %q on db %q: %w", user, authDB, adapter.ErrNotFound)
	}
	if userHasRole(u, roleName, roleDB) {
		return adapter.StepSkipped, nil
	}
	cmd := bson.D{
		{Key: "grantRolesToUser", Value: user},
		{Key: "roles", Value: bson.A{roleRef{Role: roleName, DB: roleDB}}},
	}
	if err := runCommand(ctx, client, authDB, cmd); err != nil {
		return adapter.StepFailed, fmt.Errorf("grant role %q on db %q to user %q on db %q: %w",
			roleName, roleDB, user, authDB, err)
	}
	return adapter.StepApplied, nil
}

// applyRevoke снимает роль с пользователя; отсутствующая роль или пользователь
// — StepSkipped.
func applyRevoke(ctx context.Context, client *mongo.Client, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user, authDB, roleDB, roleName, err := accessTargets(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	u, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found || !userHasRole(u, roleName, roleDB) {
		return adapter.StepSkipped, nil
	}
	cmd := bson.D{
		{Key: "revokeRolesFromUser", Value: user},
		{Key: "roles", Value: bson.A{roleRef{Role: roleName, DB: roleDB}}},
	}
	if err := runCommand(ctx, client, authDB, cmd); err != nil {
		return adapter.StepFailed, fmt.Errorf("revoke role %q on db %q from user %q on db %q: %w",
			roleName, roleDB, user, authDB, err)
	}
	return adapter.StepApplied, nil
}

// applyCreateUser создаёт SCRAM-пользователя без ролей (роли назначаются
// отдельными grant). Существующий пользователь — не «уже сделано», а
// ErrExternalIdentityConflict: Plan видел его отсутствие, значит учётку создал
// кто-то другой между Plan и Apply (см. adapterutil.IdentityConflict). Пароль
// передаётся в команде createUser и нигде не логируется; ошибка команды не
// содержит секрета.
func applyCreateUser(ctx context.Context, client *mongo.Client, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("password credential is required to create a user")
	}
	_, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return adapter.StepFailed, err
	}
	if found {
		return adapter.StepFailed, adapterutil.IdentityConflict("user", change.Account.EngineIdentity)
	}
	cmd := bson.D{
		{Key: "createUser", Value: user},
		{Key: "pwd", Value: string(change.Credential.Secret)},
		{Key: "roles", Value: bson.A{}},
	}
	if err := runCommand(ctx, client, authDB, cmd); err != nil {
		return adapter.StepFailed, fmt.Errorf("create user %q on db %q: %w", user, authDB, err)
	}
	return adapter.StepApplied, nil
}

// applyDropUser удаляет пользователя; отсутствующий пользователь — StepSkipped.
func applyDropUser(ctx context.Context, client *mongo.Client, change adapter.DesiredChange) (adapter.StepStatus, error) {
	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return adapter.StepFailed, err
	}
	_, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !found {
		return adapter.StepSkipped, nil
	}
	if err := runCommand(ctx, client, authDB, bson.D{{Key: "dropUser", Value: user}}); err != nil {
		return adapter.StepFailed, fmt.Errorf("drop user %q on db %q: %w", user, authDB, err)
	}
	return adapter.StepApplied, nil
}

// Verify выполняет read-back проверку итогового состояния плана. Details не
// содержат секретов.
func (a *Adapter) Verify(ctx context.Context, plan adapter.Plan) (*adapter.Verification, error) {
	change := plan.Change
	if change.Kind == adapter.ChangeRolePolicyApply || change.Kind == adapter.ChangeRolePolicyVerify {
		return a.verifyMongoRolePolicy(ctx, plan)
	}
	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke,
		adapter.ChangeAccountCreate, adapter.ChangeAccountDelete:
	default:
		return nil, fmt.Errorf("mongodb: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	client, err := a.connect(ctx, change.Connection)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify %s: %w", change.Kind, err)
	}
	defer disconnect(client)

	user, authDB, err := parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify %s: %w", change.Kind, err)
	}
	u, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return nil, fmt.Errorf("mongodb: verify %s: %w", change.Kind, err)
	}

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		roleDB, roleName, err := parseRolePermission(change.Permission)
		if err != nil {
			return nil, fmt.Errorf("mongodb: verify %s: %w", change.Kind, err)
		}
		has := found && userHasRole(u, roleName, roleDB)
		what := fmt.Sprintf("role %q on db %q assigned to user %q on db %q", roleName, roleDB, user, authDB)
		if change.Kind == adapter.ChangeGrant {
			return adapterutil.VerifyResult(has, what), nil
		}
		return adapterutil.VerifyResult(!has, "no "+what), nil
	case adapter.ChangeAccountCreate:
		return adapterutil.VerifyResult(found, fmt.Sprintf("user %q on db %q exists", user, authDB)), nil
	default: // adapter.ChangeAccountDelete
		return adapterutil.VerifyResult(!found, fmt.Sprintf("user %q on db %q absent", user, authDB)), nil
	}
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32).
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего пользователя через updateUser.
// Пароль не попадает в логи и тексты ошибок. Возвращает adapter.ErrNotFound,
// если пользователя нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	user, authDB, err := parseEngineIdentity(account.EngineIdentity)
	if err != nil {
		return fmt.Errorf("mongodb: rotate credential: %w", err)
	}
	if len(credential.Secret) == 0 {
		return errors.New("mongodb: rotate credential: credential secret is empty")
	}

	client, err := a.connect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("mongodb: rotate credential: %w", err)
	}
	defer disconnect(client)

	_, found, err := fetchUser(ctx, client, user, authDB)
	if err != nil {
		return fmt.Errorf("mongodb: rotate credential: %w", err)
	}
	if !found {
		return fmt.Errorf("mongodb: rotate credential: user %q on db %q: %w", user, authDB, adapter.ErrNotFound)
	}
	cmd := bson.D{
		{Key: "updateUser", Value: user},
		{Key: "pwd", Value: string(credential.Secret)},
	}
	if err := runCommand(ctx, client, authDB, cmd); err != nil {
		return fmt.Errorf("mongodb: rotate credential: update user %q on db %q: %w", user, authDB, err)
	}
	return nil
}

// accessTargets извлекает (user, authDB, roleDB, roleName) для grant/revoke.
func accessTargets(change adapter.DesiredChange) (user, authDB, roleDB, roleName string, err error) {
	user, authDB, err = parseEngineIdentity(change.Account.EngineIdentity)
	if err != nil {
		return "", "", "", "", err
	}
	roleDB, roleName, err = parseRolePermission(change.Permission)
	if err != nil {
		return "", "", "", "", err
	}
	return user, authDB, roleDB, roleName, nil
}

// fetchUser читает пользователя из его auth database через usersInfo.
// found=false, если пользователя нет.
func fetchUser(ctx context.Context, client *mongo.Client, user, authDB string) (userInfo, bool, error) {
	var result struct {
		Users []userInfo `bson:"users"`
	}
	cmd := bson.D{{Key: "usersInfo", Value: user}}
	if err := client.Database(authDB).RunCommand(ctx, cmd).Decode(&result); err != nil {
		return userInfo{}, false, fmt.Errorf("read user %q on db %q: %w", user, authDB, err)
	}
	if len(result.Users) == 0 {
		return userInfo{}, false, nil
	}
	return result.Users[0], true, nil
}

// userHasRole сообщает, назначена ли пользователю роль roleName на database
// roleDB.
func userHasRole(u userInfo, roleName, roleDB string) bool {
	for _, r := range u.Roles {
		if r.Role == roleName && r.DB == roleDB {
			return true
		}
	}
	return false
}

// runCommand выполняет admin/DB-команду на указанной базе и возвращает ошибку
// её выполнения. Тело команды нигде не логируется.
func runCommand(ctx context.Context, client *mongo.Client, database string, cmd bson.D) error {
	return client.Database(database).RunCommand(ctx, cmd).Err()
}

// parseEngineIdentity разбирает EngineIdentity "user@authdb" на пользователя и
// его auth database. Разделителем считается ПОСЛЕДНИЙ "@": имя пользователя
// может содержать "@" (например, email-подобные $external-логины), а имя базы
// — нет.
func parseEngineIdentity(identity string) (user, authDB string, err error) {
	at := strings.LastIndex(identity, "@")
	if at <= 0 || at == len(identity)-1 {
		return "", "", fmt.Errorf("engine identity %q is not in \"user@authdb\" form", identity)
	}
	return identity[:at], identity[at+1:], nil
}

// parseRolePermission разбирает permission external id "role:<db>.<name>" на
// database роли и имя роли. Разделителем базы и имени считается ПЕРВАЯ "."
// (имя базы MongoDB не содержит "."), поэтому имя роли может её содержать.
func parseRolePermission(permission string) (roleDB, roleName string, err error) {
	rest, ok := strings.CutPrefix(permission, "role:")
	if !ok || rest == "" {
		return "", "", fmt.Errorf("permission %q is not a role permission (want \"role:<db>.<name>\")", permission)
	}
	db, name, found := strings.Cut(rest, ".")
	if !found || db == "" || name == "" {
		return "", "", fmt.Errorf("permission %q is not a role permission (want \"role:<db>.<name>\")", permission)
	}
	return db, name, nil
}
