package redis

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

// Виды шагов плана Redis adapter.
const (
	stepGrantPermission  = "grant-permission"
	stepRevokePermission = "revoke-permission"
	stepCreateUser       = "create-user"
	stepDisableUser      = "disable-user"
	stepEnableUser       = "enable-user"
	stepDeleteUser       = "delete-user"
)

// Plan строит детерминированный типизированный план для DesiredChange.
// Descriptions и attributes шагов не содержат секретных значений. Валидации
// существования на этапе плана нет: её выполняет идемпотентный Apply.
func (a *Adapter) Plan(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	if err := requireAuthenticatedMutation(change.Connection); err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("redis: plan %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}
}

// checkManagedUserName валидирует engine identity: имя непусто и не default
// (bootstrap-пользователь не managed, см. doc-комментарий пакета).
func checkManagedUserName(name string) error {
	if name == "" {
		return errors.New("account engine identity is empty")
	}
	if name == defaultUserName {
		return fmt.Errorf("the %q user is the bootstrap admin surface and is not managed by grantor", defaultUserName)
	}
	return nil
}

// planAccess строит план grant/revoke permission bundle. Если ядро передало
// desired-состояние (change.AccountPermissions), план называет итоговый набор
// bundles и отклоняет непредставимый набор (admin вместе с read/write) здесь
// же: внятная ошибка до применения лучше отказа в середине Apply.
func planAccess(change adapter.DesiredChange) (*adapter.Plan, error) {
	user := change.Account.EngineIdentity
	if err := checkManagedUserName(user); err != nil {
		return nil, fmt.Errorf("redis: plan %s: %w", change.Kind, err)
	}
	bundle, err := parseBundle(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("redis: plan %s: %w", change.Kind, err)
	}
	rules := strings.Join(bundleRules[bundle], " ")
	attrs := map[string]any{"user": user, "bundle": bundle, "rules": rules}

	desired, hasDesired, err := desiredBundles(change)
	if err != nil {
		return nil, fmt.Errorf("redis: plan %s: %w", change.Kind, err)
	}
	remaining := "rebuilt from the desired state of grantor"
	if hasDesired {
		attrs["target_bundles"] = strings.Join(desired, " ")
		if len(desired) == 0 {
			remaining = "no bundles remain"
		} else {
			remaining = "remaining bundles: " + strings.Join(desired, ", ")
		}
	}
	if change.Kind == adapter.ChangeRevoke {
		return adapterutil.SingleStepPlan(change, stepRevokePermission,
			fmt.Sprintf("revoke bundle %q (%s) from user %q; %s", bundle, rules, user, remaining),
			attrs), nil
	}
	return adapterutil.SingleStepPlan(change, stepGrantPermission,
		fmt.Sprintf("grant bundle %q (%s) to user %q", bundle, rules, user), attrs), nil
}

// desiredBundles извлекает целевой набор bundles из desired-состояния ядра
// (change.AccountPermissions) и проверяет его согласованность с изменением:
// grant обязан содержать выдаваемый bundle, revoke — не содержать
// отзываемого. Второе значение — было ли desired-состояние передано вообще
// (nil означает «ядро его не передало», см. adapter.DesiredChange).
//
// Неназначаемые observed permissions ("acl:...") в desired-наборе
// игнорируются: они описывают unmanaged-правила, а такой пользователь
// отсекается проверкой managed-формы раньше, чем набор будет применён.
func desiredBundles(change adapter.DesiredChange) ([]string, bool, error) {
	if change.AccountPermissions == nil {
		return nil, false, nil
	}
	var bundles []string
	for _, p := range change.AccountPermissions {
		if _, ok := bundleRules[p]; ok {
			bundles = append(bundles, p)
		}
	}
	bundles = normalizeBundles(bundles)
	if err := checkBundleSet(bundles); err != nil {
		return nil, false, err
	}
	bundle, err := parseBundle(change.Permission)
	if err != nil {
		return nil, false, err
	}
	switch {
	case change.Kind == adapter.ChangeRevoke && slices.Contains(bundles, bundle):
		return nil, false, fmt.Errorf(
			"desired account permissions still contain the revoked bundle %q", bundle)
	case change.Kind == adapter.ChangeGrant && !slices.Contains(bundles, bundle):
		return nil, false, fmt.Errorf(
			"desired account permissions do not contain the granted bundle %q", bundle)
	}
	return bundles, true, nil
}

// planAccountCreate строит план создания ACL-пользователя. Пароль обязателен
// и берётся из change.Credential; в план он не попадает — только факт его
// наличия. Пользователь не должен существовать: existing identity отклоняется
// здесь, до резервирования credential (см. adapterutil.IdentityConflict).
func (a *Adapter) planAccountCreate(ctx context.Context, change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if err := checkManagedUserName(name); err != nil {
		return nil, fmt.Errorf("redis: plan account.create: %w", err)
	}
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return nil, errors.New("redis: plan account.create: password credential is required")
	}
	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("redis: plan account.create: %w", err)
	}
	defer client.close()
	switch _, err := client.getUser(ctx, name); {
	case err == nil:
		return nil, fmt.Errorf("redis: plan account.create: %w", adapterutil.IdentityConflict("user", name))
	case !errors.Is(err, adapter.ErrNotFound):
		return nil, fmt.Errorf("redis: plan account.create: %w", err)
	}
	return accountCreatePlan(change), nil
}

// accountCreatePlan собирает сам план создания — без обращения к target.
// Отделено от planAccountCreate, чтобы форму плана (шаг, атрибуты, отсутствие
// секрета в description) можно было проверять без поднятого Redis.
func accountCreatePlan(change adapter.DesiredChange) *adapter.Plan {
	name := change.Account.EngineIdentity
	return adapterutil.SingleStepPlan(change, stepCreateUser,
		fmt.Sprintf("create ACL user %q (enabled, with password, no permissions)", name),
		map[string]any{"user": name, "with_password": true})
}

// planDisableEnable строит план disable/enable через нативный флаг ACL
// SETUSER off/on: правила и пароли сохраняются, блокируется аутентификация.
func planDisableEnable(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if err := checkManagedUserName(name); err != nil {
		return nil, fmt.Errorf("redis: plan %s: %w", change.Kind, err)
	}
	if change.Kind == adapter.ChangeAccountDisable {
		return adapterutil.SingleStepPlan(change, stepDisableUser,
			fmt.Sprintf("disable user %q: ACL SETUSER off (authentication blocked, rules and passwords kept)", name),
			map[string]any{"user": name, "flag": "off"}), nil
	}
	return adapterutil.SingleStepPlan(change, stepEnableUser,
		fmt.Sprintf("enable user %q: ACL SETUSER on", name),
		map[string]any{"user": name, "flag": "on"}), nil
}

// planAccountDelete строит план удаления пользователя: ACL DELUSER удаляет
// учётку вместе с её правилами.
func planAccountDelete(change adapter.DesiredChange) (*adapter.Plan, error) {
	name := change.Account.EngineIdentity
	if err := checkManagedUserName(name); err != nil {
		return nil, fmt.Errorf("redis: plan account.delete: %w", err)
	}
	return adapterutil.SingleStepPlan(change, stepDeleteUser,
		fmt.Sprintf("delete ACL user %q with all its rules", name),
		map[string]any{"user": name}), nil
}

// Apply применяет план через один admin-клиент. Каждый шаг идемпотентен:
// если состояние уже целевое — StepSkipped. Ошибка шага помечает его
// StepFailed (текст без секретов), оставшиеся шаги получают StepUnknown и не
// выполняются. После успешно применённых шагов ACL best-effort сохраняется в
// aclfile (см. persistACL).
func (a *Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	if err := requireAuthenticatedMutation(plan.Change.Connection); err != nil {
		return nil, err
	}
	client, err := a.newClient(plan.Change.Connection)
	if err != nil {
		return nil, fmt.Errorf("redis: apply %s: %w", plan.Change.Kind, err)
	}
	defer client.close()

	res := adapterutil.ApplySteps(ctx, plan, client, applyStep)
	// Хотя бы один StepApplied эквивалентен прежнему флагу applied (шаг с
	// ошибкой помечается StepFailed): тогда ACL best-effort сохраняется в
	// aclfile.
	for _, sr := range res.Steps {
		if sr.Status == adapter.StepApplied {
			client.persistACL(ctx)
			break
		}
	}
	return res, nil
}

// applyStep выполняет один шаг плана.
func applyStep(ctx context.Context, c *adminClient, change adapter.DesiredChange, step adapter.PlanStep) (adapter.StepStatus, error) {
	switch step.Kind {
	case stepGrantPermission:
		return applyAccess(ctx, c, change, false)
	case stepRevokePermission:
		return applyAccess(ctx, c, change, true)
	case stepCreateUser:
		return applyCreateUser(ctx, c, change)
	case stepDisableUser:
		return applyFlag(ctx, c, change, false)
	case stepEnableUser:
		return applyFlag(ctx, c, change, true)
	case stepDeleteUser:
		return applyDeleteUser(ctx, c, change)
	default:
		return adapter.StepFailed, fmt.Errorf("unknown plan step kind %q", step.Kind)
	}
}

// applyAccess выполняет grant/revoke bundle: читает текущие правила
// пользователя, вычисляет целевой набор bundles и перестраивает правила одной
// атомарной командой ACL SETUSER (см. rulesFor). Уже целевое состояние —
// StepSkipped. Пользователь с unmanaged-правилами — ошибка: grantor не
// перезаписывает чужие правила.
//
// Целевой набор берётся из desired-состояния ядра (change.AccountPermissions),
// а не реконструируется из текущего ACL: ACL Redis — единый набор правил, и
// реконструкция «наблюдаемое ± изменяемый bundle» переносит в результат любую
// потерю или расхождение состояния движка. Побочный эффект желаемый: любое
// изменение доступа приводит правила аккаунта к desired-состоянию целиком,
// поэтому расхождение чинится штатной операцией, а не пересозданием binding.
// Если ядро desired-состояние не передало, адаптер деградирует до прежней
// реконструкции.
func applyAccess(ctx context.Context, c *adminClient, change adapter.DesiredChange, revoke bool) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	bundle, err := parseBundle(change.Permission)
	if err != nil {
		return adapter.StepFailed, err
	}
	u, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	observed, managed, err := c.matchBundles(ctx, u)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !managed {
		return adapter.StepFailed, fmt.Errorf(
			"user %q has ACL rules not managed by grantor; refusing to rewrite them", name)
	}

	target, hasDesired, err := desiredBundles(change)
	if err != nil {
		return adapter.StepFailed, err
	}
	if !hasDesired {
		target = normalizeBundles(observed)
		if revoke {
			target = slices.DeleteFunc(target, func(b string) bool { return b == bundle })
		} else if !slices.Contains(target, bundle) {
			target = normalizeBundles(append(target, bundle))
		}
		if err := checkBundleSet(target); err != nil {
			return adapter.StepFailed, err
		}
	}
	if slices.Equal(normalizeBundles(observed), target) {
		return adapter.StepSkipped, nil
	}

	rules, err := rulesFor(target)
	if err != nil {
		return adapter.StepFailed, err
	}
	if err := c.setUser(ctx, name, rules...); err != nil {
		op := "grant"
		if revoke {
			op = "revoke"
		}
		return adapter.StepFailed, fmt.Errorf("%s %s for user %q: %w", op, bundle, name, redactACLError(err, ""))
	}
	return adapter.StepApplied, nil
}

// applyCreateUser создаёт включённого пользователя с паролем и без прав.
// Существующий пользователь — не «уже сделано», а ErrExternalIdentityConflict:
// Plan видел его отсутствие, значит учётку создал кто-то другой между Plan и
// Apply (см. adapterutil.IdentityConflict). Пароль передаётся только внутри
// команды и не попадает в текст ошибки (см. redactACLError).
func applyCreateUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if !adapterutil.HasPasswordSecret(change.Credential) {
		return adapter.StepFailed, errors.New("password credential is required to create a user")
	}
	if _, err := c.getUser(ctx, name); err == nil {
		return adapter.StepFailed, adapterutil.IdentityConflict("user", name)
	} else if !errors.Is(err, adapter.ErrNotFound) {
		return adapter.StepFailed, err
	}
	pw := string(change.Credential.Secret)
	// Redis 6.2 defaults new users to all Pub/Sub channels. Canonical empty
	// permissions must be explicit before discovery or grant interprets them.
	if err := c.setUser(ctx, name, "on", ">"+pw, "nocommands", "resetkeys", "resetchannels"); err != nil {
		return adapter.StepFailed, fmt.Errorf("create user %q: %w", name, redactACLError(err, pw))
	}
	return adapter.StepApplied, nil
}

// applyFlag переключает нативный флаг on/off. Уже целевое состояние —
// StepSkipped; отсутствующий пользователь — ошибка adapter.ErrNotFound.
func applyFlag(ctx context.Context, c *adminClient, change adapter.DesiredChange, enable bool) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	u, err := c.getUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, err
	}
	if u.enabled == enable {
		return adapter.StepSkipped, nil
	}
	flag := "off"
	if enable {
		flag = "on"
	}
	if err := c.setUser(ctx, name, flag); err != nil {
		return adapter.StepFailed, fmt.Errorf("set user %q %s: %w", name, flag, redactACLError(err, ""))
	}
	return adapter.StepApplied, nil
}

// applyDeleteUser удаляет пользователя; ACL DELUSER идемпотентен и возвращает
// число удалённых — 0 означает, что пользователя уже нет (StepSkipped).
func applyDeleteUser(ctx context.Context, c *adminClient, change adapter.DesiredChange) (adapter.StepStatus, error) {
	name := change.Account.EngineIdentity
	if err := checkManagedUserName(name); err != nil {
		return adapter.StepFailed, err
	}
	deleted, err := c.delUser(ctx, name)
	if err != nil {
		return adapter.StepFailed, fmt.Errorf("delete user %q: %w", name, redactACLError(err, ""))
	}
	if deleted == 0 {
		return adapter.StepSkipped, nil
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
		return nil, fmt.Errorf("redis: verify %s: %w", change.Kind, adapter.ErrUnsupportedChange)
	}

	client, err := a.newClient(change.Connection)
	if err != nil {
		return nil, fmt.Errorf("redis: verify %s: %w", change.Kind, err)
	}
	defer client.close()
	name := change.Account.EngineIdentity

	u, err := client.getUser(ctx, name)
	found := err == nil
	if err != nil && !errors.Is(err, adapter.ErrNotFound) {
		return nil, fmt.Errorf("redis: verify %s: %w", change.Kind, err)
	}

	switch change.Kind {
	case adapter.ChangeGrant, adapter.ChangeRevoke:
		if found {
			u, err = client.canonicalLegacyUser(ctx, u)
			if err != nil {
				return nil, fmt.Errorf("redis: verify ACL command metadata: %w", err)
			}
		}
		return verifyAccess(change, name, u, found)
	case adapter.ChangeAccountCreate:
		ok := found && u.passwords > 0
		return adapterutil.VerifyResult(ok, fmt.Sprintf("user %q exists and has a password", name)), nil
	case adapter.ChangeAccountDisable:
		return adapterutil.VerifyResult(found && !u.enabled, fmt.Sprintf("user %q is disabled (flag off)", name)), nil
	case adapter.ChangeAccountEnable:
		return adapterutil.VerifyResult(found && u.enabled, fmt.Sprintf("user %q is enabled (flag on)", name)), nil
	default: // adapter.ChangeAccountDelete
		return adapterutil.VerifyResult(!found, fmt.Sprintf("user %q is absent", name)), nil
	}
}

// verifyAccess проверяет итог grant/revoke. Отсутствия отозванного bundle
// недостаточно: ACL Redis переписывается целиком, поэтому неудачная мутация
// способна снести и остальные права аккаунта, а проверка «нет отозванного»
// такой исход подтвердила бы как успех. Поэтому проверяются три вещи:
//
//   - правила остались managed-формой (перезапись чужими или битыми правилами
//     — не успех);
//   - изменяемый bundle присутствует (grant) или отсутствует (revoke);
//   - если ядро передало desired-состояние — наблюдаемый набор bundles
//     совпадает с ним ровно, то есть остальные права аккаунта уцелели.
func verifyAccess(change adapter.DesiredChange, name string, u aclUser, found bool) (*adapter.Verification, error) {
	bundle, err := parseBundle(change.Permission)
	if err != nil {
		return nil, fmt.Errorf("redis: verify %s: %w", change.Kind, err)
	}
	if !found {
		// Удалённый пользователь доступа не имеет: revoke достигнут, grant нет.
		return adapterutil.VerifyResult(change.Kind == adapter.ChangeRevoke,
			fmt.Sprintf("user %q is absent", name)), nil
	}
	observed, managed := matchBundles(u)
	observed = normalizeBundles(observed)
	has := slices.Contains(observed, bundle)

	want := "no bundle"
	ok := managed && !has
	if change.Kind == adapter.ChangeGrant {
		want = "bundle"
		ok = managed && has
	}
	details := fmt.Sprintf("%s %q for user %q; bundles: %s",
		want, bundle, name, bundleList(observed))

	desired, hasDesired, derr := desiredBundles(change)
	if derr != nil {
		return adapterutil.VerifyResult(false, fmt.Sprintf(
			"desired account permissions for user %q are inconsistent", name)), nil
	}
	if hasDesired {
		if !slices.Equal(observed, desired) {
			ok = false
		}
		details = fmt.Sprintf("%s %q for user %q; bundles: %s (want %s)",
			want, bundle, name, bundleList(observed), bundleList(desired))
	}
	if !managed {
		details = fmt.Sprintf("user %q has ACL rules not managed by grantor", name)
	}
	return adapterutil.VerifyResult(ok, details), nil
}

// bundleList форматирует набор bundles для Details верификации.
func bundleList(bundles []string) string {
	if len(bundles) == 0 {
		return "none"
	}
	return strings.Join(bundles, ", ")
}

// GenerateCredential генерирует криптослучайный пароль из [a-zA-Z0-9] длиной
// policy.Length (по умолчанию 32).
func (a *Adapter) GenerateCredential(_ context.Context, policy adapter.CredentialPolicy) (*adapter.Credential, error) {
	return adapterutil.GenerateCredential(policy, Engine)
}

// RotateCredential меняет пароль существующего пользователя одной атомарной
// командой ACL SETUSER resetpass ><new>: аккаунт не остаётся ни без пароля,
// ни со старым паролем (см. doc-комментарий пакета). Правила и флаг on/off не
// затрагиваются. Пароль не попадает в логи и тексты ошибок. Возвращает
// adapter.ErrNotFound, если пользователя нет.
func (a *Adapter) RotateCredential(ctx context.Context, cfg adapter.Connection, account adapter.Account, credential adapter.Credential) error {
	if err := requireAuthenticatedMutation(cfg); err != nil {
		return err
	}
	name := account.EngineIdentity
	if err := checkManagedUserName(name); err != nil {
		return fmt.Errorf("redis: rotate credential: %w", err)
	}
	if len(credential.Secret) == 0 {
		return errors.New("redis: rotate credential: credential secret is empty")
	}

	client, err := a.newClient(cfg)
	if err != nil {
		return fmt.Errorf("redis: rotate credential: %w", err)
	}
	defer client.close()

	if _, err := client.getUser(ctx, name); err != nil {
		return fmt.Errorf("redis: rotate credential: %w", err)
	}
	pw := string(credential.Secret)
	if err := client.setUser(ctx, name, "resetpass", ">"+pw); err != nil {
		return fmt.Errorf("redis: rotate credential: set password for user %q: %w",
			name, redactACLError(err, pw))
	}
	client.persistACL(ctx)
	return nil
}

// --- Помощники уровня клиента ---

// getUser возвращает разобранного пользователя или adapter.ErrNotFound.
func (c *adminClient) getUser(ctx context.Context, name string) (aclUser, error) {
	users, err := c.aclListUsers(ctx)
	if err != nil {
		return aclUser{}, err
	}
	u, ok := findUser(users, name)
	if !ok {
		return aclUser{}, fmt.Errorf("user %q: %w", name, adapter.ErrNotFound)
	}
	return u, nil
}

// setUser выполняет ACL SETUSER с указанными правилами. Каждое правило
// передаётся отдельным RESP-аргументом, поэтому имена и пароли не требуют
// экранирования.
func (c *adminClient) setUser(ctx context.Context, name string, rules ...string) error {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.rdb.ACLSetUser(reqCtx, name, rules...).Err()
}

// delUser выполняет ACL DELUSER и возвращает число удалённых пользователей.
func (c *adminClient) delUser(ctx context.Context, name string) (int64, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	return c.rdb.ACLDelUser(reqCtx, name).Result()
}

// persistACL best-effort сохраняет ACL в aclfile: если CONFIG GET aclfile
// возвращает непустой путь, выполняется ACL SAVE. Ошибки игнорируются
// (dev/ephemeral-серверы без aclfile — норма); ответственность за
// персистентность — на владельце целевой системы (см. doc-комментарий
// пакета).
func (c *adminClient) persistACL(ctx context.Context) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	cfg, err := c.rdb.ConfigGet(reqCtx, "aclfile").Result()
	if err != nil || cfg["aclfile"] == "" {
		return
	}
	saveCtx, saveCancel := context.WithTimeout(ctx, requestTimeout)
	defer saveCancel()
	_ = c.rdb.Do(saveCtx, "acl", "save").Err()
}

// --- Чистые помощники ---

// parseBundle проверяет, что permission — назначаемый bundle (read, write
// или admin). Observed acl-permissions ("acl:...") не назначаемы и
// отклоняются.
func parseBundle(perm string) (string, error) {
	if _, ok := bundleRules[perm]; !ok {
		return "", fmt.Errorf("permission %q is not an assignable redis permission (want %q, %q, %q or %q)",
			perm, bundleRead, bundleWrite, bundleMonitoring, bundleAdmin)
	}
	return perm, nil
}

// redactACLError возвращает безопасный текст ошибки команды, которая могла
// содержать пароль. Ответ сервера редуцируется до класса ошибки (первого
// токена вроде ERR/NOPERM): Redis цитирует аргументы команды в сообщениях об
// ошибках ACL SETUSER, поэтому оставлять сырой текст нельзя. В остальных
// ошибках (сеть, timeout) секрет, если он вдруг встретился, заменяется на
// "[REDACTED]".
func redactACLError(err error, secretText string) error {
	var rerr goredis.Error
	if errors.As(err, &rerr) {
		return fmt.Errorf("server rejected the command (%s)", errorPrefix(rerr.Error()))
	}
	msg := err.Error()
	if secretText != "" {
		msg = strings.ReplaceAll(msg, secretText, "[REDACTED]")
	}
	return errors.New(msg)
}

// errorPrefix возвращает первый токен сообщения об ошибке Redis — класс
// ошибки (ERR, NOPERM, WRONGPASS...).
func errorPrefix(msg string) string {
	if f := strings.Fields(msg); len(f) > 0 {
		return f[0]
	}
	return "ERR"
}
