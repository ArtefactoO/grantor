package redis

// Доказательство владения существующим паролем ACL-пользователя
// (adapter.CredentialProver). Контракт используется adopt-режимом
// verify_password: grantor принимает существующую учётную запись под
// управление, ПОДТВЕРДИВ её текущий пароль, и ничего в Redis не меняет.
//
// Redis для этого удобен: AUTH <user> <pass> аутентифицирует ровно указанного
// пользователя, поэтому подмены identity, как при pg_hba trust, здесь нет.
// Опасность другая — пользователь с флагом nopass принимает ЛЮБОЙ пароль, и
// без отрицательной пробы такой аккаунт «подтвердил» бы что угодно. Поэтому
// проба всегда двойная: supplied password обязан пройти, случайный — обязан
// быть отвергнут.
//
// Классификация ответа на пробу тоньше, чем «ошибка/не ошибка»:
//   - nil — команда прошла, аутентификация состоялась;
//   - NOPERM — команда запрещена ACL, но АУТЕНТИФИКАЦИЯ УЖЕ ПРОШЛА: у
//     ограниченного пользователя (например, только +@read) PING и ACL WHOAMI
//     запрещены, и считать это отказом пароля было бы неверно;
//   - WRONGPASS — пароль (или пара username/password) отвергнут; тот же ответ
//     Redis даёт для выключенного пользователя (ACL SETUSER <name> off), и это
//     сознательно трактуется как отказ: доказать пароль выключенной учётки
//     нельзя, а adopt на ней не должен «проходить наполовину»;
//   - прочее — недоступность target (повторяемая ошибка, не отказ пароля).

import (
	"context"
	"errors"
	"fmt"

	goredis "github.com/redis/go-redis/v9"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
)

var _ adapter.CredentialProver = (*Adapter)(nil)

// negativeProbePasswordLength — длина случайного пароля отрицательной пробы.
const negativeProbePasswordLength = 32

// ProveCredential проверяет, что Redis принимает supplied password именно для
// указанного ACL-пользователя, и что заведомо неверный случайный password тот
// же пользователь отвергает. Целевая система не изменяется: выполняются только
// AUTH (внутри установки соединения) и read-only ACL WHOAMI.
func (a *Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection,
	account adapter.Account, credential adapter.Credential) error {
	if cfg.AuthMode == "none" {
		return errors.New("redis: authentication_disabled: credential proof is unavailable")
	}
	name := account.EngineIdentity
	if name == "" || len(credential.Secret) == 0 {
		return errors.New("redis: prove credential: account identity and password are required")
	}
	if name == defaultUserName {
		// default — bootstrap-поверхность администратора и не managed (см.
		// doc-комментарий пакета): доказывать его пароль незачем.
		return fmt.Errorf("redis: prove credential: user %q is not managed by grantor", defaultUserName)
	}
	// Credential, выписанный на другое имя, доказывать нечего: расхождение
	// видно ещё до сети, и трогать target ради заведомого отказа не нужно.
	if credential.Username != "" && credential.Username != name {
		return fmt.Errorf("redis: prove credential for user %q: credential belongs to another identity: %w",
			name, adapter.ErrExternalIdentityConflict)
	}

	accepted, identity, err := a.probeAuth(ctx, cfg, name, credential.Secret)
	if err != nil {
		return fmt.Errorf("redis: prove credential for user %q: target unavailable", name)
	}
	if !accepted {
		return fmt.Errorf("redis: prove credential for user %q: %w", name, adapter.ErrExternalIdentityConflict)
	}
	// identity непусто только когда ACL WHOAMI разрешён пользователю; имена
	// пользователей Redis точные, поэтому расхождение означает подмену.
	if identity != "" && identity != name {
		return fmt.Errorf("redis: prove credential for user %q: authenticated as another identity: %w",
			name, adapter.ErrExternalIdentityConflict)
	}

	wrong, err := adapterutil.RandomPassword(negativeProbePasswordLength)
	if err != nil {
		return fmt.Errorf("redis: prove credential for user %q: generate negative probe: %w", name, err)
	}
	defer clear(wrong)
	acceptedWrong, _, err := a.probeAuth(ctx, cfg, name, wrong)
	if err != nil {
		return fmt.Errorf("redis: prove credential for user %q: negative probe: target unavailable", name)
	}
	if acceptedWrong {
		// Пользователь с nopass (или сервер без проверки пароля) принимает
		// любое значение: подтвердить конкретный пароль здесь невозможно.
		return fmt.Errorf("redis: prove credential for user %q: target accepts an unrelated password: %w",
			name, adapter.ErrCredentialProofUnsupported)
	}
	return nil
}

// probeAuth открывает короткоживущее соединение от имени name/secret и
// сообщает, приняла ли аутентификацию целевая система. identity заполняется
// результатом ACL WHOAMI, если команда пользователю разрешена (иначе пусто —
// это не отказ). Ошибка означает недоступность target, а не отказ пароля.
func (a *Adapter) probeAuth(ctx context.Context, cfg adapter.Connection, name string, secret []byte) (bool, string, error) {
	probe := cfg
	probe.AuthMode = "password"
	probe.AdminCredential = adapter.Credential{Kind: "password", Username: name, Secret: secret}
	client, err := a.newClient(probe)
	if err != nil {
		return false, "", err
	}
	defer client.close()

	switch err := client.ping(ctx); {
	case err == nil:
	case goredis.HasErrorPrefix(err, "WRONGPASS"), goredis.HasErrorPrefix(err, "NOAUTH"):
		return false, "", nil
	case goredis.HasErrorPrefix(err, "NOPERM"):
		// Аутентификация прошла, PING запрещён правилами пользователя.
		return true, "", nil
	default:
		return false, "", err
	}

	me, err := client.whoAmI(ctx)
	switch {
	case err == nil:
		return true, me, nil
	case goredis.HasErrorPrefix(err, "NOPERM"):
		return true, "", nil
	default:
		return true, "", err
	}
}
