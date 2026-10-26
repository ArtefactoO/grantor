// Kubernetes-аутентификация клиента Vault (миграция с bundled dev-Vault на
// центральный Vault организации): вместо статического токена процесс
// логинится JWT'ом своего ServiceAccount в auth mount Kubernetes
// (POST /v1/auth/<mount>/login) и фоново сопровождает выданный client token —
// продлевает его на ~2/3 lease через auth/token/renew-self, а при отказе
// продления (включая 403 на отозванном токене) перелогинивается свежим JWT:
// projected token ротируется kubelet'ом, поэтому файл перечитывается при
// каждом login.
//
// Инвариант безопасности (раздел 24 архитектуры): ни JWT, ни client token не
// логируются и не попадают в тексты ошибок — ошибки несут только auth mount,
// роль и путь к файлу JWT.

package vault

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
)

const (
	// renewFraction — доля lease, после которой токен продлевается (~2/3).
	renewFraction = 2.0 / 3.0
	// renewJitter — относительный джиттер задержек цикла (±10%), чтобы
	// реплики не продлевали токены синхронно.
	renewJitter = 0.1
	// loginRetryDelay — базовая пауза перед повтором неудавшегося re-login.
	loginRetryDelay = 5 * time.Second
)

// kubernetesAuth — состояние Kubernetes-аутентификации клиента: параметры
// login и фоновое сопровождение токена. Смена токена выполняется через
// api.Client.SetToken, который сериализует доступ RWMutex'ом, поэтому
// конкурентные KV-запросы во время swap безопасны.
type kubernetesAuth struct {
	api      *api.Client
	authPath string
	role     string
	jwtPath  string
	log      *slog.Logger
}

// login читает свежий JWT ServiceAccount и обменивает его на client token
// через auth mount. Возвращает renewable и lease выданного токена. JWT и
// токен в ошибки не попадают.
func (a *kubernetesAuth) login(ctx context.Context) (renewable bool, lease time.Duration, err error) {
	jwt, err := os.ReadFile(a.jwtPath)
	if err != nil {
		return false, 0, fmt.Errorf("vault: kubernetes login: read service account jwt: %w", err)
	}
	secret, err := a.api.Logical().WriteWithContext(ctx, "auth/"+a.authPath+"/login", map[string]any{
		"role": a.role,
		"jwt":  strings.TrimSpace(string(jwt)),
	})
	clear(jwt)
	if err != nil {
		return false, 0, fmt.Errorf("vault: kubernetes login (auth mount %q, role %q): %w",
			a.authPath, a.role, err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return false, 0, fmt.Errorf("vault: kubernetes login (auth mount %q): response carries no client token",
			a.authPath)
	}
	// Thread-safe swap: SetToken защищён mutex'ом api.Client, уже идущие
	// запросы дочитывают старый токен (он остаётся валиден до истечения).
	a.api.SetToken(secret.Auth.ClientToken)
	return secret.Auth.Renewable, time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// renewSelf продлевает текущий client token через auth/token/renew-self и
// возвращает обновлённые renewable и lease.
func (a *kubernetesAuth) renewSelf(ctx context.Context) (renewable bool, lease time.Duration, err error) {
	secret, err := a.api.Auth().Token().RenewSelfWithContext(ctx, 0)
	if err != nil {
		return false, 0, fmt.Errorf("vault: renew token: %w", err)
	}
	if secret == nil || secret.Auth == nil {
		return false, 0, fmt.Errorf("vault: renew token: response carries no auth data")
	}
	return secret.Auth.Renewable, time.Duration(secret.Auth.LeaseDuration) * time.Second, nil
}

// renewLoop фоново сопровождает client token до отмены ctx: спит ~2/3 lease
// (с джиттером), затем продлевает токен; отказ продления или non-renewable
// токен ведут к re-login свежим JWT. Неудавшийся re-login повторяется через
// loginRetryDelay — старый токен при этом продолжает использоваться, пока
// валиден. Тот же паттерн фонового цикла, что у планировщика обслуживания
// (internal/core/maintenance.Scheduler): select по ctx.Done и таймеру.
func (a *kubernetesAuth) renewLoop(ctx context.Context, renewable bool, lease time.Duration) {
	a.log.Info("vault: kubernetes token renewal started",
		"auth_mount", a.authPath, "role", a.role, "lease", lease)
	next := withJitter(time.Duration(float64(lease) * renewFraction))
	for {
		if !sleepCtx(ctx, next) {
			a.log.Info("vault: kubernetes token renewal stopped")
			return
		}
		if renewable {
			var err error
			renewable, lease, err = a.renewSelf(ctx)
			if err == nil {
				next = withJitter(time.Duration(float64(lease) * renewFraction))
				continue
			}
			if ctx.Err() != nil {
				return
			}
			// Отказ продления (истёкший/отозванный токен, 403, сетевой сбой):
			// перелогиниваемся свежим JWT. Текст ошибки секретов не несёт.
			a.log.Warn("vault: token renewal failed; re-login with a fresh service account jwt",
				"error", err)
		}
		var err error
		renewable, lease, err = a.login(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("vault: kubernetes re-login failed; will retry", "error", err)
			next = withJitter(loginRetryDelay)
			continue
		}
		next = withJitter(time.Duration(float64(lease) * renewFraction))
	}
}

// withJitter добавляет к задержке случайный джиттер ±renewJitter.
func withJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return loginRetryDelay
	}
	factor := 1 - renewJitter + 2*renewJitter*rand.Float64()
	return time.Duration(float64(d) * factor)
}

// sleepCtx ждёт d или отмены ctx; false — ctx отменён.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
