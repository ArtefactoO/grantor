// Package credentialcheck обнаруживает пароли, изменённые в обход grantor.
//
// Задача. ProveCredential вызывается только сразу после ротации и в
// connector-restore; фоновой сверки нет. Если секрет переписали руками в
// Vault, «Получить учётные данные» отдаёт пароль, которого в целевой системе
// нет, и ничто об этом не сообщает: дрифт считает bindings и объекты, а не
// валидность пароля. Само расхождение чинится только следующей ротацией.
//
// Метод. Vault KV v2 нумерует версии секрета. При ротации grantor запоминает
// версию, которую реально применил к целевой системе (accounts
// .credential_version, миграция 00017). Прогон сверки читает ТОЛЬКО
// метаданные секрета — vault.Client.Metadata не возвращает секретных данных —
// и сравнивает текущую версию с якорем. Текущая версия больше якоря означает,
// что после последнего применения в секрет кто-то писал мимо grantor.
//
// Чего сверка НЕ делает и почему:
//
//   - не ротирует автоматически. Расхождение может быть намеренным
//     (оператор готовит смену пароля), а самовольная ротация сменила бы
//     пароль в целевой системе и сломала бы то, что этим паролем
//     пользуется. Решение остаётся за человеком;
//   - не подключается к целевым системам. Правку на самом таргете этот
//     детектор не видит: для неё нужен ProveCredential, то есть живое
//     подключение и пароль в памяти для каждого аккаунта. Это отдельная,
//     существенно более дорогая проверка;
//   - не трогает аккаунты без якоря (credential_version = 0): исторические
//     записи и adopt mode=metadata, где пароль grantor никогда не применял.
//     Сравнивать не с чем, а ложный finding хуже отсутствующего.
//
// Устройство прогона зеркалит rediscovery и maintenance: фоновой планировщик
// в worker (scheduler.go, cmd/worker), singleton между репликами через
// PostgreSQL advisory lock.
//
// Порядок внутри прогона важен: кандидаты читаются обычным запросом, затем
// выполняются обращения к Vault, и лишь потом открывается короткая
// транзакция с advisory lock, которая записывает результат. Держать lock
// открытым во время сетевых обращений к Vault нельзя — транзакция жила бы
// столько же, сколько самый медленный ответ Vault. Реплика, не взявшая lock,
// свои результаты выбрасывает: записи идемпотентны, но audit-события
// дублировать незачем.
package credentialcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

const (
	// credentialCheckLockClass и credentialCheckLockObj — фиксированный ключ
	// singleton advisory lock прогона сверки. classid общий с maintenance и
	// rediscovery ("GRAN"), objid свой ("CRED"): прогоны друг друга не
	// блокируют.
	credentialCheckLockClass int32 = 0x4752_414e // "GRAN"
	credentialCheckLockObj   int32 = 0x4352_4544 // "CRED"
)

// Актор audit-событий сверки: сервисный субъект без привязки к человеку,
// по образцу grantor-maintenance и grantor-rediscovery.
const (
	checkActorType = "service"
	checkActorID   = "grantor-credential-check"
)

// auditActionCredentialDiverged — audit action обнаруженного расхождения.
// Пишется только на переходе в расхождение, а не на каждом прогоне: иначе
// одна забытая ручная правка засыпала бы журнал одинаковыми событиями.
const auditActionCredentialDiverged = "security.credential_version_diverged"

// vaultMetadataReader — то, что сверке нужно от Vault: только несекретные
// метаданные. Интерфейс сужен сознательно, чтобы пакет не имел технической
// возможности прочитать пароль.
type vaultMetadataReader interface {
	Metadata(ctx context.Context, path string) (*vault.Metadata, error)
}

// Config — настройки сверки.
type Config struct {
	// Interval — период прогонов планировщика. Значение <= 0 недопустимо для
	// Runner; решение «выключено» принимает cmd/worker по env
	// GRANTOR_CREDENTIAL_CHECK_INTERVAL (0 = планировщик не запускается).
	Interval time.Duration
	// MaxPathsPerRun ограничивает число обращений к Vault за прогон. 0 —
	// без ограничения. Ограничение нужно на больших инсталляциях: прогон не
	// должен превращаться в длинную серию сетевых вызовов.
	MaxPathsPerRun int
}

// Stats — результат одного прогона. Нулевой Stats означает, что прогон либо
// ничего не нашёл, либо был пропущен (advisory lock удерживает другая
// реплика).
type Stats struct {
	// PathsChecked — сколько путей Vault удалось опросить.
	PathsChecked int
	// AccountsChecked — сколько аккаунтов получили свежую наблюдаемую версию.
	AccountsChecked int
	// Diverged — аккаунты, у которых версия в Vault опередила якорь.
	Diverged int
	// NewlyDiverged — из них те, кто разошёлся впервые (по ним написан audit).
	NewlyDiverged int
	// PathsUnavailable — пути, метаданные которых прочитать не удалось.
	// Недоступность Vault не считается расхождением: она ничего не
	// доказывает.
	PathsUnavailable int
}

// IsZero сообщает, что прогон ничего не затронул.
func (s Stats) IsZero() bool {
	return s.PathsChecked == 0 && s.AccountsChecked == 0 && s.Diverged == 0 &&
		s.NewlyDiverged == 0 && s.PathsUnavailable == 0
}

// Runner выполняет прогоны сверки над одним пулом соединений.
type Runner struct {
	pool  *pgxpool.Pool
	vault vaultMetadataReader
	cfg   Config
	audit *audit.Writer
}

// New собирает Runner. Vault обязателен: без него сверять не с чем.
func New(pool *pgxpool.Pool, v vaultMetadataReader, cfg Config) *Runner {
	return &Runner{pool: pool, vault: v, cfg: cfg}
}

// WithAudit включает запись audit-события расхождения и возвращает тот же
// Runner (chained wiring в main). nil-writer оставляет audit выключенным.
func (r *Runner) WithAudit(w *audit.Writer) *Runner {
	r.audit = w
	return r
}

// Interval возвращает период между прогонами.
func (r *Runner) Interval() time.Duration { return r.cfg.Interval }

// candidate — аккаунт, участвующий в сверке.
type candidate struct {
	accountID      uuid.UUID
	connectionID   uuid.UUID
	engineIdentity string
	vaultPath      string
	anchor         int
	// observed — наблюдаемая версия с прошлого прогона; нужна, чтобы отличить
	// новое расхождение от уже известного.
	observed int
}

// RunOnce выполняет один прогон сверки.
func (r *Runner) RunOnce(ctx context.Context) (Stats, error) {
	if r.vault == nil {
		return Stats{}, errors.New("credentialcheck: vault is not configured")
	}

	candidates, err := r.listCandidates(ctx)
	if err != nil {
		return Stats{}, err
	}
	if len(candidates) == 0 {
		return Stats{}, nil
	}

	// Один путь — один запрос метаданных: общий секрет принципала разделяют
	// все его аккаунты в окружении, и опрашивать его по разу на аккаунт было
	// бы кратной лишней нагрузкой на Vault.
	byPath := map[string][]candidate{}
	order := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, seen := byPath[c.vaultPath]; !seen {
			order = append(order, c.vaultPath)
		}
		byPath[c.vaultPath] = append(byPath[c.vaultPath], c)
	}
	if r.cfg.MaxPathsPerRun > 0 && len(order) > r.cfg.MaxPathsPerRun {
		order = order[:r.cfg.MaxPathsPerRun]
	}

	stats := Stats{}
	type result struct {
		candidate candidate
		current   int
	}
	results := make([]result, 0, len(candidates))

	for _, path := range order {
		if ctx.Err() != nil {
			return stats, ctx.Err()
		}
		md, err := r.vault.Metadata(ctx, path)
		if err != nil {
			// Недоступность или отсутствие прав — не доказательство правки.
			// Аккаунты этого пути остаются с прежней наблюдаемой версией.
			stats.PathsUnavailable++
			slog.WarnContext(ctx, "credentialcheck: read secret metadata", "path", path, "error", err)
			continue
		}
		stats.PathsChecked++
		for _, c := range byPath[path] {
			results = append(results, result{candidate: c, current: md.CurrentVersion})
		}
	}
	if len(results) == 0 {
		return stats, nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return stats, fmt.Errorf("credentialcheck: begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var locked bool
	if err := tx.QueryRow(ctx, `select pg_try_advisory_xact_lock($1, $2)`,
		credentialCheckLockClass, credentialCheckLockObj).Scan(&locked); err != nil {
		return stats, fmt.Errorf("credentialcheck: advisory lock: %w", err)
	}
	if !locked {
		// Прогон уже идёт в другой реплике: свои результаты выбрасываем.
		return Stats{}, nil
	}

	for _, res := range results {
		if _, err := tx.Exec(ctx, `
			update accounts set
				credential_observed_version = $2,
				credential_checked_at = now()
			where id = $1`, res.candidate.accountID, res.current); err != nil {
			return stats, fmt.Errorf("credentialcheck: record observed version: %w", err)
		}
		stats.AccountsChecked++

		if res.current <= res.candidate.anchor {
			continue
		}
		stats.Diverged++
		// Audit пишется только на переходе: прошлый прогон расхождения не
		// видел. Повторять событие на каждом прогоне — значит утопить журнал.
		if res.candidate.observed > res.candidate.anchor {
			continue
		}
		stats.NewlyDiverged++
		if err := r.writeDivergedAudit(ctx, tx, res.candidate, res.current); err != nil {
			return stats, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return stats, fmt.Errorf("credentialcheck: commit: %w", err)
	}
	return stats, nil
}

// listCandidates выбирает управляемые живые аккаунты с якорем и путём.
// Читается вне транзакции с lock: обращения к Vault выполняются между этим
// чтением и записью результата, и держать lock всё это время нельзя.
func (r *Runner) listCandidates(ctx context.Context) ([]candidate, error) {
	rows, err := r.pool.Query(ctx, `
		select id, connection_id, engine_identity, vault_path,
		       credential_version, credential_observed_version
		from accounts
		where ownership = 'managed'
		  and status <> 'deleted'
		  and credential_version > 0
		  and vault_path <> ''
		order by vault_path, id`)
	if err != nil {
		return nil, fmt.Errorf("credentialcheck: list candidates: %w", err)
	}
	defer rows.Close()

	var out []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.accountID, &c.connectionID, &c.engineIdentity,
			&c.vaultPath, &c.anchor, &c.observed); err != nil {
			return nil, fmt.Errorf("credentialcheck: scan candidate: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credentialcheck: list candidates: %w", err)
	}
	return out, nil
}

// writeDivergedAudit фиксирует обнаруженное расхождение. В метаданные
// попадают только номера версий и идентичность аккаунта — ни пароля, ни
// пути к секрету: путь указывает на секрет, и в журнале ему не место.
func (r *Runner) writeDivergedAudit(ctx context.Context, tx pgx.Tx, c candidate, current int) error {
	if r.audit == nil {
		return nil
	}
	metadata, err := json.Marshal(map[string]any{
		"account":         c.engineIdentity,
		"applied_version": c.anchor,
		"vault_version":   current,
	})
	if err != nil {
		return fmt.Errorf("credentialcheck: marshal audit metadata: %w", err)
	}
	accountID := c.accountID
	connectionID := c.connectionID
	if err := r.audit.Write(ctx, tx, audit.Event{
		ActorType:    checkActorType,
		ActorID:      checkActorID,
		Action:       auditActionCredentialDiverged,
		ConnectionID: &connectionID,
		AccountID:    &accountID,
		Result:       audit.ResultSuccess,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("credentialcheck: write audit: %w", err)
	}
	return nil
}
