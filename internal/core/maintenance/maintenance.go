// Package maintenance — периодические операции обслуживания metadata
// database grantor (docs/threat-model.md, раздел 6: P2 R8 retention/GC и
// P2 R9 TTL enforcement bindings; docs/architecture.md, разделы 8–9 и
// 7.4). Прогон запускается фоново в worker-процессе (см. scheduler.go и
// cmd/worker) и выполняется как singleton через PostgreSQL advisory lock:
// несколько реплик worker берут один и тот же фиксированный ключ, работает
// только та, что взяла lock.
//
// Что делает один прогон (RunOnce):
//
//   - GC устаревших ресурсов в статусе missing: discovery не удаляет
//     исчезнувшие объекты, а помечает их missing (раздел 9); здесь они
//     физически удаляются по истечении retention. Managed/observed ресурсы
//     не трогаются никогда — удаляется только status='missing';
//   - GC терминальных операций (success/cancelled) старше retention. failed
//     и partial НЕ удаляются: их ещё могут разбирать и повторять вручную;
//   - TTL enforcement bindings: у bindings с наступившим expires_at
//     desired_state переводится в absent (раздел 7.4) и ставится операция
//     access.revoke. Пакет по-прежнему не зависит от jobs: постановка идёт
//     через локальный интерфейс RevokeEnqueuer, который worker связывает с
//     реальным dispatcher (см. WithRevoke). Без него прогон деградирует до
//     одной лишь пометки desired=absent — это видно в дрифте, но доступ на
//     целевой системе остаётся, поэтому в worker зависимость обязательна.
//
// Audit retention физически НЕ реализован: таблица audit_events
// append-only (триггер audit_events_no_update_delete запрещает DELETE, и
// это правильно — раздел 22). Архивация/партиционирование audit — вне
// scope пакета, на стороне БД/инфраструктуры. Поле Config.AuditRetention
// оставлено как задокументированный ориентир, но в логике прогона не
// используется.
package maintenance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connectorstate"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

const (
	// maintenanceLockClass и maintenanceLockObj — фиксированный ключ
	// singleton advisory lock прогона обслуживания. Используется
	// двухаргументная форма pg_try_advisory_xact_lock(classid, objid): её
	// пространство ключей отдельно от одноаргументных per-connection locks
	// (locks.ConnectionLockKey → pg_advisory_xact_lock(bigint)), поэтому
	// коллизия ключей между обслуживанием и мутациями connection
	// невозможна. Значения — ASCII "GRAN"/"MAIN" для читаемости, оба
	// умещаются в signed int32.
	maintenanceLockClass int32 = 0x4752_414e // "GRAN"
	maintenanceLockObj   int32 = 0x4d41_494e // "MAIN"
)

// Дефолты retention/interval. Retention намеренно длинные: metadata
// database не должна расти безгранично (раздел 8, DoS), но и удалять
// историю рано не нужно.
const (
	// defaultMissingResourceRetention — сколько ресурс живёт в статусе
	// missing до физического удаления. 30 суток.
	defaultMissingResourceRetention = 720 * time.Hour
	// defaultOperationRetention — сколько терминальная операция
	// (success/cancelled) хранится до удаления. 90 суток.
	defaultOperationRetention = 2160 * time.Hour
	// defaultAuditRetention — ориентир хранения audit (НЕ enforced,
	// audit append-only; см. doc-комментарий пакета). 365 суток.
	defaultAuditRetention = 8760 * time.Hour
	// defaultInterval — период между прогонами обслуживания. 1 час.
	defaultInterval = time.Hour
)

// ActorType и ActorID — актор audit-событий планировщика
// обслуживания: сервисный субъект без привязки к человеку (TTL enforcement,
// aging/offboarding findings, IdP-poll). Один на пакет — все прогоны пишут
// события от этого актора.
const (
	ActorType = "service"
	ActorID   = "grantor-maintenance"
)

// Config — настройки обслуживания. Нулевые поля заполняются дефолтами
// (см. withDefaults).
type Config struct {
	// MissingResourceRetention — возраст ресурса в статусе missing, после
	// которого он удаляется. Отсчитывается от observed_at (последнее
	// наблюдение), с откатом на updated_at.
	MissingResourceRetention time.Duration
	// OperationRetention — возраст терминальной (success/cancelled)
	// операции по finished_at, после которого она удаляется.
	OperationRetention time.Duration
	// AuditRetention — ориентир хранения audit. НЕ используется в логике:
	// audit_events append-only, физическое удаление запрещено триггером
	// схемы (см. doc-комментарий пакета). Оставлено как явный TODO для
	// внешней архивации/партиционирования.
	AuditRetention time.Duration
	// Interval — период между прогонами обслуживания (используется
	// scheduler-ом, см. scheduler.go).
	Interval time.Duration
	// AdminCredentialMaxAge — порог старения admin credential подключения
	// (docs/architecture.md, раздел 17.3, R12): подключение, чей admin
	// credential старше этого возраста, отмечается security finding
	// (audit security.admin_credential_aged + Prometheus gauge). Отсчёт от
	// connections.admin_credential_set_at. 0 (дефолт НЕ подставляется —
	// см. withDefaults) отключает эвалуацию старения: политика возраста
	// org-специфична, до её явной установки finding не эмитим.
	AdminCredentialMaxAge time.Duration
	// ConnectorCertificateWarning — за сколько предупреждать об истечении
	// клиентского сертификата connector'а. 0 = проверка выключена.
	ConnectorCertificateWarning time.Duration
}

// withDefaults возвращает копию конфигурации с заполненными дефолтами.
func (c Config) withDefaults() Config {
	if c.MissingResourceRetention <= 0 {
		c.MissingResourceRetention = defaultMissingResourceRetention
	}
	if c.OperationRetention <= 0 {
		c.OperationRetention = defaultOperationRetention
	}
	if c.AuditRetention <= 0 {
		c.AuditRetention = defaultAuditRetention
	}
	if c.Interval <= 0 {
		c.Interval = defaultInterval
	}
	return c
}

// Stats — результат одного прогона обслуживания. Нулевой Stats означает,
// что прогон либо ничего не сделал, либо был пропущен (advisory lock
// удерживает другая реплика).
type Stats struct {
	// MissingResourcesDeleted — удалено ресурсов в статусе missing.
	MissingResourcesDeleted int
	// OperationsDeleted — удалено терминальных операций.
	OperationsDeleted int
	// BindingsExpired — bindings, у которых desired_state переведён в
	// absent по наступившему expires_at.
	BindingsExpired int
	// AdminCredentialsAged — активные подключения, чей admin credential
	// превысил порог старения (AdminCredentialMaxAge) на этом прогоне. 0,
	// если эвалуация выключена (порог не задан) или устаревших нет.
	AdminCredentialsAged int
	// PrincipalsDisabled — принципалы, переведённые в disabled IdP-поллом
	// на этом прогоне. 0, если поллинг выключен (провайдер не подключён)
	// или переходов нет.
	PrincipalsDisabled int
	// OffboardingIncomplete — disabled-принципалы, у которых на этом
	// прогоне остались активные accounts или present/desired bindings
	// (audit security.offboarding_incomplete).
	OffboardingIncomplete int
	// ConnectorCertificatesExpiring — connector'ы, чей сертификат истекает
	// раньше порога (или уже истёк) на этом прогоне.
	ConnectorCertificatesExpiring int
	// PrincipalsPurged — принципалы, финализированные необратимым purge
	// (pending_purge -> deleted) на этом прогоне.
	PrincipalsPurged int
	// PurgeDeletesEnqueued — account.delete, поставленные purge-шагом.
	PurgeDeletesEnqueued int
	// AdminCredentialStagesCleaned — terminal operation-scoped candidate
	// paths removed from Vault and acknowledged in the durable journal.
	AdminCredentialStagesCleaned int
}

// IsZero сообщает, что прогон не затронул ни одной строки.
func (s Stats) IsZero() bool {
	return s.MissingResourcesDeleted == 0 && s.OperationsDeleted == 0 &&
		s.BindingsExpired == 0 && s.AdminCredentialsAged == 0 &&
		s.PrincipalsDisabled == 0 && s.OffboardingIncomplete == 0 &&
		s.ConnectorCertificatesExpiring == 0 &&
		s.PrincipalsPurged == 0 && s.PurgeDeletesEnqueued == 0 &&
		s.AdminCredentialStagesCleaned == 0
}

// Runner выполняет прогоны обслуживания над одним пулом соединений.
type Runner struct {
	pool                      *pgxpool.Pool
	cfg                       Config
	inv                       *inventory.Store
	principals                *principals.Store
	audit                     *audit.Writer
	dir                       DirectoryPoll
	revoke                    RevokeEnqueuer
	connectors                ConnectorStore
	purge                     PurgeEnqueuer
	creds                     CredentialPurger
	adminCredentialStageVault AdminCredentialStageVault
}

type AdminCredentialStageVault interface {
	DeleteMetadata(ctx context.Context, path string) error
}

func (r *Runner) WithAdminCredentialStageCleanup(client AdminCredentialStageVault) *Runner {
	r.adminCredentialStageVault = client
	return r
}

// ConnectorStore — источник наблюдений о connector'ах; nil выключает
// проверку сертификатов (control plane без gateway).
type ConnectorStore interface {
	ExpiringSoon(ctx context.Context, tx pgx.Tx, now time.Time, within time.Duration) ([]connectorstate.Session, error)
}

// WithConnectors подключает наблюдения о connector'ах.
func (r *Runner) WithConnectors(store ConnectorStore) *Runner {
	r.connectors = store
	return r
}

// RevokeEnqueuer ставит операцию отзыва истёкшего binding в той же
// транзакции, что и пометка desired=absent.
//
// Интерфейс объявлен здесь, а реализация живёт в worker: иначе пакет
// обслуживания зависел бы от jobs, а jobs — от него. Транзакция передаётся
// вызывающим: пометка и постановка операции обязаны быть атомарны, иначе
// возможен binding с desired=absent без единой операции отзыва — ровно то
// состояние, из-за которого TTL не отзывал доступ.
type RevokeEnqueuer interface {
	EnqueueExpiredRevoke(ctx context.Context, tx pgx.Tx, bindingID uuid.UUID) error
}

// WithRevoke включает фактический отзыв истёкших bindings и возвращает тот
// же Runner (chained wiring в main, как WithAudit). nil оставляет прогон в
// режиме одной лишь пометки desired=absent.
func (r *Runner) WithRevoke(e RevokeEnqueuer) *Runner {
	if e != nil {
		r.revoke = e
	}
	return r
}

// New собирает Runner с применёнными дефолтами конфигурации. Audit по
// умолчанию не пишется (включается через WithAudit); поллинг identity
// directory по умолчанию выключен (включается через WithDirectoryPoll).
func New(pool *pgxpool.Pool, cfg Config) *Runner {
	return &Runner{
		pool:       pool,
		cfg:        cfg.withDefaults(),
		inv:        inventory.NewStore(),
		principals: principals.NewStore(),
	}
}

// WithAudit включает запись audit-события "binding.expired" при TTL
// enforcement и возвращает тот же Runner (chained wiring в main, как
// audit.Writer.WithLogger). nil-writer оставляет audit выключенным.
func (r *Runner) WithAudit(w *audit.Writer) *Runner {
	r.audit = w
	return r
}

// Interval возвращает период между прогонами (после применения дефолтов).
func (r *Runner) Interval() time.Duration {
	return r.cfg.Interval
}

// RunOnce выполняет один прогон обслуживания под единой транзакцией,
// удерживающей singleton advisory lock.
//
// Порядок: берётся transaction-scoped advisory lock фиксированным ключом;
// если lock уже удерживает другая реплика worker — прогон тихо
// пропускается (возвращается пустой Stats, nil). Иначе последовательно
// выполняются GC missing-ресурсов, GC терминальных операций и TTL
// enforcement bindings, после чего транзакция коммитится. Lock
// освобождается автоматически при commit/rollback.
func (r *Runner) RunOnce(ctx context.Context) (Stats, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Stats{}, fmt.Errorf("maintenance: begin tx: %w", err)
	}
	// После успешного Commit откат — no-op с ErrTxClosed; ошибку
	// игнорируем сознательно.
	defer tx.Rollback(ctx) //nolint:errcheck

	var acquired bool
	if err := tx.QueryRow(ctx,
		`select pg_try_advisory_xact_lock($1, $2)`,
		maintenanceLockClass, maintenanceLockObj,
	).Scan(&acquired); err != nil {
		return Stats{}, fmt.Errorf("maintenance: acquire singleton lock: %w", err)
	}
	if !acquired {
		// Прогон выполняет другая реплика — тихо выходим.
		return Stats{}, nil
	}

	now := time.Now()
	var stats Stats

	stats.MissingResourcesDeleted, err = r.gcMissingResources(ctx, tx, now.Add(-r.cfg.MissingResourceRetention))
	if err != nil {
		return Stats{}, err
	}
	stats.OperationsDeleted, err = r.gcTerminalOperations(ctx, tx, now.Add(-r.cfg.OperationRetention))
	if err != nil {
		return Stats{}, err
	}
	stats.BindingsExpired, err = r.expireBindings(ctx, tx)
	if err != nil {
		return Stats{}, err
	}
	stats.AdminCredentialsAged, err = r.evaluateAdminCredentialAging(ctx, tx, now)
	if err != nil {
		return Stats{}, err
	}
	// Сначала poll (переводит исчезнувших из IdP в disabled), затем
	// эвалуация offboarding: принципал, выключенный этим же прогоном и
	// сохранивший доступ, получает finding в том же прогоне.
	stats.PrincipalsDisabled, err = r.pollDirectory(ctx, tx)
	if err != nil {
		return Stats{}, err
	}
	stats.OffboardingIncomplete, err = r.evaluateOffboarding(ctx, tx)
	if err != nil {
		return Stats{}, err
	}
	stats.ConnectorCertificatesExpiring, err = r.evaluateConnectorCertificates(ctx, tx, now)
	if err != nil {
		return Stats{}, err
	}
	// Финальная фаза offboarding: уничтожение по истечении срока хранения.
	stats.PrincipalsPurged, stats.PurgeDeletesEnqueued, err = r.purgeExpiredPrincipals(ctx, tx, now)
	if err != nil {
		return Stats{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Stats{}, fmt.Errorf("maintenance: commit: %w", err)
	}
	stats.AdminCredentialStagesCleaned, err = r.cleanupAdminCredentialStages(ctx)
	if err != nil {
		return stats, err
	}
	return stats, nil
}

// gcMissingResources удаляет ресурсы в статусе missing старше cutoff.
//
// Удаляются только листья (без дочерних строк в resources): это исключает
// каскадное удаление живого потомка через FK parent_id ON DELETE CASCADE.
// Глубокие поддеревья вычищаются за несколько прогонов, слой за слоем — по
// мере того как их листья устаревают; managed/observed ресурс, оставшийся
// под missing-родителем, навсегда защищает родителя от удаления. Возраст
// считается по observed_at (последнее наблюдение) с откатом на updated_at
// (момент пометки missing). Managed и любые не-missing ресурсы не
// затрагиваются.
func (r *Runner) gcMissingResources(ctx context.Context, tx pgx.Tx, cutoff time.Time) (int, error) {
	tag, err := tx.Exec(ctx, `
		delete from resources r
		where r.status = 'missing'
		  and coalesce(r.observed_at, r.updated_at) < $1
		  and not exists (select 1 from resources c where c.parent_id = r.id)`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("maintenance: gc missing resources: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// gcTerminalOperations удаляет терминальные операции (success/cancelled)
// с finished_at старше cutoff.
//
// failed и partial НЕ удаляются: они допускают retry и разбор. Удаляются
// только операции без дочерних строк (листья) — это исключает каскадное
// удаление живого child через FK parent_id ON DELETE CASCADE (у bulk
// parent с ещё не завершённым/failed child). Иерархия вычищается за
// несколько прогонов. audit_events операции не затрагиваются: у них нет FK
// на operations, история действий сохраняется.
func (r *Runner) gcTerminalOperations(ctx context.Context, tx pgx.Tx, cutoff time.Time) (int, error) {
	tag, err := tx.Exec(ctx, `
	delete from operations o
		where o.status in ('success', 'cancelled')
		  and o.finished_at is not null
		  and o.finished_at < $1
		  and not exists (
			select 1 from connection_admin_credential_changes c
			where c.operation_id = o.id and c.stage_cleanup_pending
		  )
		  and not exists (select 1 from operations c where c.parent_id = o.id)`,
		cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("maintenance: gc terminal operations: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *Runner) cleanupAdminCredentialStages(ctx context.Context) (int, error) {
	if r.adminCredentialStageVault == nil {
		return 0, nil
	}
	store := admincredentials.NewStore()
	items, err := store.ListStageCleanupPending(ctx, r.pool, 100)
	if err != nil {
		return 0, fmt.Errorf("maintenance: list admin credential stage cleanup: %w", err)
	}
	cleaned := 0
	var cleanupErr error
	for i := range items {
		item := items[i]
		if err := r.cleanupAdminCredentialStage(ctx, item); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf(
				"maintenance: cleanup admin credential stage for operation %s: %w", item.OperationID, err))
			continue
		}
		cleaned++
	}
	return cleaned, cleanupErr
}

func (r *Runner) cleanupAdminCredentialStage(ctx context.Context,
	item admincredentials.StageCleanup) error {
	if r.adminCredentialStageVault == nil {
		return errors.New("admin credential stage Vault is unavailable")
	}
	if err := r.adminCredentialStageVault.DeleteMetadata(ctx, item.StageVaultPath); err != nil {
		return err
	}
	return admincredentials.NewStore().MarkStageCleaned(ctx, r.pool, item.OperationID)
}

// expiredBinding — кандидат на TTL enforcement: managed binding с
// наступившим expires_at.
type expiredBinding struct {
	id           uuid.UUID
	accountID    uuid.UUID
	connectionID uuid.UUID
	principalID  *uuid.UUID
	permissionID uuid.UUID
	expiresAt    time.Time
}

// expireBindings переводит desired_state в absent у bindings с
// наступившим expires_at и desired_state='present'.
//
// Bindings без expires_at и с ещё не наступившим сроком не трогаются.
// Сам отзыв в целевой системе здесь НЕ выполняется и НЕ ставится в
// очередь (см. doc-комментарий пакета): пометка desired=absent даёт drift,
// который разбирает reconciliation/оператор. Для каждого помеченного
// binding пишется audit-событие "binding.expired" (если Writer задан).
func (r *Runner) expireBindings(ctx context.Context, tx pgx.Tx) (int, error) {
	// Сначала собираем кандидатов целиком: pgx не даёт выполнять новые
	// запросы на том же соединении, пока открыт курсор rows.
	rows, err := tx.Query(ctx, `
		select b.id, b.account_id, a.connection_id, a.principal_id,
		       b.permission_definition_id, b.expires_at
		from bindings b
		join accounts a on a.id = b.account_id
		where b.expires_at is not null
		  and b.expires_at < now()
		  and b.desired_state = 'present'
		  and b.transition_operation_id is null
		order by b.id`)
	if err != nil {
		return 0, fmt.Errorf("maintenance: select expired bindings: %w", err)
	}

	var candidates []expiredBinding
	for rows.Next() {
		var b expiredBinding
		if err := rows.Scan(
			&b.id, &b.accountID, &b.connectionID, &b.principalID,
			&b.permissionID, &b.expiresAt,
		); err != nil {
			rows.Close()
			return 0, fmt.Errorf("maintenance: scan expired binding: %w", err)
		}
		candidates = append(candidates, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("maintenance: select expired bindings: %w", err)
	}

	for i := range candidates {
		b := &candidates[i]
		// desired=absent; status пересчитывается через ResolveBindingStatus
		// относительно текущего observed (обычно present → drift).
		if _, err := r.inv.SetBindingDesired(ctx, tx, b.id, inventory.BindingAbsent); err != nil {
			if errors.Is(err, inventory.ErrBindingTransitionConflict) {
				continue
			}
			return 0, fmt.Errorf("maintenance: expire binding %s: %w", b.id, err)
		}
		// Пометка сама по себе доступа не снимает: право остаётся на целевой
		// системе до фактического отзыва. Операция ставится в той же
		// транзакции — атомарно с пометкой.
		if r.revoke != nil {
			if err := r.revoke.EnqueueExpiredRevoke(ctx, tx, b.id); err != nil {
				return 0, fmt.Errorf("maintenance: enqueue revoke for expired binding %s: %w", b.id, err)
			}
		}
		if err := r.writeExpiredAudit(ctx, tx, b); err != nil {
			return 0, err
		}
	}
	return len(candidates), nil
}

// auditActionBindingExpired — audit action TTL enforcement bindings. Объявлен
// в точке использования, как security.admin_credential_aged (aging.go) и
// principal.disabled (offboarding.go).
const auditActionBindingExpired = "binding.expired"

// writeExpiredAudit пишет audit-событие "binding.expired" для помеченного
// binding. No-op, если Writer не задан.
func (r *Runner) writeExpiredAudit(ctx context.Context, tx pgx.Tx, b *expiredBinding) error {
	if r.audit == nil {
		return nil
	}
	meta, err := json.Marshal(map[string]any{
		"binding_id":               b.id.String(),
		"permission_definition_id": b.permissionID.String(),
		"expires_at":               b.expiresAt.UTC().Format(time.RFC3339Nano),
		"reason":                   "ttl_expired",
	})
	if err != nil {
		return fmt.Errorf("maintenance: marshal audit metadata for binding %s: %w", b.id, err)
	}
	connectionID := b.connectionID
	accountID := b.accountID
	event := audit.Event{
		ActorType:    ActorType,
		ActorID:      ActorID,
		Action:       auditActionBindingExpired,
		ConnectionID: &connectionID,
		AccountID:    &accountID,
		PrincipalID:  b.principalID,
		Result:       audit.ResultSuccess,
		Metadata:     meta,
	}
	if err := r.audit.Write(ctx, tx, event); err != nil {
		return fmt.Errorf("maintenance: write binding.expired audit for %s: %w", b.id, err)
	}
	return nil
}
