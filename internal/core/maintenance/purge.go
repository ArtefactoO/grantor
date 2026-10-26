package maintenance

// Фаза 2 обратимого offboarding: необратимое уничтожение по истечении
// срока хранения. До этого шага pending_purge был вечным — UI обещал
// удаление через срок, но не выполнял его.
//
// Конвергентная машина по прогонам: пока у принципала остаются живые
// managed-логины, прогон только ставит account.delete (исполняет worker) и
// оставляет статус pending_purge; когда учётных записей не осталось —
// зачищаются общие секреты Vault, отвязываются оставшиеся связанные
// аккаунты (unmanaged и групповые роли: их lifecycle grantor'у не
// принадлежит, удалять их нельзя) и принципал переходит в deleted.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/principals"
)

// purgeBatchLimit — принципалов за прогон: уничтожение не срочное, а
// всплеск account.delete по многим кластерам разом не нужен никому.
const purgeBatchLimit = 20

// PurgeEnqueuer ставит операцию account.delete в транзакции прогона.
// Интерфейс объявлен здесь, реализация — в jobs (worker), по той же
// причине, что RevokeEnqueuer: иначе циклическая зависимость пакетов.
type PurgeEnqueuer interface {
	EnqueuePurgeDelete(ctx context.Context, tx pgx.Tx, accountID uuid.UUID, reason string) (bool, error)
}

// CredentialPurger удаляет общий секрет принципала окружения из Vault.
// Реализация — credentials.Service.
type CredentialPurger interface {
	DeletePrincipalCredential(ctx context.Context, principalID uuid.UUID, environment string) error
}

// WithPurge включает необратимое уничтожение по истечении срока хранения.
// nil enqueuer оставляет pending_purge вечным (безопасная сторона).
func (r *Runner) WithPurge(e PurgeEnqueuer, c CredentialPurger) *Runner {
	if e != nil {
		r.purge = e
		r.creds = c
	}
	return r
}

// purgeDeletableAccount — учётная запись, которую purge удаляет в целевой
// системе: живой managed-логин. Групповые роли не удаляются даже managed —
// их DROP уничтожил бы право, которым пользуются другие; они отвязываются
// на финализации. Чистая функция для юнит-тестов.
func purgeDeletableAccount(a inventory.Account) bool {
	return a.Ownership == inventory.OwnershipManaged &&
		a.Status != inventory.AccountDeleted &&
		inventory.AccountHoldsCredential(a)
}

// purgeExpiredPrincipals обрабатывает принципалов с истёкшим сроком
// хранения. Возвращает число финализированных и число поставленных
// account.delete.
func (r *Runner) purgeExpiredPrincipals(ctx context.Context, tx pgx.Tx, now time.Time) (purged, enqueued int, err error) {
	if r.purge == nil {
		return 0, 0, nil
	}
	due, err := r.principals.ListPurgeDue(ctx, tx, now, purgeBatchLimit)
	if err != nil {
		return 0, 0, err
	}
	for i := range due {
		p := due[i]
		accounts, err := r.inv.ListAccountsByPrincipal(ctx, tx, p.ID)
		if err != nil {
			return purged, enqueued, err
		}
		deletable := make([]inventory.Account, 0, len(accounts))
		for j := range accounts {
			if purgeDeletableAccount(accounts[j]) {
				deletable = append(deletable, accounts[j])
			}
		}
		if len(deletable) > 0 {
			reason := fmt.Sprintf("principal purge after retention (offboarded, purge_after %s)",
				formatPurgeAfter(p.PurgeAfter))
			for j := range deletable {
				ok, err := r.purge.EnqueuePurgeDelete(ctx, tx, deletable[j].ID, reason)
				if err != nil {
					return purged, enqueued, err
				}
				if ok {
					enqueued++
				}
			}
			// Финализация — следующим прогоном, когда worker доведёт
			// удаления; статус остаётся pending_purge.
			continue
		}

		// Незавершённые операции принципала (в т.ч. поставленные прошлым
		// прогоном удаления) — ждём: финализация под ними была бы гонкой.
		var busy bool
		if err := tx.QueryRow(ctx, `
			select exists (
				select 1 from operations
				where principal_id = $1
				  and status in ('pending_approval', 'pending', 'running')
			)`, p.ID).Scan(&busy); err != nil {
			return purged, enqueued, fmt.Errorf("maintenance: purge %s: inspect operations: %w", p.ID, err)
		}
		if busy {
			continue
		}

		// Общие секреты всех известных окружений. Реестр — источник истины
		// окружений (миграция 00021 бэкфиллит его из connections).
		// Недоступный Vault не валит прогон и не финализирует принципала
		// молча: кандидат остаётся до следующего прогона. Отсутствие Vault в
		// конфигурации — не препятствие: секретов тогда не существует.
		if r.creds != nil {
			envs, err := r.listEnvironments(ctx, tx)
			if err != nil {
				return purged, enqueued, err
			}
			failed := false
			for _, env := range envs {
				if err := r.creds.DeletePrincipalCredential(ctx, p.ID, env); err != nil {
					if errors.Is(err, credentials.ErrVaultNotConfigured) {
						break
					}
					failed = true
					break
				}
			}
			if failed {
				continue
			}
		}

		// Отвязка оставшихся связанных аккаунтов (unmanaged, групповые
		// роли, tombstone-строки не трогаем): их lifecycle принадлежит
		// целевой системе, у принципала-тени связей быть не должно.
		unlinkTag, err := tx.Exec(ctx, `
			update accounts set principal_id = null, updated_at = now()
			where principal_id = $1 and status != 'deleted'`, p.ID)
		if err != nil {
			return purged, enqueued, fmt.Errorf("maintenance: purge %s: unlink accounts: %w", p.ID, err)
		}

		if _, err := r.principals.SetStatus(ctx, tx, p.ID, principals.StatusDeleted); err != nil {
			return purged, enqueued, err
		}
		if r.audit != nil {
			meta, err := json.Marshal(map[string]any{
				"unlinked_accounts": unlinkTag.RowsAffected(),
				"purge_after":       formatPurgeAfter(p.PurgeAfter),
			})
			if err != nil {
				return purged, enqueued, fmt.Errorf("maintenance: marshal purge audit for %s: %w", p.ID, err)
			}
			if err := r.audit.Write(ctx, tx, audit.Event{
				ActorType:   ActorType,
				ActorID:     ActorID,
				Action:      "principal.purged",
				PrincipalID: &p.ID,
				Result:      audit.ResultSuccess,
				Metadata:    meta,
			}); err != nil {
				return purged, enqueued, err
			}
		}
		purged++
	}
	return purged, enqueued, nil
}

// listEnvironments возвращает имена окружений реестра.
func (r *Runner) listEnvironments(ctx context.Context, tx pgx.Tx) ([]string, error) {
	rows, err := tx.Query(ctx, `select name from environments order by name`)
	if err != nil {
		return nil, fmt.Errorf("maintenance: list environments: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("maintenance: list environments: scan: %w", err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("maintenance: list environments: %w", err)
	}
	return out, nil
}

// formatPurgeAfter — срок в audit/reason без паники на nil.
func formatPurgeAfter(t *time.Time) string {
	if t == nil {
		return "unset"
	}
	return t.UTC().Format(time.RFC3339)
}
