// Package connectorstate хранит наблюдаемое состояние execution
// connector'ов: кто подключался, когда его видели последний раз и до
// какого числа действует его сертификат.
//
// Сессия connector'а живёт в памяти gateway, поэтому снаружи о нём нельзя
// было узнать ничего. Истечение сертификата при этом обрывает связь
// бесповоротно: агент перестаёт проходить mTLS, а операции подключений
// сегмента начинают падать retryable-ошибкой без внятной причины. Здесь
// хранится наблюдение, по которому control plane предупреждает заранее.
package connectorstate

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Session — строка connector_sessions.
type Session struct {
	ConnectorID         string
	ConnectedAt         time.Time
	LastSeenAt          time.Time
	CertificateNotAfter time.Time
	Capabilities        []string
	ProtocolVersion     string
	// Deployment — среда, о которой агент объявил в Hello ("kubernetes",
	// "vm"); пусто — не сообщил.
	Deployment string
}

// Store читает и пишет наблюдения о connector'ах.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Observe фиксирует состояние сессии.
//
// connected_at обновляется только при новом подключении: иначе heartbeat
// затирал бы момент установления сессии, и «сколько connector на связи»
// нельзя было бы отличить от «когда его видели».
func (s *Store) Observe(ctx context.Context, sess Session) error {
	const query = `
		insert into connector_sessions
			(connector_id, connected_at, last_seen_at, certificate_not_after,
			 capabilities, protocol_version, deployment_kind)
		values ($1, $2, $3, $4, $5, $6, $7)
		on conflict (connector_id) do update set
			connected_at = case
				when connector_sessions.connected_at < excluded.connected_at
					then excluded.connected_at
				else connector_sessions.connected_at
			end,
			last_seen_at = excluded.last_seen_at,
			certificate_not_after = excluded.certificate_not_after,
			capabilities = excluded.capabilities,
			protocol_version = excluded.protocol_version,
			deployment_kind = excluded.deployment_kind`
	if _, err := s.pool.Exec(ctx, query,
		sess.ConnectorID, sess.ConnectedAt, sess.LastSeenAt,
		sess.CertificateNotAfter, sess.Capabilities, sess.ProtocolVersion,
		sess.Deployment,
	); err != nil {
		return fmt.Errorf("connectorstate: observe %q: %w", sess.ConnectorID, err)
	}
	return nil
}

// List возвращает все известные connector'ы.
func (s *Store) List(ctx context.Context) ([]Session, error) {
	const query = `
		select connector_id, connected_at, last_seen_at, certificate_not_after,
		       capabilities, protocol_version, deployment_kind
		  from connector_sessions
		 order by connector_id`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("connectorstate: list: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ConnectorID, &item.ConnectedAt, &item.LastSeenAt,
			&item.CertificateNotAfter, &item.Capabilities, &item.ProtocolVersion,
			&item.Deployment); err != nil {
			return nil, fmt.Errorf("connectorstate: scan: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connectorstate: list rows: %w", err)
	}
	return out, nil
}

// ExpiringSoon возвращает connector'ы, чей сертификат истекает раньше
// now+within, включая уже истёкшие.
//
// Порог задаёт вызывающий: за сколько предупреждать — вопрос практики
// эксплуатации, а не свойство данных.
func (s *Store) ExpiringSoon(ctx context.Context, tx pgx.Tx, now time.Time, within time.Duration) ([]Session, error) {
	const query = `
		select connector_id, connected_at, last_seen_at, certificate_not_after,
		       capabilities, protocol_version, deployment_kind
		  from connector_sessions
		 where certificate_not_after <= $1
		 order by certificate_not_after`
	rows, err := tx.Query(ctx, query, now.Add(within))
	if err != nil {
		return nil, fmt.Errorf("connectorstate: expiring: %w", err)
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var item Session
		if err := rows.Scan(&item.ConnectorID, &item.ConnectedAt, &item.LastSeenAt,
			&item.CertificateNotAfter, &item.Capabilities, &item.ProtocolVersion,
			&item.Deployment); err != nil {
			return nil, fmt.Errorf("connectorstate: scan expiring: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connectorstate: expiring rows: %w", err)
	}
	return out, nil
}

// Profile — операторские данные о connector'е: человеческое имя и уточнение
// среды. Живут отдельно от наблюдений: имя сессии — CN сертификата, менять
// его без перевыпуска нельзя, а название и тип задаёт человек.
type Profile struct {
	ConnectorID    string
	DisplayName    string
	DeploymentKind string
	UpdatedBy      string
	UpdatedAt      time.Time
}

// Допустимые значения типа развёртывания в профиле; пусто — «как сообщил
// агент».
const (
	DeploymentKubernetes = "kubernetes"
	DeploymentVM         = "vm"
	DeploymentOther      = "other"
)

// ValidDeploymentKind сообщает, допустимо ли значение для профиля.
func ValidDeploymentKind(value string) bool {
	switch value {
	case "", DeploymentKubernetes, DeploymentVM, DeploymentOther:
		return true
	default:
		return false
	}
}

// Profiles возвращает профили по connector_id.
func (s *Store) Profiles(ctx context.Context) (map[string]Profile, error) {
	const query = `
		select connector_id, display_name, deployment_kind, updated_by, updated_at
		  from connector_profiles`
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("connectorstate: profiles: %w", err)
	}
	defer rows.Close()

	out := map[string]Profile{}
	for rows.Next() {
		var item Profile
		if err := rows.Scan(&item.ConnectorID, &item.DisplayName, &item.DeploymentKind,
			&item.UpdatedBy, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("connectorstate: scan profile: %w", err)
		}
		out[item.ConnectorID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connectorstate: profile rows: %w", err)
	}
	return out, nil
}

// SaveProfile создаёт или обновляет профиль. Профиль допускается и для
// connector'а, который ещё ни разу не подключался: имя задаётся заранее.
func (s *Store) SaveProfile(ctx context.Context, p Profile) (Profile, error) {
	const query = `
		insert into connector_profiles
			(connector_id, display_name, deployment_kind, updated_by, updated_at)
		values ($1, $2, $3, $4, now())
		on conflict (connector_id) do update set
			display_name = excluded.display_name,
			deployment_kind = excluded.deployment_kind,
			updated_by = excluded.updated_by,
			updated_at = now()
		returning connector_id, display_name, deployment_kind, updated_by, updated_at`
	var out Profile
	if err := s.pool.QueryRow(ctx, query,
		p.ConnectorID, p.DisplayName, p.DeploymentKind, p.UpdatedBy,
	).Scan(&out.ConnectorID, &out.DisplayName, &out.DeploymentKind,
		&out.UpdatedBy, &out.UpdatedAt); err != nil {
		return Profile{}, fmt.Errorf("connectorstate: save profile %q: %w", p.ConnectorID, err)
	}
	return out, nil
}

// Forget удаляет наблюдение и профиль connector'а одной транзакцией.
// Возвращает false, если наблюдения не было.
//
// Нужен после перевыпуска сертификата с другим CN: старая строка иначе висит
// вечным offline и выглядит как потерянный сегмент. Подключившись снова,
// connector заведёт запись заново — удаление ничего не ломает.
func (s *Store) Forget(ctx context.Context, connectorID string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("connectorstate: forget %q: %w", connectorID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `delete from connector_sessions where connector_id = $1`, connectorID)
	if err != nil {
		return false, fmt.Errorf("connectorstate: forget session %q: %w", connectorID, err)
	}
	if _, err := tx.Exec(ctx, `delete from connector_profiles where connector_id = $1`, connectorID); err != nil {
		return false, fmt.Errorf("connectorstate: forget profile %q: %w", connectorID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("connectorstate: commit forget %q: %w", connectorID, err)
	}
	return tag.RowsAffected() > 0, nil
}
