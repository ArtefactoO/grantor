package principals

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/readscope"
)

var (
	// ErrNotFound возвращается, когда принципал с указанным id не
	// существует.
	ErrNotFound = errors.New("principals: not found")
	// ErrAlreadyExists возвращается, когда внешняя identity
	// (external_provider, external_subject) уже занята другим принципалом.
	ErrAlreadyExists = errors.New("principals: already exists")
)

// pgUniqueViolation — SQLSTATE-код PostgreSQL нарушения уникальности,
// который Create переводит в ErrAlreadyExists.
const pgUniqueViolation = "23505"

// Querier — минимальный контракт выполнения запросов pgx; ему
// удовлетворяют и *pgxpool.Pool, и pgx.Tx. Интерфейс объявлен локально
// (а не импортирован из core/operations), чтобы пакеты ядра не зависели
// друг от друга: структурная типизация Go делает локальные копии
// взаимозаменяемыми для вызывающего.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблице principals. Не хранит соединение: Querier
// передаётся в каждый метод, чтобы вызывающий управлял транзакциями.
// Zero value полностью работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// principalColumns — список колонок principals, согласованный со
// scanPrincipal.
const principalColumns = `id, type, display_name, external_provider, external_subject,
	external_identity_status, external_identity_checked_at,
	external_identity_status_changed_at, status, attributes, disabled_at,
	purge_after, created_at, updated_at`

// scanPrincipal читает одну строку principals; порядок полей обязан
// совпадать с principalColumns.
func scanPrincipal(row pgx.Row) (Principal, error) {
	var p Principal
	var attrs []byte
	var externalIdentityStatus *string
	err := row.Scan(
		&p.ID, &p.Type, &p.DisplayName, &p.ExternalProvider, &p.ExternalSubject,
		&externalIdentityStatus, &p.ExternalIdentityCheckedAt,
		&p.ExternalIdentityStatusChangedAt, &p.Status, &attrs, &p.DisabledAt,
		&p.PurgeAfter, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return Principal{}, err
	}
	p.Attributes = attrs
	if externalIdentityStatus != nil {
		status := ExternalIdentityStatus(*externalIdentityStatus)
		p.ExternalIdentityStatus = &status
	}
	return p, nil
}

// CreateParams — параметры создания принципала. ExternalProvider и
// ExternalSubject необязательны: пустые значения означают локального
// принципала без внешней identity.
type CreateParams struct {
	Type             Type
	DisplayName      string
	ExternalProvider string
	ExternalSubject  string
}

// Create создаёт принципала в статусе active и возвращает созданную
// строку. Type обязан входить в допустимые значения, display name — быть
// непустым; проверки выполняются до обращения к базе. Занятая внешняя
// identity — ErrAlreadyExists.
func (s *Store) Create(ctx context.Context, q Querier, params CreateParams) (Principal, error) {
	if !params.Type.Valid() {
		return Principal{}, fmt.Errorf("principals: create: invalid type %q", params.Type)
	}
	if strings.TrimSpace(params.DisplayName) == "" {
		return Principal{}, errors.New("principals: create: display name is required")
	}

	p, err := scanPrincipal(q.QueryRow(ctx, `
		insert into principals (type, display_name, external_provider, external_subject)
		values ($1, $2, $3, $4)
		returning `+principalColumns,
		string(params.Type), params.DisplayName, params.ExternalProvider, params.ExternalSubject,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return Principal{}, fmt.Errorf(
				"principals: create: external identity %s/%s is already taken: %w",
				params.ExternalProvider, params.ExternalSubject, ErrAlreadyExists)
		}
		return Principal{}, fmt.Errorf("principals: create %q: %w", params.DisplayName, err)
	}
	return p, nil
}

// List возвращает принципалов в порядке создания со счётчиком их учётных
// записей — одним запросом через LEFT JOIN + GROUP BY (аккаунты в
// статусе deleted не считаются, см. ListItem). limit <= 0 заменяется
// значением 100, отрицательный offset — нулём.
func (s *Store) List(ctx context.Context, q Querier, limit, offset int) ([]ListItem, error) {
	return s.ListScoped(ctx, q, limit, offset, nil)
}

// ListScoped retains the global principal directory while counting only
// accounts whose connection is visible. Authorization runs before COUNT,
// GROUP BY and pagination, including principals with zero visible accounts.
func (s *Store) ListScoped(ctx context.Context, q Querier, limit, offset int, scope *readscope.Scope) ([]ListItem, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	args := []any{limit, offset}
	accountScope := ""
	if scope != nil {
		accountScope = " and " + scope.Connection("a.connection_id", &args)
	}
	rows, err := q.Query(ctx, `
		select p.id, p.type, p.display_name, p.external_provider, p.external_subject,
		       p.external_identity_status, p.external_identity_checked_at,
		       p.external_identity_status_changed_at, p.status, p.attributes,
		       p.disabled_at, p.purge_after, p.created_at, p.updated_at,
		       count(a.id)
		from principals p
		left join accounts a on a.principal_id = p.id and a.status <> 'deleted'`+accountScope+`
		group by p.id
		order by p.created_at, p.id
		limit $1 offset $2`, args...)
	if err != nil {
		return nil, fmt.Errorf("principals: list: %w", err)
	}
	defer rows.Close()

	var out []ListItem
	for rows.Next() {
		var item ListItem
		var attrs []byte
		var externalIdentityStatus *string
		if err := rows.Scan(
			&item.ID, &item.Type, &item.DisplayName, &item.ExternalProvider,
			&item.ExternalSubject, &externalIdentityStatus,
			&item.ExternalIdentityCheckedAt, &item.ExternalIdentityStatusChangedAt,
			&item.Status, &attrs, &item.DisabledAt, &item.PurgeAfter,
			&item.CreatedAt, &item.UpdatedAt, &item.AccountsCount,
		); err != nil {
			return nil, fmt.Errorf("principals: list: scan: %w", err)
		}
		item.Attributes = attrs
		if externalIdentityStatus != nil {
			status := ExternalIdentityStatus(*externalIdentityStatus)
			item.ExternalIdentityStatus = &status
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("principals: list: %w", err)
	}
	return out, nil
}

// ExternalIdentityStatusUpdate — результат записи одного успешного IdP
// наблюдения. PreviousStatus nil при первом наблюдении; StatusChanged
// отличает фактический переход зеркала от обновления одного checked_at.
type ExternalIdentityStatusUpdate struct {
	Principal       Principal
	PreviousStatus  *ExternalIdentityStatus
	StatusChanged   bool
	LocallyDisabled bool
}

// RecordExternalIdentityStatus сохраняет результат успешной сверки внешней
// identity и сообщает, был ли локальный active-принципал выключен этим
// наблюдением. Зеркало обновляется независимо от локального principal.Status:
// active во внешнем каталоге не включает локально disabled principal, а
// external deleted не создаёт локальный deleted tombstone. disableLocal
// задаёт policy-решение потребителя: внешний disabled всегда передаётся с
// true, а deleted/missing учитывает GRANTOR_IDP_MISSING_IS_DISABLED. checked_at
// обновляется на каждом успешном poll, status_changed_at — только при смене
// зеркального статуса. Несуществующий id — ErrNotFound.
func (s *Store) RecordExternalIdentityStatus(
	ctx context.Context,
	q Querier,
	id uuid.UUID,
	status ExternalIdentityStatus,
	disableLocal bool,
) (ExternalIdentityStatusUpdate, error) {
	if !status.Valid() {
		return ExternalIdentityStatusUpdate{}, fmt.Errorf(
			"principals: record external identity status %s: invalid status %q", id, status)
	}

	row := q.QueryRow(ctx, `
		with current as (
			select status as previous_local_status,
			       external_identity_status as previous_external_identity_status
			from principals
			where id = $1
			for update
		)
		update principals p set
			external_identity_status = $2,
			external_identity_checked_at = now(),
			external_identity_status_changed_at = case
				when p.external_identity_status is distinct from $2 then now()
				else p.external_identity_status_changed_at
			end,
			status = case
				when p.status = 'active' and $3 then 'disabled'
				else p.status
			end,
			disabled_at = case
				when p.status = 'active' and $3 then now()
				else p.disabled_at
			end,
			updated_at = case
				when p.external_identity_status is distinct from $2
					or (p.status = 'active' and $3)
				then now()
				else p.updated_at
			end
		from current
		where p.id = $1
		returning `+principalColumns+`,
			current.previous_external_identity_status,
			(current.previous_external_identity_status is distinct from $2),
			(current.previous_local_status = 'active' and $3)`,
		id, string(status), disableLocal)

	var p Principal
	var attrs []byte
	var externalIdentityStatus *string
	var previousStatus *string
	var statusChanged bool
	var locallyDisabled bool
	if err := row.Scan(
		&p.ID, &p.Type, &p.DisplayName, &p.ExternalProvider, &p.ExternalSubject,
		&externalIdentityStatus, &p.ExternalIdentityCheckedAt,
		&p.ExternalIdentityStatusChangedAt, &p.Status, &attrs, &p.DisabledAt,
		&p.PurgeAfter, &p.CreatedAt, &p.UpdatedAt, &previousStatus, &statusChanged, &locallyDisabled,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ExternalIdentityStatusUpdate{}, fmt.Errorf(
				"principals: record external identity status %s: %w", id, ErrNotFound)
		}
		return ExternalIdentityStatusUpdate{}, fmt.Errorf(
			"principals: record external identity status %s: %w", id, err)
	}
	p.Attributes = attrs
	if externalIdentityStatus != nil {
		value := ExternalIdentityStatus(*externalIdentityStatus)
		p.ExternalIdentityStatus = &value
	}
	var previous *ExternalIdentityStatus
	if previousStatus != nil {
		value := ExternalIdentityStatus(*previousStatus)
		previous = &value
	}
	return ExternalIdentityStatusUpdate{
		Principal:       p,
		PreviousStatus:  previous,
		StatusChanged:   statusChanged,
		LocallyDisabled: locallyDisabled,
	}, nil
}

// Get возвращает принципала по id. Если его нет — ErrNotFound.
func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Principal, error) {
	p, err := scanPrincipal(q.QueryRow(ctx,
		`select `+principalColumns+` from principals where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, fmt.Errorf("principals: get %s: %w", id, ErrNotFound)
		}
		return Principal{}, fmt.Errorf("principals: get %s: %w", id, err)
	}
	return p, nil
}

// ListByIDs возвращает принципалов по набору id одним запросом (без N+1;
// порядок — display_name, id). Несуществующие id молча пропускаются:
// вызывающий строит map по результату и сам решает, как трактовать
// отсутствие. Пустой список id — пустой результат без похода в базу.
func (s *Store) ListByIDs(ctx context.Context, q Querier, ids []uuid.UUID) ([]Principal, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx,
		`select `+principalColumns+` from principals
		 where id = any($1) order by display_name, id`, ids)
	if err != nil {
		return nil, fmt.Errorf("principals: list by ids: %w", err)
	}
	defer rows.Close()

	var out []Principal
	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, fmt.Errorf("principals: list by ids: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("principals: list by ids: %w", err)
	}
	return out, nil
}

// SetStatus обновляет статус принципала (active|disabled|pending_purge|
// deleted) и возвращает обновлённую строку. Несуществующий id — ErrNotFound.
// Статус — только метаданные control plane: учётные записи принципала
// автоматически не выключаются (см. doc-комментарий пакета); каскад по
// аккаунтам оркеструет API-слой. disabled_at поддерживается автоматически:
// переход в disabled фиксирует момент, повторное включение сбрасывает его,
// повторный disable уже выключенного не сдвигает; переход в deleted
// (offboarding, tombstone) оставляет disabled_at как есть. Store не
// запрещает переходы — guard «из deleted выхода нет» живёт на API-слое.
//
// purge_after этим методом не управляется: срок хранения задаётся отдельно
// (SetPurgeAfter), потому что переход в pending_purge и вычисление даты
// уничтожения — разные решения, и второе зависит от конфигурации.
func (s *Store) SetStatus(ctx context.Context, q Querier, id uuid.UUID, status Status) (Principal, error) {
	if !status.Valid() {
		return Principal{}, fmt.Errorf("principals: set status %s: invalid status %q", id, status)
	}
	p, err := scanPrincipal(q.QueryRow(ctx, `
		update principals set
			status = $2,
			disabled_at = case
				when $2 = 'disabled' and status <> 'disabled' then now()
				when $2 = 'active' then null
				else disabled_at
			end,
			updated_at = now()
		where id = $1
		returning `+principalColumns, id, string(status)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, fmt.Errorf("principals: set status %s: %w", id, ErrNotFound)
		}
		return Principal{}, fmt.Errorf("principals: set status %s: %w", id, err)
	}
	return p, nil
}

// SetPurgeAfter задаёт или снимает срок необратимого уничтожения принципала.
// nil очищает срок (восстановление), непустое значение назначает его. Метод
// отделён от SetStatus: срок вычисляется из конфигурации retention, а статус
// меняет API-слой вместе с каскадом по аккаунтам.
func (s *Store) SetPurgeAfter(ctx context.Context, q Querier, id uuid.UUID, purgeAfter *time.Time) (Principal, error) {
	p, err := scanPrincipal(q.QueryRow(ctx, `
		update principals set purge_after = $2, updated_at = now()
		where id = $1
		returning `+principalColumns, id, purgeAfter))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, fmt.Errorf("principals: set purge after %s: %w", id, ErrNotFound)
		}
		return Principal{}, fmt.Errorf("principals: set purge after %s: %w", id, err)
	}
	return p, nil
}

// ListPurgeDue возвращает принципалов в pending_purge, чей срок хранения уже
// истёк, в порядке наступления срока. Кандидаты фоновой задачи уничтожения.
func (s *Store) ListPurgeDue(ctx context.Context, q Querier, now time.Time, limit int) ([]Principal, error) {
	rows, err := q.Query(ctx, `
		select `+principalColumns+` from principals
		where status = $1 and purge_after is not null and purge_after <= $2
		order by purge_after
		limit $3`, string(StatusPendingPurge), now, limit)
	if err != nil {
		return nil, fmt.Errorf("principals: list purge due: %w", err)
	}
	defer rows.Close()

	var out []Principal
	for rows.Next() {
		p, err := scanPrincipal(rows)
		if err != nil {
			return nil, fmt.Errorf("principals: list purge due: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("principals: list purge due: %w", err)
	}
	return out, nil
}

// PurgeDeletedOrphan безвозвратно удаляет tombstone принципала, только если
// у него больше нет ни одного account и незавершённых операций. Возвращает
// purged=false для принципала, который ещё нельзя удалить. Row lock не даёт
// конкурентной выдаче доступа создать новый account между проверкой и DELETE.
func (s *Store) PurgeDeletedOrphan(ctx context.Context, q Querier, id uuid.UUID) (Principal, bool, error) {
	p, err := scanPrincipal(q.QueryRow(ctx,
		`select `+principalColumns+` from principals where id = $1 for update`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, false, fmt.Errorf("principals: purge %s: %w", id, ErrNotFound)
		}
		return Principal{}, false, fmt.Errorf("principals: purge %s: %w", id, err)
	}
	if p.Status != StatusDeleted {
		return p, false, nil
	}

	var blocked bool
	if err := q.QueryRow(ctx, `
		select exists (select 1 from accounts where principal_id = $1)
		    or exists (
				select 1 from operations
				where principal_id = $1
				  and status in ('pending_approval', 'pending', 'running')
			)`, id).Scan(&blocked); err != nil {
		return Principal{}, false, fmt.Errorf("principals: purge %s: inspect dependencies: %w", id, err)
	}
	if blocked {
		return p, false, nil
	}

	// scope_policies.subject хранит UUID текстом без FK; его нужно чистить
	// явно. service_tokens удаляются FK-каскадом вместе с principal.
	if _, err := q.Exec(ctx, `
		delete from scope_policies
		where subject_kind = 'principal' and subject = $1`, id.String()); err != nil {
		return Principal{}, false, fmt.Errorf("principals: purge %s: delete scope policies: %w", id, err)
	}
	if _, err := q.Exec(ctx, `delete from principals where id = $1`, id); err != nil {
		return Principal{}, false, fmt.Errorf("principals: purge %s: delete: %w", id, err)
	}
	return p, true, nil
}

// DisableIfActive переводит принципала в disabled, только если он сейчас
// active, и сообщает, произошёл ли переход. Уже выключенный или
// несуществующий принципал не затрагивается (false, nil) — вызывающий
// (IdP-poll обслуживания) остаётся идемпотентным: повторный прогон не
// генерирует повторных переходов и audit-событий.
func (s *Store) DisableIfActive(ctx context.Context, q Querier, id uuid.UUID) (Principal, bool, error) {
	p, err := scanPrincipal(q.QueryRow(ctx, `
		update principals set
			status = 'disabled',
			disabled_at = now(),
			updated_at = now()
		where id = $1 and status = 'active'
		returning `+principalColumns, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Principal{}, false, nil
		}
		return Principal{}, false, fmt.Errorf("principals: disable if active %s: %w", id, err)
	}
	return p, true, nil
}
