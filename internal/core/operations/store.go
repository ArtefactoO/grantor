package operations

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
	// ErrNotFound возвращается, когда операция с указанным id (или
	// idempotency key) не существует.
	ErrNotFound = errors.New("operations: operation not found")
	// ErrInvalidTransition возвращается при попытке перехода, которого
	// нет в карте допустимых переходов (см. CanTransition).
	ErrInvalidTransition = errors.New("operations: invalid status transition")
	// ErrStatusConflict возвращается, когда переход допустим, но текущий
	// статус строки в базе не совпал с ожидаемым from (конкурентное
	// изменение). Вызывающий может перечитать операцию и решить заново.
	ErrStatusConflict = errors.New("operations: status conflict")
)

// Querier — минимальный контракт выполнения запросов pgx. Ему
// удовлетворяют и *pgxpool.Pool, и pgx.Tx, поэтому методы Store работают
// как вне, так и внутри транзакции вызывающего.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблице operations. Не хранит соединение: Querier
// передаётся в каждый метод, чтобы вызывающий управлял транзакциями.
// Zero value полностью работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// operationColumns — единый список колонок для всех RETURNING/SELECT,
// согласованный со scanOperation.
const operationColumns = `id, parent_id, idempotency_key, kind, status,
	connection_id, principal_id, account_id, resource_id, binding_id,
	payload, plan, result, error, actor_type, actor_id,
	approved_by, approved_at, decision_reason, correlation_id,
	created_at, started_at, finished_at, resolved_at, resolved_by, updated_at`

// CreateParams — параметры создания операции. Если RequiresApproval,
// операция создаётся в статусе pending_approval и не будет выполнена до
// approve; иначе — сразу в pending.
type CreateParams struct {
	// ID optionally pins a caller-owned operation identity. Credential-change
	// request_id uses this to make the Vault stage path and operation durable
	// across a lost API/metadata response. Nil preserves the database default.
	ID               *uuid.UUID
	Kind             string
	IdempotencyKey   *string
	ParentID         *uuid.UUID
	ConnectionID     *uuid.UUID
	PrincipalID      *uuid.UUID
	AccountID        *uuid.UUID
	ResourceID       *uuid.UUID
	BindingID        *uuid.UUID
	Payload          []byte
	ActorType        string
	ActorID          string
	CorrelationID    string
	RequiresApproval bool
}

// Create создаёт операцию идемпотентно по idempotency key. Если ключ
// задан и операция с ним уже существует, вставка не выполняется
// (ON CONFLICT по частичному уникальному индексу
// operations_idempotency_key_idx) и возвращается существующая строка с
// created=false. При created=true возвращается свежесозданная строка.
//
// Гонки: конкурентная вставка того же ключа ждёт коммита победителя на
// уникальном индексе, поэтому последующий SELECT его увидит; если
// победитель откатился и строка исчезла, возвращается ошибка — вызов
// можно безопасно повторить.
func (s *Store) Create(ctx context.Context, q Querier, params CreateParams) (Operation, bool, error) {
	status := StatusPending
	if params.RequiresApproval {
		status = StatusPendingApproval
	}
	payload := params.Payload
	if len(payload) == 0 {
		payload = []byte("{}")
	}

	row := q.QueryRow(ctx, `
		insert into operations (
			id,
			parent_id, idempotency_key, kind, status,
			connection_id, principal_id, account_id, resource_id, binding_id,
			payload, actor_type, actor_id, correlation_id
		) values (coalesce($1::uuid, gen_random_uuid()), $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11, $12, $13, $14)
		on conflict (idempotency_key) where idempotency_key is not null do nothing
		returning `+operationColumns,
		params.ID, params.ParentID, params.IdempotencyKey, params.Kind, status,
		params.ConnectionID, params.PrincipalID, params.AccountID,
		params.ResourceID, params.BindingID,
		payload, params.ActorType, params.ActorID, params.CorrelationID,
	)
	op, err := scanOperation(row)
	switch {
	case err == nil:
		return op, true, nil
	case !errors.Is(err, pgx.ErrNoRows):
		return Operation{}, false, fmt.Errorf("operations: create: %w", err)
	}

	// Вставка не вернула строку — конфликт по idempotency key.
	if params.IdempotencyKey == nil {
		return Operation{}, false, errors.New("operations: create: insert returned no row without idempotency key")
	}
	existing, err := scanOperation(q.QueryRow(ctx,
		`select `+operationColumns+` from operations where idempotency_key = $1`,
		*params.IdempotencyKey,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Operation{}, false, fmt.Errorf(
				"operations: create: conflicting operation vanished for idempotency key: %w", ErrNotFound)
		}
		return Operation{}, false, fmt.Errorf("operations: create: load existing by idempotency key: %w", err)
	}
	return existing, false, nil
}

// Get возвращает операцию по id. Если её нет — ErrNotFound.
func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Operation, error) {
	op, err := scanOperation(q.QueryRow(ctx,
		`select `+operationColumns+` from operations where id = $1`, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Operation{}, fmt.Errorf("operations: get %s: %w", id, ErrNotFound)
		}
		return Operation{}, fmt.Errorf("operations: get %s: %w", id, err)
	}
	return op, nil
}

// GetByIdempotencyKey возвращает операцию по публичному durable ключу.
func (s *Store) GetByIdempotencyKey(ctx context.Context, q Querier, key string) (Operation, error) {
	op, err := scanOperation(q.QueryRow(ctx,
		`select `+operationColumns+` from operations where idempotency_key = $1`, key,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Operation{}, fmt.Errorf("operations: get by idempotency key: %w", ErrNotFound)
		}
		return Operation{}, fmt.Errorf("operations: get by idempotency key: %w", err)
	}
	return op, nil
}

// ListByParent возвращает дочерние операции parent в порядке создания.
// LatestParentChildBindings возвращает binding_id детей kind последнего
// top-level parent'а parentKind у принципала. Используется отменой offboard:
// перевыдать нужно ровно те права, которые отозвал именно этот offboard, а
// не все absent-bindings принципала — среди них могут быть отозванные
// раньше и осознанно.
func (s *Store) LatestParentChildBindings(ctx context.Context, q Querier,
	principalID uuid.UUID, parentKind, childKind string) ([]uuid.UUID, error) {
	rows, err := q.Query(ctx, `
		with latest as (
			select id from operations
			where principal_id = $1 and kind = $2 and parent_id is null
			order by created_at desc
			limit 1
		)
		select c.binding_id from operations c
		join latest on c.parent_id = latest.id
		where c.kind = $3 and c.binding_id is not null
		order by c.created_at`, principalID, parentKind, childKind)
	if err != nil {
		return nil, fmt.Errorf("operations: latest parent child bindings: %w", err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("operations: latest parent child bindings: scan: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("operations: latest parent child bindings: %w", err)
	}
	return out, nil
}

// LatestParent возвращает последнюю корневую (parent_id is null) операцию
// kind по принципалу. Нужен отмене offboard: его незавершённые дети ищутся
// по конкретному parent, а не по статусу — pending_approval может висеть и
// у другого, более раннего каскада. ErrNotFound — таких операций не было.
func (s *Store) LatestParent(ctx context.Context, q Querier, principalID uuid.UUID, kind string) (Operation, error) {
	op, err := scanOperation(q.QueryRow(ctx, `select `+operationColumns+` from operations
		where principal_id = $1 and kind = $2 and parent_id is null
		order by created_at desc limit 1`, principalID, kind))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Operation{}, fmt.Errorf("operations: latest parent %s for principal %s: %w",
				kind, principalID, ErrNotFound)
		}
		return Operation{}, fmt.Errorf("operations: latest parent: %w", err)
	}
	return op, nil
}

// ListEnteredStatusSince возвращает операции, ВОШЕДШИЕ в один из statuses
// после since (для pending_approval — по created_at, для терминальных — по
// finished_at). Используется webhook-уведомлениями: поллер worker'а ловит
// новые события одним запросом независимо от того, какой путь API их
// создал. Порядок — по времени входа; limit ограничивает всплеск.
func (s *Store) ListEnteredStatusSince(ctx context.Context, q Querier, statuses []string, since time.Time, limit int) ([]Operation, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.Query(ctx,
		`select `+operationColumns+` from operations
		where status = any($1)
		  and coalesce(finished_at, created_at) > $2
		order by coalesce(finished_at, created_at), id
		limit $3`,
		statuses, since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("operations: list entered status since: %w", err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("operations: list entered status since: scan: %w", err)
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("operations: list entered status since: %w", err)
	}
	return ops, nil
}

func (s *Store) ListByParent(ctx context.Context, q Querier, parentID uuid.UUID) ([]Operation, error) {
	rows, err := q.Query(ctx,
		`select `+operationColumns+` from operations where parent_id = $1 order by created_at, id`,
		parentID,
	)
	if err != nil {
		return nil, fmt.Errorf("operations: list by parent %s: %w", parentID, err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("operations: list by parent %s: scan: %w", parentID, err)
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("operations: list by parent %s: %w", parentID, err)
	}
	return ops, nil
}

// Filter — необязательные условия выборки List. Nil ConnectionID, пустой
// Status и пустые Statuses/Kinds означают отсутствие соответствующего
// условия. Limit <= 0 заменяется значением 100, отрицательный Offset —
// нулём.
type Filter struct {
	ReadScope    *readscope.Scope
	ConnectionID *uuid.UUID
	// TopLevelOnly исключает дочерние операции bulk-parent. Используется в
	// коротких activity-сводках, где одно действие оператора должно занимать
	// одну строку, а не дублироваться всеми children.
	TopLevelOnly bool
	// Status ограничивает выборку одним статусом операции (например
	// pending_approval для списка ожидающих подтверждения). Пусто — без
	// условия по статусу.
	Status Status
	// Statuses ограничивает выборку любым из перечисленных статусов
	// (вкладки экрана «Операции»: активные / ошибки). Пустой срез — без
	// условия. Задаётся вместе со Status оба условия применяются по AND —
	// вызывающие используют что-то одно.
	Statuses []Status
	// Kinds ограничивает выборку любым из перечисленных kind операций
	// (фильтр по kind в UI). Пустой срез — без условия.
	Kinds []string
	// ActorTypes ограничивает выборку типами инициатора (например user для
	// действий оператора без фоновых service-операций). Пустой срез — без условия.
	ActorTypes []string
	// CreatedFrom включает операции, созданные ровно в этот момент и позже.
	CreatedFrom *time.Time
	// CreatedBefore исключает операции, созданные ровно в этот момент, и
	// включает только более ранние. Вместе границы образуют интервал [from, before).
	CreatedBefore *time.Time
	// UnresolvedOnly исключает операторски обработанные incidents. Флаг
	// применяется независимо от status; вызывающие используют его для
	// активных error-лент, а полная история остаётся доступна без флага.
	UnresolvedOnly bool
	Limit          int
	Offset         int
}

// filterSQL строит WHERE и аргументы один раз для page rows и exact total.
// Limit/Offset намеренно не входят сюда: total описывает всю отфильтрованную
// выборку независимо от текущей страницы.
func filterSQL(f Filter) (string, []any) {
	var conds []string
	var args []any
	if f.ConnectionID != nil {
		args = append(args, *f.ConnectionID)
		conds = append(conds, fmt.Sprintf("connection_id = $%d", len(args)))
	}
	if f.TopLevelOnly {
		conds = append(conds, "parent_id is null")
	}
	if f.Status != "" {
		args = append(args, f.Status)
		conds = append(conds, fmt.Sprintf("status = $%d", len(args)))
	}
	if len(f.Statuses) > 0 {
		// []Status приводится к []string: pgx кодирует в text[] только
		// базовые slice-типы.
		statuses := make([]string, 0, len(f.Statuses))
		for _, st := range f.Statuses {
			statuses = append(statuses, string(st))
		}
		args = append(args, statuses)
		conds = append(conds, fmt.Sprintf("status = any($%d)", len(args)))
	}
	if len(f.Kinds) > 0 {
		args = append(args, f.Kinds)
		conds = append(conds, fmt.Sprintf("kind = any($%d)", len(args)))
	}
	if len(f.ActorTypes) > 0 {
		args = append(args, f.ActorTypes)
		conds = append(conds, fmt.Sprintf("actor_type = any($%d)", len(args)))
	}
	if f.CreatedFrom != nil {
		args = append(args, *f.CreatedFrom)
		conds = append(conds, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if f.CreatedBefore != nil {
		args = append(args, *f.CreatedBefore)
		conds = append(conds, fmt.Sprintf("created_at < $%d", len(args)))
	}
	if f.UnresolvedOnly {
		conds = append(conds, "resolved_at is null")
	}
	if f.ReadScope != nil {
		conds = append(conds, f.ReadScope.Operation("scope_list_operation.id", &args))
	}

	if len(conds) == 0 {
		return "", args
	}
	return " where " + strings.Join(conds, " and "), args
}

// List возвращает операции по фильтру от новых к старым (created_at
// desc; id — детерминированный tiebreaker).
func (s *Store) List(ctx context.Context, q Querier, f Filter) ([]Operation, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := filterSQL(f)
	sql := `select ` + operationColumns + ` from operations scope_list_operation` + where
	args = append(args, limit)
	sql += fmt.Sprintf(" order by created_at desc, id desc limit $%d", len(args))
	args = append(args, offset)
	sql += fmt.Sprintf(" offset $%d", len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("operations: list: %w", err)
	}
	defer rows.Close()

	var ops []Operation
	for rows.Next() {
		op, err := scanOperation(rows)
		if err != nil {
			return nil, fmt.Errorf("operations: list: scan: %w", err)
		}
		ops = append(ops, op)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("operations: list: %w", err)
	}
	return ops, nil
}

// Count возвращает точное число операций по тем же предикатам Filter, что и
// List. Пагинация намеренно игнорируется.
func (s *Store) Count(ctx context.Context, q Querier, f Filter) (int64, error) {
	where, args := filterSQL(f)
	var total int64
	if err := q.QueryRow(ctx, `select count(*) from operations scope_list_operation`+where, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("operations: count: %w", err)
	}
	return total, nil
}

// ListPage возвращает страницу операций и точное число строк во всей
// отфильтрованной выборке. Count и List используют единый filterSQL, поэтому
// connection/status/kind/time predicates не могут разойтись.
func (s *Store) ListPage(ctx context.Context, q Querier, f Filter) ([]Operation, int64, error) {
	total, err := s.Count(ctx, q, f)
	if err != nil {
		return nil, 0, err
	}
	ops, err := s.List(ctx, q, f)
	if err != nil {
		return nil, 0, err
	}
	return ops, total, nil
}

// StatusTotals — точные размеры статусных вкладок экрана операций.
// Active/Errors используют те же группы, что UI; All включает все статусы.
type StatusTotals struct {
	Active int64
	Errors int64
	All    int64
}

// CountStatusTotals считает все три статусные группы одним SQL-запросом.
// Connection/kind/time предикаты сохраняются, а текущий Status/Statuses
// намеренно игнорируется: счётчики вкладок не должны зависеть от открытой
// вкладки. Вызывающий передаёт тот же REPEATABLE READ tx, что и ListPage,
// поэтому rows, total и status totals принадлежат одному snapshot.
func (s *Store) CountStatusTotals(ctx context.Context, q Querier, f Filter) (StatusTotals, error) {
	f.Status = ""
	f.Statuses = nil
	where, args := filterSQL(f)

	active := []string{
		string(StatusPending),
		string(StatusPendingApproval),
		string(StatusRunning),
	}
	errorsGroup := []string{
		string(StatusFailed),
		string(StatusPartial),
		string(StatusCancelled),
	}
	args = append(args, active)
	activeArg := len(args)
	args = append(args, errorsGroup)
	errorsArg := len(args)

	var totals StatusTotals
	err := q.QueryRow(ctx, fmt.Sprintf(`
		select
			count(*) filter (where status = any($%d)),
			count(*) filter (where status = any($%d) and resolved_at is null),
			count(*)
		from operations scope_list_operation%s`, activeArg, errorsArg, where), args...).Scan(
		&totals.Active,
		&totals.Errors,
		&totals.All,
	)
	if err != nil {
		return StatusTotals{}, fmt.Errorf("operations: count status totals: %w", err)
	}
	return totals, nil
}

// TransitionOpts — необязательные данные перехода. Error всегда
// записывается в колонку error (пустая строка очищает её — так retry
// failed->pending сбрасывает текст прошлой ошибки). Plan и Result
// записываются только если не nil, иначе сохраняются прежние значения.
type TransitionOpts struct {
	Error  string
	Plan   []byte
	Result []byte
}

// Transition атомарно переводит операцию из статуса from в to.
//
// Переход валидируется по CanTransition (ErrInvalidTransition), затем
// выполняется UPDATE с guard `status = from`: если строка не обновилась,
// операция либо не существует (ErrNotFound), либо её статус изменил
// кто-то другой (ErrStatusConflict). При to=running выставляется
// started_at (если ещё NULL — при retry сохраняется первый старт), при
// finished-статусах (success/partial/failed/cancelled) — finished_at;
// updated_at обновляется всегда.
func (s *Store) Transition(ctx context.Context, q Querier, id uuid.UUID, from, to Status, opts TransitionOpts) (Operation, error) {
	if !CanTransition(from, to) {
		return Operation{}, fmt.Errorf("operations: transition %s: %q -> %q: %w",
			id, from, to, ErrInvalidTransition)
	}

	op, err := scanOperation(q.QueryRow(ctx, `
		update operations set
			status = $2,
			error = $3,
			plan = coalesce($4, plan),
			result = coalesce($5, result),
			started_at = case when $6 then coalesce(started_at, now()) else started_at end,
			finished_at = case when $7 then now() else finished_at end,
			resolved_at = case when $2 in ('pending', 'running') then null else resolved_at end,
			resolved_by = case when $2 in ('pending', 'running') then null else resolved_by end,
			updated_at = now()
		where id = $1 and status = $8
		returning `+operationColumns,
		id, to, opts.Error, opts.Plan, opts.Result,
		to == StatusRunning, to.IsFinished(), from,
	))
	if err == nil {
		return op, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, fmt.Errorf("operations: transition %s: %q -> %q: %w", id, from, to, err)
	}

	// Guard не сработал: различаем отсутствие строки и конфликт статуса.
	current, getErr := s.Get(ctx, q, id)
	if getErr != nil {
		return Operation{}, fmt.Errorf("operations: transition %s: %q -> %q: %w", id, from, to, getErr)
	}
	return Operation{}, fmt.Errorf("operations: transition %s: %q -> %q: current status %q: %w",
		id, from, to, current.Status, ErrStatusConflict)
}

// Resolve acknowledges a finished unsuccessful operation without changing its
// execution status or error. It is idempotent: resolving an already resolved
// failure returns the existing row. Successful/active operations cannot be
// resolved because they are not incidents.
func (s *Store) Resolve(ctx context.Context, q Querier, id uuid.UUID, actor string) (Operation, bool, error) {
	op, err := scanOperation(q.QueryRow(ctx, `
		update operations set
			resolved_at = now(),
			resolved_by = $2,
			updated_at = now()
		where id = $1
		  and status in ('failed', 'partial', 'cancelled')
		  and resolved_at is null
		returning `+operationColumns,
		id, actor,
	))
	if err == nil {
		return op, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, false, fmt.Errorf("operations: resolve %s: %w", id, err)
	}

	current, getErr := s.Get(ctx, q, id)
	if getErr != nil {
		return Operation{}, false, fmt.Errorf("operations: resolve %s: %w", id, getErr)
	}
	if current.ResolvedAt != nil && (current.Status == StatusFailed || current.Status == StatusPartial || current.Status == StatusCancelled) {
		return current, false, nil
	}
	return Operation{}, false, fmt.Errorf("operations: resolve %s in status %q: %w", id, current.Status, ErrInvalidTransition)
}

// FinalizeParent доводит parent bulk-операцию до итогового статуса в
// базе, когда завершился её последний ребёнок: running -> success |
// partial | failed по AggregateChildren. Вызывается в той же транзакции,
// что и терминальный переход ребёнка (worker или reject), поэтому
// сводный статус parent коммитится атомарно с итогом ребёнка.
//
// Идемпотентно и устойчиво к гонкам: строка parent блокируется
// row-level lock'ом (lockParent), поэтому два ребёнка, завершающиеся
// одновременно в разных транзакциях, проверяют «все ли дети finished»
// строго по очереди. Первый видит незакоммиченный (для него — ещё не
// finished) статус соседа и выходит no-op'ом; второй, дождавшись
// коммита, видит оба итога и финализирует. Возвращает finalized=false,
// если parent не в running или хотя бы один ребёнок не завершён; parent
// без детей финализируется в success (см. комментарий ниже).
func (s *Store) FinalizeParent(ctx context.Context, q Querier, parentID uuid.UUID) (Operation, bool, error) {
	status, err := s.lockParent(ctx, q, parentID)
	if err != nil {
		return Operation{}, false, fmt.Errorf("operations: finalize parent %s: %w", parentID, err)
	}
	if status != StatusRunning {
		// Уже финализирован конкурентной транзакцией, ждёт approve или
		// повторяется (partial/failed -> pending) — финализировать нечего.
		return Operation{}, false, nil
	}

	statuses, err := s.childStatuses(ctx, q, parentID)
	if err != nil {
		return Operation{}, false, fmt.Errorf("operations: finalize parent %s: %w", parentID, err)
	}
	agg := AggregateChildren(statuses)
	if agg == StatusRunning {
		// Не все дети завершились — финализирует последний из них.
		return Operation{}, false, nil
	}
	if agg == "" {
		// Детей нет вовсе: parent и дети создаются одной транзакцией,
		// поэтому снаружи running-parent без детей навсегда останется без
		// них — вся работа bulk-операции выполнилась метаданными в
		// транзакции создания, итог success.
		agg = StatusSuccess
	}

	op, err := s.Transition(ctx, q, parentID, StatusRunning, agg, TransitionOpts{})
	if err != nil {
		return Operation{}, false, fmt.Errorf("operations: finalize parent %s: %w", parentID, err)
	}
	return op, true, nil
}

// ReviveParent возвращает финализированный parent bulk-операции в
// running при retry ребёнка: partial | failed -> pending -> running (оба
// шага — по обычной state machine переходов). Вызывается в той же
// транзакции, что и сброс ребёнка failed/partial -> pending: пока дети
// выполняются заново, итог parent неизвестен, и честный статус — running;
// при завершении последнего ребёнка FinalizeParent финализирует parent
// снова.
//
// Идемпотентно: строка parent блокируется row-level lock'ом (lockParent),
// и если parent уже не в partial/failed (например, второй retry-ребёнок
// оживил его первым), возвращается revived=false без изменений.
func (s *Store) ReviveParent(ctx context.Context, q Querier, parentID uuid.UUID) (Operation, bool, error) {
	status, err := s.lockParent(ctx, q, parentID)
	if err != nil {
		return Operation{}, false, fmt.Errorf("operations: revive parent %s: %w", parentID, err)
	}
	if status != StatusPartial && status != StatusFailed {
		return Operation{}, false, nil
	}

	if _, err := s.Transition(ctx, q, parentID, status, StatusPending, TransitionOpts{}); err != nil {
		return Operation{}, false, fmt.Errorf("operations: revive parent %s: %w", parentID, err)
	}
	op, err := s.Transition(ctx, q, parentID, StatusPending, StatusRunning, TransitionOpts{})
	if err != nil {
		return Operation{}, false, fmt.Errorf("operations: revive parent %s: %w", parentID, err)
	}
	return op, true, nil
}

// lockParent блокирует строку операции row-level lock'ом (SELECT ... FOR
// NO KEY UPDATE) и возвращает её текущий статус. Сериализует конкурентные
// FinalizeParent/ReviveParent по одному parent: проигравший гонку ждёт
// коммита победителя и перечитывает уже итоговое состояние. Требует
// вызова внутри транзакции — вне её lock не имеет смысла и отпускается
// немедленно.
//
// Именно FOR NO KEY UPDATE, а не FOR UPDATE: повторный UPDATE строки
// ребёнка в той же транзакции (pending -> running -> итог) заставляет
// FK-триггер parent_id перепроверить ссылку и взять FOR KEY SHARE на
// строку parent. Два ребёнка одного parent, завершающиеся параллельно,
// оба держат KEY SHARE — их одновременный апгрейд до FOR UPDATE даёт
// deadlock (40P01). FOR NO KEY UPDATE совместим с KEY SHARE (ключ строки
// не меняется), но взаимно исключителен, поэтому сериализация финализации
// сохраняется без цикла блокировок.
func (s *Store) lockParent(ctx context.Context, q Querier, parentID uuid.UUID) (Status, error) {
	var status Status
	err := q.QueryRow(ctx,
		`select status from operations where id = $1 for no key update`, parentID,
	).Scan(&status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("lock row: %w", err)
	}
	return status, nil
}

// childStatuses возвращает статусы всех дочерних операций parent.
func (s *Store) childStatuses(ctx context.Context, q Querier, parentID uuid.UUID) ([]Status, error) {
	rows, err := q.Query(ctx,
		`select status from operations where parent_id = $1`, parentID,
	)
	if err != nil {
		return nil, fmt.Errorf("list child statuses: %w", err)
	}
	defer rows.Close()

	var statuses []Status
	for rows.Next() {
		var st Status
		if err := rows.Scan(&st); err != nil {
			return nil, fmt.Errorf("scan child status: %w", err)
		}
		statuses = append(statuses, st)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list child statuses: %w", err)
	}
	return statuses, nil
}

// Approve переводит операцию из pending_approval в pending (approval
// workflow, ADR-0010): подтверждённая операция становится обычной pending и
// будет подхвачена уже поставленным в очередь job (worker снимает snooze,
// как только статус покидает pending_approval). Записывает approved_by,
// approved_at (now()) и decision_reason.
//
// Guard `status = pending_approval` делает вызов безопасным при гонках: если
// строка не в pending_approval, возвращается ErrStatusConflict (или
// ErrNotFound, если операции нет) — вызывающий отличает уже-подтверждённую/
// отклонённую операцию от отсутствующей. Идемпотентность повторного approve
// (двойной клик) разрешается вызывающим по текущему статусу.
func (s *Store) Approve(ctx context.Context, q Querier, id uuid.UUID, approver, reason string) (Operation, error) {
	return s.decide(ctx, q, id, StatusPending, &approver, reason, false)
}

// Reject переводит операцию из pending_approval в cancelled (терминальный
// отклонённый статус): операция никогда не выполнится. Записывает
// decision_reason и finished_at (cancelled — finished). approved_by не
// выставляется: колонка означает именно подтверждение, а «кто отклонил» —
// в append-only audit (operation.rejected). Guard — как в Approve.
func (s *Store) Reject(ctx context.Context, q Querier, id uuid.UUID, reason string) (Operation, error) {
	return s.decide(ctx, q, id, StatusCancelled, nil, reason, true)
}

// decide — общий guarded UPDATE approve/reject из pending_approval в to.
// approver != nil выставляет approved_by/approved_at (approve); finished
// выставляет finished_at (reject → cancelled терминален). Различает
// отсутствие строки (ErrNotFound) и несовпадение статуса (ErrStatusConflict).
func (s *Store) decide(ctx context.Context, q Querier, id uuid.UUID, to Status, approver *string, reason string, finished bool) (Operation, error) {
	op, err := scanOperation(q.QueryRow(ctx, `
		update operations set
			status = $2,
			approved_by = case when $3 then $4 else approved_by end,
			approved_at = case when $3 then now() else approved_at end,
			decision_reason = $5,
			finished_at = case when $6 then now() else finished_at end,
			updated_at = now()
		where id = $1 and status = $7
		returning `+operationColumns,
		id, to, approver != nil, approver, reason, finished, StatusPendingApproval,
	))
	if err == nil {
		return op, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Operation{}, fmt.Errorf("operations: decide %s -> %q: %w", id, to, err)
	}

	// Guard не сработал: различаем отсутствие строки и конфликт статуса.
	current, getErr := s.Get(ctx, q, id)
	if getErr != nil {
		return Operation{}, fmt.Errorf("operations: decide %s -> %q: %w", id, to, getErr)
	}
	return Operation{}, fmt.Errorf("operations: decide %s -> %q: current status %q: %w",
		id, to, current.Status, ErrStatusConflict)
}

// scanOperation читает одну строку operations в Operation. Порядок
// полей обязан совпадать с operationColumns.
func scanOperation(row pgx.Row) (Operation, error) {
	var op Operation
	err := row.Scan(
		&op.ID, &op.ParentID, &op.IdempotencyKey, &op.Kind, &op.Status,
		&op.ConnectionID, &op.PrincipalID, &op.AccountID, &op.ResourceID, &op.BindingID,
		&op.Payload, &op.Plan, &op.Result, &op.Error, &op.ActorType, &op.ActorID,
		&op.ApprovedBy, &op.ApprovedAt, &op.DecisionReason, &op.CorrelationID,
		&op.CreatedAt, &op.StartedAt, &op.FinishedAt, &op.ResolvedAt, &op.ResolvedBy,
		&op.UpdatedAt,
	)
	if err != nil {
		return Operation{}, err
	}
	return op, nil
}
