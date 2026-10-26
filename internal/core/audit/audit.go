// Package audit — запись и чтение audit trail grantor
// (docs/architecture.md, раздел 22). Таблица audit_events append-only:
// update/delete запрещены триггером схемы, поэтому Writer умеет только
// вставлять и читать. Metadata обязана быть sanitized: секретные
// значения в события не попадают никогда.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/readscope"
)

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

// Result values audit-события — значения колонки audit_events.result для
// штатного исхода и провала действия. Именованные константы вместо строковых
// литералов на местах эмита (api/jobs/maintenance): опечатка в исходе события
// контроля безопасности не проходит молча. Прочие исходы (например "alert" у
// security findings) задаются на месте — единого перечисления они не образуют.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// Event зеркалит строку таблицы audit_events. Ссылочные id — без FK:
// события переживают удаление ссылочных строк. Metadata — sanitized
// jsonb-документ; nil записывается пустым объектом.
type Event struct {
	ID           int64
	OccurredAt   time.Time
	ActorType    string
	ActorID      string
	Action       string
	ConnectionID *uuid.UUID
	ResourceID   *uuid.UUID
	PrincipalID  *uuid.UUID
	AccountID    *uuid.UUID
	OperationID  *uuid.UUID
	Result       string
	Metadata     []byte
}

// Writer — доступ к таблице audit_events. Не хранит соединение: Querier
// передаётся в каждый метод, чтобы событие можно было записать в одной
// транзакции с изменением, которое оно описывает. Zero value полностью
// работоспособен: без logger дублирование событий в structured log stream
// выключено (обратная совместимость и тихие тесты).
type Writer struct {
	// logger — необязательный канал дублирования записанных событий в
	// structured log stream (stdout) для внешнего экспорта в ELK/SIEM
	// (ADR-0007, раздел 22 архитектуры). nil = дублирование выключено.
	logger *slog.Logger
}

// NewWriter возвращает готовый к использованию Writer без дублирования
// событий в log stream. Дублирование включается через WithLogger.
func NewWriter() *Writer {
	return &Writer{}
}

// WithLogger включает дублирование записанных событий в structured log
// stream через переданный logger и возвращает тот же Writer (chained
// wiring в main, как executor.WithMutations). nil-logger оставляет
// дублирование выключенным.
func (w *Writer) WithLogger(logger *slog.Logger) *Writer {
	w.logger = logger
	return w
}

// Write вставляет событие. Поля ID и OccurredAt события игнорируются на
// входе в части генерации: id выдаёт база, нулевой OccurredAt
// заменяется now() на стороне базы.
//
// После успешного INSERT событие дублируется в structured log stream через
// LogEvent (no-op, если logger не задан). Компромисс канала: INSERT
// выполняется в транзакции вызывающего, а pgx не даёт after-commit hook,
// поэтому лог пишется до Commit вызывающего. Если Commit затем откатится
// (редко: audit.Write в наших обработчиках стоит последним перед Commit, и
// откатить его может лишь сбой самого Commit), в log stream уйдёт событие
// без строки в таблице. Это осознанно принято: источник истины —
// append-only таблица audit_events, а канал экспорта best-effort; для
// контроля R13 лишнее событие в SIEM (over-report) безопаснее пропуска
// (under-report). При ошибке самого INSERT событие не логируется.
func (w *Writer) Write(ctx context.Context, q Querier, e Event) error {
	if e.ActorType == "" || e.ActorID == "" {
		return errors.New("audit: write: actor type and actor id are required")
	}
	if e.Action == "" {
		return errors.New("audit: write: action is required")
	}
	var occurredAt *time.Time
	if !e.OccurredAt.IsZero() {
		occurredAt = &e.OccurredAt
	}
	metadata := e.Metadata
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}
	if _, err := q.Exec(ctx, `
		insert into audit_events (
			occurred_at, actor_type, actor_id, action,
			connection_id, resource_id, principal_id, account_id, operation_id,
			result, metadata
		) values (coalesce($1, now()), $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		occurredAt, e.ActorType, e.ActorID, e.Action,
		e.ConnectionID, e.ResourceID, e.PrincipalID, e.AccountID, e.OperationID,
		e.Result, metadata,
	); err != nil {
		return fmt.Errorf("audit: write %q: %w", e.Action, err)
	}
	w.LogEvent(ctx, e)
	return nil
}

// LogEvent дублирует одно событие в structured log stream (stdout) на
// уровне Info с атрибутом audit=true для инфраструктурного сбора в ELK/SIEM
// (ADR-0007, раздел 22 архитектуры). База не затрагивается. Writer без
// logger (nil) — no-op: обратная совместимость и отсутствие шума в тестах.
//
// Metadata события уже sanitized по контракту пакета (секреты в audit не
// попадают никогда), поэтому пишется как есть — вложенным JSON-объектом;
// пустая metadata нормализуется в "{}". Nil-указатели ссылочных id
// опускаются. Нулевой occurred_at заменяется временем вызова: у события,
// чей occurred_at проставляет база, лог-строка несёт близкое (в пределах
// микросекунд) время emit.
func (w *Writer) LogEvent(ctx context.Context, e Event) {
	if w.logger == nil {
		return
	}
	occurredAt := e.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	metadata := e.Metadata
	if len(metadata) == 0 {
		metadata = []byte("{}")
	}
	attrs := []slog.Attr{
		slog.Bool("audit", true),
		slog.String("action", e.Action),
		slog.String("actor_type", e.ActorType),
		slog.String("actor_id", e.ActorID),
		slog.String("result", e.Result),
		slog.Time("occurred_at", occurredAt),
	}
	if e.ConnectionID != nil {
		attrs = append(attrs, slog.String("connection_id", e.ConnectionID.String()))
	}
	if e.ResourceID != nil {
		attrs = append(attrs, slog.String("resource_id", e.ResourceID.String()))
	}
	if e.PrincipalID != nil {
		attrs = append(attrs, slog.String("principal_id", e.PrincipalID.String()))
	}
	if e.AccountID != nil {
		attrs = append(attrs, slog.String("account_id", e.AccountID.String()))
	}
	if e.OperationID != nil {
		attrs = append(attrs, slog.String("operation_id", e.OperationID.String()))
	}
	// json.RawMessage сериализуется slog-JSONHandler как вложенный объект
	// (реализует json.Marshaler), а не base64 как обычный []byte.
	attrs = append(attrs, slog.Any("metadata", json.RawMessage(metadata)))
	w.logger.LogAttrs(ctx, slog.LevelInfo, "audit event", attrs...)
}

// Filter — необязательные условия выборки событий. Nil-указатели, пустые
// строки и пустые списки означают отсутствие условия; заданные поля
// соединяются через AND.
type Filter struct {
	ReadScope    *readscope.Scope
	ConnectionID *uuid.UUID
	OperationID  *uuid.UUID
	AccountID    *uuid.UUID
	// Standalone оставляет только события, не принадлежащие ни одной
	// операции. Объединённая лента показывает операцию одной строкой, а её
	// собственные события — в детали операции, поэтому без этого условия
	// каждая операция попадала бы в ленту дважды.
	Standalone     bool
	Actions        []string
	ActorID        string
	OccurredFrom   *time.Time
	OccurredBefore *time.Time
}

// where собирает условия фильтра и их аргументы. Один сборщик на List и
// Count: расхождение выборки и её счётчика было бы невидимым для тестов
// каждого метода по отдельности.
func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	addCond := func(format string, value any) {
		args = append(args, value)
		conds = append(conds, fmt.Sprintf(format, len(args)))
	}
	if f.ConnectionID != nil {
		addCond("connection_id = $%d", *f.ConnectionID)
	}
	if f.OperationID != nil {
		addCond("operation_id = $%d", *f.OperationID)
	}
	if f.AccountID != nil {
		addCond("account_id = $%d", *f.AccountID)
	}
	if f.Standalone {
		conds = append(conds, "operation_id is null")
	}
	if len(f.Actions) > 0 {
		addCond("action = any($%d)", f.Actions)
	}
	if f.ActorID != "" {
		addCond("actor_id = $%d", f.ActorID)
	}
	if f.OccurredFrom != nil {
		addCond("occurred_at >= $%d", *f.OccurredFrom)
	}
	if f.OccurredBefore != nil {
		addCond("occurred_at < $%d", *f.OccurredBefore)
	}
	if f.ReadScope != nil {
		conds = append(conds, f.ReadScope.Audit("audit_events", &args))
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " where " + strings.Join(conds, " and "), args
}

// Count возвращает число событий, попадающих под фильтр, без учёта
// limit/offset.
func (w *Writer) Count(ctx context.Context, q Querier, f Filter) (int64, error) {
	where, args := f.where()
	var total int64
	if err := q.QueryRow(ctx, `select count(*) from audit_events`+where, args...).Scan(&total); err != nil {
		return 0, fmt.Errorf("audit: count: %w", err)
	}
	return total, nil
}

// List возвращает события по фильтру от новых к старым. limit <= 0
// заменяется значением 100, отрицательный offset — нулём.
func (w *Writer) List(ctx context.Context, q Querier, f Filter, limit, offset int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	where, args := f.where()
	sql := `select id, occurred_at, actor_type, actor_id, action,
		connection_id, resource_id, principal_id, account_id, operation_id,
		result, metadata
	from audit_events` + where
	args = append(args, limit)
	sql += fmt.Sprintf(" order by occurred_at desc, id desc limit $%d", len(args))
	args = append(args, offset)
	sql += fmt.Sprintf(" offset $%d", len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var metadata []byte
		if err := rows.Scan(
			&e.ID, &e.OccurredAt, &e.ActorType, &e.ActorID, &e.Action,
			&e.ConnectionID, &e.ResourceID, &e.PrincipalID, &e.AccountID, &e.OperationID,
			&e.Result, &metadata,
		); err != nil {
			return nil, fmt.Errorf("audit: list: scan: %w", err)
		}
		e.Metadata = metadata
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	return events, nil
}
