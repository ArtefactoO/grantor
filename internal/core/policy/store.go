package policy

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrNotFound возвращается, когда scope policy с указанным id не
	// существует.
	ErrNotFound = errors.New("policy: scope policy not found")
	// ErrAlreadyExists возвращается, когда политика с той же тройкой
	// (subject_kind, subject, environment) уже заведена.
	ErrAlreadyExists = errors.New("policy: scope policy already exists")
)

// pgUniqueViolation — SQLSTATE-код PostgreSQL нарушения уникальности,
// который Create переводит в ErrAlreadyExists.
const pgUniqueViolation = "23505"

// Querier — минимальный контракт выполнения запросов pgx; ему удовлетворяют
// и *pgxpool.Pool, и pgx.Tx. Интерфейс объявлен локально (а не импортирован
// из других core-пакетов), чтобы пакеты ядра не зависели друг от друга:
// структурная типизация Go делает локальные копии взаимозаменяемыми.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблице scope_policies. Не хранит соединение: Querier
// передаётся в каждый метод, чтобы вызывающий управлял транзакциями. Zero
// value полностью работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// scopePolicyColumns — список колонок scope_policies, согласованный со
// scanScopePolicy.
const scopePolicyColumns = `id, subject_kind, subject, environment, created_at`

// scanScopePolicy читает одну строку scope_policies; порядок полей обязан
// совпадать с scopePolicyColumns.
func scanScopePolicy(row pgx.Row) (ScopePolicy, error) {
	var p ScopePolicy
	if err := row.Scan(&p.ID, &p.SubjectKind, &p.Subject, &p.Environment, &p.CreatedAt); err != nil {
		return ScopePolicy{}, err
	}
	return p, nil
}

// CreateParams — параметры создания scope policy.
type CreateParams struct {
	SubjectKind string
	Subject     string
	Environment string
}

// Create создаёт scope policy и возвращает созданную строку. subject_kind
// обязан входить в допустимые значения, subject и environment — быть
// непустыми; проверки выполняются до обращения к базе. Дубликат тройки —
// ErrAlreadyExists.
func (s *Store) Create(ctx context.Context, q Querier, params CreateParams) (ScopePolicy, error) {
	if !ValidSubjectKind(params.SubjectKind) {
		return ScopePolicy{}, fmt.Errorf("policy: create: invalid subject kind %q", params.SubjectKind)
	}
	if params.Subject == "" {
		return ScopePolicy{}, errors.New("policy: create: subject is required")
	}
	if params.Environment == "" {
		return ScopePolicy{}, errors.New("policy: create: environment is required")
	}

	p, err := scanScopePolicy(q.QueryRow(ctx, `
		insert into scope_policies (subject_kind, subject, environment)
		values ($1, $2, $3)
		returning `+scopePolicyColumns,
		params.SubjectKind, params.Subject, params.Environment,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return ScopePolicy{}, fmt.Errorf(
				"policy: create: policy for %s/%s in %q already exists: %w",
				params.SubjectKind, params.Subject, params.Environment, ErrAlreadyExists)
		}
		return ScopePolicy{}, fmt.Errorf("policy: create: %w", err)
	}
	return p, nil
}

// List возвращает все scope policies в детерминированном порядке.
func (s *Store) List(ctx context.Context, q Querier) ([]ScopePolicy, error) {
	rows, err := q.Query(ctx,
		`select `+scopePolicyColumns+` from scope_policies
		 order by subject_kind, subject, environment`)
	if err != nil {
		return nil, fmt.Errorf("policy: list: %w", err)
	}
	defer rows.Close()

	var out []ScopePolicy
	for rows.Next() {
		p, err := scanScopePolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("policy: list: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("policy: list: %w", err)
	}
	return out, nil
}

// Delete удаляет scope policy по id. Несуществующий id — ErrNotFound.
func (s *Store) Delete(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `delete from scope_policies where id = $1`, id)
	if err != nil {
		return fmt.Errorf("policy: delete %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy: delete %s: %w", id, ErrNotFound)
	}
	return nil
}

// AllowedEnvironments возвращает окружения, разрешённые роли role и, если
// principalID непустой, — конкретному принципалу. Собираются политики
// subject_kind='role' с subject=role И subject_kind='principal' с
// subject=principalID; значение '*' среди них даёт allowAll=true (доступ ко
// всем окружениям). Пустой principalID (человек-operator без grantor-
// принципала) отбирает только role-политики.
//
// Пустой результат при allowAll=false — валидное состояние: у operator нет ни
// одной политики, и в режиме enforce это означает deny-by-default (решение
// принимает вызывающий, см. internal/api).
func (s *Store) AllowedEnvironments(ctx context.Context, q Querier, role, principalID string) (allowed []string, allowAll bool, err error) {
	rows, err := q.Query(ctx, `
		select environment from scope_policies
		where (subject_kind = $1 and subject = $2)
		   or (subject_kind = $3 and subject = $4)`,
		SubjectRole, role, SubjectPrincipal, principalID)
	if err != nil {
		return nil, false, fmt.Errorf("policy: allowed environments: %w", err)
	}
	defer rows.Close()

	var environments []string
	for rows.Next() {
		var env string
		if err := rows.Scan(&env); err != nil {
			return nil, false, fmt.Errorf("policy: allowed environments: scan: %w", err)
		}
		environments = append(environments, env)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("policy: allowed environments: %w", err)
	}
	allowed, allowAll = resolveAllowed(environments)
	return allowed, allowAll, nil
}
