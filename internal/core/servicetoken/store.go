package servicetoken

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/principals"
)

var (
	// ErrNotFound возвращается, когда токен с указанным id не существует.
	ErrNotFound = errors.New("servicetoken: token not found")
	// ErrInvalidToken возвращается, когда токен не найден, отозван, либо
	// принадлежит не-service или неактивному принципалу. Один код на все
	// причины: не даём оракул о том, какая проверка не прошла.
	ErrInvalidToken = errors.New("servicetoken: invalid token")
	// ErrPrincipalNotFound возвращается Create, когда принципал не существует
	// (нарушение внешнего ключа).
	ErrPrincipalNotFound = errors.New("servicetoken: principal not found")
)

// SQLSTATE-коды PostgreSQL, которые Store переводит в доменные ошибки.
const (
	pgForeignKeyViolation = "23503"
)

// Querier — минимальный контракт выполнения запросов pgx; ему удовлетворяют
// и *pgxpool.Pool, и pgx.Tx. Интерфейс объявлен локально, чтобы пакеты ядра
// не зависели друг от друга (структурная типизация Go).
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store — доступ к таблице service_tokens. Не хранит соединение: Querier
// передаётся в каждый метод. Zero value полностью работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// Token зеркалит несекретную часть строки service_tokens. token_hash в модель
// не входит: его значение наружу не отдаётся никогда.
type Token struct {
	ID          uuid.UUID
	PrincipalID uuid.UUID
	Name        string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
	Permissions []string
}

// tokenColumns — список несекретных колонок service_tokens (без token_hash),
// согласованный со scanToken.
const tokenColumns = `id, principal_id, name, created_at, last_used_at, revoked_at, permissions`

// scanToken читает одну строку service_tokens (без token_hash); порядок полей
// обязан совпадать с tokenColumns.
func scanToken(row pgx.Row) (Token, error) {
	var t Token
	if err := row.Scan(&t.ID, &t.PrincipalID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt, &t.Permissions); err != nil {
		return Token{}, err
	}
	return t, nil
}

// Create выпускает токен для принципала и возвращает plaintext-токен (ОДИН
// раз) и его запись. Тип принципала (service) проверяет вызывающий (API);
// Store лишь принимает уже проверенный id и хранит sha256-хекс токена.
// Несуществующий принципал — ErrPrincipalNotFound.
func (s *Store) Create(ctx context.Context, q Querier, principalID uuid.UUID, name string, grants ...[]string) (string, Token, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", Token{}, errors.New("servicetoken: create: name is required")
	}
	permissions := []string{}
	if len(grants) > 1 {
		return "", Token{}, errors.New("servicetoken: invalid permissions")
	}
	if len(grants) == 1 {
		permissions = append(permissions, grants[0]...)
	}
	for _, permission := range permissions {
		if permission != PermissionCreateConnections {
			return "", Token{}, errors.New("servicetoken: unknown permission")
		}
	}
	slices.Sort(permissions)
	permissions = slices.Compact(permissions)
	token, err := GenerateToken()
	if err != nil {
		return "", Token{}, fmt.Errorf("servicetoken: create: %w", err)
	}

	rec, err := scanToken(q.QueryRow(ctx, `
		insert into service_tokens (principal_id, name, token_hash, permissions)
		values ($1, $2, $3, $4)
		returning `+tokenColumns,
		principalID, name, HashToken(token), permissions,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation {
			return "", Token{}, fmt.Errorf("servicetoken: create for %s: %w", principalID, ErrPrincipalNotFound)
		}
		return "", Token{}, fmt.Errorf("servicetoken: create for %s: %w", principalID, err)
	}
	return token, rec, nil
}

// List возвращает токены (без секретов) в порядке от новых к старым. Непустой
// principalID ограничивает выборку токенами одного принципала.
func (s *Store) List(ctx context.Context, q Querier, principalID *uuid.UUID) ([]Token, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if principalID != nil {
		rows, err = q.Query(ctx,
			`select `+tokenColumns+` from service_tokens
			 where principal_id = $1
			 order by created_at desc, id`, *principalID)
	} else {
		rows, err = q.Query(ctx,
			`select `+tokenColumns+` from service_tokens
			 order by created_at desc, id`)
	}
	if err != nil {
		return nil, fmt.Errorf("servicetoken: list: %w", err)
	}
	defer rows.Close()

	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("servicetoken: list: scan: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("servicetoken: list: %w", err)
	}
	return out, nil
}

// Revoke помечает токен отозванным (revoked_at). Идемпотентна: повторный
// вызов сохраняет первоначальное время отзыва. Несуществующий id —
// ErrNotFound.
func (s *Store) Revoke(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx,
		`update service_tokens set revoked_at = coalesce(revoked_at, now()) where id = $1`, id)
	if err != nil {
		return fmt.Errorf("servicetoken: revoke %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("servicetoken: revoke %s: %w", id, ErrNotFound)
	}
	return nil
}

// Authenticate проверяет plaintext-токен и возвращает принципала-владельца.
// Токен обязан начинаться с TokenPrefix, быть не отозванным (revoked_at is
// null) и принадлежать активному принципалу type=service. При успехе
// обновляется last_used_at. Любая непройденная проверка — ErrInvalidToken
// (без различения причины, чтобы не давать оракул).
func (s *Store) Authenticate(ctx context.Context, q Querier, token string) (principals.Principal, error) {
	p, _, err := s.AuthenticateWithPermissions(ctx, q, token)
	return p, err
}

// PermissionCreateConnections is delegated explicitly by an interactive admin.
const PermissionCreateConnections = "connections:create"

// AuthenticateWithPermissions returns only grants stored with the credential.
func (s *Store) AuthenticateWithPermissions(ctx context.Context, q Querier, token string) (principals.Principal, []string, error) {
	if !HasTokenPrefix(token) {
		return principals.Principal{}, nil, ErrInvalidToken
	}

	// UPDATE ... FROM обновляет last_used_at и возвращает принципала одним
	// запросом; фильтры отсекают отозванные токены и не-service/неактивных
	// принципалов.
	var (
		p           principals.Principal
		attrs       []byte
		permissions []string
	)
	err := q.QueryRow(ctx, `
		update service_tokens st
		set last_used_at = now()
		from principals p
		where st.token_hash = $1
		  and st.revoked_at is null
		  and p.id = st.principal_id
		  and p.type = 'service'
		  and p.status = 'active'
		returning p.id, p.type, p.display_name, p.external_provider, p.external_subject,
		          p.status, p.attributes, p.created_at, p.updated_at, st.permissions`,
		HashToken(token),
	).Scan(
		&p.ID, &p.Type, &p.DisplayName, &p.ExternalProvider, &p.ExternalSubject,
		&p.Status, &attrs, &p.CreatedAt, &p.UpdatedAt, &permissions,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return principals.Principal{}, nil, ErrInvalidToken
		}
		return principals.Principal{}, nil, fmt.Errorf("servicetoken: authenticate: %w", err)
	}
	p.Attributes = attrs
	return p, permissions, nil
}
