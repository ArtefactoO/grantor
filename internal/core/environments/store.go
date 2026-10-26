// Package environments — реестр окружений (таблица environments).
//
// Реестр аддитивен к connections.environment: он позволяет заводить
// окружение до первого подключения (например, чтобы заранее подготовить
// env-credential принципала). Списки окружений в API строятся объединением
// реестра и фактических подключений.
package environments

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrAlreadyExists возвращается при создании окружения с занятым именем.
var ErrAlreadyExists = errors.New("environments: environment already exists")

// pgUniqueViolation — SQLSTATE-код PostgreSQL нарушения уникальности.
const pgUniqueViolation = "23505"

// Querier — минимальный контракт выполнения запросов pgx; локальная копия,
// чтобы core-пакеты не зависели друг от друга.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Environment — одна строка реестра.
type Environment struct {
	Name      string
	CreatedAt time.Time
}

// Store — доступ к таблице environments. Zero value работоспособен.
type Store struct{}

// NewStore возвращает готовый к использованию Store.
func NewStore() *Store {
	return &Store{}
}

// Create добавляет окружение в реестр. Имя обязано быть непустым; валидация
// формата (Vault-сегмент, без '/') выполняется на уровне API. Занятое имя —
// ErrAlreadyExists.
func (s *Store) Create(ctx context.Context, q Querier, name string) (Environment, error) {
	if name == "" {
		return Environment{}, errors.New("environments: create: name is required")
	}
	var env Environment
	err := q.QueryRow(ctx, `
		insert into environments (name)
		values ($1)
		returning name, created_at`, name,
	).Scan(&env.Name, &env.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return Environment{}, fmt.Errorf("environments: create %q: %w", name, ErrAlreadyExists)
		}
		return Environment{}, fmt.Errorf("environments: create %q: %w", name, err)
	}
	return env, nil
}

// List возвращает реестр в алфавитном порядке.
func (s *Store) List(ctx context.Context, q Querier) ([]Environment, error) {
	rows, err := q.Query(ctx, `select name, created_at from environments order by name`)
	if err != nil {
		return nil, fmt.Errorf("environments: list: %w", err)
	}
	defer rows.Close()

	var out []Environment
	for rows.Next() {
		var env Environment
		if err := rows.Scan(&env.Name, &env.CreatedAt); err != nil {
			return nil, fmt.Errorf("environments: list: scan: %w", err)
		}
		out = append(out, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("environments: list: %w", err)
	}
	return out, nil
}
