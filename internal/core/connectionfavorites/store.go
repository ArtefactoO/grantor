// Package connectionfavorites stores identity-owned catalog preferences, never
// authority. Every read must still intersect the caller's current connection scope.
package connectionfavorites

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

type Store struct{}

func NewStore() *Store { return &Store{} }

// User ownership includes the verified directory identity epoch. Rebinding an
// issuer/subject to a different directory UID cannot inherit a previous person's
// preferences. Service credentials share their stable service-principal owner.
type Owner struct {
	UserID              *uuid.UUID
	UserIdentityBoundAt *time.Time
	ServicePrincipalID  *uuid.UUID
}

var ErrInvalidOwner = errors.New("connection favorites: invalid owner")

func (o Owner) valid() bool {
	user := o.UserID != nil && *o.UserID != uuid.Nil && o.UserIdentityBoundAt != nil && !o.UserIdentityBoundAt.IsZero() && o.ServicePrincipalID == nil
	service := o.ServicePrincipalID != nil && *o.ServicePrincipalID != uuid.Nil && o.UserID == nil && o.UserIdentityBoundAt == nil
	return user || service
}

const ownerPredicate = `((f.user_id=$1 and f.user_identity_bound_at=$2) or f.service_principal_id=$3)`

// List returns only currently visible connection IDs, including after a scope
// policy or connection environment changes. It never returns owner metadata.
func (s *Store) List(ctx context.Context, q Querier, owner Owner, environments []string, allEnvironments bool) ([]uuid.UUID, error) {
	if !owner.valid() {
		return nil, ErrInvalidOwner
	}
	rows, err := q.Query(ctx, `select f.connection_id from connection_favorites f
	join connections c on c.id=f.connection_id where `+ownerPredicate+`
	and ($4::boolean or c.environment=any($5::text[])) order by f.connection_id`,
		owner.UserID, owner.UserIdentityBoundAt, owner.ServicePrincipalID, allEnvironments, environments)
	if err != nil {
		return nil, fmt.Errorf("connection favorites: list: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("connection favorites: scan: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("connection favorites: list rows: %w", err)
	}
	return ids, nil
}

// Set is idempotent. Callers authorize and lock the connection before mutation.
func (s *Store) Set(ctx context.Context, q Querier, owner Owner, connectionID uuid.UUID, favorite bool) error {
	if !owner.valid() {
		return ErrInvalidOwner
	}
	var err error
	if favorite {
		_, err = q.Exec(ctx, `insert into connection_favorites(user_id,user_identity_bound_at,service_principal_id,connection_id)
		values($1,$2,$3,$4) on conflict do nothing`, owner.UserID, owner.UserIdentityBoundAt, owner.ServicePrincipalID, connectionID)
	} else {
		_, err = q.Exec(ctx, `delete from connection_favorites f where `+ownerPredicate+` and f.connection_id=$4`,
			owner.UserID, owner.UserIdentityBoundAt, owner.ServicePrincipalID, connectionID)
	}
	if err != nil {
		return fmt.Errorf("connection favorites: set: %w", err)
	}
	return nil
}
