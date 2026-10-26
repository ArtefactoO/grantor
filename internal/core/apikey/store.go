package apikey

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/auth"
)

type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Store struct{}

func NewStore() *Store { return &Store{} }

type User struct {
	ID                                                                      uuid.UUID
	Issuer, Subject, Username, DirectoryUID, Email                          string
	Role                                                                    auth.Role
	Active, DirectoryManaged                                                bool
	AuthorizedUntil, AuthenticatedAt, IdentityBoundAt, CreatedAt, UpdatedAt time.Time
}

type Key struct {
	ID, UserID            uuid.UUID
	Name                  string
	Role                  auth.Role
	Environments          []string
	ExpiresAt, CreatedAt  time.Time
	LastUsedAt, RevokedAt *time.Time
}

const userColumns = `id, issuer, subject, username, directory_uid, email, role, active,
directory_managed, authorized_until, authenticated_at, identity_bound_at, created_at, updated_at`
const keyColumns = `id, user_id, name, role, environments, expires_at, created_at, last_used_at, revoked_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Username, &u.DirectoryUID, &u.Email, &u.Role, &u.Active,
		&u.DirectoryManaged, &u.AuthorizedUntil, &u.AuthenticatedAt, &u.IdentityBoundAt, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}
func scanKey(row pgx.Row) (Key, error) {
	var k Key
	err := row.Scan(&k.ID, &k.UserID, &k.Name, &k.Role, &k.Environments, &k.ExpiresAt, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	return k, err
}

func (s *Store) GetUser(ctx context.Context, q Querier, issuer, subject string) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `select `+userColumns+` from api_users where issuer=$1 and subject=$2`, issuer, subject))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("apikey: get owner: %w", err)
	}
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, q Querier, id uuid.UUID) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `select `+userColumns+` from api_users where id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("apikey: get owner by id: %w", err)
	}
	return u, nil
}

// Login callers serialize by issuer/subject before invoking this method. A
// reassigned directory identity never inherits keys from the previous person.
func (s *Store) SaveLogin(ctx context.Context, q Querier, u User) (User, error) {
	previous, err := s.GetUser(ctx, q, u.Issuer, u.Subject)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return User{}, err
	}
	if err == nil {
		u.IdentityBoundAt = previous.IdentityBoundAt
		if previous.DirectoryUID != u.DirectoryUID || previous.DirectoryManaged != u.DirectoryManaged {
			if err := s.RevokeUser(ctx, q, previous.ID); err != nil {
				return User{}, err
			}
			u.IdentityBoundAt = u.AuthenticatedAt
		}
	}
	if u.IdentityBoundAt.IsZero() {
		u.IdentityBoundAt = u.AuthenticatedAt
	}
	saved, err := scanUser(q.QueryRow(ctx, `insert into api_users
	(issuer,subject,username,directory_uid,email,role,active,directory_managed,authorized_until,authenticated_at,identity_bound_at)
	values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	on conflict(issuer,subject) do update set username=excluded.username,directory_uid=excluded.directory_uid,
	email=excluded.email,role=excluded.role,active=excluded.active,directory_managed=excluded.directory_managed,
	authorized_until=excluded.authorized_until,authenticated_at=excluded.authenticated_at,
	identity_bound_at=excluded.identity_bound_at,updated_at=now() returning `+userColumns,
		u.Issuer, u.Subject, u.Username, u.DirectoryUID, u.Email, u.Role, u.Active, u.DirectoryManaged,
		u.AuthorizedUntil, u.AuthenticatedAt, u.IdentityBoundAt))
	if err != nil {
		return User{}, fmt.Errorf("apikey: save owner login: %w", err)
	}
	return saved, nil
}

func (s *Store) ListManagedUsers(ctx context.Context, q Querier, issuer string) ([]User, error) {
	rows, err := q.Query(ctx, `select `+userColumns+` from api_users u where directory_managed and issuer=$1
	and exists(select 1 from personal_api_keys k where k.user_id=u.id and k.revoked_at is null and k.expires_at>now())
	order by authorized_until,id limit 256`, issuer)
	if err != nil {
		return nil, fmt.Errorf("apikey: list owner refresh: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Refresh uses the previous immutable UID as a compare-and-set guard against
// a concurrent fresh login replacing the directory identity.
func (s *Store) Refresh(ctx context.Context, q Querier, u User, active bool, role auth.Role, email string, until time.Time) error {
	_, err := q.Exec(ctx, `update api_users set active=$3,role=$4,email=$5,authorized_until=$6,updated_at=now()
	where id=$1 and directory_uid=$2`, u.ID, u.DirectoryUID, active, role, email, until)
	if err != nil {
		return fmt.Errorf("apikey: refresh owner: %w", err)
	}
	return nil
}

func (s *Store) LockUser(ctx context.Context, q Querier, id uuid.UUID) (User, error) {
	u, err := scanUser(q.QueryRow(ctx, `select `+userColumns+` from api_users where id=$1 for update`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("apikey: lock owner: %w", err)
	}
	return u, nil
}

type CreateParams struct {
	UserID       uuid.UUID
	Name         string
	Role         auth.Role
	Environments []string
	ExpiresAt    time.Time
}

func (s *Store) Create(ctx context.Context, q Querier, p CreateParams) (string, Key, error) {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || utf8.RuneCountInString(p.Name) > 128 || !p.Role.Allows(auth.RoleViewer) || !p.ExpiresAt.After(time.Now()) ||
		p.ExpiresAt.After(time.Now().Add(MaximumLifetime)) || (p.Environments != nil && len(p.Environments) == 0) {
		return "", Key{}, ErrInvalidParams
	}
	token, err := GenerateToken()
	if err != nil {
		return "", Key{}, fmt.Errorf("apikey: generate: %w", err)
	}
	key, err := scanKey(q.QueryRow(ctx, `insert into personal_api_keys(user_id,name,token_hash,role,environments,expires_at)
	select id,$2,$3,$4,$5,$6 from api_users where id=$1 and active and authorized_until>now()
	and (directory_managed or $6::timestamptz<=authorized_until)
	and case role when 'admin' then 3 when 'operator' then 2 when 'viewer' then 1 else 0 end >=
	case $4::text when 'admin' then 3 when 'operator' then 2 when 'viewer' then 1 else 0 end
	returning `+keyColumns, p.UserID, p.Name, HashToken(token), p.Role, p.Environments, p.ExpiresAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return "", Key{}, ErrOwnerUnavailable
	}
	if err != nil {
		return "", Key{}, fmt.Errorf("apikey: create: %w", err)
	}
	return token, key, nil
}

func (s *Store) List(ctx context.Context, q Querier, userID uuid.UUID) ([]Key, error) {
	rows, err := q.Query(ctx, `select `+keyColumns+` from personal_api_keys where user_id=$1 order by created_at desc,id`, userID)
	if err != nil {
		return nil, fmt.Errorf("apikey: list: %w", err)
	}
	defer rows.Close()
	keys := make([]Key, 0)
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *Store) Revoke(ctx context.Context, q Querier, userID, keyID uuid.UUID) error {
	tag, err := q.Exec(ctx, `update personal_api_keys set revoked_at=coalesce(revoked_at,now()) where id=$1 and user_id=$2`, keyID, userID)
	if err != nil {
		return fmt.Errorf("apikey: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
func (s *Store) RevokeUser(ctx context.Context, q Querier, userID uuid.UUID) error {
	_, err := q.Exec(ctx, `update personal_api_keys set revoked_at=coalesce(revoked_at,now()) where user_id=$1`, userID)
	if err != nil {
		return fmt.Errorf("apikey: revoke owner keys: %w", err)
	}
	return nil
}

type Authentication struct {
	User         User
	KeyID        uuid.UUID
	Role         auth.Role
	Environments []string
	ExpiresAt    time.Time
}

func (s *Store) Authenticate(ctx context.Context, q Querier, token string) (Authentication, error) {
	if !HasTokenPrefix(token) {
		return Authentication{}, ErrInvalidToken
	}
	var a Authentication
	var ceiling auth.Role
	err := q.QueryRow(ctx, `update personal_api_keys k set last_used_at=now() from api_users u
	where k.token_hash=$1 and k.revoked_at is null and k.expires_at>now()
	and u.id=k.user_id and u.active and u.authorized_until>now() and u.role in ('viewer','operator','admin')
	returning k.id,k.role,k.environments,k.expires_at,u.id,u.issuer,u.subject,u.username,u.email,u.role`, HashToken(token)).Scan(
		&a.KeyID, &ceiling, &a.Environments, &a.ExpiresAt, &a.User.ID, &a.User.Issuer, &a.User.Subject, &a.User.Username, &a.User.Email, &a.User.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Authentication{}, ErrInvalidToken
	}
	if err != nil {
		return Authentication{}, fmt.Errorf("apikey: authenticate: %w", err)
	}
	a.Role = EffectiveRole(a.User.Role, ceiling)
	if a.Role == "" {
		return Authentication{}, ErrInvalidToken
	}
	return a, nil
}
