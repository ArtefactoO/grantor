package connectionregistration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/readscope"
)

type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Store struct{}

func NewStore() *Store { return &Store{} }

const sourceColumns = `id, name, owner_type, owner_id, environment, target_spec, version, status, cleanup_pending, created_at, updated_at, revoked_at`
const registrationColumns = `id, owner_type, owner_id, registration_key, environment, spec, coalesce(credential_source_id, '00000000-0000-0000-0000-000000000000'::uuid), credential_source_version, connection_id, operation_id, phase, canonical_version, created_at, updated_at`

func scanSource(row pgx.Row) (Source, error) {
	var s Source
	err := row.Scan(&s.ID, &s.Name, &s.Owner.Type, &s.Owner.ID, &s.Environment, &s.TargetSpec, &s.Version, &s.Status, &s.CleanupPending, &s.CreatedAt, &s.UpdatedAt, &s.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Source{}, ErrNotFound
	}
	return s, err
}

func scanRegistration(row pgx.Row) (Registration, error) {
	var r Registration
	err := row.Scan(&r.ID, &r.Owner.Type, &r.Owner.ID, &r.RegistrationKey, &r.Environment, &r.Spec, &r.CredentialSourceID, &r.CredentialSourceVersion, &r.ConnectionID, &r.OperationID, &r.Phase, &r.CanonicalVersion, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, ErrNotFound
	}
	return r, err
}

// LockOwner uses a separate two-int advisory namespace, so it cannot collide
// with worker per-connection bigint locks. Hash collisions only serialize.
func (s *Store) LockOwner(ctx context.Context, q Querier, owner Owner) error {
	h := fnv.New32a()
	_, _ = h.Write([]byte(owner.Type + ":" + owner.ID.String()))
	_, err := q.Exec(ctx, `select pg_advisory_xact_lock($1::integer, $2::integer)`, int32(0x4752_5247), int32(h.Sum32()))
	if err != nil {
		return fmt.Errorf("connection registration: lock owner: %w", err)
	}
	return nil
}

func (s *Store) CreateSource(ctx context.Context, q Querier, p Source) (Source, error) {
	if p.ID == uuid.Nil || !p.Owner.Valid() || p.Name == "" || p.Environment == "" || !json.Valid(p.TargetSpec) {
		return Source{}, errors.New("connection registration: invalid source")
	}
	return scanSource(q.QueryRow(ctx, `insert into connection_credential_sources(id,name,owner_type,owner_id,environment,target_spec) values($1,$2,$3,$4,$5,$6) returning `+sourceColumns, p.ID, p.Name, p.Owner.Type, p.Owner.ID, p.Environment, p.TargetSpec))
}

func (s *Store) GetSource(ctx context.Context, q Querier, id uuid.UUID, lock bool) (Source, error) {
	query := `select ` + sourceColumns + ` from connection_credential_sources where id=$1`
	if lock {
		query += ` for update`
	}
	return scanSource(q.QueryRow(ctx, query, id))
}

func (s *Store) FinalizeSource(ctx context.Context, q Querier, id uuid.UUID, version int) (Source, error) {
	if version <= 0 {
		return Source{}, errors.New("connection registration: invalid source version")
	}
	return scanSource(q.QueryRow(ctx, `update connection_credential_sources set version=$2,status='active',updated_at=now() where id=$1 and status='preparing' returning `+sourceColumns, id, version))
}

func (s *Store) ListSources(ctx context.Context, q Querier, owner *Owner) ([]Source, error) {
	query, args := `select `+sourceColumns+` from connection_credential_sources`, []any{}
	if owner != nil {
		query += ` where owner_type=$1 and owner_id=$2`
		args = append(args, owner.Type, owner.ID)
	}
	query += ` order by created_at desc,id limit 500`
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("connection registration: list sources: %w", err)
	}
	defer rows.Close()
	out := make([]Source, 0)
	for rows.Next() {
		source, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	return out, rows.Err()
}

func (s *Store) RevokeSource(ctx context.Context, q Querier, id uuid.UUID) (Source, error) {
	return scanSource(q.QueryRow(ctx, `update connection_credential_sources set status='revoked',revoked_at=coalesce(revoked_at,now()),cleanup_pending=true,updated_at=now() where id=$1 returning `+sourceColumns, id))
}

func (s *Store) ClearSourceCleanup(ctx context.Context, q Querier, id uuid.UUID) error {
	_, err := q.Exec(ctx, `update connection_credential_sources set cleanup_pending=false,updated_at=now() where id=$1 and status='revoked'`, id)
	return err
}

type ReserveParams struct {
	Owner                   Owner
	RequestID               uuid.UUID
	RegistrationKey         string
	Environment             string
	Spec                    json.RawMessage
	CredentialSourceID      uuid.UUID
	CredentialSourceVersion int
}

func sameIntent(r Registration, p ReserveParams) bool {
	if r.RegistrationKey != p.RegistrationKey || r.Environment != p.Environment || r.CredentialSourceID != p.CredentialSourceID || r.CredentialSourceVersion != p.CredentialSourceVersion {
		return false
	}
	var a, b any
	return json.Unmarshal(r.Spec, &a) == nil && json.Unmarshal(p.Spec, &b) == nil && reflect.DeepEqual(a, b)
}

// Reserve must run under LockOwner. An alias binds every request UUID to the
// immutable registration, including later runs which reuse the stable key.
func (s *Store) Reserve(ctx context.Context, q Querier, p ReserveParams) (Registration, bool, error) {
	if !p.Owner.Valid() || p.RequestID == uuid.Nil || p.RegistrationKey == "" || p.Environment == "" || !validRegistrationCredential(p.Spec, p.CredentialSourceID, p.CredentialSourceVersion) || !json.Valid(p.Spec) {
		return Registration{}, false, errors.New("connection registration: invalid reservation")
	}
	var existingID uuid.UUID
	err := q.QueryRow(ctx, `select registration_id from connection_registration_requests where owner_type=$1 and owner_id=$2 and request_id=$3`, p.Owner.Type, p.Owner.ID, p.RequestID).Scan(&existingID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Registration{}, false, err
	}
	if err == nil {
		r, err := s.Get(ctx, q, existingID)
		if err != nil {
			return Registration{}, false, err
		}
		if !sameIntent(r, p) {
			return Registration{}, false, ErrConflict
		}
		return r, false, nil
	}
	r, err := scanRegistration(q.QueryRow(ctx, `select `+registrationColumns+` from connection_registrations where owner_type=$1 and owner_id=$2 and registration_key=$3`, p.Owner.Type, p.Owner.ID, p.RegistrationKey))
	created := false
	if errors.Is(err, ErrNotFound) {
		r, err = scanRegistration(q.QueryRow(ctx, `insert into connection_registrations(id,owner_type,owner_id,registration_key,environment,spec,credential_source_id,credential_source_version,connection_id,operation_id) values($1,$2,$3,$4,$5,$6,nullif($7::uuid, '00000000-0000-0000-0000-000000000000'::uuid),$8,$9,$10) returning `+registrationColumns, uuid.New(), p.Owner.Type, p.Owner.ID, p.RegistrationKey, p.Environment, p.Spec, p.CredentialSourceID, p.CredentialSourceVersion, uuid.New(), uuid.New()))
		created = true
	}
	if err != nil {
		return Registration{}, false, err
	}
	if !sameIntent(r, p) {
		return Registration{}, false, ErrConflict
	}
	_, err = q.Exec(ctx, `insert into connection_registration_requests(owner_type,owner_id,request_id,registration_id) values($1,$2,$3,$4)`, p.Owner.Type, p.Owner.ID, p.RequestID, r.ID)
	return r, created, err
}

func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Registration, error) {
	return scanRegistration(q.QueryRow(ctx, `select `+registrationColumns+` from connection_registrations where id=$1`, id))
}

func (s *Store) List(ctx context.Context, q Querier, owner Owner, limit, offset int) ([]Registration, error) {
	return s.ListVisible(ctx, q, &owner, nil, limit, offset)
}

func (s *Store) ListAll(ctx context.Context, q Querier, limit, offset int) ([]Registration, error) {
	return s.ListVisible(ctx, q, nil, nil, limit, offset)
}

// registrationReadPredicate checks the original approved environment and the
// current connection/operation graph. A later admin move must not preserve a
// stale environment grant on the historical registration receipt.
func registrationReadPredicate(scope *readscope.Scope, args *[]any) string {
	if scope == nil {
		return "true"
	}
	conditions := make([]string, 0, 2)
	if !scope.AllowAll {
		*args = append(*args, scope.Environments)
		conditions = append(conditions, fmt.Sprintf("connection_registrations.environment = any($%d::text[])", len(*args)))
	}
	connection := scope.Connection("connection_registrations.connection_id", args)
	operation := scope.Operation("connection_registrations.operation_id", args)
	conditions = append(conditions, `(connection_registrations.phase <> 'registered' or (`+connection+` and
		(not exists(select 1 from operations where id=connection_registrations.operation_id) or `+operation+`)))`)
	return strings.Join(conditions, " and ")
}

func (s *Store) ReadAllowed(ctx context.Context, q Querier, id uuid.UUID, scope *readscope.Scope) (bool, error) {
	args := []any{id}
	predicate := registrationReadPredicate(scope, &args)
	var allowed bool
	err := q.QueryRow(ctx, `select exists(select 1 from connection_registrations where id=$1 and `+predicate+`)`, args...).Scan(&allowed)
	return allowed, err
}

func (s *Store) OperationExists(ctx context.Context, q Querier, id uuid.UUID) (bool, error) {
	var exists bool
	err := q.QueryRow(ctx, `select exists(select 1 from operations where id=$1)`, id).Scan(&exists)
	return exists, err
}

// ListVisible applies every authorization predicate before pagination so a
// page of hidden records cannot crowd out the caller's next visible receipt.
func (s *Store) ListVisible(ctx context.Context, q Querier, owner *Owner, scope *readscope.Scope, limit, offset int) ([]Registration, error) {
	conditions, args := []string{}, []any{}
	if owner != nil {
		conditions = append(conditions, "owner_type=$1 and owner_id=$2")
		args = append(args, owner.Type, owner.ID)
	}
	conditions = append(conditions, registrationReadPredicate(scope, &args))
	query := `select ` + registrationColumns + ` from connection_registrations where ` + strings.Join(conditions, " and ") + ` order by created_at desc,id`
	args = append(args, limit, offset)
	query += fmt.Sprintf(" limit $%d offset $%d", len(args)-1, len(args))
	rows, err := q.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Registration, 0)
	for rows.Next() {
		r, err := scanRegistration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) SetCanonicalVersion(ctx context.Context, q Querier, id uuid.UUID, version int) (Registration, error) {
	if version <= 0 {
		return Registration{}, errors.New("connection registration: invalid canonical version")
	}
	return scanRegistration(q.QueryRow(ctx, `update connection_registrations set canonical_version=$2,phase='credential_ready',updated_at=now() where id=$1 and phase='preparing' returning `+registrationColumns, id, version))
}

func (s *Store) MarkRegistered(ctx context.Context, q Querier, id uuid.UUID) (Registration, error) {
	return scanRegistration(q.QueryRow(ctx, `update connection_registrations set phase='registered',updated_at=now() where id=$1 and phase='credential_ready' returning `+registrationColumns, id))
}

func (s *Store) BeginCancellation(ctx context.Context, q Querier, id uuid.UUID) (Registration, error) {
	return scanRegistration(q.QueryRow(ctx, `update connection_registrations set phase='canceling',updated_at=now() where id=$1 and phase in ('preparing','credential_ready','canceling') returning `+registrationColumns, id))
}

func (s *Store) FinishCancellation(ctx context.Context, q Querier, id uuid.UUID) (Registration, error) {
	return scanRegistration(q.QueryRow(ctx, `update connection_registrations set phase='cancelled',updated_at=now() where id=$1 and phase='canceling' returning `+registrationColumns, id))
}

func validRegistrationCredential(spec json.RawMessage, sourceID uuid.UUID, version int) bool {
	var target struct {
		Engine   string `json:"engine"`
		AuthMode string `json:"auth_mode"`
	}
	if json.Unmarshal(spec, &target) != nil {
		return false
	}
	if target.AuthMode == "none" {
		return target.Engine == "redis" && sourceID == uuid.Nil && version == 0
	}
	return sourceID != uuid.Nil && version > 0
}

func (s *Store) SetNoAuthReady(ctx context.Context, q Querier, id uuid.UUID) (Registration, error) {
	return scanRegistration(q.QueryRow(ctx, `update connection_registrations set phase='credential_ready',updated_at=now() where id=$1 and phase='preparing' and credential_source_id is null and spec->>'engine'='redis' and spec->>'auth_mode'='none' returning `+registrationColumns, id))
}
