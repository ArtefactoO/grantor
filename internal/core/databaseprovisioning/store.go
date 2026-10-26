// Package databaseprovisioning stores the fixed database -> READ -> READ_WRITE
// workflow. It never infers a creation receipt from discovery or an object name.
package databaseprovisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrNotFound = errors.New("database provisioning: not found")
	ErrConflict = errors.New("database provisioning: receipt conflict")
)

type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Row struct {
	OperationID           uuid.UUID
	ResourceID            uuid.UUID
	ConnectionID          uuid.UUID
	Phase                 string
	DatabaseCreateStarted bool
	DatabaseCreated       bool
	DatabaseOID           uint32
	DatabaseOwner         string
	DatabaseOwnerOID      uint32
	TargetIdentity        string
	Templates             json.RawMessage
	ReadPolicyKey         string
	ReadWritePolicyKey    string
	ReadCreated           bool
	ReadWriteCreated      bool
	ErrorCode             string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) Create(ctx context.Context, q Querier, operationID, resourceID, connectionID uuid.UUID) error {
	if operationID == uuid.Nil || resourceID == uuid.Nil || connectionID == uuid.Nil {
		return fmt.Errorf("database provisioning: operation, resource and connection are required")
	}
	_, err := q.Exec(ctx, `insert into database_provisionings(operation_id,resource_id,connection_id)
		values($1,$2,$3)`, operationID, resourceID, connectionID)
	if err != nil {
		return fmt.Errorf("database provisioning: create: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, q Querier, operationID uuid.UUID) (Row, error) {
	var r Row
	err := q.QueryRow(ctx, `select operation_id,resource_id,connection_id,phase,
		database_create_started,database_created,database_oid,database_owner,database_owner_oid,target_identity,
		templates,read_policy_key,read_write_policy_key,read_created,read_write_created,
		error_code,created_at,updated_at from database_provisionings where operation_id=$1`, operationID).Scan(
		&r.OperationID, &r.ResourceID, &r.ConnectionID, &r.Phase, &r.DatabaseCreateStarted,
		&r.DatabaseCreated, &r.DatabaseOID, &r.DatabaseOwner, &r.DatabaseOwnerOID, &r.TargetIdentity, &r.Templates,
		&r.ReadPolicyKey, &r.ReadWritePolicyKey, &r.ReadCreated, &r.ReadWriteCreated,
		&r.ErrorCode, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Row{}, ErrNotFound
	}
	if err != nil {
		return Row{}, fmt.Errorf("database provisioning: get: %w", err)
	}
	return r, nil
}

// BeginDatabase is durable before the first possible CREATE side effect. An
// interrupted attempt may be inspected, but must not adopt a matching database.
func (s *Store) BeginDatabase(ctx context.Context, q Querier, operationID uuid.UUID) error {
	tag, err := q.Exec(ctx, `update database_provisionings set database_create_started=true,
		phase='database_creating',error_code='',updated_at=now()
		where operation_id=$1 and not database_create_started and not database_created`, operationID)
	return changed(tag, err)
}

// ConfirmDatabase belongs in the same transaction as resource publication and
// the resource.created audit. It requires successful Apply and exact Verify.
func (s *Store) ConfirmDatabase(ctx context.Context, q Querier, operationID uuid.UUID, oid uint32, owner string, ownerOID uint32, target string) error {
	if oid == 0 || owner == "" || ownerOID == 0 || target == "" {
		return ErrConflict
	}
	tag, err := q.Exec(ctx, `update database_provisionings set database_created=true,
		database_oid=$2,database_owner=$3,database_owner_oid=$4,target_identity=$5,phase='database_created',error_code='',updated_at=now()
		where operation_id=$1 and database_create_started and not database_created`, operationID, oid, owner, ownerOID, target)
	return changed(tag, err)
}

// PrepareCatalog is atomic with the connection catalog update. The normalized
// templates become immutable intent, not a recipe reinterpreted on retry.
func (s *Store) PrepareCatalog(ctx context.Context, q Querier, operationID uuid.UUID, templates json.RawMessage, readKey, writeKey string) error {
	tag, err := q.Exec(ctx, `update database_provisionings set templates=$2,read_policy_key=$3,
		read_write_policy_key=$4,phase='catalog_prepared',error_code='',updated_at=now()
		where operation_id=$1 and database_created and phase='database_created'`, operationID, templates, readKey, writeKey)
	return changed(tag, err)
}

func (s *Store) ConfirmRole(ctx context.Context, q Querier, operationID uuid.UUID, readWrite bool) error {
	query := `update database_provisionings set read_created=true,phase='read_created',error_code='',updated_at=now()
		where operation_id=$1 and database_created and phase in ('catalog_prepared','read_created')`
	if readWrite {
		query = `update database_provisionings set read_write_created=true,phase='complete',error_code='',updated_at=now()
		where operation_id=$1 and database_created and read_created and phase in ('read_created','complete')`
	}
	tag, err := q.Exec(ctx, query, operationID)
	return changed(tag, err)
}

func (s *Store) SetError(ctx context.Context, q Querier, operationID uuid.UUID, code string) error {
	tag, err := q.Exec(ctx, `update database_provisionings set error_code=$2,updated_at=now() where operation_id=$1`, operationID, code)
	return changed(tag, err)
}

func changed(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return fmt.Errorf("database provisioning: update: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}
