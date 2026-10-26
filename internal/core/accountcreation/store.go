// Package accountcreation records CREATE separately from password proof.
// A role name or discovery snapshot can never manufacture a creation receipt.
package accountcreation

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrNotFound = errors.New("account creation receipt not found")
var ErrConflict = errors.New("account creation receipt changed")

type Querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type Receipt struct {
	OperationID                uuid.UUID
	AccountID                  uuid.UUID
	ConnectionID               uuid.UUID
	EngineIdentity             string
	TargetIdentity             string
	AdminIdentity              string
	ConfigIncarnation          string
	AdminCredentialIncarnation int
	LifecycleVersion           int64
	CredentialPath             string
	CredentialVersion          int
	Phase                      string
	RoleOID                    uint32
}

type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Receipt, error) {
	var r Receipt
	err := q.QueryRow(ctx, `select operation_id,account_id,connection_id,engine_identity,
		target_identity,admin_identity,config_incarnation,admin_credential_incarnation,
		lifecycle_version,credential_path,credential_version,phase,role_oid
		from account_creation_receipts where operation_id=$1`, id).Scan(
		&r.OperationID, &r.AccountID, &r.ConnectionID, &r.EngineIdentity, &r.TargetIdentity,
		&r.AdminIdentity, &r.ConfigIncarnation, &r.AdminCredentialIncarnation,
		&r.LifecycleVersion, &r.CredentialPath, &r.CredentialVersion, &r.Phase, &r.RoleOID)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, fmt.Errorf("account creation: read receipt: %w", err)
	}
	return r, nil
}

func (s *Store) Create(ctx context.Context, q Querier, r Receipt) error {
	if r.OperationID == uuid.Nil || r.AccountID == uuid.Nil || r.ConnectionID == uuid.Nil ||
		r.EngineIdentity == "" || r.TargetIdentity == "" || r.AdminIdentity == "" ||
		r.ConfigIncarnation == "" || r.AdminCredentialIncarnation <= 0 || r.LifecycleVersion < 0 ||
		r.CredentialPath == "" || r.CredentialVersion <= 0 {
		return ErrConflict
	}
	_, err := q.Exec(ctx, `insert into account_creation_receipts
		(operation_id,account_id,connection_id,engine_identity,target_identity,admin_identity,
		config_incarnation,admin_credential_incarnation,lifecycle_version,credential_path,credential_version)
		values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, r.OperationID, r.AccountID, r.ConnectionID,
		r.EngineIdentity, r.TargetIdentity, r.AdminIdentity, r.ConfigIncarnation,
		r.AdminCredentialIncarnation, r.LifecycleVersion, r.CredentialPath, r.CredentialVersion)
	if err != nil {
		return fmt.Errorf("account creation: reserve receipt: %w", err)
	}
	return nil
}

func change(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return fmt.Errorf("account creation: record phase: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

// Begin is committed before the first possible target write. A crash without
// Confirm leaves an unknown outcome, never permission to repeat CREATE.
func (s *Store) Begin(ctx context.Context, q Querier, id uuid.UUID) error {
	tag, err := q.Exec(ctx, `update account_creation_receipts set phase='creating',updated_at=now()
		where operation_id=$1 and phase='planned'`, id)
	return change(tag, err)
}

func (s *Store) Confirm(ctx context.Context, q Querier, id uuid.UUID, oid uint32) error {
	if oid == 0 {
		return ErrConflict
	}
	tag, err := q.Exec(ctx, `update account_creation_receipts set phase='created',role_oid=$2,updated_at=now()
		where operation_id=$1 and phase='creating' and role_oid=0`, id, oid)
	return change(tag, err)
}

// Complete belongs to the same transaction as account activation and audit.
func (s *Store) Complete(ctx context.Context, q Querier, id, verificationID uuid.UUID) error {
	if verificationID == uuid.Nil {
		return ErrConflict
	}
	tag, err := q.Exec(ctx, `update account_creation_receipts set phase='verified',
		verified_operation_id=$2,updated_at=now() where operation_id=$1 and phase='created' and role_oid>0`, id, verificationID)
	return change(tag, err)
}
