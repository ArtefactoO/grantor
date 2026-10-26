package admincredentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/core/connections"
)

type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct{}

func NewStore() *Store { return &Store{} }

const changeColumns = `c.operation_id, c.connection_id, c.request_id, c.mode, c.candidate_mode,
	c.epoch, c.stage_vault_path, coalesce(c.staged_vault_version, 0),
	c.expected_canonical_version, c.canonical_vault_version,
	c.expected_canonical_identity, c.expected_authority_fingerprint,
	c.expected_target_identity,
	c.previous_status, c.phase, c.target_side_effect_possible, c.error_code,
	c.completion_result,
	c.stage_cleanup_pending,
	c.cancel_request_id, o.status, c.created_at, c.started_at, c.finished_at,
	c.updated_at`

func changeSelect(where string) string {
	return `select ` + changeColumns + `
		from connection_admin_credential_changes c
		join operations o on o.id = c.operation_id
		where ` + where
}

type CreateParams struct {
	OperationID              uuid.UUID
	ConnectionID             uuid.UUID
	RequestID                uuid.UUID
	Mode                     Mode
	CandidateMode            string
	Epoch                    int64
	StageVaultPath           string
	StagedVaultVersion       int
	ExpectedCanonicalVersion int
	PreviousStatus           connections.Status
	ExpectedUpdatedAt        time.Time
}

// Create reserves the next per-connection epoch and moves the connection to
// credential_updating in the caller's transaction. The caller must already
// hold the per-connection advisory lock and have inserted OperationID.
func (s *Store) Create(ctx context.Context, q Querier, p CreateParams) (Change, error) {
	if p.OperationID == uuid.Nil || p.ConnectionID == uuid.Nil || p.RequestID == uuid.Nil {
		return Change{}, errors.New("admin credentials: create: operation, connection and request ids are required")
	}
	if !p.Mode.Valid() || (p.CandidateMode != "generated" && p.CandidateMode != "provided" && p.CandidateMode != "none") ||
		p.Epoch <= 0 || (p.CandidateMode != "none" && p.StageVaultPath == "") ||
		(p.CandidateMode == "none" && (p.Mode != ModeSwitch || p.StageVaultPath != "" || p.StagedVaultVersion != 0 || p.ExpectedCanonicalVersion != 0)) ||
		p.StagedVaultVersion < 0 || p.ExpectedCanonicalVersion < 0 {
		return Change{}, errors.New("admin credentials: create: invalid lifecycle parameters")
	}
	if !allowedPreviousStatus(p.PreviousStatus) {
		return Change{}, fmt.Errorf("admin credentials: create: connection status %q cannot start a change", p.PreviousStatus)
	}

	_, err := q.Exec(ctx, `
		insert into connection_admin_credential_changes (
			operation_id, connection_id, request_id, mode, candidate_mode, epoch,
			stage_vault_path, staged_vault_version,
			expected_canonical_version, previous_status, phase, stage_cleanup_pending
		) values (
			$1, $2, $3, $4, $5, $6, $7, nullif($8, 0), $9, $10,
			case when $8 > 0 then 'staged' else 'preparing' end, $5 <> 'none'
		)`,
		p.OperationID, p.ConnectionID, p.RequestID, p.Mode, p.CandidateMode, p.Epoch,
		p.StageVaultPath, p.StagedVaultVersion, p.ExpectedCanonicalVersion,
		p.PreviousStatus,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Change{}, fmt.Errorf("admin credentials: create: %w", ErrActiveChange)
		}
		return Change{}, fmt.Errorf("admin credentials: create: %w", err)
	}

	tag, err := q.Exec(ctx, `
		update connections
		set status = 'credential_updating', updated_at = now()
		where id = $1 and status = $2 and updated_at = $3`,
		p.ConnectionID, p.PreviousStatus, p.ExpectedUpdatedAt,
	)
	if err != nil {
		return Change{}, fmt.Errorf("admin credentials: create: mark connection updating: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Change{}, fmt.Errorf("admin credentials: create: connection compare-and-swap failed: %w", connections.ErrVersionConflict)
	}

	change, err := s.Get(ctx, q, p.OperationID)
	if err != nil {
		return Change{}, err
	}
	return change, nil
}

// FinalizeStage binds the exact Vault version to a provisional preparing row.
// Only after this transition may the caller enqueue the operation.
func (s *Store) FinalizeStage(ctx context.Context, q Querier, operationID uuid.UUID,
	version int) (Change, error) {
	if version < 0 {
		return Change{}, errors.New("admin credentials: staged Vault version must not be negative")
	}
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set staged_vault_version = $2, phase = 'staged', updated_at = now()
		where operation_id = $1
		  and (($2 > 0 and candidate_mode <> 'none') or ($2 = 0 and candidate_mode = 'none'))
		  and (phase = 'preparing'
		       or (phase = 'staged' and staged_vault_version = $2))`, operationID, version)
	if err != nil {
		return Change{}, fmt.Errorf("admin credentials: finalize stage: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Change{}, fmt.Errorf("admin credentials: finalize stage: %w", ErrStaleOperation)
	}
	return s.Get(ctx, q, operationID)
}

// NextEpoch must be called under the per-connection advisory lock used by
// Create. It is separate so the immutable operation payload can pin the same
// value before both rows are inserted transactionally.
func (s *Store) NextEpoch(ctx context.Context, q Querier, connectionID uuid.UUID) (int64, error) {
	var epoch int64
	if err := q.QueryRow(ctx, `
		select coalesce(max(epoch), 0) + 1
		from connection_admin_credential_changes where connection_id = $1`, connectionID).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("admin credentials: next epoch: %w", err)
	}
	return epoch, nil
}

func allowedPreviousStatus(status connections.Status) bool {
	switch status {
	case connections.StatusActive, connections.StatusDegraded,
		connections.StatusConnectionFailed, connections.StatusDiscoveryFailed:
		return true
	default:
		return false
	}
}

func (s *Store) Get(ctx context.Context, q Querier, operationID uuid.UUID) (Change, error) {
	return scanChange(changeSelect(`c.operation_id = $1`), q, ctx, operationID)
}

func (s *Store) GetByRequest(ctx context.Context, q Querier, connectionID, requestID uuid.UUID) (Change, error) {
	return scanChange(changeSelect(`c.connection_id = $1 and c.request_id = $2`), q, ctx, connectionID, requestID)
}

func (s *Store) Latest(ctx context.Context, q Querier, connectionID uuid.UUID) (Change, error) {
	return scanChange(changeSelect(`c.connection_id = $1 order by c.created_at desc, c.operation_id desc limit 1`), q, ctx, connectionID)
}

func (s *Store) Active(ctx context.Context, q Querier, connectionID uuid.UUID) (Change, error) {
	return scanChange(changeSelect(`c.connection_id = $1 and c.phase not in ('completed', 'failed', 'cancelled')`), q, ctx, connectionID)
}

func scanChange(query string, q Querier, ctx context.Context, args ...any) (Change, error) {
	var c Change
	err := q.QueryRow(ctx, query, args...).Scan(
		&c.OperationID, &c.ConnectionID, &c.RequestID, &c.Mode, &c.CandidateMode,
		&c.Epoch, &c.StageVaultPath, &c.StagedVaultVersion,
		&c.ExpectedCanonicalVersion, &c.CanonicalVaultVersion,
		&c.ExpectedCanonicalIdentity, &c.ExpectedAuthorityFingerprint,
		&c.ExpectedTargetIdentity,
		&c.PreviousStatus, &c.Phase, &c.TargetSideEffectPossible,
		&c.ErrorCode, &c.CompletionResult, &c.StageCleanupPending,
		&c.CancelRequestID, &c.OperationStatus,
		&c.CreatedAt, &c.StartedAt, &c.FinishedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Change{}, fmt.Errorf("admin credentials: get change: %w", ErrNotFound)
		}
		return Change{}, fmt.Errorf("admin credentials: get change: %w", err)
	}
	return c, nil
}

// SetExpectedProof durably pins the exact old identity/authority/target before
// the first possible target mutation. A retry after a lost response compares
// the candidate proof to these values instead of accepting a merely working
// but underprivileged credential.
func (s *Store) SetExpectedProof(ctx context.Context, q Querier, operationID uuid.UUID,
	canonicalIdentity, authorityFingerprint, targetIdentity string) error {
	if canonicalIdentity == "" || authorityFingerprint == "" {
		return errors.New("admin credentials: expected identity and authority fingerprint are required")
	}
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set expected_canonical_identity = case
				when expected_canonical_identity = '' then $2 else expected_canonical_identity end,
			expected_authority_fingerprint = case
				when expected_authority_fingerprint = '' then $3 else expected_authority_fingerprint end,
			expected_target_identity = case
				when expected_target_identity = '' then $4 else expected_target_identity end,
			updated_at = now()
		where operation_id = $1
		  and phase not in ('completed', 'failed', 'cancelled')
		  and (expected_canonical_identity = '' or expected_canonical_identity = $2)
		  and (expected_authority_fingerprint = '' or expected_authority_fingerprint = $3)
		  and (expected_target_identity = '' or expected_target_identity = $4)`,
		operationID, canonicalIdentity, authorityFingerprint, targetIdentity)
	if err != nil {
		return fmt.Errorf("admin credentials: set expected proof: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("admin credentials: set expected proof: %w", ErrStaleOperation)
	}
	return nil
}

// SetPhase advances an owned, unfinished lifecycle row. externalSideEffect is
// monotonic: once true it can never be cleared by a retry or stale response.
func (s *Store) SetPhase(ctx context.Context, q Querier, operationID uuid.UUID, phase Phase,
	externalSideEffect bool, errorCode string) (Change, error) {
	if phase.Terminal() || phaseRank(phase) == 0 {
		return Change{}, errors.New("admin credentials: set phase requires a known nonterminal phase")
	}
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set phase = $2,
			target_side_effect_possible = target_side_effect_possible or $3,
			error_code = $4,
			started_at = coalesce(started_at, now()),
			finished_at = case when $2 in ('completed', 'failed', 'cancelled') then now() else null end,
			updated_at = now()
		where operation_id = $1
		  and phase not in ('completed', 'failed', 'cancelled')
		  and (
			phase = $2
			or (phase = 'staged' and $2 in ('candidate_proving', 'target_applying'))
			or (phase in ('candidate_proving', 'target_applying') and $2 = 'target_applied')
			or (phase = 'target_applied' and $2 = 'promoting')
			or (phase = 'promoted' and $2 = 'metadata_committing')
		  )`,
		operationID, phase, externalSideEffect, errorCode,
	)
	if err != nil {
		return Change{}, fmt.Errorf("admin credentials: set phase: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Change{}, fmt.Errorf("admin credentials: set phase: %w", ErrStaleOperation)
	}
	return s.Get(ctx, q, operationID)
}

func (s *Store) SetCanonicalVersion(ctx context.Context, q Querier, operationID uuid.UUID, version int) error {
	if version < 0 {
		return errors.New("admin credentials: canonical Vault version must not be negative")
	}
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set canonical_vault_version = $2, phase = 'promoted',
			target_side_effect_possible = true, updated_at = now()
		where operation_id = $1
		  and (($2 > 0 and candidate_mode <> 'none') or ($2 = 0 and candidate_mode = 'none'))
		  and (phase = 'promoting'
		       or (phase = 'promoted' and canonical_vault_version = $2))`, operationID, version)
	if err != nil {
		return fmt.Errorf("admin credentials: set canonical version: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("admin credentials: set canonical version: %w", ErrStaleOperation)
	}
	return nil
}

func (s *Store) Complete(ctx context.Context, q Querier, operationID uuid.UUID, result []byte) (Change, error) {
	if len(result) == 0 || !json.Valid(result) {
		return Change{}, errors.New("admin credentials: completion result must be valid JSON")
	}
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set phase = 'completed', completion_result = $2,
			target_side_effect_possible = true, error_code = '',
			finished_at = now(), updated_at = now()
		where operation_id = $1
		  and canonical_vault_version is not null
		  and phase = 'metadata_committing'`, operationID, result)
	if err != nil {
		return Change{}, fmt.Errorf("admin credentials: complete: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Change{}, fmt.Errorf("admin credentials: complete: %w", ErrStaleOperation)
	}
	return s.Get(ctx, q, operationID)
}

// RestoreTerminal closes a failed/cancelled change and restores the exact
// stable status observed before it started. It must be called in the same
// transaction that finalizes/cancels the top-level operation.
func (s *Store) RestoreTerminal(ctx context.Context, q Querier, operationID uuid.UUID,
	phase Phase, errorCode string, cancelRequestID *uuid.UUID) (Change, error) {
	if phase != PhaseFailed && phase != PhaseCancelled {
		return Change{}, errors.New("admin credentials: restore terminal requires failed or cancelled phase")
	}
	var connID uuid.UUID
	var previous connections.Status
	err := q.QueryRow(ctx, `
		update connection_admin_credential_changes
		set phase = $2, error_code = $3, cancel_request_id = coalesce(cancel_request_id, $4),
			finished_at = now(), updated_at = now()
		where operation_id = $1
		  and phase not in ('completed', 'failed', 'cancelled')
		  and not target_side_effect_possible
		returning connection_id, previous_status`, operationID, phase, errorCode, cancelRequestID,
	).Scan(&connID, &previous)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Change{}, fmt.Errorf("admin credentials: restore terminal: %w", ErrStaleOperation)
		}
		return Change{}, fmt.Errorf("admin credentials: restore terminal: %w", err)
	}
	tag, err := q.Exec(ctx, `
		update connections set status = $2, updated_at = now()
		where id = $1 and status = 'credential_updating'`, connID, previous)
	if err != nil {
		return Change{}, fmt.Errorf("admin credentials: restore connection status: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return Change{}, fmt.Errorf("admin credentials: restore connection status: %w", connections.ErrStatusConflict)
	}
	return s.Get(ctx, q, operationID)
}

// BlocksOperation tells River whether a pre-existing job must be snoozed
// behind the active credential epoch. The credential operation owning that
// epoch is the only exception.
func (s *Store) BlocksOperation(ctx context.Context, q Querier, connectionID, operationID uuid.UUID) (bool, error) {
	var blocked bool
	err := q.QueryRow(ctx, `
		select exists (
			select 1 from connection_admin_credential_changes
			where connection_id = $1
			  and operation_id <> $2
			  and phase not in ('completed', 'failed', 'cancelled')
		)`, connectionID, operationID).Scan(&blocked)
	if err != nil {
		return false, fmt.Errorf("admin credentials: check operation block: %w", err)
	}
	return blocked, nil
}

type StageCleanup struct {
	OperationID    uuid.UUID
	ConnectionID   uuid.UUID
	StageVaultPath string
}

func (s *Store) ListStageCleanupPending(ctx context.Context, q Querier, limit int) ([]StageCleanup, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := q.Query(ctx, `
		select operation_id, connection_id, stage_vault_path
		from connection_admin_credential_changes
		where stage_cleanup_pending
		  and phase in ('completed', 'failed', 'cancelled')
		order by finished_at, operation_id
		limit $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("admin credentials: list stage cleanup: %w", err)
	}
	defer rows.Close()
	var out []StageCleanup
	for rows.Next() {
		var item StageCleanup
		if err := rows.Scan(&item.OperationID, &item.ConnectionID, &item.StageVaultPath); err != nil {
			return nil, fmt.Errorf("admin credentials: scan stage cleanup: %w", err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("admin credentials: list stage cleanup: %w", err)
	}
	return out, nil
}

func (s *Store) MarkStageCleaned(ctx context.Context, q Querier, operationID uuid.UUID) error {
	tag, err := q.Exec(ctx, `
		update connection_admin_credential_changes
		set stage_cleanup_pending = false, updated_at = now()
		where operation_id = $1
		  and stage_cleanup_pending
		  and phase in ('completed', 'failed', 'cancelled')`, operationID)
	if err != nil {
		return fmt.Errorf("admin credentials: mark stage cleaned: %w", err)
	}
	if tag.RowsAffected() == 0 {
		var pending bool
		if err := q.QueryRow(ctx, `select stage_cleanup_pending
			from connection_admin_credential_changes where operation_id = $1`, operationID).Scan(&pending); err != nil {
			return fmt.Errorf("admin credentials: mark stage cleaned: %w", err)
		}
		if pending {
			return fmt.Errorf("admin credentials: mark stage cleaned: change is not terminal: %w", ErrStaleOperation)
		}
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
