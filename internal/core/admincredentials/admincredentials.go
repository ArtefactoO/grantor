// Package admincredentials owns the durable, secret-free lifecycle of the
// credential Grantor itself uses to administer a connection. Secret material
// is addressed only by Vault path/version and never enters these types.
package admincredentials

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

type Mode string

const (
	ModeSwitch Mode = "switch"
	ModeRotate Mode = "rotate"
)

func (m Mode) Valid() bool { return m == ModeSwitch || m == ModeRotate }

type Phase string

const (
	PhasePreparing          Phase = "preparing"
	PhaseStaged             Phase = "staged"
	PhaseCandidateProving   Phase = "candidate_proving"
	PhaseTargetApplying     Phase = "target_applying"
	PhaseTargetApplied      Phase = "target_applied"
	PhasePromoting          Phase = "promoting"
	PhasePromoted           Phase = "promoted"
	PhaseMetadataCommitting Phase = "metadata_committing"
	PhaseCompleted          Phase = "completed"
	PhaseFailed             Phase = "failed"
	PhaseCancelled          Phase = "cancelled"
)

func (p Phase) Terminal() bool {
	return p == PhaseCompleted || p == PhaseFailed || p == PhaseCancelled
}

func (p Phase) AtLeast(other Phase) bool {
	return phaseRank(p) >= phaseRank(other)
}

func phaseRank(p Phase) int {
	switch p {
	case PhasePreparing:
		return 1
	case PhaseStaged:
		return 2
	case PhaseCandidateProving:
		return 3
	case PhaseTargetApplying:
		return 4
	case PhaseTargetApplied:
		return 5
	case PhasePromoting:
		return 6
	case PhasePromoted:
		return 7
	case PhaseMetadataCommitting:
		return 8
	case PhaseCompleted, PhaseFailed, PhaseCancelled:
		return 9
	default:
		return 0
	}
}

// CanCancel is deliberately phase- and fence-based. The boolean is durable
// because an external response may be lost after the target or canonical
// Vault path has already changed; phase text alone is not sufficient evidence
// that rollback is still safe.
func (p Phase) CanCancel(targetSideEffectPossible bool) bool {
	return !p.Terminal() && !targetSideEffectPossible
}

var (
	ErrNotFound            = errors.New("admin credentials: change not found")
	ErrActiveChange        = errors.New("admin credentials: another change is active")
	ErrStaleOperation      = errors.New("admin credentials: stale operation epoch")
	ErrCancellationTooLate = errors.New("admin credentials: cancellation is no longer safe")
	ErrRequestConflict     = errors.New("admin credentials: request id conflicts with another operation")
)

// Change mirrors connection_admin_credential_changes plus the public status
// of its top-level operation. Values are safe for API/audit; stage coordinates
// are intentionally omitted from JSON DTOs by the HTTP layer.
type Change struct {
	OperationID                  uuid.UUID
	ConnectionID                 uuid.UUID
	RequestID                    uuid.UUID
	Mode                         Mode
	CandidateMode                string
	Epoch                        int64
	StageVaultPath               string
	StagedVaultVersion           int
	ExpectedCanonicalVersion     int
	CanonicalVaultVersion        *int
	ExpectedCanonicalIdentity    string
	ExpectedAuthorityFingerprint string
	ExpectedTargetIdentity       string
	PreviousStatus               connections.Status
	Phase                        Phase
	TargetSideEffectPossible     bool
	ErrorCode                    string
	CompletionResult             []byte
	StageCleanupPending          bool
	CancelRequestID              *uuid.UUID
	OperationStatus              operations.Status
	CreatedAt                    time.Time
	StartedAt                    *time.Time
	FinishedAt                   *time.Time
	UpdatedAt                    time.Time
}

func (c Change) CancelAllowed() bool {
	return c.Phase.CanCancel(c.TargetSideEffectPossible)
}

func (c Change) Retryable() bool {
	if c.Phase.Terminal() {
		return false
	}
	// Once an external side effect may have happened, forward-only recovery is
	// mandatory even when the latest typed error would have been deterministic
	// before mutation. Disabling retry here would strand the connection in
	// credential_updating with neither cancel nor switch available.
	if c.TargetSideEffectPossible {
		return true
	}
	switch c.ErrorCode {
	case "invalid_candidate", "rotation_unsupported", "canonical_version_changed":
		return false
	case "admin_authority_changed", "old_credential_still_valid", "target_identity_changed":
		return c.TargetSideEffectPossible
	default:
		return true
	}
}
