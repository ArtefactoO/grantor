package adapter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const (
	// CapConnectionAdminCredentialSwitch permits proving a ready candidate
	// connection credential. It is deliberately independent from self-rotate:
	// a verified replacement account remains the recovery path for topologies
	// where changing the current account in place is unsafe.
	CapConnectionAdminCredentialSwitch Capability = "connection.admin_credential.switch"
	// CapConnectionAdminCredentialRotate permits candidate-first self-rotation
	// of the exact account currently used by the connection.
	CapConnectionAdminCredentialRotate Capability = "connection.admin_credential.rotate"

	TopologyAdminCredentialSwitchSupported      = "admin_credential_switch_supported"
	TopologyAdminCredentialRotateSupported      = "admin_credential_rotate_supported"
	TopologyAdminCredentialBlockedReason        = "admin_credential_rotation_blocked_reason"
	TopologyAdminCredentialCanonicalIdentity    = "admin_credential_canonical_identity"
	TopologyAdminCredentialAuthorityFingerprint = "admin_credential_authority_fingerprint"
	TopologyAdminCredentialTargetIdentity       = "admin_credential_target_identity"
)

var (
	// ErrAdminCredentialRejected is returned only for a deterministic target
	// authentication rejection. Candidate-first rotation may branch from this
	// error to proving the old credential; timeouts and malformed/ambiguous
	// server replies must never be wrapped with it.
	ErrAdminCredentialRejected = errors.New("adapter: connection admin credential rejected")
	// ErrAdminCredentialProofAmbiguous means the target did not prove whether
	// it accepted or rejected the exact credential. It is fail-closed and
	// retryable by the operation layer.
	ErrAdminCredentialProofAmbiguous = errors.New("adapter: connection admin credential proof is ambiguous")
	// ErrAdminCredentialRotationUnsupported means discovery proved that the
	// current engine/topology cannot safely mutate its own admin credential.
	ErrAdminCredentialRotationUnsupported = errors.New("adapter: connection admin credential rotation is unsupported")
	// ErrAdminCredentialAuthorityChanged means the candidate authenticates but
	// no longer has the exact administrative authority proved for the old
	// credential.
	ErrAdminCredentialAuthorityChanged = errors.New("adapter: connection admin authority changed")
	// ErrAdminCredentialOldStillValid means candidate authentication succeeded
	// but the old secret was not deterministically invalidated.
	ErrAdminCredentialOldStillValid = errors.New("adapter: old connection admin credential is still valid")
)

// AdminCredentialAssessment is a secret-free, live capability assessment.
// BlockedReason describes only self-rotation; SwitchSupported may remain true
// so a ready, independently privileged account can recover the connection.
type AdminCredentialAssessment struct {
	SwitchSupported      bool   `json:"switch_supported"`
	RotateSupported      bool   `json:"rotate_supported"`
	BlockedReason        string `json:"blocked_reason,omitempty"`
	CanonicalIdentity    string `json:"canonical_identity"`
	AuthorityFingerprint string `json:"authority_fingerprint"`
	TargetIdentity       string `json:"target_identity,omitempty"`
}

func (a AdminCredentialAssessment) Proof() AdminCredentialProof {
	return AdminCredentialProof{
		CanonicalIdentity: a.CanonicalIdentity, AuthorityFingerprint: a.AuthorityFingerprint,
		TargetIdentity: a.TargetIdentity,
	}
}

// AdminCredentialProof proves exact authentication identity, target identity
// (when the engine exposes one) and administrative authority. It contains no
// credential material or derivative of the secret.
type AdminCredentialProof struct {
	CanonicalIdentity    string `json:"canonical_identity"`
	AuthorityFingerprint string `json:"authority_fingerprint"`
	TargetIdentity       string `json:"target_identity,omitempty"`
}

// AdminCredentialRotationResult is safe to persist in operation metadata.
// AlreadyApplied identifies recovery after a lost target response: candidate
// worked and the old credential was already deterministically rejected.
type AdminCredentialRotationResult struct {
	AlreadyApplied bool                 `json:"already_applied"`
	Proof          AdminCredentialProof `json:"proof"`
}

// ConnectionAdminCredentialManager is deliberately separate from ordinary
// account credential rotation. A connection admin can mutate users, roles and
// access; proving an ordinary login is not sufficient authority to replace it.
type ConnectionAdminCredentialManager interface {
	AssessConnectionAdminCredential(ctx context.Context, cfg Connection) (AdminCredentialAssessment, error)
	ProveConnectionAdminCredential(ctx context.Context, cfg Connection, candidate Credential) (AdminCredentialProof, error)
	RotateConnectionAdminCredential(ctx context.Context, cfg Connection, candidate Credential,
		expected AdminCredentialProof) (AdminCredentialRotationResult, error)
}

// AdminCredentialRotationHooks let engine packages share the forward-only
// candidate-first state machine while retaining typed, engine-native proof
// and mutation commands.
type AdminCredentialRotationHooks struct {
	Prove func(context.Context, Credential) (AdminCredentialProof, error)
	Apply func(context.Context, Credential, AdminCredentialProof) error
}

// RunCandidateFirstAdminCredentialRotation implements the only allowed
// self-rotation ordering:
//  1. prove candidate first (lost-response recovery);
//  2. branch to mutation only on deterministic candidate rejection;
//  3. prove old identity/authority, mutate once, then prove candidate;
//  4. require deterministic old rejection and unchanged authority.
//
// Apply errors are returned without reinterpretation: a lost/ambiguous target
// response remains retryable and the next invocation starts from candidate
// proof again.
func RunCandidateFirstAdminCredentialRotation(
	ctx context.Context,
	current Credential,
	candidate Credential,
	expected AdminCredentialProof,
	hooks AdminCredentialRotationHooks,
) (AdminCredentialRotationResult, error) {
	if hooks.Prove == nil || hooks.Apply == nil {
		return AdminCredentialRotationResult{}, errors.New("adapter: admin credential rotation hooks are incomplete")
	}
	if candidate.Kind != "password" || len(candidate.Secret) == 0 {
		return AdminCredentialRotationResult{}, errors.New("adapter: candidate admin password is required")
	}
	if candidate.Username != current.Username {
		return AdminCredentialRotationResult{}, fmt.Errorf(
			"adapter: candidate admin identity differs from the current identity: %w",
			ErrAdminCredentialRotationUnsupported)
	}
	if err := validateAdminCredentialProof(expected); err != nil {
		return AdminCredentialRotationResult{}, fmt.Errorf("adapter: expected admin credential proof fence: %w", err)
	}

	candidateProof, candidateErr := hooks.Prove(ctx, candidate)
	switch {
	case candidateErr == nil:
		if err := validateAdminCredentialProof(candidateProof); err != nil {
			return AdminCredentialRotationResult{}, err
		}
		if !sameAdminCredentialProof(candidateProof, expected) {
			return AdminCredentialRotationResult{}, ErrAdminCredentialAuthorityChanged
		}
		_, oldErr := hooks.Prove(ctx, current)
		if oldErr == nil {
			return AdminCredentialRotationResult{}, ErrAdminCredentialOldStillValid
		}
		if !errors.Is(oldErr, ErrAdminCredentialRejected) {
			return AdminCredentialRotationResult{}, fmt.Errorf("prove old admin credential after candidate success: %w", oldErr)
		}
		return AdminCredentialRotationResult{AlreadyApplied: true, Proof: candidateProof}, nil
	case !errors.Is(candidateErr, ErrAdminCredentialRejected):
		return AdminCredentialRotationResult{}, fmt.Errorf("prove candidate admin credential: %w", candidateErr)
	}

	oldProof, err := hooks.Prove(ctx, current)
	if err != nil {
		return AdminCredentialRotationResult{}, fmt.Errorf("prove current admin credential: %w", err)
	}
	if err := validateAdminCredentialProof(oldProof); err != nil {
		return AdminCredentialRotationResult{}, err
	}
	if !sameAdminCredentialProof(oldProof, expected) {
		return AdminCredentialRotationResult{}, ErrAdminCredentialAuthorityChanged
	}
	if err := hooks.Apply(ctx, candidate, oldProof); err != nil {
		return AdminCredentialRotationResult{}, err
	}
	finalProof, err := hooks.Prove(ctx, candidate)
	if err != nil {
		return AdminCredentialRotationResult{}, fmt.Errorf("prove rotated admin credential: %w", err)
	}
	if err := validateAdminCredentialProof(finalProof); err != nil {
		return AdminCredentialRotationResult{}, err
	}
	if !sameAdminCredentialProof(finalProof, oldProof) {
		return AdminCredentialRotationResult{}, ErrAdminCredentialAuthorityChanged
	}
	_, oldErr := hooks.Prove(ctx, current)
	if oldErr == nil {
		return AdminCredentialRotationResult{}, ErrAdminCredentialOldStillValid
	}
	if !errors.Is(oldErr, ErrAdminCredentialRejected) {
		return AdminCredentialRotationResult{}, fmt.Errorf("prove old admin credential invalidation: %w", oldErr)
	}
	return AdminCredentialRotationResult{Proof: finalProof}, nil
}

func sameAdminCredentialProof(a, b AdminCredentialProof) bool {
	return a.CanonicalIdentity == b.CanonicalIdentity &&
		a.AuthorityFingerprint == b.AuthorityFingerprint && a.TargetIdentity == b.TargetIdentity
}

func validateAdminCredentialProof(proof AdminCredentialProof) error {
	if proof.CanonicalIdentity == "" || proof.AuthorityFingerprint == "" {
		return fmt.Errorf("adapter: incomplete admin credential proof: %w", ErrAdminCredentialProofAmbiguous)
	}
	return nil
}

// AdminCredentialAuthorityFingerprint hashes sorted, non-secret authority
// facts (role names, privilege names, tags and topology invariants). Engines
// must never pass credential values or their derivatives.
func AdminCredentialAuthorityFingerprint(facts ...string) string {
	facts = slices.Clone(facts)
	slices.Sort(facts)
	sum := sha256.Sum256([]byte(strings.Join(facts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// PublishAdminCredentialAssessment stores the safe discovery projection used
// by per-connection capability scoping.
func PublishAdminCredentialAssessment(topology map[string]any, assessment AdminCredentialAssessment) {
	if topology == nil {
		return
	}
	topology[TopologyAdminCredentialSwitchSupported] = assessment.SwitchSupported
	topology[TopologyAdminCredentialRotateSupported] = assessment.RotateSupported
	if assessment.BlockedReason != "" {
		topology[TopologyAdminCredentialBlockedReason] = assessment.BlockedReason
	} else {
		delete(topology, TopologyAdminCredentialBlockedReason)
	}
	publishAdminCredentialString(topology, TopologyAdminCredentialCanonicalIdentity, assessment.CanonicalIdentity)
	publishAdminCredentialString(topology, TopologyAdminCredentialAuthorityFingerprint, assessment.AuthorityFingerprint)
	publishAdminCredentialString(topology, TopologyAdminCredentialTargetIdentity, assessment.TargetIdentity)
}

func publishAdminCredentialString(topology map[string]any, key, value string) {
	if value == "" {
		delete(topology, key)
		return
	}
	topology[key] = value
}

// AdminCredentialAssessmentFromTopology restores the safe discovery proof
// used to pin connector operations. ok is false unless switch proof and both
// canonical identity and authority fingerprint are present.
func AdminCredentialAssessmentFromTopology(topology map[string]any) (AdminCredentialAssessment, bool) {
	assessment := AdminCredentialAssessment{}
	assessment.SwitchSupported, _ = topology[TopologyAdminCredentialSwitchSupported].(bool)
	assessment.RotateSupported, _ = topology[TopologyAdminCredentialRotateSupported].(bool)
	assessment.BlockedReason, _ = topology[TopologyAdminCredentialBlockedReason].(string)
	assessment.CanonicalIdentity, _ = topology[TopologyAdminCredentialCanonicalIdentity].(string)
	assessment.AuthorityFingerprint, _ = topology[TopologyAdminCredentialAuthorityFingerprint].(string)
	assessment.TargetIdentity, _ = topology[TopologyAdminCredentialTargetIdentity].(string)
	return assessment, assessment.SwitchSupported && assessment.CanonicalIdentity != "" &&
		assessment.AuthorityFingerprint != ""
}

// ScopeAdminCredentialCapabilities removes switch/rotate from the manifest
// maximum until a live assessment explicitly enables them.
func ScopeAdminCredentialCapabilities(capabilities []Capability, topology map[string]any) []Capability {
	switchSupported, _ := topology[TopologyAdminCredentialSwitchSupported].(bool)
	rotateSupported, _ := topology[TopologyAdminCredentialRotateSupported].(bool)
	return slices.DeleteFunc(slices.Clone(capabilities), func(capability Capability) bool {
		return capability == CapConnectionAdminCredentialSwitch && !switchSupported ||
			capability == CapConnectionAdminCredentialRotate && !rotateSupported
	})
}
