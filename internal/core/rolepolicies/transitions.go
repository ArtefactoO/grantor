package rolepolicies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// ReserveParams pins the state reviewed by the administrator. Version and
// observed fingerprint are checked under the row lock before any operation is
// allowed to own the transition.
type ReserveParams struct {
	ConnectionID        uuid.UUID
	TemplateKey         string
	Action              Action
	OperationID         uuid.UUID
	Version             int64
	ObservedFingerprint string
}

func (s *Store) Reserve(ctx context.Context, q Querier, p ReserveParams) (Reservation, error) {
	if p.ConnectionID == uuid.Nil || p.OperationID == uuid.Nil || p.TemplateKey == "" {
		return Reservation{}, fmt.Errorf("role policies: reserve: connection, operation and template key are required")
	}
	policy, err := scanPolicy(q.QueryRow(ctx, `select `+policyColumns+` from role_policies
		where connection_id=$1 and template_key=$2 for update`, p.ConnectionID, p.TemplateKey))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Reservation{}, fmt.Errorf("role policies: reserve %q: %w", p.TemplateKey, ErrNotFound)
		}
		return Reservation{}, fmt.Errorf("role policies: reserve %q: %w", p.TemplateKey, err)
	}
	if policy.Version != p.Version || policy.ObservedFingerprint != p.ObservedFingerprint {
		return Reservation{}, fmt.Errorf("role policies: reserve %q: version or observation changed: %w",
			p.TemplateKey, ErrStale)
	}
	if !policy.ApplySupported || policy.BlockedReason != "" {
		return Reservation{}, fmt.Errorf("role policies: reserve %q: %s: %w",
			p.TemplateKey, policy.BlockedReason, ErrApplyUnsupported)
	}
	if policy.TransitionOperationID != nil && *policy.TransitionOperationID != p.OperationID {
		var status string
		err := q.QueryRow(ctx, `select status from operations where id=$1`, *policy.TransitionOperationID).Scan(&status)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Reservation{}, fmt.Errorf("role policies: inspect transition owner: %w", err)
		}
		if status != "cancelled" && (status != "failed" || policy.TransitionRetryPending) {
			return Reservation{}, fmt.Errorf("role policies: template %q already has an active transition: %w",
				p.TemplateKey, ErrConflict)
		}
	}

	switch p.Action {
	case ActionCreate:
		// Fresh requests may reserve only an observed missing PostgreSQL
		// role. Recovery of the same operation keeps its transition/version
		// and is independently guarded by missing-or-exact target checks.
		creatable, err := s.Creatability(ctx, q, policy)
		if err != nil {
			return Reservation{}, err
		}
		if !creatable {
			return Reservation{}, fmt.Errorf("role policies: template %q is not a missing unmanaged PostgreSQL role: %w",
				p.TemplateKey, ErrConflict)
		}
	case ActionApply:
		if policy.DesiredSpec.Engine == "postgres" && policy.RoleMissing() {
			return Reservation{}, fmt.Errorf("role policies: role %q does not exist; use create: %w", policy.DesiredSpec.RoleName, ErrConflict)
		}
		if policy.Managed {
			return Reservation{}, fmt.Errorf("role policies: template %q is already managed; use repair: %w",
				p.TemplateKey, ErrConflict)
		}
	case ActionAdopt:
		if policy.Managed {
			return Reservation{}, fmt.Errorf("role policies: template %q is already managed: %w",
				p.TemplateKey, ErrConflict)
		}
		if !policy.Exact {
			return Reservation{}, fmt.Errorf("role policies: template %q can be adopted only from exact observed state: %w",
				p.TemplateKey, ErrConflict)
		}
	case ActionRepair:
		if !policy.Managed {
			return Reservation{}, fmt.Errorf("role policies: template %q is unmanaged; use apply or adopt: %w",
				p.TemplateKey, ErrConflict)
		}
		if policy.Exact && policy.Status != StatusFailed {
			return Reservation{}, fmt.Errorf("role policies: template %q has no drift to repair: %w",
				p.TemplateKey, ErrConflict)
		}
	default:
		return Reservation{}, fmt.Errorf("role policies: unknown action %q", p.Action)
	}

	accountID, err := s.reserveRoleIdentity(ctx, q, policy, p.Action)
	if err != nil {
		return Reservation{}, err
	}
	if accountID != nil {
		tag, err := q.Exec(ctx, `update operations set account_id=$2, updated_at=now()
			where id=$1 and (account_id is null or account_id=$2)`, p.OperationID, *accountID)
		if err != nil {
			return Reservation{}, fmt.Errorf("role policies: link transition account: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return Reservation{}, fmt.Errorf("role policies: operation account identity changed: %w", ErrConflict)
		}
	}
	nextVersion := policy.Version + 1
	managed := policy.Managed || p.Action != ActionAdopt
	reserved, err := scanPolicy(q.QueryRow(ctx, `update role_policies set
		account_id=$2, managed=$3, status='pending', version=$4,
		transition_operation_id=$5, target_started=false,
		transition_retry_pending=true, updated_at=now()
		where id=$1 and version=$4-1
		returning `+policyColumns,
		policy.ID, accountID, managed, nextVersion, p.OperationID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Reservation{}, fmt.Errorf("role policies: reserve %q raced: %w", p.TemplateKey, ErrStale)
		}
		return Reservation{}, fmt.Errorf("role policies: reserve %q: %w", p.TemplateKey, err)
	}
	return Reservation{Policy: reserved, ExpectedVersion: nextVersion}, nil
}

func (s *Store) reserveRoleIdentity(ctx context.Context, q Querier, p Policy, action Action) (*uuid.UUID, error) {
	if p.DesiredSpec.Engine != "postgres" {
		return p.AccountID, nil
	}
	var id uuid.UUID
	var kind, status, ownership string
	err := q.QueryRow(ctx, `select id, kind, status, ownership from accounts
		where connection_id=$1 and engine_identity=$2 for update`,
		p.ConnectionID, p.DesiredSpec.RoleName).Scan(&id, &kind, &status, &ownership)
	if errors.Is(err, pgx.ErrNoRows) {
		if action == ActionAdopt {
			return nil, fmt.Errorf("role policies: role identity %q is not in inventory: %w",
				p.DesiredSpec.RoleName, ErrConflict)
		}
		err = q.QueryRow(ctx, `insert into accounts (
			connection_id, kind, engine_identity, status, ownership, attributes
		) values ($1,'group',$2,'provisioning','managed','{}')
		returning id`, p.ConnectionID, p.DesiredSpec.RoleName).Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("role policies: reserve role identity %q: %w", p.DesiredSpec.RoleName, err)
		}
		return &id, nil
	}
	if err != nil {
		return nil, fmt.Errorf("role policies: reserve role identity %q: %w", p.DesiredSpec.RoleName, err)
	}
	if kind != "group" || status == "deleted" {
		return nil, fmt.Errorf("role policies: identity %q is a %s/%s account and cannot be a managed role: %w",
			p.DesiredSpec.RoleName, kind, status, ErrConflict)
	}
	var busy bool
	if err := q.QueryRow(ctx, `select exists (
		select 1 from operations where account_id=$1
		  and status in ('pending_approval','pending','running')
		  and (kind like 'account.%' or kind='role.create')
	)`, id).Scan(&busy); err != nil {
		return nil, fmt.Errorf("role policies: inspect role identity operation %q: %w", p.DesiredSpec.RoleName, err)
	}
	if busy {
		return nil, fmt.Errorf("role policies: role identity %q has an active lifecycle operation: %w",
			p.DesiredSpec.RoleName, ErrConflict)
	}
	_ = ownership // Ownership changes only after exact Verify.
	return &id, nil
}

// ValidateTransition is the final metadata fence immediately before target
// access. A stale job must fail before Plan, connector dispatch or Apply.
func (s *Store) ValidateTransition(ctx context.Context, q Querier, operationID uuid.UUID,
	expectedVersion int64, observedFingerprint, expectedFingerprint string,
	expectedSpec adapter.RolePolicySpec, requireObservedFingerprint bool,
) (Policy, error) {
	p, err := scanPolicy(q.QueryRow(ctx, `select `+policyColumns+` from role_policies
		where transition_operation_id=$1`, operationID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, fmt.Errorf("role policies: transition %s: %w", operationID, ErrStale)
		}
		return Policy{}, fmt.Errorf("role policies: transition %s: %w", operationID, err)
	}
	if p.Version != expectedVersion ||
		((requireObservedFingerprint || !p.TargetStarted) && p.ObservedFingerprint != observedFingerprint) ||
		p.ExpectedFingerprint != expectedFingerprint ||
		!reflect.DeepEqual(p.DesiredSpec, expectedSpec) {
		return Policy{}, fmt.Errorf("role policies: transition %s no longer matches pinned intent: %w",
			operationID, ErrStale)
	}
	if !p.ApplySupported || p.BlockedReason != "" {
		return Policy{}, fmt.Errorf("role policies: transition %s is no longer supported: %w",
			operationID, ErrApplyUnsupported)
	}
	return p, nil
}

// BeginTarget durably crosses the first-possible-side-effect boundary. Before
// the first attempt it still requires the reviewed observed fingerprint;
// retries of the same owner/version ignore observation changes and converge
// the pinned spec forward after an ambiguous/lost target response.
func (s *Store) BeginTarget(ctx context.Context, q Querier, operationID uuid.UUID,
	expectedVersion int64, observedFingerprint, expectedFingerprint string,
	expectedSpec adapter.RolePolicySpec,
) (Policy, error) {
	p, err := s.ValidateTransition(ctx, q, operationID, expectedVersion,
		observedFingerprint, expectedFingerprint, expectedSpec, false)
	if err != nil {
		return Policy{}, err
	}
	if p.TargetStarted {
		return p, nil
	}
	started, err := scanPolicy(q.QueryRow(ctx, `update role_policies set
		target_started=true, updated_at=now()
		where id=$1 and transition_operation_id=$2 and version=$3
		  and target_started=false and observed_fingerprint=$4
		returning `+policyColumns, p.ID, operationID, expectedVersion, observedFingerprint))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, fmt.Errorf("role policies: begin target transition %s: %w", operationID, ErrStale)
		}
		return Policy{}, fmt.Errorf("role policies: begin target transition %s: %w", operationID, err)
	}
	return started, nil
}

// CompletionArtifacts are sanitized plan/result bytes persisted in the
// success receipt. River removes its in-memory copy before the outer commit;
// recovery must republish these bytes or a successful operation would lose
// its review trail in that crash window.
type CompletionArtifacts struct {
	Plan   []byte
	Result []byte
}

// RecoverCompletion checks the durable success receipt written atomically
// with policy metadata and the success audit event. It closes the crash window
// between that inner commit and River's outer operation-status commit: the
// same immutable job may return success without a second target mutation or a
// duplicate audit event. A receipt owned by the operation but carrying another
// intent is corruption/stale delivery, never a successful retry.
func (s *Store) RecoverCompletion(ctx context.Context, q Querier,
	operationID, policyID uuid.UUID, expectedVersion int64,
	observedFingerprint, expectedFingerprint string,
	expectedSpec adapter.RolePolicySpec,
) (CompletionArtifacts, bool, error) {
	var storedPolicyID uuid.UUID
	var storedVersion int64
	var storedObserved, storedExpected string
	var rawSpec []byte
	var artifacts CompletionArtifacts
	err := q.QueryRow(ctx, `select role_policy_id, expected_version,
		observed_fingerprint, expected_fingerprint, desired_spec, plan, result
		from role_policy_operation_completions where operation_id=$1`, operationID).Scan(
		&storedPolicyID, &storedVersion, &storedObserved, &storedExpected, &rawSpec,
		&artifacts.Plan, &artifacts.Result)
	if errors.Is(err, pgx.ErrNoRows) {
		return CompletionArtifacts{}, false, nil
	}
	if err != nil {
		return CompletionArtifacts{}, false, fmt.Errorf("role policies: recognize completion %s: %w", operationID, err)
	}
	var storedSpec adapter.RolePolicySpec
	if err := json.Unmarshal(rawSpec, &storedSpec); err != nil {
		return CompletionArtifacts{}, false, fmt.Errorf("role policies: decode completion %s spec: %w", operationID, err)
	}
	if storedPolicyID != policyID || storedVersion != expectedVersion ||
		storedObserved != observedFingerprint || storedExpected != expectedFingerprint ||
		!reflect.DeepEqual(storedSpec, expectedSpec) {
		return CompletionArtifacts{}, false, fmt.Errorf("role policies: completion %s does not match pinned intent: %w",
			operationID, ErrStale)
	}
	return artifacts, true, nil
}

func (s *Store) RecognizeCompletion(ctx context.Context, q Querier,
	operationID, policyID uuid.UUID, expectedVersion int64,
	observedFingerprint, expectedFingerprint string,
	expectedSpec adapter.RolePolicySpec,
) (bool, error) {
	_, recognized, err := s.RecoverCompletion(ctx, q, operationID, policyID,
		expectedVersion, observedFingerprint, expectedFingerprint, expectedSpec)
	return recognized, err
}

// Complete records exact Verify, activates role ownership and publishes the
// membership permission atomically. This path works for direct and connector
// execution because exactness comes from adapter.Verify in either mode.
// Adapter fingerprints share one canonical domain: Exact means the observed
// fingerprint equals ExpectedFingerprint, so successful exact Verify may
// safely persist the pinned expected value as the fresh observation.
func (s *Store) Complete(ctx context.Context, q Querier, operationID uuid.UUID,
	expectedVersion int64, observedFingerprint, expectedFingerprint string,
	expectedSpec adapter.RolePolicySpec, completionArtifacts ...CompletionArtifacts,
) (Policy, error) {
	if len(completionArtifacts) > 1 {
		return Policy{}, errors.New("role policies: complete accepts at most one artifact set")
	}
	var artifacts CompletionArtifacts
	if len(completionArtifacts) == 1 {
		artifacts = completionArtifacts[0]
	}
	p, err := s.ValidateTransition(ctx, q, operationID, expectedVersion,
		observedFingerprint, expectedFingerprint, expectedSpec, false)
	if err != nil {
		return Policy{}, err
	}
	exactSummary, err := exactObservedSummary(p.ObservedSummary, p.DesiredSpec)
	if err != nil {
		return Policy{}, err
	}
	completed, err := scanPolicy(q.QueryRow(ctx, `update role_policies set
		managed=true, exact=true, observed_fingerprint=expected_fingerprint,
		observed_summary=$4, blocked_reason='', status='synced',
		transition_operation_id=null, target_started=false,
		transition_retry_pending=false,
		observed_at=now(), updated_at=now()
		where id=$1 and transition_operation_id=$2 and version=$3
		returning `+policyColumns, p.ID, operationID, expectedVersion, exactSummary))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, fmt.Errorf("role policies: complete transition %s: %w", operationID, ErrStale)
		}
		return Policy{}, fmt.Errorf("role policies: complete transition %s: %w", operationID, err)
	}
	if completed.AccountID != nil {
		tag, err := q.Exec(ctx, `update accounts set kind='group', status='active',
			ownership='managed', updated_at=now()
			where id=$1 and connection_id=$2 and engine_identity=$3 and status <> 'deleted'`,
			*completed.AccountID, completed.ConnectionID, completed.DesiredSpec.RoleName)
		if err != nil {
			return Policy{}, fmt.Errorf("role policies: activate role identity: %w", err)
		}
		if tag.RowsAffected() != 1 {
			return Policy{}, fmt.Errorf("role policies: role identity changed before completion: %w", ErrStale)
		}
	}
	var engine string
	if err := q.QueryRow(ctx, `select engine from connections where id=$1`, completed.ConnectionID).Scan(&engine); err != nil {
		return Policy{}, fmt.Errorf("role policies: load connection engine: %w", err)
	}
	attrs, err := policyPermissionAttributes(completed.DesiredSpec, StatusSynced, true)
	if err != nil {
		return Policy{}, err
	}
	if _, err := q.Exec(ctx, `insert into permission_definitions (
		connection_id, engine, external_id, name, assignable, dangerous,
		attributes, status
	) values ($1,$2,$3,$4,true,$5,$6,'observed')
		on conflict (connection_id, external_id) do update set
			name=excluded.name, assignable=true, dangerous=excluded.dangerous, status='observed',
			attributes=permission_definitions.attributes || excluded.attributes,
			updated_at=now()`, completed.ConnectionID, engine, completed.ExternalID,
		completed.DesiredSpec.RoleName, completed.Dangerous, attrs); err != nil {
		return Policy{}, fmt.Errorf("role policies: publish permission %q: %w", completed.ExternalID, err)
	}
	desiredSpec, err := json.Marshal(expectedSpec)
	if err != nil {
		return Policy{}, fmt.Errorf("role policies: marshal completion %s spec: %w", operationID, err)
	}
	if _, err := q.Exec(ctx, `insert into role_policy_operation_completions (
		operation_id, role_policy_id, expected_version, observed_fingerprint,
		expected_fingerprint, desired_spec, plan, result
	) values ($1,$2,$3,$4,$5,$6,$7,$8)`, operationID, completed.ID, expectedVersion,
		observedFingerprint, expectedFingerprint, desiredSpec, artifacts.Plan, artifacts.Result); err != nil {
		return Policy{}, fmt.Errorf("role policies: record completion %s: %w", operationID, err)
	}
	return completed, nil
}

func exactObservedSummary(previous json.RawMessage, spec adapter.RolePolicySpec) ([]byte, error) {
	summary := map[string]any{}
	if len(previous) > 0 {
		if err := json.Unmarshal(previous, &summary); err != nil {
			return nil, fmt.Errorf("role policies: decode observed summary on completion: %w", err)
		}
	}
	summary["missing"] = []string{}
	summary["extra"] = []string{}
	summary["missing_count"] = 0
	summary["extra_count"] = 0
	summary["truncated"] = false
	if spec.Engine == "mongodb" {
		roles, rolesTruncated := completionMongoRolePreview(spec.MongoInheritedRoles)
		privileges, privilegesTruncated := completionMongoPrivilegePreview(spec.MongoPrivileges)
		summary["exists"] = true
		summary["builtin"] = false
		summary["direct_inherited_roles"] = roles
		summary["direct_inherited_roles_count"] = len(spec.MongoInheritedRoles)
		summary["direct_privileges"] = privileges
		summary["direct_privileges_count"] = len(spec.MongoPrivileges)
		summary["truncated"] = rolesTruncated || privilegesTruncated
		// updateRole replaces the direct arrays. Effective inheritance must be
		// rediscovered from rolesInfo rather than copied from a stale pre-repair
		// observation, so omit those projections until the next Sync.
		delete(summary, "inherited_roles")
		delete(summary, "inherited_roles_count")
		delete(summary, "inherited_privileges")
		delete(summary, "inherited_privileges_count")
		summary["auth_restrictions_count"] = 0
		summary["inherited_auth_restrictions_count"] = 0
	}
	if role, ok := summary["role"].(map[string]any); ok {
		role["exists"] = true
		role["safe"] = true
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("role policies: marshal observed summary on completion: %w", err)
	}
	if len(raw) > 64*1024 {
		return nil, errors.New("role policies: completed observed summary exceeds 64 KiB")
	}
	return raw, nil
}

func completionMongoRolePreview(values []adapter.MongoRoleRef) ([]adapter.MongoRoleRef, bool) {
	const limit = 50
	count := min(len(values), limit)
	out := append([]adapter.MongoRoleRef(nil), values[:count]...)
	if out == nil {
		out = []adapter.MongoRoleRef{}
	}
	return out, len(values) > count
}

func completionMongoPrivilegePreview(values []adapter.MongoRolePrivilege) ([]adapter.MongoRolePrivilege, bool) {
	const (
		privilegeLimit = 20
		actionBudget   = 100
	)
	count := min(len(values), privilegeLimit)
	out := make([]adapter.MongoRolePrivilege, 0, count)
	remainingActions := actionBudget
	truncated := len(values) > count
	for _, value := range values[:count] {
		if remainingActions == 0 {
			truncated = true
			break
		}
		actions := value.Actions
		if len(actions) > remainingActions {
			actions = actions[:remainingActions]
			truncated = true
		}
		remainingActions -= len(actions)
		out = append(out, adapter.MongoRolePrivilege{
			Resource: value.Resource, Actions: append([]string(nil), actions...),
		})
	}
	if out == nil {
		out = []adapter.MongoRolePrivilege{}
	}
	return out, truncated
}

// MarkFailed exposes the latest failed attempt but keeps transition ownership
// so automatic/manual retry of the same immutable operation remains valid.
// A new operation may take over only after observing the old operation in a
// terminal failed/cancelled state.
func (s *Store) MarkFailed(ctx context.Context, q Querier, operationID uuid.UUID,
	expectedVersion int64,
) error {
	tag, err := q.Exec(ctx, `update role_policies set status='failed', updated_at=now()
		where transition_operation_id=$1 and version=$2`, operationID, expectedVersion)
	if err != nil {
		return fmt.Errorf("role policies: mark transition %s failed: %w", operationID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("role policies: mark transition %s failed: %w", operationID, ErrStale)
	}
	return nil
}

// MarkRetryExhausted is called by the outer River worker only for a
// deterministic failure or the last allowed attempt. Intermediate failures
// keep retry_pending=true so a new admin request cannot steal the transition
// while River is waiting for its next automatic retry.
func (s *Store) MarkRetryExhausted(ctx context.Context, q Querier, operationID uuid.UUID) error {
	tag, err := q.Exec(ctx, `update role_policies set
		transition_retry_pending=false, status='failed', updated_at=now()
		where transition_operation_id=$1`, operationID)
	if err != nil {
		return fmt.Errorf("role policies: mark transition %s retry exhausted: %w", operationID, err)
	}
	if tag.RowsAffected() == 0 {
		// A malformed/stale role-policy operation may fail before it ever
		// owns a policy row. Its operation status still must become terminal;
		// there is no lifecycle owner to release in that case.
		return nil
	}
	return nil
}

// MarkRetryPending re-arms ownership when the manual retry endpoint moves an
// exhausted operation back to pending. The operation transition and this
// marker are committed in one metadata transaction, so GET can never offer a
// competing Repair while the retried job is queued.
func (s *Store) MarkRetryPending(ctx context.Context, q Querier, operationID uuid.UUID) error {
	tag, err := q.Exec(ctx, `update role_policies set
		transition_retry_pending=true, updated_at=now()
		where transition_operation_id=$1 and status='failed'
		  and transition_retry_pending=false`, operationID)
	if err != nil {
		return fmt.Errorf("role policies: mark transition %s retry pending: %w", operationID, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("role policies: mark transition %s retry pending: %w", operationID, ErrStale)
	}
	return nil
}

// Repairability is the API projection of the same takeover contract enforced
// by Reserve. It distinguishes a transient failed attempt still owned by
// River from a terminal failed/cancelled owner that a fresh Repair operation
// may safely replace.
func (s *Store) Repairability(ctx context.Context, q Querier, p Policy) (repairable, transitionActive bool, err error) {
	base := p.Managed && (!p.Exact || p.Status == StatusFailed) &&
		p.ApplySupported && p.BlockedReason == ""
	if p.DesiredSpec.Engine == "postgres" && p.RoleMissing() {
		base = false
	}
	if p.TransitionOperationID == nil {
		return base, false, nil
	}
	var status string
	err = q.QueryRow(ctx, `select status from operations where id=$1`, *p.TransitionOperationID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("role policies: inspect transition %s: %w", *p.TransitionOperationID, err)
	}
	switch status {
	case "pending_approval", "pending", "running":
		return false, true, nil
	case "failed":
		if p.TransitionRetryPending {
			return false, true, nil
		}
		return base, false, nil
	case "cancelled":
		return base, false, nil
	default:
		return false, false, nil
	}
}

func (p Policy) Repairable() bool {
	return p.Managed && (!p.Exact || p.Status == StatusFailed) &&
		(p.DesiredSpec.Engine != "postgres" || !p.RoleMissing()) &&
		p.ApplySupported && p.BlockedReason == "" &&
		p.TransitionOperationID == nil
}

// MarshalPinnedSpec validates that the operation payload can carry the full
// immutable spec without secrets or engine commands.
func MarshalPinnedSpec(spec adapter.RolePolicySpec) ([]byte, error) {
	b, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("role policies: marshal pinned spec: %w", err)
	}
	return b, nil
}
