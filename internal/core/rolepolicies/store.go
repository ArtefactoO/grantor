package rolepolicies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArtefactoO/grantor/internal/adapter"
)

// Querier is satisfied by both pgx pools and transactions.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

type Store struct{}

func NewStore() *Store { return &Store{} }

const policyColumns = `id, connection_id, account_id, template_key, name,
	description, external_id, desired_spec, expected_fingerprint,
	observed_fingerprint, observed_summary, managed, exact, dangerous, apply_supported,
	blocked_reason, status, version, transition_operation_id, target_started,
	transition_retry_pending, observed_at,
	created_at, updated_at`

func scanPolicy(row pgx.Row) (Policy, error) {
	var p Policy
	var desired []byte
	err := row.Scan(
		&p.ID, &p.ConnectionID, &p.AccountID, &p.TemplateKey, &p.Name,
		&p.Description, &p.ExternalID, &desired, &p.ExpectedFingerprint,
		&p.ObservedFingerprint, &p.ObservedSummary, &p.Managed, &p.Exact,
		&p.Dangerous, &p.ApplySupported, &p.BlockedReason, &p.Status, &p.Version,
		&p.TransitionOperationID, &p.TargetStarted, &p.TransitionRetryPending,
		&p.ObservedAt, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		return Policy{}, err
	}
	if err := json.Unmarshal(desired, &p.DesiredSpec); err != nil {
		return Policy{}, fmt.Errorf("decode desired spec: %w", err)
	}
	return p, nil
}

func (s *Store) Get(ctx context.Context, q Querier, id uuid.UUID) (Policy, error) {
	p, err := scanPolicy(q.QueryRow(ctx,
		`select `+policyColumns+` from role_policies where id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, fmt.Errorf("role policies: get %s: %w", id, ErrNotFound)
		}
		return Policy{}, fmt.Errorf("role policies: get %s: %w", id, err)
	}
	return p, nil
}

func (s *Store) GetByKey(ctx context.Context, q Querier, connectionID uuid.UUID, key string) (Policy, error) {
	p, err := scanPolicy(q.QueryRow(ctx,
		`select `+policyColumns+` from role_policies where connection_id = $1 and template_key = $2`,
		connectionID, key))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, fmt.Errorf("role policies: key %q in connection %s: %w", key, connectionID, ErrNotFound)
		}
		return Policy{}, fmt.Errorf("role policies: get key %q: %w", key, err)
	}
	return p, nil
}

func (s *Store) List(ctx context.Context, q Querier, connectionID uuid.UUID) ([]Policy, error) {
	rows, err := q.Query(ctx, `select `+policyColumns+` from role_policies
		where connection_id = $1 order by name, template_key`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("role policies: list connection %s: %w", connectionID, err)
	}
	defer rows.Close()
	var out []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("role policies: list connection %s: scan: %w", connectionID, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("role policies: list connection %s: %w", connectionID, err)
	}
	return out, nil
}

// ReconcileSnapshot persists role-policy observations after the ordinary
// inventory snapshot is reconciled, in the same transaction. It preserves
// managed desired intent, fences identity changes and changes assignability
// only from exact managed state.
func (s *Store) ReconcileSnapshot(ctx context.Context, q Querier, connectionID uuid.UUID,
	observed []adapter.ObservedRolePolicy, observedAt time.Time,
) error {
	var engine string
	if err := q.QueryRow(ctx, `select engine from connections where id = $1`, connectionID).Scan(&engine); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("role policies: reconcile connection %s: %w", connectionID, ErrNotFound)
		}
		return fmt.Errorf("role policies: reconcile connection %s: %w", connectionID, err)
	}

	seenKeys := make(map[string]struct{}, len(observed))
	seenExternal := make(map[string]struct{}, len(observed))
	for i := range observed {
		o := observed[i]
		if err := validateObservation(engine, o); err != nil {
			return fmt.Errorf("role policies: reconcile observation %d: %w", i, err)
		}
		if _, dup := seenKeys[o.Spec.Key]; dup {
			return fmt.Errorf("role policies: duplicate template key %q", o.Spec.Key)
		}
		if _, dup := seenExternal[o.ExternalID]; dup {
			return fmt.Errorf("role policies: duplicate external id %q", o.ExternalID)
		}
		seenKeys[o.Spec.Key] = struct{}{}
		seenExternal[o.ExternalID] = struct{}{}
	}

	for i := range observed {
		if err := s.reconcileOne(ctx, q, connectionID, observed[i], observedAt); err != nil {
			return err
		}
	}
	if err := s.reconcileRemoved(ctx, q, connectionID, seenKeys); err != nil {
		return err
	}
	return s.reconcileMongoDependencies(ctx, q, connectionID)
}

// reconcileMongoDependencies prevents a policy from laundering an unmanaged
// custom role through an otherwise exact direct definition. Mongo templates
// may inherit built-in read/readWrite directly; every other dependency is a
// catalog role-policy and must itself be managed, exact and transition-free.
// Existing user bindings are never revoked, but the dependent permission and
// new lifecycle mutations fail closed until a later discovery sees the whole
// dependency graph ready again.
func (s *Store) reconcileMongoDependencies(ctx context.Context, q Querier, connectionID uuid.UUID) error {
	policies, err := s.List(ctx, q, connectionID)
	if err != nil {
		return err
	}
	byExternalID := make(map[string]Policy, len(policies))
	for _, policy := range policies {
		byExternalID[policy.ExternalID] = policy
	}

	const (
		unvisited = iota
		visiting
		visited
	)
	state := make(map[string]int, len(policies))
	ready := make(map[string]bool, len(policies))
	var policyReady func(string) bool
	policyReady = func(externalID string) bool {
		if state[externalID] == visited {
			return ready[externalID]
		}
		if state[externalID] == visiting {
			// Catalog validation rejects cycles. Stored legacy/corrupt state is
			// nevertheless treated conservatively instead of recursing forever.
			return false
		}
		policy, exists := byExternalID[externalID]
		if !exists {
			return false
		}
		state[externalID] = visiting
		value := policy.Managed && policy.Exact && policy.ApplySupported &&
			policy.BlockedReason == "" && policy.Status == StatusSynced &&
			policy.TransitionOperationID == nil
		if value && policy.DesiredSpec.Engine == "mongodb" {
			for _, dependency := range policy.DesiredSpec.MongoInheritedRoles {
				if mongoBuiltinPolicyDependency(dependency) {
					continue
				}
				if !policyReady(mongoRolePolicyExternalID(dependency)) {
					value = false
					break
				}
			}
		}
		state[externalID] = visited
		ready[externalID] = value
		return value
	}

	for _, policy := range policies {
		if policy.DesiredSpec.Engine != "mongodb" || policy.BlockedReason != "" {
			continue
		}
		var blockers []string
		for _, dependency := range policy.DesiredSpec.MongoInheritedRoles {
			if mongoBuiltinPolicyDependency(dependency) {
				continue
			}
			externalID := mongoRolePolicyExternalID(dependency)
			if !policyReady(externalID) {
				blockers = append(blockers, externalID)
			}
		}
		if len(blockers) == 0 {
			continue
		}
		slices.Sort(blockers)
		summary, err := dependencyBlockedSummary(policy.ObservedSummary, blockers)
		if err != nil {
			return fmt.Errorf("role policies: dependency summary %q: %w", policy.TemplateKey, err)
		}
		const reason = "inherited_policy_not_ready"
		if _, err := q.Exec(ctx, `update role_policies set
			observed_summary=$2, apply_supported=false, blocked_reason=$3,
			status='blocked', updated_at=now() where id=$1`, policy.ID, summary, reason); err != nil {
			return fmt.Errorf("role policies: block inherited policy %q: %w", policy.TemplateKey, err)
		}
		if err := s.setPermissionPolicyState(ctx, q, connectionID, policy.ExternalID,
			policy.DesiredSpec, policy.Managed, false, policy.Dangerous, false, reason); err != nil {
			return err
		}
	}
	return nil
}

func mongoBuiltinPolicyDependency(ref adapter.MongoRoleRef) bool {
	return ref.Role == "read" || ref.Role == "readWrite"
}

func mongoRolePolicyExternalID(ref adapter.MongoRoleRef) string {
	return "role:" + ref.DB + "." + ref.Role
}

func dependencyBlockedSummary(previous json.RawMessage, blockers []string) ([]byte, error) {
	summary := map[string]any{}
	if len(previous) > 0 {
		if err := json.Unmarshal(previous, &summary); err != nil {
			return nil, err
		}
	}
	summary["dependency_blockers"] = blockers
	raw, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if len(raw) > 64*1024 {
		return nil, errors.New("observed summary exceeds 64 KiB after dependency projection")
	}
	return raw, nil
}

func validateObservation(engine string, o adapter.ObservedRolePolicy) error {
	spec := o.Spec
	switch {
	case spec.Engine == "":
		return errors.New("spec engine is empty")
	case spec.Engine != engine:
		return fmt.Errorf("spec engine %q differs from connection engine %q", spec.Engine, engine)
	case spec.Key == "":
		return errors.New("spec key is empty")
	case spec.Name == "":
		return errors.New("spec name is empty")
	case spec.RoleName == "":
		return errors.New("spec role_name is empty")
	case o.ExternalID == "":
		return errors.New("external_id is empty")
	case o.ExpectedFingerprint == "":
		return errors.New("expected_fingerprint is empty")
	}
	return nil
}

func normalizeSummary(summary map[string]any) ([]byte, error) {
	if summary == nil {
		summary = map[string]any{}
	}
	for _, key := range []string{"missing", "extra"} {
		values, err := normalizePreviewList(summary[key])
		if err != nil {
			return nil, fmt.Errorf("%s preview: %w", key, err)
		}
		summary[key] = values
	}
	b, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("marshal observed summary: %w", err)
	}
	if len(b) > 64*1024 {
		return nil, errors.New("observed summary exceeds 64 KiB")
	}
	return b, nil
}

func normalizePreviewList(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	var out []string
	switch values := value.(type) {
	case []string:
		out = append(out, values...)
	case []any:
		out = make([]string, 0, len(values))
		for _, item := range values {
			text, ok := item.(string)
			if !ok {
				return nil, errors.New("must contain only strings")
			}
			out = append(out, text)
		}
	default:
		return nil, errors.New("must be an array")
	}
	if len(out) > 200 {
		return nil, errors.New("must contain at most 200 entries")
	}
	for _, item := range out {
		if len(item) > 512 {
			return nil, errors.New("entry exceeds 512 bytes")
		}
	}
	return out, nil
}

func policyStatus(managed, exact, supported, exists bool, blocked string) Status {
	if blocked != "" || (managed && !supported) {
		return StatusBlocked
	}
	if !exists {
		return StatusMissing
	}
	if !managed {
		return StatusObserved
	}
	if exact {
		return StatusSynced
	}
	return StatusDrift
}

func observationRoleExists(summary map[string]any) bool {
	if exists, ok := summary["exists"].(bool); ok {
		return exists
	}
	role, ok := summary["role"].(map[string]any)
	if !ok {
		return true
	}
	exists, ok := role["exists"].(bool)
	return !ok || exists
}

func policyIdentity(spec adapter.RolePolicySpec) [3]string {
	return [3]string{spec.Engine, spec.RoleName, spec.Database}
}

func (s *Store) reconcileOne(ctx context.Context, q Querier, connectionID uuid.UUID,
	o adapter.ObservedRolePolicy, observedAt time.Time,
) error {
	desired, err := json.Marshal(o.Spec)
	if err != nil {
		return fmt.Errorf("role policies: template %q: marshal desired spec: %w", o.Spec.Key, err)
	}
	summary, err := normalizeSummary(o.Summary)
	if err != nil {
		return fmt.Errorf("role policies: template %q: %w", o.Spec.Key, err)
	}
	accountID, err := matchingAccountID(ctx, q, connectionID, o.Spec)
	if err != nil {
		return err
	}

	existing, err := scanPolicy(q.QueryRow(ctx, `select `+policyColumns+` from role_policies
		where connection_id = $1 and template_key = $2 for update`, connectionID, o.Spec.Key))
	if errors.Is(err, pgx.ErrNoRows) {
		blocked := o.BlockedReason
		status := policyStatus(false, o.Exact, o.ApplySupported,
			observationRoleExists(o.Summary), blocked)
		_, err = q.Exec(ctx, `insert into role_policies (
			connection_id, account_id, template_key, name, description, external_id,
			desired_spec, expected_fingerprint, observed_fingerprint,
			observed_summary, exact, dangerous, apply_supported, blocked_reason, status,
			observed_at
		) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
			connectionID, accountID, o.Spec.Key, o.Spec.Name, o.Spec.Description,
			o.ExternalID, desired, o.ExpectedFingerprint, o.ObservedFingerprint,
			summary, o.Exact, o.Dangerous, o.ApplySupported, blocked, status, observedAt)
		if err != nil {
			return fmt.Errorf("role policies: insert template %q: %w", o.Spec.Key, err)
		}
		return s.setPermissionPolicyState(ctx, q, connectionID, o.ExternalID,
			o.Spec, false, o.Exact, o.Dangerous, o.ApplySupported, blocked)
	}
	if err != nil {
		return fmt.Errorf("role policies: load template %q: %w", o.Spec.Key, err)
	}

	used, err := policyPermissionUsed(ctx, q, connectionID, existing.ExternalID)
	if err != nil {
		return err
	}
	if policyIdentity(existing.DesiredSpec) != policyIdentity(o.Spec) && (existing.Managed || used) {
		const reason = "template_identity_changed"
		if _, err := q.Exec(ctx, `update role_policies set
			observed_fingerprint=$2, observed_summary=$3, exact=false,
			apply_supported=false, blocked_reason=$4, status='blocked',
			observed_at=$5, updated_at=now()
			where id=$1`, existing.ID, o.ObservedFingerprint, summary, reason, observedAt); err != nil {
			return fmt.Errorf("role policies: block identity change %q: %w", o.Spec.Key, err)
		}
		return s.setPermissionPolicyState(ctx, q, connectionID, existing.ExternalID,
			existing.DesiredSpec, existing.Managed, false, existing.Dangerous, false, reason)
	}

	blocked := o.BlockedReason
	if existing.Managed && !o.ApplySupported && blocked == "" {
		blocked = "apply_unsupported"
	}
	status := policyStatus(existing.Managed, o.Exact, o.ApplySupported,
		observationRoleExists(o.Summary), blocked)
	if existing.TransitionOperationID != nil {
		status = existing.Status
	}
	changed := !reflect.DeepEqual(existing.DesiredSpec, o.Spec) ||
		existing.ExpectedFingerprint != o.ExpectedFingerprint ||
		existing.ExternalID != o.ExternalID ||
		existing.Dangerous != o.Dangerous
	versionDelta := 0
	if changed && existing.TransitionOperationID == nil {
		versionDelta = 1
	}
	if _, err := q.Exec(ctx, `update role_policies set
		account_id=$2, name=$3, description=$4, external_id=$5,
		desired_spec=$6, expected_fingerprint=$7, observed_fingerprint=$8,
		observed_summary=$9, exact=$10,
		dangerous=case when transition_operation_id is null then $11 else dangerous end,
		apply_supported=$12,
		blocked_reason=$13, status=$14, version=version+$15,
		observed_at=$16, updated_at=now()
		where id=$1`, existing.ID, accountID, o.Spec.Name, o.Spec.Description,
		o.ExternalID, desired, o.ExpectedFingerprint, o.ObservedFingerprint,
		summary, o.Exact, o.Dangerous, o.ApplySupported, blocked, status, versionDelta, observedAt); err != nil {
		return fmt.Errorf("role policies: update template %q: %w", o.Spec.Key, err)
	}
	assignmentExact := o.Exact && existing.TransitionOperationID == nil
	return s.setPermissionPolicyState(ctx, q, connectionID, o.ExternalID,
		o.Spec, existing.Managed, assignmentExact, o.Dangerous, o.ApplySupported, blocked)
}

func matchingAccountID(ctx context.Context, q Querier, connectionID uuid.UUID,
	spec adapter.RolePolicySpec,
) (*uuid.UUID, error) {
	// PostgreSQL roles and accounts share one identity namespace. Other
	// engines may materialize roles independently and intentionally keep the
	// optional account link empty.
	if spec.Engine != "postgres" {
		return nil, nil
	}
	var id uuid.UUID
	err := q.QueryRow(ctx, `select id from accounts
		where connection_id=$1 and engine_identity=$2 and status <> 'deleted'`,
		connectionID, spec.RoleName).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("role policies: find account %q: %w", spec.RoleName, err)
	}
	return &id, nil
}

func policyPermissionUsed(ctx context.Context, q Querier, connectionID uuid.UUID, externalID string) (bool, error) {
	var used bool
	err := q.QueryRow(ctx, `select exists (
		select 1 from permission_definitions p
		join bindings b on b.permission_definition_id = p.id
		join accounts a on a.id = b.account_id
		where p.connection_id=$1 and p.external_id=$2
		  and (
			b.desired_state = 'present'
			or (b.observed_state = 'present' and b.observed_effective)
		  )
		  and not (
			coalesce(p.attributes->>'role_policy_key', '') <> ''
			and a.attributes @> '{"connection_admin":true}'::jsonb
			and b.observed_attributes @> '{"admin_option":true}'::jsonb
		  )
	)`, connectionID, externalID).Scan(&used)
	if err != nil {
		return false, fmt.Errorf("role policies: inspect permission use %q: %w", externalID, err)
	}
	return used, nil
}

func (s *Store) reconcileRemoved(ctx context.Context, q Querier, connectionID uuid.UUID,
	seen map[string]struct{},
) error {
	rows, err := q.Query(ctx, `select `+policyColumns+` from role_policies
		where connection_id=$1 for update`, connectionID)
	if err != nil {
		return fmt.Errorf("role policies: inspect removed templates: %w", err)
	}
	var policies []Policy
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			rows.Close()
			return fmt.Errorf("role policies: inspect removed templates: scan: %w", err)
		}
		policies = append(policies, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("role policies: inspect removed templates: %w", err)
	}
	for _, p := range policies {
		if _, ok := seen[p.TemplateKey]; ok {
			continue
		}
		used, err := policyPermissionUsed(ctx, q, connectionID, p.ExternalID)
		if err != nil {
			return err
		}
		if !p.Managed && !used && p.TransitionOperationID == nil {
			if _, err := q.Exec(ctx, `delete from role_policies where id=$1`, p.ID); err != nil {
				return fmt.Errorf("role policies: remove unused template %q: %w", p.TemplateKey, err)
			}
			continue
		}
		const reason = "template_removed"
		if _, err := q.Exec(ctx, `update role_policies set exact=false,
			apply_supported=false, blocked_reason=$2, status='blocked',
			observed_at=now(), updated_at=now() where id=$1`, p.ID, reason); err != nil {
			return fmt.Errorf("role policies: block removed template %q: %w", p.TemplateKey, err)
		}
		if err := s.setPermissionPolicyState(ctx, q, connectionID, p.ExternalID,
			p.DesiredSpec, p.Managed, false, p.Dangerous, false, reason); err != nil {
			return err
		}
	}
	return nil
}

func policyPermissionAttributes(spec adapter.RolePolicySpec, status Status, managed bool) ([]byte, error) {
	return json.Marshal(map[string]any{
		"role_policy_key":     spec.Key,
		"role_policy_managed": managed,
		"role_policy_status":  status,
		"role_policy_profile": spec.Profile,
	})
}

func (s *Store) setPermissionPolicyState(ctx context.Context, q Querier,
	connectionID uuid.UUID, externalID string, spec adapter.RolePolicySpec,
	managed, exact, dangerous, supported bool, blocked string,
) error {
	assignable := managed && exact && supported && blocked == ""
	status := policyStatus(managed, exact, supported, true, blocked)
	attrs, err := policyPermissionAttributes(spec, status, managed)
	if err != nil {
		return fmt.Errorf("role policies: permission attributes %q: %w", externalID, err)
	}
	// Reconciliation does not invent a target role before successful exact
	// Verify. It only gates an already discovered definition.
	if _, err := q.Exec(ctx, `update permission_definitions set
		assignable=$3, dangerous=$4, attributes=attributes || $5::jsonb, updated_at=now()
		where connection_id=$1 and external_id=$2`,
		connectionID, externalID, assignable, dangerous, attrs); err != nil {
		return fmt.Errorf("role policies: gate permission %q: %w", externalID, err)
	}
	return nil
}

// ValidateTemplateChange rejects removal or physical identity changes of a
// managed/used policy and any edit while a transition owns the policy.
func (s *Store) ValidateTemplateChange(ctx context.Context, q Querier,
	connectionID uuid.UUID, next []adapter.RolePolicySpec,
) error {
	byKey := make(map[string]adapter.RolePolicySpec, len(next))
	for _, spec := range next {
		if _, duplicate := byKey[spec.Key]; duplicate {
			return fmt.Errorf("duplicate role policy template key %q", spec.Key)
		}
		byKey[spec.Key] = spec
	}
	current, err := s.List(ctx, q, connectionID)
	if err != nil {
		return err
	}
	for _, p := range current {
		used, err := policyPermissionUsed(ctx, q, connectionID, p.ExternalID)
		if err != nil {
			return err
		}
		nextSpec, exists := byKey[p.TemplateKey]
		if p.TransitionOperationID != nil {
			if !exists || !reflect.DeepEqual(p.DesiredSpec, nextSpec) {
				return fmt.Errorf("template %q has an active transition: %w", p.TemplateKey, ErrConflict)
			}
			continue
		}
		if !p.Managed && !used {
			continue
		}
		if !exists {
			return fmt.Errorf("template %q is managed or used and cannot be removed: %w",
				p.TemplateKey, ErrUnsafeTemplateChange)
		}
		if policyIdentity(p.DesiredSpec) != policyIdentity(nextSpec) {
			return fmt.Errorf("template %q role/database identity cannot change while managed or used: %w",
				p.TemplateKey, ErrUnsafeTemplateChange)
		}
	}
	return nil
}
