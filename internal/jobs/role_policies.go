package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/postgresconfig"
)

const (
	KindRolePolicyApply  = "role.policy.apply"
	KindRolePolicyAdopt  = "role.policy.adopt"
	KindRolePolicyRepair = "role.policy.repair"
	KindRolePolicyCreate = "role.policy.create"
)

// RolePolicyPayload is immutable, secret-free operation intent. Both
// fingerprints and the full normalized spec are pinned, so a queued job can
// never reinterpret a changed connection template.
type RolePolicyPayload struct {
	RolePolicyID                  uuid.UUID              `json:"role_policy_id"`
	Action                        rolepolicies.Action    `json:"action"`
	ExpectedVersion               int64                  `json:"expected_version"`
	ObservedFingerprint           string                 `json:"observed_fingerprint"`
	ExpectedFingerprint           string                 `json:"expected_fingerprint"`
	ExpectedTargetIdentity        string                 `json:"expected_target_identity"`
	ExpectedDatabaseOID           uint32                 `json:"expected_database_oid,omitempty"`
	ExpectedDatabaseOwner         string                 `json:"expected_database_owner,omitempty"`
	ExpectedDatabaseOwnerOID      uint32                 `json:"expected_database_owner_oid,omitempty"`
	ExpectedAdminIdentity         string                 `json:"expected_admin_identity,omitempty"`
	ExpectedConfigIncarnation     string                 `json:"expected_config_incarnation,omitempty"`
	ExpectedCredentialIncarnation int                    `json:"expected_credential_incarnation,omitempty"`
	ExpectedCatalogFingerprint    string                 `json:"expected_catalog_fingerprint,omitempty"`
	ExternalID                    string                 `json:"external_id"`
	Spec                          adapter.RolePolicySpec `json:"spec"`
}

func decodeRolePolicyPayload(raw []byte) (RolePolicyPayload, error) {
	var p RolePolicyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return RolePolicyPayload{}, terminal(fmt.Errorf("decode role policy payload: %w", err))
	}
	switch {
	case p.RolePolicyID == uuid.Nil:
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: role_policy_id is not set"))
	case p.ExpectedVersion <= 0:
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: expected_version must be positive"))
	case p.ObservedFingerprint == "":
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: observed_fingerprint is empty"))
	case p.ExpectedFingerprint == "":
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: expected_fingerprint is empty"))
	case p.ExpectedTargetIdentity == "":
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: expected_target_identity is empty"))
	case p.ExternalID == "":
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: external_id is empty"))
	case p.Spec.Key == "" || p.Spec.RoleName == "":
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: spec identity is incomplete"))
	}
	switch p.Action {
	case rolepolicies.ActionApply, rolepolicies.ActionAdopt, rolepolicies.ActionRepair, rolepolicies.ActionCreate:
	default:
		return RolePolicyPayload{}, terminal(fmt.Errorf("decode role policy payload: unknown action %q", p.Action))
	}
	if p.Action == rolepolicies.ActionCreate && p.Spec.Engine != "postgres" {
		return RolePolicyPayload{}, terminal(errors.New("decode role policy payload: create requires PostgreSQL"))
	}
	if p.ExpectedDatabaseOID != 0 && p.Spec.Engine != "postgres" {
		return p, terminal(errors.New("decode role policy payload: database identity requires PostgreSQL"))
	}
	return p, nil
}

func rolePolicyActionForKind(kind string) rolepolicies.Action {
	switch kind {
	case KindRolePolicyCreate, KindRolePolicyCreateDatabase,
		KindPostgresRolePolicyCreateV2, KindPostgresRolePolicyCreateDatabaseV2:
		return rolepolicies.ActionCreate
	case KindRolePolicyApply, KindPostgresRolePolicyApplyV2:
		return rolepolicies.ActionApply
	case KindRolePolicyAdopt, KindPostgresRolePolicyAdoptV2:
		return rolepolicies.ActionAdopt
	case KindRolePolicyRepair, KindPostgresRolePolicyRepairV2:
		return rolepolicies.ActionRepair
	default:
		return ""
	}
}

// rolePolicyTransitionActionForKind is intentionally separate from current
// execution/retry classification. Helper-era PostgreSQL kinds remain members
// of the durable transition family so River releases their ownership when the
// new worker terminates them, even though the API must not offer a retry.
func rolePolicyTransitionActionForKind(kind string) rolepolicies.Action {
	return rolePolicyActionForKind(kind)
}

func (e *MainExecutor) executeRolePolicy(ctx context.Context, op operations.Operation) error {
	if op.ConnectionID == nil {
		return terminal(fmt.Errorf("jobs: role policy operation %s: connection id is not set", op.ID))
	}
	payload, err := decodeRolePolicyPayload(op.Payload)
	if err != nil {
		return err
	}
	action := rolePolicyActionForKind(op.Kind)
	if action == "" || action != payload.Action {
		return terminal(fmt.Errorf("jobs: role policy operation %s: kind/action mismatch", op.ID))
	}
	v2 := isPostgresV2OperationKind(op.Kind)
	if v2 && (payload.ExpectedDatabaseOID == 0 || payload.ExpectedDatabaseOwner == "" ||
		payload.ExpectedDatabaseOwnerOID == 0 || payload.ExpectedAdminIdentity == "" ||
		payload.ExpectedConfigIncarnation == "" || payload.ExpectedCredentialIncarnation <= 0 ||
		payload.ExpectedCatalogFingerprint == "") {
		return terminal(errors.New("PostgreSQL v2 role policy payload has incomplete authority/database/catalog pins"))
	}
	if err := e.preflightPostgresV2Connector(ctx, op.Kind, *op.ConnectionID); err != nil {
		return e.failRolePolicy(ctx, op, payload, err)
	}
	if !v2 && (op.Kind == KindRolePolicyCreateDatabase) != (payload.ExpectedDatabaseOID != 0) {
		return terminal(errors.New("database-pinned role policy requires its dedicated operation kind"))
	}
	store := rolepolicies.NewStore()
	recoveredArtifacts, alreadyCompleted, err := store.RecoverCompletion(ctx, e.deps.Pool, op.ID,
		payload.RolePolicyID, payload.ExpectedVersion, payload.ObservedFingerprint,
		payload.ExpectedFingerprint, payload.Spec)
	if err != nil {
		return terminal(fmt.Errorf("jobs: role policy operation %s: %w", op.ID, err))
	}
	if alreadyCompleted {
		// Complete, permission publication and the success audit event share
		// the receipt transaction. Only River's outer status marker was lost;
		// returning success here lets it converge without duplicate effects.
		if len(recoveredArtifacts.Plan) > 0 {
			e.setPlanArtifact(op.ID, recoveredArtifacts.Plan)
		}
		if len(recoveredArtifacts.Result) > 0 {
			e.setResultArtifact(op.ID, recoveredArtifacts.Result)
		}
		return nil
	}
	policy, err := store.ValidateTransition(ctx, e.deps.Pool, op.ID,
		payload.ExpectedVersion, payload.ObservedFingerprint,
		payload.ExpectedFingerprint, payload.Spec, action == rolepolicies.ActionAdopt)
	if err != nil {
		return terminal(fmt.Errorf("jobs: role policy operation %s: %w", op.ID, err))
	}
	if policy.ID != payload.RolePolicyID || policy.ConnectionID != *op.ConnectionID ||
		policy.ExternalID != payload.ExternalID {
		return terminal(fmt.Errorf("jobs: role policy operation %s: pinned identity changed: %w",
			op.ID, rolepolicies.ErrStale))
	}

	conn, cfg, direct, viaConnector, err := e.mutationTarget(ctx, op.Kind, policy.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return e.failRolePolicy(ctx, op, payload, err)
	}
	if v2 {
		if err := validatePostgresRuntimePins(conn, cfg, payload.ExpectedAdminIdentity,
			payload.ExpectedTargetIdentity, payload.ExpectedConfigIncarnation,
			payload.ExpectedCredentialIncarnation); err != nil {
			return e.failRolePolicy(ctx, op, payload, err)
		}
		var attrs map[string]any
		if json.Unmarshal(conn.DiscoveryConfig, &attrs) != nil {
			return e.failRolePolicy(ctx, op, payload, terminal(errors.New("current role-policy catalog is malformed")))
		}
		catalog, catalogErr := postgresconfig.FromAttributes(attrs)
		if catalogErr != nil || postgresconfig.CatalogFingerprint(catalog) != payload.ExpectedCatalogFingerprint {
			return e.failRolePolicy(ctx, op, payload, terminal(errors.New("current role-policy catalog no longer matches intent")))
		}
	}
	capabilityAdapter := direct
	if viaConnector {
		capabilityAdapter, err = adapter.New(conn.Engine)
		if err != nil {
			return e.failRolePolicy(ctx, op, payload, terminal(err))
		}
	}
	capability := adapter.CapRolePolicyApply
	if action == rolepolicies.ActionCreate {
		capability = adapter.CapRolePolicyCreate
	}
	if !capabilityAdapter.Manifest().HasCapability(capability) ||
		!slices.Contains(conn.Capabilities, string(capability)) {
		return e.failRolePolicy(ctx, op, payload, terminal(fmt.Errorf(
			"%s is unsupported for connection %s: %w", capability, conn.ID, adapter.ErrUnsupportedChange)))
	}
	actualTargetIdentity := connections.TargetIdentity(conn)
	if actualTargetIdentity == "" || actualTargetIdentity != payload.ExpectedTargetIdentity {
		return e.failRolePolicy(ctx, op, payload, terminal(fmt.Errorf(
			"role policy target identity changed: expected %q, got %q: %w",
			payload.ExpectedTargetIdentity, actualTargetIdentity, rolepolicies.ErrStale)))
	}

	changeKind := adapter.ChangeRolePolicyApply
	jobKind := connector.JobApply
	if action == rolepolicies.ActionCreate {
		changeKind = adapter.ChangeRolePolicyCreate
		if payload.ExpectedDatabaseOID != 0 {
			changeKind = adapter.ChangeRolePolicyCreateDatabase
		}
	}
	if action == rolepolicies.ActionAdopt {
		changeKind = adapter.ChangeRolePolicyVerify
		jobKind = connector.JobVerify
	}
	if v2 {
		if mapped, ok := postgresV2OperationChangeKind[op.Kind]; ok {
			changeKind = mapped
		}
	}
	spec := payload.Spec
	desired := adapter.DesiredChange{
		Kind: changeKind, Connection: cfg, Permission: payload.ExternalID,
		RolePolicySpec: &spec, ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
		ExpectedDatabaseOID:      payload.ExpectedDatabaseOID,
		ExpectedDatabaseOwner:    payload.ExpectedDatabaseOwner,
		ExpectedDatabaseOwnerOID: payload.ExpectedDatabaseOwnerOID,
		ExpectedAdminIdentity:    payload.ExpectedAdminIdentity,
	}
	if op.Kind == KindRolePolicyCreateDatabase || op.Kind == KindPostgresRolePolicyCreateDatabaseV2 {
		desired.Permission = ""
	}
	if action != rolepolicies.ActionAdopt {
		if v2 && action != rolepolicies.ActionCreate && policy.RoleMissing() {
			return e.failRolePolicy(ctx, op, payload, terminal(fmt.Errorf("policy role %q is missing; create it explicitly instead of retrying apply: %w", spec.RoleName, adapter.ErrNotFound)))
		}
		if _, err := store.BeginTarget(ctx, e.deps.Pool, op.ID,
			payload.ExpectedVersion, payload.ObservedFingerprint,
			payload.ExpectedFingerprint, payload.Spec); err != nil {
			return e.failRolePolicy(ctx, op, payload,
				terminal(fmt.Errorf("begin target transition: %w", err)))
		}
	}
	var verification *adapter.Verification
	switch {
	case viaConnector:
		if v2 {
			if err := e.requireActiveConnectorCapability(adapter.CapPostgresSuperuserDirectV1); err != nil {
				return e.failRolePolicy(ctx, op, payload, err)
			}
		}
		change := connector.ChangeRef{
			Kind: string(changeKind), Permission: desired.Permission,
			RolePolicySpec: &spec, ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
			ExpectedDatabaseOID:        payload.ExpectedDatabaseOID,
			ExpectedAdminIdentity:      payload.ExpectedAdminIdentity,
			ExpectedDatabaseOwner:      payload.ExpectedDatabaseOwner,
			ExpectedDatabaseOwnerOID:   payload.ExpectedDatabaseOwnerOID,
			ExpectedCatalogFingerprint: payload.ExpectedCatalogFingerprint,
		}
		job, buildErr := connectorMutationJobOfKind(op, conn, cfg, change, jobKind, time.Now())
		if buildErr != nil {
			err = buildErr
		} else {
			var result connector.JobResult
			result, err = e.connectorDispatch(ctx, job, connectorJobCredentials(cfg))
			if len(result.Plan) > 0 {
				e.setPlanArtifact(op.ID, result.Plan)
			}
			if len(result.Result) > 0 {
				e.setResultArtifact(op.ID, result.Result)
			}
			if err == nil && result.Status != connector.JobSuccess {
				err = fmt.Errorf("connector job %s: status %q: %s", job.ID, result.Status, result.Error)
			}
			if err == nil {
				var parsed connector.SanitizedResult
				parsed, err = connector.ParseSanitizedResult(result.Result)
				if err == nil && parsed.Verification == nil {
					err = fmt.Errorf("connector job %s: result carries no verification", job.ID)
				}
				if err == nil {
					verification = &adapter.Verification{
						Verified: parsed.Verification.Verified,
						Details:  parsed.Verification.Details,
						Observed: parsed.Verification.Observed,
					}
				}
			}
		}
	case action == rolepolicies.ActionAdopt:
		verification, err = e.planVerifyRolePolicy(ctx, op.ID, direct, desired)
	default:
		verification, err = e.planApplyVerify(ctx, op.ID, direct, desired)
	}
	if err == nil && (verification == nil || !verification.Verified) {
		details := ""
		if verification != nil {
			details = verification.Details
		}
		err = fmt.Errorf("verify: target role policy is not exact: %s", details)
	}
	if err != nil {
		return e.failRolePolicy(ctx, op, payload, err)
	}

	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: role policy operation %s: begin completion: %w", op.ID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	artifacts := e.loadArtifacts(op.ID)
	completed, err := store.Complete(ctx, tx, op.ID, payload.ExpectedVersion,
		payload.ObservedFingerprint, payload.ExpectedFingerprint, payload.Spec,
		rolepolicies.CompletionArtifacts{Plan: artifacts.Plan, Result: artifacts.Result})
	if err != nil {
		return fmt.Errorf("jobs: role policy operation %s: complete: %w", op.ID, err)
	}
	metadata, err := json.Marshal(map[string]any{
		"template_key": completed.TemplateKey,
		"external_id":  completed.ExternalID,
		"profile":      completed.DesiredSpec.Profile,
		"action":       action,
	})
	if err != nil {
		return fmt.Errorf("jobs: role policy operation %s: marshal audit metadata: %w", op.ID, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID,
		Action:       rolePolicySuccessAuditAction(action),
		ConnectionID: &completed.ConnectionID, AccountID: completed.AccountID,
		OperationID: &op.ID, Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		return fmt.Errorf("jobs: role policy operation %s: audit: %w", op.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: role policy operation %s: commit: %w", op.ID, err)
	}
	return nil
}

func rolePolicySuccessAuditAction(action rolepolicies.Action) string {
	switch action {
	case rolepolicies.ActionCreate:
		return "role_policy.created"
	case rolepolicies.ActionApply:
		return "role_policy.applied"
	case rolepolicies.ActionAdopt:
		return "role_policy.adopted"
	case rolepolicies.ActionRepair:
		return "role_policy.repaired"
	default:
		return "role_policy.completed"
	}
}

func (e *MainExecutor) planVerifyRolePolicy(ctx context.Context, opID uuid.UUID,
	ad adapter.Adapter, change adapter.DesiredChange,
) (*adapter.Verification, error) {
	plan, err := ad.Plan(ctx, change)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	planBytes, err := marshalPlan(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal plan: %w", err)
	}
	e.setPlanArtifact(opID, planBytes)
	verification, err := ad.Verify(ctx, *plan)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	result, err := marshalResult(&adapter.Result{}, verification)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	e.setResultArtifact(opID, result)
	if !verification.Verified {
		return verification, fmt.Errorf("verify: target role policy is not exact: %s", verification.Details)
	}
	return verification, nil
}

func (e *MainExecutor) failRolePolicy(ctx context.Context, op operations.Operation,
	payload RolePolicyPayload, cause error,
) error {
	metadata, marshalErr := json.Marshal(map[string]any{
		"template_key": payload.Spec.Key, "action": payload.Action,
		"error": cause.Error(),
	})
	if marshalErr != nil {
		return errors.Join(cause, marshalErr)
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return errors.Join(cause, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := rolepolicies.NewStore().MarkFailed(ctx, tx, op.ID, payload.ExpectedVersion); err != nil &&
		!errors.Is(err, rolepolicies.ErrStale) {
		return errors.Join(cause, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID,
		Action:       "role_policy." + string(payload.Action) + "_failed",
		ConnectionID: op.ConnectionID, OperationID: &op.ID,
		Result: audit.ResultFailure, Metadata: metadata,
	}); err != nil {
		return errors.Join(cause, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}
