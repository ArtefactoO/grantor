package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

type rolePolicyJSON struct {
	ID                    uuid.UUID                        `json:"id"`
	ConnectionID          uuid.UUID                        `json:"connection_id"`
	Key                   string                           `json:"template_key"`
	Name                  string                           `json:"name"`
	Description           string                           `json:"description"`
	ExternalID            string                           `json:"external_id"`
	DesiredSpec           rolepolicies.PolicyTechnicalSpec `json:"desired_spec"`
	ExpectedFingerprint   string                           `json:"expected_fingerprint"`
	ObservedFingerprint   string                           `json:"observed_fingerprint"`
	ObservedSummary       json.RawMessage                  `json:"observed_summary"`
	Managed               bool                             `json:"managed"`
	Exact                 bool                             `json:"exact"`
	Dangerous             bool                             `json:"dangerous"`
	ApplySupported        bool                             `json:"apply_supported"`
	Repairable            bool                             `json:"repairable"`
	Creatable             bool                             `json:"creatable"`
	TransitionActive      bool                             `json:"transition_active"`
	BlockedReason         string                           `json:"blocked_reason"`
	Status                rolepolicies.Status              `json:"status"`
	Version               int64                            `json:"version"`
	TransitionOperationID *uuid.UUID                       `json:"transition_operation_id,omitempty"`
	ObservedAt            *time.Time                       `json:"observed_at,omitempty"`
	UpdatedAt             time.Time                        `json:"updated_at"`
}

type rolePolicyListResponse struct {
	Policies  []rolePolicyJSON    `json:"policies"`
	Inventory *inventoryFreshness `json:"inventory,omitempty"`
}

func toRolePolicyJSON(p rolepolicies.Policy, repairable, transitionActive bool) rolePolicyJSON {
	return rolePolicyJSON{
		ID: p.ID, ConnectionID: p.ConnectionID, Key: p.TemplateKey,
		Name: p.Name, Description: p.Description, ExternalID: p.ExternalID,
		DesiredSpec:         rolepolicies.TechnicalSpec(p.DesiredSpec),
		ExpectedFingerprint: p.ExpectedFingerprint,
		ObservedFingerprint: p.ObservedFingerprint,
		ObservedSummary:     p.ObservedSummary, Managed: p.Managed, Exact: p.Exact,
		Dangerous:      p.Dangerous,
		ApplySupported: p.ApplySupported, Repairable: repairable,
		TransitionActive: transitionActive,
		BlockedReason:    p.BlockedReason, Status: p.Status, Version: p.Version,
		TransitionOperationID: p.TransitionOperationID,
		ObservedAt:            p.ObservedAt, UpdatedAt: p.UpdatedAt,
	}
}

func (s *Server) listRolePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	conn, err := s.connections.Get(ctx, tx, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	policies, err := rolepolicies.NewStore().List(ctx, tx, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	out := make([]rolePolicyJSON, 0, len(policies))
	for _, p := range policies {
		repairable, transitionActive, err := rolepolicies.NewStore().Repairability(ctx, tx, p)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		creatable, err := rolepolicies.NewStore().Creatability(ctx, tx, p)
		if err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		projected := toRolePolicyJSON(p, repairable, transitionActive)
		projected.Creatable = creatable && !transitionActive
		out = append(out, projected)
	}
	freshness, err := inventoryFreshnessForSnapshot(ctx, tx, conn, policies)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusOK, rolePolicyListResponse{Policies: out, Inventory: freshness})
}

type rolePolicyMutationRequest struct {
	RequestID              uuid.UUID          `json:"request_id"`
	Version                int64              `json:"version"`
	ObservedFingerprint    string             `json:"observed_fingerprint"`
	Confirm                bool               `json:"confirm"`
	ExpectedTargetIdentity patchField[string] `json:"expected_target_identity"`
}

func (r rolePolicyMutationRequest) validate(action rolepolicies.Action) error {
	if r.RequestID == uuid.Nil {
		return errors.New("request_id is required")
	}
	if r.Version < 0 {
		return errors.New("version must be non-negative")
	}
	if strings.TrimSpace(r.ObservedFingerprint) == "" {
		return errors.New("observed_fingerprint is required")
	}
	if !r.Confirm {
		return errors.New("confirm=true is required after reviewing the policy preview")
	}
	if action == rolepolicies.ActionCreate {
		if !r.ExpectedTargetIdentity.Set || strings.TrimSpace(r.ExpectedTargetIdentity.Value) == "" {
			return errors.New("expected_target_identity is required for role policy creation")
		}
	} else if r.ExpectedTargetIdentity.Set {
		return errors.New("expected_target_identity is supported only for role policy creation")
	}
	return nil
}

func validateRolePolicyKey(key string) error {
	if key == "" {
		return errors.New("role policy key is required")
	}
	if !utf8.ValidString(key) || len(key) > 128 {
		return errors.New("role policy key must be valid UTF-8 and at most 128 bytes")
	}
	if strings.TrimSpace(key) != key || strings.ContainsFunc(key, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) {
		return errors.New("role policy key must not contain surrounding whitespace or control characters")
	}
	return nil
}

func rolePolicyOperationKind(action rolepolicies.Action) string {
	switch action {
	case rolepolicies.ActionCreate:
		return jobs.KindRolePolicyCreate
	case rolepolicies.ActionApply:
		return jobs.KindRolePolicyApply
	case rolepolicies.ActionAdopt:
		return jobs.KindRolePolicyAdopt
	case rolepolicies.ActionRepair:
		return jobs.KindRolePolicyRepair
	default:
		return ""
	}
}

func postgresRolePolicyOperationKind(action rolepolicies.Action) string {
	switch action {
	case rolepolicies.ActionCreate:
		return jobs.KindPostgresRolePolicyCreateV2
	case rolepolicies.ActionApply:
		return jobs.KindPostgresRolePolicyApplyV2
	case rolepolicies.ActionAdopt:
		return jobs.KindPostgresRolePolicyAdoptV2
	case rolepolicies.ActionRepair:
		return jobs.KindPostgresRolePolicyRepairV2
	default:
		return ""
	}
}

func (s *Server) applyRolePolicy(w http.ResponseWriter, r *http.Request) {
	s.mutateRolePolicy(w, r, rolepolicies.ActionApply)
}

func (s *Server) createRolePolicy(w http.ResponseWriter, r *http.Request) {
	s.mutateRolePolicy(w, r, rolepolicies.ActionCreate)
}

func (s *Server) adoptRolePolicy(w http.ResponseWriter, r *http.Request) {
	s.mutateRolePolicy(w, r, rolepolicies.ActionAdopt)
}

func (s *Server) repairRolePolicy(w http.ResponseWriter, r *http.Request) {
	s.mutateRolePolicy(w, r, rolepolicies.ActionRepair)
}

func (s *Server) mutateRolePolicy(w http.ResponseWriter, r *http.Request, action rolepolicies.Action) {
	ctx := r.Context()
	connectionID, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}
	key := r.PathValue("key")
	if err := validateRolePolicyKey(key); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req rolePolicyMutationRequest
	if !decodeStrictJSON(w, r, &req) {
		return
	}
	if err := req.validate(action); err != nil {
		respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		return
	}
	conn, err := s.connections.Get(ctx, s.pool, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.checkConnectionScope(ctx, sess, conn.Environment); err != nil {
		s.respondScopeError(ctx, w, err)
		return
	}
	if conn.Status != connections.StatusActive {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"connection status %q does not allow role policy mutations", conn.Status))
		return
	}
	capability := adapter.CapRolePolicyApply
	if action == rolepolicies.ActionCreate {
		capability = adapter.CapRolePolicyCreate
	}
	if conn.Engine == "postgres" {
		if _, err := requirePostgresProvisioningAuthority(conn, capability); err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}
	if !engineSupports(conn.Engine, capability) ||
		!slices.Contains(conn.Capabilities, string(capability)) {
		respondError(w, http.StatusConflict, fmt.Sprintf(
			"%s is unsupported for connection %s", capability, conn.ID))
		return
	}

	kind := rolePolicyOperationKind(action)
	idempotencyKey := fmt.Sprintf("role-policy:%s:%s:%s:%s", connectionID, key, action, req.RequestID)
	if action != rolepolicies.ActionCreate {
		if existing, err := s.operations.GetByIdempotencyKey(ctx, s.pool, idempotencyKey); err == nil {
			respondJSON(w, http.StatusAccepted, map[string]any{"operation_id": existing.ID})
			return
		} else if !errors.Is(err, operations.ErrNotFound) {
			respondStoreError(ctx, w, err)
			return
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: begin role policy %s: %w", action, err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := locks.AcquireTx(ctx, tx, connectionID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	// Reload under the same advisory lock as worker mutations and connection
	// reconfiguration. A failed operation may still be in an uncommitted retry;
	// without the lock a new request could steal its transition mid-target.
	conn, err = s.connections.Get(ctx, tx, connectionID)
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if conn.Status != connections.StatusActive ||
		!slices.Contains(connectionCapabilitiesForProjection(conn), string(capability)) {
		respondError(w, http.StatusConflict, "connection state changed before role policy reservation")
		return
	}
	var postgresPins postgresProvisioningPins
	if conn.Engine == "postgres" {
		postgresPins, err = requirePostgresProvisioningAuthority(conn, capability)
		if err != nil {
			respondError(w, http.StatusConflict, err.Error())
			return
		}
	}
	targetIdentity := connections.TargetIdentity(conn)
	if targetIdentity == "" {
		respondError(w, http.StatusConflict,
			"target identity is unavailable; run discovery before managing role policies")
		return
	}
	if action == rolepolicies.ActionCreate {
		// Discovery may prove a different cluster after a connection is
		// reconfigured. Never silently replace the target reviewed by the
		// caller, including on deduplicated retries of an accepted request.
		if targetIdentity != req.ExpectedTargetIdentity.Value {
			respondError(w, http.StatusConflict, "target identity changed since the role creation preview")
			return
		}
		targetIdentity = req.ExpectedTargetIdentity.Value
	}
	store := rolepolicies.NewStore()
	policy, err := store.GetByKey(ctx, tx, connectionID, key)
	if err != nil {
		s.respondRolePolicyError(ctx, w, err)
		return
	}
	var databaseOID, databaseOwnerOID uint32
	var databaseOwner string
	if conn.Engine == "postgres" {
		resources, listErr := s.inventory.ListResources(ctx, tx, connectionID)
		if listErr != nil {
			respondStoreError(ctx, w, listErr)
			return
		}
		for i := range resources {
			resource := resources[i]
			if resource.Kind != resourceKindDatabase || resource.Name != policy.DesiredSpec.Database ||
				resource.Status != inventory.ResourceObserved {
				continue
			}
			attrs := decodeAttributes(resource.Attributes)
			databaseOID, _ = uint32JSON(attrs["database_oid"])
			databaseOwner, _ = attrs["owner"].(string)
			databaseOwnerOID, _ = uint32JSON(attrs["owner_oid"])
			break
		}
		if databaseOID == 0 || databaseOwner == "" || databaseOwnerOID == 0 {
			respondError(w, http.StatusConflict,
				"database owner incarnation is unavailable; run discovery before managing the role policy")
			return
		}
	}
	payload := jobs.RolePolicyPayload{
		RolePolicyID: policy.ID, Action: action, ExpectedVersion: policy.Version + 1,
		ObservedFingerprint:    req.ObservedFingerprint,
		ExpectedFingerprint:    policy.ExpectedFingerprint,
		ExpectedTargetIdentity: targetIdentity,
		ExternalID:             policy.ExternalID, Spec: policy.DesiredSpec,
		ExpectedDatabaseOID: databaseOID, ExpectedDatabaseOwner: databaseOwner,
		ExpectedDatabaseOwnerOID:      databaseOwnerOID,
		ExpectedAdminIdentity:         postgresPins.AdminIdentity,
		ExpectedConfigIncarnation:     postgresPins.ConfigIncarnation,
		ExpectedCredentialIncarnation: postgresPins.CredentialIncarnation,
		ExpectedCatalogFingerprint:    postgresPins.CatalogFingerprint,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		respondStoreError(ctx, w, fmt.Errorf("api: marshal role policy payload: %w", err))
		return
	}
	if conn.Engine == "postgres" {
		kind = postgresRolePolicyOperationKind(action)
	}
	op, created, err := s.operations.Create(ctx, tx, operations.CreateParams{
		Kind: kind, IdempotencyKey: &idempotencyKey, ConnectionID: &connectionID,
		Payload: payloadJSON, ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		CorrelationID: req.RequestID.String(),
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if !created {
		if err := tx.Commit(ctx); err != nil {
			respondStoreError(ctx, w, err)
			return
		}
		respondJSON(w, http.StatusAccepted, map[string]any{"operation_id": op.ID})
		return
	}
	reserved, err := store.Reserve(ctx, tx, rolepolicies.ReserveParams{
		ConnectionID: connectionID, TemplateKey: key, Action: action,
		OperationID: op.ID, Version: req.Version,
		ObservedFingerprint: req.ObservedFingerprint,
	})
	if err != nil {
		s.respondRolePolicyError(ctx, w, err)
		return
	}
	if reserved.ExpectedVersion != payload.ExpectedVersion {
		respondStoreError(ctx, w, fmt.Errorf("api: reserved role policy version changed unexpectedly"))
		return
	}
	if err := s.dispatcher.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	metadata, err := json.Marshal(map[string]any{
		"template_key": key, "action": action, "profile": policy.DesiredSpec.Profile,
	})
	if err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := s.audit.Write(ctx, tx, audit.Event{
		ActorType: sess.ActorType(), ActorID: sess.ActorID(),
		Action:       "role_policy." + string(action) + "_requested",
		ConnectionID: &connectionID, AccountID: reserved.Policy.AccountID,
		OperationID: &op.ID, Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		respondStoreError(ctx, w, err)
		return
	}
	respondJSON(w, http.StatusAccepted, map[string]any{"operation_id": op.ID})
}

func (s *Server) respondRolePolicyError(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, rolepolicies.ErrNotFound):
		respondError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, rolepolicies.ErrConflict),
		errors.Is(err, rolepolicies.ErrStale),
		errors.Is(err, rolepolicies.ErrApplyUnsupported),
		errors.Is(err, rolepolicies.ErrUnsafeTemplateChange):
		respondError(w, http.StatusConflict, err.Error())
	default:
		respondStoreError(ctx, w, err)
	}
}
