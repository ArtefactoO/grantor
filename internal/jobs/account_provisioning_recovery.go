package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
)

const auditActionProvisioningRecovered = "account.provisioning_recovered"

// KindAccountRecoverProvisioning is a dedicated control-plane intent so an
// older worker rejects it before target access. Its wire job is still the
// existing read-only JobDiscover, which carries no recovery metadata.
const KindAccountRecoverProvisioning = "account.recover_provisioning"

// ErrProvisioningRecoveryAccountAbsent is not a failed discovery: the target
// was read successfully, but the failed creation reservation must be retained
// so an explicit CREATE retry can still use its original credential and fence.
var ErrProvisioningRecoveryAccountAbsent = errors.New("account not found on target; creation can be retried")

// ProvisioningRecoveryPayload pins the metadata-only recovery intent of
// account.recover_provisioning. It never crosses the connector boundary: the
// agent only executes its existing read-only discovery job.
type ProvisioningRecoveryPayload struct {
	RecoveryAccountID        uuid.UUID `json:"recovered_account_id"`
	SourceOperationID        uuid.UUID `json:"source_operation_id"`
	ExpectedLifecycleVersion int64     `json:"expected_lifecycle_version"`
}

func parseProvisioningRecoveryPayload(op operations.Operation) (*ProvisioningRecoveryPayload, error) {
	if len(op.Payload) == 0 {
		if op.Kind == KindAccountRecoverProvisioning {
			return nil, terminal(errors.New("jobs: provisioning recovery payload is required"))
		}
		return nil, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(op.Payload, &fields); err != nil {
		return nil, terminal(fmt.Errorf("jobs: decode discovery payload: %w", err))
	}
	if _, account := fields["recovered_account_id"]; !account {
		if _, source := fields["source_operation_id"]; !source {
			if _, version := fields["expected_lifecycle_version"]; !version {
				if op.Kind == KindAccountRecoverProvisioning {
					return nil, terminal(errors.New("jobs: provisioning recovery payload is required"))
				}
				return nil, nil
			}
		}
	}
	if op.Kind != KindAccountRecoverProvisioning {
		return nil, terminal(errors.New("jobs: provisioning recovery payload requires account.recover_provisioning operation"))
	}
	var payload ProvisioningRecoveryPayload
	if err := json.Unmarshal(op.Payload, &payload); err != nil {
		return nil, terminal(fmt.Errorf("jobs: decode provisioning recovery payload: %w", err))
	}
	var version *int64
	if raw, exists := fields["expected_lifecycle_version"]; exists {
		if err := json.Unmarshal(raw, &version); err != nil {
			return nil, terminal(fmt.Errorf("jobs: decode provisioning recovery lifecycle fence: %w", err))
		}
	}
	if payload.RecoveryAccountID == uuid.Nil || payload.SourceOperationID == uuid.Nil ||
		version == nil || payload.ExpectedLifecycleVersion < 0 ||
		op.AccountID == nil || *op.AccountID != payload.RecoveryAccountID || op.ConnectionID == nil {
		return nil, terminal(errors.New("jobs: invalid provisioning recovery identity or lifecycle fence"))
	}
	return &payload, nil
}

func provisioningRecoveryCompleted(ctx context.Context, q inventory.Querier, op operations.Operation,
	payload ProvisioningRecoveryPayload,
) (bool, error) {
	var completed bool
	err := q.QueryRow(ctx, `select exists (
		select 1 from audit_events where operation_id=$1 and account_id=$2 and connection_id=$3
		and action=$4 and result='success' and metadata->>'source_operation_id'=$5
		and metadata->>'previous_lifecycle_version'=$6
	)`, op.ID, payload.RecoveryAccountID, op.ConnectionID, auditActionProvisioningRecovered,
		payload.SourceOperationID.String(), strconv.FormatInt(payload.ExpectedLifecycleVersion, 10)).Scan(&completed)
	if err != nil {
		return false, fmt.Errorf("jobs: inspect provisioning recovery receipt: %w", err)
	}
	return completed, nil
}

// checkProvisioningRecovery runs before Vault/target access and again under
// the account row lock in the snapshot transaction. The outer worker holds
// the connection advisory lock; ordinary account API requests share row locks.
func (e *MainExecutor) checkProvisioningRecovery(ctx context.Context, q inventory.Querier,
	op operations.Operation, payload ProvisioningRecoveryPayload,
) (inventory.Account, error) {
	acct, err := e.deps.Inventory.GetAccount(ctx, q, payload.RecoveryAccountID)
	if err != nil {
		return inventory.Account{}, err
	}
	if op.ConnectionID == nil || acct.ConnectionID != *op.ConnectionID || acct.Ownership != inventory.OwnershipManaged {
		return inventory.Account{}, terminal(errors.New("jobs: provisioning recovery account identity or ownership changed"))
	}
	if err := inventory.CheckAccountLifecycle(acct, inventory.AccountProvisioning, payload.ExpectedLifecycleVersion); err != nil {
		return inventory.Account{}, err
	}
	source, err := operations.NewStore().Get(ctx, q, payload.SourceOperationID)
	if err != nil {
		return inventory.Account{}, err
	}
	sourceCreation := source.Kind == KindAccountCreate || source.Kind == KindRoleCreate ||
		source.Kind == KindPostgresAccountCreateV2 || source.Kind == KindPostgresAccountProvisionV1 || source.Kind == KindPostgresRoleCreateV2
	if source.Status != operations.StatusFailed || source.AccountID == nil || *source.AccountID != acct.ID ||
		source.ConnectionID == nil || *source.ConnectionID != acct.ConnectionID ||
		!sourceCreation {
		return inventory.Account{}, terminal(errors.New("jobs: provisioning recovery requires the failed account creation operation"))
	}
	if source.Kind == KindPostgresAccountProvisionV1 {
		receipt, receiptErr := accountcreation.NewStore().Get(ctx, q, source.ID)
		if receiptErr != nil && !errors.Is(receiptErr, accountcreation.ErrNotFound) {
			return inventory.Account{}, receiptErr
		}
		if receiptErr == nil && receipt.Phase != "planned" {
			return inventory.Account{}, terminal(errors.New("creation receipt cannot be abandoned by metadata-only recovery"))
		}
	}
	sourcePayload, err := decodeAccountPayload(source.Payload)
	if err != nil {
		return inventory.Account{}, err
	}
	if sourcePayload.AccountID != acct.ID || sourcePayload.ExpectedStatus != inventory.AccountProvisioning ||
		sourcePayload.ExpectedLifecycleVersion != payload.ExpectedLifecycleVersion {
		return inventory.Account{}, terminal(errors.New("jobs: provisioning recovery creation fence changed"))
	}
	var busy, bindings, policy bool
	if err := q.QueryRow(ctx, `select
		exists (select 1 from operations where account_id=$1 and id<>$2
			and status in ('pending_approval','pending','running','partial'))
		or exists (select 1 from river_job j join operations o
			on j.args->>'operation_id'=o.id::text or (j.args->'next_operation_ids') ? o.id::text
			where o.account_id=$1 and o.id<>$2
			and j.state not in ('completed','cancelled','discarded')),
		exists (select 1 from bindings where account_id=$1
			and (desired_state is not null or transition_operation_id is not null)),
		exists (select 1 from role_policies where account_id=$1)`, acct.ID, op.ID).
		Scan(&busy, &bindings, &policy); err != nil {
		return inventory.Account{}, fmt.Errorf("jobs: inspect provisioning recovery dependencies: %w", err)
	}
	if busy {
		return inventory.Account{}, inventory.ErrAccountLifecycleBusy
	}
	if bindings || policy {
		return inventory.Account{}, terminal(errors.New("jobs: provisioning recovery has managed bindings or role policy dependencies"))
	}
	return acct, nil
}

// releaseObservedProvisioning returns a post-commit outcome separately from
// an error that must roll back the snapshot. Absence is a valid observation,
// not permission to discard the only remaining way to retry CREATE.
func (e *MainExecutor) releaseObservedProvisioning(ctx context.Context, tx pgx.Tx,
	op operations.Operation, payload ProvisioningRecoveryPayload, snapshot *adapter.Snapshot,
) (recovered *inventory.Account, outcome error, err error) {
	var version int64
	if err := tx.QueryRow(ctx, `select lifecycle_version from accounts where id=$1 for update`, payload.RecoveryAccountID).
		Scan(&version); err != nil {
		return nil, nil, fmt.Errorf("jobs: lock provisioning recovery account: %w", err)
	}
	acct, err := e.checkProvisioningRecovery(ctx, tx, op, payload)
	if err != nil {
		return nil, nil, err
	}
	var observed *adapter.ObservedAccount
	for i := range snapshot.Accounts {
		if snapshot.Accounts[i].EngineIdentity == acct.EngineIdentity {
			if observed != nil {
				return nil, nil, terminal(errors.New("jobs: discovery returned duplicate provisioning recovery identities"))
			}
			observed = &snapshot.Accounts[i]
		}
	}
	if observed == nil {
		return nil, terminal(ErrProvisioningRecoveryAccountAbsent), nil
	}
	if adapter.AttrBool(observed.Attributes, adapter.AttrConnectionAdmin) {
		return nil, terminal(errors.New("jobs: provisioning recovery identity is the connection admin")), nil
	}
	if _, err := e.deps.Inventory.ReleaseFailedProvisioning(ctx, tx, acct.ID, version); err != nil {
		return nil, nil, err
	}
	return &acct, nil, nil
}

func (e *MainExecutor) recordProvisioningRecovered(ctx context.Context, tx pgx.Tx,
	op operations.Operation, payload ProvisioningRecoveryPayload, before inventory.Account,
) error {
	metadata, err := json.Marshal(map[string]any{
		"source_operation_id": payload.SourceOperationID, "engine_identity": before.EngineIdentity,
		"previous_lifecycle_version": before.LifecycleVersion, "lifecycle_version": before.LifecycleVersion + 1,
		"credential_reference_cleared": before.VaultPath != "" || before.CredentialMode != nil,
		"target_modified":              false,
	})
	if err != nil {
		return fmt.Errorf("jobs: marshal provisioning recovery audit: %w", err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID, Action: auditActionProvisioningRecovered,
		ConnectionID: op.ConnectionID, AccountID: &before.ID, OperationID: &op.ID,
		Result: audit.ResultSuccess, Metadata: metadata,
	}); err != nil {
		return fmt.Errorf("jobs: write provisioning recovery receipt: %w", err)
	}
	return nil
}
