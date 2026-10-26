package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

// This projection reports creation facts, never mutation eligibility. The
// detail endpoint still checks current authority before offering recovery.
type accountProvisioningSummaryJSON struct {
	State           string     `json:"state"`
	OperationID     *uuid.UUID `json:"operation_id,omitempty"`
	OperationStatus string     `json:"operation_status,omitempty"`
}

func provisioningSummary(acct inventory.Account, operationID *uuid.UUID, kind, status string,
	payload []byte, receipt accountcreation.Receipt, busy bool,
) accountProvisioningSummaryJSON {
	out := accountProvisioningSummaryJSON{State: "unknown"}
	var source jobs.AccountPayload
	current := operationID != nil && json.Unmarshal(payload, &source) == nil &&
		source.AccountID == acct.ID && source.ExpectedStatus == inventory.AccountProvisioning &&
		source.ExpectedLifecycleVersion == acct.LifecycleVersion
	if current {
		out.OperationID, out.OperationStatus = operationID, status
	}
	if busy {
		out.State = "running"
		return out
	}
	if !current || status != string(operations.StatusFailed) {
		return out
	}
	if kind == jobs.KindPostgresAccountProvisionV1 {
		switch receipt.Phase {
		case "creating", "verified":
			return out
		case "created":
			if receipt.RoleOID > 0 && jobs.AccountCreationReceiptMatches(receipt, acct, source) {
				out.State = "verification_required"
			}
			return out
		}
	}
	out.State = "failed"
	return out
}

// One connection-scoped query serves every provisioning row. Active queued
// sequence predecessors count as work even when the CREATE itself is failed.
// Neither payloads nor receipt paths are copied into the response.
func listAccountProvisioningSummaries(ctx context.Context, q inventory.Querier,
	connectionID uuid.UUID, accounts []inventory.Account,
) (map[uuid.UUID]accountProvisioningSummaryJSON, error) {
	byID := make(map[uuid.UUID]inventory.Account)
	out := make(map[uuid.UUID]accountProvisioningSummaryJSON)
	for _, acct := range accounts {
		if acct.Status == inventory.AccountProvisioning && acct.Ownership == inventory.OwnershipManaged {
			byID[acct.ID] = acct
			out[acct.ID] = accountProvisioningSummaryJSON{State: "unknown"}
		}
	}
	if len(byID) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		with queued_operations as (
			select j.args->>'operation_id' as operation_id
			from river_job j where j.state not in ('completed','cancelled','discarded')
			union
			select refs.operation_id
			from river_job j cross join lateral jsonb_array_elements_text(
				case when jsonb_typeof(j.args->'next_operation_ids')='array'
				then j.args->'next_operation_ids' else '[]'::jsonb end
			) refs(operation_id)
			where j.state not in ('completed','cancelled','discarded')
		), busy_accounts as (
			select distinct o.account_id from operations o
			where o.connection_id=$1 and o.account_id is not null
			and (o.status in ('pending_approval','pending','running')
				or o.id::text in (select operation_id from queued_operations))
		)
		select a.id,a.lifecycle_version,o.id,coalesce(o.kind,''),coalesce(o.status,''),
			coalesce(o.payload,'{}'::jsonb),b.account_id is not null,
			coalesce(r.engine_identity,''),coalesce(r.target_identity,''),coalesce(r.admin_identity,''),
			coalesce(r.config_incarnation,''),coalesce(r.admin_credential_incarnation,0),
			coalesce(r.lifecycle_version,0),coalesce(r.credential_path,''),
			coalesce(r.credential_version,0),coalesce(r.phase,''),coalesce(r.role_oid,0)
		from accounts a
		left join lateral (
			select id,kind,status,payload from operations
			where account_id=a.id and connection_id=a.connection_id and kind in (
				'account.create','role.create','postgres.account.create.v2',
				'postgres.account.provision.v1','postgres.role.create.v2'
			) order by created_at desc,id desc limit 1
		) o on true
		left join account_creation_receipts r on r.operation_id=o.id
			and r.account_id=a.id and r.connection_id=a.connection_id
		left join busy_accounts b on b.account_id=a.id
		where a.connection_id=$1 and a.status='provisioning' and a.ownership='managed'`, connectionID)
	if err != nil {
		return nil, fmt.Errorf("api: read account creation summaries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var version int64
		var operationID *uuid.UUID
		var kind, status string
		var payload []byte
		var busy bool
		var receipt accountcreation.Receipt
		if err := rows.Scan(&id, &version, &operationID, &kind, &status, &payload, &busy,
			&receipt.EngineIdentity, &receipt.TargetIdentity, &receipt.AdminIdentity,
			&receipt.ConfigIncarnation, &receipt.AdminCredentialIncarnation,
			&receipt.LifecycleVersion, &receipt.CredentialPath, &receipt.CredentialVersion,
			&receipt.Phase, &receipt.RoleOID); err != nil {
			return nil, fmt.Errorf("api: scan account creation summary: %w", err)
		}
		acct, ok := byID[id]
		if !ok || acct.LifecycleVersion != version {
			continue
		}
		receipt.AccountID, receipt.ConnectionID = id, connectionID
		if operationID != nil {
			receipt.OperationID = *operationID
		}
		out[id] = provisioningSummary(acct, operationID, kind, status, payload, receipt, busy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("api: iterate account creation summaries: %w", err)
	}
	return out, nil
}
