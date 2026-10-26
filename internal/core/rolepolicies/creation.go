package rolepolicies

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// RoleMissing requires an explicit complete observation, never absent metadata.
func (p Policy) RoleMissing() bool {
	var summary map[string]any
	return json.Unmarshal(p.ObservedSummary, &summary) == nil && !observationRoleExists(summary)
}

// Creatability also allows recovery of a terminal failed reservation that never
// produced a real role. It does not turn an externally deleted managed account
// into a fresh identity: only the original unlinked provisioning placeholder is
// eligible. The create adapter independently rechecks missing-or-exact live state.
func (s *Store) Creatability(ctx context.Context, q Querier, p Policy) (bool, error) {
	if p.DesiredSpec.Engine != "postgres" || !p.RoleMissing() || !p.ApplySupported || p.BlockedReason != "" {
		return false, nil
	}
	if p.TransitionOperationID != nil {
		var status string
		var parentID *uuid.UUID
		err := q.QueryRow(ctx, `select status,parent_id from operations where id=$1`, *p.TransitionOperationID).Scan(&status, &parentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("role policies: inspect creation transition: %w", err)
		}
		// Database workflows own their inline children; recovery stays at the root.
		if parentID != nil {
			return false, nil
		}
		if status != "cancelled" && (status != "failed" || p.TransitionRetryPending) {
			return false, nil
		}
	}
	if !p.Managed {
		return p.Status == StatusMissing, nil
	}
	if p.AccountID == nil || (p.Status != StatusFailed && p.Status != StatusMissing) {
		return false, nil
	}
	var eligible bool
	err := q.QueryRow(ctx, `select exists(select 1 from accounts a
		where a.id=$1 and a.connection_id=$2 and a.engine_identity=$3
		and a.kind='group' and a.status='provisioning' and a.ownership='managed'
		and a.principal_id is null and a.vault_path=''
		and not exists(select 1 from operations o where o.account_id=a.id
		  and o.status in ('pending','pending_approval','running')))`,
		*p.AccountID, p.ConnectionID, p.DesiredSpec.RoleName).Scan(&eligible)
	if err != nil {
		return false, fmt.Errorf("role policies: inspect creation placeholder: %w", err)
	}
	return eligible, nil
}
