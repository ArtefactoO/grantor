package inventory

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// DriftSummaries counts only the requested connections. Aggregate each source
// before joining so accounts, bindings and resources cannot multiply each other.
func (s *Store) DriftSummaries(ctx context.Context, q Querier, connectionIDs []uuid.UUID) (map[uuid.UUID]DriftCounters, error) {
	out := make(map[uuid.UUID]DriftCounters, len(connectionIDs))
	ids := make([]uuid.UUID, 0, len(connectionIDs))
	for _, id := range connectionIDs {
		if _, exists := out[id]; exists {
			continue
		}
		out[id] = DriftCounters{}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		with requested as (
			select unnest($1::uuid[]) as connection_id
		), binding_counts as (
			select a.connection_id,
				count(*) filter (where b.source='external' and b.desired_state is null) as unmanaged,
				count(*) filter (where b.status in ('drift','failed')) as drifted
			from accounts a join bindings b on b.account_id=a.id
			where a.connection_id=any($1::uuid[])
			group by a.connection_id
		), resource_counts as (
			select connection_id,count(*) as missing
			from resources
			where connection_id=any($1::uuid[]) and status='missing' and ownership='managed'
			group by connection_id
		), account_counts as (
			select connection_id,count(*) as missing
			from accounts
			where connection_id=any($1::uuid[]) and ownership='managed' and status in ('missing','provisioning')
			group by connection_id
		)
		select requested.connection_id,coalesce(b.unmanaged,0),coalesce(b.drifted,0),
			coalesce(r.missing,0),coalesce(a.missing,0)
		from requested
		left join binding_counts b using(connection_id)
		left join resource_counts r using(connection_id)
		left join account_counts a using(connection_id)`, ids)
	if err != nil {
		return nil, fmt.Errorf("inventory: drift summaries: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var counters DriftCounters
		if err := rows.Scan(&id, &counters.UnmanagedBindings, &counters.DriftBindings,
			&counters.MissingManagedResources, &counters.MissingManagedAccounts); err != nil {
			return nil, fmt.Errorf("inventory: scan drift summaries: %w", err)
		}
		out[id] = counters
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inventory: iterate drift summaries: %w", err)
	}
	return out, nil
}
