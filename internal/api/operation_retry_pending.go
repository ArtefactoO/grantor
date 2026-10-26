package api

import (
	"context"

	"github.com/ArtefactoO/grantor/internal/core/operations"
)

// Failed/partial is the result of an attempt, not proof that River exhausted
// its retries. Only scoped operation IDs are passed after the access checks.
func operationRetryPending(ctx context.Context, q operations.Querier, op operations.Operation, children []operations.Operation) (bool, error) {
	if op.Status != operations.StatusFailed && op.Status != operations.StatusPartial {
		return false, nil
	}
	ids := []string{op.ID.String()}
	for i := range children {
		ids = append(ids, children[i].ID.String())
	}
	var pending bool
	err := q.QueryRow(ctx, `select exists (select 1 from river_job
		where state not in ('completed','cancelled','discarded') and
		(args->>'operation_id'=any($1::text[]) or (args->'next_operation_ids') ?| $1::text[]))`, ids).Scan(&pending)
	return pending, err
}
