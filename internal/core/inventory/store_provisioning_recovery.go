package inventory

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReleaseFailedProvisioning abandons only an unconfirmed creation intent.
// The caller holds the connection advisory/account row locks, has checked all
// operation/queue/dependency guards and found the exact identity in a fresh
// read-only snapshot. The snapshot and recovery receipt must be committed in
// this same transaction. Neither the target nor Vault is changed. Missing is
// temporary until UpsertSnapshot confirms the freshly observed kind/status.
func (s *Store) ReleaseFailedProvisioning(ctx context.Context, q Querier, id uuid.UUID, version int64) (Account, error) {
	a, err := scanAccount(q.QueryRow(ctx, `
		update accounts set ownership='unmanaged', status='missing',
			vault_path='', credential_mode=null,
			credential_version=0, credential_observed_version=0, credential_checked_at=null,
			lifecycle_version=lifecycle_version+1, updated_at=now()
		where id=$1 and lifecycle_version=$2 and status='provisioning' and ownership='managed'
		returning `+accountColumns, id, version))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, fmt.Errorf("inventory: release provisioning account %s: %w", id, ErrAccountLifecycleConflict)
	}
	if err != nil {
		return Account{}, fmt.Errorf("inventory: release provisioning account %s: %w", id, err)
	}
	return a, nil
}
