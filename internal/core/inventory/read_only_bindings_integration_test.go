//go:build integration

package inventory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestReadOnlyObservationsRemainUnmanagedDuringExistingAdopt(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	snapshot := fullSnapshot()
	snapshot.Permissions = append(snapshot.Permissions, adapter.ObservedPermission{ExternalID: "readonly-observation", Name: "column ACL", Dangerous: true})
	snapshot.Bindings = append(snapshot.Bindings, adapter.ObservedBinding{AccountEngineIdentity: "svc", PermissionExternalID: "readonly-observation", Attributes: map[string]any{"managed_binding_eligible": false}})
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snapshot, time.Now()); err != nil {
		t.Fatal(err)
	}
	accounts, err := store.ListAccounts(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range accounts {
		if account.EngineIdentity == "svc" {
			bindings, err := store.ListBindingsByAccount(ctx, pool, account.ID)
			if err != nil {
				t.Fatal(err)
			}
			var readonly inventory.Binding
			for _, b := range bindings {
				if !inventory.BindingManagementEligible(b) {
					readonly = b
				}
			}
			if _, err := store.AdoptBinding(ctx, pool, readonly.ID); !errors.Is(err, inventory.ErrBindingReadOnly) {
				t.Fatal("individual adoption took over read-only observation")
			}
			if count, err := store.CountUnmanagedDangerousBindings(ctx, pool, account.ID); err != nil || count != 0 {
				t.Fatal("read-only observation blocked existing account adoption")
			}
			if adopted, err := store.AdoptAccountBindings(ctx, pool, account.ID); err != nil || adopted != 1 {
				t.Fatal("ordinary role binding adoption changed")
			}
			bindings, err = store.ListBindingsByAccount(ctx, pool, account.ID)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range bindings {
				if b.ID == readonly.ID && b.DesiredState != nil {
					t.Fatal("bulk adoption took over read-only observation")
				}
			}
		}
	}
}
