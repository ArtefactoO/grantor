//go:build integration

package inventory_test

import (
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func TestIncompleteScopePreservesInventoryUntilCompleteObservation(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	store := inventory.NewStore()
	conn := newTestConnection(ctx, t, pool)
	if _, err := pool.Exec(ctx, `update connections set capabilities='["inventory.resources","inventory.accounts","inventory.permissions","inventory.bindings"]'::jsonb where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	snap := fullSnapshot()
	snap.Permissions[0].ScopeExternalID = "schema:app.public"
	snap.Bindings[0].ScopeExternalID = "schema:app.public"
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, snap, time.Now()); err != nil {
		t.Fatal(err)
	}
	partial := &adapter.Snapshot{Resources: snap.Resources[:1], Accounts: snap.Accounts, IncompleteScopes: []string{"db:app"}}
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, partial, time.Now()); err != nil {
		t.Fatal(err)
	}
	var permissionStatus, bindingState, resourceStatus string
	read := func() {
		t.Helper()
		if err := pool.QueryRow(ctx, `select p.status,b.observed_state,r.status from permission_definitions p
		join bindings b on b.permission_definition_id=p.id join accounts a on a.id=b.account_id
		join resources r on r.id=b.scope_resource_id where a.connection_id=$1`, conn.ID).Scan(&permissionStatus, &bindingState, &resourceStatus); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if permissionStatus != "observed" || bindingState != "present" || resourceStatus != "observed" {
		t.Fatal("unavailable scope was treated as removed")
	}
	partial.IncompleteScopes = nil
	if _, err := store.UpsertSnapshot(ctx, pool, conn.ID, partial, time.Now()); err != nil {
		t.Fatal(err)
	}
	read()
	if permissionStatus != "missing" || bindingState != string(inventory.BindingAbsent) || resourceStatus != "missing" {
		t.Fatalf("complete snapshot did not detect genuine disappearance: permission=%s binding=%s resource=%s", permissionStatus, bindingState, resourceStatus)
	}
}
