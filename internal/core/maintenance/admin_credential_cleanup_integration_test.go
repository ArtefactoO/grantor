//go:build integration

package maintenance

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

type cleanupVault struct {
	mu       sync.Mutex
	failOnce bool
	deleted  []string
}

func (v *cleanupVault) DeleteMetadata(_ context.Context, path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failOnce {
		v.failOnce = false
		return errors.New("temporary Vault cleanup failure")
	}
	v.deleted = append(v.deleted, path)
	return nil
}

func TestRunOnceRetriesDurableAdminCredentialStageCleanup(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	connStore := connections.NewStore()
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName: "cleanup-" + uuid.NewString(), Engine: "postgres",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]connections.Status{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	} {
		conn, err = connStore.Transition(ctx, pool, conn.ID, step[0], step[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	opID := uuid.New()
	op, created, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{
		ID: &opID, Kind: "connection.admin_credential.switch", ConnectionID: &conn.ID,
	})
	if err != nil || !created {
		t.Fatalf("create operation: created=%v err=%v", created, err)
	}
	store := admincredentials.NewStore()
	change, err := store.Create(ctx, pool, admincredentials.CreateParams{
		OperationID: op.ID, ConnectionID: conn.ID, RequestID: op.ID,
		Mode: admincredentials.ModeSwitch, CandidateMode: "provided", Epoch: 1,
		StageVaultPath: "connections/stage/" + op.ID.String(), StagedVaultVersion: 1,
		PreviousStatus: conn.Status, ExpectedUpdatedAt: conn.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operations.NewStore().Transition(ctx, pool, op.ID,
		operations.StatusPending, operations.StatusCancelled, operations.TransitionOpts{}); err != nil {
		t.Fatal(err)
	}
	change, err = store.RestoreTerminal(ctx, pool, op.ID,
		admincredentials.PhaseCancelled, "", nil)
	if err != nil || !change.StageCleanupPending {
		t.Fatalf("terminal cleanup marker=%v err=%v", change.StageCleanupPending, err)
	}

	vaultClient := &cleanupVault{failOnce: true}
	runner := New(pool, Config{}).WithAdminCredentialStageCleanup(vaultClient)
	item := admincredentials.StageCleanup{
		OperationID: change.OperationID, ConnectionID: change.ConnectionID,
		StageVaultPath: change.StageVaultPath,
	}
	if err := runner.cleanupAdminCredentialStage(ctx, item); err == nil {
		t.Fatal("first cleanup failure must remain visible")
	}
	change, err = store.Get(ctx, pool, op.ID)
	if err != nil || !change.StageCleanupPending {
		t.Fatalf("cleanup marker cleared after failure: %+v err=%v", change, err)
	}
	if err := runner.cleanupAdminCredentialStage(ctx, item); err != nil {
		t.Fatal(err)
	}
	change, err = store.Get(ctx, pool, op.ID)
	if err != nil || change.StageCleanupPending {
		t.Fatalf("cleanup marker after retry: %+v err=%v", change, err)
	}
}
