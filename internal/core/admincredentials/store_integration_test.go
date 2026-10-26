//go:build integration

package admincredentials_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func activeConnection(t *testing.T) connections.Connection {
	t.Helper()
	pool := pgtest.Pool(t)
	store := connections.NewStore()
	conn, err := store.Create(t.Context(), pool, connections.CreateParams{
		DisplayName: "admin-credential-" + uuid.NewString(), Engine: "postgres",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range [][2]connections.Status{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	} {
		conn, err = store.Transition(t.Context(), pool, conn.ID, step[0], step[1])
		if err != nil {
			t.Fatal(err)
		}
	}
	return conn
}

func createOperation(t *testing.T, connectionID, id uuid.UUID) operations.Operation {
	t.Helper()
	pool := pgtest.Pool(t)
	op, created, err := operations.NewStore().Create(t.Context(), pool, operations.CreateParams{
		ID: &id, Kind: "connection.admin_credential.switch", ConnectionID: &connectionID,
		ActorType: "test", ActorID: t.Name(),
	})
	if err != nil || !created {
		t.Fatalf("create operation: created=%v err=%v", created, err)
	}
	return op
}

func TestStoreFencesEpochOperationsAndRestoresSafeCancellation(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	conn := activeConnection(t)
	opID := uuid.New()
	op := createOperation(t, conn.ID, opID)
	store := admincredentials.NewStore()
	epoch, err := store.NextEpoch(ctx, pool, conn.ID)
	if err != nil || epoch != 1 {
		t.Fatalf("next epoch = %d, err=%v", epoch, err)
	}
	change, err := store.Create(ctx, pool, admincredentials.CreateParams{
		OperationID: op.ID, ConnectionID: conn.ID, RequestID: op.ID,
		Mode: admincredentials.ModeSwitch, CandidateMode: "provided", Epoch: epoch,
		StageVaultPath:     "connections/" + conn.ID.String() + "/admin-changes/" + op.ID.String(),
		StagedVaultVersion: 1, ExpectedCanonicalVersion: 2,
		PreviousStatus: conn.Status, ExpectedUpdatedAt: conn.UpdatedAt,
	})
	if err != nil {
		t.Fatalf("create change: %v", err)
	}
	if change.Phase != admincredentials.PhaseStaged || change.Epoch != 1 {
		t.Fatalf("change = %+v", change)
	}
	updating, err := connections.NewStore().Get(ctx, pool, conn.ID)
	if err != nil || updating.Status != connections.StatusCredentialUpdating {
		t.Fatalf("connection status = %q, err=%v", updating.Status, err)
	}

	otherID := uuid.New()
	_, _, err = operations.NewStore().Create(ctx, pool, operations.CreateParams{
		ID: &otherID, Kind: "access.grant", ConnectionID: &conn.ID,
	})
	if err == nil {
		t.Fatal("SQL fence allowed a new operation during credential change")
	}
	blocked, err := store.BlocksOperation(ctx, pool, conn.ID, otherID)
	if err != nil || !blocked {
		t.Fatalf("other operation blocked=%v err=%v", blocked, err)
	}
	blocked, err = store.BlocksOperation(ctx, pool, conn.ID, op.ID)
	if err != nil || blocked {
		t.Fatalf("owner operation blocked=%v err=%v", blocked, err)
	}

	cancelID := uuid.New()
	closed, err := store.RestoreTerminal(ctx, pool, op.ID,
		admincredentials.PhaseCancelled, "", &cancelID)
	if err != nil {
		t.Fatalf("cancel change: %v", err)
	}
	if closed.Phase != admincredentials.PhaseCancelled || closed.CancelRequestID == nil ||
		*closed.CancelRequestID != cancelID {
		t.Fatalf("closed = %+v", closed)
	}
	restored, err := connections.NewStore().Get(ctx, pool, conn.ID)
	if err != nil || restored.Status != connections.StatusActive {
		t.Fatalf("restored status = %q, err=%v", restored.Status, err)
	}
}

func TestStorePinsProofAndDurableCompletionReceipt(t *testing.T) {
	ctx := t.Context()
	pool := pgtest.Pool(t)
	conn := activeConnection(t)
	op := createOperation(t, conn.ID, uuid.New())
	store := admincredentials.NewStore()
	change, err := store.Create(ctx, pool, admincredentials.CreateParams{
		OperationID: op.ID, ConnectionID: conn.ID, RequestID: op.ID,
		Mode: admincredentials.ModeRotate, CandidateMode: "generated", Epoch: 1,
		StageVaultPath: "connections/stage/" + op.ID.String(), StagedVaultVersion: 3,
		ExpectedCanonicalVersion: 7, PreviousStatus: conn.Status, ExpectedUpdatedAt: conn.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetExpectedProof(ctx, pool, op.ID, "admin", "authority-v1", "target-v1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPhase(ctx, pool, op.ID, admincredentials.PhasePromoting, true, ""); !errors.Is(err, admincredentials.ErrStaleOperation) {
		t.Fatalf("phase skip error = %v", err)
	}
	change, err = store.SetPhase(ctx, pool, op.ID, admincredentials.PhaseTargetApplying, true, "")
	if err != nil || change.CancelAllowed() {
		t.Fatalf("target phase = %+v err=%v", change, err)
	}
	if _, err := store.RestoreTerminal(ctx, pool, op.ID, admincredentials.PhaseCancelled, "", nil); !errors.Is(err, admincredentials.ErrStaleOperation) {
		t.Fatalf("unsafe cancel error = %v", err)
	}
	if _, err := store.SetPhase(ctx, pool, op.ID, admincredentials.PhaseTargetApplied, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPhase(ctx, pool, op.ID, admincredentials.PhasePromoting, true, ""); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCanonicalVersion(ctx, pool, op.ID, 8); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetPhase(ctx, pool, op.ID, admincredentials.PhaseMetadataCommitting, true, ""); err != nil {
		t.Fatal(err)
	}
	result := []byte(`{"mode":"rotate","epoch":1,"canonical_vault_version":8}`)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `update connections set status = 'active', updated_at = now() where id = $1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	completed, err := store.Complete(ctx, tx, op.ID, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, completed.CompletionResult); err != nil {
		t.Fatal(err)
	}
	if completed.Phase != admincredentials.PhaseCompleted ||
		compact.String() != string(result) ||
		completed.ExpectedAuthorityFingerprint != "authority-v1" {
		t.Fatalf("completed = %+v", completed)
	}
	if _, err := store.SetPhase(ctx, pool, op.ID, admincredentials.PhaseStaged, false, ""); !errors.Is(err, admincredentials.ErrStaleOperation) {
		t.Fatalf("completed phase regression error = %v", err)
	}
}
