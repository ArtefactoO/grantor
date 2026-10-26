//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// TestRestoreBindingEvidenceWritesFailureAudit фиксирует race между enqueue и
// worker: discovery может снова наблюсти binding tombstone после API eligibility
// check. Worker обязан fail-closed и записать sanitized account.restore_failed.
func TestRestoreBindingEvidenceWritesFailureAudit(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.Pool(t)
	connStore := connections.NewStore()
	invStore := inventory.NewStore()
	opStore := operations.NewStore()

	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:  "restore-binding-audit-" + uuid.NewString(),
		Engine:       "fake",
		Capabilities: []string{string(adapter.CapAccountRestore)},
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	for _, transition := range [][2]connections.Status{
		{connections.StatusDraft, connections.StatusValidating},
		{connections.StatusValidating, connections.StatusDiscovering},
		{connections.StatusDiscovering, connections.StatusActive},
	} {
		if _, err := connStore.Transition(ctx, pool, conn.ID, transition[0], transition[1]); err != nil {
			t.Fatalf("transition connection %s -> %s: %v", transition[0], transition[1], err)
		}
	}
	acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "deleted_with_observed_binding",
		CredentialMode: inventory.CredentialModeGenerated, VaultPath: "accounts/test/credential",
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	if err := invStore.SetAccountStatus(ctx, pool, acct.ID, inventory.AccountDeleted); err != nil {
		t.Fatalf("mark account deleted: %v", err)
	}

	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       audit.NewWriter(),
		Pool:        pool,
	})
	r, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue: testQueue(), WorkerCount: 1, MaxAttempts: 1, SnoozeOnLock: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	// API ordering: reserve lifecycle + create operation + enqueue atomically.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin restore enqueue: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	reserved, err := invStore.ReserveAccountLifecycle(ctx, tx, acct.ID, inventory.AccountDeleted)
	if err != nil {
		t.Fatalf("reserve restore lifecycle: %v", err)
	}
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, ExpectedStatus: inventory.AccountDeleted,
		ExpectedLifecycleVersion: reserved.LifecycleVersion,
		CredentialMode:           inventory.CredentialModeGenerated, CredentialVaultVersion: 1,
	})
	if err != nil {
		t.Fatalf("marshal restore payload: %v", err)
	}
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindAccountRestore, ConnectionID: &conn.ID, AccountID: &acct.ID,
		Payload: payload, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create restore operation: %v", err)
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue restore operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit restore enqueue: %v", err)
	}

	// Discovery path writes observed bindings directly and intentionally does
	// not use EnsureBinding, whose API guard rejects deleted accounts.
	var permissionID uuid.UUID
	if err := pool.QueryRow(ctx, `
		insert into permission_definitions (connection_id, engine, external_id, name, assignable)
		values ($1, 'fake', $2, 'Observed role', true) returning id`,
		conn.ID, "role:observed-"+uuid.NewString()).Scan(&permissionID); err != nil {
		t.Fatalf("insert observed permission: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		insert into bindings (account_id, permission_definition_id, source, observed_state, status)
		values ($1, $2, 'external', 'present', 'pending')`, acct.ID, permissionID); err != nil {
		t.Fatalf("insert observed binding between enqueue and worker: %v", err)
	}

	startRiver(t, r)
	failed := waitForStatus(t, pool, opStore, op.ID, operations.StatusFailed, 30*time.Second)
	if !strings.Contains(failed.Error, "observed binding evidence") {
		t.Errorf("restore error = %q, want observed binding evidence", failed.Error)
	}
	var count int
	var auditError string
	if err := pool.QueryRow(ctx, `
		select count(*), coalesce(max(metadata->>'error'), '')
		from audit_events where operation_id = $1 and action = 'account.restore_failed'`,
		op.ID).Scan(&count, &auditError); err != nil {
		t.Fatalf("read restore failure audit: %v", err)
	}
	if count != 1 || auditError != "account restore failed: binding_evidence" {
		t.Errorf("restore failure audit = count %d error %q", count, auditError)
	}
}
