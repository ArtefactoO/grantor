//go:build integration

package accountcreation_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func creationStoreFixture(t *testing.T) (*pgxpool.Pool, accountcreation.Receipt) {
	t.Helper()
	pool := pgtest.Pool(t)
	conn, err := connections.NewStore().Create(t.Context(), pool, connections.CreateParams{DisplayName: "receipt-store-" + uuid.NewString(), Engine: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	acct, err := inventory.NewStore().CreateProvisioningAccount(t.Context(), pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, Kind: "login", EngineIdentity: "receipt_login", CredentialMode: "provided", VaultPath: "accounts/receipt/credential"})
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := operations.NewStore().Create(t.Context(), pool, operations.CreateParams{Kind: "postgres.account.provision.v1", ConnectionID: &conn.ID, AccountID: &acct.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	return pool, accountcreation.Receipt{OperationID: op.ID, AccountID: acct.ID, ConnectionID: conn.ID, EngineIdentity: acct.EngineIdentity,
		TargetIdentity: "postgres:system:42", AdminIdentity: "grantor", ConfigIncarnation: "config-1", AdminCredentialIncarnation: 3,
		LifecycleVersion: acct.LifecycleVersion, CredentialPath: acct.VaultPath, CredentialVersion: 7}
}

func TestAccountCreationReceiptCannotSkipOrReplayCreationPhases(t *testing.T) {
	pool, reserved := creationStoreFixture(t)
	store := accountcreation.NewStore()
	if _, err := store.Get(t.Context(), pool, reserved.OperationID); !errors.Is(err, accountcreation.ErrNotFound) {
		t.Fatalf("absent creation receipt = %v", err)
	}
	// A caller-supplied OID or phase cannot turn a reservation into evidence.
	reserved.Phase, reserved.RoleOID = "created", 123
	if err := store.Create(t.Context(), pool, reserved); err != nil {
		t.Fatal(err)
	}
	row, err := store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || row.Phase != "planned" || row.RoleOID != 0 {
		t.Fatal("reservation manufactured a creation receipt")
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, 123); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("confirmation skipped the durable creating boundary")
	}
	if err := store.Begin(t.Context(), pool, reserved.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(t.Context(), pool, reserved.OperationID); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("an unknown creating phase became eligible for another CREATE")
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, 0); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("an empty OID became a confirmed creation receipt")
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, ^uint32(0)); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, 456); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("confirmation overwrote the acknowledged role incarnation")
	}
	if err := store.Begin(t.Context(), pool, reserved.OperationID); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("confirmed creation receipt allowed CREATE to restart")
	}
	row, err = store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || row.Phase != "created" || row.RoleOID != ^uint32(0) {
		t.Fatal("phase guards changed or truncated the role OID")
	}
	verification, _, err := operations.NewStore().Create(t.Context(), pool, operations.CreateParams{Kind: "postgres.account.verify_creation.v1", ConnectionID: &reserved.ConnectionID,
		AccountID: &reserved.AccountID, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(t.Context(), pool, reserved.OperationID, uuid.Nil); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("completion accepted an absent verification operation")
	}
	if err := store.Complete(t.Context(), pool, reserved.OperationID, verification.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(t.Context(), pool, reserved.OperationID, verification.ID); !errors.Is(err, accountcreation.ErrConflict) {
		t.Fatal("completion silently re-applied a metadata transition")
	}
	final, err := store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || final.Phase != "verified" {
		t.Fatal("verification receipt did not survive a fresh store read")
	}
	row.Phase = final.Phase
	if !reflect.DeepEqual(row, final) {
		t.Fatal("receipt transitions changed immutable account, credential or authority pins")
	}
}

func TestAccountCreationReceiptReservationRejectsIncompletePinsAndOverwrite(t *testing.T) {
	pool, reserved := creationStoreFixture(t)
	store := accountcreation.NewStore()
	for _, tc := range []struct {
		name   string
		mutate func(*accountcreation.Receipt)
	}{
		{"operation", func(r *accountcreation.Receipt) { r.OperationID = uuid.Nil }},
		{"account", func(r *accountcreation.Receipt) { r.AccountID = uuid.Nil }},
		{"connection", func(r *accountcreation.Receipt) { r.ConnectionID = uuid.Nil }},
		{"identity", func(r *accountcreation.Receipt) { r.EngineIdentity = "" }},
		{"target", func(r *accountcreation.Receipt) { r.TargetIdentity = "" }},
		{"admin", func(r *accountcreation.Receipt) { r.AdminIdentity = "" }},
		{"config", func(r *accountcreation.Receipt) { r.ConfigIncarnation = "" }},
		{"admin incarnation", func(r *accountcreation.Receipt) { r.AdminCredentialIncarnation = 0 }},
		{"lifecycle", func(r *accountcreation.Receipt) { r.LifecycleVersion = -1 }},
		{"credential path", func(r *accountcreation.Receipt) { r.CredentialPath = "" }},
		{"credential version", func(r *accountcreation.Receipt) { r.CredentialVersion = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := reserved
			tc.mutate(&bad)
			if err := store.Create(t.Context(), pool, bad); !errors.Is(err, accountcreation.ErrConflict) {
				t.Fatal("incomplete creation intent was reserved")
			}
		})
	}
	if _, err := store.Get(t.Context(), pool, reserved.OperationID); !errors.Is(err, accountcreation.ErrNotFound) {
		t.Fatal("rejected intents left partial reservations")
	}
	if err := store.Create(t.Context(), pool, reserved); err != nil {
		t.Fatal(err)
	}
	bad := reserved
	bad.EngineIdentity = "foreign_login"
	if err := store.Create(t.Context(), pool, bad); err == nil {
		t.Fatal("duplicate source operation overwrote immutable creation intent")
	}
	row, err := store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || row.EngineIdentity != reserved.EngineIdentity {
		t.Fatal("duplicate reservation changed the original receipt")
	}
}

func TestAccountCreationReceiptCompletionParticipatesInMetadataTransaction(t *testing.T) {
	pool, reserved := creationStoreFixture(t)
	store := accountcreation.NewStore()
	if err := store.Create(t.Context(), pool, reserved); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(t.Context(), pool, reserved.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, 123); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := inventory.NewStore().SetAccountStatusGuarded(t.Context(), tx, reserved.AccountID, inventory.AccountProvisioning, inventory.AccountActive, reserved.LifecycleVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(t.Context(), tx, reserved.OperationID, reserved.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	row, err := store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || row.Phase != "created" || row.RoleOID != 123 {
		t.Fatal("rolled-back promotion left a verified receipt")
	}
	acct, err := inventory.NewStore().GetAccount(t.Context(), pool, reserved.AccountID)
	if err != nil || acct.Status != inventory.AccountProvisioning {
		t.Fatal("rolled-back promotion activated an unconfirmed account")
	}
}

func TestAccountCreationReceiptDoesNotBlockConnectionDeletionOrAccountRetention(t *testing.T) {
	for _, target := range []string{"connection", "deleted account"} {
		t.Run(target, func(t *testing.T) {
			pool, reserved := creationStoreFixture(t)
			store := accountcreation.NewStore()
			if err := store.Create(t.Context(), pool, reserved); err != nil {
				t.Fatal(err)
			}
			if err := store.Begin(t.Context(), pool, reserved.OperationID); err != nil {
				t.Fatal(err)
			}
			if err := store.Confirm(t.Context(), pool, reserved.OperationID, 123); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(t.Context(), `update operations set status='failed' where id=$1`, reserved.OperationID); err != nil {
				t.Fatal(err)
			}
			if err := audit.NewWriter().Write(t.Context(), pool, audit.Event{ActorType: "test", ActorID: t.Name(), Action: "account.created",
				ConnectionID: &reserved.ConnectionID, AccountID: &reserved.AccountID, OperationID: &reserved.OperationID, Result: audit.ResultSuccess}); err != nil {
				t.Fatal(err)
			}
			// These owning metadata stores have no adapter, Vault or target path.
			if target == "connection" {
				if err := connections.NewStore().Delete(t.Context(), pool, reserved.ConnectionID); err != nil {
					t.Fatal(err)
				}
			} else {
				inv := inventory.NewStore()
				if err := inv.MarkAccountDeleted(t.Context(), pool, reserved.AccountID, "test", "retention fixture"); err != nil {
					t.Fatal(err)
				}
				tx, err := pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context()) //nolint:errcheck
				if _, err := inv.PreparePurgeDeletedAccount(t.Context(), tx, reserved.AccountID); err != nil {
					t.Fatal(err)
				}
				if _, err := inv.PurgeDeletedAccount(t.Context(), tx, reserved.AccountID); err != nil {
					t.Fatal(err)
				}
				if err := tx.Commit(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := store.Get(t.Context(), pool, reserved.OperationID); !errors.Is(err, accountcreation.ErrNotFound) {
				t.Fatal("removed owning metadata retained a usable creation receipt")
			}
			op, err := operations.NewStore().Get(t.Context(), pool, reserved.OperationID)
			if err != nil || op.AccountID != nil || (target == "connection" && op.ConnectionID != nil) {
				t.Fatal("metadata cascade deleted operation history or retained a dangling account reference")
			}
			var auditCount int
			if err := pool.QueryRow(t.Context(), `select count(*) from audit_events where operation_id=$1 and account_id=$2 and action='account.created'`,
				reserved.OperationID, reserved.AccountID).Scan(&auditCount); err != nil || auditCount != 1 {
				t.Fatal("metadata cascade deleted append-only account audit history")
			}
		})
	}
}

func TestAccountCreationReceiptRetainsProofWhenVerificationOperationAgesOut(t *testing.T) {
	pool, reserved := creationStoreFixture(t)
	store := accountcreation.NewStore()
	if err := store.Create(t.Context(), pool, reserved); err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(t.Context(), pool, reserved.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := store.Confirm(t.Context(), pool, reserved.OperationID, 123); err != nil {
		t.Fatal(err)
	}
	verification, _, err := operations.NewStore().Create(t.Context(), pool, operations.CreateParams{Kind: "postgres.account.verify_creation.v1", ConnectionID: &reserved.ConnectionID,
		AccountID: &reserved.AccountID, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Complete(t.Context(), pool, reserved.OperationID, verification.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `delete from operations where id=$1`, verification.ID); err != nil {
		t.Fatal(err)
	}
	r, err := store.Get(t.Context(), pool, reserved.OperationID)
	if err != nil || r.Phase != "verified" || r.RoleOID != 123 {
		t.Fatal("verification history retention lost the original acknowledged creation proof")
	}
	var verificationID *uuid.UUID
	if err := pool.QueryRow(t.Context(), `select verified_operation_id from account_creation_receipts where operation_id=$1`, reserved.OperationID).Scan(&verificationID); err != nil || verificationID != nil {
		t.Fatal("verification history retention left a dangling operation reference")
	}
}
