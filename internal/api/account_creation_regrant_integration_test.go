//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

func accountCreationRegrantPermission(t *testing.T, env *testEnv, connectionID uuid.UUID) inventory.Permission {
	t.Helper()
	snapshot := &adapter.Snapshot{ObservedAt: time.Now(), Permissions: []adapter.ObservedPermission{{
		ExternalID: "role:r_regrant", Name: "r_regrant", Assignable: true,
	}}}
	if _, err := inventory.NewStore().UpsertSnapshot(t.Context(), env.pool, connectionID, snapshot, snapshot.ObservedAt); err != nil {
		t.Fatal(err)
	}
	return findPermission(t, env.pool, connectionID, "role:r_regrant")
}

func accountCreationRegrantSharedPath(t *testing.T, principal principals.Principal, conn connections.Connection) string {
	t.Helper()
	environment := conn.Environment
	if environment == "" {
		environment = "default"
	}
	path, err := vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), environment)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func accountCreationRegrantRequest(principal principals.Principal, conn connections.Connection, permission inventory.Permission, manifest bool) (string, any) {
	if manifest {
		return "/api/v1/access/apply", map[string]any{
			"version": "v1", "environment": conn.Environment, "prune": false,
			"entries": []map[string]any{{
				"principal": principal.ExternalSubject, "connection": conn.ID.String(),
				"role": permission.ExternalID, "state": "present",
			}},
		}
	}
	return "/api/v1/principals/" + principal.ID.String() + "/access", map[string]any{
		"items": []map[string]any{{"connection_id": conn.ID, "permission_id": permission.ID}},
	}
}

func TestIntegrationAccountCreationRegrantKeepsUnresolvedReceiptBeforeVault(t *testing.T) {
	for _, phase := range []string{"created", "creating"} {
		for _, route := range []string{"principal access", "manifest apply"} {
			t.Run(phase+"/"+route, func(t *testing.T) {
				// No Vault provider exists: reaching credential materialization would
				// fail with 503 rather than the intended receipt conflict.
				env := newTestEnv(t, nil)
				acct, source := confirmedAccountCreationFixture(t, env, phase == "created")
				conn, err := connections.NewStore().Get(t.Context(), env.pool, acct.ConnectionID)
				if err != nil {
					t.Fatal(err)
				}
				principal := createPrincipalWithSubject(t, env.pool, acct.EngineIdentity)
				sharedPath := accountCreationRegrantSharedPath(t, principal, conn)
				if _, err := env.pool.Exec(t.Context(), `update accounts set principal_id=$2,
					credential_mode='existing_vault_ref',vault_path=$3,updated_at=now() where id=$1`,
					acct.ID, principal.ID, sharedPath); err != nil {
					t.Fatal(err)
				}
				var payload jobs.AccountPayload
				if err := json.Unmarshal(source.Payload, &payload); err != nil {
					t.Fatal(err)
				}
				payload.SharedCredentialPath = sharedPath
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := env.pool.Exec(t.Context(), `update operations set payload=$2 where id=$1`, source.ID, raw); err != nil {
					t.Fatal(err)
				}
				if _, err := env.pool.Exec(t.Context(), `update account_creation_receipts set credential_path=$2 where operation_id=$1`, source.ID, sharedPath); err != nil {
					t.Fatal(err)
				}
				permission := accountCreationRegrantPermission(t, env, conn.ID)
				before := accountRow(t, env.pool, acct.ID)
				receiptBefore, err := accountcreation.NewStore().Get(t.Context(), env.pool, source.ID)
				if err != nil {
					t.Fatal(err)
				}
				sourceBefore, err := operations.NewStore().Get(t.Context(), env.pool, source.ID)
				if err != nil {
					t.Fatal(err)
				}
				var receiptUpdatedBefore time.Time
				if err := env.pool.QueryRow(t.Context(), `select updated_at from account_creation_receipts where operation_id=$1`, source.ID).Scan(&receiptUpdatedBefore); err != nil {
					t.Fatal(err)
				}
				var receiptsBefore, operationsBefore, bindingsBefore int
				if err := env.pool.QueryRow(t.Context(), `select
					(select count(*) from account_creation_receipts where account_id=$1),
					(select count(*) from operations where account_id=$1 or principal_id=$2 or connection_id=$3),
					(select count(*) from bindings where account_id=$1)`, acct.ID, principal.ID, conn.ID).
					Scan(&receiptsBefore, &operationsBefore, &bindingsBefore); err != nil {
					t.Fatal(err)
				}
				path, body := accountCreationRegrantRequest(principal, conn, permission, route == "manifest apply")
				operator := session(auth.RoleOperator)
				resp := env.do(t, http.MethodPost, path, body, &operator, true)
				requireStatus(t, resp, http.StatusConflict)
				var failure struct {
					Error string `json:"error"`
				}
				if err := json.Unmarshal(readBody(t, resp), &failure); err != nil || failure.Error == "" {
					t.Fatal("receipt rejection has no explanatory error")
				}
				after := accountRow(t, env.pool, acct.ID)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("regrant changed the reserved account or its credential reference")
				}
				receiptAfter, err := accountcreation.NewStore().Get(t.Context(), env.pool, source.ID)
				if err != nil || !reflect.DeepEqual(receiptBefore, receiptAfter) {
					t.Fatal("regrant replaced or modified the unresolved creation receipt")
				}
				var receiptUpdatedAfter time.Time
				if err := env.pool.QueryRow(t.Context(), `select updated_at from account_creation_receipts where operation_id=$1`, source.ID).Scan(&receiptUpdatedAfter); err != nil || !receiptUpdatedBefore.Equal(receiptUpdatedAfter) {
					t.Fatal("regrant touched the unresolved creation receipt")
				}
				sourceAfter, err := operations.NewStore().Get(t.Context(), env.pool, source.ID)
				if err != nil || !reflect.DeepEqual(sourceBefore, sourceAfter) {
					t.Fatal("regrant rewrote the original creation operation")
				}
				var receiptsAfter, operationsAfter, bindingsAfter int
				if err := env.pool.QueryRow(t.Context(), `select
					(select count(*) from account_creation_receipts where account_id=$1),
					(select count(*) from operations where account_id=$1 or principal_id=$2 or connection_id=$3),
					(select count(*) from bindings where account_id=$1)`, acct.ID, principal.ID, conn.ID).
					Scan(&receiptsAfter, &operationsAfter, &bindingsAfter); err != nil {
					t.Fatal(err)
				}
				if receiptsAfter != receiptsBefore || operationsAfter != operationsBefore || bindingsAfter != bindingsBefore {
					t.Fatal("regrant persisted a new creation, access operation, binding or receipt")
				}
				resp = env.do(t, http.MethodGet, "/api/v1/accounts/"+acct.ID.String()+"/provisioning", nil, &operator, false)
				requireStatus(t, resp, http.StatusOK)
				var info struct {
					OperationID       uuid.UUID `json:"operation_id"`
					OperationKind     string    `json:"operation_kind"`
					CreationPhase     string    `json:"creation_phase"`
					VerificationReady bool      `json:"verification_ready"`
					BlockedReason     string    `json:"blocked_reason"`
				}
				if err := json.Unmarshal(readBody(t, resp), &info); err != nil || info.OperationID != source.ID ||
					info.OperationKind != jobs.KindPostgresAccountProvisionV1 || info.CreationPhase != phase ||
					info.VerificationReady != (phase == "created") || (phase == "creating" && info.BlockedReason != "creation_outcome_unknown") {
					t.Fatalf("regrant lost the original continuation eligibility: %+v, %v", info, err)
				}
			})
		}
	}
}

func TestIntegrationAccountCreationRegrantMovesMissingToProvisioningAtomically(t *testing.T) {
	for _, manifest := range []bool{false, true} {
		t.Run(map[bool]string{false: "principal access", true: "manifest apply"}[manifest], func(t *testing.T) {
			vaultClient := newTestVault(t)
			env := newTestEnv(t, vaultClient)
			conn := postgresAuthorityConnection(t, env, adapter.ProvisioningAuthorityConfirmed, adapter.ProvisioningAuthoritySuperuserConfirmed)
			identity := "missing_" + uniqueSuffix()
			principal := createPrincipalWithSubject(t, env.pool, identity)
			sharedPath := accountCreationRegrantSharedPath(t, principal, conn)
			version, err := vaultClient.Put(t.Context(), sharedPath, map[string]any{"password": "regrant-fixture-not-a-real-secret"})
			if err != nil {
				t.Fatal(err)
			}
			inv := inventory.NewStore()
			acct, err := inv.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{
				ConnectionID: conn.ID, EngineIdentity: identity, PrincipalID: &principal.ID,
				CredentialMode: inventory.CredentialModeExistingVaultRef, VaultPath: sharedPath,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := inv.SetAccountStatus(t.Context(), env.pool, acct.ID, inventory.AccountMissing); err != nil {
				t.Fatal(err)
			}
			permission := accountCreationRegrantPermission(t, env, conn.ID)
			before := accountRow(t, env.pool, acct.ID)
			path, body := accountCreationRegrantRequest(principal, conn, permission, manifest)
			operator := session(auth.RoleOperator)
			resp := env.do(t, http.MethodPost, path, body, &operator, true)
			requireStatus(t, resp, http.StatusAccepted)
			after := accountRow(t, env.pool, acct.ID)
			if after.Status != inventory.AccountProvisioning || after.LifecycleVersion != before.LifecycleVersion+1 ||
				after.VaultPath != before.VaultPath || after.Ownership != before.Ownership ||
				!reflect.DeepEqual(after.PrincipalID, before.PrincipalID) {
				t.Fatal("missing-account regrant did not atomically reserve the existing managed identity")
			}
			var operationID uuid.UUID
			var kind string
			var raw []byte
			if err := env.pool.QueryRow(t.Context(), `select id,kind,payload from operations
				where account_id=$1 and kind=$2`, acct.ID, jobs.KindPostgresAccountProvisionV1).Scan(&operationID, &kind, &raw); err != nil {
				t.Fatal(err)
			}
			var payload jobs.AccountPayload
			if err := json.Unmarshal(raw, &payload); err != nil || kind != jobs.KindPostgresAccountProvisionV1 ||
				payload.AccountID != acct.ID || payload.ExpectedStatus != inventory.AccountProvisioning ||
				payload.ExpectedLifecycleVersion != after.LifecycleVersion || payload.SharedCredentialPath != sharedPath ||
				payload.CredentialVaultVersion != version || payload.CreationOperationID != uuid.Nil {
				t.Fatalf("missing-account regrant queued an incompatible creation intent: %v", err)
			}
			if err := inventory.CheckAccountLifecycle(after, payload.ExpectedStatus, payload.ExpectedLifecycleVersion); err != nil {
				t.Fatalf("the new worker would reject the account before reaching the target: %v", err)
			}
			var jobsQueued int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from river_job where args->>'operation_id'=$1`, operationID.String()).Scan(&jobsQueued); err != nil || jobsQueued != 1 {
				t.Fatalf("account reservation committed without its single durable creation job: %v", err)
			}
		})
	}
}
