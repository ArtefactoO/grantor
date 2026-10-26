//go:build integration

package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/accountcreation"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

func confirmedAccountCreationFixture(t *testing.T, env *testEnv, confirmed bool) (inventory.Account, operations.Operation) {
	t.Helper()
	ctx := t.Context()
	conn := postgresAuthorityConnection(t, env, adapter.ProvisioningAuthorityConfirmed, adapter.ProvisioningAuthoritySuperuserConfirmed)
	inv := inventory.NewStore()
	acct, err := inv.CreateProvisioningAccount(ctx, env.pool, inventory.CreateManagedAccountParams{
		ConnectionID: conn.ID, EngineIdentity: "created_" + uniqueSuffix(), CredentialMode: inventory.CredentialModeProvided})
	if err != nil {
		t.Fatal(err)
	}
	path := "accounts/" + acct.ID.String() + "/credential"
	if err := inv.SetAccountVaultPath(ctx, env.pool, acct.ID, path); err != nil {
		t.Fatal(err)
	}
	acct, err = inv.ReserveAccountLifecycle(ctx, env.pool, acct.ID, inventory.AccountProvisioning)
	if err != nil {
		t.Fatal(err)
	}
	payload := jobs.AccountPayload{AccountID: acct.ID, ExpectedStatus: inventory.AccountProvisioning,
		ExpectedLifecycleVersion: acct.LifecycleVersion, ExpectedAdminIdentity: "grantor",
		ExpectedTargetIdentity: "postgres:system:123456789", ExpectedConfigIncarnation: connections.ConfigIncarnation(conn),
		ExpectedCredentialIncarnation: 9, CredentialVaultVersion: 7}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := operations.NewStore().Create(ctx, env.pool, operations.CreateParams{
		Kind: jobs.KindPostgresAccountProvisionV1, ConnectionID: &conn.ID, AccountID: &acct.ID,
		Payload: raw, ActorType: "test", ActorID: t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	finishOperation(t, env, op.ID, operations.StatusFailed)
	store := accountcreation.NewStore()
	err = store.Create(ctx, env.pool, accountcreation.Receipt{OperationID: op.ID, AccountID: acct.ID,
		ConnectionID: conn.ID, EngineIdentity: acct.EngineIdentity, TargetIdentity: payload.ExpectedTargetIdentity,
		AdminIdentity: payload.ExpectedAdminIdentity, ConfigIncarnation: payload.ExpectedConfigIncarnation,
		AdminCredentialIncarnation: 9, LifecycleVersion: acct.LifecycleVersion, CredentialPath: path, CredentialVersion: 7})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Begin(ctx, env.pool, op.ID); err != nil {
		t.Fatal(err)
	}
	if confirmed {
		if err := store.Confirm(ctx, env.pool, op.ID, 4321); err != nil {
			t.Fatal(err)
		}
	}
	return accountRow(t, env.pool, acct.ID), op
}

func TestIntegrationAccountCreationVerificationEnqueuesOnlyProof(t *testing.T) {
	env := newTestEnv(t, nil) // No credential can be read or target contacted here.
	acct, source := confirmedAccountCreationFixture(t, env, true)
	operator := session(auth.RoleOperator)
	response := env.do(t, http.MethodGet, "/api/v1/accounts/"+acct.ID.String()+"/provisioning", nil, &operator, false)
	requireStatus(t, response, http.StatusOK)
	var info struct {
		VerificationReady bool `json:"verification_ready"`
		Recoverable       bool `json:"recoverable"`
		Retryable         bool `json:"retryable"`
	}
	if err := json.Unmarshal(readBody(t, response), &info); err != nil {
		t.Fatal(err)
	}
	if !info.VerificationReady || info.Recoverable || info.Retryable {
		t.Fatalf("unexpected verification eligibility: %+v", info)
	}
	body := provisioningRecoveryBody(acct, source)
	path := "/api/v1/accounts/" + acct.ID.String() + "/verify-creation"
	response = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var accepted provisioningRecoveryAccepted
	if err := json.Unmarshal(readBody(t, response), &accepted); err != nil {
		t.Fatal(err)
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, accepted.OperationID)
	if err != nil || op.Kind != jobs.KindPostgresAccountVerifyCreationV1 {
		t.Fatalf("queued mutation instead of verification: %+v %v", op, err)
	}
	var p jobs.AccountPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil || p.CreationOperationID != source.ID || p.ExpectedLifecycleVersion != acct.LifecycleVersion || p.CredentialVaultVersion != 7 {
		t.Fatalf("verification did not preserve the source intent: %+v %v", p, err)
	}
	after := accountRow(t, env.pool, acct.ID)
	if after.Status != acct.Status || after.Ownership != acct.Ownership || after.LifecycleVersion != acct.LifecycleVersion || after.VaultPath != acct.VaultPath {
		t.Fatal("enqueue changed the account or released its creation reservation")
	}
	// A lost HTTP acknowledgement replays the same receipt even after account
	// activation. It cannot enqueue a second proof or CREATE.
	if _, err := env.pool.Exec(t.Context(), `update accounts set status='active',updated_at=now() where id=$1`, acct.ID); err != nil {
		t.Fatal(err)
	}
	response = env.do(t, http.MethodPost, path, body, &operator, true)
	requireStatus(t, response, http.StatusAccepted)
	var replay provisioningRecoveryAccepted
	if err := json.Unmarshal(readBody(t, response), &replay); err != nil || replay.OperationID != accepted.OperationID {
		t.Fatalf("lost response duplicated verification: %+v %v", replay, err)
	}
}

func TestIntegrationAccountCreationVerificationRequiresExactKnownIntent(t *testing.T) {
	for _, scenario := range []string{"unknown_create", "stale_card", "wrong_source", "foreign_source_kind", "source_pending", "lifecycle_changed", "connection_changed", "viewer"} {
		t.Run(scenario, func(t *testing.T) {
			env := newTestEnv(t, nil)
			acct, source := confirmedAccountCreationFixture(t, env, scenario != "unknown_create")
			body := provisioningRecoveryBody(acct, source)
			actor := session(auth.RoleOperator)
			want := http.StatusConflict
			switch scenario {
			case "stale_card":
				body["updated_at"] = acct.CreatedAt
			case "wrong_source":
				body["operation_id"] = uuid.NewString()
			case "foreign_source_kind":
				_, err := env.pool.Exec(t.Context(), `update operations set kind='postgres.account.create.v2' where id=$1`, source.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "source_pending":
				_, err := env.pool.Exec(t.Context(), `update operations set status='pending' where id=$1`, source.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "lifecycle_changed":
				_, err := env.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, acct.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "connection_changed":
				_, err := env.pool.Exec(t.Context(), `update connections set endpoints='["other:5432"]' where id=$1`, acct.ConnectionID)
				if err != nil {
					t.Fatal(err)
				}
			case "viewer":
				actor = session(auth.RoleViewer)
				want = http.StatusForbidden
			}
			before := postgresMutationCounts(t, env)
			response := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/verify-creation", body, &actor, true)
			requireStatus(t, response, want)
			if after := postgresMutationCounts(t, env); after != before {
				t.Fatalf("denied verification changed metadata: %+v -> %+v", before, after)
			}
			if scenario == "unknown_create" {
				admin := session(auth.RoleAdmin)
				response = env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/recover-provisioning", body, &admin, true)
				requireStatus(t, response, http.StatusConflict)
				response = env.do(t, http.MethodPost, "/api/v1/operations/"+source.ID.String()+"/retry", nil, &actor, true)
				requireStatus(t, response, http.StatusConflict)
			}
		})
	}
}
