//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/locks"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
)

type provisioningInfoBody struct {
	AccountID     uuid.UUID `json:"account_id"`
	UpdatedAt     time.Time `json:"updated_at"`
	OperationID   uuid.UUID `json:"operation_id"`
	State         string    `json:"state"`
	Recoverable   bool      `json:"recoverable"`
	Retryable     bool      `json:"retryable"`
	BlockedReason string    `json:"blocked_reason"`
}

type provisioningRecoveryAccepted struct {
	AccountID   uuid.UUID `json:"account_id"`
	OperationID uuid.UUID `json:"operation_id"`
}

func failedProvisioningFixture(t *testing.T, env *testEnv, kind string) (connections.Connection, inventory.Account, operations.Operation) {
	t.Helper()
	conn := activeFakeConnection(t, env.pool)
	identity, operationKind := "svc-a", jobs.KindAccountCreate
	if kind == "group" {
		identity, operationKind = "readers", jobs.KindRoleCreate
	}
	acct := findAccount(t, env.pool, conn.ID, identity)
	if _, err := env.pool.Exec(t.Context(), `update accounts set ownership='managed', status='provisioning',
		lifecycle_version=1, credential_mode='provided', vault_path='accounts/' || id::text || '/credential',
		credential_version=7, credential_observed_version=3, credential_checked_at=now() where id=$1`, acct.ID); err != nil {
		t.Fatal(err)
	}
	acct = accountRow(t, env.pool, acct.ID)
	payload, err := json.Marshal(jobs.AccountPayload{
		AccountID: acct.ID, ExpectedStatus: inventory.AccountProvisioning, ExpectedLifecycleVersion: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, _, err := operations.NewStore().Create(t.Context(), env.pool, operations.CreateParams{
		Kind: operationKind, ConnectionID: &conn.ID, AccountID: &acct.ID,
		Payload: payload, ActorType: "test", ActorID: t.Name(),
	})
	if err != nil {
		t.Fatal(err)
	}
	finishOperation(t, env, op.ID, operations.StatusFailed)
	if _, err := env.pool.Exec(t.Context(), `update operations set error='identity conflict' where id=$1`, op.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `insert into river_job(kind,args,state,max_attempts,attempt,finalized_at)
		values ('operation.execute',jsonb_build_object('operation_id',$1::text),'discarded',5,5,now())`, op.ID); err != nil {
		t.Fatal(err)
	}
	return conn, acct, op
}

func provisioningInfo(t *testing.T, env *testEnv, acctID uuid.UUID) provisioningInfoBody {
	t.Helper()
	viewer := session(auth.RoleViewer)
	resp := env.do(t, http.MethodGet, "/api/v1/accounts/"+acctID.String()+"/provisioning", nil, &viewer, false)
	requireStatus(t, resp, http.StatusOK)
	var info provisioningInfoBody
	if err := json.Unmarshal(readBody(t, resp), &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func provisioningRecoveryBody(acct inventory.Account, source operations.Operation) map[string]any {
	return map[string]any{"request_id": uuid.NewString(), "operation_id": source.ID, "updated_at": acct.UpdatedAt}
}

func TestIntegrationProvisioningRecoveryLoginAndGroup(t *testing.T) {
	for _, kind := range []string{"login", "group"} {
		t.Run(kind, func(t *testing.T) {
			env := newTestEnv(t, nil) // Any attempt to read/rotate a password would fail.
			conn, acct, source := failedProvisioningFixture(t, env, kind)
			info := provisioningInfo(t, env, acct.ID)
			if info.State != "failed" || !info.Recoverable || info.OperationID != source.ID {
				t.Fatalf("provisioning state = %+v", info)
			}
			admin := session(auth.RoleAdmin)
			path := "/api/v1/accounts/" + acct.ID.String() + "/recover-provisioning"
			body := provisioningRecoveryBody(acct, source)
			resp := env.do(t, http.MethodPost, path, body, &admin, true)
			requireStatus(t, resp, http.StatusAccepted)
			var accepted provisioningRecoveryAccepted
			if err := json.Unmarshal(readBody(t, resp), &accepted); err != nil {
				t.Fatal(err)
			}
			after := accountRow(t, env.pool, acct.ID)
			if after.Status != acct.Status || after.Ownership != acct.Ownership ||
				after.LifecycleVersion != acct.LifecycleVersion || after.VaultPath != acct.VaultPath {
				t.Fatalf("enqueue must not release the reservation before fresh discovery: %+v", after)
			}
			store := operations.NewStore()
			discover, err := store.Get(t.Context(), env.pool, accepted.OperationID)
			if err != nil || discover.Kind != jobs.KindAccountRecoverProvisioning || discover.Status != operations.StatusPending {
				t.Fatalf("recovery must enqueue discovery only: %+v / %v", discover, err)
			}
			executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
				Pool: env.pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Audit: audit.NewWriter(),
			})
			if err := executor.Execute(t.Context(), discover); err != nil {
				t.Fatalf("read-only discovery: %v", err)
			}
			after = accountRow(t, env.pool, acct.ID)
			if after.Status != inventory.AccountActive || after.Ownership != inventory.OwnershipUnmanaged ||
				after.Kind != kind || after.LifecycleVersion != 2 || after.VaultPath != "" || after.CredentialMode != nil {
				t.Fatalf("fresh discovery did not restore the observed identity: %+v", after)
			}
			var cleared bool
			if err := env.pool.QueryRow(t.Context(), `select credential_version=0 and credential_observed_version=0
				and credential_checked_at is null from accounts where id=$1`, acct.ID).Scan(&cleared); err != nil || !cleared {
				t.Fatalf("credential anchors not cleared: %v", err)
			}
			// The abandoned CREATE is rejected before Vault or target access.
			if err := executor.Execute(t.Context(), source); !errors.Is(err, inventory.ErrAccountLifecycleConflict) {
				t.Fatalf("stale create reached execution: %v", err)
			}
			// A lost metadata/outer-operation response is idempotent too.
			if err := executor.Execute(t.Context(), discover); err != nil {
				t.Fatalf("replayed discovery recovery: %v", err)
			}
			// Simulate the lost response: old CAS/intent still returns the same operation.
			resp = env.do(t, http.MethodPost, path, body, &admin, true)
			requireStatus(t, resp, http.StatusAccepted)
			var replay provisioningRecoveryAccepted
			if err := json.Unmarshal(readBody(t, resp), &replay); err != nil || replay.OperationID != discover.ID {
				t.Fatalf("recovery replay created new work: %+v / %v", replay, err)
			}
			var recoveryAudits int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from audit_events where account_id=$1
				and action='account.provisioning_recovered'`, acct.ID).Scan(&recoveryAudits); err != nil || recoveryAudits != 1 {
				t.Fatalf("recovery audit count=%d: %v", recoveryAudits, err)
			}
			history, err := store.Get(t.Context(), env.pool, source.ID)
			if err != nil || history.Status != operations.StatusFailed || history.Error != "identity conflict" {
				t.Fatalf("original failure history changed: %+v / %v", history, err)
			}
			if conn.ID != after.ConnectionID {
				t.Fatal("recovery moved connection")
			}
		})
	}
}

func TestIntegrationProvisioningRecoveryGuards(t *testing.T) {
	for _, scenario := range []string{"retryable_job", "queued_sequence", "desired_binding", "stale_cas", "stale_generation", "wrong_operation", "connection_lock", "credential_updating"} {
		t.Run(scenario, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, acct, source := failedProvisioningFixture(t, env, "login")
			body := provisioningRecoveryBody(acct, source)
			switch scenario {
			case "retryable_job":
				_, err := env.pool.Exec(t.Context(), `update river_job set state='retryable', finalized_at=null
					where args->>'operation_id'=$1`, source.ID.String())
				if err != nil {
					t.Fatal(err)
				}
			case "queued_sequence":
				_, err := env.pool.Exec(t.Context(), `insert into river_job(kind,args) values('operation.execute',
					jsonb_build_object('operation_id',$1::text,'next_operation_ids',jsonb_build_array($2::text)))`, uuid.New(), source.ID)
				if err != nil {
					t.Fatal(err)
				}
			case "desired_binding":
				permission := findPermission(t, env.pool, conn.ID, "role:app-readonly")
				if _, _, err := inventory.NewStore().EnsureBinding(t.Context(), env.pool, inventory.EnsureBindingParams{
					AccountID: acct.ID, PermissionID: permission.ID, DesiredState: inventory.BindingPresent,
				}); err != nil {
					t.Fatal(err)
				}
			case "stale_cas":
				body["updated_at"] = acct.UpdatedAt.Add(-time.Second)
			case "stale_generation":
				if _, err := env.pool.Exec(t.Context(), `update operations set payload=jsonb_set(payload,
					'{expected_lifecycle_version}','0'::jsonb) where id=$1`, source.ID); err != nil {
					t.Fatal(err)
				}
			case "wrong_operation":
				body["operation_id"] = uuid.NewString()
			case "connection_lock":
				tx, err := env.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(t.Context()) //nolint:errcheck
				if err := locks.AcquireTx(t.Context(), tx, conn.ID); err != nil {
					t.Fatal(err)
				}
			case "credential_updating":
				if _, err := env.pool.Exec(t.Context(), `update connections set status='credential_updating' where id=$1`, conn.ID); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					// This intentionally incomplete journal fixture must not
					// leak into unrelated connection-list integration tests.
					if _, err := env.pool.Exec(context.Background(), `update connections set status='active' where id=$1`, conn.ID); err != nil {
						t.Error(err)
					}
				})
			}
			admin := session(auth.RoleAdmin)
			resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/recover-provisioning", body, &admin, true)
			requireStatus(t, resp, http.StatusConflict)
			after := accountRow(t, env.pool, acct.ID)
			if after.LifecycleVersion != acct.LifecycleVersion || after.Status != acct.Status || after.VaultPath != acct.VaultPath {
				t.Fatalf("guard rejection changed account: %+v", after)
			}
			if scenario == "retryable_job" || scenario == "queued_sequence" {
				info := provisioningInfo(t, env, acct.ID)
				if info.State != "running" || info.Recoverable || info.BlockedReason != "busy" {
					t.Fatalf("failed op with a live job must still be running: %+v", info)
				}
			}
		})
	}
}

func TestIntegrationProvisioningRecoveryAuthAndConcurrency(t *testing.T) {
	env := newTestEnv(t, nil)
	_, acct, source := failedProvisioningFixture(t, env, "login")
	path := "/api/v1/accounts/" + acct.ID.String() + "/recover-provisioning"
	body := provisioningRecoveryBody(acct, source)
	admin := session(auth.RoleAdmin)
	for _, role := range []auth.Role{auth.RoleViewer, auth.RoleOperator} {
		sess := session(role)
		requireStatus(t, env.do(t, http.MethodPost, path, body, &sess, true), http.StatusForbidden)
	}
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, false), http.StatusForbidden)
	bad := provisioningRecoveryBody(acct, source)
	bad["force"] = true
	requireStatus(t, env.do(t, http.MethodPost, path, bad, &admin, true), http.StatusBadRequest)
	for _, action := range []string{"/rotate", "?confirm=true"} {
		method := http.MethodPost
		if action == "?confirm=true" {
			method = http.MethodDelete
		}
		requireStatus(t, env.do(t, method, "/api/v1/accounts/"+acct.ID.String()+action, nil, &admin, true), http.StatusConflict)
	}
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Go(func() {
			resp := env.do(t, http.MethodPost, path, provisioningRecoveryBody(acct, source), &admin, true)
			statuses <- resp.StatusCode
			_ = resp.Body.Close()
		})
	}
	wg.Wait()
	close(statuses)
	accepted, conflict := 0, 0
	for status := range statuses {
		if status == http.StatusAccepted {
			accepted++
		} else if status == http.StatusConflict {
			conflict++
		}
	}
	if accepted != 1 || conflict != 1 {
		t.Fatalf("concurrent recovery accepted=%d conflict=%d", accepted, conflict)
	}
}

func TestIntegrationProvisioningRecoveryAbsentRoleCanRetryCreation(t *testing.T) {
	env := newTestEnv(t, nil)
	conn, acct, source := failedProvisioningFixture(t, env, "group")
	if _, err := env.pool.Exec(t.Context(), `update accounts set engine_identity=$2,updated_at=now() where id=$1`,
		acct.ID, "absent_"+uniqueSuffix()); err != nil {
		t.Fatal(err)
	}
	acct = accountRow(t, env.pool, acct.ID)
	admin := session(auth.RoleAdmin)
	resp := env.do(t, http.MethodPost, "/api/v1/accounts/"+acct.ID.String()+"/recover-provisioning",
		provisioningRecoveryBody(acct, source), &admin, true)
	requireStatus(t, resp, http.StatusAccepted)
	var accepted provisioningRecoveryAccepted
	if err := json.Unmarshal(readBody(t, resp), &accepted); err != nil {
		t.Fatal(err)
	}
	discover, err := operations.NewStore().Get(t.Context(), env.pool, accepted.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Pool: env.pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Audit: audit.NewWriter(),
	})
	if err := executor.Execute(t.Context(), discover); err == nil {
		t.Fatal("absent role must not be reported as recovered")
	}
	after := accountRow(t, env.pool, acct.ID)
	if after.Status != inventory.AccountProvisioning || after.Ownership != inventory.OwnershipManaged ||
		after.LifecycleVersion != acct.LifecycleVersion || after.VaultPath != acct.VaultPath {
		t.Fatalf("absence destroyed the creation reservation: %+v", after)
	}
	currentConn, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil || currentConn.Status != connections.StatusActive {
		t.Fatalf("successful discovery must not degrade connection: %+v / %v", currentConn, err)
	}
	finishOperation(t, env, discover.ID, operations.StatusFailed)
	if _, err := env.pool.Exec(t.Context(), `update river_job set state='discarded',finalized_at=now()
		where args->>'operation_id'=$1`, discover.ID.String()); err != nil {
		t.Fatal(err)
	}
	info := provisioningInfo(t, env, acct.ID)
	if info.State != "failed" || !info.Retryable {
		t.Fatalf("absent role must retain explicit create retry: %+v", info)
	}
	operator := session(auth.RoleOperator)
	resp = env.do(t, http.MethodPost, "/api/v1/operations/"+source.ID.String()+"/retry", nil, &operator, true)
	requireStatus(t, resp, http.StatusAccepted)
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/operations/"+source.ID.String()+"/retry", nil, &operator, true), http.StatusConflict)
}

func TestIntegrationRoleCreationRetryPreservesEngineAdminGate(t *testing.T) {
	for _, engine := range []string{"postgres", "mongodb"} {
		t.Run(engine, func(t *testing.T) {
			env := newTestEnv(t, nil)
			conn, acct, source := failedProvisioningFixture(t, env, "group")
			if _, err := env.pool.Exec(t.Context(), `update connections set engine=$2 where id=$1`, conn.ID, engine); err != nil {
				t.Fatal(err)
			}
			operator, admin := session(auth.RoleOperator), session(auth.RoleAdmin)
			infoPath := "/api/v1/accounts/" + acct.ID.String() + "/provisioning"
			resp := env.do(t, http.MethodGet, infoPath, nil, &operator, false)
			requireStatus(t, resp, http.StatusOK)
			var info provisioningInfoBody
			if err := json.Unmarshal(readBody(t, resp), &info); err != nil || info.Retryable {
				t.Fatalf("operator UI must not offer database role creation retry: %+v / %v", info, err)
			}
			path := "/api/v1/operations/" + source.ID.String() + "/retry"
			operatorStatus := http.StatusForbidden
			if engine == "postgres" {
				operatorStatus = http.StatusConflict
			}
			requireStatus(t, env.do(t, http.MethodPost, path, nil, &operator, true), operatorStatus)
			unchanged, err := operations.NewStore().Get(t.Context(), env.pool, source.ID)
			if err != nil || unchanged.Status != operations.StatusFailed {
				t.Fatalf("denied retry changed source operation: %+v / %v", unchanged, err)
			}
			resp = env.do(t, http.MethodGet, infoPath, nil, &admin, false)
			requireStatus(t, resp, http.StatusOK)
			if err := json.Unmarshal(readBody(t, resp), &info); err != nil || info.Retryable != (engine != "postgres") {
				t.Fatalf("admin retryability for %s = %+v / %v", engine, info, err)
			}
			if engine == "postgres" {
				requireStatus(t, env.do(t, http.MethodPost, path, nil, &admin, true), http.StatusConflict)
				return
			}
			requireStatus(t, env.do(t, http.MethodPost, path, nil, &admin, true), http.StatusAccepted)
		})
	}
}

func TestIntegrationLegacyPostgresAccountCreationIsHistoryOnly(t *testing.T) {
	env := newTestEnv(t, nil)
	conn, acct, source := failedProvisioningFixture(t, env, "login")
	if _, err := env.pool.Exec(t.Context(), `update connections set engine='postgres',
		capabilities=capabilities || '["account.create"]'::jsonb where id=$1`, conn.ID); err != nil {
		t.Fatal(err)
	}
	info := provisioningInfo(t, env, acct.ID)
	if info.State != "failed" || !info.Recoverable || info.Retryable {
		t.Fatalf("legacy PostgreSQL account.create projection = %+v", info)
	}
	admin := session(auth.RoleAdmin)
	requireStatus(t, env.do(t, http.MethodPost,
		"/api/v1/operations/"+source.ID.String()+"/retry", nil, &admin, true), http.StatusConflict)
	unchanged, err := operations.NewStore().Get(t.Context(), env.pool, source.ID)
	if err != nil || unchanged.Status != operations.StatusFailed {
		t.Fatalf("history-only account operation changed: %+v / %v", unchanged, err)
	}
}
