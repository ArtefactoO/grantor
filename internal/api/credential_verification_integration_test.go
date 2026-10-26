//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/api"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/apikey"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

func credentialVerificationAPIAccount(t *testing.T, env *testEnv, client *vault.Client) inventory.Account {
	t.Helper()
	registerPostgresOnceAPI.Do(func() { adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() }) })
	conn := postgresAuthorityConnection(t, env, adapter.ProvisioningAuthorityConfirmed, adapter.ProvisioningAuthoritySuperuserConfirmed)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// A guard fixture can intentionally enter credential_updating without a
		// journal. Restore validity even if a later cleanup statement fails.
		if _, err := env.pool.Exec(cleanupCtx, `update connections set status=$2 where id=$1`, conn.ID, conn.Status); err != nil {
			t.Errorf("restore credential fixture connection: %v", err)
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from river_job j using operations o where o.connection_id=$1 and (j.args->>'operation_id'=o.id::text or (j.args->'next_operation_ids') ? o.id::text)`, conn.ID); err != nil {
			t.Errorf("clean credential fixture jobs: %v", err)
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from operations where connection_id=$1`, conn.ID); err != nil {
			t.Errorf("clean credential fixture operations: %v", err)
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from bindings where account_id in(select id from accounts where connection_id=$1)`, conn.ID); err != nil {
			t.Errorf("clean credential fixture bindings: %v", err)
		}
		if _, err := env.pool.Exec(cleanupCtx, `delete from connections where id=$1`, conn.ID); err != nil {
			t.Errorf("clean credential fixture connection: %v", err)
		}
	})
	caps, _ := json.Marshal([]string{string(adapter.CapCredentialProve)})
	if _, err := env.pool.Exec(t.Context(), `update connections set capabilities=$2,environment=$3 where id=$1`, conn.ID, caps, "verification-"+conn.ID.String()); err != nil {
		t.Fatal(err)
	}
	a := managedAccount(t, env.pool, conn.ID, "")
	path := "accounts/" + a.ID.String() + "/credential"
	if err := inventory.NewStore().SetAccountVaultPath(t.Context(), env.pool, a.ID, path); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Put(t.Context(), path, map[string]any{"username": a.EngineIdentity, "password": "fixture-canonical-password"}); err != nil {
		t.Fatal("could not stage fixture canonical credential")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := client.DeleteMetadata(ctx, path); err != nil {
			t.Error("clean credential fixture canonical secret failed")
		}
	})
	return accountRow(t, env.pool, a.ID)
}

func verificationAPIRequest(t *testing.T, env *testEnv, a inventory.Account, body map[string]any, actor *auth.Session) *http.Response {
	t.Helper()
	return env.do(t, http.MethodPost, "/api/v1/accounts/"+a.ID.String()+"/credential/verify", body, actor, true)
}

func TestIntegrationCredentialVerificationAPIStagesOnlyProofAndReplaysReceipt(t *testing.T) {
	client := newTestVault(t)
	env := newTestEnv(t, client)
	a := credentialVerificationAPIAccount(t, env, client)
	operator := session(auth.RoleOperator)
	body := map[string]any{"request_id": uuid.New(), "mode": "reconcile", "password": "fixture-supplied-password", "expected_vault_version": 1}
	response := verificationAPIRequest(t, env, a, body, &operator)
	requireStatus(t, response, http.StatusAccepted)
	var accepted struct {
		OperationID uuid.UUID `json:"operation_id"`
		Version     int       `json:"canonical_vault_version"`
	}
	if err := json.Unmarshal(readBody(t, response), &accepted); err != nil || accepted.Version != 1 {
		t.Fatal("invalid verification acceptance")
	}
	op, err := operations.NewStore().Get(t.Context(), env.pool, accepted.OperationID)
	if err != nil || op.Kind != jobs.KindCredentialVerify {
		t.Fatal("wrong verification operation")
	}
	var p jobs.CredentialVerifyPayload
	if err := json.Unmarshal(op.Payload, &p); err != nil || !p.Reconcile || p.ProofVersion != 1 || p.CanonicalVersion != 1 || p.EngineIdentity != a.EngineIdentity || p.CredentialPath != a.VaultPath {
		t.Fatal("operation lost its pinned non-secret intent")
	}
	service := credentials.NewService(client, nil)
	_, candidate, err := service.GetVerificationProof(t.Context(), a.ID, op.ID, p.ProofVersion)
	if err != nil || string(candidate) != "fixture-supplied-password" {
		t.Fatal("supplied credential was not staged in its operation")
	}
	clear(candidate)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := service.DeleteVerificationProof(ctx, a.ID, op.ID); err != nil {
			t.Error("clean credential fixture proof failed")
		}
	})
	d, version, err := client.Get(t.Context(), a.VaultPath)
	if err != nil || version != 1 || d["password"] != "fixture-canonical-password" {
		t.Fatal("enqueue replaced canonical credential before proof")
	}
	if _, err := env.pool.Exec(t.Context(), `update accounts set status='disabled',lifecycle_version=lifecycle_version+1 where id=$1`, a.ID); err != nil {
		t.Fatal(err)
	}
	response = verificationAPIRequest(t, env, a, body, &operator)
	requireStatus(t, response, http.StatusAccepted)
	var replay struct {
		OperationID uuid.UUID `json:"operation_id"`
	}
	if err := json.Unmarshal(readBody(t, response), &replay); err != nil || replay.OperationID != op.ID {
		t.Fatal("HTTP retry did not return the original operation")
	}
	var jobsCount, auditCount int
	if err := env.pool.QueryRow(t.Context(), `select (select count(*) from river_job where args->>'operation_id'=$1),
		(select count(*) from audit_events where operation_id=$1::uuid and action='credential.verify_requested')`, op.ID.String()).Scan(&jobsCount, &auditCount); err != nil || jobsCount != 1 || auditCount != 1 {
		t.Fatal("HTTP retry duplicated job or audit")
	}
	events, err := audit.NewWriter().List(t.Context(), env.pool, audit.Filter{OperationID: &op.ID}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if bytes.Contains(event.Metadata, []byte("fixture-supplied-password")) {
			t.Fatal("candidate reached audit")
		}
	}
	if bytes.Contains(op.Payload, []byte("fixture-supplied-password")) {
		t.Fatal("candidate reached operation payload")
	}
	body["mode"] = "verify"
	delete(body, "password")
	requireStatus(t, verificationAPIRequest(t, env, a, body, &operator), http.StatusConflict)
}

func verificationAPICounts(t *testing.T, env *testEnv, accountID uuid.UUID) [4]int64 {
	t.Helper()
	var out [4]int64
	err := env.pool.QueryRow(t.Context(), `select
  (select lifecycle_version from accounts where id=$1),
  (select count(*) from operations where account_id=$1),
  (select count(*) from river_job j join operations o on j.args->>'operation_id'=o.id::text where o.account_id=$1),
  (select count(*) from audit_events where account_id=$1)`, accountID).Scan(&out[0], &out[1], &out[2], &out[3])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestIntegrationCredentialVerificationAPIRejectsUnsafeIntent(t *testing.T) {
	for _, scenario := range []string{"viewer", "invalid_mode", "verify_with_password", "empty_candidate", "nul_candidate", "oversized_candidate", "negative_version", "stale_version", "unmanaged", "group", "disabled", "shared_reconcile", "unsupported_engine", "missing_target", "connection_updating"} {
		t.Run(scenario, func(t *testing.T) {
			client := newTestVault(t)
			env := newTestEnv(t, client)
			a := credentialVerificationAPIAccount(t, env, client)
			actor := session(auth.RoleOperator)
			body := map[string]any{"request_id": uuid.New(), "mode": "reconcile", "password": "fixture-supplied-password", "expected_vault_version": 1}
			want := http.StatusConflict
			var mutationErr error
			switch scenario {
			case "viewer":
				actor = session(auth.RoleViewer)
				want = http.StatusForbidden
			case "invalid_mode":
				body["mode"] = "adopt"
				want = http.StatusBadRequest
			case "verify_with_password":
				body["mode"] = "verify"
				want = http.StatusBadRequest
			case "empty_candidate":
				body["password"] = ""
				want = http.StatusBadRequest
			case "nul_candidate":
				body["password"] = "fixture\x00password"
				want = http.StatusBadRequest
			case "oversized_candidate":
				body["password"] = strings.Repeat("x", 4097)
				want = http.StatusBadRequest
			case "negative_version":
				body["expected_vault_version"] = -1
				want = http.StatusBadRequest
			case "stale_version":
				body["expected_vault_version"] = 0
			case "unmanaged":
				_, mutationErr = env.pool.Exec(t.Context(), `update accounts set ownership='unmanaged' where id=$1`, a.ID)
			case "group":
				_, mutationErr = env.pool.Exec(t.Context(), `update accounts set kind='group' where id=$1`, a.ID)
			case "disabled":
				_, mutationErr = env.pool.Exec(t.Context(), `update accounts set status='disabled' where id=$1`, a.ID)
			case "shared_reconcile":
				_, mutationErr = env.pool.Exec(t.Context(), `update accounts set vault_path='principals/fixture/environments/itest/credential' where id=$1`, a.ID)
			case "unsupported_engine":
				_, mutationErr = env.pool.Exec(t.Context(), `update connections set engine='fake',capabilities='[]' where id=$1`, a.ConnectionID)
			case "missing_target":
				_, mutationErr = env.pool.Exec(t.Context(), `update connections set topology='{}' where id=$1`, a.ConnectionID)
			case "connection_updating":
				_, mutationErr = env.pool.Exec(t.Context(), `update connections set status='credential_updating' where id=$1`, a.ConnectionID)
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			before := verificationAPICounts(t, env, a.ID)
			requireStatus(t, verificationAPIRequest(t, env, a, body, &actor), want)
			if after := verificationAPICounts(t, env, a.ID); after != before {
				t.Fatal("rejected intent queued a mutation")
			}
			_, version, err := client.Get(t.Context(), a.VaultPath)
			if err != nil || version != 1 {
				t.Fatal("rejected intent changed canonical credential")
			}
		})
	}
}

func newVerificationPersonalKeyEnv(t *testing.T, client *vault.Client) (*testEnv, string) {
	t.Helper()
	pool := pgtest.Pool(t)
	store := apikey.NewStore()
	issuer := newFakeOIDC(t).URL
	manager := api.NewAPIKeyIdentityManager(pool, store, nil, time.Minute)
	manager.SetIssuer(issuer)
	authn, err := auth.New(t.Context(), auth.Config{IssuerURL: issuer, ClientID: "grantor", RedirectURL: "http://localhost/auth/callback", SessionSecret: []byte(testSessionSecret),
		TokenAuth: api.NewPersonalKeyAuth(pool, store, issuer), SessionObserver: manager.ObserveSession})
	if err != nil {
		t.Fatal(err)
	}
	manager.SetRoleResolver(authn.RoleFor)
	codec, err := auth.NewCodec([]byte(testSessionSecret))
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := jobs.NewInsertOnly(pool)
	if err != nil {
		t.Fatal(err)
	}
	server, err := api.New(api.Config{Pool: pool, Connections: connections.NewStore(), Inventory: inventory.NewStore(), Operations: operations.NewStore(), Audit: audit.NewWriter(),
		Vault: client, Credentials: credentials.NewService(client, nil), Dispatcher: dispatcher, Auth: authn, APIKeys: store, APIKeyIdentity: manager})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.Routes(mux)
	srv := httptest.NewServer(authn.Middleware(mux))
	t.Cleanup(srv.Close)
	return &testEnv{pool: pool, srv: srv, codec: codec}, issuer
}

func TestIntegrationCredentialVerificationPersonalKeyScopeAndRole(t *testing.T) {
	client := newTestVault(t)
	env, issuer := newVerificationPersonalKeyEnv(t, client)
	a := credentialVerificationAPIAccount(t, env, client)
	conn, err := connections.NewStore().Get(t.Context(), env.pool, a.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := policy.NewStore().Create(t.Context(), env.pool, policy.CreateParams{SubjectKind: "role", Subject: "operator", Environment: conn.Environment})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := env.pool.Exec(ctx, `delete from scope_policies where id=$1`, grant.ID); err != nil {
			t.Errorf("clean credential fixture scope: %v", err)
		}
	})
	path := "/api/v1/accounts/" + a.ID.String() + "/credential/verify"
	for _, test := range []struct {
		role        auth.Role
		environment string
		want        int
	}{{auth.RoleViewer, conn.Environment, http.StatusForbidden}, {auth.RoleOperator, "foreign-environment", http.StatusForbidden}, {auth.RoleOperator, conn.Environment, http.StatusAccepted}, {auth.RoleAdmin, conn.Environment, http.StatusAccepted}} {
		token := issueProfilesPersonalKey(t, env, issuer, test.role, []string{test.environment})
		body := map[string]any{"request_id": uuid.New(), "mode": "verify"}
		response := env.doBearer(t, http.MethodPost, path, body, token)
		requireStatus(t, response, test.want)
		if test.want == http.StatusAccepted {
			var out struct {
				OperationID uuid.UUID `json:"operation_id"`
			}
			if err := json.Unmarshal(readBody(t, response), &out); err != nil {
				t.Fatal(err)
			}
			finishOperation(t, env, out.OperationID, operations.StatusSuccess)
			requireStatus(t, env.doBearer(t, http.MethodGet, "/api/v1/accounts/"+a.ID.String()+"/credential-verification", nil, token), http.StatusOK)
		}
	}
}

func TestIntegrationCredentialVerificationReservationBlocksConcurrentAccountWork(t *testing.T) {
	for _, phase := range []string{"pending", "retrying"} {
		t.Run(phase, func(t *testing.T) {
			client := newTestVault(t)
			env := newTestEnv(t, client)
			a := credentialVerificationAPIAccount(t, env, client)
			actor := session(auth.RoleOperator)
			response := verificationAPIRequest(t, env, a, map[string]any{"request_id": uuid.New(), "mode": "verify"}, &actor)
			requireStatus(t, response, http.StatusAccepted)
			var out struct {
				OperationID uuid.UUID `json:"operation_id"`
			}
			if err := json.Unmarshal(readBody(t, response), &out); err != nil {
				t.Fatal(err)
			}
			if phase == "retrying" {
				if _, err := env.pool.Exec(t.Context(), `update operations set status='failed' where id=$1`, out.OperationID); err != nil {
					t.Fatal(err)
				}
			}
			before := verificationAPICounts(t, env, a.ID)
			requireStatus(t, verificationAPIRequest(t, env, a, map[string]any{"request_id": uuid.New(), "mode": "verify"}, &actor), http.StatusConflict)
			for _, action := range []string{"rotate", "disable"} {
				requireStatus(t, env.do(t, http.MethodPost, "/api/v1/accounts/"+a.ID.String()+"/"+action, nil, &actor, true), http.StatusConflict)
			}
			if after := verificationAPICounts(t, env, a.ID); after != before {
				t.Fatal("concurrent work advanced lifecycle or queued another operation")
			}
		})
	}
}

func TestIntegrationCredentialVerificationStatusInvalidatesHistoricalProof(t *testing.T) {
	for _, scenario := range []string{"matching", "canonical_advanced", "canonical_destroyed", "lifecycle_advanced", "large_lifecycle_advanced", "identity_changed", "config_changed", "target_changed", "disabled"} {
		t.Run(scenario, func(t *testing.T) {
			client := newTestVault(t)
			env := newTestEnv(t, client)
			a := credentialVerificationAPIAccount(t, env, client)
			c, err := connections.NewStore().Get(t.Context(), env.pool, a.ConnectionID)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "large_lifecycle_advanced" {
				a.LifecycleVersion = 1 << 53
				if _, err := env.pool.Exec(t.Context(), `update accounts set lifecycle_version=$2 where id=$1`, a.ID, a.LifecycleVersion); err != nil {
					t.Fatal(err)
				}
			}
			receipt, _ := json.Marshal(map[string]any{"credential_proved": true, "vault_version": 1, "lifecycle_version": a.LifecycleVersion,
				"config_incarnation": connections.ConfigIncarnation(c), "target_identity": connections.TargetIdentity(c), "engine_identity": a.EngineIdentity,
				"authentication_scope": a.AuthenticationScope, "principal_id": uuid.Nil, "credential_path": a.VaultPath, "verified_at": time.Now().UTC(), "application_access_ready": false})
			if err := audit.NewWriter().Write(t.Context(), env.pool, audit.Event{Action: "credential.verified", ActorType: "test", ActorID: t.Name(), AccountID: &a.ID, ConnectionID: &a.ConnectionID, Result: audit.ResultSuccess, Metadata: receipt}); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "canonical_advanced":
				_, err = client.Put(t.Context(), a.VaultPath, map[string]any{"username": a.EngineIdentity, "password": "fixture-new-canonical"})
			case "canonical_destroyed":
				err = client.DestroyVersions(t.Context(), a.VaultPath, []int{1})
			case "lifecycle_advanced", "large_lifecycle_advanced":
				_, err = env.pool.Exec(t.Context(), `update accounts set lifecycle_version=lifecycle_version+1 where id=$1`, a.ID)
			case "identity_changed":
				_, err = env.pool.Exec(t.Context(), `update accounts set engine_identity='foreign_'||engine_identity where id=$1`, a.ID)
			case "config_changed":
				_, err = env.pool.Exec(t.Context(), `update connections set endpoints='["foreign:5432"]' where id=$1`, a.ConnectionID)
			case "target_changed":
				_, err = env.pool.Exec(t.Context(), `update connections set topology='{"system_identifier":"foreign"}' where id=$1`, a.ConnectionID)
			case "disabled":
				_, err = env.pool.Exec(t.Context(), `update accounts set status='disabled' where id=$1`, a.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			actor := session(auth.RoleViewer)
			response := env.do(t, http.MethodGet, "/api/v1/accounts/"+a.ID.String()+"/credential-verification", nil, &actor, false)
			requireStatus(t, response, http.StatusOK)
			var out struct {
				Matches          bool           `json:"matches_current_vault_version"`
				ApplicationReady bool           `json:"application_access_ready"`
				Last             map[string]any `json:"last_verification"`
			}
			if err := json.Unmarshal(readBody(t, response), &out); err != nil {
				t.Fatal(err)
			}
			if out.Matches != (scenario == "matching") || out.ApplicationReady || out.Last == nil {
				t.Fatal("historical login proof became application readiness or survived an incarnation change")
			}
		})
	}
}

func TestIntegrationCredentialVerificationFixtureCleansInvalidTransientConnection(t *testing.T) {
	client := newTestVault(t)
	env := newTestEnv(t, client)
	var connectionID uuid.UUID
	t.Run("transient guard fixture", func(t *testing.T) {
		a := credentialVerificationAPIAccount(t, env, client)
		connectionID = a.ConnectionID
		if _, err := env.pool.Exec(t.Context(), `update connections set status='credential_updating' where id=$1`, connectionID); err != nil {
			t.Fatal(err)
		}
	})
	var remaining int
	if err := env.pool.QueryRow(t.Context(), `select count(*) from connections where id=$1`, connectionID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatal("credential fixture leaked an invalid connection into later API tests")
	}
}
