//go:build integration

package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ArtefactoO/grantor/internal/adapter"
	redisadapter "github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/auth"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/connectionregistration"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/policy"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

var registerRedisNoAuthAPI sync.Once

func registerRedisNoAuth(t *testing.T) {
	t.Helper()
	registerRedisNoAuthAPI.Do(func() { adapter.Register("redis", func() adapter.Adapter { return redisadapter.New() }) })
}

func TestIntegrationRedisNoAuthCreateAndSwitchDoNotRequireVault(t *testing.T) {
	registerRedisNoAuth(t)
	env := newTestEnv(t, nil)
	admin := session(auth.RoleAdmin)
	resp := env.do(t, http.MethodPost, "/api/v1/connections", map[string]any{"display_name": "no-auth", "engine": "redis", "auth_mode": "none", "environment": "test", "endpoints": []string{"10.42.0.1:6379"}}, &admin, true)
	requireStatus(t, resp, http.StatusCreated)
	var created struct {
		ID             uuid.UUID `json:"id"`
		AuthMode       string    `json:"auth_mode"`
		VaultAdminPath string    `json:"vault_admin_path"`
	}
	if err := json.Unmarshal(readBody(t, resp), &created); err != nil {
		t.Fatal(err)
	}
	if created.AuthMode != "none" || created.VaultAdminPath != "" {
		t.Fatalf("unexpected no-auth connection: %+v", created)
	}
	conn, err := connections.NewStore().Get(t.Context(), env.pool, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive} {
		conn, err = connections.NewStore().Transition(t.Context(), env.pool, conn.ID, conn.Status, to)
		if err != nil {
			t.Fatal(err)
		}
	}
	requestID := uuid.New()
	body := map[string]any{"request_id": requestID, "updated_at": conn.UpdatedAt, "auth_mode": "none"}
	path := "/api/v1/connections/" + conn.ID.String() + "/admin-credential/switch"
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusAccepted)
	requireStatus(t, env.do(t, http.MethodPost, path, body, &admin, true), http.StatusAccepted)
	change, err := admincredentials.NewStore().Get(t.Context(), env.pool, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(t.Context(), `update connection_admin_credential_changes set staged_vault_version=1 where operation_id=$1`, requestID); err == nil {
		t.Fatal("no-auth journal accepted a Vault stage version")
	}
	if _, err := env.pool.Exec(t.Context(), `update connection_admin_credential_changes set canonical_vault_version=1 where operation_id=$1`, requestID); err == nil {
		t.Fatal("no-auth journal accepted a canonical secret version")
	}
	if change.CandidateMode != "none" || change.StageVaultPath != "" || change.StagedVaultVersion != 0 || change.StageCleanupPending || change.Phase != admincredentials.PhaseStaged {
		t.Fatalf("unsafe no-auth journal: %+v", change)
	}
	updating, err := connections.NewStore().Get(t.Context(), env.pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, env.do(t, http.MethodPost, "/api/v1/connections/"+conn.ID.String()+"/admin-credential/cancel", map[string]any{"request_id": uuid.New(), "updated_at": updating.UpdatedAt}, &admin, true), http.StatusAccepted)
}

func TestIntegrationRedisNoAuthMachineRegistrationWithoutCredentialSource(t *testing.T) {
	registerRedisNoAuth(t)
	env := newScopeTestEnv(t, nil, policy.EnforcementEnforce)
	admin := session(auth.RoleAdmin)
	principalID := createPrincipal(t, env, admin, "service")
	environment := "noauth-" + uuid.NewString()
	token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
	body := map[string]any{"registration_key": "redis:" + uuid.NewString(), "request_id": uuid.NewString(), "display_name": "no-auth", "engine": "redis", "auth_mode": "none", "environment": environment, "endpoints": []string{"10.42.0.1:6379"}}
	resp := env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	receipt := readOnboardingReceipt(t, resp)
	conn, err := connections.NewStore().Get(t.Context(), env.pool, receipt.ConnectionID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.AuthMode != "none" || conn.VaultAdminPath != "" || conn.Status != connections.StatusDiscovering {
		t.Fatalf("invalid registered connection: %+v", conn)
	}
	resp = env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token)
	requireStatus(t, resp, http.StatusAccepted)
	if replay := readOnboardingReceipt(t, resp); replay.ID != receipt.ID {
		t.Fatal("no-auth registration replay duplicated connection")
	}
	body["auth_mode"] = "password"
	requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusBadRequest)
}

func TestIntegrationRedisNoAuthCancelRegistrationWithoutVaultIO(t *testing.T) {
	registerRedisNoAuth(t)
	for _, configured := range []bool{false, true} {
		name := "without_vault"
		if configured {
			name = "unavailable_vault"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			var vaultClient *vault.Client
			if configured {
				endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(endpoint.Close)
				var err error
				vaultClient, err = vault.New(vault.Config{Address: endpoint.URL, Token: "noauth-test-token", Mount: "secret"})
				if err != nil {
					t.Fatal(err)
				}
			}
			dispatcher := &countingDispatcher{err: errors.New("fixture completion failure after durable reservation")}
			env := buildTestEnv(t, testEnvOpts{vault: vaultClient, enforcement: policy.EnforcementEnforce, dispatcher: dispatcher})
			admin := session(auth.RoleAdmin)
			principalID := createPrincipal(t, env, admin, "service")
			environment := "noauth-cancel-" + uuid.NewString()
			token := issueOnboardingServiceToken(t, env, principalID, environment, true, true)
			body := map[string]any{"registration_key": "redis:" + uuid.NewString(), "request_id": uuid.NewString(), "display_name": "no-auth", "engine": "redis", "auth_mode": "none", "environment": environment, "endpoints": []string{"10.42.0.1:6379"}}
			requireStatus(t, env.doBearer(t, http.MethodPost, "/api/v1/connection-registrations", body, token), http.StatusInternalServerError)
			store := connectionregistration.NewStore()
			receipts, err := store.List(t.Context(), env.pool, connectionregistration.Owner{Type: "service", ID: uuid.MustParse(principalID)}, 10, 0)
			if err != nil || len(receipts) != 1 || receipts[0].Phase != "preparing" {
				t.Fatalf("unfinished receipt missing: %+v %v", receipts, err)
			}
			receipt := receipts[0]
			path := "/api/v1/connection-registrations/" + receipt.ID.String()
			for range 2 {
				resp := env.doBearer(t, http.MethodDelete, path, nil, token)
				requireStatus(t, resp, http.StatusOK)
				if got := readOnboardingReceipt(t, resp); got.Phase != "cancelled" || got.ID != receipt.ID {
					t.Fatalf("cancel receipt not durable: %+v", got)
				}
			}
			after, err := store.Get(t.Context(), env.pool, receipt.ID)
			if err != nil || after.Phase != "cancelled" {
				t.Fatalf("cancel did not finish: %+v %v", after, err)
			}
			if calls.Load() != 0 {
				t.Fatalf("no-auth registration/cancel contacted Vault %d times", calls.Load())
			}
			if _, err := connections.NewStore().Get(t.Context(), env.pool, receipt.ConnectionID); !errors.Is(err, connections.ErrNotFound) {
				t.Fatalf("cancel created connection: %v", err)
			}
		})
	}
}

func TestIntegrationRedisNoAuthCredentialMutationsNeverContactVault(t *testing.T) {
	registerRedisNoAuth(t)
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			t.Cleanup(endpoint.Close)
			client, err := vault.New(vault.Config{Address: endpoint.URL, Token: "noauth-rotation-test", Mount: "secret"})
			if err != nil {
				t.Fatal(err)
			}
			env := newTestEnv(t, client)
			admin := session(auth.RoleAdmin)
			store := connections.NewStore()
			conn, err := store.Create(t.Context(), env.pool, connections.CreateParams{DisplayName: "existing-password-connection", Engine: "redis", ExecutionMode: mode, Environment: "test", Endpoints: []string{"10.42.0.1:6379"}, Capabilities: redisadapter.New().Manifest().CapabilityNames()})
			if err != nil {
				t.Fatal(err)
			}
			for _, to := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive} {
				conn, err = store.Transition(t.Context(), env.pool, conn.ID, conn.Status, to)
				if err != nil {
					t.Fatal(err)
				}
			}
			principalID := uuid.MustParse(createPrincipal(t, env, admin, "service"))
			inv := inventory.NewStore()
			own, err := inv.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{ConnectionID: conn.ID, EngineIdentity: "own_monitor", PrincipalID: &principalID, CredentialMode: inventory.CredentialModeGenerated, VaultPath: "accounts/existing/credential"})
			if err != nil {
				t.Fatal(err)
			}
			sharedPath, _ := vault.PrincipalEnvironmentCredentialPath(principalID.String(), "test")
			shared, err := inv.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{ConnectionID: conn.ID, EngineIdentity: "shared_monitor", PrincipalID: &principalID, CredentialMode: inventory.CredentialModeExistingVaultRef, VaultPath: sharedPath})
			if err != nil {
				t.Fatal(err)
			}
			// A supported neighbor shares this exact principal/environment secret.
			// Skipping only the no-auth account would still publish a new
			// password for it through the common Vault path.
			neighbor, err := store.Create(t.Context(), env.pool, connections.CreateParams{DisplayName: "password-neighbor", Engine: "redis", Environment: "test", Endpoints: []string{"10.42.0.2:6379"}, Capabilities: redisadapter.New().Manifest().CapabilityNames()})
			if err != nil {
				t.Fatal(err)
			}
			for _, to := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive} {
				neighbor, err = store.Transition(t.Context(), env.pool, neighbor.ID, neighbor.Status, to)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = inv.CreateManagedAccount(t.Context(), env.pool, inventory.CreateManagedAccountParams{ConnectionID: neighbor.ID, EngineIdentity: "neighbor_monitor", PrincipalID: &principalID, CredentialMode: inventory.CredentialModeExistingVaultRef, VaultPath: sharedPath}); err != nil {
				t.Fatal(err)
			}
			// Simulate the committed connection projection after password -> none;
			// stale stored capabilities must not authorize any new credential write.
			if _, err = env.pool.Exec(t.Context(), `update connections set auth_mode='none',vault_admin_path='' where id=$1`, conn.ID); err != nil {
				t.Fatal(err)
			}
			for _, request := range []struct {
				path string
				body any
			}{
				{"/api/v1/accounts/" + own.ID.String() + "/rotate", nil},
				{"/api/v1/accounts/" + own.ID.String() + "/rotate", map[string]any{"attach": true}},
				{"/api/v1/accounts/" + shared.ID.String() + "/rotate", map[string]any{"detach": true}},
				{"/api/v1/principals/" + principalID.String() + "/rotate?environment=test", nil},
				{"/api/v1/principals/" + principalID.String() + "/offboard?confirm=true", nil},
			} {
				requireStatus(t, env.do(t, http.MethodPost, request.path, request.body, &admin, true), http.StatusConflict)
			}
			observed := &adapter.Snapshot{Accounts: []adapter.ObservedAccount{{EngineIdentity: "unmanaged_monitor", Kind: "login"}}}
			if _, err := inv.UpsertSnapshot(t.Context(), env.pool, conn.ID, observed, time.Now()); err != nil {
				t.Fatal(err)
			}
			unmanaged, err := inv.FindAccountByIdentity(t.Context(), env.pool, conn.ID, "unmanaged_monitor")
			if err != nil {
				t.Fatal(err)
			}
			for _, adoptMode := range []string{"generate", "set_password", "verify_password", "metadata"} {
				body := map[string]any{"mode": adoptMode}
				if adoptMode == "set_password" || adoptMode == "verify_password" {
					body["password"] = "synthetic-existing-password"
				}
				requireStatus(t, env.do(t, http.MethodPost, "/api/v1/accounts/"+unmanaged.ID.String()+"/adopt", body, &admin, true), http.StatusConflict)
			}
			if calls.Load() != 0 {
				t.Fatalf("no-auth API mutations contacted Vault %d times", calls.Load())
			}
			var operations int
			if err := env.pool.QueryRow(t.Context(), `select count(*) from operations where connection_id=$1`, conn.ID).Scan(&operations); err != nil || operations != 0 {
				t.Fatalf("blocked mutations queued operations: %d %v", operations, err)
			}
		})
	}
}
