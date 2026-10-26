//go:build integration

package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/ArtefactoO/grantor/internal/adapter"
	redisadapter "github.com/ArtefactoO/grantor/internal/adapters/redis"
	"github.com/ArtefactoO/grantor/internal/core/admincredentials"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

var redisNoAuthJobsOnce sync.Once

func TestIntegrationRedisAdminSwitchPasswordNonePasswordWithoutVaultDependency(t *testing.T) {
	addr := os.Getenv("GRANTOR_TEST_REDIS_NOAUTH_ADDR")
	if addr == "" {
		t.Skip("GRANTOR_TEST_REDIS_NOAUTH_ADDR is required")
	}
	redisNoAuthJobsOnce.Do(func() { adapter.Register("redis", func() adapter.Adapter { return redisadapter.New() }) })
	ctx := t.Context()
	pool := accessLifecycleGuardPool(t)
	store := connections.NewStore()
	a := redisadapter.New()
	admin := goredis.NewClient(&goredis.Options{Addr: addr})
	defer admin.Close()
	username := "lifecycle_" + uuid.NewString()
	const password = "redis-lifecycle-fixture"
	if err := admin.Do(ctx, "ACL", "SETUSER", username, "on", ">"+password, "~*", "&*", "+@all").Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Do(context.Background(), "ACL", "DELUSER", username).Err() })
	conn, err := store.Create(ctx, pool, connections.CreateParams{DisplayName: "redis-noauth", Engine: "redis", Endpoints: []string{addr}, Capabilities: a.Manifest().CapabilityNames()})
	if err != nil {
		t.Fatal(err)
	}
	for _, to := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive} {
		conn, err = store.Transition(ctx, pool, conn.ID, conn.Status, to)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg, _ := connections.AdapterConfig(conn)
	cfg.AdminCredential = adapter.Credential{Kind: "password", Username: username, Secret: []byte(password)}
	initial, err := a.Discover(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	topology, _ := json.Marshal(initial.Topology)
	if err = store.SetDiscoveryResult(ctx, pool, conn.ID, initial.ServerVersion, topology, a.Manifest().CapabilityNames(), time.Now()); err != nil {
		t.Fatal(err)
	}
	memVault := newLifecycleVault()
	canonical, _ := vault.ConnectionAdminPath(conn.ID.String())
	canonicalVersion, err := memVault.PutCAS(ctx, canonical, map[string]any{"username": username, "password": password}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `update connections set vault_admin_path=$2 where id=$1`, conn.ID, canonical); err != nil {
		t.Fatal(err)
	}
	conn, err = store.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	executor := NewMainExecutor(DiscoveryDeps{Pool: pool, Connections: store, Inventory: inventory.NewStore(), Audit: audit.NewWriter()}).WithMutations(MutationDeps{})
	reserve := func(mode string, epoch int64, stage string, version int) operations.Operation {
		t.Helper()
		opID := uuid.New()
		payload, _ := MarshalAdminCredentialOperationPayload(admincredentials.ModeSwitch, epoch)
		expectedVersion := canonicalVersion
		if mode == "none" {
			expectedVersion = 0
		}
		op, created, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{ID: &opID, Kind: KindConnectionAdminCredentialSwitch, ConnectionID: &conn.ID, Payload: payload, ActorType: "test", ActorID: t.Name()})
		if err != nil || !created {
			t.Fatalf("operation %v %v", created, err)
		}
		_, err = admincredentials.NewStore().Create(ctx, pool, admincredentials.CreateParams{OperationID: op.ID, ConnectionID: conn.ID, RequestID: op.ID, Mode: admincredentials.ModeSwitch, CandidateMode: mode, Epoch: epoch, StageVaultPath: stage, StagedVaultVersion: version, ExpectedCanonicalVersion: expectedVersion, PreviousStatus: conn.Status, ExpectedUpdatedAt: conn.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		if version == 0 {
			if _, err = admincredentials.NewStore().FinalizeStage(ctx, pool, op.ID, 0); err != nil {
				t.Fatal(err)
			}
		}
		return op
	}
	noneOp := reserve("none", 1, "", 0)
	// Simulate a crash after the no-secret promotion marker. Replay must remain
	// forward-only and must not require Vault even when the old credential did.
	first := true
	executor.mut.BeforeAdminCredentialMetadataCommit = func(context.Context, operations.Operation) error {
		if first {
			first = false
			return errors.New("fixture metadata failure")
		}
		return nil
	}
	if err = executor.Execute(ctx, noneOp); err == nil {
		t.Fatal("metadata failure did not interrupt switch")
	}
	if err = executor.Execute(ctx, noneOp); err != nil {
		t.Fatal(err)
	}
	conn, err = store.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.AuthMode != "none" || conn.VaultAdminPath != "" || conn.Status != connections.StatusActive || slices.Contains(conn.Capabilities, string(adapter.CapAccessGrant)) {
		t.Fatalf("unsafe no-auth result %+v", conn)
	}
	change, err := admincredentials.NewStore().Get(ctx, pool, noneOp.ID)
	if err != nil || change.StageCleanupPending || change.CanonicalVaultVersion == nil || *change.CanonicalVaultVersion != 0 {
		t.Fatalf("incomplete no-auth receipt %+v %v", change, err)
	}
	if err = executor.Execute(ctx, noneOp); err != nil {
		t.Fatalf("receipt replay %v", err)
	}
	executor.deps.Vault = memVault
	executor.mut.BeforeAdminCredentialMetadataCommit = nil
	stage := "connections/" + conn.ID.String() + "/admin-changes/" + uuid.NewString()
	version, err := memVault.PutCAS(ctx, stage, map[string]any{"username": username, "password": password}, 0)
	if err != nil {
		t.Fatal(err)
	}
	passwordOp := reserve("provided", 2, stage, version)
	if err = executor.Execute(ctx, passwordOp); err != nil {
		t.Fatal(err)
	}
	conn, err = store.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatal(err)
	}
	if conn.AuthMode != "password" || conn.VaultAdminPath != canonical || !slices.Contains(conn.Capabilities, string(adapter.CapAccessGrant)) {
		t.Fatalf("password switch did not recover management %+v", conn)
	}
}

func TestIntegrationRedisNoAuthQueuedRotationsNeverContactVault(t *testing.T) {
	redisNoAuthJobsOnce.Do(func() { adapter.Register("redis", func() adapter.Adapter { return redisadapter.New() }) })
	for _, mode := range []string{connections.ExecutionModeDirect, connections.ExecutionModeConnector} {
		for _, shared := range []bool{false, true} {
			label := mode + "-own"
			if shared {
				label = mode + "-shared"
			}
			t.Run(label, func(t *testing.T) {
				ctx := t.Context()
				pool := accessLifecycleGuardPool(t)
				store := connections.NewStore()
				conn, err := store.Create(ctx, pool, connections.CreateParams{DisplayName: label, Engine: "redis", ExecutionMode: mode, Environment: "test", Endpoints: []string{"10.42.0.1:6379"}, Capabilities: redisadapter.New().Manifest().CapabilityNames()})
				if err != nil {
					t.Fatal(err)
				}
				for _, to := range []connections.Status{connections.StatusValidating, connections.StatusDiscovering, connections.StatusActive} {
					conn, err = store.Transition(ctx, pool, conn.ID, conn.Status, to)
					if err != nil {
						t.Fatal(err)
					}
				}
				principal, err := principals.NewStore().Create(ctx, pool, principals.CreateParams{Type: principals.TypeService, DisplayName: label})
				if err != nil {
					t.Fatal(err)
				}
				credentialMode := inventory.CredentialModeGenerated
				path := "accounts/fixture/credential"
				if shared {
					credentialMode = inventory.CredentialModeExistingVaultRef
					path, _ = vault.PrincipalEnvironmentCredentialPath(principal.ID.String(), "test")
				}
				acct, err := inventory.NewStore().CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{ConnectionID: conn.ID, EngineIdentity: "existing_monitor", PrincipalID: &principal.ID, CredentialMode: credentialMode, VaultPath: path})
				if err != nil {
					t.Fatal(err)
				}
				payload := AccountPayload{AccountID: acct.ID, ExpectedStatus: acct.Status, ExpectedLifecycleVersion: acct.LifecycleVersion}
				if shared {
					payload.SharedCredentialPath = path
				}
				raw, _ := json.Marshal(payload)
				op, _, err := operations.NewStore().Create(ctx, pool, operations.CreateParams{Kind: KindCredentialRotate, ConnectionID: &conn.ID, AccountID: &acct.ID, PrincipalID: &principal.ID, Payload: raw, ActorType: "test", ActorID: t.Name()})
				if err != nil {
					t.Fatal(err)
				}
				// The operation was queued in password mode; admin switch finished before
				// this worker consumes it. Existing account ownership/secret pointers stay.
				if _, err = pool.Exec(ctx, `update connections set auth_mode='none',vault_admin_path='' where id=$1`, conn.ID); err != nil {
					t.Fatal(err)
				}
				var calls atomic.Int32
				endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(endpoint.Close)
				client, err := vault.New(vault.Config{Address: endpoint.URL, Token: "queued-noauth-fixture", Mount: "secret"})
				if err != nil {
					t.Fatal(err)
				}
				executor := NewMainExecutor(DiscoveryDeps{Connections: store, Pool: pool, Inventory: inventory.NewStore(), Audit: audit.NewWriter(), Vault: client}).WithMutations(MutationDeps{Credentials: credentials.NewService(client, nil)})
				if err = executor.Execute(ctx, op); !errors.Is(err, adapter.ErrUnsupportedChange) {
					t.Fatalf("queued no-auth rotation did not fail closed: %v", err)
				}
				if calls.Load() != 0 {
					t.Fatalf("queued no-auth rotation contacted Vault %d times", calls.Load())
				}
				after, err := inventory.NewStore().GetAccount(ctx, pool, acct.ID)
				if err != nil {
					t.Fatal(err)
				}
				if after.VaultPath != acct.VaultPath || after.LifecycleVersion != acct.LifecycleVersion {
					t.Fatal("blocked queued rotation changed account credential metadata")
				}
			})
		}
	}
}
