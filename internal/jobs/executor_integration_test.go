//go:build integration

package jobs_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// registerPostgresOnce защищает от повторной регистрации adapter при
// нескольких тестах (и при -count > 1): registry пакета adapter живёт на
// весь процесс.
var registerPostgresOnce sync.Once

func pinPostgresV2AccountPayload(t *testing.T, q connections.Querier, connectionID uuid.UUID,
	payload jobs.AccountPayload,
) jobs.AccountPayload {
	t.Helper()
	conn, err := connections.NewStore().Get(t.Context(), q, connectionID)
	if err != nil {
		t.Fatalf("load PostgreSQL v2 connection pins: %v", err)
	}
	var topology map[string]any
	if err := json.Unmarshal(conn.Topology, &topology); err != nil {
		t.Fatalf("decode PostgreSQL v2 authority topology: %v", err)
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(
		topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	if !ok || authority.Status != adapter.ProvisioningAuthorityConfirmed ||
		authority.Reason != adapter.ProvisioningAuthoritySuperuserConfirmed {
		t.Fatalf("PostgreSQL v2 authority is not confirmed: %+v", authority)
	}
	payload.ExpectedAdminIdentity = authority.ExpectedAdminIdentity
	payload.ExpectedTargetIdentity = connections.TargetIdentity(conn)
	payload.ExpectedConfigIncarnation = connections.ConfigIncarnation(conn)
	payload.ExpectedCredentialIncarnation = authority.CredentialIncarnation
	return payload
}

// testVaultPath — фиктивный vault path admin credential тестового
// подключения; фейковый VaultReader отвечает только на него.
const testVaultPath = "test/creds"

// fakeVaultReader отдаёт admin credential целевого PostgreSQL, разобранный
// из DSN. Так интеграционный тест executor не зависит от реального Vault:
// проверяется контракт VaultReader, а не клиент Vault.
type fakeVaultReader struct {
	username string
	password string
}

func (f fakeVaultReader) Get(_ context.Context, path string) (map[string]any, int, error) {
	if path != testVaultPath {
		return nil, 0, fmt.Errorf("fake vault: unexpected path %q", path)
	}
	return map[string]any{"username": f.username, "password": f.password}, 1, nil
}

// TestMainExecutorDiscoversPostgres — сквозной сценарий discovery: создание
// подключения в metadata database, постановка операции connection.discover
// через River и проверка сведённого инвентаря реального целевого
// PostgreSQL (GRANTOR_TEST_TARGET_PG_DSN, как в интеграционных тестах
// postgres adapter).
func TestMainExecutorDiscoversPostgres(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping executor discovery test")
	}
	ctx := context.Background()
	pool := pgtest.Pool(t)

	cc, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	registerPostgresOnce.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})

	connStore := connections.NewStore()
	discoveryConfig, err := json.Marshal(map[string]string{"database": cc.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-executor-" + uuid.NewString(),
		Engine:              postgres.Engine,
		Endpoints:           []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      testVaultPath,
		DiscoveryConfig:     discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating); err != nil {
		t.Fatalf("transition to validating: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusValidating, connections.StatusDiscovering); err != nil {
		t.Fatalf("transition to discovering: %v", err)
	}

	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	auditWriter := audit.NewWriter()
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       fakeVaultReader{username: cc.User, password: cc.Password},
		Pool:        pool,
	})
	r, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &conn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create operation: %v", err)
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue operation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit tx: %v", err)
	}

	startRiver(t, r)
	waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 60*time.Second)

	got, err := connStore.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("get connection: %v", err)
	}
	if got.Status != connections.StatusActive {
		t.Errorf("connection status = %q, want active", got.Status)
	}
	if got.LastDiscoveryAt == nil {
		t.Error("last_discovery_at is not set after discovery")
	}
	if got.ServerVersion == "" {
		t.Error("server_version is empty after discovery")
	}

	resources, err := invStore.ListResources(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list resources: %v", err)
	}
	foundDB := false
	for _, res := range resources {
		if res.Kind == "database" && res.ExternalID == "db:"+cc.Database {
			foundDB = true
			break
		}
	}
	if !foundDB {
		t.Errorf("database resource %q not found among %d resources", "db:"+cc.Database, len(resources))
	}

	// Админская роль из DSN обязана попасть в аккаунты discovery.
	accounts, err := invStore.ListAccounts(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("list accounts: %v", err)
	}
	foundAdmin := false
	for _, a := range accounts {
		if a.EngineIdentity == cc.User {
			foundAdmin = true
			if a.Ownership != "unmanaged" {
				t.Errorf("admin account ownership = %q, want unmanaged", a.Ownership)
			}
			break
		}
	}
	if !foundAdmin {
		t.Errorf("admin account %q not found among %d accounts", cc.User, len(accounts))
	}

	if _, err := invStore.DriftSummary(ctx, pool, conn.ID); err != nil {
		t.Errorf("DriftSummary: %v", err)
	}

	events, err := auditWriter.List(ctx, pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:      []string{"connection.discovered"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("audit event connection.discovered not found")
	} else if events[0].Result != "success" {
		t.Errorf("audit event result = %q, want success", events[0].Result)
	}
}

// TestMainExecutorDiscoversPostgresWithInsufficientProvisioningAuthority
// crosses the complete target -> executor -> inventory/connection record
// boundary. A successful read-only discovery by a non-SUPERUSER remains a
// healthy inventory refresh; only PostgreSQL creation/policy capabilities are
// removed from the durable connection projection.
func TestMainExecutorDiscoversPostgresWithInsufficientProvisioningAuthority(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	if targetDSN == "" {
		t.Skip("GRANTOR_TEST_TARGET_PG_DSN is not set; skipping executor discovery test")
	}
	ctx := context.Background()
	pool := pgtest.Pool(t)

	adminConfig, err := pgx.ParseConfig(targetDSN)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_TARGET_PG_DSN: %v", err)
	}
	adminConn, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("connect target administrator: %v", err)
	}

	limitedUser := "grantor_itest_limited_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	limitedPassword := "limited-" + uuid.NewString()
	var quotedPassword string
	if err := adminConn.QueryRow(ctx, `select quote_literal($1)`, limitedPassword).Scan(&quotedPassword); err != nil {
		t.Fatalf("quote limited credential: %v", err)
	}
	if _, err := adminConn.Exec(ctx, "create role "+pgx.Identifier{limitedUser}.Sanitize()+
		" login nosuperuser nocreaterole nocreatedb password "+quotedPassword); err != nil {
		t.Fatalf("create limited discovery role: %v", err)
	}
	t.Cleanup(func() {
		defer adminConn.Close(context.Background()) //nolint:errcheck
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := adminConn.Exec(cleanupCtx, "drop role if exists "+pgx.Identifier{limitedUser}.Sanitize()); err != nil {
			t.Errorf("drop limited discovery role: %v", err)
		}
	})

	registerPostgresOnce.Do(func() {
		adapter.Register(postgres.Engine, func() adapter.Adapter { return postgres.New() })
	})
	discoveryConfig, err := json.Marshal(map[string]string{"database": adminConfig.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	connStore := connections.NewStore()
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-insufficient-authority-" + uuid.NewString(),
		Engine:              postgres.Engine,
		Endpoints:           []string{fmt.Sprintf("%s:%d", adminConfig.Host, adminConfig.Port)},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      testVaultPath,
		DiscoveryConfig:     discoveryConfig,
		Capabilities:        postgres.New().Manifest().CapabilityNames(),
	})
	if err != nil {
		t.Fatalf("create connection: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating); err != nil {
		t.Fatalf("transition to validating: %v", err)
	}
	if _, err := connStore.Transition(ctx, pool, conn.ID, connections.StatusValidating, connections.StatusDiscovering); err != nil {
		t.Fatalf("transition to discovering: %v", err)
	}

	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	runner, err := jobs.New(pool, opStore, jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       audit.NewWriter(),
		Vault:       fakeVaultReader{username: limitedUser, password: limitedPassword},
		Pool:        pool,
	}), jobs.Config{Queue: testQueue(), WorkerCount: 1, SnoozeOnLock: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin enqueue: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: jobs.KindConnectionDiscover, ConnectionID: &conn.ID,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create discovery operation: %v", err)
	}
	if err := runner.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue discovery: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit enqueue: %v", err)
	}
	startRiver(t, runner)
	waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 60*time.Second)

	got, err := connStore.Get(ctx, pool, conn.ID)
	if err != nil {
		t.Fatalf("get discovered connection: %v", err)
	}
	if got.Status != connections.StatusActive || got.LastDiscoveryAt == nil {
		t.Fatalf("discovered connection = status:%q observed:%v, want active with timestamp",
			got.Status, got.LastDiscoveryAt)
	}
	var topology map[string]any
	if err := json.Unmarshal(got.Topology, &topology); err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	authority, ok := adapter.ProvisioningAuthorityFromTopology(
		topology, adapter.PostgresProvisioningAuthorityTopologyKey)
	if !ok || authority.Status != adapter.ProvisioningAuthorityInsufficient ||
		authority.Reason != adapter.ProvisioningAuthoritySuperuserRequired ||
		authority.ExpectedAdminIdentity != limitedUser || authority.ObservedAdminIdentity != limitedUser {
		t.Fatalf("authority = %+v, parsed:%v; want exact insufficient SUPERUSER assessment", authority, ok)
	}
	resources, err := invStore.ListResources(ctx, pool, conn.ID)
	if err != nil || len(resources) == 0 {
		t.Fatalf("inventory resources = %d, err:%v; successful discovery must be retained", len(resources), err)
	}
	accounts, err := invStore.ListAccounts(ctx, pool, conn.ID)
	if err != nil || !slices.ContainsFunc(accounts, func(account inventory.Account) bool {
		return account.EngineIdentity == limitedUser
	}) {
		t.Fatalf("inventory accounts = %d, err:%v; limited administrator was not retained", len(accounts), err)
	}
	for _, forbidden := range []adapter.Capability{
		adapter.CapAccountCreate,
		adapter.CapAccountRestore,
		adapter.CapRoleCreate,
		adapter.ResourceCapability("create", "database"),
		adapter.CapRolePolicyApply,
		adapter.CapRolePolicyCreate,
		adapter.CapPostgresSuperuserDirectV1,
	} {
		if slices.Contains(got.Capabilities, string(forbidden)) {
			t.Errorf("insufficient authority connection retained forbidden capability %q: %v",
				forbidden, got.Capabilities)
		}
	}
	for _, retained := range []adapter.Capability{
		adapter.CapInventoryResources,
		adapter.CapInventoryAccounts,
		adapter.CapAccessGrant,
		adapter.CapAccessRevoke,
	} {
		if !slices.Contains(got.Capabilities, string(retained)) {
			t.Errorf("insufficient authority discovery lost read/access capability %q: %v",
				retained, got.Capabilities)
		}
	}
}
