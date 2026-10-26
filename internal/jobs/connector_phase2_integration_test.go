//go:build integration

package jobs_test

// Интеграционный тест connector phase 2 (TEST_ID=connp2): сквозной путь
// operation engine -> gateway -> in-process connector agent -> целевой
// PostgreSQL harness.
//
// Проверяется:
//   - discovery connector-подключения выполняется РЕАЛЬНОЙ операцией
//     connection.discover через River/MainExecutor (не прямым Dispatch), а
//     инвентарь сводится тем же путём, что и при direct-режиме: fixture-БД и
//     fixture-роль целевого кластера дают одинаковые строки инвентаря в обоих
//     режимах, а инвентарь connector-подключения точно зеркалит snapshot,
//     который исполнил connector (сравнение по разобранному jsonb из durable
//     dedup-строки, не по подстрокам). Полные наборы ресурсов/ролей кластера
//     сознательно не сравниваются: параллельные integration-пакеты создают и
//     удаляют свои объекты в том же harness-кластере, полная выборка racy.
//   - durable-дедупликация: результат задания переживает «рестарт gateway»
//     (новый gateway.Server над тем же store поверх metadata DB) — повтор с
//     тем же IdempotencyKey возвращает закешированный результат и не
//     исполняет discovery второй раз (счётчик вызовов adapter).
//   - секреты не попадают в connector_job_dedup: admin password целевого
//     кластера не встречается ни в одной textish-колонке новой таблицы
//     (динамический sweep из nosecrets_integration_test покрывает её
//     автоматически — это здесь и утверждается).
//   - мутирующая операция на connector-подключении у worker БЕЗ
//     сконфигурированного gateway падает с типизированной ошибкой «gateway is
//     not configured» — молчаливого fallback к прямому исполнению нет (сами
//     мутации через connector — этап 3, см. connector_phase3_integration_test).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// phase2CountingAdapter считает вызовы Discover на стороне connector, чтобы
// доказать и маршрутизацию (direct-подключение не проходит через connector),
// и durable-дедупликацию (повтор не исполняется).
type phase2CountingAdapter struct {
	adapter.Adapter
	calls *atomic.Int64
}

func (c phase2CountingAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	c.calls.Add(1)
	return c.Adapter.Discover(ctx, cfg)
}

// phase2Runtime — gateway + in-process connector agent над общим durable
// dedup-store. Пересоздаётся в тесте для сценария «рестарт gateway».
type phase2Runtime struct {
	srv   *gateway.Server
	stop  func()
	calls *atomic.Int64
}

// startPhase2Runtime поднимает gateway на loopback mTLS и подключает к нему
// in-process agent с реальным postgres adapter. Vault agent'у не нужен
// (ADR-0014): credentials заданий резолвит worker и доставляет кадром
// TypeCredentials.
func startPhase2Runtime(t *testing.T, pair conntest.TLSPair, signer connector.Signer,
	verifier connector.Verifier, dedup gateway.DedupStore,
	calls *atomic.Int64) phase2Runtime {
	t.Helper()

	srv, err := gateway.New(gateway.Config{TLS: pair.ServerTLS, Signer: signer, Dedup: dedup})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	ag, err := agent.New(agent.Config{
		ConnectorID: "connector-connp2",
		GatewayAddr: ln.Addr().String(),
		TLS:         pair.ClientTLS,
		Verifier:    verifier,
		NewAdapter: func(string) (adapter.Adapter, error) {
			return phase2CountingAdapter{Adapter: postgres.New(), calls: calls}, nil
		},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	runCtx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(runCtx) }()
	stop := func() {
		cancel()
		_ = ln.Close()
		_ = srv.Close()
		<-runErr
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		stop()
		t.Fatalf("connector did not connect to gateway: %v", err)
	}
	return phase2Runtime{srv: srv, stop: stop, calls: calls}
}

// connp2Exec выполняет одиночный SQL на целевом кластере от имени admin.
func connp2Exec(ctx context.Context, t *testing.T, dsn, sql string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target admin: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatalf("target exec %q: %v", sql, err)
	}
}

// connp2Cleanup выполняет best-effort SQL очистки фикстур целевого кластера.
func connp2Cleanup(dsn, sql string) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	_, _ = conn.Exec(ctx, sql)
}

// createPhase2Connection создаёт подключение к целевому PG и проводит его до
// статуса discovering.
func createPhase2Connection(ctx context.Context, t *testing.T, pool *pgxpool.Pool,
	store *connections.Store, cc *pgx.ConnConfig, executionMode, vaultPath string) connections.Connection {
	t.Helper()
	discoveryConfig, err := json.Marshal(map[string]string{"database": cc.Database})
	if err != nil {
		t.Fatalf("marshal discovery config: %v", err)
	}
	conn, err := store.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-connp2-" + executionMode + "-" + uuid.NewString(),
		Engine:              postgres.Engine,
		Endpoints:           []string{fmt.Sprintf("%s:%d", cc.Host, cc.Port)},
		ExecutionMode:       executionMode,
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      vaultPath,
		DiscoveryConfig:     discoveryConfig,
	})
	if err != nil {
		t.Fatalf("create %s connection: %v", executionMode, err)
	}
	if _, err := store.Transition(ctx, pool, conn.ID, connections.StatusDraft, connections.StatusValidating); err != nil {
		t.Fatalf("transition to validating: %v", err)
	}
	if _, err := store.Transition(ctx, pool, conn.ID, connections.StatusValidating, connections.StatusDiscovering); err != nil {
		t.Fatalf("transition to discovering: %v", err)
	}
	return conn
}

// resourceByExternalID находит ресурс по external id.
func resourceByExternalID(resources []inventory.Resource, externalID string) (inventory.Resource, bool) {
	for i := range resources {
		if resources[i].ExternalID == externalID {
			return resources[i], true
		}
	}
	return inventory.Resource{}, false
}

// accountByIdentity находит аккаунт по engine identity.
func accountByIdentity(accounts []inventory.Account, identity string) (inventory.Account, bool) {
	for i := range accounts {
		if accounts[i].EngineIdentity == identity {
			return accounts[i], true
		}
	}
	return inventory.Account{}, false
}

func TestIntegrationConnectorPhase2(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	vaultAddr := os.Getenv("GRANTOR_TEST_VAULT_ADDR")
	vaultToken := os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if targetDSN == "" || vaultAddr == "" || vaultToken == "" {
		t.Skip("set GRANTOR_TEST_TARGET_PG_DSN and GRANTOR_TEST_VAULT_ADDR/_TOKEN to run the connector phase 2 test")
	}
	vaultMount := os.Getenv("GRANTOR_TEST_VAULT_MOUNT")
	if vaultMount == "" {
		vaultMount = "secret"
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

	// Уникальные фикстуры целевого кластера: только этот тест их трогает,
	// поэтому их строки инвентаря сравнимы между двумя discovery без гонок с
	// параллельными integration-пакетами.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	fixtureDB := "connp2_app_" + suffix
	fixtureRole := "connp2_role_" + suffix
	connp2Exec(ctx, t, targetDSN, "create database "+pgx.Identifier{fixtureDB}.Sanitize())
	t.Cleanup(func() {
		connp2Cleanup(targetDSN, "drop database if exists "+pgx.Identifier{fixtureDB}.Sanitize()+" with (force)")
	})
	connp2Exec(ctx, t, targetDSN, "create role "+pgx.Identifier{fixtureRole}.Sanitize()+" login")
	t.Cleanup(func() {
		connp2Cleanup(targetDSN, "drop role if exists "+pgx.Identifier{fixtureRole}.Sanitize())
	})

	// Admin credential целевого кластера — только в Vault; его резолвит
	// WORKER (как в direct-режиме) и доставляет connector'у кадром
	// TypeCredentials (ADR-0014) — connector к Vault не ходит.
	vaultClient, err := vault.New(vault.Config{Address: vaultAddr, Token: vaultToken, Mount: vaultMount})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	adminPath := "connp2/" + suffix + "/admin"
	if _, err := vaultClient.Put(ctx, adminPath, map[string]any{
		"username": cc.User,
		"password": cc.Password,
	}); err != nil {
		t.Fatalf("seed vault admin credential: %v", err)
	}

	// mTLS + Ed25519 подпись (production-путь) + durable dedup поверх
	// metadata DB — как у worker-встроенного gateway.
	pair := conntest.GenTLS(t, "localhost", "connector-connp2")
	gwPub, gwPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer := connector.NewED25519Signer("gw", gwPriv)
	verifier := connector.NewED25519Verifier("gw", gwPub)
	dedup := connectorjobs.NewStore(pool, 0)

	calls := &atomic.Int64{}
	rt := startPhase2Runtime(t, pair, signer, verifier, dedup, calls)
	restarted := false
	t.Cleanup(func() {
		if !restarted {
			rt.stop()
		}
	})

	// Реальный operation engine: executor с connector-routing + River.
	connStore := connections.NewStore()
	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	auditWriter := audit.NewWriter()
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       vaultClient,
		Pool:        pool,
	}).WithConnector(jobs.ConnectorDeps{Dispatcher: rt.srv})
	r, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  2,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	startRiver(t, r)

	connectorConn := createPhase2Connection(ctx, t, pool, connStore, cc,
		connections.ExecutionModeConnector, adminPath)
	directConn := createPhase2Connection(ctx, t, pool, connStore, cc,
		connections.ExecutionModeDirect, adminPath)

	// --- Discovery обоих подключений через реальные операции ---
	connectorOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &connectorConn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	directOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindConnectionDiscover,
		ConnectionID:  &directConn.ID,
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, connectorOp.ID, operations.StatusSuccess, 90*time.Second)
	waitForStatus(t, pool, opStore, directOp.ID, operations.StatusSuccess, 90*time.Second)

	// Routing: через connector прошло ровно одно discovery (direct-режим не
	// трогает gateway).
	if got := calls.Load(); got != 1 {
		t.Fatalf("connector Discover calls = %d, want 1 (connector connection only)", got)
	}

	// Оба подключения активны, server version одинаков.
	gotConnector, err := connStore.Get(ctx, pool, connectorConn.ID)
	if err != nil {
		t.Fatalf("get connector connection: %v", err)
	}
	gotDirect, err := connStore.Get(ctx, pool, directConn.ID)
	if err != nil {
		t.Fatalf("get direct connection: %v", err)
	}
	if gotConnector.Status != connections.StatusActive {
		t.Errorf("connector connection status = %q, want active", gotConnector.Status)
	}
	if gotConnector.LastDiscoveryAt == nil {
		t.Error("connector connection last_discovery_at is not set")
	}
	if gotConnector.ServerVersion == "" || gotConnector.ServerVersion != gotDirect.ServerVersion {
		t.Errorf("server version: connector %q, direct %q — must match",
			gotConnector.ServerVersion, gotDirect.ServerVersion)
	}

	// --- Инвентарь: fixture-объекты идентичны в обоих режимах ---
	connectorResources, err := invStore.ListResources(ctx, pool, connectorConn.ID)
	if err != nil {
		t.Fatalf("list connector resources: %v", err)
	}
	directResources, err := invStore.ListResources(ctx, pool, directConn.ID)
	if err != nil {
		t.Fatalf("list direct resources: %v", err)
	}
	connectorDB, okC := resourceByExternalID(connectorResources, "db:"+fixtureDB)
	directDB, okD := resourceByExternalID(directResources, "db:"+fixtureDB)
	if !okC || !okD {
		t.Fatalf("fixture database %q missing: connector=%v direct=%v", fixtureDB, okC, okD)
	}
	if connectorDB.Kind != directDB.Kind || connectorDB.Name != directDB.Name ||
		connectorDB.CanonicalPath != directDB.CanonicalPath || connectorDB.Status != directDB.Status {
		t.Errorf("fixture database rows differ:\n connector=%+v\n direct=%+v", connectorDB, directDB)
	}

	connectorAccounts, err := invStore.ListAccounts(ctx, pool, connectorConn.ID)
	if err != nil {
		t.Fatalf("list connector accounts: %v", err)
	}
	directAccounts, err := invStore.ListAccounts(ctx, pool, directConn.ID)
	if err != nil {
		t.Fatalf("list direct accounts: %v", err)
	}
	connectorRole, okC := accountByIdentity(connectorAccounts, fixtureRole)
	directRole, okD := accountByIdentity(directAccounts, fixtureRole)
	if !okC || !okD {
		t.Fatalf("fixture role %q missing: connector=%v direct=%v", fixtureRole, okC, okD)
	}
	if connectorRole.Kind != directRole.Kind || connectorRole.Ownership != directRole.Ownership ||
		connectorRole.Status != directRole.Status {
		t.Errorf("fixture role rows differ:\n connector=%+v\n direct=%+v", connectorRole, directRole)
	}

	// --- Durable dedup-строка: разобранный jsonb, статус success, и
	// инвентарь connector-подключения зеркалит исполненный snapshot ---
	dedupKey := "idem:op:" + connectorOp.ID.String() + ":snapshot-gzip-v1"
	var rawResult []byte
	if err := pool.QueryRow(ctx,
		`select result from connector_job_dedup where dedup_key = $1`, dedupKey,
	).Scan(&rawResult); err != nil {
		t.Fatalf("read dedup row %q: %v", dedupKey, err)
	}
	var cached connector.JobResult
	if err := json.Unmarshal(rawResult, &cached); err != nil {
		t.Fatalf("unmarshal cached job result: %v", err)
	}
	if cached.Status != connector.JobSuccess || cached.JobID != connectorOp.ID.String() {
		t.Fatalf("cached result = {status:%q job:%q}, want success for operation %s",
			cached.Status, cached.JobID, connectorOp.ID)
	}
	snap, err := connector.ParseDiscoveryResult(cached.Result)
	if err != nil {
		t.Fatalf("unmarshal cached snapshot: %v", err)
	}
	if len(snap.Resources) != len(connectorResources) {
		t.Errorf("inventory resources = %d, snapshot resources = %d — ingestion must mirror snapshot",
			len(connectorResources), len(snap.Resources))
	}
	for _, res := range snap.Resources {
		if _, ok := resourceByExternalID(connectorResources, res.ExternalID); !ok {
			t.Errorf("snapshot resource %q missing from connector inventory", res.ExternalID)
		}
	}
	for _, acct := range snap.Accounts {
		if _, ok := accountByIdentity(connectorAccounts, acct.EngineIdentity); !ok {
			t.Errorf("snapshot account %q missing from connector inventory", acct.EngineIdentity)
		}
	}

	// Audit идентичен прямому пути: connection.discovered от той же операции.
	events, err := auditWriter.List(ctx, pool, audit.Filter{
		ConnectionID: &connectorConn.ID,
		Actions:      []string{"connection.discovered"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Error("audit event connection.discovered not found for connector connection")
	}

	// --- Секреты не в dedup-таблице: динамический sweep покрывает новую
	// jsonb-колонку, admin password целевого кластера не встречается ---
	cols, err := listTextishColumns(ctx, pool)
	if err != nil {
		t.Fatalf("list textish columns: %v", err)
	}
	var dedupCols []textishColumn
	for _, c := range cols {
		if c.Table == "connector_job_dedup" {
			dedupCols = append(dedupCols, c)
		}
	}
	if len(dedupCols) == 0 {
		t.Fatal("connector_job_dedup has no textish columns in the sweep; no-secrets coverage is broken")
	}
	if cc.Password == "" {
		t.Fatal("target admin password is empty; no-secrets check is vacuous")
	}
	hits, err := sweepForCanary(ctx, pool, dedupCols, cc.Password)
	if err != nil {
		t.Fatalf("sweep connector_job_dedup: %v", err)
	}
	for _, h := range hits {
		t.Errorf("target admin password leaked into %s.%s (%d rows)", h.Table, h.Column, h.Rows)
	}

	// --- Durable dedup переживает «рестарт gateway»: новый Server над тем же
	// store возвращает закешированный результат, discovery не исполняется
	// второй раз ---
	rt.stop()
	restarted = true
	rt2 := startPhase2Runtime(t, pair, signer, verifier, dedup, calls)
	t.Cleanup(rt2.stop)

	dupJob := connector.Job{
		ID:              "connp2-duplicate",
		Kind:            connector.JobDiscover,
		ConnectionID:    connectorConn.ID.String(),
		Engine:          postgres.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "op:" + connectorOp.ID.String() + ":snapshot-gzip-v1",
		Nonce:           "connp2-duplicate-nonce",
	}
	// Credentials дубликату не нужны: durable dedup возвращает кеш до
	// исполнения, пустой кадр credentials никого не смущает.
	dupRes, err := rt2.srv.Dispatch(ctx, dupJob, connector.JobCredentials{})
	if err != nil {
		t.Fatalf("Dispatch duplicate after gateway restart: %v", err)
	}
	if dupRes.Status != connector.JobSuccess || dupRes.JobID != connectorOp.ID.String() {
		t.Errorf("duplicate result = {status:%q job:%q}, want cached success of %s",
			dupRes.Status, dupRes.JobID, connectorOp.ID)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("connector Discover calls after duplicate = %d, want 1 (durable dedup must not re-execute)", got)
	}

	// --- Мутация на connector-подключении у worker без gateway: типизированный
	// отказ, без молчаливого fallback к прямому исполнению (изоляция сегмента).
	// Исполнение мутаций через сконфигурированный gateway покрывает
	// connector_phase3_integration_test.
	acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   connectorConn.ID,
		EngineIdentity: "connp2m" + suffix,
		CredentialMode: "generated",
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	noGatewayExec := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       vaultClient,
		Pool:        pool,
	})
	rNoGW, err := jobs.New(pool, opStore, noGatewayExec, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  1,
		MaxAttempts:  1,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New (no gateway): %v", err)
	}
	startRiver(t, rNoGW)
	disableOp := enqueueOperation(t, pool, rNoGW, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountDisable,
		ConnectionID:  &connectorConn.ID,
		AccountID:     &acct.ID,
		Payload:       accountPayload(t, acct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	failedOp := waitForStatus(t, pool, opStore, disableOp.ID, operations.StatusFailed, 90*time.Second)
	if !strings.Contains(failedOp.Error, "connector gateway is not configured") {
		t.Errorf("mutation error = %q, want typed \"connector gateway is not configured\"", failedOp.Error)
	}
	// Мутация не должна была пройти ни через connector, ни напрямую.
	if got := calls.Load(); got != 1 {
		t.Errorf("connector calls after rejected mutation = %d, want 1", got)
	}
}
