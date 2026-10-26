//go:build integration

package jobs_test

// Интеграционный тест connector phase 3 (TEST_ID=connp3): мутирующие операции
// через execution connector сквозным путём operation engine -> gateway ->
// in-process connector agent -> целевой PostgreSQL harness + реальный Vault.
//
// Проверяется:
//   - полный lifecycle на connector-подключении реальными операциями River:
//     account.create (credential в Vault по правильному пути, роль в target,
//     логин работает, пароль НИГДЕ в metadata DB), access.grant/revoke
//     (membership наблюдаем в target), credential.rotate (новая версия Vault,
//     логин новым паролем), account.disable/enable (rolcanlogin);
//   - эквивалентность direct-режиму: та же последовательность операций на
//     direct-подключении того же кластера даёт те же статусы binding/account,
//     тот же набор audit actions и структурно те же sanitized plan/result
//     (разобранный jsonb, не подстроки);
//   - plan-only задание (JobPlan) строит план, не меняя целевую систему;
//   - разрыв соединения mid-job: apply исполнен, результат потерян, операция
//     падает retryable-ошибкой, retry River после переподключения agent
//     сходится к exactly-once наблюдаемому эффекту (повторный apply — step
//     skipped, ровно одно success-audit-событие);
//   - «мёртвый» (молчащий, без heartbeat) connector: задание завершается
//     чисто retryable-ошибкой по liveness/lease, после переподключения retry
//     доводит операцию до успеха;
//   - секреты не попадают в metadata DB: canary-sweep всех textish-колонок по
//     admin-паролю, начальным и ротированным паролям аккаунтов.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
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
	"github.com/ArtefactoO/grantor/internal/connector/wire"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/connectorjobs"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/principals"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// connp3Hook — управление adapter на стороне connector: счётчик Apply и
// «взводимый» обрыв соединения после успешного применения (сценарий потери
// результата mid-job).
type connp3Hook struct {
	applyCalls atomic.Int64
	dropArmed  atomic.Bool
	// killAgent рвёт соединение текущего agent (cancel его контекста).
	killAgent atomic.Value // func()
}

// connp3Adapter оборачивает реальный postgres adapter: после успешного Apply
// при взведённом dropArmed рвёт соединение agent ДО отправки результата.
type connp3Adapter struct {
	adapter.Adapter
	hook *connp3Hook
}

func (a connp3Adapter) Apply(ctx context.Context, plan adapter.Plan) (*adapter.Result, error) {
	res, err := a.Adapter.Apply(ctx, plan)
	a.hook.applyCalls.Add(1)
	if err == nil && a.hook.dropArmed.CompareAndSwap(true, false) {
		if kill, ok := a.hook.killAgent.Load().(func()); ok && kill != nil {
			kill()
			// Даём context.AfterFunc агента закрыть соединение до того, как
			// agent попытается записать результат: результат теряется, gateway
			// видит разрыв mid-job.
			time.Sleep(700 * time.Millisecond)
		}
	}
	return res, err
}

// ProveCredential сохраняет optional capability обёрнутого PostgreSQL adapter.
// Без явного делегирования embedding через adapter.Adapter скрывает
// CredentialProver, и managed-link корректно fail-closed ещё до target.
func (a connp3Adapter) ProveCredential(ctx context.Context, cfg adapter.Connection,
	account adapter.Account, credential adapter.Credential) error {
	prover, ok := a.Adapter.(adapter.CredentialProver)
	if !ok {
		return adapter.ErrCredentialProofUnsupported
	}
	return prover.ProveCredential(ctx, cfg, account, credential)
}

// connp3Runtime — gateway с durable dedup и управляемый lifecycle agent
// (остановка/повторный запуск для сценариев разрыва).
type connp3Runtime struct {
	t     *testing.T
	srv   *gateway.Server
	ln    net.Listener
	pair  conntest.TLSPair
	verif connector.Verifier
	hook  *connp3Hook
	agent *agent.Agent

	agentStop func()
	agentDone chan error
}

// startConnp3Gateway поднимает gateway на loopback mTLS с коротким
// liveness-окном (agent шлёт heartbeat каждые 500ms).
func startConnp3Gateway(t *testing.T, pair conntest.TLSPair, signer connector.Signer,
	verifier connector.Verifier, dedup gateway.DedupStore, hook *connp3Hook) *connp3Runtime {
	t.Helper()
	srv, err := gateway.New(gateway.Config{
		TLS:               pair.ServerTLS,
		Signer:            signer,
		Dedup:             dedup,
		LivenessWindow:    5 * time.Second,
		QuiescenceTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	rt := &connp3Runtime{t: t, srv: srv, ln: ln, pair: pair, verif: verifier, hook: hook}
	t.Cleanup(func() {
		rt.stopAgent()
		_ = ln.Close()
		_ = srv.Close()
	})
	return rt
}

// startAgent подключает новый in-process agent к gateway (реальный postgres
// adapter под connp3Adapter; Vault agent'у не нужен — credentials приходят
// кадром TypeCredentials от worker, ADR-0014) и ждёт регистрации сессии.
func (rt *connp3Runtime) startAgent() {
	rt.t.Helper()
	rt.stopAgent()
	if rt.agent == nil {
		var err error
		rt.agent, err = agent.New(agent.Config{
			ConnectorID:       "connector-connp3",
			GatewayAddr:       rt.ln.Addr().String(),
			TLS:               rt.pair.ClientTLS,
			Verifier:          rt.verif,
			HeartbeatInterval: 500 * time.Millisecond,
			Capabilities:      postgres.New().Manifest().Capabilities,
			NewAdapter: func(string) (adapter.Adapter, error) {
				return connp3Adapter{Adapter: postgres.New(), hook: rt.hook}, nil
			},
		})
		if err != nil {
			rt.t.Fatalf("agent.New: %v", err)
		}
	}
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.agent.Run(runCtx) }()
	rt.agentStop = func() {
		cancel()
		<-done
	}
	rt.agentDone = done
	rt.hook.killAgent.Store(func() { cancel() })

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer waitCancel()
	if err := rt.srv.WaitReady(waitCtx); err != nil {
		rt.t.Fatalf("connector did not connect to gateway: %v", err)
	}
}

// stopAgent останавливает текущий agent (если он запущен) и ждёт завершения.
func (rt *connp3Runtime) stopAgent() {
	if rt.agentStop != nil {
		rt.agentStop()
		rt.agentStop = nil
	}
}

// waitAgentDead ждёт, пока текущий agent завершится (например, после
// взведённого обрыва mid-job).
func (rt *connp3Runtime) waitAgentDead(timeout time.Duration) {
	rt.t.Helper()
	select {
	case err := <-rt.agentDone:
		rt.agentDone = nil
		rt.agentStop = nil
		_ = err // разрыв по cancel — штатный исход
	case <-time.After(timeout):
		rt.t.Fatal("agent did not die after armed mid-job drop")
	}
}

// connp3CanLogin возвращает наличие роли и её rolcanlogin в целевом кластере.
func connp3CanLogin(ctx context.Context, t *testing.T, dsn, role string) (found, canLogin bool) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	err = conn.QueryRow(ctx, `select rolcanlogin from pg_roles where rolname = $1`, role).Scan(&canLogin)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false
	}
	if err != nil {
		t.Fatalf("read rolcanlogin of %q: %v", role, err)
	}
	return true, canLogin
}

// connp3Login проверяет, что identity/password реально аутентифицируются в
// целевом кластере.
func connp3Login(ctx context.Context, t *testing.T, dsn, identity, password string) {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	cc.User = identity
	cc.Password = password
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatalf("login as %q: %v", identity, err)
	}
	_ = conn.Close(ctx)
}

// connp3SetPassword задаёт пароль fixture, не передавая statement/секрет в
// ошибку теста: PgError может цитировать исходный SQL.
func connp3SetPassword(ctx context.Context, t *testing.T, dsn, identity, password string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect target for fixture password: %v", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var quoted string
	if err := conn.QueryRow(ctx, `select quote_literal($1)`, password).Scan(&quoted); err != nil {
		t.Fatal("quote fixture password failed")
	}
	if _, err := conn.Exec(ctx,
		"alter role "+pgx.Identifier{identity}.Sanitize()+" password "+quoted); err != nil {
		t.Fatal("set fixture password failed")
	}
}

// connp3ModeOutcome — наблюдаемый итог последовательности операций одного
// режима исполнения, сравнивается между connector и direct.
type connp3ModeOutcome struct {
	AccountStatus   string
	BindingObserved string
	BindingStatus   string
	AuditActions    map[string]int
	GrantPlan       connp3PlanShape
	GrantVerified   bool
	RotateResult    map[string]any
}

// connp3PlanShape — структурная форма sanitized-плана grant без
// mode-специфичных значений (identity аккаунта).
type connp3PlanShape struct {
	ChangeKind string
	Permission string
	StepKinds  []string
}

// connp3AuditCount возвращает количество audit-событий операции с действием.
func connp3AuditCount(ctx context.Context, t *testing.T, pool *pgxpool.Pool, opID uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`select count(*) from audit_events where operation_id = $1 and action = $2`,
		opID, action).Scan(&n); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	return n
}

// enqueueReservedLifecycle воспроизводит API transaction ordering новой
// account lifecycle: reserve version/status -> create operation -> enqueue.
func enqueueReservedLifecycle(t *testing.T, pool *pgxpool.Pool, r *jobs.River,
	opStore *operations.Store, invStore *inventory.Store, connID, accountID uuid.UUID,
	kind string, expected inventory.AccountStatus, extra jobs.AccountPayload) operations.Operation {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lifecycle tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	reserved, err := invStore.ReserveAccountLifecycle(ctx, tx, accountID, expected)
	if err != nil {
		t.Fatalf("reserve %s lifecycle: %v", kind, err)
	}
	extra.AccountID = accountID
	extra.ExpectedStatus = expected
	extra.ExpectedLifecycleVersion = reserved.LifecycleVersion
	payload, err := json.Marshal(extra)
	if err != nil {
		t.Fatalf("marshal %s payload: %v", kind, err)
	}
	op, _, err := opStore.Create(ctx, tx, operations.CreateParams{
		Kind: kind, ConnectionID: &connID, AccountID: &accountID, Payload: payload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	if err != nil {
		t.Fatalf("create %s operation: %v", kind, err)
	}
	if err := r.EnqueueOperationTx(ctx, tx, op.ID); err != nil {
		t.Fatalf("enqueue %s operation: %v", kind, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit %s operation: %v", kind, err)
	}
	return op
}

func connp3AccessPayload(t *testing.T, bindingID uuid.UUID, lifecycleVersion int64) []byte {
	t.Helper()
	raw, err := json.Marshal(jobs.AccessPayload{
		BindingID: bindingID, ExpectedAccountLifecycleVersion: lifecycleVersion,
	})
	if err != nil {
		t.Fatalf("marshal lifecycle access payload: %v", err)
	}
	return raw
}

func TestIntegrationConnectorPhase3(t *testing.T) {
	targetDSN := os.Getenv("GRANTOR_TEST_TARGET_PG_DSN")
	vaultAddr := os.Getenv("GRANTOR_TEST_VAULT_ADDR")
	vaultToken := os.Getenv("GRANTOR_TEST_VAULT_TOKEN")
	if targetDSN == "" || vaultAddr == "" || vaultToken == "" {
		t.Skip("set GRANTOR_TEST_TARGET_PG_DSN and GRANTOR_TEST_VAULT_ADDR/_TOKEN to run the connector phase 3 test")
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

	// Уникальные фикстуры целевого кластера: общая роль-permission и роль для
	// plan-only/disconnect сценариев. Managed-аккаунты создаются операциями;
	// отдельный unmanaged login нужен regression managed-link через connector.
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:8]
	readersRole := "connp3_readers_" + suffix
	rwRole := "connp3_rw_" + suffix
	for _, role := range []string{readersRole, rwRole} {
		connp2Exec(ctx, t, targetDSN, "create role "+pgx.Identifier{role}.Sanitize()+" nologin")
		t.Cleanup(func() {
			connp2Cleanup(targetDSN, "drop role if exists "+pgx.Identifier{role}.Sanitize())
		})
	}
	managedLinkIdentity := "connp3_link_" + suffix
	managedLinkOldPassword := "connp3-link-old-" + suffix
	connp2Exec(ctx, t, targetDSN, "create role "+pgx.Identifier{managedLinkIdentity}.Sanitize()+" login")
	connp3SetPassword(ctx, t, targetDSN, managedLinkIdentity, managedLinkOldPassword)
	t.Cleanup(func() {
		connp2Cleanup(targetDSN, "drop role if exists "+pgx.Identifier{managedLinkIdentity}.Sanitize())
	})

	// Admin credential целевого кластера — только в Vault.
	vaultClient, err := vault.New(vault.Config{Address: vaultAddr, Token: vaultToken, Mount: vaultMount})
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}
	adminPath := "connp3/" + suffix + "/admin"
	if _, err := vaultClient.Put(ctx, adminPath, map[string]any{
		"username": cc.User,
		"password": cc.Password,
	}); err != nil {
		t.Fatalf("seed vault admin credential: %v", err)
	}

	// mTLS + Ed25519 подпись + durable dedup поверх metadata DB.
	pair := conntest.GenTLS(t, "localhost", "connector-connp3")
	gwPub, gwPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer := connector.NewED25519Signer("gw", gwPriv)
	verifier := connector.NewED25519Verifier("gw", gwPub)
	dedup := connectorjobs.NewStore(pool, 0)

	hook := &connp3Hook{}
	rt := startConnp3Gateway(t, pair, signer, verifier, dedup, hook)
	rt.startAgent()

	// Реальный operation engine: executor с mutations + connector routing.
	connStore := connections.NewStore()
	opStore := operations.NewStore()
	invStore := inventory.NewStore()
	principalStore := principals.NewStore()
	auditWriter := audit.NewWriter()
	credSvc := credentials.NewService(vaultClient, nil)
	var restoreMetadataFailure atomic.Bool
	var restoreOperationCommitFailure atomic.Bool
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       vaultClient,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{
		Credentials: credSvc,
		BeforeRestoreMetadataCommit: func(context.Context, operations.Operation) error {
			if restoreMetadataFailure.CompareAndSwap(true, false) {
				return errors.New("forced post-verify metadata failure")
			}
			return nil
		},
		BeforeRestoreOperationCommit: func(_ context.Context, op operations.Operation) error {
			if op.Kind == jobs.KindPostgresAccountRestoreV2 && restoreOperationCommitFailure.CompareAndSwap(true, false) {
				return errors.New("forced post-metadata pre-operation-commit failure")
			}
			return nil
		},
	}).
		WithConnector(jobs.ConnectorDeps{Dispatcher: rt.srv})
	r, err := jobs.New(pool, opStore, executor, jobs.Config{
		Queue:        testQueue(),
		WorkerCount:  2,
		MaxAttempts:  4,
		SnoozeOnLock: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("jobs.New: %v", err)
	}
	startRiver(t, r)

	// --- Два подключения к одному кластеру: connector и direct ---
	conns := map[string]connections.Connection{
		connections.ExecutionModeConnector: createPhase2Connection(ctx, t, pool, connStore, cc,
			connections.ExecutionModeConnector, adminPath),
		connections.ExecutionModeDirect: createPhase2Connection(ctx, t, pool, connStore, cc,
			connections.ExecutionModeDirect, adminPath),
	}
	for mode, conn := range conns {
		op := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindConnectionDiscover,
			ConnectionID:  &conn.ID,
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 90*time.Second)
		_ = mode
	}

	// Bare role creation uses the same lifecycle in both execution modes,
	// but must never create or rotate an account credential.
	for mode, conn := range conns {
		roleName := "connp3_group_" + mode + "_" + suffix
		t.Cleanup(func() {
			connp2Cleanup(targetDSN, "drop role if exists "+pgx.Identifier{roleName}.Sanitize())
		})
		roleAccount, err := invStore.CreateProvisioningAccount(ctx, pool, inventory.CreateManagedAccountParams{
			ConnectionID: conn.ID, EngineIdentity: roleName, Kind: inventory.AccountKindGroup,
		})
		if err != nil {
			t.Fatalf("reserve %s role account: %v", mode, err)
		}
		createRole := enqueueReservedLifecycle(t, pool, r, opStore, invStore, conn.ID, roleAccount.ID,
			jobs.KindPostgresRoleCreateV2, inventory.AccountProvisioning,
			pinPostgresV2AccountPayload(t, pool, conn.ID, jobs.AccountPayload{}))
		waitForStatus(t, pool, opStore, createRole.ID, operations.StatusSuccess, 90*time.Second)
		created, err := invStore.GetAccount(ctx, pool, roleAccount.ID)
		if err != nil {
			t.Fatalf("read %s role account: %v", mode, err)
		}
		if created.Status != inventory.AccountActive || created.Kind != inventory.AccountKindGroup ||
			created.VaultPath != "" || created.CredentialMode != nil {
			t.Fatalf("%s role account must be an active credential-free group", mode)
		}
		if found, canLogin := connp3CanLogin(ctx, t, targetDSN, roleName); !found || canLogin {
			t.Fatalf("%s created role found/can_login = %v/%v, want true/false", mode, found, canLogin)
		}
		if _, _, err := vaultClient.Get(ctx, "accounts/"+roleAccount.ID.String()+"/credential"); !errors.Is(err, vault.ErrNotFound) {
			t.Fatalf("%s bare role has an unexpected account credential: %v", mode, err)
		}
		if got := connp3AuditCount(ctx, t, pool, createRole.ID, "role.created"); got != 1 {
			t.Fatalf("%s role.created audit count = %d, want 1", mode, got)
		}
		discover := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind: jobs.KindConnectionDiscover, ConnectionID: &conn.ID,
			ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, discover.ID, operations.StatusSuccess, 90*time.Second)
		var assignable bool
		if err := pool.QueryRow(ctx, `select assignable from permission_definitions
			where connection_id=$1 and external_id=$2`, conn.ID, "role:"+roleName).Scan(&assignable); err != nil || !assignable {
			t.Fatalf("%s created role is not an assignable discovered permission: %v", mode, err)
		}
	}

	// --- Regression: managed-link через connector. ---
	// mutationTarget в connector-режиме намеренно возвращает nil adapter;
	// worker обязан проверить proof capability по локальному PostgreSQL adapter,
	// а сам rotate+prove выполнить только внутри connector agent.
	principal, err := principalStore.Create(ctx, pool, principals.CreateParams{
		Type:        principals.TypeService,
		DisplayName: "connp3-link-" + suffix,
	})
	if err != nil {
		t.Fatalf("create managed-link principal: %v", err)
	}
	connectorConn := conns[connections.ExecutionModeConnector]
	linkEnvironment := connectorConn.Environment
	if linkEnvironment == "" {
		linkEnvironment = "default"
	}
	sharedPath, created, err := credSvc.EnsurePrincipalCredential(ctx, principal.ID,
		linkEnvironment, func() ([]byte, error) {
			return credentials.GeneratePassword(credentials.DefaultPasswordLength)
		})
	if err != nil {
		t.Fatalf("ensure managed-link credential: %v", err)
	}
	if !created {
		t.Fatal("managed-link credential was not created")
	}
	sharedSecret, _, err := credSvc.GetPrincipalCredential(ctx, principal.ID, linkEnvironment)
	if err != nil {
		t.Fatalf("read managed-link credential: %v", err)
	}
	managedLinkPassword := string(sharedSecret)
	clear(sharedSecret)
	managedLinkAccount := mutAccount(t, pool, invStore, connectorConn.ID, managedLinkIdentity)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin managed-link reservation: %v", err)
	}
	reservedLink, err := invStore.ReserveAccountLifecycle(ctx, tx, managedLinkAccount.ID, inventory.AccountActive)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("reserve managed-link account: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit managed-link reservation: %v", err)
	}
	managedLinkPayload, err := json.Marshal(jobs.AccountPayload{
		AccountID:                managedLinkAccount.ID,
		ExpectedStatus:           inventory.AccountActive,
		ExpectedLifecycleVersion: reservedLink.LifecycleVersion,
		SharedCredentialPath:     sharedPath,
		ManagedLinkPrincipalID:   &principal.ID,
	})
	if err != nil {
		t.Fatalf("marshal managed-link payload: %v", err)
	}
	managedLinkOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind: jobs.KindCredentialRotate, ConnectionID: &connectorConn.ID,
		PrincipalID: &principal.ID, AccountID: &managedLinkAccount.ID, Payload: managedLinkPayload,
		ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, managedLinkOp.ID, operations.StatusSuccess, 90*time.Second)
	linkedAccount, err := invStore.GetAccount(ctx, pool, managedLinkAccount.ID)
	if err != nil {
		t.Fatalf("get managed-link account: %v", err)
	}
	if linkedAccount.Ownership != inventory.OwnershipManaged || linkedAccount.PrincipalID == nil ||
		*linkedAccount.PrincipalID != principal.ID || linkedAccount.VaultPath != sharedPath {
		t.Fatalf("managed-link metadata = %+v, want managed principal/shared credential", linkedAccount)
	}
	connp3Login(ctx, t, targetDSN, managedLinkIdentity, managedLinkPassword)
	linkAuditRows, err := pool.Query(ctx, `
		select metadata from audit_events
		where operation_id = $1 and action = 'credential.rotated'`, managedLinkOp.ID)
	if err != nil {
		t.Fatalf("query managed-link audit: %v", err)
	}
	var linkAuditMetadata [][]byte
	for linkAuditRows.Next() {
		var metadata []byte
		if err := linkAuditRows.Scan(&metadata); err != nil {
			linkAuditRows.Close()
			t.Fatalf("scan managed-link audit: %v", err)
		}
		linkAuditMetadata = append(linkAuditMetadata, metadata)
	}
	linkAuditRows.Close()
	if err := linkAuditRows.Err(); err != nil {
		t.Fatalf("read managed-link audit: %v", err)
	}
	if len(linkAuditMetadata) != 1 {
		t.Fatalf("managed-link credential.rotated audit events = %d, want 1", len(linkAuditMetadata))
	}
	var linkAudit map[string]any
	if err := json.Unmarshal(linkAuditMetadata[0], &linkAudit); err != nil {
		t.Fatalf("decode managed-link audit metadata: %v", err)
	}
	if linkAudit["managed_link"] != true || linkAudit["credential_proved"] != true ||
		linkAudit["principal_id"] != principal.ID.String() {
		t.Fatalf("managed-link audit metadata = %+v, want managed/proved principal", linkAudit)
	}

	// Managed-link выше — отдельный connector-only regression. Эквивалентность
	// последовательности ниже сравнивает только её собственные события, поэтому
	// фиксируем per-mode audit baseline до начала одинаковых мутаций.
	comparedAuditActions := []string{
		"account.created", "access.granted", "credential.rotated",
		"account.disabled", "account.enabled", "access.revoked",
	}
	auditBaseline := map[string]map[string]int{}
	for mode, conn := range conns {
		auditBaseline[mode] = map[string]int{}
		for _, action := range comparedAuditActions {
			events, err := auditWriter.List(ctx, pool, audit.Filter{
				ConnectionID: &conn.ID,
				Actions:      []string{action},
			}, 50, 0)
			if err != nil {
				t.Fatalf("[%s] list baseline audit %s: %v", mode, action, err)
			}
			auditBaseline[mode][action] = len(events)
		}
	}

	// --- Идентичная последовательность мутаций в обоих режимах ---
	initialPasswords := map[string]string{}
	rotatedPasswords := map[string]string{}
	outcomes := map[string]connp3ModeOutcome{}
	accounts := map[string]inventory.Account{}

	for i, mode := range []string{connections.ExecutionModeConnector, connections.ExecutionModeDirect} {
		conn := conns[mode]
		identity := fmt.Sprintf("connp3_m%d_%s", i, suffix)
		t.Cleanup(func() {
			connp2Cleanup(targetDSN, "drop role if exists "+pgx.Identifier{identity}.Sanitize())
		})

		acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
			ConnectionID:   conn.ID,
			EngineIdentity: identity,
			CredentialMode: "generated",
		})
		if err != nil {
			t.Fatalf("[%s] create managed account: %v", mode, err)
		}
		accounts[mode] = acct
		initialPassword := "connp3-init-" + uuid.NewString()
		initialPasswords[mode] = initialPassword
		if _, path, err := credSvc.PutAccountCredential(ctx, acct.ID, identity, []byte(initialPassword)); err != nil {
			t.Fatalf("[%s] put account credential: %v", mode, err)
		} else if err := invStore.SetAccountVaultPath(ctx, pool, acct.ID, path); err != nil {
			t.Fatalf("[%s] set account vault path: %v", mode, err)
		}

		// account.create: роль в target, логин начальным паролем из Vault.
		createPayload, err := json.Marshal(pinPostgresV2AccountPayload(t, pool, conn.ID,
			jobs.AccountPayload{AccountID: acct.ID}))
		if err != nil {
			t.Fatalf("[%s] marshal PostgreSQL v2 account payload: %v", mode, err)
		}
		createOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindPostgresAccountCreateV2,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       createPayload,
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, createOp.ID, operations.StatusSuccess, 90*time.Second)
		if !roleExists(ctx, t, targetDSN, identity) {
			t.Fatalf("[%s] login role %q not found in target after account.create", mode, identity)
		}
		connp3Login(ctx, t, targetDSN, identity, initialPassword)

		// grant: membership наблюдаем в target; plan/result — sanitized jsonb.
		readersPerm := mutPermission(t, pool, invStore, conn.ID, "role:"+readersRole)
		binding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
			AccountID:    acct.ID,
			PermissionID: readersPerm.ID,
			DesiredState: inventory.BindingPresent,
		})
		if err != nil {
			t.Fatalf("[%s] ensure binding: %v", mode, err)
		}
		grantOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccessGrant,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			BindingID:     &binding.ID,
			Payload:       accessPayload(t, binding.ID, false),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		grantDone := waitForStatus(t, pool, opStore, grantOp.ID, operations.StatusSuccess, 90*time.Second)
		if !hasMembership(ctx, t, targetDSN, readersRole, identity) {
			t.Errorf("[%s] membership %s -> %s not found in target after grant", mode, identity, readersRole)
		}
		var grantPlan connector.SanitizedPlan
		if err := json.Unmarshal(grantDone.Plan, &grantPlan); err != nil {
			t.Fatalf("[%s] unmarshal grant plan: %v (plan=%s)", mode, err, grantDone.Plan)
		}
		grantResult, err := connector.ParseSanitizedResult(grantDone.Result)
		if err != nil {
			t.Fatalf("[%s] parse grant result: %v (result=%s)", mode, err, grantDone.Result)
		}
		if grantResult.Verification == nil || !grantResult.Verification.Verified {
			t.Errorf("[%s] grant result verification = %+v, want verified", mode, grantResult.Verification)
		}

		// credential.rotate: новая версия в Vault, логин новым паролем.
		rotateOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindCredentialRotate,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       accountPayload(t, acct.ID),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		rotateDone := waitForStatus(t, pool, opStore, rotateOp.ID, operations.StatusSuccess, 90*time.Second)
		acctAfterRotate, err := invStore.GetAccount(ctx, pool, acct.ID)
		if err != nil {
			t.Fatalf("[%s] get account after rotate: %v", mode, err)
		}
		data, version, err := vaultClient.Get(ctx, acctAfterRotate.VaultPath)
		if err != nil {
			t.Fatalf("[%s] vault get rotated credential: %v", mode, err)
		}
		if version != 2 {
			t.Errorf("[%s] vault version after rotate = %d, want 2", mode, version)
		}
		rotatedPassword, _ := data["password"].(string)
		if rotatedPassword == "" || rotatedPassword == initialPassword {
			t.Fatalf("[%s] rotated password missing or unchanged in vault", mode)
		}
		rotatedPasswords[mode] = rotatedPassword
		connp3Login(ctx, t, targetDSN, identity, rotatedPassword)
		var rotateResult map[string]any
		if err := json.Unmarshal(rotateDone.Result, &rotateResult); err != nil {
			t.Fatalf("[%s] unmarshal rotate result: %v (result=%s)", mode, err, rotateDone.Result)
		}

		// disable -> enable: rolcanlogin в target.
		disableOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccountDisable,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       accountPayload(t, acct.ID),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, disableOp.ID, operations.StatusSuccess, 90*time.Second)
		if found, canLogin := connp3CanLogin(ctx, t, targetDSN, identity); !found || canLogin {
			t.Errorf("[%s] after disable: found=%v canLogin=%v, want found and nologin", mode, found, canLogin)
		}
		enableOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccountEnable,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			Payload:       accountPayload(t, acct.ID),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, enableOp.ID, operations.StatusSuccess, 90*time.Second)
		if found, canLogin := connp3CanLogin(ctx, t, targetDSN, identity); !found || !canLogin {
			t.Errorf("[%s] after enable: found=%v canLogin=%v, want found and login", mode, found, canLogin)
		}

		// revoke: membership исчезает, binding absent/synced.
		if _, err := invStore.SetBindingDesired(ctx, pool, binding.ID, inventory.BindingAbsent); err != nil {
			t.Fatalf("[%s] set binding desired absent: %v", mode, err)
		}
		revokeOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccessRevoke,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			BindingID:     &binding.ID,
			Payload:       accessPayload(t, binding.ID, false),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, revokeOp.ID, operations.StatusSuccess, 90*time.Second)
		if hasMembership(ctx, t, targetDSN, readersRole, identity) {
			t.Errorf("[%s] membership %s -> %s still present after revoke", mode, identity, readersRole)
		}

		// Сводка режима для сравнения эквивалентности (разобранные значения).
		finalBinding, err := invStore.GetBinding(ctx, pool, binding.ID)
		if err != nil {
			t.Fatalf("[%s] get binding: %v", mode, err)
		}
		finalAcct, err := invStore.GetAccount(ctx, pool, acct.ID)
		if err != nil {
			t.Fatalf("[%s] get account: %v", mode, err)
		}
		auditActions := map[string]int{}
		for _, action := range comparedAuditActions {
			events, err := auditWriter.List(ctx, pool, audit.Filter{
				ConnectionID: &conn.ID,
				Actions:      []string{action},
			}, 50, 0)
			if err != nil {
				t.Fatalf("[%s] list audit %s: %v", mode, action, err)
			}
			auditActions[action] = len(events) - auditBaseline[mode][action]
		}
		stepKinds := make([]string, 0, len(grantPlan.Steps))
		for _, s := range grantPlan.Steps {
			stepKinds = append(stepKinds, s.Kind)
		}
		outcomes[mode] = connp3ModeOutcome{
			AccountStatus:   string(finalAcct.Status),
			BindingObserved: string(finalBinding.ObservedState),
			BindingStatus:   string(finalBinding.Status),
			AuditActions:    auditActions,
			GrantPlan: connp3PlanShape{
				ChangeKind: grantPlan.Change.Kind,
				Permission: grantPlan.Change.Permission,
				StepKinds:  stepKinds,
			},
			GrantVerified: grantResult.Verification != nil && grantResult.Verification.Verified,
			RotateResult:  rotateResult,
		}
	}

	// --- Эквивалентность connector == direct ---
	if !reflect.DeepEqual(outcomes[connections.ExecutionModeConnector], outcomes[connections.ExecutionModeDirect]) {
		t.Errorf("connector and direct outcomes differ:\n connector=%+v\n direct=%+v",
			outcomes[connections.ExecutionModeConnector], outcomes[connections.ExecutionModeDirect])
	}
	if want := map[string]any{"rotated": true, "vault_version": float64(2)}; !reflect.DeepEqual(outcomes[connections.ExecutionModeConnector].RotateResult, want) {
		t.Errorf("connector rotate result = %v, want %v", outcomes[connections.ExecutionModeConnector].RotateResult, want)
	}

	// --- account.restore direct + connector, generated + provided. ---
	// Оба режима проходят forced crash-window после target proof. Retry обязан
	// заново доказать credential (connector не использует cached success),
	// активировать тот же tombstone id и не вернуть исторические bindings.
	restorePasswords := map[string]string{}
	for _, mode := range []string{connections.ExecutionModeConnector, connections.ExecutionModeDirect} {
		conn := conns[mode]
		acct := accounts[mode]
		deleteOp := enqueueReservedLifecycle(t, pool, r, opStore, invStore,
			conn.ID, acct.ID, jobs.KindAccountDelete, inventory.AccountActive, jobs.AccountPayload{})
		waitForStatus(t, pool, opStore, deleteOp.ID, operations.StatusSuccess, 90*time.Second)
		deleted, err := invStore.GetAccount(ctx, pool, acct.ID)
		if err != nil {
			t.Fatalf("[%s] get deleted tombstone: %v", mode, err)
		}
		if deleted.ID != acct.ID || deleted.Status != inventory.AccountDeleted {
			t.Fatalf("[%s] tombstone = %+v, want same id/deleted", mode, deleted)
		}
		if bs, err := invStore.ListBindingsByAccount(ctx, pool, acct.ID); err != nil || len(bs) != 0 {
			t.Fatalf("[%s] deleted bindings = %d, %v; want zero", mode, len(bs), err)
		}

		password := "restore-" + mode + "-" + uuid.NewString()
		restorePasswords[mode] = password
		vaultVersion, _, err := credSvc.PutAccountCredential(ctx, acct.ID, acct.EngineIdentity, []byte(password))
		if err != nil {
			t.Fatalf("[%s] put fresh restore credential: %v", mode, err)
		}
		credentialMode := inventory.CredentialModeProvided
		if mode == connections.ExecutionModeConnector {
			credentialMode = inventory.CredentialModeGenerated
		}
		restoreMetadataFailure.Store(true)
		restoreOp := enqueueReservedLifecycle(t, pool, r, opStore, invStore,
			conn.ID, acct.ID, jobs.KindPostgresAccountRestoreV2, inventory.AccountDeleted,
			pinPostgresV2AccountPayload(t, pool, conn.ID,
				jobs.AccountPayload{CredentialMode: credentialMode, CredentialVaultVersion: vaultVersion}))
		restoredOp := waitForStatus(t, pool, opStore, restoreOp.ID, operations.StatusSuccess, 120*time.Second)
		if len(restoredOp.Plan) == 0 || len(restoredOp.Result) == 0 {
			t.Errorf("[%s] restore artifacts are empty", mode)
		}
		restored, err := invStore.GetAccount(ctx, pool, acct.ID)
		if err != nil {
			t.Fatalf("[%s] get restored account: %v", mode, err)
		}
		if restored.ID != acct.ID || restored.Status != inventory.AccountActive || restored.PrincipalID != nil ||
			restored.DeletedAt != nil || restored.DeletedBy != nil || restored.DeleteReason != nil {
			t.Errorf("[%s] restored metadata = %+v, want same id active bare and cleared deletion", mode, restored)
		}
		if bs, err := invStore.ListBindingsByAccount(ctx, pool, acct.ID); err != nil || len(bs) != 0 {
			t.Errorf("[%s] restored bindings = %d, %v; want zero", mode, len(bs), err)
		}
		connp3Login(ctx, t, targetDSN, acct.EngineIdentity, password)
		if got := connp3AuditCount(ctx, t, pool, restoreOp.ID, "account.restore_failed"); got != 1 {
			t.Errorf("[%s] restore failure audit count = %d, want 1 forced boundary failure", mode, got)
		}
		if got := connp3AuditCount(ctx, t, pool, restoreOp.ID, "account.restored"); got != 1 {
			t.Errorf("[%s] restore success audit count = %d, want 1", mode, got)
		}

		// Отдельный чистый crash-window: после второго delete metadata restore
		// коммитится с первой попытки, затем hook откатывает outer operation tx.
		// В БД ещё нет plan/result, поэтому retry по active incarnation обязан
		// реконструировать оба артефакта без повторной target mutation.
		deleteForCommitWindow := enqueueReservedLifecycle(t, pool, r, opStore, invStore,
			conn.ID, acct.ID, jobs.KindAccountDelete, inventory.AccountActive, jobs.AccountPayload{})
		waitForStatus(t, pool, opStore, deleteForCommitWindow.ID, operations.StatusSuccess, 90*time.Second)
		commitWindowPassword := "restore-commit-window-" + mode + "-" + uuid.NewString()
		restorePasswords[mode+"-commit-window"] = commitWindowPassword
		commitWindowVaultVersion, _, err := credSvc.PutAccountCredential(
			ctx, acct.ID, acct.EngineIdentity, []byte(commitWindowPassword))
		if err != nil {
			t.Fatalf("[%s] put commit-window restore credential: %v", mode, err)
		}
		restoreOperationCommitFailure.Store(true)
		commitWindowOp := enqueueReservedLifecycle(t, pool, r, opStore, invStore,
			conn.ID, acct.ID, jobs.KindPostgresAccountRestoreV2, inventory.AccountDeleted,
			pinPostgresV2AccountPayload(t, pool, conn.ID,
				jobs.AccountPayload{CredentialMode: credentialMode, CredentialVaultVersion: commitWindowVaultVersion}))
		commitWindowDone := waitForStatus(t, pool, opStore, commitWindowOp.ID, operations.StatusSuccess, 120*time.Second)
		if restoreOperationCommitFailure.Load() {
			t.Errorf("[%s] post-metadata/pre-operation-commit fault was not exercised", mode)
		}
		var recoveredPlan connector.SanitizedPlan
		if err := json.Unmarshal(commitWindowDone.Plan, &recoveredPlan); err != nil {
			t.Fatalf("[%s] unmarshal recovered restore plan: %v", mode, err)
		}
		if len(recoveredPlan.Steps) != 1 || recoveredPlan.Steps[0].Kind != "restore-account-recovered" ||
			len(commitWindowDone.Result) == 0 {
			t.Errorf("[%s] commit-window artifacts = plan %+v result-bytes %d, want recovered plan/result",
				mode, recoveredPlan, len(commitWindowDone.Result))
		}
		connp3Login(ctx, t, targetDSN, acct.EngineIdentity, commitWindowPassword)
		password = commitWindowPassword
		if got := connp3AuditCount(ctx, t, pool, commitWindowOp.ID, "account.restored"); got != 1 {
			t.Errorf("[%s] commit-window restore success audit count = %d, want 1", mode, got)
		}

		// Старый queued delete поколения 0 после последующего restore должен
		// упасть до target mutation; identity и fresh credential сохраняются.
		stalePayload, err := json.Marshal(jobs.AccountPayload{
			AccountID: acct.ID, ExpectedStatus: inventory.AccountActive, ExpectedLifecycleVersion: 0,
		})
		if err != nil {
			t.Fatalf("marshal stale payload: %v", err)
		}
		stale := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind: jobs.KindAccountDelete, ConnectionID: &conn.ID, AccountID: &acct.ID,
			Payload: stalePayload, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
		})
		failed := waitForStatus(t, pool, opStore, stale.ID, operations.StatusFailed, 90*time.Second)
		if !strings.Contains(failed.Error, "lifecycle version") {
			t.Errorf("[%s] stale lifecycle error = %q", mode, failed.Error)
		}
		connp3Login(ctx, t, targetDSN, acct.EngineIdentity, password)

		// Удаление tombstone физически очистило binding. Даже при missing
		// binding старый revoke поколения 0 обязан сверить op.AccountID и
		// упасть stale, а не завершиться успешным no-op после restore.
		staleRevokePayload, err := json.Marshal(jobs.AccessPayload{
			BindingID: uuid.New(), ExpectedAccountLifecycleVersion: 0,
		})
		if err != nil {
			t.Fatalf("marshal stale revoke payload: %v", err)
		}
		staleRevoke := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind: jobs.KindAccessRevoke, ConnectionID: &conn.ID, AccountID: &acct.ID,
			Payload: staleRevokePayload, ActorType: "test", ActorID: t.Name(), CorrelationID: uuid.NewString(),
		})
		failedRevoke := waitForStatus(t, pool, opStore, staleRevoke.ID, operations.StatusFailed, 90*time.Second)
		if !strings.Contains(failedRevoke.Error, "lifecycle version") {
			t.Errorf("[%s] stale missing-binding revoke error = %q", mode, failedRevoke.Error)
		}
		connp3Login(ctx, t, targetDSN, acct.EngineIdentity, password)
	}

	// --- Секреты не в metadata DB: canary-sweep всех textish-колонок ---
	cols, err := listTextishColumns(ctx, pool)
	if err != nil {
		t.Fatalf("list textish columns: %v", err)
	}
	canaries := []string{cc.Password, managedLinkPassword}
	for _, m := range []string{connections.ExecutionModeConnector, connections.ExecutionModeDirect} {
		canaries = append(canaries, initialPasswords[m], rotatedPasswords[m])
	}
	for _, canary := range canaries {
		if canary == "" {
			t.Fatal("empty canary; no-secrets sweep is vacuous")
		}
		hits, err := sweepForCanary(ctx, pool, cols, canary)
		if err != nil {
			t.Fatalf("sweep for canary: %v", err)
		}
		for _, h := range hits {
			t.Errorf("password leaked into %s.%s (%d rows)", h.Table, h.Column, h.Rows)
		}
	}
	for _, canary := range restorePasswords {
		hits, err := sweepForCanary(ctx, pool, cols, canary)
		if err != nil {
			t.Fatalf("sweep restore canary: %v", err)
		}
		for _, h := range hits {
			t.Errorf("restore password leaked into %s.%s (%d rows)", h.Table, h.Column, h.Rows)
		}
	}

	// --- Plan-only (JobPlan): план строится, целевая система не меняется.
	// Роль worker для прямого Dispatch исполняет тест: admin credential
	// уходит кадром TypeCredentials, payload секретов и ссылок не несёт ---
	connectorConn = conns[connections.ExecutionModeConnector]
	connectorAcct := accounts[connections.ExecutionModeConnector]
	connectorAcct, err = invStore.GetAccount(ctx, pool, connectorAcct.ID)
	if err != nil {
		t.Fatalf("reload connector account after restore: %v", err)
	}
	planPayload, err := connector.MutationPayload{
		Connection: connector.ConnectionRef{
			ID:        connectorConn.ID.String(),
			Engine:    postgres.Engine,
			Endpoints: connectorConn.Endpoints,
		},
		TLS:        connector.TLSRef{Mode: "disabled"},
		Attributes: map[string]any{"database": cc.Database},
		Change: connector.ChangeRef{
			Kind:       string(adapter.ChangeGrant),
			Account:    connector.AccountRef{Kind: "login", EngineIdentity: connectorAcct.EngineIdentity},
			Permission: "role:" + rwRole,
		},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal plan-only payload: %v", err)
	}
	planRes, err := rt.srv.Dispatch(ctx, connector.Job{
		ID:              "connp3-plan-" + suffix,
		Kind:            connector.JobPlan,
		ConnectionID:    connectorConn.ID.String(),
		Engine:          postgres.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        time.Now().Unix(),
		IdempotencyKey:  "connp3-plan-" + suffix,
		Nonce:           "connp3-plan-nonce-" + suffix,
		Payload:         planPayload,
	}, connector.JobCredentials{Admin: &adapter.Credential{
		Kind: "password", Username: cc.User, Secret: []byte(cc.Password),
	}})
	if err != nil {
		t.Fatalf("Dispatch plan-only job: %v", err)
	}
	if planRes.Status != connector.JobSuccess {
		t.Fatalf("plan-only status = %q, error = %q, want success", planRes.Status, planRes.Error)
	}
	var planDoc connector.SanitizedPlan
	if err := json.Unmarshal(planRes.Plan, &planDoc); err != nil {
		t.Fatalf("unmarshal plan-only plan: %v", err)
	}
	if len(planDoc.Steps) == 0 {
		t.Error("plan-only job returned no steps")
	}
	if hasMembership(ctx, t, targetDSN, rwRole, connectorAcct.EngineIdentity) {
		t.Error("plan-only job mutated the target")
	}

	// --- Разрыв mid-job: retry сходится к exactly-once эффекту ---
	rwPerm := mutPermission(t, pool, invStore, connectorConn.ID, "role:"+rwRole)
	rwBinding, _, err := invStore.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:    connectorAcct.ID,
		PermissionID: rwPerm.ID,
		DesiredState: inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure rw binding: %v", err)
	}
	applyCallsBefore := hook.applyCalls.Load()
	hook.dropArmed.Store(true)
	dropOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessGrant,
		ConnectionID:  &connectorConn.ID,
		AccountID:     &connectorAcct.ID,
		BindingID:     &rwBinding.ID,
		Payload:       connp3AccessPayload(t, rwBinding.ID, connectorAcct.LifecycleVersion),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	// Apply на стороне connector исполнен, соединение разорвано до результата
	// — agent умирает; переподключаем его для retry River.
	rt.waitAgentDead(90 * time.Second)
	rt.startAgent()
	dropDone := waitForStatus(t, pool, opStore, dropOp.ID, operations.StatusSuccess, 150*time.Second)

	// Exactly-once наблюдаемый эффект: membership выдан, повторный apply при
	// retry увидел его существующим (step skipped — durable dedup не кеширует
	// незавершённые задания, сходимость даёт идемпотентность Apply), verify
	// пройден, success-audit ровно один.
	if !hasMembership(ctx, t, targetDSN, rwRole, connectorAcct.EngineIdentity) {
		t.Error("membership missing after disconnect-retry convergence")
	}
	gotApplies := hook.applyCalls.Load() - applyCallsBefore
	if gotApplies != 2 {
		t.Errorf("apply calls for disconnected op = %d, want 2 (initial + retry)", gotApplies)
	}
	dropResult, err := connector.ParseSanitizedResult(dropDone.Result)
	if err != nil {
		t.Fatalf("parse converged result: %v (result=%s)", err, dropDone.Result)
	}
	if len(dropResult.Steps) != 1 || dropResult.Steps[0].Status != string(adapter.StepSkipped) {
		t.Errorf("converged result steps = %+v, want single skipped step (no double effect)", dropResult.Steps)
	}
	if dropResult.Verification == nil || !dropResult.Verification.Verified {
		t.Errorf("converged result verification = %+v, want verified", dropResult.Verification)
	}
	if n := connp3AuditCount(ctx, t, pool, dropOp.ID, "access.granted"); n != 1 {
		t.Errorf("access.granted audit events for converged op = %d, want exactly 1", n)
	}
	if n := connp3AuditCount(ctx, t, pool, dropOp.ID, "access.grant_failed"); n < 1 {
		t.Errorf("access.grant_failed audit events for converged op = %d, want >= 1 (first attempt failed)", n)
	}

	// --- Мёртвый (молчащий) connector: retryable-падение по liveness/lease ---
	rt.stopAgent()
	silent, err := tls.Dial("tcp", rt.ln.Addr().String(), rt.pair.ClientTLS)
	if err != nil {
		t.Fatalf("dial silent connector: %v", err)
	}
	defer func() { _ = silent.Close() }()
	if err := wire.WriteJSON(silent, wire.TypeHello, connector.Hello{
		ProtocolVersion: connector.ProtocolVersion,
		ConnectorID:     "connector-connp3-silent",
	}); err != nil {
		t.Fatalf("silent hello: %v", err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(silent, wire.TypeHelloAck, &ack); err != nil {
		t.Fatalf("silent hello ack: %v", err)
	}

	deadOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccessGrant, // идемпотентный повтор present grant
		ConnectionID:  &connectorConn.ID,
		AccountID:     &connectorAcct.ID,
		BindingID:     &rwBinding.ID,
		Payload:       connp3AccessPayload(t, rwBinding.ID, connectorAcct.LifecycleVersion),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	failedDead := waitForStatus(t, pool, opStore, deadOp.ID, operations.StatusFailed, 90*time.Second)
	if !strings.Contains(failedDead.Error, "disconnected") && !strings.Contains(failedDead.Error, "lease expired") {
		t.Errorf("dead-connector error = %q, want retryable disconnect/lease error", failedDead.Error)
	}
	// Silent raw client cannot acknowledge the fenced session token. Exercise
	// bounded crash-recovery quarantine before a fresh Agent process connects.
	_ = silent.Close()
	time.Sleep(6 * time.Second)
	// После возвращения живого connector retry River доводит операцию.
	rt.startAgent()
	waitForStatus(t, pool, opStore, deadOp.ID, operations.StatusSuccess, 150*time.Second)
}
