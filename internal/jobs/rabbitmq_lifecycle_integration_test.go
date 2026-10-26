//go:build integration

// Сквозной lifecycle-тест RabbitMQ поверх ядра: grant -> disable -> enable.
// Закрывает регрессию «после disable -> enable права не возвращаются» и её
// зеркало в metadata — ложно-зелёный статус binding, который утверждал
// observed='present' сразу после enable (и всё время, пока учётная запись
// была отключена), хотя на брокере прав уже не было.
//
// Состояние проверяется НАТИВНО в брокере (/api/users, /api/permissions) и
// реальным логином — Management API (/api/whoami) и AMQP-хендшейком на vhost,
// — а не собственными ответами grantor. Статусы bindings сверяются с этим
// фактом на каждом шаге.
//
// Требует ephemeral-контур make test-integration: metadata PostgreSQL, Vault и
// RabbitMQ с Management-плагином (GRANTOR_TEST_RABBITMQ_URL).
package jobs_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/rabbitmq"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/jobs"
	"github.com/ArtefactoO/grantor/internal/testutil/pgtest"
)

// registerRabbitMQOnce защищает от повторной регистрации adapter при
// нескольких тестах в одном процессе.
var registerRabbitMQOnce sync.Once

// rmqLifecycleVhost — vhost фикстуры этого теста. Отдельное имя, чтобы не
// пересекаться с фикстурой adapter-тестов (app_vhost).
const rmqLifecycleVhost = "gr_jobs_vhost"

// TestRabbitMQDisableEnableRestoresAccess — grant тега и доступа на vhost ->
// disable -> enable поверх реальных RabbitMQ, Vault и metadata database.
func TestRabbitMQDisableEnableRestoresAccess(t *testing.T) {
	rawURL := os.Getenv("GRANTOR_TEST_RABBITMQ_URL")
	if rawURL == "" {
		t.Skip("GRANTOR_TEST_RABBITMQ_URL is not set; skipping RabbitMQ lifecycle test")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse GRANTOR_TEST_RABBITMQ_URL: %v", err)
	}
	adminUser := u.User.Username()
	adminPass, _ := u.User.Password()

	vaultClient := newTestVaultClient(t)
	ctx := context.Background()
	pool := pgtest.Pool(t)

	registerRabbitMQOnce.Do(func() {
		adapter.Register(rabbitmq.Engine, func() adapter.Adapter { return rabbitmq.New() })
	})

	mgmt := &rmqMgmt{base: u.Scheme + "://" + u.Host, user: adminUser, pass: adminPass}
	// AMQP слушает на том же хосте; порт Management API заменяется на 5672.
	amqpAddr := net.JoinHostPort(mustHost(t, u.Host), "5672")
	mgmt.ensureVhost(t, rmqLifecycleVhost)

	// --- Connection: admin credential в реальном Vault, discovery инвентаря. ---
	adminPath := fmt.Sprintf("itest/rabbitmq-lifecycle/%s/admin", uuid.NewString())
	if _, err := vaultClient.Put(ctx, adminPath, map[string]any{
		"username": adminUser,
		"password": adminPass,
	}); err != nil {
		t.Fatalf("put admin credential: %v", err)
	}

	connStore := connections.NewStore()
	conn, err := connStore.Create(ctx, pool, connections.CreateParams{
		DisplayName:         "itest-rabbitmq-" + uuid.NewString(),
		Engine:              rabbitmq.Engine,
		Endpoints:           []string{u.Host},
		TLSConfig:           json.RawMessage(`{"mode":"disabled"}`),
		AdminCredentialMode: "existing_vault_ref",
		VaultAdminPath:      adminPath,
		DiscoveryConfig:     json.RawMessage(`{}`),
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
	credSvc := credentials.NewService(vaultClient, nil)
	executor := jobs.NewMainExecutor(jobs.DiscoveryDeps{
		Connections: connStore,
		Inventory:   invStore,
		Audit:       auditWriter,
		Vault:       vaultClient,
		Pool:        pool,
	}).WithMutations(jobs.MutationDeps{Credentials: credSvc})
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

	discover := func(reason string) {
		t.Helper()
		op := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindConnectionDiscover,
			ConnectionID:  &conn.ID,
			ActorType:     "test",
			ActorID:       t.Name() + ":" + reason,
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 60*time.Second)
	}
	discover("initial")

	// --- Managed account с известным паролем: логин проверяется по-настоящему. ---
	identity := "gr_jobs_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	password := "itest-rabbit-" + uuid.NewString()
	acct, err := invStore.CreateManagedAccount(ctx, pool, inventory.CreateManagedAccountParams{
		ConnectionID:   conn.ID,
		EngineIdentity: identity,
		CredentialMode: inventory.CredentialModeProvided,
	})
	if err != nil {
		t.Fatalf("create managed account: %v", err)
	}
	t.Cleanup(func() { mgmt.deleteUser(identity) })
	_, vaultPath, err := credSvc.PutAccountCredential(ctx, acct.ID, identity, []byte(password))
	if err != nil {
		t.Fatalf("put account credential: %v", err)
	}
	if err := invStore.SetAccountVaultPath(ctx, pool, acct.ID, vaultPath); err != nil {
		t.Fatalf("set account vault path: %v", err)
	}
	createOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountCreate,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       accountPayload(t, acct.ID),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, createOp.ID, operations.StatusSuccess, 60*time.Second)

	// --- Grant: cluster-wide тег management и полный доступ на vhost. ---
	tagPerm := mutPermission(t, pool, invStore, conn.ID, "tag:management")
	vhostPerm := mutPermission(t, pool, invStore, conn.ID, "vhost-access:"+rmqLifecycleVhost)
	// Доступ к vhost опасным не считается: сценарий проверяет
	// disable/enable, а не гейт опасных прав.
	if vhostPerm.Dangerous {
		t.Fatalf("vhost permission %q is dangerous; fixture assumption broken", vhostPerm.ExternalID)
	}

	tagBinding := ensureRmqBinding(t, ctx, pool, invStore, acct.ID, tagPerm)
	vhostBinding := ensureRmqBinding(t, ctx, pool, invStore, acct.ID, vhostPerm)
	grant := func(binding inventory.Binding, confirmed bool) {
		t.Helper()
		op := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
			Kind:          jobs.KindAccessGrant,
			ConnectionID:  &conn.ID,
			AccountID:     &acct.ID,
			BindingID:     &binding.ID,
			Payload:       accessPayload(t, binding.ID, confirmed),
			ActorType:     "test",
			ActorID:       t.Name(),
			CorrelationID: uuid.NewString(),
		})
		waitForStatus(t, pool, opStore, op.ID, operations.StatusSuccess, 60*time.Second)
	}
	grant(tagBinding, false)
	grant(vhostBinding, true)

	// Факт в брокере: тег и permission на месте, логин работает по обоим
	// протоколам.
	assertRmqTags(t, mgmt, identity, []string{"management"})
	assertRmqVhostAccess(t, mgmt, identity, rmqLifecycleVhost, true)
	if code := mgmt.whoami(t, identity, password); code != http.StatusOK {
		t.Errorf("management login after grant: status %d, want 200", code)
	}
	if got := probeAMQP(t, amqpAddr, rmqLifecycleVhost, identity, password); !got.Opened {
		t.Errorf("amqp login after grant: %+v, want opened vhost", got)
	}
	// Metadata согласована с фактом.
	assertRmqBinding(t, ctx, pool, invStore, tagBinding.ID, "after grant",
		inventory.BindingPresent, inventory.BindingStatusSynced)
	assertRmqBinding(t, ctx, pool, invStore, vhostBinding.ID, "after grant",
		inventory.BindingPresent, inventory.BindingStatusSynced)

	// --- Disable: авторизация снимается целиком. ---
	disableOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountDisable,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       rmqLifecyclePayload(t, ctx, pool, invStore, acct.ID, inventory.AccountActive),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, disableOp.ID, operations.StatusSuccess, 60*time.Second)

	assertRmqTags(t, mgmt, identity, []string{"grantor_disabled"})
	assertRmqVhostAccess(t, mgmt, identity, rmqLifecycleVhost, false)
	if code := mgmt.whoami(t, identity, password); code == http.StatusOK {
		t.Error("management login still works after disable")
	}
	// Пароль disable сознательно не инвалидирует (у движка нет нативной
	// блокировки): аутентификация проходит, а доступ к vhost — нет.
	afterDisable := probeAMQP(t, amqpAddr, rmqLifecycleVhost, identity, password)
	if !afterDisable.Authenticated {
		t.Errorf("amqp after disable: %+v, want successful authentication (password is kept by design)", afterDisable)
	}
	if afterDisable.Opened {
		t.Errorf("amqp after disable: vhost %q is still open for a disabled account", rmqLifecycleVhost)
	}
	// Ключевая проверка ложно-зелёного статуса: binding больше не смеет
	// утверждать present/synced — прав на брокере нет.
	assertRmqBinding(t, ctx, pool, invStore, tagBinding.ID, "after disable",
		inventory.BindingAbsent, inventory.BindingStatusDrift)
	assertRmqBinding(t, ctx, pool, invStore, vhostBinding.ID, "after disable",
		inventory.BindingAbsent, inventory.BindingStatusDrift)
	if got, err := invStore.GetAccount(ctx, pool, acct.ID); err != nil {
		t.Fatalf("get account after disable: %v", err)
	} else if got.Status != inventory.AccountDisabled {
		t.Errorf("account status after disable = %q, want disabled", got.Status)
	}

	// --- Enable: права возвращаются из desired state bindings. ---
	enableOp := enqueueOperation(t, pool, r, opStore, operations.CreateParams{
		Kind:          jobs.KindAccountEnable,
		ConnectionID:  &conn.ID,
		AccountID:     &acct.ID,
		Payload:       rmqLifecyclePayload(t, ctx, pool, invStore, acct.ID, inventory.AccountDisabled),
		ActorType:     "test",
		ActorID:       t.Name(),
		CorrelationID: uuid.NewString(),
	})
	waitForStatus(t, pool, opStore, enableOp.ID, operations.StatusSuccess, 60*time.Second)

	assertRmqTags(t, mgmt, identity, []string{"management"})
	assertRmqVhostAccess(t, mgmt, identity, rmqLifecycleVhost, true)
	if code := mgmt.whoami(t, identity, password); code != http.StatusOK {
		t.Errorf("management login after enable: status %d, want 200", code)
	}
	if got := probeAMQP(t, amqpAddr, rmqLifecycleVhost, identity, password); !got.Opened {
		t.Errorf("amqp login after enable: %+v, want opened vhost", got)
	}
	assertRmqBinding(t, ctx, pool, invStore, tagBinding.ID, "after enable",
		inventory.BindingPresent, inventory.BindingStatusSynced)
	assertRmqBinding(t, ctx, pool, invStore, vhostBinding.ID, "after enable",
		inventory.BindingPresent, inventory.BindingStatusSynced)

	// Восстановление зафиксировано в audit несекретной метаданной.
	events, err := auditWriter.List(ctx, pool, audit.Filter{
		ConnectionID: &conn.ID,
		Actions:       []string{"account.enabled"},
	}, 10, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no account.enabled audit event")
	}
	var meta struct {
		RestoredBindings int `json:"restored_bindings"`
	}
	if err := json.Unmarshal(events[0].Metadata, &meta); err != nil {
		t.Fatalf("unmarshal audit metadata: %v", err)
	}
	if meta.RestoredBindings != 2 {
		t.Errorf("audit restored_bindings = %d, want 2", meta.RestoredBindings)
	}

	// Статусы после enable — не ложно-зелёные: независимый discovery видит
	// ровно то же состояние и дрифта не создаёт.
	discover("after enable")
	assertRmqBinding(t, ctx, pool, invStore, tagBinding.ID, "after rediscovery",
		inventory.BindingPresent, inventory.BindingStatusSynced)
	assertRmqBinding(t, ctx, pool, invStore, vhostBinding.ID, "after rediscovery",
		inventory.BindingPresent, inventory.BindingStatusSynced)
	drift, err := invStore.DriftFindings(ctx, pool, &conn.ID)
	if err != nil {
		t.Fatalf("drift findings: %v", err)
	}
	for _, f := range drift {
		if f.BindingID != nil && (*f.BindingID == tagBinding.ID || *f.BindingID == vhostBinding.ID) {
			t.Errorf("binding %s is reported as drift after enable: %s", *f.BindingID, f.Detail)
		}
	}
}

// rmqLifecyclePayload резервирует поколение lifecycle (как это делает API) и
// собирает payload account-операции с ожидаемым статусом и версией.
func rmqLifecyclePayload(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	inv *inventory.Store, accountID uuid.UUID, expected inventory.AccountStatus) []byte {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	reserved, err := inv.ReserveAccountLifecycle(ctx, tx, accountID, expected)
	if err != nil {
		t.Fatalf("reserve account lifecycle: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit reserve: %v", err)
	}
	raw, err := json.Marshal(jobs.AccountPayload{
		AccountID:                accountID,
		ExpectedStatus:           expected,
		ExpectedLifecycleVersion: reserved.LifecycleVersion,
	})
	if err != nil {
		t.Fatalf("marshal account payload: %v", err)
	}
	return raw
}

// ensureRmqBinding создаёт managed binding с desired='present'; scope берётся
// из самого permission (у vhost-permission он задан, у тега — нет).
func ensureRmqBinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	inv *inventory.Store, accountID uuid.UUID, perm inventory.Permission) inventory.Binding {
	t.Helper()
	b, _, err := inv.EnsureBinding(ctx, pool, inventory.EnsureBindingParams{
		AccountID:       accountID,
		PermissionID:    perm.ID,
		ScopeResourceID: perm.ScopeResourceID,
		DesiredState:    inventory.BindingPresent,
	})
	if err != nil {
		t.Fatalf("ensure binding for %q: %v", perm.ExternalID, err)
	}
	return b
}

// assertRmqBinding сверяет observed state и status binding с ожидаемыми.
func assertRmqBinding(t *testing.T, ctx context.Context, pool *pgxpool.Pool, inv *inventory.Store,
	id uuid.UUID, stage string, observed inventory.BindingState, status inventory.BindingStatus) {
	t.Helper()
	b, err := inv.GetBinding(ctx, pool, id)
	if err != nil {
		t.Fatalf("get binding %s (%s): %v", id, stage, err)
	}
	if b.ObservedState != observed || b.Status != status {
		t.Errorf("binding %s %s: observed/status = %q/%q, want %q/%q",
			id, stage, b.ObservedState, b.Status, observed, status)
	}
}

// assertRmqTags сверяет функциональные и служебные теги пользователя в
// брокере с ожидаемым набором.
func assertRmqTags(t *testing.T, m *rmqMgmt, user string, want []string) {
	t.Helper()
	got := m.userTags(t, user)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("native tags of user %q = %v, want %v", user, got, want)
	}
}

// assertRmqVhostAccess сверяет наличие полного permission пользователя на
// vhost по нативному /api/permissions.
func assertRmqVhostAccess(t *testing.T, m *rmqMgmt, user, vhost string, want bool) {
	t.Helper()
	perm, found := m.permission(t, vhost, user)
	switch {
	case want && !found:
		t.Errorf("native permission of user %q on vhost %q is missing", user, vhost)
	case want && (perm.Configure != ".*" || perm.Write != ".*" || perm.Read != ".*"):
		t.Errorf("native permission of user %q on vhost %q = %+v, want full access", user, vhost, perm)
	case !want && found:
		t.Errorf("native permission of user %q on vhost %q still exists: %+v", user, vhost, perm)
	}
}

// mustHost возвращает host без порта.
func mustHost(t *testing.T, hostPort string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

// --- Нативный клиент Management API (проверки идут мимо adapter) ---

type rmqMgmt struct {
	base string
	user string
	pass string
}

type rmqPermission struct {
	Configure string `json:"configure"`
	Write     string `json:"write"`
	Read      string `json:"read"`
}

// request выполняет запрос к Management API под указанными credentials и
// возвращает статус и тело. Пароли передаются заголовком и не печатаются.
func (m *rmqMgmt) request(method, path, user, pass string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, m.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// ensureVhost идемпотентно создаёт vhost фикстуры.
func (m *rmqMgmt) ensureVhost(t *testing.T, name string) {
	t.Helper()
	status, body, err := m.request(http.MethodPut, "/api/vhosts/"+url.PathEscape(name),
		m.user, m.pass, map[string]any{})
	if err != nil {
		t.Fatalf("ensure vhost %q: %v", name, err)
	}
	if status < 200 || status >= 300 {
		t.Fatalf("ensure vhost %q: status %d: %s", name, status, body)
	}
}

// deleteUser убирает пользователя фикстуры (best-effort cleanup).
func (m *rmqMgmt) deleteUser(name string) {
	_, _, _ = m.request(http.MethodDelete, "/api/users/"+url.PathEscape(name), m.user, m.pass, nil)
}

// userTags читает теги пользователя из /api/users/<name>. Management API
// отдаёт их массивом (новые версии) или строкой через запятую (старые).
func (m *rmqMgmt) userTags(t *testing.T, name string) []string {
	t.Helper()
	status, body, err := m.request(http.MethodGet, "/api/users/"+url.PathEscape(name), m.user, m.pass, nil)
	if err != nil {
		t.Fatalf("read user %q: %v", name, err)
	}
	if status != http.StatusOK {
		t.Fatalf("read user %q: status %d: %s", name, status, body)
	}
	var payload struct {
		Tags json.RawMessage `json:"tags"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode user %q: %v", name, err)
	}
	var list []string
	if err := json.Unmarshal(payload.Tags, &list); err != nil {
		var s string
		if err := json.Unmarshal(payload.Tags, &s); err != nil {
			t.Fatalf("decode tags of user %q: %v", name, err)
		}
		list = strings.Split(s, ",")
	}
	out := make([]string, 0, len(list))
	for _, tag := range list {
		if tag = strings.TrimSpace(tag); tag != "" {
			out = append(out, tag)
		}
	}
	return out
}

// permission читает permission пользователя на vhost; found=false при 404.
func (m *rmqMgmt) permission(t *testing.T, vhost, user string) (rmqPermission, bool) {
	t.Helper()
	status, body, err := m.request(http.MethodGet,
		"/api/permissions/"+url.PathEscape(vhost)+"/"+url.PathEscape(user), m.user, m.pass, nil)
	if err != nil {
		t.Fatalf("read permission of %q on %q: %v", user, vhost, err)
	}
	if status == http.StatusNotFound {
		return rmqPermission{}, false
	}
	if status != http.StatusOK {
		t.Fatalf("read permission of %q on %q: status %d: %s", user, vhost, status, body)
	}
	var p rmqPermission
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode permission of %q on %q: %v", user, vhost, err)
	}
	return p, true
}

// whoami возвращает статус реального логина пользователя в Management API.
func (m *rmqMgmt) whoami(t *testing.T, user, pass string) int {
	t.Helper()
	status, _, err := m.request(http.MethodGet, "/api/whoami", user, pass, nil)
	if err != nil {
		t.Fatalf("whoami as %q: %v", user, err)
	}
	return status
}

// --- Минимальный AMQP 0-9-1 пробник ---
//
// Полноценный AMQP-клиент в зависимости сознательно не добавляется (adapter
// работает только с Management API), но проверка «доступ реально работает»
// обязана идти тем же протоколом, которым пользуется приложение. Пробник
// выполняет ровно handshake: PLAIN-аутентификацию и открытие vhost, различая
// отказ аутентификации и отказ авторизации на vhost.

const (
	amqpFrameMethod     = 1
	amqpFrameEnd        = 0xCE
	amqpClassConnection = 10
	amqpMethodStart     = 10
	amqpMethodStartOk   = 11
	amqpMethodTune      = 30
	amqpMethodTuneOk    = 31
	amqpMethodOpen      = 40
	amqpMethodOpenOk    = 41
	amqpMethodClose     = 50
)

// amqpResult — исход handshake: прошла ли аутентификация и открылся ли vhost.
type amqpResult struct {
	Authenticated bool
	Opened        bool
	CloseCode     uint16
	CloseText     string
}

// probeAMQP выполняет AMQP 0-9-1 handshake до Connection.Open-Ok включительно.
func probeAMQP(t *testing.T, addr, vhost, user, pass string) amqpResult {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		t.Fatalf("dial amqp %s: %v", addr, err)
	}
	defer conn.Close() //nolint:errcheck
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("set amqp deadline: %v", err)
	}

	if _, err := conn.Write([]byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}); err != nil {
		t.Fatalf("write amqp protocol header: %v", err)
	}
	class, method, _, err := amqpReadMethod(conn)
	if err != nil {
		t.Fatalf("read connection.start: %v", err)
	}
	if class != amqpClassConnection || method != amqpMethodStart {
		t.Fatalf("first amqp method = %d.%d, want connection.start", class, method)
	}

	var buf bytes.Buffer
	amqpPutShort(&buf, amqpClassConnection)
	amqpPutShort(&buf, amqpMethodStartOk)
	amqpPutTable(&buf, map[string]string{"product": "grantor-integration-probe"})
	amqpPutShortStr(&buf, "PLAIN")
	amqpPutLongStr(&buf, "\x00"+user+"\x00"+pass)
	amqpPutShortStr(&buf, "en_US")
	if err := amqpWriteFrame(conn, buf.Bytes()); err != nil {
		t.Fatalf("write connection.start-ok: %v", err)
	}

	class, method, args, err := amqpReadMethod(conn)
	if err != nil {
		// Отказ аутентификации RabbitMQ выражает разрывом соединения.
		return amqpResult{}
	}
	if class == amqpClassConnection && method == amqpMethodClose {
		code, text := amqpParseClose(args)
		return amqpResult{CloseCode: code, CloseText: text}
	}
	if class != amqpClassConnection || method != amqpMethodTune {
		t.Fatalf("amqp method after start-ok = %d.%d, want connection.tune", class, method)
	}
	res := amqpResult{Authenticated: true}

	channelMax, frameMax := amqpParseTune(t, args)
	buf.Reset()
	amqpPutShort(&buf, amqpClassConnection)
	amqpPutShort(&buf, amqpMethodTuneOk)
	amqpPutShort(&buf, channelMax)
	amqpPutLong(&buf, frameMax)
	amqpPutShort(&buf, 0) // heartbeat отключён: соединение живёт секунды
	if err := amqpWriteFrame(conn, buf.Bytes()); err != nil {
		t.Fatalf("write connection.tune-ok: %v", err)
	}

	buf.Reset()
	amqpPutShort(&buf, amqpClassConnection)
	amqpPutShort(&buf, amqpMethodOpen)
	amqpPutShortStr(&buf, vhost)
	amqpPutShortStr(&buf, "") // reserved-1
	buf.WriteByte(0)          // reserved-2
	if err := amqpWriteFrame(conn, buf.Bytes()); err != nil {
		t.Fatalf("write connection.open: %v", err)
	}

	class, method, args, err = amqpReadMethod(conn)
	if err != nil {
		return res
	}
	switch {
	case class == amqpClassConnection && method == amqpMethodOpenOk:
		res.Opened = true
	case class == amqpClassConnection && method == amqpMethodClose:
		res.CloseCode, res.CloseText = amqpParseClose(args)
	default:
		t.Fatalf("amqp method after open = %d.%d, want open-ok or close", class, method)
	}
	return res
}

// amqpWriteFrame отправляет method-кадр на канале 0.
func amqpWriteFrame(w io.Writer, payload []byte) error {
	frame := make([]byte, 0, 8+len(payload))
	frame = append(frame, amqpFrameMethod, 0, 0) // type + channel 0
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
	frame = append(frame, payload...)
	frame = append(frame, amqpFrameEnd)
	_, err := w.Write(frame)
	return err
}

// amqpReadMethod читает один method-кадр и возвращает class, method и
// оставшиеся аргументы.
func amqpReadMethod(r io.Reader) (class, method uint16, args []byte, err error) {
	header := make([]byte, 7)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[3:7])
	payload := make([]byte, size+1) // тело + frame-end
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	if payload[size] != amqpFrameEnd {
		return 0, 0, nil, fmt.Errorf("amqp frame end = %#x, want %#x", payload[size], amqpFrameEnd)
	}
	if header[0] != amqpFrameMethod {
		return 0, 0, nil, fmt.Errorf("amqp frame type = %d, want method", header[0])
	}
	if size < 4 {
		return 0, 0, nil, fmt.Errorf("amqp method frame is %d bytes", size)
	}
	body := payload[:size]
	return binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint16(body[2:4]), body[4:], nil
}

// amqpParseTune читает channel-max и frame-max из connection.tune.
func amqpParseTune(t *testing.T, args []byte) (channelMax uint16, frameMax uint32) {
	t.Helper()
	if len(args) < 6 {
		t.Fatalf("connection.tune payload is %d bytes", len(args))
	}
	return binary.BigEndian.Uint16(args[0:2]), binary.BigEndian.Uint32(args[2:6])
}

// amqpParseClose читает reply-code и reply-text из connection.close.
func amqpParseClose(args []byte) (uint16, string) {
	if len(args) < 3 {
		return 0, ""
	}
	code := binary.BigEndian.Uint16(args[0:2])
	textLen := int(args[2])
	if len(args) < 3+textLen {
		return code, ""
	}
	return code, string(args[3 : 3+textLen])
}

func amqpPutShort(b *bytes.Buffer, v uint16) {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], v)
	b.Write(raw[:])
}

func amqpPutLong(b *bytes.Buffer, v uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], v)
	b.Write(raw[:])
}

func amqpPutShortStr(b *bytes.Buffer, s string) {
	b.WriteByte(byte(len(s)))
	b.WriteString(s)
}

func amqpPutLongStr(b *bytes.Buffer, s string) {
	amqpPutLong(b, uint32(len(s)))
	b.WriteString(s)
}

// amqpPutTable кодирует field table из строковых значений ('S').
func amqpPutTable(b *bytes.Buffer, fields map[string]string) {
	var body bytes.Buffer
	for k, v := range fields {
		amqpPutShortStr(&body, k)
		body.WriteByte('S')
		amqpPutLongStr(&body, v)
	}
	amqpPutLong(b, uint32(body.Len()))
	b.Write(body.Bytes())
}
