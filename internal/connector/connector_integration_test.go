//go:build integration

// Интеграционный тест runtime execution connector этапа 1c: поднимает gateway и
// connector в одном процессе поверх РЕАЛЬНОГО mTLS-listener (self-signed CA
// генерируется в тесте), соединяет их и диспетчеризует подписанное задание
// JobDiscover для «целевого» PostgreSQL. Проверяет, что discover, исполненный
// connector, эквивалентен прямому Discover через тот же postgres adapter
// (connector-executed == direct), а также что чужая версия протокола и порченая
// подпись отклоняются, и что повтор с тем же IdempotencyKey не исполняется
// дважды.
//
// Требует env GRANTOR_TEST_TARGET_PG_DSN (целевой PostgreSQL harness); Vault
// тесту не нужен — по ADR-0014 credentials заданию доставляет control plane
// кадром TypeCredentials, и его роль здесь исполняет сам тест. Без env тест
// пропускается (TEST_ID=connrt make test-integration поднимает harness).
package connector_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/agent"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
)

const targetEnv = "GRANTOR_TEST_TARGET_PG_DSN"

// countingAdapter считает вызовы Discover, чтобы доказать, что дубликат
// (тот же IdempotencyKey) не исполняется дважды.
type countingAdapter struct {
	adapter.Adapter
	calls *atomic.Int64
}

func (c countingAdapter) Discover(ctx context.Context, cfg adapter.Connection) (*adapter.Snapshot, error) {
	c.calls.Add(1)
	return c.Adapter.Discover(ctx, cfg)
}

func TestConnectorDiscoverRoundTrip(t *testing.T) {
	dsn := os.Getenv(targetEnv)
	if dsn == "" {
		t.Skipf("set %s to run the connector round-trip test", targetEnv)
	}
	ctx := context.Background()

	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	endpoint := fmt.Sprintf("%s:%d", cc.Host, cc.Port)

	// Уникальная фикстура-БД, изолированная от других integration-пакетов,
	// которые могут параллельно менять роли в том же кластере.
	suffix := randomHex(t, 4)
	fixtureDB := "connrt_app_" + suffix
	createFixtureDatabase(ctx, t, dsn, fixtureDB)
	t.Cleanup(func() { dropDatabase(dsn, fixtureDB) })

	// mTLS + Ed25519 подпись заданий (production-путь).
	pair := conntest.GenTLS(t, "localhost", "connector-connrt")
	gwPub, gwPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer := connector.NewED25519Signer("gw", gwPriv)
	verifier := connector.NewED25519Verifier("gw", gwPub)

	srv, err := gateway.New(gateway.Config{TLS: pair.ServerTLS, Signer: signer})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	calls := &atomic.Int64{}
	ag, err := agent.New(agent.Config{
		ConnectorID: "connector-connrt",
		GatewayAddr: ln.Addr().String(),
		TLS:         pair.ClientTLS,
		Verifier:    verifier,
		NewAdapter: func(string) (adapter.Adapter, error) {
			return countingAdapter{Adapter: postgres.New(), calls: calls}, nil
		},
	})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	go func() { runErr <- ag.Run(runCtx) }()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
		_ = srv.Close()
		<-runErr
	})

	waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("connector did not connect to gateway: %v", err)
	}

	// Descriptor подключения: только несекретные данные; admin credential в
	// payload не входит — он доставляется кадром TypeCredentials (ADR-0014).
	connRef := connector.ConnectionRef{
		ID:        "conn-postgres-connrt",
		Engine:    postgres.Engine,
		Endpoints: []string{endpoint},
	}
	payload, err := connector.DiscoverPayload{
		Connection: connRef,
		TLS:        connector.TLSRef{Mode: "disabled"},
		Attributes: map[string]any{"database": cc.Database},
	}.Marshal()
	if err != nil {
		t.Fatalf("marshal discover payload: %v", err)
	}
	newJob := func(id, idem string) connector.Job {
		return connector.Job{
			ID:              id,
			Kind:            connector.JobDiscover,
			ConnectionID:    connRef.ID,
			Engine:          postgres.Engine,
			ProtocolVersion: connector.ProtocolVersion,
			IssuedAt:        time.Now().Unix(),
			IdempotencyKey:  idem,
			Nonce:           id + "-nonce",
			Payload:         payload,
		}
	}

	// Роль control plane исполняет тест: admin credential уходит кадром
	// TypeCredentials вместе с заданием (свежие слайсы на каждый dispatch —
	// agent зануляет материал после исполнения).
	adminCreds := func() connector.JobCredentials {
		return connector.JobCredentials{Admin: &adapter.Credential{
			Kind: "password", Username: cc.User, Secret: []byte(cc.Password),
		}}
	}

	// --- Успешный round-trip + эквивалентность прямому Discover ---
	res, err := srv.Dispatch(ctx, newJob("connrt-1", "connrt-idem"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch discover: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("discover status = %q, error = %q, want success", res.Status, res.Error)
	}
	var viaConnector adapter.Snapshot
	if err := json.Unmarshal(res.Result, &viaConnector); err != nil {
		t.Fatalf("unmarshal connector snapshot: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("Discover calls after first dispatch = %d, want 1", calls.Load())
	}

	// Прямой Discover тем же adapter из inline-credential (как direct worker).
	direct, err := postgres.New().Discover(ctx, directConnection(cc, endpoint))
	if err != nil {
		t.Fatalf("direct Discover: %v", err)
	}

	if viaConnector.ServerVersion == "" {
		t.Error("connector snapshot has empty server version")
	}
	if viaConnector.ServerVersion != direct.ServerVersion {
		t.Errorf("server version: connector %q != direct %q", viaConnector.ServerVersion, direct.ServerVersion)
	}
	// Ресурсы стабильны в узком окне между двумя discover; сравниваем полный
	// набор ExternalID (connector-executed == direct).
	if c, d := resourceIDs(viaConnector.Resources), resourceIDs(direct.Resources); !equalStrings(c, d) {
		t.Errorf("resource sets differ:\n connector=%v\n direct=%v", c, d)
	}
	// Фикстура-БД видна обоими путями.
	if !containsResource(viaConnector.Resources, "db:"+fixtureDB) {
		t.Errorf("connector snapshot missing fixture database %q", fixtureDB)
	}

	// --- Дедупликация: повтор с тем же IdempotencyKey не исполняется дважды ---
	dup, err := srv.Dispatch(ctx, newJob("connrt-2", "connrt-idem"), adminCreds())
	if err != nil {
		t.Fatalf("Dispatch duplicate: %v", err)
	}
	if dup.Status != connector.JobSuccess {
		t.Errorf("duplicate status = %q, want cached success", dup.Status)
	}
	if calls.Load() != 1 {
		t.Fatalf("Discover calls after duplicate = %d, want 1 (must not execute twice)", calls.Load())
	}

	// --- Порченая подпись отклоняется, задание не исполняется ---
	tampered, err := connector.SignJob(signer, newJob("connrt-3", "connrt-tamper"))
	if err != nil {
		t.Fatalf("SignJob: %v", err)
	}
	tampered.Signature[0] ^= 0xFF
	tres, err := srv.DispatchEnvelope(ctx, tampered)
	if err != nil {
		t.Fatalf("DispatchEnvelope tampered: %v", err)
	}
	if tres.Status != connector.JobFailed {
		t.Errorf("tampered status = %q, want failed", tres.Status)
	}

	// --- Чужая версия протокола отклоняется, задание не исполняется ---
	badVersion := newJob("connrt-4", "connrt-version")
	badVersion.ProtocolVersion = "v2"
	badEnv, err := connector.SignJob(signer, badVersion)
	if err != nil {
		t.Fatalf("SignJob bad version: %v", err)
	}
	vres, err := srv.DispatchEnvelope(ctx, badEnv)
	if err != nil {
		t.Fatalf("DispatchEnvelope bad version: %v", err)
	}
	if vres.Status != connector.JobFailed {
		t.Errorf("wrong-version status = %q, want failed", vres.Status)
	}

	if calls.Load() != 1 {
		t.Fatalf("Discover calls after rejections = %d, want 1 (rejected jobs must not execute)", calls.Load())
	}
}

// directConnection строит adapter.Connection с inline admin credential из
// разобранного DSN (путь direct worker).
func directConnection(cc *pgx.ConnConfig, endpoint string) adapter.Connection {
	return adapter.Connection{
		ID:         "conn-postgres-connrt",
		Engine:     postgres.Engine,
		Endpoints:  []string{endpoint},
		TLS:        adapter.TLSConfig{Mode: "disabled"},
		Attributes: map[string]any{"database": cc.Database},
		AdminCredential: adapter.Credential{
			Kind:     "password",
			Username: cc.User,
			Secret:   []byte(cc.Password),
		},
	}
}

// createFixtureDatabase идемпотентно создаёт уникальную БД в целевом кластере.
func createFixtureDatabase(ctx context.Context, t *testing.T, dsn, name string) {
	t.Helper()
	admin := connectAdmin(ctx, t, dsn)
	defer func() { _ = admin.Close(ctx) }()
	// CREATE DATABASE не выполняется в транзакции; одиночный Exec в pgx —
	// autocommit.
	if _, err := admin.Exec(ctx, "create database "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatalf("create fixture database %q: %v", name, err)
	}
}

// dropDatabase удаляет фикстуру-БД; ошибки игнорируются (cleanup не маскирует
// результат теста).
func dropDatabase(dsn, name string) {
	ctx := context.Background()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		return
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close(ctx) }()
	_, _ = conn.Exec(ctx, "drop database if exists "+pgx.Identifier{name}.Sanitize()+" with (force)")
}

func connectAdmin(ctx context.Context, t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	cc, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse %s: %v", targetEnv, err)
	}
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		t.Fatalf("connect target admin: %v", err)
	}
	return conn
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return fmt.Sprintf("%x", buf)
}

func resourceIDs(rs []adapter.ObservedResource) []string {
	ids := make([]string, 0, len(rs))
	for _, r := range rs {
		ids = append(ids, r.ExternalID)
	}
	sort.Strings(ids)
	return ids
}

func containsResource(rs []adapter.ObservedResource, externalID string) bool {
	for _, r := range rs {
		if r.ExternalID == externalID {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
