package gateway_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/conntest"
	"github.com/ArtefactoO/grantor/internal/connector/gateway"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

func TestPostgresV2RequiresActiveHelloCapabilityBeforeCredentials(t *testing.T) {
	srv, addr, clientTLS := startGateway(t)
	conn := dialRaw(t, addr, clientTLS)
	if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{
		ProtocolVersion: connector.ProtocolVersion, ConnectorID: "baseline-connector",
		Capabilities: []connector.Capability{adapter.CapCredentialProve},
	}); err != nil {
		t.Fatal(err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		t.Fatal(err)
	}
	if srv.ActiveConnectorSupports(adapter.CapPostgresSuperuserDirectV1) {
		t.Fatal("baseline Hello unexpectedly supports PostgreSQL v2")
	}
	payload, err := (connector.MutationPayload{
		Connection: connector.ConnectionRef{ID: "c", Engine: "postgres", ConfigIncarnation: strings.Repeat("a", 64)},
		Change: connector.ChangeRef{
			Kind:                  string(adapter.ChangePostgresAccountCreateV2),
			Account:               connector.AccountRef{Kind: "login", EngineIdentity: "service_app"},
			ExpectedAdminIdentity: "grantor_admin", ExpectedTargetIdentity: "postgres:system:42",
		},
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, err = srv.Dispatch(t.Context(), connector.Job{
		ID: "v2-before-hello", Kind: connector.JobApply, ConnectionID: "c", Engine: "postgres",
		ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "v2-before-hello", Payload: payload,
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
		t.Fatalf("Dispatch error = %v, want ErrCapabilityUnavailable", err)
	}
	// Older agents already advertise adapter.credential.prove for restore and
	// rotate, but cannot execute standalone proof. No job or credential frame
	// may be sent without the new runtime marker on the selected session.
	_, err = srv.Dispatch(t.Context(), connector.Job{
		ID: "proof-before-hello", Kind: connector.JobProveCredential, ConnectionID: "c", Engine: "postgres",
		ProtocolVersion: connector.ProtocolVersion, IdempotencyKey: "proof-before-hello",
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrCapabilityUnavailable) {
		t.Fatalf("proof dispatched to old agent: %v", err)
	}
}

func TestActiveConnectorSupportsPostgresV2Marker(t *testing.T) {
	srv, addr, clientTLS := startGateway(t)
	conn := dialRaw(t, addr, clientTLS)
	if err := wire.WriteJSON(conn, wire.TypeHello, connector.Hello{
		ProtocolVersion: connector.ProtocolVersion, ConnectorID: "v2-connector",
		Capabilities: []connector.Capability{adapter.CapPostgresSuperuserDirectV1},
	}); err != nil {
		t.Fatal(err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		t.Fatal(err)
	}
	if !srv.ActiveConnectorSupports(adapter.CapPostgresSuperuserDirectV1) {
		t.Fatal("active v2 Hello marker was not observed")
	}
}

// startGateway поднимает gateway на случайном локальном порту и возвращает его
// вместе с адресом и клиентским tls.Config для подключения connector.
func startGateway(t *testing.T) (*gateway.Server, string, *tls.Config) {
	t.Helper()
	pair := conntest.GenTLS(t, "localhost", "connector-test")
	srv, err := gateway.New(gateway.Config{
		TLS:    pair.ServerTLS,
		Signer: connector.NewHMACSigner("k", []byte("secret")),
	})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = srv.Close()
	})
	return srv, ln.Addr().String(), pair.ClientTLS
}

// dialRaw подключается к gateway напрямую (без agent), чтобы управлять кадром
// Hello вручную.
func dialRaw(t *testing.T, addr string, clientTLS *tls.Config) *tls.Conn {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func TestHandshakeAccept(t *testing.T) {
	_, addr, clientTLS := startGateway(t)
	conn := dialRaw(t, addr, clientTLS)

	hello := connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "connector-test"}
	if err := wire.WriteJSON(conn, wire.TypeHello, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		t.Fatalf("read hello ack: %v", err)
	}
	if ack.ProtocolVersion != connector.ProtocolVersion {
		t.Errorf("ack version = %q, want %q", ack.ProtocolVersion, connector.ProtocolVersion)
	}
	if ack.SessionID == "" {
		t.Error("ack session_id is empty")
	}
}

func TestHandshakeRejectsWrongVersion(t *testing.T) {
	_, addr, clientTLS := startGateway(t)
	conn := dialRaw(t, addr, clientTLS)

	hello := connector.Hello{ProtocolVersion: "v2", ConnectorID: "connector-test"}
	if err := wire.WriteJSON(conn, wire.TypeHello, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	// Gateway отвечает кадром TypeError и закрывает соединение: version
	// negotiation отклоняет несовместимый connector.
	var ack wire.HelloAck
	err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack)
	if err == nil {
		t.Fatal("expected version-negotiation rejection, got hello ack")
	}
}

func TestDispatchWithoutConnector(t *testing.T) {
	srv, _, _ := startGateway(t)
	_, err := srv.Dispatch(context.Background(), connector.Job{
		ID: "job-1", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrNoConnector) {
		t.Fatalf("Dispatch without connector = %v, want ErrNoConnector", err)
	}
}

// --- Этап 3: liveness, lease и разрыв mid-job ---

// startGatewayCfg — как startGateway, но с переопределением таймингов.
func startGatewayCfg(t *testing.T, cfg gateway.Config) (*gateway.Server, string, *tls.Config) {
	t.Helper()
	pair := conntest.GenTLS(t, "localhost", "connector-test")
	cfg.TLS = pair.ServerTLS
	cfg.Signer = connector.NewHMACSigner("k", []byte("secret"))
	srv, err := gateway.New(cfg)
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() {
		_ = ln.Close()
		_ = srv.Close()
	})
	return srv, ln.Addr().String(), pair.ClientTLS
}

// handshakeRaw проходит handshake connector вручную (Hello -> HelloAck).
func handshakeRaw(t *testing.T, conn *tls.Conn) wire.HelloAck {
	t.Helper()
	hello := connector.Hello{ProtocolVersion: connector.ProtocolVersion, ConnectorID: "connector-test"}
	if err := wire.WriteJSON(conn, wire.TypeHello, hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		t.Fatalf("read hello ack: %v", err)
	}
	// Снимаем тестовый дедлайн dialRaw: сценарии ниже управляют временем сами.
	_ = conn.SetDeadline(time.Time{})
	return ack
}

// TestLivenessDropsSilentConnector — молчащий connector (нет ни heartbeat, ни
// результатов) снимается по liveness-окну: сессия исчезает, Dispatch отвечает
// ErrNoConnector (retryable-семантика недоступного сегмента).
func TestLivenessDropsSilentConnector(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		LivenessWindow: time.Second,
	})
	conn := dialRaw(t, addr, clientTLS)
	handshakeRaw(t, conn)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if !srv.ConnectorAlive() {
		t.Fatal("connector must be alive right after handshake")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, _, ok := srv.ConnectedConnector()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("silent connector was not dropped by the liveness window")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if srv.ConnectorAlive() {
		t.Error("ConnectorAlive = true after liveness drop")
	}
	_, err := srv.Dispatch(context.Background(), connector.Job{
		ID: "job-1", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrNoConnector) {
		t.Fatalf("Dispatch after liveness drop = %v, want ErrNoConnector", err)
	}
}

// TestLeaseExpiresOnStuckJob — connector жив (шлёт heartbeat), но результат не
// возвращает: Dispatch завершается по lease retryable-ошибкой ErrLeaseExpired,
// не дожидаясь результата вечно.
func TestLeaseExpiresOnStuckJob(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		LivenessWindow: 5 * time.Second,
		IOTimeout:      400 * time.Millisecond,
	})
	conn := dialRaw(t, addr, clientTLS)
	handshakeRaw(t, conn)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	// «Застрявший» connector: читает задание, но результата не шлёт.
	go func() {
		_, _, _ = wire.ReadFrame(conn)
	}()

	_, err := srv.Dispatch(context.Background(), connector.Job{
		ID: "stuck-1", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
		IdempotencyKey: "idem-stuck-1",
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrLeaseExpired) {
		t.Fatalf("Dispatch on stuck connector = %v, want ErrLeaseExpired", err)
	}
	if _, _, ok := srv.ConnectedConnector(); ok {
		t.Fatal("expired job retained the old connector session")
	}
	_, err = srv.Dispatch(context.Background(), connector.Job{
		ID: "stuck-2", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrNoConnector) {
		t.Fatalf("Dispatch before reconnect = %v, want ErrNoConnector", err)
	}
}

func TestFencedSessionRequiresCrossAgentQuiescenceProof(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		LivenessWindow:    5 * time.Second,
		IOTimeout:         2 * time.Second,
		QuiescenceTimeout: 2 * time.Second,
	})
	oldConn := dialRaw(t, addr, clientTLS)
	oldAck := handshakeRaw(t, oldConn)
	if oldAck.SessionID == "" {
		t.Fatal("old session has no fencing id")
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady old session: %v", err)
	}
	go func() {
		_, _, _ = wire.ReadFrame(oldConn) // job
		_, _, _ = wire.ReadFrame(oldConn) // credentials
	}()
	dispatchCtx, dispatchCancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer dispatchCancel()
	_, err := srv.Dispatch(dispatchCtx, connector.Job{
		ID: "cross-agent-fence", Kind: connector.JobDiscover,
		ProtocolVersion: connector.ProtocolVersion,
	}, connector.JobCredentials{})
	if err == nil {
		t.Fatal("stuck dispatch unexpectedly succeeded")
	}

	// A different rollout pod does not know the old session token and cannot
	// overlap its possibly still-returning target call.
	unproven := dialRaw(t, addr, clientTLS)
	if err := wire.WriteJSON(unproven, wire.TypeHello, connector.Hello{
		ProtocolVersion: connector.ProtocolVersion, ConnectorID: "new-pod",
	}); err != nil {
		t.Fatalf("write unproven hello: %v", err)
	}
	typ, payload, err := wire.ReadFrame(unproven)
	if err != nil {
		t.Fatalf("read unproven rejection: %v", err)
	}
	if typ != wire.TypeError {
		t.Fatalf("unproven replacement received frame %v, want TypeError", typ)
	}
	var rejection wire.ErrorFrame
	if err := json.Unmarshal(payload, &rejection); err != nil {
		t.Fatalf("decode unproven rejection: %v", err)
	}
	if rejection.Reason == "" || strings.Contains(rejection.Reason, oldAck.SessionID) {
		t.Fatalf("quiescence rejection leaked bearer session id: %q", rejection.Reason)
	}

	// The original Agent advertises the token only after its Run waited all
	// session jobs. That proof clears the barrier before the timeout fallback.
	proven := dialRaw(t, addr, clientTLS)
	if err := wire.WriteJSON(proven, wire.TypeHello, connector.Hello{
		ProtocolVersion: connector.ProtocolVersion, ConnectorID: "old-pod",
		QuiescedSessionID: oldAck.SessionID,
	}); err != nil {
		t.Fatalf("write proven hello: %v", err)
	}
	var newAck wire.HelloAck
	if err := wire.ReadJSON(proven, wire.TypeHelloAck, &newAck); err != nil {
		t.Fatalf("read proven HelloAck: %v", err)
	}
	if newAck.SessionID == "" || newAck.SessionID == oldAck.SessionID {
		t.Fatalf("new session id = %q, old = %q", newAck.SessionID, oldAck.SessionID)
	}
}

// TestDispatchSignsEffectiveLease проверяет, что gateway сначала вычисляет
// единый lease (min caller deadline, IOTimeout), записывает его в Job до
// подписи и привязывает credentials уже к этому подписанному job.
func TestDispatchSignsEffectiveLease(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		IOTimeout: 5 * time.Second,
	})
	conn := dialRaw(t, addr, clientTLS)
	handshakeRaw(t, conn)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	envelopes := make(chan connector.Envelope, 1)
	frameMatches := make(chan bool, 1)
	go func() {
		typ, payload, err := wire.ReadFrame(conn)
		if err != nil || typ != wire.TypeJob {
			return
		}
		var env connector.Envelope
		if jsonErr := json.Unmarshal(payload, &env); jsonErr != nil {
			return
		}
		envelopes <- env

		typ, payload, err = wire.ReadFrame(conn)
		if err != nil || typ != wire.TypeCredentials {
			return
		}
		var frame connector.CredentialsFrame
		if jsonErr := json.Unmarshal(payload, &frame); jsonErr != nil {
			return
		}
		frameMatches <- frame.Matches(env.Job)
		_ = wire.WriteJSON(conn, wire.TypeResult, connector.JobResult{
			JobID: env.Job.ID, Status: connector.JobSuccess, ObservedAt: time.Now().Unix(),
		})
	}()

	callerDeadline := time.Now().Add(3 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), callerDeadline)
	defer cancel()
	res, err := srv.Dispatch(ctx, connector.Job{
		ID:              "lease-signed-1",
		Kind:            connector.JobDiscover,
		ProtocolVersion: connector.ProtocolVersion,
		IdempotencyKey:  "idem-lease-signed-1",
		Nonce:           "lease-signed-1-nonce",
	}, connector.JobCredentials{})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if res.Status != connector.JobSuccess {
		t.Fatalf("status = %q, want success", res.Status)
	}
	var env connector.Envelope
	select {
	case env = <-envelopes:
	case <-time.After(5 * time.Second):
		t.Fatal("raw connector did not receive the job envelope")
	}
	if got, want := env.Job.Deadline, callerDeadline.Unix(); got != want {
		t.Fatalf("signed Job.Deadline = %d, want caller lease %d", got, want)
	}
	if err := connector.VerifyEnvelope(connector.NewHMACVerifier("k", []byte("secret")), env); err != nil {
		t.Fatalf("VerifyEnvelope after deadline clamp: %v", err)
	}
	select {
	case matches := <-frameMatches:
		if !matches {
			t.Fatal("credentials frame was not bound to the clamped signed job")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("raw connector did not receive the credentials frame")
	}
}

// TestCallerCancellationAfterWriteDropsSession — после фактической отправки
// job отмена caller ctx означает неопределённый target outcome. Gateway обязан
// fencing'нуть всю сессию, а не оставить её доступной следующему Dispatch.
func TestCallerCancellationAfterWriteDropsSession(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		IOTimeout: 5 * time.Second,
	})
	conn := dialRaw(t, addr, clientTLS)
	handshakeRaw(t, conn)

	waitCtx, waitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer waitCancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	received := make(chan struct{})
	go func() {
		if typ, _, err := wire.ReadFrame(conn); err == nil && typ == wire.TypeJob {
			if typ, _, err = wire.ReadFrame(conn); err == nil && typ == wire.TypeCredentials {
				close(received)
			}
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := srv.Dispatch(ctx, connector.Job{
			ID:              "cancel-after-write-1",
			Kind:            connector.JobDiscover,
			ProtocolVersion: connector.ProtocolVersion,
			IdempotencyKey:  "idem-cancel-after-write-1",
			Nonce:           "cancel-after-write-1-nonce",
		}, connector.JobCredentials{})
		done <- err
	}()
	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("raw connector did not receive both job frames")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Dispatch after caller cancellation = %v, want context.Canceled", err)
	}
	if _, _, ok := srv.ConnectedConnector(); ok {
		t.Fatal("caller cancellation retained the old connector session")
	}
	_, err := srv.Dispatch(context.Background(), connector.Job{
		ID: "cancel-after-write-2", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrNoConnector) {
		t.Fatalf("Dispatch before reconnect = %v, want ErrNoConnector", err)
	}
}

// TestMidJobDisconnectFailsRetryable — connector, разорвавший соединение после
// получения задания, но до результата: ожидающий Dispatch получает retryable
// ErrConnectorGone (после чего повтор с тем же IdempotencyKey безопасен —
// durable dedup хранит только успехи, а Apply идемпотентен).
func TestMidJobDisconnectFailsRetryable(t *testing.T) {
	srv, addr, clientTLS := startGatewayCfg(t, gateway.Config{
		LivenessWindow: 5 * time.Second,
	})
	conn := dialRaw(t, addr, clientTLS)
	handshakeRaw(t, conn)

	waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.WaitReady(waitCtx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}

	// Connector читает задание и обрывает соединение, не ответив.
	go func() {
		_, _, _ = wire.ReadFrame(conn)
		_ = conn.Close()
	}()

	_, err := srv.Dispatch(context.Background(), connector.Job{
		ID: "gone-1", Kind: connector.JobDiscover, ProtocolVersion: connector.ProtocolVersion,
		IdempotencyKey: "idem-gone-1",
	}, connector.JobCredentials{})
	if !errors.Is(err, gateway.ErrConnectorGone) {
		t.Fatalf("Dispatch on mid-job disconnect = %v, want ErrConnectorGone", err)
	}
}
