// Package agent реализует runtime самого execution connector (этапы 1c и 3,
// ADR-0002/ADR-0006/ADR-0014, docs/architecture.md разделы 4.3 и 24).
//
// Connector устанавливает ИСХОДЯЩЕЕ mTLS-соединение к gateway (внутри закрытой
// сети ничего не слушает), предъявляя свой клиентский сертификат как
// идентичность, объявляет версию протокола и adapter capabilities (Hello) и
// далее в цикле принимает Envelope: проверяет версию и подпись (отклоняет
// чужие/старые) и исполняет задание через тот же engine adapter, что и direct
// worker. С этапа 3 поддержаны все виды заданий: discover, plan, apply
// (полный поток plan -> apply -> verify мутации), verify (read-back) и
// rotate_credential, admin_credential_switch и admin_credential_rotate;
// задания разных connections исполняются параллельно (ограничение
// MaxInFlight), а задания одного connection дополнительно сериализованы
// локальным context-aware gate. Отдельная горутина шлёт heartbeat-кадры
// TypePing, по которым gateway отличает живой connector от умершего.
//
// Инвариант секретов (ADR-0014): connector НЕ имеет доступа к Vault.
// Credentials целевой системы резолвит control plane (worker) и доставляет
// отдельным кадром TypeCredentials сразу после подписанного кадра задания;
// agent сопоставляет кадр с заданием по JobID/Nonce, использует материал в
// памяти и зануляет его после исполнения (включая упавшие задания). В
// подписанный payload, JobResult и логи секреты не попадают: plan/result
// проходят ту же санитизацию, что и артефакты операций direct-пути
// (connector.MarshalSanitized*). Произвольный код невозможен:
// обрабатывается только фиксированное множество JobKind; неизвестный вид
// даёт типизированный failed-результат, не роняя процесс.
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapter/adapterutil"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

// defaultDialTimeout — предел установки исходящего mTLS-соединения к gateway.
const defaultDialTimeout = 15 * time.Second

// defaultHeartbeatInterval — период heartbeat-кадров TypePing. Должен быть
// заметно меньше liveness-окна gateway (default 45s), чтобы живой connector
// не был ошибочно признан умершим.
const defaultHeartbeatInterval = 10 * time.Second

// defaultMaxInFlight — предел одновременно исполняемых заданий. Совпадает с
// дефолтом gateway. Локальные gates ниже независимо сериализуют target-вызовы
// одного connection: transport не полагается только на advisory lock control
// plane, потому что потерянный ответ и retry могут пересечь wire-сессии.
const defaultMaxInFlight = 8

// defaultCredentialsTimeout — предел ожидания кадра TypeCredentials после
// кадра задания. Gateway пишет оба кадра подряд под одним мьютексом, поэтому
// в норме ожидание мгновенно; таймаут защищает от control plane прежнего
// контракта (без кадра credentials) — задание тогда падает типизированным
// failed-результатом, а не висит вечно.
const defaultCredentialsTimeout = 15 * time.Second

// Config — конфигурация connector.
type Config struct {
	// ConnectorID — идентификатор connector, объявляемый в Hello.
	ConnectorID string
	// GatewayAddr — адрес gateway (host:port) для исходящего mTLS.
	GatewayAddr string
	// TLS — клиентский tls.Config (клиентский сертификат + roots + ServerName;
	// см. wire.ClientTLSConfig). Обязателен.
	TLS *tls.Config
	// Verifier проверяет подпись заданий (публичный ключ gateway для Ed25519
	// либо общий секрет для HMAC). Обязателен.
	Verifier connector.Verifier
	// Capabilities — adapter capabilities, которые connector умеет исполнять;
	// объявляются в Hello.
	Capabilities []adapter.Capability
	// Deployment — где развёрнут агент ("kubernetes", "vm"); пусто — не
	// сообщать. Подсказка оператору, на приём заданий не влияет.
	Deployment string
	// NewAdapter создаёт adapter для engine; nil — adapter.New (реестр).
	NewAdapter func(engine string) (adapter.Adapter, error)
	// NewAdapterWithDialer must bind every target and discovered-peer dial to
	// the supplied guard. It is required to advertise the private DNS contract.
	NewAdapterWithDialer func(string, adapterutil.DialContextFunc) (adapter.Adapter, error)
	TargetResolver       netguard.Resolver
	TargetDialContext    adapterutil.DialContextFunc
	// Logger — логгер; nil заменяется на slog.Default().
	Logger *slog.Logger
	// DialTimeout — предел установки соединения; <=0 — defaultDialTimeout.
	DialTimeout time.Duration
	// HeartbeatInterval — период кадров TypePing; <=0 —
	// defaultHeartbeatInterval.
	HeartbeatInterval time.Duration
	// MaxInFlight — предел одновременно исполняемых заданий; <=0 —
	// defaultMaxInFlight.
	MaxInFlight int
	// CredentialsTimeout — предел ожидания кадра TypeCredentials после
	// кадра задания; <=0 — defaultCredentialsTimeout.
	CredentialsTimeout time.Duration
}

// Agent — runtime execution connector.
type Agent struct {
	cfg               Config
	log               *slog.Logger
	newAdapter        func(engine string) (adapter.Adapter, error)
	dialTimeout       time.Duration
	heartbeat         time.Duration
	maxInFlight       int
	credsTimeout      time.Duration
	gates             *connectionGates
	sessionMu         sync.Mutex
	quiescedSessionID string
}

// New создаёт connector. TLS и Verifier обязательны. Доступ к Vault agent'у
// не нужен: credentials заданий доставляет control plane (ADR-0014).
func New(cfg Config) (*Agent, error) {
	if cfg.GatewayAddr == "" {
		return nil, errors.New("agent: gateway address is required")
	}
	if cfg.TLS == nil {
		return nil, errors.New("agent: TLS config is required")
	}
	if cfg.Verifier == nil {
		return nil, errors.New("agent: verifier is required")
	}
	if configuredCapability(cfg.Capabilities, connector.CapPrivateKubernetesDNSV1) && cfg.NewAdapterWithDialer == nil {
		return nil, errors.New("agent: private Kubernetes DNS capability requires a guarded adapter factory")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	newAdapter := cfg.NewAdapter
	if newAdapter == nil {
		newAdapter = adapter.New
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	heartbeat := cfg.HeartbeatInterval
	if heartbeat <= 0 {
		heartbeat = defaultHeartbeatInterval
	}
	maxInFlight := cfg.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = defaultMaxInFlight
	}
	credsTimeout := cfg.CredentialsTimeout
	if credsTimeout <= 0 {
		credsTimeout = defaultCredentialsTimeout
	}
	return &Agent{
		cfg:          cfg,
		log:          log,
		newAdapter:   newAdapter,
		dialTimeout:  dialTimeout,
		heartbeat:    heartbeat,
		maxInFlight:  maxInFlight,
		credsTimeout: credsTimeout,
		gates:        newConnectionGates(),
	}, nil
}

// Run устанавливает соединение с gateway, проходит handshake и исполняет
// задания, пока соединение живо или пока не отменён ctx. Возвращает nil при
// отмене ctx и ошибку при сбое соединения/handshake. Задания исполняются
// параллельно (не более maxInFlight одновременно); запись кадров в соединение
// сериализована мьютексом.
func (a *Agent) Run(ctx context.Context) error {
	dialer := &net.Dialer{Timeout: a.dialTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", a.cfg.GatewayAddr, a.cfg.TLS)
	if err != nil {
		return fmt.Errorf("agent: dial gateway %s: %w", a.cfg.GatewayAddr, err)
	}

	// У каждой wire-сессии свой context. Любой разрыв транспорта отменяет
	// все target-вызовы этой сессии; Run возвращается (и supervisor может
	// reconnect) только после их завершения. Это quiescence barrier между
	// потерянным ответом старого job и выдачей следующего job новой сессии.
	sessionCtx, sessionCancel := context.WithCancel(ctx)
	stopSession := func() {
		sessionCancel()
		_ = conn.Close()
	}
	stop := context.AfterFunc(ctx, stopSession)
	var wg sync.WaitGroup
	var sessionID string
	defer func() {
		stop()
		stopSession()
		wg.Wait()
		if sessionID != "" {
			a.sessionMu.Lock()
			a.quiescedSessionID = sessionID
			a.sessionMu.Unlock()
		}
	}()

	if sessionID, err = a.handshake(conn); err != nil {
		return fmt.Errorf("agent: handshake: %w", err)
	}
	a.log.Info("agent: connected to gateway",
		"gateway", a.cfg.GatewayAddr, "connector_id", a.cfg.ConnectorID)

	// writeMu сериализует запись кадров: результаты параллельных заданий и
	// heartbeat не должны перемешиваться в потоке.
	var writeMu sync.Mutex
	writeFrame := func(t wire.Type, v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if v == nil {
			return wire.WriteFrame(conn, t, nil)
		}
		return wire.WriteJSON(conn, t, v)
	}

	// Heartbeat: отдельная горутина шлёт TypePing, пока жив ctx и соединение.
	// Ошибка записи означает умершее соединение — его закрытие разблокирует
	// основной цикл чтения; сам heartbeat при этом просто завершается.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(a.heartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-sessionCtx.Done():
				return
			case <-ticker.C:
				if err := writeFrame(wire.TypePing, nil); err != nil {
					stopSession()
					return
				}
			}
		}
	}()

	// Параллельное исполнение заданий: семафор ограничивает in-flight, а
	// WaitGroup не даёт Run вернуться, пока задания не дописали результаты
	// (или не упали на закрытом соединении).
	sem := make(chan struct{}, a.maxInFlight)
	// Ожидающие кадры TypeCredentials: слот регистрируется на каждое
	// принятое задание ДО чтения следующего кадра, а gateway пишет кадр
	// credentials сразу за кадром задания под одним мьютексом, поэтому
	// доставка всегда находит получателя (ADR-0014).
	waiters := newCredsWaiters()

	for {
		typ, payload, err := wire.ReadFrame(conn)
		if err != nil {
			stopSession()
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("agent: read frame: %w", err)
		}
		switch typ {
		case wire.TypeJob:
			var env connector.Envelope
			if err := json.Unmarshal(payload, &env); err != nil {
				a.log.Warn("agent: malformed job envelope ignored", "error", err)
				continue
			}
			credsCh := waiters.register(env.Job.ID)
			select {
			case sem <- struct{}{}:
			case <-sessionCtx.Done():
				waiters.remove(env.Job.ID, credsCh)
				if ctx.Err() != nil {
					return nil
				}
				return errors.New("agent: wire session ended while scheduling job")
			}
			wg.Add(1)
			go func(env connector.Envelope) {
				defer wg.Done()
				defer func() { <-sem }()
				// Слот снимается после исполнения; кадр, оставшийся без
				// потребителя (задание отклонено до ожидания), зануляется.
				defer waiters.remove(env.Job.ID, credsCh)
				res := a.handleJob(sessionCtx, env, credsCh)
				// После смерти wire-сессии результат уже некому принимать. Не
				// пытаться писать его в закрытый socket, но обязательно дождаться
				// завершения handler через wg перед возвратом из Run.
				if sessionCtx.Err() != nil {
					return
				}
				if err := writeFrame(wire.TypeResult, res); err != nil {
					a.log.Warn("agent: write result failed",
						"job_id", env.Job.ID, "error", err)
					// Соединение мертво: закрываем его, чтобы основной цикл
					// чтения завершился, а gateway увидел разрыв и зафейлил
					// dispatch retryable-ошибкой.
					stopSession()
				}
			}(env)
		case wire.TypeCredentials:
			var frame connector.CredentialsFrame
			if err := json.Unmarshal(payload, &frame); err != nil {
				// Текст ошибки JSON может содержать фрагмент секретного
				// payload — не логируем её.
				a.log.Warn("agent: malformed credentials frame ignored")
				continue
			}
			if !waiters.deliver(frame) {
				frame.Zero()
				a.log.Warn("agent: credentials frame for unknown job ignored",
					"job_id", frame.JobID)
			}
		default:
			// Неизвестные/служебные кадры игнорируются без разрыва соединения
			// (обратная совместимость расширений v1).
			a.log.Warn("agent: unexpected frame type ignored", "type", typ.String())
		}
	}
}

// connectionGates сериализует target execution по ConnectionID. Счётчик refs
// удерживает gate в map, пока его владеет или ждёт хотя бы один job; ожидание
// context-aware, поэтому истёкший lease либо умершая wire-сессия не оставляют
// зависший waiter и не блокируют reconnect.
type connectionGates struct {
	mu    sync.Mutex
	gates map[string]*connectionGate
}

type connectionGate struct {
	token chan struct{}
	refs  int
}

func newConnectionGates() *connectionGates {
	return &connectionGates{gates: map[string]*connectionGate{}}
}

func (g *connectionGates) acquire(ctx context.Context, connectionID string) (func(), error) {
	g.mu.Lock()
	gate := g.gates[connectionID]
	if gate == nil {
		gate = &connectionGate{token: make(chan struct{}, 1)}
		g.gates[connectionID] = gate
	}
	gate.refs++
	g.mu.Unlock()

	select {
	case gate.token <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-gate.token
				g.releaseRef(connectionID, gate)
			})
		}, nil
	case <-ctx.Done():
		g.releaseRef(connectionID, gate)
		return nil, ctx.Err()
	}
}

func (g *connectionGates) releaseRef(connectionID string, gate *connectionGate) {
	g.mu.Lock()
	defer g.mu.Unlock()
	gate.refs--
	if gate.refs == 0 && g.gates[connectionID] == gate {
		delete(g.gates, connectionID)
	}
}

// credsWaiters сопоставляет кадры TypeCredentials с ожидающими заданиями по
// JobID. Безопасен для конкурентного использования: регистрирует read loop,
// потребляют горутины заданий.
type credsWaiters struct {
	mu sync.Mutex
	m  map[string]chan connector.CredentialsFrame
}

func newCredsWaiters() *credsWaiters {
	return &credsWaiters{m: map[string]chan connector.CredentialsFrame{}}
}

// register создаёт слот ожидания кадра credentials задания id.
func (w *credsWaiters) register(id string) chan connector.CredentialsFrame {
	ch := make(chan connector.CredentialsFrame, 1)
	w.mu.Lock()
	w.m[id] = ch
	w.mu.Unlock()
	return ch
}

// deliver передаёт кадр слоту его задания; false — слот не зарегистрирован
// (кадр неизвестного задания — вызывающий обязан его занулить).
func (w *credsWaiters) deliver(frame connector.CredentialsFrame) bool {
	w.mu.Lock()
	ch, ok := w.m[frame.JobID]
	if ok {
		delete(w.m, frame.JobID)
	}
	w.mu.Unlock()
	if ok {
		ch <- frame
	}
	return ok
}

// remove снимает слот задания id и зануляет кадр, оставшийся в слоте без
// потребителя (failed jobs не удерживают секретный материал).
func (w *credsWaiters) remove(id string, ch chan connector.CredentialsFrame) {
	w.mu.Lock()
	if current, ok := w.m[id]; ok && current == ch {
		delete(w.m, id)
	}
	w.mu.Unlock()
	select {
	case frame := <-ch:
		frame.Zero()
	default:
	}
}

// handshake отправляет Hello и ждёт HelloAck. Кадр TypeError (например, отказ
// version negotiation gateway) преобразуется в ошибку.
func (a *Agent) handshake(conn net.Conn) (string, error) {
	a.sessionMu.Lock()
	quiescedSessionID := a.quiescedSessionID
	a.sessionMu.Unlock()
	hello := connector.Hello{
		ProtocolVersion:   connector.ProtocolVersion,
		ConnectorID:       a.cfg.ConnectorID,
		Capabilities:      a.cfg.Capabilities,
		Deployment:        connector.NormalizeDeployment(a.cfg.Deployment),
		QuiescedSessionID: quiescedSessionID,
	}
	if err := wire.WriteJSON(conn, wire.TypeHello, hello); err != nil {
		return "", err
	}
	var ack wire.HelloAck
	if err := wire.ReadJSON(conn, wire.TypeHelloAck, &ack); err != nil {
		return "", err
	}
	if ack.ProtocolVersion != connector.ProtocolVersion {
		return "", fmt.Errorf("%w: gateway acked %q, want %q",
			connector.ErrUnsupportedVersion, ack.ProtocolVersion, connector.ProtocolVersion)
	}
	return ack.SessionID, nil
}

// handleJob верифицирует и исполняет одно задание, всегда возвращая JobResult
// (в том числе для отказов проверки и неподдерживаемых видов) — процесс не
// падает на некорректном задании. Credentials задания приходят кадром
// TypeCredentials (credsCh); их материал зануляется по завершении задания
// независимо от исхода.
func (a *Agent) handleJob(ctx context.Context, env connector.Envelope, credsCh <-chan connector.CredentialsFrame) connector.JobResult {
	res := connector.JobResult{JobID: env.Job.ID, ObservedAt: time.Now().Unix()}

	// Version negotiation + проверка подписи. VerifyEnvelope сначала отсекает
	// чужую версию (ErrUnsupportedVersion), затем порченую/чужую подпись
	// (ErrBadSignature/ErrUnknownKey) — задание с ними НЕ исполняется (и
	// кадра credentials не ждёт: слот занулит вызывающий).
	if err := connector.VerifyEnvelope(a.cfg.Verifier, env); err != nil {
		a.log.Warn("agent: rejected job", "job_id", env.Job.ID, "error", err)
		return failed(res, fmt.Sprintf("job rejected: %v", err))
	}

	jobCtx := ctx
	cancel := func() {}
	if env.Job.Deadline > 0 {
		jobCtx, cancel = context.WithDeadline(ctx, time.Unix(env.Job.Deadline, 0))
	}
	defer cancel()
	if jobCtx.Err() != nil {
		return failed(res, "job deadline exceeded before execution")
	}
	// Reject protocol/routing errors that need no secret before waiting for a
	// credentials frame. Besides reducing ambiguity for mixed-version rollout,
	// this guarantees that an unknown or retired mutation can neither consume
	// credentials nor hold an execution slot until the credentials timeout.
	if err := a.preflightJob(env.Job); err != nil {
		return failed(res, err.Error())
	}

	// Кадр credentials обязателен для исполнения (ADR-0014): gateway пишет
	// его сразу за кадром задания. Отсутствие в пределах credsTimeout —
	// типизированный отказ (например, control plane прежнего контракта без
	// поддержки кадра), а не вечное ожидание.
	var creds connector.CredentialsFrame
	timer := time.NewTimer(a.credsTimeout)
	defer timer.Stop()
	select {
	case creds = <-credsCh:
	case <-timer.C:
		return failed(res, "credentials frame was not received for the job "+
			"(control plane must send TypeCredentials right after the job frame)")
	case <-jobCtx.Done():
		if errors.Is(jobCtx.Err(), context.DeadlineExceeded) {
			return failed(res, "job deadline exceeded before the credentials frame arrived")
		}
		return failed(res, "agent session ended before the credentials frame arrived")
	}
	// Зануление секретного материала после исполнения — и для упавших
	// заданий; слайсы разделяются с adapter.Credential, переданными adapter.
	defer creds.Zero()
	if !creds.Matches(env.Job) {
		return failed(res, "credentials frame is not bound to the job (job id/nonce mismatch)")
	}

	release, err := a.gates.acquire(jobCtx, env.Job.ConnectionID)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return failed(res, "job deadline exceeded while waiting for the connection execution gate")
		}
		return failed(res, "agent session ended while waiting for the connection execution gate")
	}
	defer release()

	switch env.Job.Kind {
	case connector.JobAccountCreation:
		return a.accountCreation(jobCtx, env.Job, creds, res)
	case connector.JobDiscover:
		return a.discover(jobCtx, env.Job, creds, res)
	case connector.JobPlan:
		return a.plan(jobCtx, env.Job, creds, res)
	case connector.JobApply:
		return a.apply(jobCtx, env.Job, creds, res)
	case connector.JobVerify:
		return a.verify(jobCtx, env.Job, creds, res)
	case connector.JobRotateCredential:
		return a.rotateCredential(jobCtx, env.Job, creds, res)
	case connector.JobProveCredential:
		return a.proveCredential(jobCtx, env.Job, creds, res)
	case connector.JobAdminCredentialSwitch, connector.JobAdminCredentialRotate:
		return a.adminCredentialChange(jobCtx, env.Job, creds, res)
	default:
		return failed(res, fmt.Sprintf("unknown job kind %q", env.Job.Kind))
	}
}

// preflightJob performs only signed, secret-free protocol checks. Target and
// adapter resolution deliberately remain after the credentials binding check
// for executable jobs. PostgreSQL v2 additionally requires the capability
// advertised by this exact agent build; there is no legacy-kind fallback.
func (a *Agent) preflightJob(job connector.Job) error {
	noAuth, err := connector.JobUsesRedisNoAuth(job)
	if err != nil {
		return err
	}
	if noAuth && !configuredCapability(a.cfg.Capabilities, connector.CapRedisNoAuthV1) {
		return errors.New("connector: Redis no-auth v1 is unavailable; update the connector")
	}
	guard, err := connector.JobNetworkGuard(job)
	if err != nil {
		return err
	}
	if guard != "" && (!configuredCapability(a.cfg.Capabilities, connector.CapPrivateKubernetesDNSV1) || a.cfg.NewAdapterWithDialer == nil) {
		return errors.New("connector: private Kubernetes DNS guard is unavailable; update the connector")
	}
	switch job.Kind {
	case connector.JobAccountCreation:
		if !configuredCapability(a.cfg.Capabilities, adapter.CapPostgresAccountCreationV1) ||
			!configuredCapability(a.cfg.Capabilities, adapter.CapPostgresSuperuserDirectV1) {
			return errors.New("connector proof-carrying account creation v1 is unavailable; update the connector")
		}
		p, err := connector.ParseAccountCreationPayload(job.Payload)
		if err != nil {
			return err
		}
		if job.Engine != "postgres" || job.ConnectionID != p.Request.Connection.ID {
			return errors.New("connector: account creation routing mismatch")
		}
		return nil
	case connector.JobProveCredential:
		if !configuredCapability(a.cfg.Capabilities, connector.CapCredentialProofV1) {
			return errors.New("connector credential proof v1 is unavailable; update the connector")
		}
		_, err := connector.ParseCredentialProofPayload(job.Payload)
		return err
	case connector.JobPlan, connector.JobApply, connector.JobVerify:
		_, kind, err := parseMutationForRouting(job)
		if err != nil {
			return err
		}
		if adapter.IsPostgresSuperuserDirectChange(kind) &&
			!configuredCapability(a.cfg.Capabilities, adapter.CapPostgresSuperuserDirectV1) {
			return fmt.Errorf("connector: PostgreSQL SUPERUSER-direct v1 is disabled in this connector build: %w", adapter.ErrUnsupportedChange)
		}
		if adapter.IsPostgresStatsMembershipChange(kind) && !configuredCapability(a.cfg.Capabilities, adapter.CapPostgresStatsMembershipV1) {
			return fmt.Errorf("connector: PostgreSQL statistics membership v1 is unavailable; update the connector: %w", adapter.ErrUnsupportedChange)
		}
		if adapter.IsPostgresObjectACLChange(kind) && !configuredCapability(a.cfg.Capabilities, adapter.CapPostgresObjectACLV1) {
			return fmt.Errorf("connector: object ACL v1 is unavailable; update the connector: %w", adapter.ErrUnsupportedChange)
		}
		return nil
	case connector.JobDiscover, connector.JobRotateCredential,
		connector.JobAdminCredentialSwitch, connector.JobAdminCredentialRotate:
		return nil
	default:
		return fmt.Errorf("unknown job kind %q", job.Kind)
	}
}

func configuredCapability(capabilities []adapter.Capability, want adapter.Capability) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

// discover исполняет JobDiscover: разбирает payload, строит adapter.Connection
// с admin credential из кадра credentials и снимает snapshot тем же adapter,
// что и direct worker. Snapshot кладётся в JobResult.Result.
func (a *Agent) discover(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	payload, err := connector.ParseDiscoverPayload(job.Payload)
	if err != nil {
		return failed(res, err.Error())
	}
	ad, cfg, err := a.target(job.Engine, payload.Connection, payload.TLS, payload.Attributes,
		creds.Admin, creds.AdminCredentialIncarnation)
	if err != nil {
		return failed(res, err.Error())
	}

	snap, err := ad.Discover(ctx, cfg)
	if err != nil {
		return failed(res, fmt.Sprintf("discover: %v", err))
	}
	if snap == nil {
		return failed(res, "discover: adapter returned no snapshot")
	}
	if job.Engine == "postgres" && !payload.PostgresObjectACL {
		permissions := snap.Permissions[:0]
		for _, permission := range snap.Permissions {
			if !strings.HasPrefix(permission.ExternalID, adapter.PostgresObjectACLPrefix) {
				permissions = append(permissions, permission)
			}
		}
		snap.Permissions = permissions
		bindings := snap.Bindings[:0]
		for _, binding := range snap.Bindings {
			if !strings.HasPrefix(binding.PermissionExternalID, adapter.PostgresObjectACLPrefix) {
				bindings = append(bindings, binding)
			}
		}
		snap.Bindings = bindings
		delete(snap.Topology, "postgres_object_acl_version")
		delete(snap.Topology, "postgres_default_privileges")
	}
	snapJSON, err := connector.MarshalDiscoveryResult(snap, payload.SnapshotEncoding)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal snapshot: %v", err))
	}

	res.Status = connector.JobSuccess
	res.Result = snapJSON
	a.log.Info("agent: discover completed",
		"job_id", job.ID, "engine", cfg.Engine, "connection_id", payload.Connection.ID,
		"resources", len(snap.Resources), "accounts", len(snap.Accounts))
	return res
}

// plan исполняет JobPlan: строит детерминированный план мутации БЕЗ изменения
// целевой системы и возвращает его sanitized-проекцию в JobResult.Plan.
func (a *Agent) plan(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	ad, change, err := a.mutationChange(job, creds)
	if err != nil {
		return failed(res, err.Error())
	}
	defer clearChangeSecret(&change)

	plan, err := ad.Plan(ctx, change)
	if err != nil {
		return failed(res, fmt.Sprintf("plan: %v", err))
	}
	planBytes, err := connector.MarshalSanitizedPlan(plan)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal plan: %v", err))
	}
	res.Status = connector.JobSuccess
	res.Plan = planBytes
	return res
}

// apply исполняет JobApply — полный поток мутации, зеркалящий direct-путь
// (internal/jobs planApplyVerify): Plan -> Apply -> read-back Verify.
// Sanitized-план попадает в JobResult.Plan до применения (и остаётся там при
// падении Apply), sanitized-результат — в JobResult.Result; шаг со статусом
// failed и непройденный verify дают failed-результат с теми же текстами
// ошибок, что и при прямом исполнении. Повторное исполнение того же задания
// безопасно: Apply идемпотентен по контракту adapter.
func (a *Agent) apply(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	ad, change, err := a.mutationChange(job, creds)
	if err != nil {
		return failed(res, err.Error())
	}
	defer clearChangeSecret(&change)

	plan, err := ad.Plan(ctx, change)
	if err != nil {
		return failed(res, fmt.Sprintf("plan: %v", err))
	}
	planBytes, err := connector.MarshalSanitizedPlan(plan)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal plan: %v", err))
	}
	res.Plan = planBytes

	applied, err := ad.Apply(ctx, *plan)
	if err != nil {
		return failed(res, fmt.Sprintf("apply: %v", err))
	}
	resultBytes, err := connector.MarshalSanitizedResult(applied, nil)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal result: %v", err))
	}
	res.Result = resultBytes
	for _, step := range applied.Steps {
		if step.Status == adapter.StepFailed {
			return failed(res, fmt.Sprintf("apply: step %q failed: %s", step.Step.Kind, step.Error))
		}
	}

	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		return failed(res, fmt.Sprintf("verify: %v", err))
	}
	resultBytes, err = connector.MarshalSanitizedResult(applied, ver)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal verified result: %v", err))
	}
	res.Result = resultBytes
	if !ver.Verified {
		return failed(res, fmt.Sprintf("verify: target state is not verified: %s", ver.Details))
	}

	res.Status = connector.JobSuccess
	a.log.Info("agent: apply completed",
		"job_id", job.ID, "change", change.Kind, "account", change.Account.EngineIdentity)
	return res
}

// verify исполняет JobVerify: строит план и выполняет только read-back
// проверку, не меняя целевую систему. Verification возвращается в
// JobResult.Result (sanitized, без шагов применения).
func (a *Agent) verify(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	ad, change, err := a.mutationChange(job, creds)
	if err != nil {
		return failed(res, err.Error())
	}
	defer clearChangeSecret(&change)

	plan, err := ad.Plan(ctx, change)
	if err != nil {
		return failed(res, fmt.Sprintf("plan: %v", err))
	}
	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		return failed(res, fmt.Sprintf("verify: %v", err))
	}
	resultBytes, err := connector.MarshalSanitizedResult(&adapter.Result{}, ver)
	if err != nil {
		return failed(res, fmt.Sprintf("marshal result: %v", err))
	}
	res.Status = connector.JobSuccess
	res.Result = resultBytes
	return res
}

// rotateCredential исполняет JobRotateCredential: применяет НОВУЮ версию
// секрета учётной записи, доставленную кадром credentials (control plane
// записал её в Vault до выпуска задания), тем же adapter.RotateCredential,
// что и direct worker. Результат несекретный: подтверждение и версия Vault
// из того же кадра.
func (a *Agent) rotateCredential(ctx context.Context, job connector.Job, creds connector.CredentialsFrame, res connector.JobResult) connector.JobResult {
	payload, err := connector.ParseRotatePayload(job.Payload)
	if err != nil {
		return failed(res, err.Error())
	}
	ad, cfg, err := a.target(job.Engine, payload.Connection, payload.TLS, payload.Attributes,
		creds.Admin, creds.AdminCredentialIncarnation)
	if err != nil {
		return failed(res, err.Error())
	}
	if creds.Account == nil {
		return failed(res, "credentials frame carries no account credential for rotation")
	}
	cred := creds.Account.Credential()
	if cred.Username == "" {
		// Worker заполняет username (engine identity); fallback — defensive.
		cred.Username = payload.Account.EngineIdentity
	}

	// VerifyCredential означает security-sensitive link-and-manage. Проверяем
	// manifest + optional prover ДО изменения target: старый connector сначала
	// ротировал пароль и только потом обнаруживал отсутствие proof-контракта,
	// оставляя учётку изменённой при failed job.
	if payload.VerifyCredential && !adapter.SupportsCredentialProof(ad) {
		return failed(res, "credential proof is unsupported for managed link")
	}
	if payload.VerifyCredential {
		if preflight, ok := ad.(adapter.CredentialProofPreflighter); ok {
			if err := preflight.CheckCredentialProofAccess(ctx, cfg, adapterAccount(payload.Account)); err != nil {
				res = failed(res, "credential verification preflight failed: "+err.Error())
				if errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
					res.ErrorCode = "credential_access_denied"
				}
				if errors.Is(err, adapter.ErrCredentialProofUnsupported) {
					res.ErrorCode = "credential_proof_unsupported"
				}
				return res
			}
		}
	}
	if err := ad.RotateCredential(ctx, cfg, adapterAccount(payload.Account), cred); err != nil {
		return failed(res, fmt.Sprintf("rotate credential: %v", err))
	}
	if payload.VerifyCredential {
		prover := ad.(adapter.CredentialProver)
		if err := prover.ProveCredential(ctx, cfg, adapterAccount(payload.Account), cred); err != nil {
			res = failed(res, fmt.Sprintf("password changed, but credential verification failed: %v", err))
			if errors.Is(err, adapter.ErrCredentialProofAccessDenied) {
				res.ErrorCode = "credential_access_denied"
			}
			return res
		}
	}
	outcome, err := connector.RotateOutcome{Rotated: true, VaultVersion: creds.AccountVaultVersion, Verified: payload.VerifyCredential}.Marshal()
	if err != nil {
		return failed(res, err.Error())
	}
	res.Status = connector.JobSuccess
	res.Result = outcome
	a.log.Info("agent: credential rotated",
		"job_id", job.ID, "account", payload.Account.EngineIdentity,
		"vault_version", creds.AccountVaultVersion)
	return res
}

// adminCredentialChange executes the dedicated connection-administrator
// contract. It never falls back to RotateCredential: an adapter without the
// stronger manager interface is rejected before ValidateConnection, Discover
// or any target mutation. Candidate/old secrets live only in the credentials
// frame and are zeroed by handleJob after this method returns.
func (a *Agent) adminCredentialChange(
	ctx context.Context,
	job connector.Job,
	creds connector.CredentialsFrame,
	res connector.JobResult,
) connector.JobResult {
	payload, err := connector.ParseAdminCredentialPayload(job.Payload)
	if err != nil {
		return failed(res, err.Error())
	}
	expectedKind, err := payload.JobKind()
	if err != nil {
		return failed(res, err.Error())
	}
	if expectedKind != job.Kind {
		return failed(res, fmt.Sprintf(
			"admin credential payload mode %q does not match job kind %q", payload.Mode, job.Kind))
	}
	if job.ConnectionID == "" || job.ConnectionID != payload.Connection.ID {
		return failed(res, "admin credential job connection identity does not match its payload")
	}
	if job.Engine == "" || job.Engine != payload.Connection.Engine {
		return failed(res, "admin credential job engine does not match its payload")
	}
	candidate := adapter.Credential{Kind: "none", Username: "default"}
	if payload.CandidateAuthMode == "none" {
		if creds.Account != nil || creds.AccountVaultVersion != 0 {
			return failed(res, "no-auth candidate must not carry credential material")
		}
	} else {
		if creds.Account == nil || creds.AccountVaultVersion <= 0 {
			return failed(res, "credentials frame carries no exact staged admin candidate")
		}
		candidate = creds.Account.Credential()
		if candidate.Kind != "password" || candidate.Username != payload.CandidateUsername || len(candidate.Secret) == 0 {
			return failed(res, "staged admin candidate does not match the signed payload")
		}
	}

	// Constructing an adapter is local and side-effect free. The stronger
	// interface check must happen before the first target call.
	ad, currentCfg, err := a.target(job.Engine, payload.Connection, payload.TLS,
		payload.Attributes, creds.Admin, creds.AdminCredentialIncarnation)
	if err != nil {
		return failed(res, err.Error())
	}
	manager, ok := ad.(adapter.ConnectionAdminCredentialManager)
	if !ok {
		return failed(res, "connection admin credential manager is unsupported for this engine")
	}
	candidateCfg := currentCfg
	candidateCfg.AdminCredential = candidate
	candidateCfg.AuthMode = "password"
	if candidate.Kind == "none" {
		candidateCfg.AuthMode = "none"
	}
	candidateCfg.AdminCredentialIncarnation = creds.AccountVaultVersion

	var proof adapter.AdminCredentialProof
	alreadyApplied := false
	switch payload.Mode {
	case connector.AdminCredentialModeSwitch:
		proof, err = manager.ProveConnectionAdminCredential(ctx, currentCfg, candidate)
		if err != nil {
			return failedAdminCredential(res, err,
				fmt.Sprintf("prove staged connection admin credential: %v", err))
		}
		// ValidateConnection is deliberately separate from authentication
		// proof: a valid login that lost administrative authority must not be
		// promoted to canonical.
		if err = ad.ValidateConnection(ctx, candidateCfg); err != nil {
			return failed(res, fmt.Sprintf("validate staged connection admin credential: %v", err))
		}
	case connector.AdminCredentialModeRotate:
		if creds.Admin == nil || currentCfg.AdminCredential.Kind != "password" ||
			currentCfg.AdminCredential.Username == "" || len(currentCfg.AdminCredential.Secret) == 0 {
			return failed(res, "admin credential rotation requires the old canonical credential")
		}
		if currentCfg.AdminCredential.Username != candidate.Username {
			return failed(res, "admin credential rotation cannot change the canonical username")
		}
		assessment, assessErr := manager.AssessConnectionAdminCredential(ctx, currentCfg)
		if assessErr != nil {
			return failedAdminCredential(res, assessErr,
				fmt.Sprintf("assess current connection admin credential: %v", assessErr))
		}
		if !assessment.RotateSupported {
			return failedAdminCredential(res, adapter.ErrAdminCredentialRotationUnsupported,
				"connection admin credential rotation is no longer supported by the target")
		}
		if assessment.CanonicalIdentity != payload.ExpectedCanonicalIdentity ||
			assessment.AuthorityFingerprint != payload.ExpectedAuthorityFingerprint {
			return failedAdminCredential(res, adapter.ErrAdminCredentialAuthorityChanged,
				"connection admin identity or authority changed before target mutation")
		}
		if assessment.TargetIdentity == "" || assessment.TargetIdentity != payload.ExpectedTargetIdentity {
			return failedAdminCredential(res, adapter.ErrTargetIdentityConflict,
				"connection admin target identity changed before target mutation")
		}
		rotation, rotateErr := manager.RotateConnectionAdminCredential(ctx, currentCfg, candidate,
			adapter.AdminCredentialProof{
				CanonicalIdentity:    payload.ExpectedCanonicalIdentity,
				AuthorityFingerprint: payload.ExpectedAuthorityFingerprint,
				TargetIdentity:       payload.ExpectedTargetIdentity,
			})
		if rotateErr != nil {
			return failedAdminCredential(res, rotateErr,
				fmt.Sprintf("rotate connection admin credential: %v", rotateErr))
		}
		proof = rotation.Proof
		alreadyApplied = rotation.AlreadyApplied
	default:
		// ParseAdminCredentialPayload already rejects this branch. Retain the
		// closed switch for defense against future enum changes.
		return failed(res, fmt.Sprintf("admin credential mode %q is unsupported", payload.Mode))
	}
	if proof.CanonicalIdentity == "" || proof.AuthorityFingerprint == "" {
		return failed(res, "connection admin credential proof is incomplete")
	}
	snapshot, err := ad.Discover(ctx, candidateCfg)
	if err != nil {
		return failed(res, fmt.Sprintf("discover with staged connection admin credential: %v", err))
	}
	if snapshot == nil {
		return failed(res, "discover with staged connection admin credential returned no snapshot")
	}
	outcome, err := connector.AdminCredentialOutcome{
		Mode: payload.Mode, Epoch: payload.Epoch,
		CandidateUsername:  payload.CandidateUsername,
		CandidateAuthMode:  payload.CandidateAuthMode,
		StagedVaultVersion: creds.AccountVaultVersion,
		Proof:              proof,
		AlreadyApplied:     alreadyApplied,
		Snapshot:           snapshot,
	}.Marshal()
	if err != nil {
		return failed(res, err.Error())
	}
	res.Status = connector.JobSuccess
	res.Result = outcome
	a.log.Info("agent: connection admin credential operation completed",
		"job_id", job.ID, "mode", payload.Mode, "epoch", payload.Epoch,
		"staged_vault_version", creds.AccountVaultVersion)
	return res
}

// target строит adapter и adapter.Connection из секрет-free descriptor
// payload и admin credential кадра credentials (ADR-0014: Vault-чтений на
// стороне connector нет). nil admin — подключение без admin credential
// (пустой vault_admin_path), как и в direct-пути. engine из Job приоритетен;
// пустой — из ConnectionRef.
func (a *Agent) target(engine string, ref connector.ConnectionRef, tlsRef connector.TLSRef,
	attrs map[string]any, admin *connector.FrameCredential,
	adminCredentialIncarnation int,
) (adapter.Adapter, adapter.Connection, error) {
	if engine == "" {
		engine = ref.Engine
	}
	var ad adapter.Adapter
	var err error
	if ref.NetworkGuard == "" {
		ad, err = a.newAdapter(engine)
	} else {
		if ref.NetworkGuard != netguard.PrivateKubernetesDNSV1 ||
			!configuredCapability(a.cfg.Capabilities, connector.CapPrivateKubernetesDNSV1) ||
			a.cfg.NewAdapterWithDialer == nil ||
			netguard.KubernetesDNSNetworkGuard("connector", tlsRef.Mode, ref.Endpoints) != ref.NetworkGuard {
			return nil, adapter.Connection{}, errors.New("connector: invalid or unsupported network guard profile")
		}
		base := a.cfg.TargetDialContext
		if base == nil {
			base = adapterutil.DefaultDialContext
		}
		dialer := netguard.NewGuardedDialerWithDial(netguard.Policy{PrivateKubernetesDNS: true}, a.cfg.TargetResolver,
			netguard.DialContextFunc(base))
		ad, err = a.cfg.NewAdapterWithDialer(engine, dialer.DialContext)
	}
	if err != nil {
		return nil, adapter.Connection{}, fmt.Errorf("resolve adapter for engine %q: %w", engine, err)
	}
	cfg := adapter.Connection{
		ID:                         ref.ID,
		Engine:                     engine,
		AuthMode:                   ref.AuthMode,
		Endpoints:                  ref.Endpoints,
		ConfigIncarnation:          ref.ConfigIncarnation,
		AdminCredentialIncarnation: adminCredentialIncarnation,
		TLS: adapter.TLSConfig{
			Mode:               tlsRef.Mode,
			CACertPEM:          tlsRef.CACertPEM,
			ClientCertPEM:      tlsRef.ClientCertPEM,
			InsecureSkipVerify: tlsRef.InsecureSkipVerify,
		},
		Attributes: attrs,
	}
	if ref.AuthMode == "none" {
		if engine != "redis" || admin != nil {
			return nil, adapter.Connection{}, errors.New("connector: invalid no-auth credential frame")
		}
		cfg.AdminCredential = adapter.Credential{Kind: "none", Username: "default"}
	}
	if admin != nil {
		cfg.AdminCredential = admin.Credential()
	}
	return ad, cfg, nil
}

// mutationChange разбирает MutationPayload и собирает adapter.DesiredChange
// для plan/apply/verify: connection с admin credential из кадра credentials
// и, если кадр несёт credential учётной записи (account.create), сам этот
// credential.
func (a *Agent) mutationChange(job connector.Job, creds connector.CredentialsFrame) (adapter.Adapter, adapter.DesiredChange, error) {
	payload, changeKind, err := parseMutationForRouting(job)
	if err != nil {
		return nil, adapter.DesiredChange{}, err
	}
	ad, cfg, err := a.target(job.Engine, payload.Connection, payload.TLS, payload.Attributes,
		creds.Admin, creds.AdminCredentialIncarnation)
	if err != nil {
		return nil, adapter.DesiredChange{}, err
	}
	if adapter.IsPostgresSuperuserDirectChange(changeKind) {
		if cfg.AdminCredentialIncarnation <= 0 || creds.Admin == nil {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: PostgreSQL SUPERUSER-direct v1 requires an exact admin credential incarnation")
		}
		if !ad.Manifest().HasCapability(adapter.CapPostgresSuperuserDirectV1) {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: PostgreSQL SUPERUSER-direct v1 is unsupported: %w", adapter.ErrUnsupportedChange)
		}
	}
	if adapter.IsPostgresStatsMembershipChange(changeKind) {
		pins := payload.Change.StatsMembership
		if !ad.Manifest().HasCapability(adapter.CapPostgresStatsMembershipV1) {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: PostgreSQL statistics membership v1 is unsupported: %w", adapter.ErrUnsupportedChange)
		}
		if creds.AdminCredentialIncarnation != pins.CredentialIncarnation || creds.Admin.Username != pins.AdminIdentity {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: PostgreSQL statistics admin credential does not match its pins: %w", adapter.ErrTargetIdentityConflict)
		}
		if creds.Account != nil || creds.AccountVaultVersion != 0 {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: statistics membership does not accept an account credential")
		}
	}
	if adapter.IsPostgresObjectACLChange(changeKind) {
		pins := payload.Change.ObjectACL
		if !ad.Manifest().HasCapability(adapter.CapPostgresObjectACLV1) || creds.Admin == nil ||
			creds.AdminCredentialIncarnation != pins.CredentialIncarnation || creds.Admin.Username != pins.AdminIdentity ||
			creds.Account != nil || creds.AccountVaultVersion != 0 {
			return nil, adapter.DesiredChange{}, adapter.ErrPostgresObjectACL
		}
	}
	if changeKind == adapter.ChangePostgresAccountCreateV2 &&
		!ad.Manifest().HasCapability(adapter.CapAccountCreate) {
		return nil, adapter.DesiredChange{}, fmt.Errorf("connector: postgres.account.create.v2 is unsupported: %w", adapter.ErrUnsupportedChange)
	}
	if changeKind == adapter.ChangePostgresAccountRestoreV2 &&
		!ad.Manifest().HasCapability(adapter.CapAccountRestore) {
		return nil, adapter.DesiredChange{}, fmt.Errorf("connector: postgres.account.restore.v2 is unsupported: %w", adapter.ErrUnsupportedChange)
	}
	if (changeKind == adapter.ChangePostgresRolePolicyApplyV2 ||
		changeKind == adapter.ChangePostgresRolePolicyVerifyV2 ||
		changeKind == adapter.ChangePostgresRolePolicyAdoptV2 ||
		changeKind == adapter.ChangePostgresRolePolicyRepairV2) &&
		!ad.Manifest().HasCapability(adapter.CapRolePolicyApply) {
		return nil, adapter.DesiredChange{}, fmt.Errorf("connector: PostgreSQL v2 role policy is unsupported: %w", adapter.ErrUnsupportedChange)
	}
	if changeKind == adapter.ChangeRoleCreate || changeKind == adapter.ChangePostgresRoleCreateV2 {
		if !ad.Manifest().HasCapability(adapter.CapRoleCreate) {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: role.create is unsupported: %w", adapter.ErrUnsupportedChange)
		}
		// A NOLOGIN role never has a credential. Reject a mismatched frame
		// before Plan rather than silently passing a password to the adapter.
		if creds.Account != nil || creds.AccountVaultVersion != 0 {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: role.create does not accept an account credential")
		}
	}
	if (changeKind == adapter.ChangeRolePolicyCreate || changeKind == adapter.ChangeRolePolicyCreateDatabase ||
		changeKind == adapter.ChangePostgresRolePolicyCreateV2 || changeKind == adapter.ChangePostgresRolePolicyCreateDatabaseV2) &&
		(cfg.Engine != "postgres" || !ad.Manifest().HasCapability(adapter.CapRolePolicyCreate)) {
		return nil, adapter.DesiredChange{}, fmt.Errorf("connector: role.policy.create is unsupported: %w", adapter.ErrUnsupportedChange)
	}
	if changeKind == adapter.ChangeResourceCreate || changeKind == adapter.ChangePostgresDatabaseCreateV2 {
		if cfg.Engine != "postgres" || !ad.Manifest().HasCapability(adapter.ResourceCapability("create", "database")) {
			return nil, adapter.DesiredChange{}, fmt.Errorf("connector: resource.create.database is unsupported: %w", adapter.ErrUnsupportedChange)
		}
	}
	if (changeKind == adapter.ChangeResourceCreate || changeKind == adapter.ChangeRolePolicyCreateDatabase ||
		changeKind == adapter.ChangePostgresDatabaseCreateV2 || changeKind == adapter.ChangePostgresRolePolicyCreateDatabaseV2) &&
		(creds.Account != nil || creds.AccountVaultVersion != 0) {
		return nil, adapter.DesiredChange{}, fmt.Errorf("connector: database lifecycle does not accept an account credential")
	}
	change := adapter.DesiredChange{
		Kind:                     changeKind,
		Connection:               cfg,
		Account:                  adapterAccount(payload.Change.Account),
		Permission:               payload.Change.Permission,
		Scope:                    payload.Change.Scope,
		AccountPermissions:       payload.Change.AccountPermissions,
		Attributes:               payload.Change.Attributes,
		RolePolicySpec:           payload.Change.RolePolicySpec,
		StatsMembership:          payload.Change.StatsMembership,
		ObjectACL:                payload.Change.ObjectACL,
		ExpectedAdminIdentity:    payload.Change.ExpectedAdminIdentity,
		ExpectedTargetIdentity:   payload.Change.ExpectedTargetIdentity,
		ExpectedDatabaseOID:      payload.Change.ExpectedDatabaseOID,
		ExpectedDatabaseOwner:    payload.Change.ExpectedDatabaseOwner,
		ExpectedDatabaseOwnerOID: payload.Change.ExpectedDatabaseOwnerOID,
		Resource:                 payload.Change.Resource,
	}
	if creds.Account != nil {
		cred := creds.Account.Credential()
		if cred.Username == "" {
			cred.Username = payload.Change.Account.EngineIdentity
		}
		change.Credential = &cred
	}
	return ad, change, nil
}

func parseMutationForRouting(job connector.Job) (connector.MutationPayload, adapter.ChangeKind, error) {
	payload, err := connector.ParseMutationPayload(job.Payload)
	if err != nil {
		return connector.MutationPayload{}, "", err
	}
	if job.ConnectionID != payload.Connection.ID {
		return connector.MutationPayload{}, "", errors.New("connector: signed job connection does not match mutation payload connection")
	}
	if job.Engine != payload.Connection.Engine {
		return connector.MutationPayload{}, "", errors.New("connector: signed job engine does not match mutation payload engine")
	}
	changeKind := adapter.ChangeKind(payload.Change.Kind)
	if payload.Connection.Engine == "postgres" && adapter.IsLegacyPostgresCreationChange(changeKind) {
		return connector.MutationPayload{}, "", fmt.Errorf(
			"connector: legacy PostgreSQL change kind %q is history-only", changeKind)
	}
	return payload, changeKind, nil
}

// adapterAccount строит adapter.Account из секрет-free ссылки задания.
func adapterAccount(ref connector.AccountRef) adapter.Account {
	return adapter.Account{
		Kind:                ref.Kind,
		EngineIdentity:      ref.EngineIdentity,
		AuthenticationScope: ref.AuthenticationScope,
	}
}

// clearChangeSecret зануляет секрет credential изменения (если он был
// прочитан из Vault) после исполнения задания.
func clearChangeSecret(change *adapter.DesiredChange) {
	if change.Credential != nil {
		clear(change.Credential.Secret)
	}
}

// failed заполняет JobResult статусом failed и очищенным сообщением об ошибке
// (тексты ошибок adapter/vault по контракту не содержат секретов, раздел 24).
// Уже накопленные sanitized-артефакты (Plan/Result) сохраняются — как и при
// прямом исполнении, план падения виден в операции.
func failed(res connector.JobResult, msg string) connector.JobResult {
	res.Status = connector.JobFailed
	res.Error = msg
	return res
}

func failedAdminCredential(res connector.JobResult, err error, msg string) connector.JobResult {
	res = failed(res, msg)
	switch {
	case errors.Is(err, adapter.ErrAdminCredentialRejected):
		res.ErrorCode = "invalid_candidate"
	case errors.Is(err, adapter.ErrAdminCredentialRotationUnsupported):
		res.ErrorCode = "rotation_unsupported"
	case errors.Is(err, adapter.ErrAdminCredentialAuthorityChanged):
		res.ErrorCode = "admin_authority_changed"
	case errors.Is(err, adapter.ErrAdminCredentialOldStillValid):
		res.ErrorCode = "old_credential_still_valid"
	case errors.Is(err, adapter.ErrTargetIdentityConflict):
		res.ErrorCode = "target_identity_changed"
	}
	return res
}
