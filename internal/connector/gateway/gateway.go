// Package gateway реализует runtime стороны control plane для execution
// connector (этапы 1c и 3, ADR-0002/ADR-0006, docs/architecture.md разделы
// 4.3, 24, 27.1).
//
// Gateway терминирует исходящее mTLS-соединение connector, проверяет его
// клиентский сертификат (mTLS identity) на TLS-уровне, выполняет handshake с
// version negotiation (Hello -> HelloAck; несовпадение ProtocolVersion —
// отказ), после чего выдаёт connector подписанные Envelope и принимает
// JobResult.
//
// Этап 3 — lease/heartbeat и параллельная выдача:
//
//   - задания мультиплексируются по одному соединению: результаты
//     сопоставляются с ожидающими Dispatch по JobID, одновременно in-flight
//     не более MaxInFlight заданий; advisory lock control plane остаётся
//     durable-границей, а agent независимо сериализует target execution одного
//     ConnectionID для fencing при потерянном ответе;
//   - liveness: connector шлёт heartbeat-кадры TypePing; каждый входящий кадр
//     обновляет last-seen. Молчание дольше LivenessWindow снимает сессию —
//     все in-flight Dispatch завершаются retryable-ошибкой, как при
//     недоступном target;
//   - lease: каждый Dispatch ограничен дедлайном (контекст вызывающего либо
//     IOTimeout), и тот же дедлайн подписывается в Job до отправки. Истечение
//     lease после записи fencing'ит всю wire-сессию: reconnect агента возможен
//     только после отмены и завершения старых target-вызовов. Повтор с тем же
//     IdempotencyKey безопасен: durable dedup (успешные результаты) плюс
//     идемпотентность Apply adapter гарантируют отсутствие двойного эффекта.
//
// Дедупликация по IdempotencyKey/Nonce гарантирует, что повторно доставленное
// задание не исполняется дважды (раздел 24, R5). Модель доверия сохранена:
// секреты в подписанном задании не передаются; gateway подписывает задания
// (Ed25519 в production, HMAC в dev), а credentials целевой системы,
// заранее прочитанные worker'ом из Vault, доставляет connector'у отдельным
// кадром TypeCredentials сразу после кадра задания (ADR-0014: connector к
// Vault доступа не имеет). Кадр credentials существует только в памяти и
// mTLS-канале: он не логируется и не попадает в dedup store — тот принимает
// исключительно JobResult.
package gateway

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/connector/wire"
)

// defaultIOTimeout — предел на один обмен «выдать задание — получить
// результат», если у контекста Dispatch нет своего дедлайна.
const defaultIOTimeout = 60 * time.Second

// defaultLivenessWindow — максимум молчания connector до признания его
// умершим. Должен с запасом превышать heartbeat-интервал агента (default 10s).
const defaultLivenessWindow = 45 * time.Second

// defaultMaxInFlight — предел одновременных in-flight заданий на connector.
const defaultMaxInFlight = 8

var (
	// ErrNoConnector возвращается из Dispatch, когда ни один connector не
	// подключён к gateway.
	ErrNoConnector = errors.New("gateway: no connector connected")
	// ErrClosed возвращается после Close.
	ErrClosed = errors.New("gateway: server closed")
	// ErrConnectorGone возвращается ожидающим Dispatch, когда соединение
	// connector разорвано (или он замолчал дольше liveness-окна) до получения
	// результата. Ошибка retryable: та же семантика, что и недоступный target
	// — операция уходит в retry, ложного успеха и ложного удаления нет.
	ErrConnectorGone = errors.New("gateway: connector disconnected before returning result")
	// ErrLeaseExpired возвращается из Dispatch, когда дедлайн задания истёк
	// до получения результата от connector. Retryable (см. ErrConnectorGone).
	ErrLeaseExpired = errors.New("gateway: job lease expired before result")
	// ErrCapabilityUnavailable is returned before wire delivery when the
	// selected active Hello lacks a versioned contract required by the job.
	ErrCapabilityUnavailable = errors.New("gateway: active connector capability is unavailable")
)

// Config — конфигурация gateway.
type Config struct {
	// TLS — серверный tls.Config с обязательной верификацией клиентского
	// сертификата (см. wire.ServerTLSConfig). Обязателен.
	TLS *tls.Config
	// Signer подписывает задания перед выдачей connector. Обязателен.
	Signer connector.Signer
	// Logger — логгер; nil заменяется на slog.Default().
	Logger *slog.Logger
	// IOTimeout — дефолтный lease одного задания (когда у контекста Dispatch
	// нет своего дедлайна) и предел записи кадра; <=0 — defaultIOTimeout.
	IOTimeout time.Duration
	// LivenessWindow — максимум молчания connector (нет ни heartbeat, ни
	// результатов) до снятия сессии; <=0 — defaultLivenessWindow.
	LivenessWindow time.Duration
	// MaxInFlight — предел одновременных in-flight заданий на connector;
	// <=0 — defaultMaxInFlight.
	MaxInFlight int
	// QuiescenceTimeout — crash-recovery quarantine без session token.
	// <=0 наследует IOTimeout: раньше максимального signed job deadline новый
	// Agent допускать нельзя. Уменьшать можно только там, где смерть старого
	// процесса доказана внешним supervisor-ом.
	QuiescenceTimeout time.Duration
	// SessionObserver — необязательный приёмник состояния сессий; nil
	// отключает наблюдение (standalone-режим без metadata database).
	SessionObserver SessionObserver
	// Dedup — store дедупликации завершённых заданий. Nil заменяется
	// in-memory реализацией (standalone без metadata DB); worker,
	// встраивающий gateway, передаёт durable store поверх таблицы
	// connector_job_dedup (internal/core/connectorjobs), переживающий
	// рестарт процесса.
	Dedup DedupStore
}

// Server — gateway execution connector.
type Server struct {
	tlsCfg      *tls.Config
	signer      connector.Signer
	log         *slog.Logger
	ioTimeout   time.Duration
	liveness    time.Duration
	maxInFlight int
	quiescence  time.Duration

	observer SessionObserver

	mu              sync.Mutex
	sess            *session
	readyCh         chan struct{}
	closed          bool
	fencedSessionID string
	fencedUntil     time.Time

	dedup DedupStore
}

// SessionState — наблюдаемое состояние connector'а для control plane.
// Секретов не содержит: identity из CN сертификата, его срок и время
// последнего кадра.
type SessionState struct {
	ConnectorID         string
	ConnectedAt         time.Time
	LastSeenAt          time.Time
	CertificateNotAfter time.Time
	Capabilities        []connector.Capability
	ProtocolVersion     string
	// Deployment — самообъявление агента о среде развёртывания; пусто, если
	// он его не прислал (агенты прошлых версий).
	Deployment string
}

// SessionObserver получает состояние сессии при подключении и по мере
// heartbeat'ов. Реализация живёт вне транспорта (worker пишет в metadata
// database), чтобы gateway не зависел от хранилища.
type SessionObserver interface {
	ObserveSession(state SessionState)
}

// sessionObserveInterval — как часто heartbeat доходит до наблюдателя.
// Агент шлёт ping каждые ~10 с; писать в базу с той же частотой незачем,
// а вот отставание last-seen на полминуты ни на что не влияет.
const sessionObserveInterval = 30 * time.Second

// dispatchOutcome — результат одного ожидающего Dispatch: JobResult от
// connector либо ошибка транспорта/liveness.
type dispatchOutcome struct {
	res connector.JobResult
	err error
}

// session — одно подключение connector. Задания мультиплексируются: writeMu
// сериализует запись кадров, pending сопоставляет результаты с ожидающими
// Dispatch по JobID, inflight ограничивает параллелизм, lastSeen питает
// liveness-контроль (обновляется каждым входящим кадром, включая TypePing).
type session struct {
	id       string
	conn     net.Conn
	hello    connector.Hello
	identity string
	// Наблюдаемое состояние: момент handshake и срок клиентского
	// сертификата — единственный источник предупреждения об истечении.
	connectedAt  time.Time
	certNotAfter time.Time
	lastObserved time.Time

	writeMu  sync.Mutex
	inflight chan struct{}

	mu       sync.Mutex
	pending  map[string]chan dispatchOutcome
	dead     bool
	lastSeen time.Time
}

// touch отмечает активность connector (входящий кадр).
func (s *session) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// observe отдаёт состояние сессии наблюдателю, не чаще одного раза в
// sessionObserveInterval: heartbeat идёт каждые ~10 с, и писать в
// хранилище с той же частотой незачем.
func (srv *Server) observe(sess *session, now time.Time) {
	if srv.observer == nil {
		return
	}
	sess.mu.Lock()
	if !sess.lastObserved.IsZero() && now.Sub(sess.lastObserved) < sessionObserveInterval {
		sess.mu.Unlock()
		return
	}
	sess.lastObserved = now
	state := SessionState{
		ConnectorID:         sess.identity,
		ConnectedAt:         sess.connectedAt,
		LastSeenAt:          sess.lastSeen,
		CertificateNotAfter: sess.certNotAfter,
		Capabilities:        append([]connector.Capability(nil), sess.hello.Capabilities...),
		ProtocolVersion:     sess.hello.ProtocolVersion,
		Deployment:          connector.NormalizeDeployment(sess.hello.Deployment),
	}
	sess.mu.Unlock()
	srv.observer.ObserveSession(state)
}

// seen возвращает момент последнего входящего кадра.
func (s *session) seen() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeen
}

// register регистрирует ожидание результата задания id. Ошибка — сессия уже
// мертва либо задание с тем же id уже in-flight (защита от гонки повторной
// доставки, пока первая ещё исполняется).
func (s *session) register(id string) (chan dispatchOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead {
		return nil, ErrConnectorGone
	}
	if _, ok := s.pending[id]; ok {
		return nil, fmt.Errorf("gateway: job %s is already in flight", id)
	}
	ch := make(chan dispatchOutcome, 1)
	s.pending[id] = ch
	return ch, nil
}

// deregister снимает ожидание результата задания id (lease истёк или контекст
// отменён). Поздний результат от connector будет проигнорирован с warn-логом.
func (s *session) deregister(id string) {
	s.mu.Lock()
	delete(s.pending, id)
	s.mu.Unlock()
}

// deliver доставляет результат ожидающему Dispatch. false — никто не ждёт
// (lease уже истёк либо job id неизвестен).
func (s *session) deliver(res connector.JobResult) bool {
	s.mu.Lock()
	ch, ok := s.pending[res.JobID]
	if ok {
		delete(s.pending, res.JobID)
	}
	s.mu.Unlock()
	if ok {
		ch <- dispatchOutcome{res: res}
	}
	return ok
}

// fail завершает все ожидающие Dispatch ошибкой err и помечает сессию
// мёртвой (новые register отклоняются).
func (s *session) fail(err error) {
	s.mu.Lock()
	pending := s.pending
	s.pending = map[string]chan dispatchOutcome{}
	s.dead = true
	s.mu.Unlock()
	for _, ch := range pending {
		ch <- dispatchOutcome{err: err}
	}
}

func (s *session) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) > 0
}

// New создаёт gateway. TLS и Signer обязательны.
func New(cfg Config) (*Server, error) {
	if cfg.TLS == nil {
		return nil, errors.New("gateway: TLS config is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("gateway: signer is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	ioTimeout := cfg.IOTimeout
	if ioTimeout <= 0 {
		ioTimeout = defaultIOTimeout
	}
	liveness := cfg.LivenessWindow
	if liveness <= 0 {
		liveness = defaultLivenessWindow
	}
	maxInFlight := cfg.MaxInFlight
	if maxInFlight <= 0 {
		maxInFlight = defaultMaxInFlight
	}
	quiescence := cfg.QuiescenceTimeout
	if quiescence <= 0 {
		quiescence = ioTimeout
	}
	dedup := cfg.Dedup
	if dedup == nil {
		dedup = newMemoryDedup()
	}
	return &Server{
		tlsCfg:      cfg.TLS,
		signer:      cfg.Signer,
		log:         log,
		ioTimeout:   ioTimeout,
		liveness:    liveness,
		maxInFlight: maxInFlight,
		quiescence:  quiescence,
		readyCh:     make(chan struct{}),
		observer:    cfg.SessionObserver,
		dedup:       dedup,
	}, nil
}

// Serve оборачивает listener в TLS и принимает подключения connector, выполняя
// для каждого handshake. Возвращает управление, когда listener закрыт.
func (s *Server) Serve(ln net.Listener) error {
	tlsLn := tls.NewListener(ln, s.tlsCfg)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			if s.isClosed() {
				return nil
			}
			return fmt.Errorf("gateway: accept: %w", err)
		}
		go s.handleConn(conn)
	}
}

// handleConn выполняет TLS- и протокольный handshake нового connector и, при
// успехе, регистрирует его как текущую сессию и запускает цикл чтения
// (результаты + heartbeat). Ошибки handshake логируются, и соединение
// закрывается — они не роняют Serve.
func (s *Server) handleConn(conn net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		s.log.Error("gateway: non-tls connection rejected")
		_ = conn.Close()
		return
	}
	// Явный handshake, чтобы получить идентичность пира и отсечь плохой
	// клиентский сертификат до обмена данными.
	_ = tlsConn.SetDeadline(time.Now().Add(s.ioTimeout))
	if err := tlsConn.Handshake(); err != nil {
		s.log.Warn("gateway: tls handshake failed", "error", err)
		_ = tlsConn.Close()
		return
	}
	identity := wire.PeerCommonName(tlsConn.ConnectionState())

	hello, err := s.readHello(tlsConn)
	if err != nil {
		s.log.Warn("gateway: connector handshake failed", "identity", identity, "error", err)
		_ = tlsConn.Close()
		return
	}
	// Version negotiation: несовпадение версии — отказ до любого задания.
	if hello.ProtocolVersion != connector.ProtocolVersion {
		reason := fmt.Sprintf("unsupported protocol version %q, want %q",
			hello.ProtocolVersion, connector.ProtocolVersion)
		_ = wire.WriteJSON(tlsConn, wire.TypeError, wire.ErrorFrame{Reason: reason})
		s.log.Warn("gateway: rejected connector on version mismatch",
			"identity", identity, "connector_version", hello.ProtocolVersion,
			"gateway_version", connector.ProtocolVersion)
		_ = tlsConn.Close()
		return
	}

	now := time.Now()
	sess := &session{
		id:           uuid.NewString(),
		conn:         tlsConn,
		hello:        hello,
		identity:     identity,
		connectedAt:  now,
		certNotAfter: wire.PeerCertificateNotAfter(tlsConn.ConnectionState()),
		inflight:     make(chan struct{}, s.maxInFlight),
		pending:      map[string]chan dispatchOutcome{},
		lastSeen:     now,
	}
	if err := s.acceptSession(sess); err != nil {
		_ = wire.WriteJSON(tlsConn, wire.TypeError, wire.ErrorFrame{Reason: err.Error()})
		s.log.Warn("gateway: connector session rejected", "identity", identity,
			"connector_id", hello.ConnectorID, "error", err)
		_ = tlsConn.Close()
		return
	}
	// После handshake дедлайны выставляет цикл чтения (liveness) и запись
	// кадров (ioTimeout) — общий дедлайн соединения снимается.
	_ = tlsConn.SetDeadline(time.Time{})
	s.observe(sess, now)
	s.log.Info("gateway: connector connected",
		"identity", identity, "connector_id", hello.ConnectorID,
		"capabilities", len(hello.Capabilities))
	go s.readLoop(sess)
}

// readLoop читает кадры сессии: результаты заданий раздаются ожидающим
// Dispatch по JobID, heartbeat (TypePing) лишь обновляет last-seen, прочие
// кадры игнорируются (совместимость расширений v1). Дедлайн чтения — liveness:
// молчание connector дольше LivenessWindow завершает цикл, сессия снимается,
// все in-flight Dispatch получают retryable-ошибку ErrConnectorGone.
func (s *Server) readLoop(sess *session) {
	defer func() {
		if sess.hasPending() {
			s.markFenced(sess)
		}
		sess.fail(ErrConnectorGone)
		s.dropSession(sess)
	}()
	for {
		if err := sess.conn.SetReadDeadline(time.Now().Add(s.liveness)); err != nil {
			return
		}
		typ, payload, err := wire.ReadFrame(sess.conn)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				s.log.Warn("gateway: connector liveness window expired",
					"identity", sess.identity, "connector_id", sess.hello.ConnectorID,
					"liveness_window", s.liveness, "last_seen", sess.seen())
			} else {
				s.log.Info("gateway: connector connection closed",
					"identity", sess.identity, "connector_id", sess.hello.ConnectorID,
					"error", err)
			}
			return
		}
		sess.touch()
		s.observe(sess, time.Now())
		switch typ {
		case wire.TypeResult:
			var res connector.JobResult
			if err := json.Unmarshal(payload, &res); err != nil {
				s.log.Warn("gateway: malformed result frame ignored", "error", err)
				continue
			}
			if !sess.deliver(res) {
				s.log.Warn("gateway: result for unknown or expired job ignored",
					"job_id", res.JobID)
			}
		case wire.TypePing:
			// Heartbeat: только отметка живости (touch выше).
		default:
			s.log.Warn("gateway: unexpected frame type ignored", "type", typ.String())
		}
	}
}

// readHello читает и разбирает кадр Hello с дедлайном handshake.
func (s *Server) readHello(conn net.Conn) (connector.Hello, error) {
	var hello connector.Hello
	if err := wire.ReadJSON(conn, wire.TypeHello, &hello); err != nil {
		return connector.Hello{}, err
	}
	if hello.ConnectorID == "" {
		return connector.Hello{}, errors.New("hello: empty connector id")
	}
	return hello, nil
}

// acceptSession атомарно проверяет межсессионный quiescence fence, пишет ACK
// с новым session id и только затем публикует сессию для Dispatch. Новая
// replica не может вытеснить живую: rollout обязан дождаться отключения старой.
func (s *Server) acceptSession(sess *session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if s.sess != nil {
		return errors.New("another connector session is still active")
	}
	if s.fencedSessionID != "" {
		switch {
		case sess.hello.QuiescedSessionID == s.fencedSessionID:
			s.fencedSessionID = ""
			s.fencedUntil = time.Time{}
		case time.Now().Before(s.fencedUntil):
			// Session id is a bearer proof and must not leak through TypeError or
			// logs to the unproven replacement client.
			return errors.New("previous connector session has not confirmed quiescence")
		default:
			// Crash recovery for an agent process that can no longer acknowledge
			// its token. IOTimeout is the signed target context bound.
			s.fencedSessionID = ""
			s.fencedUntil = time.Time{}
		}
	}
	if err := wire.WriteJSON(sess.conn, wire.TypeHelloAck, wire.HelloAck{
		ProtocolVersion: connector.ProtocolVersion,
		SessionID:       sess.id,
	}); err != nil {
		return fmt.Errorf("write hello ack: %w", err)
	}
	s.sess = sess
	close(s.readyCh)
	s.readyCh = make(chan struct{})
	return nil
}

// dropSession снимает сессию sess, если она ещё текущая, и закрывает её
// соединение.
func (s *Server) dropSession(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == sess {
		s.sess = nil
	}
	_ = sess.conn.Close()
}

// currentSession возвращает активную сессию или nil.
func (s *Server) currentSession() *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess
}

func (s *Server) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// WaitReady блокирует, пока не подключится connector, либо пока не истечёт
// контекст. Удобно для тестов и последовательности старта.
func (s *Server) WaitReady(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return ErrClosed
		}
		if s.sess != nil {
			s.mu.Unlock()
			return nil
		}
		ch := s.readyCh
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		}
	}
}

// ConnectedConnector возвращает id и идентичность подключённого connector.
func (s *Server) ConnectedConnector() (id, identity string, ok bool) {
	sess := s.currentSession()
	if sess == nil {
		return "", "", false
	}
	return sess.hello.ConnectorID, sess.identity, true
}

// ConnectorAlive сообщает, подключён ли connector и укладывается ли его
// последняя активность (heartbeat или результат) в liveness-окно. Используется
// для health/наблюдаемости; для Dispatch источник истины — сама сессия.
func (s *Server) ConnectorAlive() bool {
	sess := s.currentSession()
	if sess == nil {
		return false
	}
	return time.Since(sess.seen()) <= s.liveness
}

// ActiveConnectorSupports is the orchestration preflight. Dispatch repeats
// the same check against its exact selected session before writing either the
// signed job or credentials frame, closing reconnect races.
func (s *Server) ActiveConnectorSupports(want connector.Capability) bool {
	sess := s.currentSession()
	return sess != nil && time.Since(sess.seen()) <= s.liveness && sessionSupports(sess, want)
}

func sessionSupports(sess *session, want connector.Capability) bool {
	for _, capability := range sess.hello.Capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

func requiredSessionCapability(job connector.Job) (connector.Capability, bool, error) {
	switch job.Kind {
	case connector.JobAccountCreation:
		if _, err := connector.ParseAccountCreationPayload(job.Payload); err != nil {
			return "", false, err
		}
		return adapter.CapPostgresAccountCreationV1, true, nil
	case connector.JobProveCredential:
		return connector.CapCredentialProofV1, true, nil
	case connector.JobPlan, connector.JobApply, connector.JobVerify:
		payload, err := connector.ParseMutationPayload(job.Payload)
		if err != nil {
			return "", false, fmt.Errorf("gateway: inspect mutation capability: %w", err)
		}
		if adapter.IsPostgresStatsMembershipChange(adapter.ChangeKind(payload.Change.Kind)) {
			return adapter.CapPostgresStatsMembershipV1, true, nil
		}
		if adapter.IsPostgresObjectACLChange(adapter.ChangeKind(payload.Change.Kind)) {
			return adapter.CapPostgresObjectACLV1, true, nil
		}
		if adapter.IsPostgresSuperuserDirectChange(adapter.ChangeKind(payload.Change.Kind)) {
			return adapter.CapPostgresSuperuserDirectV1, true, nil
		}
	}
	return "", false, nil
}

// Dispatch подписывает задание, выдаёт его подключённому connector вместе с
// кадром credentials и возвращает результат. Секретный материал creds не
// логируется и не персистится: он уходит ТОЛЬКО кадром TypeCredentials в
// mTLS-канал (ADR-0014); зануление после возврата — обязанность вызывающего
// (worker). Дедупликация по IdempotencyKey/Nonce: повторный вызов с тем же
// ключом не исполняет задание второй раз — возвращается ранее полученный
// результат (раздел 24, R5), credentials при этом не отправляются вовсе.
// Источник заданий — operation engine (routing по
// connections.execution_mode, см. internal/jobs); прямой вызов остаётся для
// тестов.
//
// Политика кеширования: сохраняются только успешные результаты. Транспортные
// ошибки (err != nil) и failed/unknown-результаты не кешируются — иначе retry
// операции навсегда получал бы старую ошибку вместо нового исполнения.
func (s *Server) Dispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	key := dedupKey(job)
	if key != "" {
		res, ok, err := s.dedup.Lookup(ctx, key)
		if err != nil {
			// Ошибка store — отказ дедупликации, а не молчаливое повторное
			// исполнение: вызывающий повторит по своей retry-политике.
			return connector.JobResult{}, fmt.Errorf("gateway: dedup lookup: %w", err)
		}
		if ok {
			s.log.Info("gateway: duplicate job ignored, returning cached result",
				"job_id", job.ID, "dedup_key", key)
			return res, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", job.ID, err)
	}

	// Job.Deadline — часть подписанного контракта, поэтому control plane
	// фиксирует в нём тот же effective lease, которым ограничено ожидание
	// Dispatch. Более ранний deadline вызывающего job не расширяется.
	lease := s.jobLease(ctx, job.Deadline)
	if !lease.After(time.Now()) {
		if err := ctx.Err(); err != nil {
			return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", job.ID, err)
		}
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", job.ID, ErrLeaseExpired)
	}
	job.Deadline = lease.Unix()

	env, err := connector.SignJob(s.signer, job)
	if err != nil {
		return connector.JobResult{}, fmt.Errorf("gateway: sign job: %w", err)
	}
	res, err := s.dispatchEnvelope(ctx, env, creds.Frame(job), lease)
	if err != nil {
		return connector.JobResult{}, err
	}
	if key != "" && res.Status == connector.JobSuccess {
		// Результат уже получен: ошибка записи в store не должна его
		// терять — логируем и отдаём результат (в худшем случае дубликат
		// исполнится ещё раз, что для идемпотентных заданий безопасно).
		if err := s.dedup.Store(ctx, key, res); err != nil {
			s.log.Warn("gateway: dedup store failed",
				"job_id", job.ID, "dedup_key", key, "error", err)
		}
	}
	return res, nil
}

// DispatchEnvelope выдаёт уже готовый Envelope connector без подписи и
// дедупликации и ждёт результат в пределах lease. Основной путь — Dispatch;
// прямой вызов нужен для сценариев, подающих намеренно некорректный Envelope
// (порча подписи, чужая версия). Кадр credentials отправляется пустым (с
// одной привязкой JobID/Nonce): протокол требует его после каждого задания.
func (s *Server) DispatchEnvelope(ctx context.Context, env connector.Envelope) (connector.JobResult, error) {
	return s.dispatchEnvelope(ctx, env, connector.JobCredentials{}.Frame(env.Job),
		s.jobLease(ctx, env.Job.Deadline))
}

// jobLease возвращает единый deadline транспорта и выполнения. IOTimeout и
// deadline ctx ограничивают каждый dispatch; уже заданный signed job deadline
// может только сделать lease короче. Unix-second contract консервативно
// округляет lease вниз при записи в Job, поэтому connector никогда не работает
// позже gateway lease.
func (s *Server) jobLease(ctx context.Context, jobDeadline int64) time.Time {
	lease := time.Now().Add(s.ioTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(lease) {
		lease = d
	}
	if jobDeadline > 0 {
		d := time.Unix(jobDeadline, 0)
		if d.Before(lease) {
			lease = d
		}
	}
	return lease
}

// dispatchEnvelope выдаёт Envelope и следом кадр credentials (оба кадра — под
// одним мьютексом записи, поэтому смежны в потоке) и ждёт результат в
// пределах lease. Кадр credentials не логируется и не сохраняется.
//
// Lease задания: дедлайн контекста вызывающего, но не дольше IOTimeout от
// текущего момента. По истечении lease ожидание снимается и возвращается
// retryable-ошибка (ErrLeaseExpired) — поздний результат игнорируется, а
// повтор с тем же IdempotencyKey безопасен (durable dedup + идемпотентный
// Apply).
func (s *Server) dispatchEnvelope(ctx context.Context, env connector.Envelope, creds connector.CredentialsFrame,
	lease time.Time) (connector.JobResult, error) {
	sess := s.currentSession()
	if sess == nil {
		return connector.JobResult{}, ErrNoConnector
	}
	noAuth, err := connector.JobUsesRedisNoAuth(env.Job)
	if err != nil {
		return connector.JobResult{}, err
	}
	if noAuth && !sessionSupports(sess, connector.CapRedisNoAuthV1) {
		return connector.JobResult{}, fmt.Errorf("gateway: Redis no-auth requires %s: %w", connector.CapRedisNoAuthV1, ErrCapabilityUnavailable)
	}
	guard, err := connector.JobNetworkGuard(env.Job)
	if err != nil {
		return connector.JobResult{}, err
	}
	if guard != "" && !sessionSupports(sess, connector.CapPrivateKubernetesDNSV1) {
		return connector.JobResult{}, fmt.Errorf("gateway: guarded target requires %s: %w",
			connector.CapPrivateKubernetesDNSV1, ErrCapabilityUnavailable)
	}
	required, needed, err := requiredSessionCapability(env.Job)
	if err != nil {
		return connector.JobResult{}, err
	}
	if needed && !sessionSupports(sess, required) {
		return connector.JobResult{}, fmt.Errorf("gateway: job %s requires %s: %w",
			env.Job.ID, required, ErrCapabilityUnavailable)
	}
	if (env.Job.Kind == connector.JobAccountCreation || required == adapter.CapPostgresStatsMembershipV1 || required == adapter.CapPostgresObjectACLV1) && !sessionSupports(sess, adapter.CapPostgresSuperuserDirectV1) {
		return connector.JobResult{}, fmt.Errorf("gateway: job %s requires %s: %w", env.Job.ID, adapter.CapPostgresSuperuserDirectV1, ErrCapabilityUnavailable)
	}
	if !lease.After(time.Now()) {
		if err := ctx.Err(); err != nil {
			return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", env.Job.ID, err)
		}
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ErrLeaseExpired)
	}

	// Ограничение параллелизма: не более maxInFlight заданий одновременно.
	inflightTimer := time.NewTimer(time.Until(lease))
	defer inflightTimer.Stop()
	select {
	case sess.inflight <- struct{}{}:
	case <-ctx.Done():
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", env.Job.ID, ctx.Err())
	case <-inflightTimer.C:
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ErrLeaseExpired)
	}
	defer func() { <-sess.inflight }()
	if err := ctx.Err(); err != nil {
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", env.Job.ID, err)
	}
	if !lease.After(time.Now()) {
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ErrLeaseExpired)
	}

	ch, err := sess.register(env.Job.ID)
	if err != nil {
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", env.Job.ID, err)
	}

	// Последняя pre-write проверка: отмена до отправки не требует fencing,
	// потому что target ещё не мог увидеть job. Отмена, возникшая после этой
	// точки, попадёт в post-write select либо в write error и закроет сессию.
	if err := ctx.Err(); err != nil {
		sess.deregister(env.Job.ID)
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w", env.Job.ID, err)
	}
	if !lease.After(time.Now()) {
		sess.deregister(env.Job.ID)
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ErrLeaseExpired)
	}
	if err := s.writeJob(sess, env, creds, lease); err != nil {
		sess.deregister(env.Job.ID)
		s.fenceSession(sess, env.Job.ID)
		// Ошибка записи в сессию означает, что connector фактически недоступен:
		// классифицируем как retryable ErrConnectorGone (гонка с разрывом может
		// проявиться и сырой сетевой ошибкой записи), исходная причина — в цепочке.
		return connector.JobResult{}, fmt.Errorf("gateway: dispatch job %s: %w: %w", env.Job.ID, ErrConnectorGone, err)
	}

	leaseTimer := time.NewTimer(time.Until(lease))
	defer leaseTimer.Stop()
	select {
	case out := <-ch:
		if out.err != nil {
			return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, out.err)
		}
		if out.res.JobID != env.Job.ID {
			return connector.JobResult{}, fmt.Errorf(
				"gateway: result job id %q does not match dispatched %q", out.res.JobID, env.Job.ID)
		}
		return out.res, nil
	case <-leaseTimer.C:
		// После записи job мог уже изменить target. Поздний старый job и
		// retry новой операции не должны выполняться параллельно: закрываем
		// всю сессию, agent отменит session context и дождётся in-flight jobs
		// перед reconnect.
		s.fenceSession(sess, env.Job.ID)
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ErrLeaseExpired)
	case <-ctx.Done():
		s.fenceSession(sess, env.Job.ID)
		return connector.JobResult{}, fmt.Errorf("gateway: job %s: %w", env.Job.ID, ctx.Err())
	}
}

// fenceSession завершает session после неопределённого исхода уже записанного
// job. Текущий waiter снимается, остальные получают ErrConnectorGone; закрытие
// socket заставляет agent отменить target contexts и установить quiescence
// barrier до следующего reconnect.
func (s *Server) fenceSession(sess *session, jobID string) {
	sess.deregister(jobID)
	s.markFenced(sess)
	sess.fail(ErrConnectorGone)
	s.dropSession(sess)
}

func (s *Server) markFenced(sess *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fencedSessionID == "" || s.fencedSessionID == sess.id {
		s.fencedSessionID = sess.id
		s.fencedUntil = time.Now().Add(s.quiescence)
	}
}

// writeJob пишет кадр задания и сразу за ним кадр credentials под одним
// мьютексом записи (кадры смежны в потоке — параллельный dispatch не может
// вклиниться между ними); запись сериализована и ограничена IOTimeout.
// Ошибки записи не содержат содержимого кадров — секретный материал в логи
// и тексты ошибок не попадает.
func (s *Server) writeJob(sess *session, env connector.Envelope, creds connector.CredentialsFrame,
	lease time.Time) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	if err := sess.conn.SetWriteDeadline(lease); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := wire.WriteJSON(sess.conn, wire.TypeJob, env); err != nil {
		return err
	}
	if err := wire.WriteJSON(sess.conn, wire.TypeCredentials, creds); err != nil {
		return fmt.Errorf("write credentials frame: %w", err)
	}
	return nil
}

// Close закрывает gateway и текущее соединение. Serve после этого завершится
// на закрытом listener (закрытие listener — обязанность вызывающего);
// in-flight Dispatch завершатся через readLoop закрытой сессии.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.sess != nil {
		_ = s.sess.conn.Close()
		s.sess = nil
	}
	return nil
}
