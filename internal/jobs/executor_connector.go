package jobs

// Routing операций по режиму исполнения подключения (этапы 2 и 3 execution
// connector; ADR-0002, ADR-0006, ADR-0014, docs/architecture.md разделы 4.3 и
// 27.1). Подключение с execution_mode='connector' живёт в изолированном
// сегменте: worker НЕ выполняет adapter напрямую, а строит типизированное
// подписанное задание (internal/connector) и диспетчеризует его через
// gateway; результат задания сводится в metadata тем же путём, что и при
// прямом исполнении (одинаковые статусы, audit, inventory и binding-статусы).
//
// С этапа 3 через connector исполняются ВСЕ виды операций executor:
// connection.discover (JobDiscover), access.grant/revoke и account.*
// (JobApply: полный поток plan -> apply -> verify на стороне connector) и
// credential.rotate (JobRotateCredential). Routing выполняется ВНУТРИ
// executor, после всех гейтов operation engine (approval, advisory lock,
// idempotency, state machine) — они одинаковы для обоих режимов.
//
// Инвариант секретов (ADR-0014): подписанное задание и результат секретов не
// несут, а connector доступа к Vault не имеет. Credentials резолвит WORKER:
// admin credential подключения и credential учётной записи читаются из Vault
// здесь же (теми же helpers, что у direct-пути) и доставляются connector'у
// отдельным кадром TypeCredentials поверх mTLS-сессии — кадр не персистится,
// не логируется и не попадает в durable dedup (тот принимает только
// JobResult). Новый пароль ротации control plane ПРЕДВАРИТЕЛЬНО записывает в
// Vault (worker — для per-account ротации, API-слой — для общего секрета
// принципала), после чего конкретное значение и номер версии уходят
// connector'у кадром credentials. Это зеркалит порядок direct-пути «Vault
// write -> target apply»: отказ target оставляет новую версию в Vault
// неактивированной, retry доводит target до неё, отказ Vault не трогает
// target.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/netguard"
)

// Типизированные ошибки routing connector-подключений. Проверяются через
// errors.Is; тексты уходят в operations.error и audit (секретов не содержат).
var (
	// ErrConnectorGatewayNotConfigured — операция адресует
	// connector-подключение, но встроенный gateway у этого worker не
	// сконфигурирован (GRANTOR_CONNECTOR_LISTEN пуст).
	ErrConnectorGatewayNotConfigured = errors.New(
		"connector gateway is not configured (set GRANTOR_CONNECTOR_LISTEN on the worker)")
	// ErrConnectorKindNotSupported — вид операции не исполняется через
	// connector. С этапа 3 все виды операций executor (discovery, access.*,
	// account.*, credential.rotate) поддержаны, поэтому ошибка остаётся
	// только защитой от НОВЫХ видов операций: неизвестный kind на
	// connector-подключении падает типизированно, а не исполняется молча
	// напрямую (fallback нарушил бы изоляцию сегмента).
	ErrConnectorKindNotSupported = errors.New(
		"operation kind is not supported over connector")
	ErrConnectorCapabilityUnavailable = errors.New(
		"active connector does not advertise the required capability")
)

// ConnectorDispatcher — минимальный контракт выдачи задания connector,
// которому удовлетворяет gateway.Server. Интерфейс объявлен локально, чтобы
// operation engine не зависел от пакета gateway (тот же приём, что VaultReader
// и connections.Querier). Секретный материал creds уходит только кадром
// TypeCredentials mTLS-сессии; реализация обязана не логировать и не
// сохранять его.
type ConnectorDispatcher interface {
	Dispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error)
}

type connectorCapabilityChecker interface {
	ActiveConnectorSupports(adapter.Capability) bool
}

func (e *MainExecutor) requireActiveConnectorCapability(capability adapter.Capability) error {
	checker, ok := e.conn.Dispatcher.(connectorCapabilityChecker)
	if !ok || !checker.ActiveConnectorSupports(capability) {
		return fmt.Errorf("%s: %w", capability, ErrConnectorCapabilityUnavailable)
	}
	return nil
}

// ConnectorDeps — зависимости исполнения операций через execution connector.
type ConnectorDeps struct {
	// Dispatcher — встроенный gateway worker. Nil означает, что gateway не
	// сконфигурирован: операции на connector-подключениях падают с
	// ErrConnectorGatewayNotConfigured.
	Dispatcher ConnectorDispatcher
}

// WithConnector добавляет executor зависимости connector-исполнения и
// возвращает его же (chained wiring в main, как WithMutations).
func (e *MainExecutor) WithConnector(deps ConnectorDeps) *MainExecutor {
	e.conn = deps
	return e
}

// connectorRoute решает, как исполнять операцию kind на подключении с режимом
// mode: (false, nil) — прямое исполнение adapter; (true, nil) — через
// connector; ошибка — операция на connector-подключении невозможна (gateway
// не сконфигурирован либо неизвестный вид операции). Чистая функция —
// тестируется без БД.
func connectorRoute(mode, kind string, gatewayConfigured bool) (viaConnector bool, err error) {
	if mode != connections.ExecutionModeConnector {
		return false, nil
	}
	switch kind {
	case KindConnectionDiscover, KindAccountRecoverProvisioning, KindAccountAdoptVerify, KindCredentialVerify,
		KindAccessGrant, KindAccessRevoke, KindAccessReplace,
		KindPostgresStatsGrantV1, KindPostgresStatsRevokeV1,
		KindPostgresObjectACLGrantV1, KindPostgresObjectACLRevokeV1,
		KindAccountCreate, KindAccountDisable, KindAccountEnable, KindAccountDelete, KindAccountRestore,
		KindRoleCreate, KindResourceCreateDatabase, KindDatabaseCreateWithRoles, KindResourceCreatePreparedDatabase,
		KindCredentialRotate, KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair, KindRolePolicyCreate, KindRolePolicyCreateDatabase,
		KindPostgresAccountCreateV2, KindPostgresAccountProvisionV1, KindPostgresAccountVerifyCreationV1, KindPostgresAccountRestoreV2, KindPostgresRoleCreateV2,
		KindPostgresResourceCreateDatabaseV2, KindPostgresDatabaseCreateWithRolesV2,
		KindPostgresResourceCreateDatabaseForRolesV2,
		KindPostgresRolePolicyApplyV2, KindPostgresRolePolicyAdoptV2,
		KindPostgresRolePolicyRepairV2, KindPostgresRolePolicyCreateV2,
		KindPostgresRolePolicyCreateDatabaseV2,
		KindConnectionAdminCredentialSwitch, KindConnectionAdminCredentialRotate:
		if !gatewayConfigured {
			return false, ErrConnectorGatewayNotConfigured
		}
		return true, nil
	default:
		// Явный отказ вместо fallback к прямому исполнению: изолированный
		// сегмент недостижим для worker по условию режима connector.
		return false, fmt.Errorf("%s: %w", kind, ErrConnectorKindNotSupported)
	}
}

// connectorJobBase заполняет общие поля задания: id и idempotency key
// производны от id операции и стабильны между повторными доставками того же
// job River — gateway/durable store не исполнит успешное задание дважды (R5),
// а идемпотентность Apply adapter делает повтор незавершённого безопасным.
func connectorJobBase(op operations.Operation, conn connections.Connection, kind connector.JobKind,
	idempotencyKey string, payload json.RawMessage, now time.Time) connector.Job {
	return connector.Job{
		ID:              op.ID.String(),
		Kind:            kind,
		ConnectionID:    conn.ID.String(),
		Engine:          conn.Engine,
		ProtocolVersion: connector.ProtocolVersion,
		IssuedAt:        now.Unix(),
		IdempotencyKey:  idempotencyKey,
		Nonce:           uuid.NewString(),
		Payload:         payload,
	}
}

// connectorConnectionParts строит секрет-free части payload задания из строки
// подключения и adapter-конфигурации: ссылку на подключение, несекретный
// TLS-материал и engine-атрибуты из discovery_config. Admin credential в
// payload не входит — он уходит кадром credentials (ADR-0014).
func connectorConnectionParts(conn connections.Connection, cfg adapter.Connection) (connector.ConnectionRef, connector.TLSRef, map[string]any) {
	ref := connector.ConnectionRef{
		ID:                conn.ID.String(),
		Engine:            conn.Engine,
		AuthMode:          cfg.AuthMode,
		Endpoints:         conn.Endpoints,
		ConfigIncarnation: cfg.ConfigIncarnation,
		NetworkGuard:      netguard.KubernetesDNSNetworkGuard(conn.ExecutionMode, cfg.TLS.Mode, conn.Endpoints),
	}
	tlsRef := connector.TLSRef{
		Mode:               cfg.TLS.Mode,
		CACertPEM:          cfg.TLS.CACertPEM,
		ClientCertPEM:      cfg.TLS.ClientCertPEM,
		InsecureSkipVerify: cfg.TLS.InsecureSkipVerify,
	}
	return ref, tlsRef, cfg.Attributes
}

// connectorJobCredentials строит секретный материал задания из
// adapter-конфигурации подключения: admin credential уже прочитан worker'ом
// из Vault (applyAdminCredential), подключение без admin credential даёт
// пустой кадр. Материал уходит ТОЛЬКО кадром TypeCredentials; вызывающий
// обязан занулить его после dispatch (JobCredentials.Zero).
func connectorJobCredentials(cfg adapter.Connection) connector.JobCredentials {
	creds := connector.JobCredentials{AdminCredentialIncarnation: cfg.AdminCredentialIncarnation}
	if cfg.AuthMode != "none" && (cfg.AdminCredential.Username != "" || len(cfg.AdminCredential.Secret) > 0) {
		admin := cfg.AdminCredential
		// Each frame owns the bytes cleared by connectorDispatch. A shallow
		// copy aliases the caller's configuration, so a read-only Plan would
		// erase the password needed by the following Apply on the same target.
		admin.Secret = append([]byte(nil), cfg.AdminCredential.Secret...)
		creds.Admin = &admin
	}
	return creds
}

// connectorDiscoverJob строит секрет-free задание JobDiscover для подключения.
func connectorDiscoverJob(op operations.Operation, conn connections.Connection, cfg adapter.Connection, now time.Time) (connector.Job, error) {
	connRef, tlsRef, attrs := connectorConnectionParts(conn, cfg)
	encoding := ""
	if conn.Engine == "postgres" {
		encoding = connector.SnapshotGzipV1
	}
	payload, err := connector.DiscoverPayload{
		PostgresObjectACL: conn.Engine == "postgres",
		SnapshotEncoding:  encoding,
		Connection:        connRef,
		TLS:               tlsRef,
		Attributes:        attrs,
	}.Marshal()
	if err != nil {
		return connector.Job{}, err
	}
	idem := "op:" + op.ID.String()
	if encoding != "" {
		idem += ":snapshot-gzip-v1"
	}
	if op.Kind == KindConnectionDiscover && op.ParentID != nil &&
		(op.ID == databaseChildID(*op.ParentID, "discover_database") || op.ID == databaseChildID(*op.ParentID, "discover_policies")) {
		// Until the database workflow has frozen its catalog, an earlier
		// successful discovery may be incomplete (a temporarily skipped DB or
		// missing schema), or temporarily incomplete policy observation. Every
		// requested observation refresh needs a new snapshot while
		// the stable child operation remains the audit/history identity.
		idem += ":database-discovery:" + uuid.NewString()
	}
	return connectorJobBase(op, conn, connector.JobDiscover, idem, payload, now), nil
}

// connectorAccountRef строит секрет-free ссылку на учётную запись для payload
// задания.
func connectorAccountRef(acct inventory.Account) connector.AccountRef {
	return connector.AccountRef{
		Kind:                acct.Kind,
		EngineIdentity:      acct.EngineIdentity,
		AuthenticationScope: acct.AuthenticationScope,
	}
}

// connectorMutationJob строит секрет-free задание JobApply мутации
// (grant/revoke/account lifecycle): descriptor подключения + ChangeRef.
func connectorMutationJob(op operations.Operation, conn connections.Connection, cfg adapter.Connection,
	change connector.ChangeRef, now time.Time) (connector.Job, error) {
	return connectorMutationJobOfKind(op, conn, cfg, change, connector.JobApply, now)
}

// connectorMutationJobOfKind builds the same closed, secret-free mutation
// payload for apply or verify-only execution. Role-policy adopt uses JobVerify
// and therefore cannot reach Adapter.Apply on the connector.
func connectorMutationJobOfKind(op operations.Operation, conn connections.Connection, cfg adapter.Connection,
	change connector.ChangeRef, jobKind connector.JobKind, now time.Time) (connector.Job, error) {
	connRef, tlsRef, attrs := connectorConnectionParts(conn, cfg)
	payload, err := connector.MutationPayload{
		Connection: connRef,
		TLS:        tlsRef,
		Attributes: attrs,
		Change:     change,
	}.Marshal()
	if err != nil {
		return connector.Job{}, err
	}
	idem := "op:" + op.ID.String()
	switch {
	case adapter.IsPostgresSuperuserDirectChange(adapter.ChangeKind(change.Kind)):
		// Each worker attempt must repeat the live authority/incarnation proof.
		// Retransmission of this concrete signed job still reuses one stable key,
		// while a later Execute receives a fresh suffix and cannot consume a
		// cached success from an older proof or different Plan/Apply phase.
		idem += ":postgres-v2:" + string(jobKind) + ":" + uuid.NewString()
	case op.Kind == KindRolePolicyCreateDatabase:
		// A successful target reply is not a metadata completion receipt. If
		// Complete failed, the database may have been replaced before retry.
		// Re-run the OID-pinned create-only Plan/Verify on every worker attempt;
		// replay of this exact wire job still has a stable deduplication key.
		idem += ":database-proof:" + uuid.NewString()
	case change.Kind == string(adapter.ChangeAccountRestore):
		// Успешный connector result обычно durable-dedup'ится. Для restore это
		// небезопасно в crash-window после target verify, но до metadata commit:
		// retry обязан заново доказать credential, а не получить cached success.
		// Новый ключ на каждое Execute сохраняет dedup повторной wire-доставки
		// одного Job, но не подавляет обязательный proof следующего retry.
		idem += ":credential-proof:" + uuid.NewString()
	case op.Kind == KindAccessReplace:
		// Explicit reverse выполняет два последовательных grant в рамках одной
		// operation: сначала convergence старого B, затем target A. Один общий
		// dedup key вернул бы cached success B вместо применения A.
		idem += ":assignment:" + changeDedupSuffix(change)
	case op.Kind == KindAccountEnable && change.Kind == string(adapter.ChangeGrant):
		// account.enable на движке, чей disable снимает права, отправляет
		// НЕСКОЛЬКО заданий одной операции: снятие блокировки и по одному
		// grant на каждый binding с desired='present'. Общий ключ дедупа
		// вернул бы им закешированный результат первого задания — то есть
		// ложный успех вместо применённого гранта. Ключ остаётся
		// детерминированным (производен от изменения), поэтому повторная
		// доставка того же задания по-прежнему дедуплицируется.
		idem += ":restore:" + changeDedupSuffix(change)
	}
	if change.Kind == string(adapter.ChangeRolePolicyApply) || change.Kind == string(adapter.ChangeRolePolicyCreate) ||
		change.Kind == string(adapter.ChangeRolePolicyVerify) {
		idem += ":" + string(jobKind) + ":" + changeDedupSuffix(change)
	}
	return connectorJobBase(op, conn, jobKind, idem, payload, now), nil
}

// changeDedupSuffix — стабильный несекретный дискриминатор изменения для
// ключа дедупликации: короткий hex sha256 от permission и scope. Хеш, а не
// сами идентификаторы, чтобы ключ имел ограниченную длину и предсказуемый
// алфавит независимо от имён ролей и ресурсов движка.
func changeDedupSuffix(change connector.ChangeRef) string {
	sum := sha256.Sum256([]byte(change.Permission + "\x1f" + change.Scope))
	return hex.EncodeToString(sum[:])[:16]
}

// connectorRotateJob строит секрет-free задание JobRotateCredential.
// vaultPath/vaultVersion — Vault-координаты НОВОГО секрета на стороне
// worker (в payload не попадают, versия 0 = «последняя», как у общего
// секрета принципала). Idempotency key включает их: retry той же операции
// после того, как worker записал СЛЕДУЮЩУЮ версию (direct-семантика ротации:
// каждый повтор per-account ротации генерирует новую версию), не должен
// получить закешированный успех применения предыдущей — иначе target
// разошёлся бы с последней версией Vault.
func connectorRotateJob(op operations.Operation, conn connections.Connection, cfg adapter.Connection,
	account connector.AccountRef, vaultPath string, vaultVersion int, verifyCredential bool, now time.Time) (connector.Job, error) {
	if vaultPath == "" {
		return connector.Job{}, errors.New("rotate job requires the vault path of the new secret version")
	}
	connRef, tlsRef, attrs := connectorConnectionParts(conn, cfg)
	payload, err := connector.RotatePayload{
		Connection:       connRef,
		TLS:              tlsRef,
		Attributes:       attrs,
		Account:          account,
		VerifyCredential: verifyCredential,
	}.Marshal()
	if err != nil {
		return connector.Job{}, err
	}
	idem := fmt.Sprintf("op:%s:vault:%s:v%d", op.ID, vaultPath, vaultVersion)
	return connectorJobBase(op, conn, connector.JobRotateCredential, idem, payload, now), nil
}

// connectorDispatch выдаёт задание и его credentials gateway с lease по
// дедлайну контекста и возвращает результат. Ошибки транспорта (нет
// подключённого connector, разрыв соединения mid-job, истёкший lease)
// возвращаются вызывающему как ошибка операции — та же retryable-семантика,
// что и недоступный target в прямом исполнении: River повторяет job, ложного
// успеха и ложного удаления нет. Секретный материал creds после dispatch
// зануляется здесь же — независимо от исхода.
func (e *MainExecutor) connectorDispatch(ctx context.Context, job connector.Job, creds connector.JobCredentials) (connector.JobResult, error) {
	defer creds.Zero()
	if deadline, ok := ctx.Deadline(); ok {
		job.Deadline = deadline.Unix()
	}
	res, err := e.conn.Dispatcher.Dispatch(ctx, job, creds)
	if err != nil {
		return connector.JobResult{}, fmt.Errorf("dispatch connector job %s: %w", job.ID, err)
	}
	return res, nil
}

// connectorDiscover исполняет discovery подключения через execution connector:
// строит задание, диспетчеризует его gateway (admin credential — кадром
// credentials) и разбирает snapshot из JobResult.
func (e *MainExecutor) connectorDiscover(ctx context.Context, op operations.Operation, conn connections.Connection, cfg adapter.Connection) (*adapter.Snapshot, error) {
	job, err := connectorDiscoverJob(op, conn, cfg, time.Now())
	if err != nil {
		return nil, err
	}
	res, err := e.connectorDispatch(ctx, job, connectorJobCredentials(cfg))
	if err != nil {
		return nil, err
	}
	if res.Status != connector.JobSuccess {
		return nil, fmt.Errorf("connector job %s: status %q: %s", job.ID, res.Status, res.Error)
	}
	snap, err := connector.ParseDiscoveryResult(res.Result)
	if err != nil {
		return nil, fmt.Errorf("connector job %s: unmarshal snapshot: %w", job.ID, err)
	}
	if conn.Engine == "postgres" && snap.Topology["postgres_object_acl_version"] == nil && e.deps.Inventory != nil && e.deps.Pool != nil {
		resources, err := e.deps.Inventory.ListResources(ctx, e.deps.Pool, conn.ID)
		if err != nil {
			return nil, err
		}
		for _, resource := range resources {
			if resource.Kind == "database" {
				snap.IncompleteScopes = append(snap.IncompleteScopes, resource.ExternalID)
			}
		}
	}
	return snap, nil
}

// connectorPlanApplyVerify исполняет мутацию через execution connector —
// эквивалент planApplyVerify direct-пути: connector выполняет Plan -> Apply ->
// read-back Verify тем же adapter и возвращает sanitized plan/result
// (connector.MarshalSanitized*, тот же формат, что у прямого исполнения).
// Credentials (admin + при необходимости credential учётной записи) резолвит
// вызывающий и передаёт в creds. Артефакты сохраняются в операцию и при
// падении (как у direct-пути план доступен при упавшем применении),
// verification разбирается из результата.
func (e *MainExecutor) connectorPlanApplyVerify(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, change connector.ChangeRef,
	creds connector.JobCredentials) (*adapter.Verification, error) {
	return e.connectorPlanApplyVerifyArtifacts(ctx, op, conn, cfg, change, creds, true)
}

// connectorPlanApplyVerifyArtifacts — connectorPlanApplyVerify с управлением
// артефактами операции (семантика artifacts — см. planApplyVerifyArtifacts).
func (e *MainExecutor) connectorPlanApplyVerifyArtifacts(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, change connector.ChangeRef,
	creds connector.JobCredentials, artifacts bool) (*adapter.Verification, error) {
	job, err := connectorMutationJob(op, conn, cfg, change, time.Now())
	if err != nil {
		return nil, err
	}
	res, err := e.connectorDispatch(ctx, job, creds)
	if err != nil {
		return nil, err
	}
	if artifacts && len(res.Plan) > 0 {
		e.setPlanArtifact(op.ID, res.Plan)
	}
	if artifacts && len(res.Result) > 0 {
		e.setResultArtifact(op.ID, res.Result)
	}
	if res.Status != connector.JobSuccess {
		return nil, fmt.Errorf("connector job %s: status %q: %s", job.ID, res.Status, res.Error)
	}
	parsed, err := connector.ParseSanitizedResult(res.Result)
	if err != nil {
		return nil, fmt.Errorf("connector job %s: %w", job.ID, err)
	}
	if parsed.Verification == nil {
		return nil, fmt.Errorf("connector job %s: result carries no verification", job.ID)
	}
	return &adapter.Verification{
		Verified: parsed.Verification.Verified,
		Details:  parsed.Verification.Details,
		Observed: parsed.Verification.Observed,
	}, nil
}

// connectorRotateCredential применяет новую версию секрета учётной записи к
// целевой системе через execution connector. Новая версия УЖЕ записана в
// Vault control plane (worker либо API-слоем); конкретное значение и номер
// версии уходят connector'у кадром credentials (creds.Account /
// creds.AccountVaultVersion), а vaultPath/vaultVersion дополнительно
// формируют idempotency key задания. Возвращает версию Vault, которую
// применил connector (несекретный результат задания).
func (e *MainExecutor) connectorRotateCredential(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, account connector.AccountRef,
	creds connector.JobCredentials, vaultPath string, vaultVersion int, verifyCredential bool) (int, error) {
	job, err := connectorRotateJob(op, conn, cfg, account, vaultPath, vaultVersion, verifyCredential, time.Now())
	if err != nil {
		creds.Zero()
		return 0, err
	}
	res, err := e.connectorDispatch(ctx, job, creds)
	if err != nil {
		return 0, err
	}
	if res.Status != connector.JobSuccess {
		if res.ErrorCode == "credential_access_denied" {
			return 0, fmt.Errorf("connector credential verification requires LOGIN and pg_hba.conf admission: %w", adapter.ErrCredentialProofAccessDenied)
		}
		if res.ErrorCode == "credential_proof_unsupported" {
			return 0, adapter.ErrCredentialProofUnsupported
		}
		return 0, fmt.Errorf("connector job %s: status %q: %s", job.ID, res.Status, res.Error)
	}
	outcome, err := connector.ParseRotateOutcome(res.Result)
	if err != nil {
		return 0, fmt.Errorf("connector job %s: %w", job.ID, err)
	}
	if !outcome.Rotated {
		return 0, fmt.Errorf("connector job %s: rotation is not confirmed by result", job.ID)
	}
	if verifyCredential && !outcome.Verified {
		return 0, fmt.Errorf("connector job %s: credential proof is not confirmed by result", job.ID)
	}
	return outcome.VaultVersion, nil
}
