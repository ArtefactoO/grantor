package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/credentials"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/core/rolepolicies"
)

// KindConnectionDiscover — операция discovery одного connection: adapter
// собирает snapshot целевой системы, ядро сводит его в metadata.
const KindConnectionDiscover = "connection.discover"

// DiscoverOperationKey возвращает idempotency key операции discovery:
// "discover:<connection-id>:<минутное-окно>". Формат общий для ручного
// refresh (internal/api) и периодического авто-rediscovery
// (internal/core/rediscovery): повторная постановка discovery того же
// connection в пределах минуты возвращает уже созданную операцию вместо
// новой, поэтому ручной и автоматический синк не дублируются.
func DiscoverOperationKey(id uuid.UUID, now time.Time) string {
	return fmt.Sprintf("discover:%s:%d", id, now.Unix()/60)
}

// Audit actions discovery.
const (
	auditActionDiscovered      = "connection.discovered"
	auditActionDiscoveryFailed = "connection.discovery_failed"
)

// VaultReader — минимальный контракт чтения секрета из Vault (сигнатура
// совпадает с (*vault.Client).Get). Интерфейс вместо конкретного клиента
// выбран сознательно: executor не зависит от библиотеки Vault, worker без
// настроенного Vault передаёт nil (тогда discovery работает только для
// connections без VaultAdminPath), а тесты подставляют фейк.
type VaultReader interface {
	Get(ctx context.Context, path string) (map[string]any, int, error)
}

// DiscoveryDeps — зависимости MainExecutor. Pool используется для
// собственных транзакций executor: результат discovery, статус
// connection и audit-событие коммитятся атомарно.
type DiscoveryDeps struct {
	Connections *connections.Store
	Inventory   *inventory.Store
	Audit       *audit.Writer
	Vault       VaultReader
	Pool        *pgxpool.Pool
	// Test-only fault boundaries for metadata-only provisioning recovery.
	// Production wiring leaves both nil.
	BeforeProvisioningRecoveryMetadataCommit  func(context.Context, operations.Operation) error
	BeforeProvisioningRecoveryOperationCommit func(context.Context, operations.Operation) error
}

// MutationDeps — дополнительные зависимости мутирующих операций
// (mutations.go). Adapters отдельного поля не требуют: executor берёт их
// из общего registry пакета adapter по engine подключения.
type MutationDeps struct {
	// Credentials — lifecycle секретов учётных записей (Vault + Yopass).
	// Nil допустим: тогда account.create и credential.rotate возвращают
	// понятную ошибку, а grant/revoke/disable/enable/delete работают.
	Credentials *credentials.Service
	// BeforeRestoreMetadataCommit — fault-injection hook для crash-window
	// после target credential proof, но до активации tombstone. Production
	// wiring оставляет nil; тест обязан доказать безопасную сходимость retry.
	BeforeRestoreMetadataCommit func(context.Context, operations.Operation) error
	// BeforeRestoreOperationCommit — fault-injection hook тестов для окна
	// после durable metadata success restore, но до commit outer transaction
	// со статусом/артефактами operation. Production wiring оставляет nil.
	BeforeRestoreOperationCommit func(context.Context, operations.Operation) error
	// Admin credential fault hooks cover the two metadata crash windows around
	// a forward-only external change. Production wiring leaves both nil.
	BeforeAdminCredentialMetadataCommit  func(context.Context, operations.Operation) error
	BeforeAdminCredentialOperationCommit func(context.Context, operations.Operation) error
	// Fixed database workflow fault boundary after durable child receipts and
	// before the outer root operation transaction commits.
	BeforeDatabaseProvisioningOperationCommit func(context.Context, operations.Operation) error
}

// OperationArtifacts — sanitized plan/result операции, построенные
// executor во время Execute. operationWorker сохраняет их в строку
// operations при финальном переходе статуса (TransitionOpts.Plan/Result);
// nil-поля оставляют прежние значения колонок.
type OperationArtifacts struct {
	Plan   []byte
	Result []byte
}

// operationArtifactsSource — необязательное расширение Executor:
// возвращает артефакты операции для сохранения при финальном переходе.
// Отдельный интерфейс (а не изменение сигнатуры Execute) сохраняет
// контракт Executor для фейков в тестах.
type operationArtifactsSource interface {
	TakeOperationArtifacts(id uuid.UUID) OperationArtifacts
}

// operationCommitHook позволяет integration-тесту оборвать единственное
// опасное окно между side-effect транзакцией executor и outer operation tx.
// Интерфейс остаётся внутренним; production hook при nil — no-op.
type operationCommitHook interface {
	BeforeOperationCommit(ctx context.Context, op operations.Operation) error
}

// MainExecutor — реальный Executor worker: диспетчеризует операции по
// kind. Повторный Execute той же операции идемпотентен: discovery заново
// сводит snapshot fingerprint-based upsert-ом.
//
// Транзакции: executor коммитит результат discovery независимо от
// транзакции operationWorker со статусом операции. Если после коммита
// executor упадёт запись статуса операции, повторный job выполнит
// discovery ещё раз поверх уже сведённого состояния — это безопасно.
type MainExecutor struct {
	deps DiscoveryDeps
	mut  MutationDeps
	// conn — зависимости исполнения через execution connector
	// (executor_connector.go); нулевое значение = gateway не сконфигурирован.
	conn ConnectorDeps

	// artifacts — plan/result выполняющихся операций по id; заполняются
	// мутациями во время Execute и забираются operationWorker через
	// TakeOperationArtifacts после его завершения.
	artifacts sync.Map // uuid.UUID -> OperationArtifacts
}

var (
	_ Executor                 = (*MainExecutor)(nil)
	_ operationArtifactsSource = (*MainExecutor)(nil)
)

// NewMainExecutor возвращает executor с переданными зависимостями.
func NewMainExecutor(deps DiscoveryDeps) *MainExecutor {
	return &MainExecutor{deps: deps}
}

// WithMutations добавляет executor зависимости мутирующих операций и
// возвращает его же (chained wiring в main).
func (e *MainExecutor) WithMutations(deps MutationDeps) *MainExecutor {
	e.mut = deps
	return e
}

// TakeOperationArtifacts отдаёт и удаляет артефакты операции. Вызывается
// operationWorker ровно один раз после Execute; для операций без
// артефактов (discovery) возвращает нулевое значение.
func (e *MainExecutor) TakeOperationArtifacts(id uuid.UUID) OperationArtifacts {
	v, ok := e.artifacts.LoadAndDelete(id)
	if !ok {
		return OperationArtifacts{}
	}
	return v.(OperationArtifacts)
}

// setPlanArtifact сохраняет sanitized plan операции; вызывается до Apply,
// чтобы план попал в operations и при падении применения.
func (e *MainExecutor) setPlanArtifact(id uuid.UUID, plan []byte) {
	a := e.loadArtifacts(id)
	a.Plan = plan
	e.artifacts.Store(id, a)
}

// setResultArtifact сохраняет sanitized result операции.
func (e *MainExecutor) setResultArtifact(id uuid.UUID, result []byte) {
	a := e.loadArtifacts(id)
	a.Result = result
	e.artifacts.Store(id, a)
}

// loadArtifacts возвращает текущие артефакты операции или нулевое
// значение.
func (e *MainExecutor) loadArtifacts(id uuid.UUID) OperationArtifacts {
	if v, ok := e.artifacts.Load(id); ok {
		return v.(OperationArtifacts)
	}
	return OperationArtifacts{}
}

// BeforeOperationCommit реализует test-only fault injection после того, как
// restore metadata уже могла закоммититься, но operation status/artifacts ещё
// находятся в незакоммиченной outer transaction.
func (e *MainExecutor) BeforeOperationCommit(ctx context.Context, op operations.Operation) error {
	if (op.Kind == KindDatabaseCreateWithRoles || op.Kind == KindPostgresDatabaseCreateWithRolesV2) &&
		e.mut.BeforeDatabaseProvisioningOperationCommit != nil {
		return e.mut.BeforeDatabaseProvisioningOperationCommit(ctx, op)
	}
	if op.Kind == KindAccountRecoverProvisioning && e.deps.BeforeProvisioningRecoveryOperationCommit != nil {
		payload, err := parseProvisioningRecoveryPayload(op)
		if err != nil {
			return err
		}
		if payload != nil {
			return e.deps.BeforeProvisioningRecoveryOperationCommit(ctx, op)
		}
	}
	if (op.Kind == KindConnectionAdminCredentialSwitch ||
		op.Kind == KindConnectionAdminCredentialRotate) &&
		e.mut.BeforeAdminCredentialOperationCommit != nil {
		return e.mut.BeforeAdminCredentialOperationCommit(ctx, op)
	}
	if (op.Kind != KindAccountRestore && op.Kind != KindPostgresAccountRestoreV2) ||
		e.mut.BeforeRestoreOperationCommit == nil {
		return nil
	}
	return e.mut.BeforeRestoreOperationCommit(ctx, op)
}

// Execute выполняет одну операцию по её kind. Неизвестный kind — ошибка:
// job честно фейлится, а не завершается ложным успехом.
func (e *MainExecutor) Execute(ctx context.Context, op operations.Operation) error {
	if op.ConnectionID != nil && e.deps.Connections != nil && e.deps.Pool != nil && op.Kind != KindConnectionDiscover && op.Kind != KindAccountRecoverProvisioning && op.Kind != KindConnectionAdminCredentialSwitch {
		conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, *op.ConnectionID)
		if err != nil {
			if errors.Is(err, connections.ErrNotFound) {
				return terminal(err)
			}
			return err
		}
		if conn.AuthMode == "none" {
			return terminal(fmt.Errorf("authentication_disabled: queued %s is unavailable: %w", op.Kind, adapter.ErrUnsupportedChange))
		}
	}
	if err := e.rejectLegacyPostgresOperation(ctx, op); err != nil {
		return err
	}
	switch op.Kind {
	case KindConnectionDiscover, KindAccountRecoverProvisioning:
		return e.executeDiscover(ctx, op)
	case KindAccessGrant, KindPostgresStatsGrantV1, KindPostgresObjectACLGrantV1:
		return e.executeAccessChange(ctx, op, adapter.ChangeGrant)
	case KindAccessRevoke, KindPostgresStatsRevokeV1, KindPostgresObjectACLRevokeV1:
		return e.executeAccessChange(ctx, op, adapter.ChangeRevoke)
	case KindAccessReplace:
		return e.executeAccessReplace(ctx, op)
	case KindAccountCreate:
		return e.executeAccountChange(ctx, op, adapter.ChangeAccountCreate)
	case KindPostgresAccountProvisionV1:
		return e.executePostgresAccountProvisioning(ctx, op, false)
	case KindPostgresAccountVerifyCreationV1:
		return e.executePostgresAccountProvisioning(ctx, op, true)
	case KindPostgresAccountCreateV2:
		return e.executeAccountChange(ctx, op, adapter.ChangePostgresAccountCreateV2)
	case KindRoleCreate:
		return e.executeAccountChange(ctx, op, adapter.ChangeRoleCreate)
	case KindPostgresRoleCreateV2:
		return e.executeAccountChange(ctx, op, adapter.ChangePostgresRoleCreateV2)
	case KindResourceCreateDatabase, KindResourceCreatePreparedDatabase:
		return e.executeResourceCreate(ctx, op)
	case KindPostgresResourceCreateDatabaseV2, KindPostgresResourceCreateDatabaseForRolesV2:
		return e.executeResourceCreate(ctx, op)
	case KindDatabaseCreateWithRoles:
		return e.executeDatabaseCreateWithRoles(ctx, op)
	case KindPostgresDatabaseCreateWithRolesV2:
		return e.executeDatabaseCreateWithRoles(ctx, op)
	case KindAccountDisable:
		return e.executeAccountChange(ctx, op, adapter.ChangeAccountDisable)
	case KindAccountEnable:
		return e.executeAccountChange(ctx, op, adapter.ChangeAccountEnable)
	case KindAccountDelete:
		return e.executeAccountChange(ctx, op, adapter.ChangeAccountDelete)
	case KindAccountRestore:
		return e.executeAccountRestore(ctx, op)
	case KindPostgresAccountRestoreV2:
		return e.executeAccountRestore(ctx, op)
	case KindAccountAdoptVerify:
		return e.executeAccountAdoptVerify(ctx, op)
	case KindCredentialVerify:
		return e.executeCredentialVerify(ctx, op)
	case KindCredentialRotate:
		return e.executeCredentialRotate(ctx, op)
	case KindRolePolicyApply, KindRolePolicyAdopt, KindRolePolicyRepair, KindRolePolicyCreate, KindRolePolicyCreateDatabase,
		KindPostgresRolePolicyApplyV2, KindPostgresRolePolicyAdoptV2,
		KindPostgresRolePolicyRepairV2, KindPostgresRolePolicyCreateV2,
		KindPostgresRolePolicyCreateDatabaseV2:
		return e.executeRolePolicy(ctx, op)
	case KindConnectionAdminCredentialSwitch, KindConnectionAdminCredentialRotate:
		return e.executeConnectionAdminCredentialChange(ctx, op)
	default:
		// Kind операции неизменяем, поэтому повтор не изменит исход:
		// отказ детерминирован (terminal.go).
		return terminal(fmt.Errorf("jobs: execute operation %s: unknown kind %q", op.ID, op.Kind))
	}
}

// executeDiscover выполняет discovery connection: читает admin credential из
// Vault (если задан vault path) и либо вызывает adapter.Discover напрямую,
// либо (режим connector) диспетчеризует подписанное задание JobDiscover
// через gateway (executor_connector.go), доставляя credential connector'у
// кадром TypeCredentials (ADR-0014: connector к Vault не ходит). Полученный
// snapshot в обоих режимах сводится в metadata одной транзакцией со статусом
// connection и audit-событием — connector-исполнение неотличимо от прямого
// для ядра.
// Ошибка discovery фиксируется в статусе connection (discovering ->
// discovery_failed, active -> degraded) и в audit, после чего возвращается —
// River повторит job по своей политике retry.
//
// Discovery выполняется из статусов discovering, active и degraded;
// discovery_failed сначала возвращается в discovering по state machine
// (retry), остальные статусы — ошибка: там discovery ещё (или уже) не
// имеет смысла.
func (e *MainExecutor) executeDiscover(ctx context.Context, op operations.Operation) error {
	if op.ConnectionID == nil {
		return fmt.Errorf("jobs: discover operation %s: connection id is not set", op.ID)
	}
	recovery, err := parseProvisioningRecoveryPayload(op)
	if err != nil {
		return err
	}
	if recovery != nil {
		completed, err := provisioningRecoveryCompleted(ctx, e.deps.Pool, op, *recovery)
		if err != nil {
			return err
		}
		if completed {
			// Metadata and receipt committed but the outer operation commit
			// was lost. Do not rediscover or release this incarnation again.
			return nil
		}
		if _, err := e.checkProvisioningRecovery(ctx, e.deps.Pool, op, *recovery); err != nil {
			return err
		}
	}
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, *op.ConnectionID)
	if err != nil {
		return fmt.Errorf("jobs: discover operation %s: %w", op.ID, err)
	}
	// Routing по режиму исполнения — до переходов статуса: несконфигурированный
	// gateway не должен оставлять следов в state machine подключения.
	viaConnector, err := connectorRoute(conn.ExecutionMode, op.Kind, e.conn.Dispatcher != nil)
	if err != nil {
		return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
	}

	switch conn.Status {
	case connections.StatusDiscovering, connections.StatusActive, connections.StatusDegraded:
		// Допустимые статусы discovery.
	case connections.StatusDiscoveryFailed:
		// Retry после падения первоначального discovery (в том числе
		// автоматический retry River той же операции): возвращаемся в
		// discovering, чтобы success/failure ниже работали по обычным
		// переходам state machine.
		conn, err = e.deps.Connections.Transition(ctx, e.deps.Pool, conn.ID,
			connections.StatusDiscoveryFailed, connections.StatusDiscovering)
		if err != nil {
			return fmt.Errorf("jobs: discover connection %s: resume after failure: %w", *op.ConnectionID, err)
		}
	default:
		return fmt.Errorf("jobs: discover connection %s: status %q does not allow discovery", conn.ID, conn.Status)
	}

	cfg, err := adapterConnection(conn)
	if err != nil {
		return fmt.Errorf("jobs: discover operation %s: %w", op.ID, err)
	}

	// Admin credential читает worker в обоих режимах (ADR-0014): при
	// прямом исполнении он уходит в adapter, при connector-режиме —
	// connector'у кадром TypeCredentials (в подписанный payload не входит).
	if err := e.applyAdminCredential(ctx, conn, &cfg); err != nil {
		return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
	}
	defer clear(cfg.AdminCredential.Secret)
	var snap *adapter.Snapshot
	var discoverErr error
	if viaConnector {
		snap, discoverErr = e.connectorDiscover(ctx, op, conn, cfg)
	} else {
		ad, err := adapter.New(conn.Engine)
		if err != nil {
			return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
		}
		snap, discoverErr = ad.Discover(ctx, cfg)
	}
	if discoverErr != nil {
		discoverErr = fmt.Errorf("jobs: discover connection %s: %w", conn.ID, discoverErr)
		if recordErr := e.recordDiscoveryFailure(ctx, op, conn, discoverErr); recordErr != nil {
			return errors.Join(discoverErr, recordErr)
		}
		return discoverErr
	}
	markConnectionAdminAccount(conn, cfg, snap)
	if conn.Engine == postgres.Engine {
		authority, confirmed := adapter.ProvisioningAuthorityFromTopology(snap.Topology, adapter.PostgresProvisioningAuthorityTopologyKey)
		for i := range snap.Permissions {
			if snap.Permissions[i].ExternalID == postgres.StatsPermission {
				statsSupported := !viaConnector || e.requireStatsMembershipConnectorCapabilities() == nil
				snap.Permissions[i].Assignable = snap.Permissions[i].Assignable && statsSupported && confirmed &&
					authority.Status == adapter.ProvisioningAuthorityConfirmed && authority.Reason == adapter.ProvisioningAuthoritySuperuserConfirmed
			}
		}
	}
	return e.recordDiscoverySuccess(ctx, op, conn, snap)
}

// markConnectionAdminAccount помечает в снапшоте учётную запись, под которой
// grantor сам управляет подключением.
//
// Зачем: без отметки admin-учётка подключения выглядит обычным unmanaged
// аккаунтом, и оператор может принять её под управление. Дальше grantor в
// режиме generate сменил бы пароль собственной admin-учётки, не обновив
// admin credential подключения, — управление подключением ломается целиком.
// Присвоение учётки строго сильнее выдачи опасного права, а гейт на неё до
// этого отсутствовал.
//
// Отметка вычисляется здесь, а не в adapter: имя admin-учётки — свойство
// подключения (лежит в Vault), а не целевой системы. Приведение к
// engine-форме идёт через EngineIdentityFormatter, иначе mysql-идентичность
// `root@%` не совпала бы с username `root`.
func markConnectionAdminAccount(conn connections.Connection, cfg adapter.Connection, snap *adapter.Snapshot) {
	username := cfg.AdminCredential.Username
	if username == "" || snap == nil {
		return
	}
	identity := username
	if ad, err := adapter.New(conn.Engine); err == nil {
		if f, ok := ad.(adapter.EngineIdentityFormatter); ok {
			if formatted, ferr := f.FormatEngineIdentity(cfg, username); ferr == nil {
				identity = formatted
			}
		}
	}
	for i := range snap.Accounts {
		a := &snap.Accounts[i]
		if a.EngineIdentity != identity && a.EngineIdentity != username {
			continue
		}
		if a.Attributes == nil {
			a.Attributes = map[string]any{}
		}
		a.Attributes[adapter.AttrConnectionAdmin] = true
	}
}

// recordDiscoverySuccess атомарно сводит snapshot, записывает результат
// discovery, возвращает connection в active (из discovering или
// degraded; активный остаётся активным) и пишет audit-событие.
func (e *MainExecutor) recordDiscoverySuccess(ctx context.Context, op operations.Operation, conn connections.Connection, snap *adapter.Snapshot) error {
	recovery, err := parseProvisioningRecoveryPayload(op)
	if err != nil {
		return err
	}
	observedAt := snap.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	topology := []byte("{}")
	if snap.Topology != nil {
		b, err := json.Marshal(snap.Topology)
		if err != nil {
			return fmt.Errorf("jobs: discover connection %s: marshal topology: %w", conn.ID, err)
		}
		topology = b
	}

	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: discover connection %s: begin tx: %w", conn.ID, err)
	}
	// После успешного Commit откат — no-op с ErrTxClosed; ошибку
	// игнорируем сознательно.
	defer tx.Rollback(ctx) //nolint:errcheck

	var recovered *inventory.Account
	var recoveryOutcome error
	if recovery != nil {
		recovered, recoveryOutcome, err = e.releaseObservedProvisioning(ctx, tx, op, *recovery, snap)
		if err != nil {
			return err
		}
	}
	stats, err := e.deps.Inventory.UpsertSnapshot(ctx, tx, conn.ID, snap, observedAt)
	if err != nil {
		return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
	}
	if err := rolepolicies.NewStore().ReconcileSnapshot(ctx, tx, conn.ID, snap.RolePolicies, observedAt); err != nil {
		return fmt.Errorf("jobs: discover connection %s: reconcile role policies: %w", conn.ID, err)
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		return fmt.Errorf("jobs: discover connection %s: adapter manifest: %w", conn.ID, err)
	}
	if err := e.deps.Connections.SetDiscoveryResult(ctx, tx, conn.ID, snap.ServerVersion, topology, ad.Manifest().CapabilityNames(), observedAt); err != nil {
		return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
	}

	switch conn.Status {
	case connections.StatusDiscovering, connections.StatusDegraded:
		if _, err := e.deps.Connections.Transition(ctx, tx, conn.ID, conn.Status, connections.StatusActive); err != nil {
			return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
		}
	default:
		// active остаётся active; прочие статусы отсечены валидацией в
		// executeDiscover.
	}

	metadata, err := json.Marshal(map[string]any{
		"resources":         stats.Resources,
		"accounts":          stats.Accounts,
		"permissions":       stats.Permissions,
		"bindings":          stats.Bindings,
		"role_policies":     len(snap.RolePolicies),
		"missing_resources": stats.MissingResources,
		"server_version":    snap.ServerVersion,
	})
	if err != nil {
		return fmt.Errorf("jobs: discover connection %s: marshal audit metadata: %w", conn.ID, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType:    op.ActorType,
		ActorID:      op.ActorID,
		Action:       auditActionDiscovered,
		ConnectionID: &conn.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("jobs: discover connection %s: %w", conn.ID, err)
	}
	if recovered != nil {
		if err := e.recordProvisioningRecovered(ctx, tx, op, *recovery, *recovered); err != nil {
			return err
		}
		if e.deps.BeforeProvisioningRecoveryMetadataCommit != nil {
			if err := e.deps.BeforeProvisioningRecoveryMetadataCommit(ctx, op); err != nil {
				return fmt.Errorf("jobs: provisioning recovery before metadata commit: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: discover connection %s: commit: %w", conn.ID, err)
	}
	// A successful read that did not find the account is not a connection
	// failure. Keep the original reservation retryable and return the explicit
	// recovery refusal only after the ordinary snapshot has committed.
	return recoveryOutcome
}

// recordDiscoveryFailure атомарно фиксирует падение discovery: статус
// connection (discovering -> discovery_failed, active -> degraded;
// degraded остаётся degraded) и audit-событие. Текст ошибки адаптера
// sanitized по контракту adapter и не содержит секретов.
func (e *MainExecutor) recordDiscoveryFailure(ctx context.Context, op operations.Operation, conn connections.Connection, discoverErr error) error {
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: record discovery failure %s: begin tx: %w", conn.ID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	switch conn.Status {
	case connections.StatusDiscovering:
		if _, err := e.deps.Connections.Transition(ctx, tx, conn.ID, conn.Status, connections.StatusDiscoveryFailed); err != nil {
			return fmt.Errorf("jobs: record discovery failure %s: %w", conn.ID, err)
		}
	case connections.StatusActive:
		if _, err := e.deps.Connections.Transition(ctx, tx, conn.ID, conn.Status, connections.StatusDegraded); err != nil {
			return fmt.Errorf("jobs: record discovery failure %s: %w", conn.ID, err)
		}
	default:
		// degraded остаётся degraded; прочие статусы не трогаем.
	}

	metadata, err := json.Marshal(map[string]any{"error": discoverErr.Error()})
	if err != nil {
		return fmt.Errorf("jobs: record discovery failure %s: marshal audit metadata: %w", conn.ID, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType:    op.ActorType,
		ActorID:      op.ActorID,
		Action:       auditActionDiscoveryFailed,
		ConnectionID: &conn.ID,
		OperationID:  &op.ID,
		Result:       audit.ResultFailure,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("jobs: record discovery failure %s: %w", conn.ID, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: record discovery failure %s: commit: %w", conn.ID, err)
	}
	return nil
}

// adapterConnection строит adapter.Connection из строки connections без
// admin credential (его добавляет вызывающий). Проекция живёт в
// connections.AdapterConfig: формат jsonb-колонок принадлежит доменной
// модели подключения и нужен теперь и API-слою (форматирование engine
// identity). Локальная обёртка сохраняет прежние вызовы executor.
func adapterConnection(conn connections.Connection) (adapter.Connection, error) {
	return connections.AdapterConfig(conn)
}

// applyAdminCredential загружает admin credential подключения из Vault и
// проставляет его в cfg, если у подключения задан vault_admin_path. Пустой путь
// — no-op (подключение без admin credential в Vault). Возвращаемые ошибки — без
// префикса подключения: вызывающий (discover или mutationTarget) добавляет
// свой, поэтому один блок обслуживает оба пути с их разными формулировками.
func (e *MainExecutor) applyAdminCredential(ctx context.Context, conn connections.Connection, cfg *adapter.Connection) error {
	if conn.AuthMode == "none" {
		if conn.Engine != "redis" || conn.VaultAdminPath != "" {
			return errors.New("invalid no-auth connection")
		}
		cfg.AdminCredential = adapter.Credential{Kind: "none", Username: "default"}
		return nil
	}
	if conn.VaultAdminPath == "" {
		return nil
	}
	if e.deps.Vault == nil {
		return errors.New("vault admin path is set but vault reader is not configured")
	}
	data, version, err := e.deps.Vault.Get(ctx, conn.VaultAdminPath)
	if err != nil {
		return fmt.Errorf("read admin credential: %w", err)
	}
	cred, err := credentialFromVault(data)
	if err != nil {
		return err
	}
	cfg.AdminCredential = cred
	cfg.AdminCredentialIncarnation = version
	return nil
}

// credentialFromVault строит adapter.Credential из данных секрета Vault
// (поля username и password). Значения полей в ошибки не попадают.
func credentialFromVault(data map[string]any) (adapter.Credential, error) {
	username, _ := data["username"].(string)
	if username == "" {
		return adapter.Credential{}, errors.New("vault admin credential: username field is missing or empty")
	}
	password, _ := data["password"].(string)
	if password == "" {
		return adapter.Credential{}, errors.New("vault admin credential: password field is missing or empty")
	}
	return adapter.Credential{
		Kind:     "password",
		Username: username,
		Secret:   []byte(password),
	}, nil
}
