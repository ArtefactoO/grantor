package jobs

// Мутирующие операции executor (этап 1b): grant/revoke bindings,
// lifecycle managed-аккаунтов и ротация credentials через engine
// adapters. Общий поток — раздел 9 архитектуры: план -> применение ->
// read-back verify -> обновление metadata и audit в одной транзакции.
//
// Идемпотентность: повторный Execute той же операции строит план заново
// поверх фактического состояния; Apply adapters обязан быть безопасен
// при повторении (контракт adapter).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ArtefactoO/grantor/internal/adapter"
	"github.com/ArtefactoO/grantor/internal/adapters/postgres"
	"github.com/ArtefactoO/grantor/internal/connector"
	"github.com/ArtefactoO/grantor/internal/core/audit"
	"github.com/ArtefactoO/grantor/internal/core/connections"
	"github.com/ArtefactoO/grantor/internal/core/databaseprovisioning"
	"github.com/ArtefactoO/grantor/internal/core/inventory"
	"github.com/ArtefactoO/grantor/internal/core/operations"
	"github.com/ArtefactoO/grantor/internal/providers/vault"
)

// Kinds мутирующих операций. Значения совпадают с capability-именами
// adapter (раздел 10.3 архитектуры).
const (
	KindAccessGrant  = "access.grant"
	KindAccessRevoke = "access.revoke"
	// KindAccessReplace атомарно меняет permission одного exclusive
	// assignment slot. На target выполняется только ChangeGrant нового
	// permission; отдельного revoke и окна без доступа нет.
	KindAccessReplace    = "access.replace"
	KindAccountCreate    = "account.create"
	KindRoleCreate       = "role.create"
	KindAccountDisable   = "account.disable"
	KindAccountEnable    = "account.enable"
	KindAccountDelete    = "account.delete"
	KindAccountRestore   = "account.restore"
	KindCredentialRotate = "credential.rotate"
	// KindResourceCreateDatabase — создание базы в целевой системе.
	KindResourceCreateDatabase = "resource.create.database"

	// KindAccountAdoptVerify — принятие существующего аккаунта под управление
	// БЕЗ мутации целевой системы: worker доказывает, что переданный
	// оператором пароль действительно принимает target
	// (adapter.CredentialProver), и только после этого переводит ownership в
	// managed и кладёт подтверждённое значение в accounts/<id>/credential.
	// Собственной capability adapter у операции нет: право её исполнять даёт
	// сам факт реализации CredentialProver движком (то же условие, что у
	// account.restore). Префикс account. не случаен — guard «аккаунт занят
	// незавершённой lifecycle-операцией» (ReserveAccountLifecycle) отбирает
	// операции по `kind like 'account.%'`.
	KindAccountAdoptVerify = "account.adopt_verify"

	// KindBulkGrant — parent bulk-операции (раздел 19.1). Worker её не
	// выполняет: parent создаётся API сразу в running и служит группировкой
	// дочерних access.grant; итоговый статус финализируется в базе при
	// завершении последнего ребёнка (operations.Store.FinalizeParent).
	KindBulkGrant = "bulk.grant"
	// KindBulkAccountRoles — parent изменения набора ролей одного аккаунта:
	// группирует дочерние access.grant и access.revoke. Worker parent не
	// выполняет; итоговый статус формируется по детям.
	KindBulkAccountRoles = "bulk.account_roles"
	KindBulkObjectACL    = "bulk.object_acl"

	// KindBulkPrincipalAccess — parent principal-centric выдачи доступа:
	// группирует дочерние account.create и access.grant по подключениям.
	// Как и KindBulkGrant, worker parent не выполняет.
	KindBulkPrincipalAccess = "bulk.principal_access"
	// KindBulkPrincipalRotate — parent ротации общего секрета принципала:
	// группирует дочерние credential.rotate по аккаунтам окружения.
	KindBulkPrincipalRotate = "bulk.principal_rotate"
	// KindBulkPrincipalDisable / KindBulkPrincipalEnable — parent
	// обратимого каскада статуса принципала: группируют дочерние
	// account.disable / account.enable его managed-аккаунтов по всем
	// connections. Vault и bindings не затрагиваются; worker parent не
	// выполняет (создаётся API сразу в running, итог финализируется в базе
	// при завершении последнего ребёнка).
	KindBulkPrincipalDisable = "bulk.principal_disable"
	KindBulkPrincipalEnable  = "bulk.principal_enable"
	// KindBulkPrincipalOffboard — parent необратимого offboarding
	// принципала: группирует дочерние access.revoke (managed-present
	// bindings) и account.delete его managed-аккаунтов в порядке
	// «сначала ревоки аккаунта, затем его удаление». Worker parent не
	// выполняет — как прочие bulk-parent.
	KindBulkPrincipalOffboard = "bulk.principal_offboard"

	// KindBulkManifestApply — parent применения декларативного access
	// manifest (ADR-0009): группирует дочерние account.create/access.grant/
	// access.revoke. Как и прочие bulk-parent, worker его не выполняет —
	// создаётся API сразу в running, итог финализируется в базе при
	// завершении последнего ребёнка.
	KindBulkManifestApply = "bulk.manifest_apply"
)

// Audit actions мутирующих операций.
const (
	auditActionAccessGranted          = "access.granted"
	auditActionAccessGrantFailed      = "access.grant_failed"
	auditActionAccessRevoked          = "access.revoked"
	auditActionAccessRevokeFailed     = "access.revoke_failed"
	auditActionAccessReplaced         = "access.replaced"
	auditActionAccessReplaceFailed    = "access.replace_failed"
	auditActionAccountCreated         = "account.created"
	auditActionAccountCreateFailed    = "account.create_failed"
	auditActionRoleCreated            = "role.created"
	auditActionRoleCreateFailed       = "role.create_failed"
	auditActionResourceCreated        = "resource.created"
	auditActionResourceCreateFailed   = "resource.create_failed"
	auditActionAccountDisabled        = "account.disabled"
	auditActionAccountDisableFailed   = "account.disable_failed"
	auditActionAccountEnabled         = "account.enabled"
	auditActionAccountEnableFailed    = "account.enable_failed"
	auditActionAccountDeleted         = "account.deleted"
	auditActionAccountDeleteFailed    = "account.delete_failed"
	auditActionAccountRestored        = "account.restored"
	auditActionAccountRestoreFailed   = "account.restore_failed"
	auditActionAccountAdopted         = "account.adopted"
	auditActionAccountAdoptFailed     = "account.adopt_failed"
	auditActionCredentialRotated      = "credential.rotated"
	auditActionCredentialRotateFailed = "credential.rotate_failed"
)

// auditActions — пара audit actions одного вида мутации.
type auditActions struct {
	success string
	failure string
}

// changeAuditActions — соответствие ChangeKind adapter и audit actions.
var changeAuditActions = map[adapter.ChangeKind]auditActions{
	adapter.ChangeGrant:          {auditActionAccessGranted, auditActionAccessGrantFailed},
	adapter.ChangeRevoke:         {auditActionAccessRevoked, auditActionAccessRevokeFailed},
	adapter.ChangeAccountCreate:  {auditActionAccountCreated, auditActionAccountCreateFailed},
	adapter.ChangeRoleCreate:     {auditActionRoleCreated, auditActionRoleCreateFailed},
	adapter.ChangeResourceCreate: {auditActionResourceCreated, auditActionResourceCreateFailed},
	adapter.ChangeAccountDisable: {auditActionAccountDisabled, auditActionAccountDisableFailed},
	adapter.ChangeAccountEnable:  {auditActionAccountEnabled, auditActionAccountEnableFailed},
	adapter.ChangeAccountDelete:  {auditActionAccountDeleted, auditActionAccountDeleteFailed},
	adapter.ChangeAccountRestore: {auditActionAccountRestored, auditActionAccountRestoreFailed},
}

// AccessPayload — payload операций access.grant и access.revoke
// (jsonb operations.payload; секретов не содержит).
type AccessPayload struct {
	ObjectACL                *adapter.PostgresObjectACLPins `json:"object_acl,omitempty"`
	StatsMembership          *postgres.StatsMembershipPins  `json:"stats_membership,omitempty"`
	StatsCreationOperationID uuid.UUID                      `json:"stats_creation_operation_id,omitempty"`
	BindingID                uuid.UUID                      `json:"binding_id"`
	// ExpectedPermissionDefinitionID и ExpectedDesiredState пинят intent
	// обычного grant/revoke. Без них старый queued revoke мог прочитать уже
	// переиспользованный exclusive binding и удалить новое право.
	ExpectedPermissionDefinitionID uuid.UUID `json:"expected_permission_definition_id,omitempty"`
	ExpectedDesiredState           string    `json:"expected_desired_state,omitempty"`
	// PermissionAttributes — несекретный snapshot definition на момент
	// enqueue. Для versioned templates он не позволяет retry переосмыслить
	// тот же key через изменившийся connection catalog.
	PermissionAttributes map[string]any `json:"permission_attributes,omitempty"`
	// ExpectedAccountLifecycleVersion пинит account incarnation для
	// queued grant/revoke. Legacy payload получает 0 и остаётся допустимым
	// только до первого lifecycle reserve.
	ExpectedAccountLifecycleVersion int64 `json:"expected_account_lifecycle_version,omitempty"`
	// Confirmed — явное подтверждение выдачи dangerous permission.
	// Основной контроль — на API (роль admin + confirm); здесь payload
	// несёт факт подтверждения для defense in depth в executor.
	Confirmed bool `json:"confirmed,omitempty"`
	// PriorDesiredState и BindingCreated описывают состояние binding ДО
	// постановки операции: выдача переводит его в present ещё до approve, и
	// отклонённая операция должна вернуть строку ровно туда, где она была,
	// а созданную ею строку — удалить. Пусто = desired был NULL (unmanaged).
	PriorDesiredState string `json:"prior_desired_state,omitempty"`
	BindingCreated    bool   `json:"binding_created,omitempty"`
}

// AccessReplacePayload — immutable intent операции access.replace. BindingID
// остаётся тем же физическим assignment slot, From/To пинят смену A -> B,
// ExpectedBindingVersion и OperationID в самой строке не позволяют stale job
// применить более старое решение.
type AccessReplacePayload struct {
	BindingID                       uuid.UUID      `json:"binding_id"`
	FromPermissionDefinitionID      uuid.UUID      `json:"from_permission_definition_id"`
	ToPermissionDefinitionID        uuid.UUID      `json:"to_permission_definition_id"`
	AssignmentKey                   string         `json:"assignment_key"`
	ExpectedBindingVersion          int64          `json:"expected_binding_version"`
	ExpectedAccountLifecycleVersion int64          `json:"expected_account_lifecycle_version,omitempty"`
	Confirmed                       bool           `json:"confirmed,omitempty"`
	PermissionAttributes            map[string]any `json:"permission_attributes,omitempty"`
	// ReverseOfOperationID marks an explicit reverse of a failed A→B. Executor
	// first exact-converges B, creating a quiescence/fencing point, and only
	// then applies A. ConvergePermissionAttributes pins B's reviewed tuple.
	ReverseOfOperationID         uuid.UUID      `json:"reverse_of_operation_id,omitempty"`
	ConvergePermissionAttributes map[string]any `json:"converge_permission_attributes,omitempty"`
	ExpectedTargetIdentity       string         `json:"expected_target_identity,omitempty"`
}

// AccountPayload — payload операций account.* и credential.rotate.
type AccountPayload struct {
	CreationOperationID           uuid.UUID `json:"creation_operation_id,omitempty"`
	AccountID                     uuid.UUID `json:"account_id"`
	ExpectedAdminIdentity         string    `json:"expected_admin_identity,omitempty"`
	ExpectedTargetIdentity        string    `json:"expected_target_identity,omitempty"`
	ExpectedConfigIncarnation     string    `json:"expected_config_incarnation,omitempty"`
	ExpectedCredentialIncarnation int       `json:"expected_credential_incarnation,omitempty"`
	// ExpectedStatus/ExpectedLifecycleVersion резервируются API атомарно с
	// enqueue. Worker сверяет их до Vault/target; stale job fail-closed.
	ExpectedStatus           inventory.AccountStatus `json:"expected_status,omitempty"`
	ExpectedLifecycleVersion int64                   `json:"expected_lifecycle_version,omitempty"`
	// CredentialMode и CredentialVaultVersion используются account.restore.
	// Версия пинит конкретный свежий секрет; сам path канонически выводится из
	// account id и в payload не сериализуется.
	CredentialMode         string `json:"credential_mode,omitempty"`
	CredentialVaultVersion int    `json:"credential_vault_version,omitempty"`
	// SharedCredentialPath — Vault-путь общего секрета принципала
	// (principals/<id>/environments/<env>/credential) в модели
	// shared-per-principal-per-environment. Непустое значение означает, что
	// пароль читается из этого пути, а не генерируется per-account: так
	// несколько аккаунтов одного принципала в окружении остаются на одном
	// пароле. Секретов не содержит — только путь.
	SharedCredentialPath string `json:"shared_credential_path,omitempty"`
	// ManagedLinkPrincipalID отличает безопасный link-and-manage уже
	// существующего unmanaged account от обычной shared-ротации. Principal
	// и ownership фиксируются атомарно только после rotate + proof.
	ManagedLinkPrincipalID *uuid.UUID `json:"managed_link_principal_id,omitempty"`
	// AdoptBindings — вместе с аккаунтом принять под управление все его
	// unmanaged bindings. Применяется ТОЛЬКО на успехе операции, в той же
	// транзакции, что и переход ownership: bindings, принятые раньше, при
	// провале кред-операции оставались бы управляемыми у неуправляемого
	// аккаунта и «отмывали» внешний грант из отчёта о дрифте.
	AdoptBindings bool `json:"adopt_bindings,omitempty"`
	// Adopt — операция credential.rotate принимает существующий
	// unmanaged-аккаунт под управление (POST /accounts/{id}/adopt).
	// Семантика флага — «на успехе перевести ownership в managed» и
	// «разрешить ротацию ещё-не-managed аккаунта»; он ортогонален источнику
	// пароля (см. AdoptGenerate). Флаг несекретен.
	Adopt bool `json:"adopt,omitempty"`
	// AdoptGenerate — при Adopt пароль не предзаписан API-слоем, а
	// генерируется самим executor'ом adapter-генератором (adopt mode=generate,
	// POST /accounts/{id}/adopt). Без флага (adopt mode=password) executor
	// применяет ПОСЛЕДНЮЮ версию секрета accounts/<id>/credential, записанную
	// API-слоем. Разделение Adopt (переход ownership) и AdoptGenerate
	// (источник пароля) сохраняет password-режим побайтово: у него
	// AdoptGenerate=false и omitempty опускает поле. Флаг несекретен.
	AdoptGenerate bool `json:"adopt_generate,omitempty"`
	// Reason — необязательная причина удаления аккаунта (только
	// account.delete): свободный текст оператора либо автотекст каскада
	// offboard. Не секрет — обычный пользовательский текст, прошедший
	// валидацию API (trim, <= 500 символов); на успехе операции пишется в
	// accounts.delete_reason и попадает в audit metadata. omitempty
	// сохраняет payload остальных account-операций побайтово.
	Reason string `json:"reason,omitempty"`
}

// rotateSource — источник пароля операции credential.rotate; вычисляется
// из payload чистой функцией rotateCredentialSource.
type rotateSource string

const (
	// rotateSourceShared — общий секрет принципала: версию уже записал
	// API-слой по SharedCredentialPath, executor только читает и применяет.
	rotateSourceShared rotateSource = "shared"
	// rotateSourceAdopt — adopt существующего аккаунта: версию по
	// accounts/<id>/credential уже записал API-слой, executor читает
	// последнюю версию и применяет её (генерации нет).
	rotateSourceAdopt rotateSource = "adopt"
	// rotateSourceGenerate — обычная per-account ротация: executor
	// генерирует новый секрет adapter'ом и записывает его в Vault сам.
	rotateSourceGenerate rotateSource = "generate"
)

// rotateCredentialSource решает, откуда credential.rotate берёт пароль.
// SharedCredentialPath имеет приоритет над Adopt: у adopt-операций API
// общий путь не задаёт, а защита от рассинхронизации паролей принципала
// важнее. Adopt+AdoptGenerate (adopt mode=generate) выбирает generate-источник
// (executor сам генерирует пароль), при этом переход ownership обеспечивает
// отдельный флаг Adopt — источник и переход ортогональны. Adopt без
// AdoptGenerate (adopt mode=password) читает предзаписанную версию. Чистая
// функция — тестируется без БД и Vault.
func rotateCredentialSource(p AccountPayload) rotateSource {
	switch {
	case p.SharedCredentialPath != "":
		return rotateSourceShared
	case p.Adopt && !p.AdoptGenerate:
		return rotateSourceAdopt
	default:
		return rotateSourceGenerate
	}
}

// decodeAccessPayload разбирает payload access-операции.
func decodeAccessPayload(raw []byte) (AccessPayload, error) {
	var p AccessPayload
	// Payload операции неизменяем: повтор разберёт те же байты и упадёт так
	// же, поэтому ошибка разбора — детерминированный отказ (terminal.go).
	if err := json.Unmarshal(raw, &p); err != nil {
		return AccessPayload{}, terminal(fmt.Errorf("decode access payload: %w", err))
	}
	if p.BindingID == uuid.Nil {
		return AccessPayload{}, terminal(errors.New("decode access payload: binding_id is not set"))
	}
	return p, nil
}

func validateAccessIntent(kind adapter.ChangeKind, payload AccessPayload, binding inventory.Binding) error {
	if binding.TransitionOperationID != nil {
		return terminal(fmt.Errorf(
			"binding %s is owned by access replacement %s: %w",
			binding.ID, *binding.TransitionOperationID, inventory.ErrBindingTransitionConflict))
	}
	if payload.ExpectedPermissionDefinitionID != uuid.Nil &&
		binding.PermissionDefinitionID != payload.ExpectedPermissionDefinitionID {
		return terminal(fmt.Errorf(
			"binding %s permission changed from expected %s to %s: %w",
			binding.ID, payload.ExpectedPermissionDefinitionID, binding.PermissionDefinitionID,
			inventory.ErrBindingTransitionConflict))
	}
	expected := payload.ExpectedDesiredState
	if expected == "" {
		switch kind {
		case adapter.ChangeGrant:
			expected = string(inventory.BindingPresent)
		case adapter.ChangeRevoke:
			expected = string(inventory.BindingAbsent)
		}
	}
	if binding.DesiredState == nil || string(*binding.DesiredState) != expected {
		return terminal(fmt.Errorf(
			"binding %s desired state changed from expected %q: %w",
			binding.ID, expected, inventory.ErrBindingTransitionConflict))
	}
	return nil
}

func validatePinnedPermissionAttributes(pinned map[string]any, permission inventory.Permission) error {
	if pinned == nil {
		return nil
	}
	var current map[string]any
	if err := json.Unmarshal(permission.Attributes, &current); err != nil {
		return terminal(fmt.Errorf("decode current permission attributes: %w", err))
	}
	if !reflect.DeepEqual(current, pinned) {
		return terminal(fmt.Errorf(
			"permission %s changed after operation enqueue: %w",
			permission.ID, inventory.ErrBindingTransitionConflict))
	}
	return nil
}

func decodeAccessReplacePayload(raw []byte) (AccessReplacePayload, error) {
	var p AccessReplacePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return AccessReplacePayload{}, terminal(fmt.Errorf("decode access replace payload: %w", err))
	}
	switch {
	case p.BindingID == uuid.Nil:
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: binding_id is not set"))
	case p.FromPermissionDefinitionID == uuid.Nil:
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: from_permission_definition_id is not set"))
	case p.ToPermissionDefinitionID == uuid.Nil:
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: to_permission_definition_id is not set"))
	case p.FromPermissionDefinitionID == p.ToPermissionDefinitionID:
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: from and to permissions are equal"))
	case p.AssignmentKey == "":
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: assignment_key is empty"))
	case p.ExpectedBindingVersion <= 0:
		return AccessReplacePayload{}, terminal(errors.New("decode access replace payload: expected_binding_version must be positive"))
	}
	return p, nil
}

// decodeAccountPayload разбирает payload account-операции.
func decodeAccountPayload(raw []byte) (AccountPayload, error) {
	var p AccountPayload
	// См. decodeAccessPayload: неизменяемый payload делает ошибку разбора
	// детерминированной.
	if err := json.Unmarshal(raw, &p); err != nil {
		return AccountPayload{}, terminal(fmt.Errorf("decode account payload: %w", err))
	}
	if p.AccountID == uuid.Nil {
		return AccountPayload{}, terminal(errors.New("decode account payload: account_id is not set"))
	}
	return p, nil
}

// marshalPlan строит sanitized json плана. Проекция и marshaling живут в
// internal/connector (MarshalSanitizedPlan): та же форма уходит в
// JobResult.Plan connector-исполнения, поэтому artifact операции одинаков в
// обоих режимах.
func marshalPlan(plan *adapter.Plan) ([]byte, error) {
	return connector.MarshalSanitizedPlan(plan)
}

// marshalResult строит sanitized json результата применения (см. marshalPlan
// о общей проекции с connector-исполнением).
func marshalResult(res *adapter.Result, ver *adapter.Verification) ([]byte, error) {
	return connector.MarshalSanitizedResult(res, ver)
}

// adapterAccount строит adapter.Account из строки инвентаря.
func adapterAccount(a inventory.Account) adapter.Account {
	return adapter.Account{
		Kind:                a.Kind,
		EngineIdentity:      a.EngineIdentity,
		AuthenticationScope: a.AuthenticationScope,
	}
}

// accountLifecycleExpectation проверяет зарезервированную версию и
// допустимое исходное состояние. Legacy payload без expected_status получает
// строгую state-machine семантику по kind, сохраняя совместимость поколения 0.
func accountLifecycleExpectation(acct inventory.Account, payload AccountPayload, kind adapter.ChangeKind) (inventory.AccountStatus, bool, error) {
	if acct.LifecycleVersion != payload.ExpectedLifecycleVersion {
		return "", false, inventory.CheckAccountLifecycle(acct, payload.ExpectedStatus, payload.ExpectedLifecycleVersion)
	}
	expected := payload.ExpectedStatus
	if expected != "" {
		if acct.Status == expected {
			return expected, false, nil
		}
		final := inventory.AccountStatus("")
		switch kind {
		case adapter.ChangeAccountDisable:
			final = inventory.AccountDisabled
		// account.create ведёт из provisioning/missing в active: повтор
		// уже применённого create (дубль job, восстановление после crash
		// между commit metadata и завершением операции) обязан быть no-op,
		// а не конфликтом статуса.
		case adapter.ChangeAccountCreate, adapter.ChangeRoleCreate,
			adapter.ChangeAccountEnable, adapter.ChangeAccountRestore:
			final = inventory.AccountActive
		case adapter.ChangeAccountDelete:
			final = inventory.AccountDeleted
		}
		if final != "" && acct.Status == final {
			return expected, true, nil
		}
		return "", false, inventory.CheckAccountLifecycle(acct, expected, payload.ExpectedLifecycleVersion)
	}

	switch kind {
	case adapter.ChangeAccountCreate:
		expected = inventory.AccountActive
	case adapter.ChangeAccountDisable:
		expected = inventory.AccountActive
	case adapter.ChangeAccountEnable:
		expected = inventory.AccountDisabled
	case adapter.ChangeAccountDelete:
		// Удалять можно и не подтверждённую (provisioning), и исчезнувшую с
		// target (missing) учётку: drop на целевой системе идемпотентен, а
		// tombstone метаданных нужен в обоих случаях (offboard принципала).
		if acct.Status != inventory.AccountDeleted {
			expected = acct.Status
		} else {
			return "", false, fmt.Errorf("account %s status %q cannot be deleted: %w",
				acct.ID, acct.Status, inventory.ErrAccountStatusConflict)
		}
	case adapter.ChangeAccountRestore:
		expected = inventory.AccountDeleted
	default:
		return "", false, fmt.Errorf("unsupported account lifecycle change %q", kind)
	}
	if err := inventory.CheckAccountLifecycle(acct, expected, payload.ExpectedLifecycleVersion); err != nil {
		return "", false, err
	}
	return expected, false, nil
}

// mutationTarget загружает connection мутации, решает режим исполнения
// (routing — до любых обращений к Vault/target) и строит adapter.Connection
// с admin credential из Vault (worker читает его в ОБОИХ режимах, ADR-0014:
// в connector-режиме секрет уходит кадром TypeCredentials, а не в payload).
// Для прямого исполнения дополнительно возвращается adapter по engine; для
// connector-режима (viaConnector=true) adapter не нужен: полный поток
// мутации исполняет connector. Мутации выполняются только на активном
// подключении: на degraded/stale состоянии destructive-действия запрещены
// (раздел 8 архитектуры).
func (e *MainExecutor) mutationTarget(ctx context.Context, kind string, connectionID uuid.UUID) (connections.Connection, adapter.Connection, adapter.Adapter, bool, error) {
	fail := func(err error) (connections.Connection, adapter.Connection, adapter.Adapter, bool, error) {
		return connections.Connection{}, adapter.Connection{}, nil, false, err
	}
	conn, err := e.deps.Connections.Get(ctx, e.deps.Pool, connectionID)
	if err != nil {
		return fail(err)
	}
	if conn.AuthMode == "none" {
		return fail(fmt.Errorf("authentication_disabled: %s is unavailable: %w", kind, adapter.ErrUnsupportedChange))
	}
	if kind == KindCredentialRotate && !slices.Contains(connections.EffectiveCapabilities(conn, conn.Capabilities), string(adapter.CapCredentialRotate)) {
		return fail(fmt.Errorf("credential rotation is unavailable for connection %s: %w", conn.ID, adapter.ErrUnsupportedChange))
	}
	viaConnector, err := connectorRoute(conn.ExecutionMode, kind, e.conn.Dispatcher != nil)
	if err != nil {
		return fail(fmt.Errorf("connection %s: %w", conn.ID, err))
	}
	if conn.Status != connections.StatusActive {
		return fail(fmt.Errorf("connection %s: status %q does not allow mutations", conn.ID, conn.Status))
	}
	cfg, err := adapterConnection(conn)
	if err != nil {
		return fail(err)
	}
	if err := e.applyAdminCredential(ctx, conn, &cfg); err != nil {
		return fail(fmt.Errorf("connection %s: %w", conn.ID, err))
	}
	if viaConnector {
		return conn, cfg, nil, true, nil
	}
	ad, err := adapter.New(conn.Engine)
	if err != nil {
		return fail(err)
	}
	return conn, cfg, ad, false, nil
}

// managedLinkProofAdapter возвращает adapter, по capability и optional
// CredentialProver которого worker проверяет link-and-manage до ротации.
//
// В direct-режиме mutationTarget уже вернул исполняющий adapter. В connector-
// режиме он намеренно возвращает nil: target-операцию исполняет agent внутри
// изолированного сегмента. Для control-plane guard всё равно нужен локальный
// engine adapter — только чтобы проверить тот же manifest/interface contract;
// target, Vault и routing эта функция не затрагивает.
func managedLinkProofAdapter(engine string, direct adapter.Adapter, viaConnector bool) (adapter.Adapter, error) {
	if !viaConnector {
		return direct, nil
	}
	return adapter.New(engine)
}

// planApplyVerify выполняет общий adapter-поток мутации: Plan -> Apply ->
// Verify, сохраняя sanitized plan/result в артефакты операции. Sanitized plan
// сохраняется до Apply (чтобы попасть в operations и при падении применения),
// result — после Apply. Шаг со статусом failed и непройденный verify —
// ошибки.
func (e *MainExecutor) planApplyVerify(ctx context.Context, opID uuid.UUID, ad adapter.Adapter, change adapter.DesiredChange) (*adapter.Verification, error) {
	return e.planApplyVerifyArtifacts(ctx, opID, ad, change, true)
}

// planApplyVerifyArtifacts — planApplyVerify с управлением артефактами.
// artifacts=false нужен вспомогательным изменениям внутри операции (например
// восстановлению грантов внутри account.enable): артефакты операции обязаны
// описывать саму операцию, а не последнее из её вспомогательных изменений,
// которое иначе затёрло бы их в общей карте по op.ID.
func (e *MainExecutor) planApplyVerifyArtifacts(ctx context.Context, opID uuid.UUID,
	ad adapter.Adapter, change adapter.DesiredChange, artifacts bool) (*adapter.Verification, error) {
	plan, err := ad.Plan(ctx, change)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	planBytes, err := marshalPlan(plan)
	if err != nil {
		return nil, fmt.Errorf("marshal plan: %w", err)
	}
	if artifacts {
		e.setPlanArtifact(opID, planBytes)
	}

	res, err := ad.Apply(ctx, *plan)
	if err != nil {
		return nil, fmt.Errorf("apply: %w", err)
	}
	resultBytes, err := marshalResult(res, nil)
	if err != nil {
		return nil, fmt.Errorf("marshal result: %w", err)
	}
	if artifacts {
		e.setResultArtifact(opID, resultBytes)
	}
	for _, step := range res.Steps {
		if step.Status == adapter.StepFailed {
			return nil, fmt.Errorf("apply: step %q failed: %s", step.Step.Kind, step.Error)
		}
	}

	ver, err := ad.Verify(ctx, *plan)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	if resultBytes, err = marshalResult(res, ver); err == nil && artifacts {
		e.setResultArtifact(opID, resultBytes)
	}
	if !ver.Verified {
		return nil, fmt.Errorf("verify: target state is not verified: %s", ver.Details)
	}
	return ver, nil
}

// executeAccessChange выполняет grant или revoke binding: строит
// DesiredChange по строкам инвентаря, прогоняет adapter-поток и в одной
// транзакции записывает observed state binding и audit-событие.
func (e *MainExecutor) executeAccessChange(ctx context.Context, op operations.Operation, kind adapter.ChangeKind) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccessPayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	binding, err := e.deps.Inventory.GetBinding(ctx, e.deps.Pool, payload.BindingID)
	if err != nil {
		// Идемпотентность revoke: строки bindings физически удаляются только
		// soft delete аккаунта (MarkAccountDeleted) — если binding уже
		// исчез, аккаунт удалён из целевой системы и отзывать нечего,
		// доступ гарантированно отсутствует. Это штатная гонка внутри
		// offboard-parent (access.revoke и account.delete одного аккаунта
		// сериализуются advisory lock по connection, но порядок захвата
		// lock при нескольких workers не гарантирован) и вообще любого
		// pending revoke, чей аккаунт удалили параллельно. Фиксируем no-op
		// успех с меткой в audit вместо вечно падающего retry.
		if kind == adapter.ChangeRevoke && errors.Is(err, inventory.ErrNotFound) {
			// После restore тот же tombstone ID получает новое lifecycle-
			// поколение. Старый revoke не должен превратиться в no-op лишь
			// потому, что исторический binding уже удалён: сначала доказываем,
			// что job относится к текущему поколению аккаунта.
			if op.AccountID == nil {
				return wrap(errors.New("missing binding revoke has no account lifecycle context"))
			}
			acct, accountErr := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, *op.AccountID)
			if accountErr != nil {
				return wrap(accountErr)
			}
			if accountErr = inventory.CheckAccountLifecycle(acct, "", payload.ExpectedAccountLifecycleVersion); accountErr != nil {
				return wrap(accountErr)
			}
			return e.recordRevokeNoop(ctx, op, payload.BindingID, wrap)
		}
		return wrap(err)
	}
	if err := validateAccessIntent(kind, payload, binding); err != nil {
		return wrap(err)
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, binding.AccountID)
	if err != nil {
		return wrap(err)
	}
	if err := inventory.CheckAccountLifecycle(acct, "", payload.ExpectedAccountLifecycleVersion); err != nil {
		return wrap(err)
	}
	if acct.Status == inventory.AccountDeleted {
		return wrap(fmt.Errorf("account %s is deleted: %w", acct.ID, inventory.ErrAccountStatusConflict))
	}
	perm, err := e.deps.Inventory.GetPermission(ctx, e.deps.Pool, binding.PermissionDefinitionID)
	if err != nil {
		return wrap(err)
	}
	if err := validatePinnedPermissionAttributes(payload.PermissionAttributes, perm); err != nil {
		return wrap(err)
	}
	statsOperation := op.Kind == KindPostgresStatsGrantV1 || op.Kind == KindPostgresStatsRevokeV1
	objectOperation := IsPostgresObjectPermission(perm)
	if objectOperation != (payload.ObjectACL != nil) || objectOperation != (op.Kind == KindPostgresObjectACLGrantV1 || op.Kind == KindPostgresObjectACLRevokeV1) {
		return wrap(terminal(adapter.ErrPostgresObjectACL))
	}
	if objectOperation {
		if err := e.preflightObjectACLConnector(ctx, op.Kind, acct.ConnectionID); err != nil {
			return wrap(err)
		}
	}
	if IsPostgresStatsPermission(perm) != statsOperation {
		return wrap(terminal(postgres.ErrStatsMembershipUnsupported))
	}
	if statsOperation {
		if err := e.preflightStatsMembershipConnector(ctx, op.Kind, acct.ConnectionID); err != nil {
			return wrap(err)
		}
		if err := e.resolveStatsMembershipSubject(ctx, payload, acct); err != nil {
			return wrap(err)
		}
	}
	// Defense in depth: основной dangerous-контроль на API, но payload
	// операции обязан нести подтверждение — операция, созданная в обход
	// API-проверки, здесь откажет.
	if kind == adapter.ChangeGrant && perm.Dangerous && !payload.Confirmed {
		return wrap(fmt.Errorf("dangerous permission %q requires confirmed payload", perm.ExternalID))
	}
	scope := ""
	if binding.ScopeResourceID != nil {
		res, err := e.deps.Inventory.GetResource(ctx, e.deps.Pool, *binding.ScopeResourceID)
		if err != nil {
			return wrap(err)
		}
		scope = res.ExternalID
	}

	// Desired-состояние доступов аккаунта после этого изменения: адаптеры
	// движков, где права аккаунта — единый неделимый набор правил (Redis),
	// перестраивают набор по нему, а не по реконструкции из движка.
	accountPerms, err := e.accountPermissionsAfter(ctx, acct.ID, binding, perm, kind)
	if err != nil {
		return wrap(err)
	}

	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return wrap(err)
	}
	actions := changeAuditActions[kind]
	var membershipAttributes = payload.PermissionAttributes
	mutationKind := kind
	var statsMembership *adapter.PostgresStatsMembershipPins
	var expectedAdmin, expectedTarget string
	if objectOperation {
		pins := payload.ObjectACL
		if err := validatePostgresRuntimePins(conn, cfg, pins.AdminIdentity, pins.TargetIdentity, pins.ConfigIncarnation, pins.CredentialIncarnation); err != nil {
			return wrap(err)
		}
		mutationKind = adapter.ChangePostgresObjectACLGrantV1
		if kind == adapter.ChangeRevoke {
			mutationKind = adapter.ChangePostgresObjectACLRevokeV1
		}
		membershipAttributes, accountPerms = nil, nil
		expectedAdmin, expectedTarget = pins.AdminIdentity, pins.TargetIdentity
	}
	if statsOperation {
		pins := payload.StatsMembership
		if err := validatePostgresRuntimePins(conn, cfg, pins.AdminIdentity, pins.TargetIdentity, pins.ConfigIncarnation, pins.CredentialIncarnation); err != nil {
			return wrap(err)
		}
		mutationKind = adapter.ChangePostgresStatsMembershipGrantV1
		if kind == adapter.ChangeRevoke {
			mutationKind = adapter.ChangePostgresStatsMembershipRevokeV1
		}
		membershipAttributes, accountPerms = nil, nil
		statsMembership = pins
		expectedAdmin, expectedTarget = pins.AdminIdentity, pins.TargetIdentity
	}

	var ver *adapter.Verification
	if viaConnector {
		change := connector.ChangeRef{
			Kind:               string(mutationKind),
			Account:            connectorAccountRef(acct),
			Permission:         perm.ExternalID,
			Scope:              scope,
			AccountPermissions: accountPerms,
			Attributes:         payload.PermissionAttributes,
		}
		if statsOperation {
			change.AccountPermissions = nil
			change.Attributes = nil
			change.StatsMembership = payload.StatsMembership
			change.ExpectedAdminIdentity = payload.StatsMembership.AdminIdentity
			change.ExpectedTargetIdentity = payload.StatsMembership.TargetIdentity
		}
		if objectOperation {
			change.AccountPermissions, change.Attributes = nil, nil
			change.ObjectACL = payload.ObjectACL
			change.ExpectedAdminIdentity, change.ExpectedTargetIdentity = expectedAdmin, expectedTarget
		}
		ver, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, change, connectorJobCredentials(cfg))
	} else {
		ver, err = e.planApplyVerify(ctx, op.ID, ad, adapter.DesiredChange{
			Kind:                   mutationKind,
			Connection:             cfg,
			Account:                adapterAccount(acct),
			Permission:             perm.ExternalID,
			Scope:                  scope,
			AccountPermissions:     accountPerms,
			Attributes:             membershipAttributes,
			StatsMembership:        statsMembership,
			ObjectACL:              payload.ObjectACL,
			ExpectedAdminIdentity:  expectedAdmin,
			ExpectedTargetIdentity: expectedTarget,
		})
	}
	// Inventory-only цель: revoke на движке, который фундаментально не
	// поддерживает мутацию (adapter.ErrUnsupportedChange), не может оставить
	// грант на таргете — его там и нет. Снятие метаданных grantor —
	// корректный терминальный исход (иначе revoke вечно ретраится). Только
	// для удаляющего направления; grant с unsupported остаётся ошибкой.
	// Универсально по типу ошибки, без engine-условий.
	targetUnsupported := false
	if err != nil {
		if kind == adapter.ChangeRevoke && !statsOperation && !objectOperation && errors.Is(err, adapter.ErrUnsupportedChange) {
			targetUnsupported = true
			ver = nil
		} else {
			err = wrap(err)
			if recordErr := e.recordAccessMutationFailure(
				ctx, op, conn.ID, acct.ID, binding, kind, actions.failure, err,
			); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
	}

	observed := inventory.BindingPresent
	desired := inventory.BindingPresent
	if kind == adapter.ChangeRevoke {
		observed = inventory.BindingAbsent
		desired = inventory.BindingAbsent
	}
	var pinnedAttributes json.RawMessage
	if payload.PermissionAttributes != nil {
		pinnedAttributes, err = json.Marshal(payload.PermissionAttributes)
		if err != nil {
			return wrap(fmt.Errorf("marshal pinned permission attributes: %w", err))
		}
	}
	if objectOperation {
		if ver == nil || !ver.Verified || ver.Observed == nil {
			return wrap(adapter.ErrExternalIdentityConflict)
		}
		pinnedAttributes, err = json.Marshal(ver.Observed)
		if err != nil {
			return wrap(err)
		}
	}
	verDetails := ""
	if ver != nil {
		verDetails = ver.Details
	}
	metadata, err := json.Marshal(map[string]any{
		"binding_id":         binding.ID,
		"account":            acct.EngineIdentity,
		"permission":         perm.ExternalID,
		"scope":              scope,
		"verification":       verDetails,
		"target_unsupported": targetUnsupported,
	})
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	return e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, actions.success, metadata, wrap,
		func(tx pgx.Tx) error {
			_, err := e.deps.Inventory.SetBindingResultExpected(
				ctx, tx, binding.ID, perm.ID, desired, observed, pinnedAttributes,
			)
			return err
		})
}

type accessReplacementState int

const (
	accessReplacementPending accessReplacementState = iota
	accessReplacementCompleted
)

// classifyAccessReplacement проверяет durable transition owner и монотонную
// версию до любого target side effect. Completed нужен crash-window после
// metadata commit, но до финального commit статуса operation: retry завершает
// операцию как success без второго обращения к target. Любое иное состояние —
// stale payload и детерминированный fail-closed.
func classifyAccessReplacement(opID uuid.UUID, p AccessReplacePayload, b inventory.Binding) (accessReplacementState, error) {
	desiredPresent := b.DesiredState != nil && *b.DesiredState == inventory.BindingPresent
	if b.TransitionOperationID != nil && *b.TransitionOperationID == opID &&
		b.Version == p.ExpectedBindingVersion &&
		b.PermissionDefinitionID == p.ToPermissionDefinitionID &&
		b.AssignmentKey == p.AssignmentKey && desiredPresent {
		return accessReplacementPending, nil
	}
	observedTo := b.ObservedPermissionDefinitionID != nil &&
		*b.ObservedPermissionDefinitionID == p.ToPermissionDefinitionID
	if b.TransitionOperationID == nil &&
		b.Version == p.ExpectedBindingVersion+1 &&
		b.PermissionDefinitionID == p.ToPermissionDefinitionID &&
		b.AssignmentKey == p.AssignmentKey && desiredPresent &&
		b.ObservedState == inventory.BindingPresent && b.ObservedEffective && observedTo &&
		b.Status == inventory.BindingStatusSynced {
		return accessReplacementCompleted, nil
	}
	return accessReplacementPending, terminal(fmt.Errorf(
		"access replacement binding %s no longer belongs to operation %s at version %d",
		b.ID, opID, p.ExpectedBindingVersion))
}

func accessReplacementTransition(opID uuid.UUID, p AccessReplacePayload) inventory.AccessReplacementTransition {
	var attributes json.RawMessage
	if p.PermissionAttributes != nil {
		attributes, _ = json.Marshal(p.PermissionAttributes)
	}
	return inventory.AccessReplacementTransition{
		BindingID:          p.BindingID,
		OperationID:        opID,
		FromPermissionID:   p.FromPermissionDefinitionID,
		ToPermissionID:     p.ToPermissionDefinitionID,
		AssignmentKey:      p.AssignmentKey,
		ExpectedVersion:    p.ExpectedBindingVersion,
		ExpectedAttributes: attributes,
	}
}

// executeAccessReplace атомарно меняет один exclusive assignment A -> B.
// Adapter получает ровно ChangeGrant(B): для RabbitMQ это один idempotent PUT
// полной configure/write/read тройки и никогда DELETE/Revoke между шаблонами.
func (e *MainExecutor) executeAccessReplace(ctx context.Context, op operations.Operation) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccessReplacePayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	binding, err := e.deps.Inventory.GetBinding(ctx, e.deps.Pool, payload.BindingID)
	if err != nil {
		return wrap(err)
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, binding.AccountID)
	if err != nil {
		return wrap(err)
	}
	if err := inventory.CheckAccountLifecycle(acct, "", payload.ExpectedAccountLifecycleVersion); err != nil {
		return wrap(err)
	}
	if acct.Status == inventory.AccountDeleted {
		return wrap(fmt.Errorf("account %s is deleted: %w", acct.ID, inventory.ErrAccountStatusConflict))
	}
	state, err := classifyAccessReplacement(op.ID, payload, binding)
	if err != nil {
		return wrap(err)
	}
	if state == accessReplacementCompleted {
		return nil
	}

	fromPerm, err := e.deps.Inventory.GetPermission(ctx, e.deps.Pool, payload.FromPermissionDefinitionID)
	if err != nil {
		return wrap(err)
	}
	toPerm, err := e.deps.Inventory.GetPermission(ctx, e.deps.Pool, payload.ToPermissionDefinitionID)
	if err != nil {
		return wrap(err)
	}
	if err := validatePinnedPermissionAttributes(payload.PermissionAttributes, toPerm); err != nil {
		return wrap(err)
	}
	if fromPerm.AssignmentKey != payload.AssignmentKey || toPerm.AssignmentKey != payload.AssignmentKey {
		return wrap(terminal(fmt.Errorf("access replacement assignment key %q does not match pinned permissions", payload.AssignmentKey)))
	}
	if toPerm.Dangerous && !payload.Confirmed {
		return wrap(fmt.Errorf("dangerous permission %q requires confirmed payload", toPerm.ExternalID))
	}

	scope := ""
	if binding.ScopeResourceID != nil {
		res, err := e.deps.Inventory.GetResource(ctx, e.deps.Pool, *binding.ScopeResourceID)
		if err != nil {
			return wrap(err)
		}
		scope = res.ExternalID
	}
	accountPerms, err := e.accountPermissionsAfter(ctx, acct.ID, binding, toPerm, adapter.ChangeGrant)
	if err != nil {
		return wrap(err)
	}

	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return wrap(err)
	}
	if payload.ExpectedTargetIdentity != "" {
		actualIdentity := connections.TargetIdentity(conn)
		if actualIdentity != payload.ExpectedTargetIdentity {
			return wrap(terminal(fmt.Errorf(
				"connection target identity changed from %q to %q: %w",
				payload.ExpectedTargetIdentity, actualIdentity, inventory.ErrBindingTransitionConflict)))
		}
	}
	if payload.ReverseOfOperationID != uuid.Nil {
		if err := validatePinnedPermissionAttributes(payload.ConvergePermissionAttributes, fromPerm); err != nil {
			return wrap(err)
		}
		convergePerms, err := e.accountPermissionsAfter(
			ctx, acct.ID, binding, fromPerm, adapter.ChangeGrant,
		)
		if err != nil {
			return wrap(err)
		}
		if viaConnector {
			_, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, connector.ChangeRef{
				Kind: string(adapter.ChangeGrant), Account: connectorAccountRef(acct),
				Permission: fromPerm.ExternalID, Scope: scope,
				AccountPermissions: convergePerms,
				Attributes:         payload.ConvergePermissionAttributes,
			}, connectorJobCredentials(cfg))
		} else {
			_, err = e.planApplyVerify(ctx, op.ID, ad, adapter.DesiredChange{
				Kind: adapter.ChangeGrant, Connection: cfg, Account: adapterAccount(acct),
				Permission: fromPerm.ExternalID, Scope: scope,
				AccountPermissions: convergePerms,
				Attributes:         payload.ConvergePermissionAttributes,
			})
		}
		if err != nil {
			err = wrap(fmt.Errorf("converge failed replacement target before reverse: %w", err))
			if recordErr := e.recordAccessReplacementFailure(ctx, op, conn.ID, acct.ID, payload, err); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
	}
	var ver *adapter.Verification
	if viaConnector {
		ver, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, connector.ChangeRef{
			Kind:               string(adapter.ChangeGrant),
			Account:            connectorAccountRef(acct),
			Permission:         toPerm.ExternalID,
			Scope:              scope,
			AccountPermissions: accountPerms,
			Attributes:         payload.PermissionAttributes,
		}, connectorJobCredentials(cfg))
	} else {
		ver, err = e.planApplyVerify(ctx, op.ID, ad, adapter.DesiredChange{
			Kind:               adapter.ChangeGrant,
			Connection:         cfg,
			Account:            adapterAccount(acct),
			Permission:         toPerm.ExternalID,
			Scope:              scope,
			AccountPermissions: accountPerms,
			Attributes:         payload.PermissionAttributes,
		})
	}
	if err != nil {
		err = wrap(err)
		if recordErr := e.recordAccessReplacementFailure(ctx, op, conn.ID, acct.ID, payload, err); recordErr != nil {
			return errors.Join(err, recordErr)
		}
		return err
	}

	metadataFields := map[string]any{
		"binding_id":     binding.ID,
		"account":        acct.EngineIdentity,
		"from":           fromPerm.ExternalID,
		"to":             toPerm.ExternalID,
		"assignment_key": payload.AssignmentKey,
		"scope":          scope,
		"verification":   ver.Details,
	}
	if payload.ReverseOfOperationID != uuid.Nil {
		metadataFields["reverse_of"] = payload.ReverseOfOperationID
	}
	metadata, err := json.Marshal(metadataFields)
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	transition := accessReplacementTransition(op.ID, payload)
	return e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, auditActionAccessReplaced, metadata, wrap,
		func(tx pgx.Tx) error {
			_, err := e.deps.Inventory.CompleteAccessReplacement(ctx, tx, transition)
			return err
		})
}

// accountPermissionsAfter возвращает desired-набор external id назначаемых
// permissions аккаунта в том же scope, каким он обязан стать ПОСЛЕ применения
// изменения: bindings grantor с desired_state=present, плюс выдаваемый
// permission (grant) либо минус отзываемый (revoke). Порядок детерминирован.
//
// Набор передаётся адаптеру в adapter.DesiredChange.AccountPermissions. Он
// нужен движкам, где права аккаунта не независимы, а являются единым набором
// правил: отзыв одного права там переписывает весь набор, и переписывать его
// нужно по desired-состоянию control plane, иначе остальные права аккаунта
// теряются вместе с отзываемым (см. internal/adapters/redis).
//
// Учитываются только bindings того же scope (сравнение по scope_resource_id,
// без разрешения имён ресурсов) и только назначаемые permissions: observed
// permissions движка не назначаемы и целевым набором не управляются.
// В набор входят и обнаруженные, но не принятые под управление права
// (desired_state IS NULL при observed_state = present). Это не «желаемое»
// состояние в смысле control plane, но для движка с единым набором правил
// исключить их означает стереть реально существующий доступ выдачей
// соседнего права — при том что grantor решения снимать его не принимал.
// Права, которые grantor осознанно решил убрать (desired_state = absent), в
// набор не входят даже когда движок их ещё показывает: это дрифт, и целевое
// состояние здесь — их отсутствие.
func (e *MainExecutor) accountPermissionsAfter(
	ctx context.Context,
	accountID uuid.UUID,
	binding inventory.Binding,
	perm inventory.Permission,
	kind adapter.ChangeKind,
) ([]string, error) {
	bindings, err := e.deps.Inventory.ListBindingsByAccount(ctx, e.deps.Pool, accountID)
	if err != nil {
		return nil, err
	}
	perms, err := e.deps.Inventory.ListPermissions(ctx, e.deps.Pool, perm.ConnectionID)
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]inventory.Permission, len(perms))
	for _, p := range perms {
		byID[p.ID] = p
	}

	set := map[string]struct{}{}
	for _, b := range bindings {
		if b.ID == binding.ID || !sameScope(b.ScopeResourceID, binding.ScopeResourceID) {
			continue
		}
		switch {
		case b.DesiredState != nil && *b.DesiredState == inventory.BindingPresent:
			// Управляемое право: остаётся в наборе.
		case b.DesiredState == nil && b.ObservedState == inventory.BindingPresent:
			// Непринятое, но реально существующее: сохраняем, иначе выдача
			// соседнего права молча уничтожит его.
		default:
			continue
		}
		if p, ok := byID[b.PermissionDefinitionID]; ok && p.Assignable {
			set[p.ExternalID] = struct{}{}
		}
	}
	if kind == adapter.ChangeGrant {
		set[perm.ExternalID] = struct{}{}
	} else {
		delete(set, perm.ExternalID)
	}

	// Не nil даже для пустого набора: nil означает «ядро desired-состояние не
	// передало», и адаптер тогда деградирует до реконструкции из движка.
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

// sameScope сравнивает scope двух bindings: оба cluster-wide либо оба ссылаются
// на один ресурс.
func sameScope(a, b *uuid.UUID) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// recordRevokeNoop фиксирует no-op успех access.revoke, чей binding уже
// удалён вместе с аккаунтом (см. executeAccessChange): audit-событие
// access.revoked с маркером noop и result-артефакт без обращения к целевой
// системе. Целевая система не трогается: роль аккаунта уже удалена
// account.delete, отдельного отзыва не существует.
func (e *MainExecutor) recordRevokeNoop(ctx context.Context, op operations.Operation, bindingID uuid.UUID, wrap func(error) error) error {
	result, err := json.Marshal(map[string]any{
		"noop":   true,
		"reason": "binding is already deleted with its account",
	})
	if err != nil {
		return wrap(fmt.Errorf("marshal result: %w", err))
	}
	e.setResultArtifact(op.ID, result)
	metadata, err := json.Marshal(map[string]any{
		"binding_id": bindingID,
		"noop":       true,
		"reason":     "binding is already deleted with its account",
	})
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	var connectionID uuid.UUID
	if op.ConnectionID != nil {
		connectionID = *op.ConnectionID
	}
	return e.recordMutationSuccess(ctx, op, connectionID, op.AccountID, auditActionAccessRevoked, metadata, wrap,
		func(pgx.Tx) error { return nil })
}

// executeAccountChange выполняет lifecycle-операцию managed-аккаунта:
// create/disable/enable/delete. Для create credential читается из Vault
// (учётка и секрет уже созданы API), остальные операции секретов не
// требуют.
//
// account.create стартует с аккаунта в статусе provisioning (или missing —
// повторный провижининг исчезнувшей учётки) и переводит его в active
// ТОЛЬКО после успешных Apply и Verify адаптера. Неуспех статус не меняет:
// аккаунт остаётся не-живым, поэтому не попадает в ротацию и прочие
// массовые операции принципала, виден в дрифте и переиспользуется
// повторной попыткой вместо создания второй строки.
//
// Источник пароля для create определяется payload:
//   - SharedCredentialPath задан — общий секрет принципала (модель
//     shared-per-principal-per-environment): пароль читается из этого пути,
//     username берётся из engine_identity аккаунта. Так несколько аккаунтов
//     одного принципала в окружении логинятся одним паролем;
//   - иначе (одиночное создание через POST /accounts) — секрет читается по
//     пути аккаунта accounts/<id>/credential.
func (e *MainExecutor) executeAccountChange(ctx context.Context, op operations.Operation, kind adapter.ChangeKind) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccountPayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, payload.AccountID)
	if err != nil {
		return wrap(err)
	}
	behaviorKind := kind
	switch kind {
	case adapter.ChangePostgresAccountCreateV2:
		behaviorKind = adapter.ChangeAccountCreate
	case adapter.ChangePostgresRoleCreateV2:
		behaviorKind = adapter.ChangeRoleCreate
	}
	expectedStatus, alreadyApplied, err := accountLifecycleExpectation(acct, payload, behaviorKind)
	if err != nil {
		return wrap(err)
	}
	if alreadyApplied {
		return nil
	}
	if err := e.preflightPostgresV2Connector(ctx, op.Kind, acct.ConnectionID); err != nil {
		return wrap(err)
	}
	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return wrap(err)
	}
	if kind == adapter.ChangePostgresAccountCreateV2 || kind == adapter.ChangePostgresRoleCreateV2 {
		if err := validatePostgresRuntimePins(conn, cfg, payload.ExpectedAdminIdentity,
			payload.ExpectedTargetIdentity, payload.ExpectedConfigIncarnation,
			payload.ExpectedCredentialIncarnation); err != nil {
			return wrap(err)
		}
	}
	actions := changeAuditActions[behaviorKind]

	// Семантика disable движка определяет обязанности ядра по bindings: у
	// движка без нативной блокировки disable уничтожает сами права, поэтому
	// после disable их observed-состояние — absent (иначе binding остаётся
	// ложно synced до следующего discovery), а enable обязан вернуть их из
	// desired state. Manifest — контракт движка и одинаков в обоих режимах
	// исполнения, поэтому в connector-режиме читается из реестра adapters.
	clearsAccess := false
	if behaviorKind == adapter.ChangeAccountDisable || behaviorKind == adapter.ChangeAccountEnable {
		manifest, manifestErr := engineManifest(conn.Engine, ad)
		if manifestErr != nil {
			return wrap(manifestErr)
		}
		clearsAccess = manifest.DisableClearsAccess()
	}

	// Источник начального credential для account.create одинаков в обоих
	// режимах (worker читает Vault, ADR-0014): общий секрет принципала
	// (SharedCredentialPath, username = engine identity) либо per-account
	// путь. Разница только в доставке: direct-путь кладёт его в
	// DesiredChange, connector-путь — в кадр TypeCredentials.
	var accountCred *adapter.Credential
	if behaviorKind == adapter.ChangeAccountCreate {
		switch {
		case payload.SharedCredentialPath != "":
			if e.mut.Credentials == nil {
				return wrap(errors.New("credentials service is not configured"))
			}
			password, _, err := e.mut.Credentials.GetPasswordByPath(ctx, payload.SharedCredentialPath)
			if err != nil {
				return wrap(err)
			}
			defer clear(password)
			accountCred = &adapter.Credential{Kind: "password", Username: acct.EngineIdentity, Secret: password}
		case acct.VaultPath != "":
			if e.mut.Credentials == nil {
				return wrap(errors.New("credentials service is not configured"))
			}
			username, password, err := e.mut.Credentials.GetAccountCredential(ctx, acct.VaultPath, acct.EngineIdentity)
			if err != nil {
				return wrap(err)
			}
			defer clear(password)
			accountCred = &adapter.Credential{Kind: "password", Username: username, Secret: password}
		}
	}
	if viaConnector {
		creds := connectorJobCredentials(cfg)
		creds.Account = accountCred
		_, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, connector.ChangeRef{
			Kind: string(kind), Account: connectorAccountRef(acct),
			ExpectedAdminIdentity:  payload.ExpectedAdminIdentity,
			ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
		}, creds)
	} else {
		change := adapter.DesiredChange{
			Kind:                   kind,
			Connection:             cfg,
			Account:                adapterAccount(acct),
			Credential:             accountCred,
			ExpectedAdminIdentity:  payload.ExpectedAdminIdentity,
			ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
		}
		_, err = e.planApplyVerify(ctx, op.ID, ad, change)
	}
	// Inventory-only цель: account.delete на движке, который не поддерживает
	// мутацию (adapter.ErrUnsupportedChange), не может оставить учётку на
	// таргете — её там и нет (create там тоже отклонён). Снятие метаданных
	// grantor корректно; иначе delete вечно ретраится. Только для delete;
	// create/enable/disable с unsupported остаются ошибкой (см. ниже guard
	// в switch). Универсально по типу ошибки, без engine-условий.
	targetUnsupported := false
	if err != nil {
		if behaviorKind == adapter.ChangeAccountDelete && errors.Is(err, adapter.ErrUnsupportedChange) {
			targetUnsupported = true
		} else {
			err = wrap(err)
			if recordErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, actions.failure, err); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
	}

	// Восстановление прав идёт СТРОГО после снятия блокировки: обратный
	// порядок вернул бы гранты ещё заблокированной учётной записи (у
	// RabbitMQ vhost-permission начинает действовать сразу, независимо от
	// маркера). Каждый grant идемпотентен, поэтому retry операции безопасен;
	// восстановленными считаются только те bindings, чей grant прошёл verify.
	var restored []uuid.UUID
	if behaviorKind == adapter.ChangeAccountEnable && clearsAccess {
		restored, err = e.restoreAccountAccess(ctx, op, conn, cfg, ad, viaConnector, acct)
		if err != nil {
			err = wrap(err)
			if recordErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, actions.failure, err); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
	}

	auditMeta := map[string]any{
		"account":            acct.EngineIdentity,
		"connection_id":      conn.ID,
		"target_unsupported": targetUnsupported,
	}
	if kind == adapter.ChangeAccountEnable && clearsAccess {
		auditMeta["restored_bindings"] = len(restored)
	}
	// Причина удаления — несекретный текст из payload; в metadata только у
	// account.delete и только когда задана (пустая строка = «без причины»).
	if behaviorKind == adapter.ChangeAccountDelete && payload.Reason != "" {
		auditMeta["reason"] = payload.Reason
	}
	metadata, err := json.Marshal(auditMeta)
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	if err := e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, actions.success, metadata, wrap,
		func(tx pgx.Tx) error {
			switch kind {
			// role.create ведёт ту же строку accounts (kind=group), что и
			// account.create: provisioning -> active по подтверждённому verify.
			case adapter.ChangePostgresAccountCreateV2, adapter.ChangePostgresRoleCreateV2,
				adapter.ChangeAccountCreate, adapter.ChangeRoleCreate, adapter.ChangeAccountEnable:
				if err := e.deps.Inventory.SetAccountStatusGuarded(ctx, tx, acct.ID,
					expectedStatus, inventory.AccountActive, payload.ExpectedLifecycleVersion); err != nil {
					return err
				}
				// Present пишется только по подтверждённому verify каждого
				// гранта: наблюдение, а не предположение.
				return e.setBindingsObserved(ctx, tx, restored, inventory.BindingPresent)
			case adapter.ChangeAccountDisable:
				if err := e.deps.Inventory.SetAccountStatusGuarded(ctx, tx, acct.ID,
					expectedStatus, inventory.AccountDisabled, payload.ExpectedLifecycleVersion); err != nil {
					return err
				}
				if !clearsAccess {
					return nil
				}
				// Disable снял права на target (adapter.Verify это уже
				// подтвердил): фиксируем ровно то, что увидит следующий
				// discovery, вместо унаследованного observed='present'.
				ids, err := e.accountBindingIDs(ctx, tx, acct.ID)
				if err != nil {
					return err
				}
				return e.setBindingsObserved(ctx, tx, ids, inventory.BindingAbsent)
			case adapter.ChangeAccountDelete:
				// Tombstone фиксирует кто/когда/почему: актор операции и
				// причина из payload; deleted_at ставит SQL (now()). Ветка
				// target_unsupported (metadata-noop) проходит здесь же.
				return e.deps.Inventory.MarkAccountDeletedGuarded(ctx, tx, acct.ID,
					expectedStatus, payload.ExpectedLifecycleVersion, op.ActorID, payload.Reason)
			default:
				return fmt.Errorf("unsupported account change %q", kind)
			}
		}); err != nil {
		return err
	}
	// Зачистка собственного креда удалённого аккаунта (accounts/<id>/…);
	// общий секрет принципала DeleteAccountCredential не трогает. Best-effort
	// ПОСЛЕ фиксации успеха: пользователь на target уже удалён, секрет
	// бесполезен, а отказ Vault не должен ронять завершённую операцию —
	// осиротевший секрет лишь занимает место и вычищается повторным вызовом.
	if kind == adapter.ChangeAccountDelete && e.mut.Credentials != nil {
		if err := e.mut.Credentials.DeleteAccountCredential(ctx, acct.VaultPath); err != nil {
			slog.WarnContext(ctx, "jobs: delete account credential after account.delete",
				"account_id", acct.ID.String(), "error", err.Error())
		}
	}
	return nil
}

// engineManifest возвращает manifest движка. В direct-режиме adapter уже
// построен, в connector-режиме исполняет connector, но manifest описывает
// контракт самого движка и не зависит от способа исполнения, поэтому берётся
// из реестра. Неизвестный движок — ошибка: без контракта ядро не вправе
// делать выводы о состоянии bindings.
func engineManifest(engine string, ad adapter.Adapter) (adapter.Manifest, error) {
	if ad == nil {
		var err error
		if ad, err = adapter.New(engine); err != nil {
			return adapter.Manifest{}, err
		}
	}
	return ad.Manifest(), nil
}

// restoreAccountAccess возвращает права учётной записи после account.enable на
// движке, чей disable снимает саму авторизацию (Manifest
// AccountDisableEffect = DisableClearsAccess). Источник истины — desired state
// bindings ядра, а не целевая система: в ней прав уже нет. Каждый binding с
// desired='present' применяется обычным grant-потоком adapter (Plan -> Apply
// -> Verify), поэтому шаг идемпотентен: уже присутствующее право даёт skipped.
// Отдельного подтверждения dangerous-права здесь не требуется — оно относится
// к РЕШЕНИЮ выдать доступ, которое уже принято, проверено на выдаче и
// зафиксировано в desired state; enable лишь возвращает учётную запись к нему.
// Возвращаются id bindings, чьё восстановление подтверждено verify: только им
// вызывающий вправе записать observed='present'. Ошибка любого гранта
// прекращает восстановление и роняет операцию — уже применённые гранты
// остаются с прежним (absent) observed до retry или discovery, то есть ядро
// не заявляет доступ, которого не подтвердило.
func (e *MainExecutor) restoreAccountAccess(ctx context.Context, op operations.Operation,
	conn connections.Connection, cfg adapter.Connection, ad adapter.Adapter,
	viaConnector bool, acct inventory.Account) ([]uuid.UUID, error) {
	bindings, err := e.deps.Inventory.ListBindingsByAccount(ctx, e.deps.Pool, acct.ID)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		if binding.TransitionOperationID != nil {
			return nil, fmt.Errorf(
				"restore account access: binding %s is owned by access replacement %s: %w",
				binding.ID, *binding.TransitionOperationID, inventory.ErrBindingTransitionConflict)
		}
	}
	var activeAccessOperation bool
	if err := e.deps.Pool.QueryRow(ctx, `
		select exists (
			select 1 from operations
			where account_id = $1
			  and kind like 'access.%'
			  and status in ('pending_approval', 'pending', 'running')
		)`, acct.ID).Scan(&activeAccessOperation); err != nil {
		return nil, fmt.Errorf("restore account access: inspect active access operations: %w", err)
	}
	if activeAccessOperation {
		return nil, fmt.Errorf("restore account access: account %s has an unfinished access operation: %w",
			acct.ID, inventory.ErrAccountLifecycleBusy)
	}
	var restored []uuid.UUID
	for _, b := range bindings {
		// Unmanaged binding (desired IS NULL) и desired='absent' не
		// восстанавливаются: решения выдать этот доступ не было.
		if b.DesiredState == nil || *b.DesiredState != inventory.BindingPresent {
			continue
		}
		perm, err := e.deps.Inventory.GetPermission(ctx, e.deps.Pool, b.PermissionDefinitionID)
		if err != nil {
			return nil, err
		}
		var permissionAttributes map[string]any
		if perm.AssignmentKey != "" {
			if err := json.Unmarshal(perm.Attributes, &permissionAttributes); err != nil {
				return nil, fmt.Errorf("decode permission %s attributes: %w", perm.ID, err)
			}
		}
		scope := ""
		if b.ScopeResourceID != nil {
			res, err := e.deps.Inventory.GetResource(ctx, e.deps.Pool, *b.ScopeResourceID)
			if err != nil {
				return nil, err
			}
			scope = res.ExternalID
		}
		if viaConnector {
			_, err = e.connectorPlanApplyVerifyArtifacts(ctx, op, conn, cfg, connector.ChangeRef{
				Kind:       string(adapter.ChangeGrant),
				Account:    connectorAccountRef(acct),
				Permission: perm.ExternalID,
				Scope:      scope,
				Attributes: permissionAttributes,
			}, connectorJobCredentials(cfg), false)
		} else {
			_, err = e.planApplyVerifyArtifacts(ctx, op.ID, ad, adapter.DesiredChange{
				Kind:       adapter.ChangeGrant,
				Connection: cfg,
				Account:    adapterAccount(acct),
				Permission: perm.ExternalID,
				Scope:      scope,
				Attributes: permissionAttributes,
			}, false)
		}
		if err != nil {
			return nil, fmt.Errorf("restore access %q of account %s: %w", perm.ExternalID, acct.ID, err)
		}
		restored = append(restored, b.ID)
	}
	return restored, nil
}

// accountBindingIDs возвращает id всех bindings учётной записи, включая
// unmanaged: disable снимает авторизацию целиком, поэтому наблюдаемое
// состояние теряют и они (их status при этом не меняется — см.
// inventory.ResolveBindingStatus).
func (e *MainExecutor) accountBindingIDs(ctx context.Context, tx pgx.Tx, accountID uuid.UUID) ([]uuid.UUID, error) {
	bindings, err := e.deps.Inventory.ListBindingsByAccount(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(bindings))
	for _, b := range bindings {
		ids = append(ids, b.ID)
	}
	return ids, nil
}

// setBindingsObserved записывает наблюдаемое состояние перечисленным
// bindings. Статус пересчитывает единственный механизм — SetBindingResult
// поверх inventory.ResolveBindingStatus, — поэтому отдельного правила
// вычисления статуса здесь не появляется.
func (e *MainExecutor) setBindingsObserved(ctx context.Context, tx pgx.Tx,
	ids []uuid.UUID, observed inventory.BindingState) error {
	for _, id := range ids {
		if _, err := e.deps.Inventory.SetBindingResult(ctx, tx, id, observed); err != nil {
			return err
		}
	}
	return nil
}

// executeAccountRestore восстанавливает bare managed login tombstone с
// конкретной заранее записанной версией Vault credential. Metadata остаётся
// deleted до Apply и двухчастной проверки adapter (identity + exact
// credential); затем активируется одной транзакцией с success audit.
func (e *MainExecutor) executeAccountRestore(ctx context.Context, op operations.Operation) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccountPayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	if payload.ExpectedStatus != inventory.AccountDeleted || payload.ExpectedLifecycleVersion <= 0 {
		return wrap(errors.New("restore payload requires deleted expected_status and a positive lifecycle version"))
	}
	if payload.CredentialMode != inventory.CredentialModeGenerated &&
		payload.CredentialMode != inventory.CredentialModeProvided &&
		payload.CredentialMode != inventory.CredentialModeExistingVaultRef {
		return wrap(errors.New("restore payload has invalid credential_mode"))
	}
	v2 := op.Kind == KindPostgresAccountRestoreV2
	if !v2 && (payload.CredentialMode == inventory.CredentialModeExistingVaultRef) != (payload.SharedCredentialPath != "") {
		return wrap(errors.New("restore shared credential mode and path must be set together"))
	}
	if payload.CredentialVaultVersion <= 0 {
		return wrap(errors.New("restore payload requires a positive credential_vault_version"))
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, payload.AccountID)
	if err != nil {
		return wrap(err)
	}
	fail := func(code string, returned error) error {
		return e.failAccountRestore(ctx, op, acct, code, returned)
	}
	if op.AccountID == nil || *op.AccountID != acct.ID {
		return fail("operation_account_mismatch",
			wrap(errors.New("restore operation account_id does not match payload")))
	}
	_, alreadyApplied, err := accountLifecycleExpectation(acct, payload, adapter.ChangeAccountRestore)
	if err != nil {
		return fail("lifecycle_conflict", wrap(err))
	}
	if alreadyApplied {
		if err := e.reconstructRestoreArtifacts(op, acct); err != nil {
			return fail("artifact_reconstruction_failed",
				wrap(errors.New("restore operation artifacts could not be reconstructed")))
		}
		return nil
	}
	if acct.Ownership != inventory.OwnershipManaged || acct.Kind != "login" {
		return fail("ineligible_account",
			wrap(fmt.Errorf("account %s is not an eligible managed login tombstone", acct.ID)))
	}
	bindings, err := e.deps.Inventory.ListBindingsByAccount(ctx, e.deps.Pool, acct.ID)
	if err != nil {
		return fail("inventory_unavailable", wrap(errors.New("restore binding evidence is unavailable")))
	}
	if len(bindings) != 0 {
		return fail("binding_evidence",
			wrap(fmt.Errorf("account %s has observed binding evidence: %w", acct.ID, adapter.ErrExternalIdentityConflict)))
	}
	if err := e.preflightPostgresV2Connector(ctx, op.Kind, acct.ConnectionID); err != nil {
		return fail("connector_capability_unavailable", wrap(err))
	}
	if e.mut.Credentials == nil {
		return fail("credentials_unavailable", wrap(errors.New("credentials service is not configured")))
	}

	var username, vaultPath string
	var password []byte
	sharedCredentialPath := payload.SharedCredentialPath
	if v2 && payload.CredentialMode == inventory.CredentialModeExistingVaultRef {
		sharedCredentialPath = acct.VaultPath
	}
	if sharedCredentialPath != "" {
		if op.PrincipalID == nil || acct.PrincipalID == nil || *op.PrincipalID != *acct.PrincipalID {
			return fail("principal_mismatch", wrap(errors.New("restore principal does not match tombstone")))
		}
		conn, connErr := e.deps.Connections.Get(ctx, e.deps.Pool, acct.ConnectionID)
		if connErr != nil {
			return fail("connection_unavailable", wrap(connErr))
		}
		environment := conn.Environment
		if environment == "" {
			environment = "default"
		}
		expectedPath, pathErr := vault.PrincipalEnvironmentCredentialPath(op.PrincipalID.String(), environment)
		if pathErr != nil || sharedCredentialPath != expectedPath || acct.VaultPath != expectedPath {
			return fail("credential_path_mismatch", wrap(errors.New("restore principal credential path is invalid")))
		}
		username, password, err = e.mut.Credentials.GetAccountCredentialVersion(
			ctx, expectedPath, acct.EngineIdentity, payload.CredentialVaultVersion)
		vaultPath = expectedPath
	} else {
		username, password, vaultPath, err = e.mut.Credentials.GetOwnAccountCredentialVersion(
			ctx, acct.ID, payload.CredentialVaultVersion)
	}
	if err != nil {
		return fail("credential_unavailable", wrap(errors.New("reserved restore credential is unavailable")))
	}
	defer clear(password)
	if username != acct.EngineIdentity {
		return fail("credential_identity_mismatch",
			wrap(fmt.Errorf("reserved credential identity does not match account: %w", adapter.ErrExternalIdentityConflict)))
	}

	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return fail("target_unavailable", wrap(errors.New("restore target is unavailable")))
	}
	if v2 {
		if err := validatePostgresRuntimePins(conn, cfg, payload.ExpectedAdminIdentity,
			payload.ExpectedTargetIdentity, payload.ExpectedConfigIncarnation,
			payload.ExpectedCredentialIncarnation); err != nil {
			return fail("target_changed", wrap(err))
		}
	}
	cred := &adapter.Credential{Kind: "password", Username: username, Secret: password}
	changeKind := adapter.ChangeAccountRestore
	if v2 {
		changeKind = adapter.ChangePostgresAccountRestoreV2
	}
	if viaConnector {
		creds := connectorJobCredentials(cfg)
		creds.Account = cred
		creds.AccountVaultVersion = payload.CredentialVaultVersion
		_, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, connector.ChangeRef{
			Kind: string(changeKind), Account: connectorAccountRef(acct),
			ExpectedAdminIdentity:  payload.ExpectedAdminIdentity,
			ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
		}, creds)
	} else {
		if !ad.Manifest().HasCapability(adapter.CapAccountRestore) {
			err = adapter.ErrUnsupportedChange
		} else if _, ok := ad.(adapter.CredentialProver); !ok {
			err = adapter.ErrCredentialProofUnsupported
		} else {
			_, err = e.planApplyVerify(ctx, op.ID, ad, adapter.DesiredChange{
				Kind: changeKind, Connection: cfg,
				Account: adapterAccount(acct), Credential: cred,
				ExpectedAdminIdentity:  payload.ExpectedAdminIdentity,
				ExpectedTargetIdentity: payload.ExpectedTargetIdentity,
			})
		}
	}
	if err != nil {
		code := "adapter_failure"
		switch {
		case errors.Is(err, adapter.ErrExternalIdentityConflict):
			code = "external_identity_conflict"
		case errors.Is(err, adapter.ErrCredentialProofUnsupported):
			code = "credential_proof_unsupported"
		case errors.Is(err, adapter.ErrUnsupportedChange):
			code = "unsupported_capability"
		}
		return fail(code,
			wrap(errors.New("restore target verification failed: "+code)))
	}
	if e.mut.BeforeRestoreMetadataCommit != nil {
		if err := e.mut.BeforeRestoreMetadataCommit(ctx, op); err != nil {
			return fail("metadata_activation_failed",
				wrap(errors.New("restore metadata activation failed after target verification")))
		}
	}

	metadata, err := json.Marshal(map[string]any{
		"account": acct.EngineIdentity, "lifecycle_version": payload.ExpectedLifecycleVersion,
		"credential_mode": payload.CredentialMode, "credential_proved": true,
	})
	if err != nil {
		return fail("audit_metadata_invalid", wrap(errors.New("restore audit metadata is invalid")))
	}
	err = e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, auditActionAccountRestored, metadata, wrap,
		func(tx pgx.Tx) error {
			var err error
			if sharedCredentialPath != "" && op.PrincipalID != nil {
				_, err = e.deps.Inventory.RestorePrincipalAccountGuarded(ctx, tx, acct.ID,
					payload.ExpectedLifecycleVersion, vaultPath, *op.PrincipalID)
			} else {
				_, err = e.deps.Inventory.RestoreAccountGuarded(ctx, tx, acct.ID,
					payload.ExpectedLifecycleVersion, payload.CredentialMode, vaultPath)
			}
			return err
		})
	if err != nil {
		return fail("metadata_activation_failed", wrap(errors.New("restore metadata activation failed")))
	}
	return nil
}

// reconstructRestoreArtifacts восстанавливает sanitized plan/result после
// crash окна, в котором guarded metadata+success audit уже закоммитились, а
// outer operation tx со статусом и in-memory artifacts — нет. Активная та же
// lifecycle incarnation является durable доказательством завершённого proof;
// target повторно не мутируется. Уже сохранённый plan/result не заменяются.
func (e *MainExecutor) reconstructRestoreArtifacts(op operations.Operation, acct inventory.Account) error {
	step := adapter.PlanStep{
		Kind:        "restore-account-recovered",
		Description: fmt.Sprintf("recover committed restore artifacts for account %q", acct.EngineIdentity),
	}
	if len(op.Plan) == 0 {
		plan, err := marshalPlan(&adapter.Plan{
			Change: adapter.DesiredChange{
				Kind:    adapter.ChangeAccountRestore,
				Account: adapterAccount(acct),
			},
			Steps: []adapter.PlanStep{step},
		})
		if err != nil {
			return err
		}
		e.setPlanArtifact(op.ID, plan)
	}
	if len(op.Result) == 0 {
		result, err := marshalResult(&adapter.Result{Steps: []adapter.StepResult{{
			Step: step, Status: adapter.StepSkipped,
		}}}, &adapter.Verification{
			Verified: true,
			Details:  "restore lifecycle metadata was already committed after credential proof",
		})
		if err != nil {
			return err
		}
		e.setResultArtifact(op.ID, result)
	}
	return nil
}

// terminalRestoreCodes — коды отказа account.restore, исход которых не зависит
// от повтора: capability движка, чужая identity на target и несоответствие
// операции текущему поколению/состоянию аккаунта. Коды *_unavailable и
// *_failed сюда не входят — за ними стоит временная недоступность Vault,
// target или metadata database, и повтор обязан остаться.
//
// Отдельный список нужен потому, что failAccountRestore сознательно возвращает
// sanitized текст без исходной цепочки ошибок: errors.Is по ней уже не
// работает, а классификация обязана остаться точной (terminal.go).
var terminalRestoreCodes = map[string]bool{
	"operation_account_mismatch":   true,
	"lifecycle_conflict":           true,
	"ineligible_account":           true,
	"binding_evidence":             true,
	"credential_identity_mismatch": true,
	"unsupported_capability":       true,
	"credential_proof_unsupported": true,
	"external_identity_conflict":   true,
}

// failAccountRestore пишет только стабильный sanitized code. Исходные ошибки
// Vault/adapter могут содержать endpoint/path и в audit не попадают.
func (e *MainExecutor) failAccountRestore(ctx context.Context, op operations.Operation,
	acct inventory.Account, code string, returned error) error {
	safe := errors.New("account restore failed: " + code)
	if err := e.recordMutationFailure(ctx, op, acct.ConnectionID, &acct.ID, nil,
		auditActionAccountRestoreFailed, safe); err != nil {
		// Отказ записи audit — временная проблема metadata database, а не
		// причина отказа restore: job остаётся повторяемым.
		return errors.Join(returned, err)
	}
	if terminalRestoreCodes[code] {
		return terminal(returned)
	}
	return returned
}

// executeCredentialRotate ротирует credential аккаунта и применяет
// новый пароль к целевой системе.
//
// Источник нового пароля определяется payload (rotateCredentialSource):
//   - SharedCredentialPath задан — общий секрет принципала (модель
//     shared-per-principal-per-environment). Новую версию уже записал
//     API-слой (RotatePrincipalCredential); здесь пароль только читается по
//     этому пути и применяется к target. Генерации нет: иначе у аккаунтов
//     принципала разошлись бы пароли. По одной такой операции на кластер;
//     недоступный кластер остаётся на старом пароле до retry (best-effort);
//   - Adopt задан — принятие существующего unmanaged-аккаунта под
//     управление (POST /accounts/{id}/adopt). Флаг Adopt отвечает только за
//     переход ownership в managed на успехе и допуск unmanaged-аккаунта;
//     источник пароля независим. mode=password (AdoptGenerate=false): пароль
//     по accounts/<id>/credential уже записал API-слой, здесь читается его
//     последняя версия и применяется к target (генерации нет),
//     credential_mode=provided. mode=generate (AdoptGenerate=true): executor
//     сам генерирует пароль adapter-генератором, пишет его в Vault и применяет
//     к target — как обычная per-account ротация, но с переходом ownership,
//     credential_mode=generated. В обоих случаях до успеха аккаунт остаётся
//     unmanaged — состояния «managed без применённого credential» не
//     возникает, а неактивированная версия в Vault безвредна и сходится на
//     retry;
//   - иначе (ротация одиночного аккаунта через POST /accounts/{id}/rotate)
//     adapter генерирует новый секрет per-account, он пишется новой версией
//     в accounts/<id>/credential и применяется к target. Managed-аккаунт с
//     ещё пустым vault_path (принят через adopt mode=metadata) проходит тем
//     же путём: первая ротация создаёт секрет и заполняет
//     vault_path/credential_mode.
//
// Известное упрощение против 17.3 архитектуры: pending-версий в Vault
// нет. Если применение к целевой системе упало, новая версия остаётся в
// Vault последней, но неактивированной в target; retry операции приведёт
// target к ней. Старый пароль при этом продолжает работать до первого
// успешного применения.
//
// На connector-подключении применение выполняет connector
// (JobRotateCredential): worker генерирует и записывает новую версию в Vault
// (per-account) либо читает версию, записанную API (shared), и доставляет
// конкретное значение с номером версии connector'у кадром TypeCredentials
// (ADR-0014) — connector к Vault не ходит, а в подписанном задании секрета
// нет.
func (e *MainExecutor) executeCredentialRotate(ctx context.Context, op operations.Operation) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: %s operation %s: %w", op.Kind, op.ID, err)
	}
	payload, err := decodeAccountPayload(op.Payload)
	if err != nil {
		return wrap(err)
	}
	acct, err := e.deps.Inventory.GetAccount(ctx, e.deps.Pool, payload.AccountID)
	if err != nil {
		return wrap(err)
	}
	if acct.LifecycleVersion != payload.ExpectedLifecycleVersion {
		return wrap(inventory.CheckAccountLifecycle(acct, payload.ExpectedStatus, payload.ExpectedLifecycleVersion))
	}
	if acct.Status == inventory.AccountDeleted {
		return wrap(fmt.Errorf("account %s is deleted: %w", acct.ID, inventory.ErrAccountStatusConflict))
	}
	expectedRotateStatus := payload.ExpectedStatus
	if expectedRotateStatus == "" {
		expectedRotateStatus = acct.Status
	}
	if err := inventory.CheckAccountLifecycle(acct, expectedRotateStatus, payload.ExpectedLifecycleVersion); err != nil {
		return wrap(err)
	}
	source := rotateCredentialSource(payload)
	// Adopt-операция по определению работает с unmanaged-аккаунтом (retry
	// после успеха увидит уже managed — это безопасно и идемпотентно);
	// остальные ротации допускают только managed. Guard смотрит на флаг Adopt
	// (право ротировать ещё-не-managed аккаунт), а не на источник пароля:
	// adopt mode=generate имеет generate-источник, но так же принимает
	// unmanaged-аккаунт.
	if !payload.Adopt && payload.ManagedLinkPrincipalID == nil && acct.Ownership != inventory.OwnershipManaged {
		return wrap(fmt.Errorf("account %q is not managed by grantor", acct.EngineIdentity))
	}
	if e.mut.Credentials == nil {
		return wrap(errors.New("credentials service is not configured"))
	}
	if payload.ManagedLinkPrincipalID != nil {
		if op.PrincipalID == nil || *op.PrincipalID != *payload.ManagedLinkPrincipalID {
			return wrap(errors.New("managed link principal does not match operation principal"))
		}
		// Проверка already-applied выполняется до mutationTarget: crash-window
		// recovery не должна зависеть от доступности target/admin credential.
		linkConn, connErr := e.deps.Connections.Get(ctx, e.deps.Pool, acct.ConnectionID)
		if connErr != nil {
			return wrap(connErr)
		}
		linkEnvironment := linkConn.Environment
		if linkEnvironment == "" {
			linkEnvironment = "default"
		}
		expectedPath, pathErr := vault.PrincipalEnvironmentCredentialPath(payload.ManagedLinkPrincipalID.String(), linkEnvironment)
		if pathErr != nil || payload.SharedCredentialPath != expectedPath {
			return wrap(errors.New("managed link shared credential path is invalid"))
		}
		alreadyApplied := acct.Ownership == inventory.OwnershipManaged &&
			acct.PrincipalID != nil && *acct.PrincipalID == *payload.ManagedLinkPrincipalID &&
			acct.CredentialMode != nil && *acct.CredentialMode == inventory.CredentialModeExistingVaultRef &&
			acct.VaultPath == expectedPath
		if alreadyApplied {
			result, marshalErr := json.Marshal(map[string]any{
				"rotated": true, "verified": true, "already_applied": true,
			})
			if marshalErr != nil {
				return wrap(marshalErr)
			}
			e.setResultArtifact(op.ID, result)
			return nil
		}
		if acct.Ownership != inventory.OwnershipUnmanaged && acct.Ownership != inventory.OwnershipManaged {
			return wrap(fmt.Errorf("account %q ownership does not allow managed link", acct.EngineIdentity))
		}
	}
	conn, targetCfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, acct.ConnectionID)
	defer clear(targetCfg.AdminCredential.Secret)
	if err != nil {
		return wrap(err)
	}
	// Link-and-manage использует общий flow для всех движков, но никогда не
	// ротирует target до независимой проверки capability и prover-контракта.
	// Проверка дублирует API guard намеренно: worker обязан оставаться
	// fail-closed для повторов и операций, созданных старой версией API.
	if payload.ManagedLinkPrincipalID != nil {
		proofAdapter, proofErr := managedLinkProofAdapter(conn.Engine, ad, viaConnector)
		if proofErr != nil {
			return wrap(fmt.Errorf("resolve credential proof adapter: %w", proofErr))
		}
		if !adapter.SupportsCredentialProof(proofAdapter) ||
			!adapter.HasManagedCredentialCapabilities(conn.Capabilities) {
			return wrap(errors.New("credential rotation with proof is unsupported for managed link"))
		}
	}

	username := acct.EngineIdentity
	var (
		version int
		path    string
	)
	if viaConnector {
		// Порядок direct-пути «Vault write -> target apply» сохранён: новая
		// версия секрета сначала оказывается в Vault (её пишет worker для
		// per-account ротации либо уже записал API-слой для общего секрета
		// принципала), затем конкретное значение и номер версии уходят
		// connector'у кадром TypeCredentials (ADR-0014) — в подписанный
		// payload секрет не попадает. Отказ target оставляет версию в Vault
		// неактивированной — retry доведёт target до неё, ложного удаления
		// доступа нет.
		var password []byte
		switch source {
		case rotateSourceShared:
			// Новую версию общего секрета уже записал API-слой; worker
			// читает её последнюю версию (как direct-путь) и передаёт
			// connector'у.
			path = payload.SharedCredentialPath
			password, version, err = e.mut.Credentials.GetPasswordByPath(ctx, path)
			if err != nil {
				return wrap(err)
			}
		case rotateSourceAdopt:
			// Adopt: пароль по accounts/<id>/credential уже записал API-слой;
			// worker читает последнюю версию и передаёт connector'у именно её
			// (pinned) — как shared-путь, генерации нет.
			password, version, path, err = e.mut.Credentials.GetOwnAccountCredential(ctx, acct.ID)
			if err != nil {
				return wrap(err)
			}
		default:
			// Per-account ротация: worker генерирует новый секрет тем же
			// adapter-генератором, что и direct-путь (локальная операция,
			// target не нужен), записывает его в Vault и передаёт
			// connector'у именно эту (pinned) версию.
			genAd, genErr := adapter.New(conn.Engine)
			if genErr != nil {
				return wrap(genErr)
			}
			newCred, genErr := genAd.GenerateCredential(ctx, adapter.CredentialPolicy{})
			if genErr != nil {
				return wrap(fmt.Errorf("generate credential: %w", genErr))
			}
			password = newCred.Secret
			version, path, err = e.mut.Credentials.PutAccountCredential(ctx, acct.ID, username, password)
			if err != nil {
				clear(password)
				return wrap(err)
			}
		}
		creds := connectorJobCredentials(targetCfg)
		creds.Account = &adapter.Credential{Kind: "password", Username: username, Secret: password}
		creds.AccountVaultVersion = version
		// Зануление секретов (password + admin) выполняет connectorDispatch
		// внутри connectorRotateCredential.
		version, err = e.connectorRotateCredential(ctx, op, conn, targetCfg,
			connectorAccountRef(acct), creds, path, version, payload.ManagedLinkPrincipalID != nil)
		if err != nil {
			err = wrap(fmt.Errorf("rotate credential: %w", err))
			if recordErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, auditActionCredentialRotateFailed, err); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
	} else {
		var password []byte
		switch source {
		case rotateSourceShared:
			// Новую версию общего секрета уже записал API-слой; берём её и
			// применяем к target — без генерации, чтобы аккаунты принципала
			// не разошлись по паролям.
			password, version, err = e.mut.Credentials.GetPasswordByPath(ctx, payload.SharedCredentialPath)
			if err != nil {
				return wrap(err)
			}
			path = payload.SharedCredentialPath
		case rotateSourceAdopt:
			// Adopt: применяем последнюю версию accounts/<id>/credential,
			// предварительно записанную API-слоем, — без генерации.
			password, version, path, err = e.mut.Credentials.GetOwnAccountCredential(ctx, acct.ID)
			if err != nil {
				return wrap(err)
			}
		default:
			newCred, genErr := ad.GenerateCredential(ctx, adapter.CredentialPolicy{})
			if genErr != nil {
				return wrap(fmt.Errorf("generate credential: %w", genErr))
			}
			password = newCred.Secret
			version, path, err = e.mut.Credentials.PutAccountCredential(ctx, acct.ID, username, password)
			if err != nil {
				clear(password)
				return wrap(err)
			}
		}
		defer clear(password)

		if payload.ManagedLinkPrincipalID != nil {
			if preflight, ok := ad.(adapter.CredentialProofPreflighter); ok {
				if err := preflight.CheckCredentialProofAccess(ctx, targetCfg, adapterAccount(acct)); err != nil {
					return wrap(fmt.Errorf("credential verification preflight failed: %w", err))
				}
			}
		}
		if err := ad.RotateCredential(ctx, targetCfg, adapterAccount(acct), adapter.Credential{
			Kind:     "password",
			Username: username,
			Secret:   password,
		}); err != nil {
			err = wrap(fmt.Errorf("rotate credential: %w", err))
			if recordErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, auditActionCredentialRotateFailed, err); recordErr != nil {
				return errors.Join(err, recordErr)
			}
			return err
		}
		if payload.ManagedLinkPrincipalID != nil {
			prover, ok := ad.(adapter.CredentialProver)
			if !ok {
				return wrap(errors.New("credential proof is unsupported for managed link"))
			}
			if err := prover.ProveCredential(ctx, targetCfg, adapterAccount(acct), adapter.Credential{
				Kind: "password", Username: username, Secret: password,
			}); err != nil {
				err = wrap(fmt.Errorf("password changed, but credential verification failed: %w", err))
				if recordErr := e.recordMutationFailure(ctx, op, conn.ID, &acct.ID, nil, auditActionCredentialRotateFailed, err); recordErr != nil {
					return errors.Join(err, recordErr)
				}
				return err
			}
		}
	}

	result, err := json.Marshal(map[string]any{"rotated": true, "vault_version": version})
	if err != nil {
		return wrap(fmt.Errorf("marshal result: %w", err))
	}
	e.setResultArtifact(op.ID, result)

	auditMeta := map[string]any{
		"account":       acct.EngineIdentity,
		"vault_version": version,
	}
	if payload.Adopt {
		// Маркер adopt в audit-метаданных (секретов не несёт): успех этой
		// ротации одновременно принял аккаунт под управление. Ставится для
		// обоих adopt-режимов (password и generate) — источник пароля на
		// смысл маркера не влияет.
		auditMeta["adopted"] = true
	}
	if payload.ManagedLinkPrincipalID != nil {
		auditMeta["managed_link"] = true
		auditMeta["principal_id"] = *payload.ManagedLinkPrincipalID
		auditMeta["credential_proved"] = true
	}
	metadata, err := json.Marshal(auditMeta)
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	// Режим credential фиксируется вместе с путём: adopt mode=password —
	// provided (пароль задал оператор); adopt mode=generate — generated
	// (пароль сгенерировал grantor); обычная ротация заполняет generated
	// аккаунту без режима (первая ротация после adopt mode=metadata) и
	// аккаунту, который этой ротацией СЪЕХАЛ с общего секрета принципала на
	// собственный путь; в остальных случаях режим не трогается. Ownership при
	// этом всегда managed: для уже managed-аккаунта это no-op, для adopt —
	// сам переход.
	//
	// Пара (credential_mode, vault_path) обязана оставаться согласованной:
	// per-account ротация всегда пишет accounts/<id>/credential, поэтому
	// оставшийся existing_vault_ref был бы ложью о том, что аккаунт всё ещё
	// делит секрет принципала, — и снова втягивал бы его в ротацию
	// принципала с чужим SharedCredentialPath.
	credentialMode := ""
	switch {
	case source == rotateSourceShared:
		credentialMode = inventory.CredentialModeExistingVaultRef
	case source == rotateSourceAdopt:
		credentialMode = inventory.CredentialModeProvided
	case payload.Adopt:
		// adopt mode=generate: generate-источник + переход ownership.
		credentialMode = inventory.CredentialModeGenerated
	case source == rotateSourceGenerate:
		credentialMode = inventory.CredentialModeGenerated
	}
	successErr := e.recordMutationSuccess(ctx, op, conn.ID, &acct.ID, auditActionCredentialRotated, metadata, wrap,
		func(tx pgx.Tx) error {
			if payload.ManagedLinkPrincipalID != nil {
				if _, err := e.deps.Inventory.SetAccountManagedLinkedGuarded(ctx, tx, acct.ID,
					expectedRotateStatus, payload.ExpectedLifecycleVersion,
					*payload.ManagedLinkPrincipalID, path); err != nil {
					return err
				}
				return e.deps.Inventory.SetAccountCredentialVersion(ctx, tx, acct.ID, version)
			}
			if _, err := e.deps.Inventory.SetAccountManagedGuarded(ctx, tx, acct.ID,
				expectedRotateStatus, payload.ExpectedLifecycleVersion, path, credentialMode); err != nil {
				return err
			}
			if payload.AdoptBindings {
				if _, err := e.deps.Inventory.AdoptAccountBindings(ctx, tx, acct.ID); err != nil {
					return err
				}
			}
			// Якорь версии: пароль этой версии только что применён к целевой
			// системе, значит с ней согласована именно она. Расхождение с
			// текущей версией в Vault потом означает правку мимо grantor
			// (internal/core/credentialcheck).
			return e.deps.Inventory.SetAccountCredentialVersion(ctx, tx, acct.ID, version)
		})
	if successErr != nil {
		return successErr
	}
	// Migration managed per-account -> shared deletes the old own secret only
	// after metadata commit. DeleteAccountCredential is path-guarded and will
	// never delete a principal/environment shared reference.
	if source == rotateSourceShared && acct.VaultPath != "" && acct.VaultPath != path {
		if err := e.mut.Credentials.DeleteAccountCredential(ctx, acct.VaultPath); err != nil {
			slog.WarnContext(ctx, "jobs: delete migrated account credential", "account_id", acct.ID, "error", err)
		}
	}
	return nil
}

// recordMutationSuccess атомарно фиксирует успех мутации: применяет
// inventory-мутацию (callback mutate) и пишет audit-событие успеха одной
// транзакцией. Зеркалит recordMutationFailure для success-пути (Begin →
// mutation → audit → Commit), выделяя общий хвост executeAccessChange/
// executeAccountChange/executeCredentialRotate. metadata маршалит вызывающий
// (её состав специфичен для операции); wrap — тот же обёртчик ошибок
// вызывающего ("jobs: <kind> operation <id>: %w"), чтобы тексты ошибок хвоста
// не изменились после выделения.
func (e *MainExecutor) recordMutationSuccess(ctx context.Context, op operations.Operation, connectionID uuid.UUID,
	accountID *uuid.UUID, action string, metadata []byte, wrap func(error) error, mutate func(pgx.Tx) error) error {
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return wrap(fmt.Errorf("begin tx: %w", err))
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := mutate(tx); err != nil {
		return wrap(err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType:    op.ActorType,
		ActorID:      op.ActorID,
		Action:       action,
		ConnectionID: &connectionID,
		AccountID:    accountID,
		OperationID:  &op.ID,
		Result:       audit.ResultSuccess,
		Metadata:     metadata,
	}); err != nil {
		return wrap(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return wrap(fmt.Errorf("commit: %w", err))
	}
	return nil
}

// recordMutationFailure атомарно фиксирует падение мутации: audit-событие
// и (для access-операций) статус failed у binding. Текст ошибки sanitized
// по контракту adapter и секретов не содержит.
func (e *MainExecutor) recordMutationFailure(ctx context.Context, op operations.Operation, connectionID uuid.UUID, accountID, bindingID *uuid.UUID, action string, cause error) error {
	metadata, err := json.Marshal(map[string]any{"error": cause.Error()})
	if err != nil {
		return fmt.Errorf("jobs: record mutation failure %s: marshal audit metadata: %w", op.ID, err)
	}

	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: record mutation failure %s: begin tx: %w", op.ID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if bindingID != nil {
		if err := e.deps.Inventory.MarkBindingFailed(ctx, tx, *bindingID); err != nil {
			return fmt.Errorf("jobs: record mutation failure %s: %w", op.ID, err)
		}
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType:    op.ActorType,
		ActorID:      op.ActorID,
		Action:       action,
		ConnectionID: &connectionID,
		AccountID:    accountID,
		OperationID:  &op.ID,
		Result:       audit.ResultFailure,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("jobs: record mutation failure %s: %w", op.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: record mutation failure %s: commit: %w", op.ID, err)
	}
	return nil
}

func (e *MainExecutor) recordAccessMutationFailure(ctx context.Context, op operations.Operation,
	connectionID, accountID uuid.UUID, binding inventory.Binding, kind adapter.ChangeKind,
	action string, cause error,
) error {
	metadata, err := json.Marshal(map[string]any{"error": cause.Error(), "binding_id": binding.ID})
	if err != nil {
		return fmt.Errorf("jobs: record access failure %s: marshal audit metadata: %w", op.ID, err)
	}
	desired := inventory.BindingPresent
	if kind == adapter.ChangeRevoke {
		desired = inventory.BindingAbsent
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: record access failure %s: begin tx: %w", op.ID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := e.deps.Inventory.MarkBindingFailedExpected(
		ctx, tx, binding.ID, binding.PermissionDefinitionID, desired,
	); err != nil {
		return fmt.Errorf("jobs: record access failure %s: %w", op.ID, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType: op.ActorType, ActorID: op.ActorID, Action: action,
		ConnectionID: &connectionID, AccountID: &accountID, OperationID: &op.ID,
		Result: audit.ResultFailure, Metadata: metadata,
	}); err != nil {
		return fmt.Errorf("jobs: record access failure %s: %w", op.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: record access failure %s: commit: %w", op.ID, err)
	}
	return nil
}

func (e *MainExecutor) recordAccessReplacementFailure(ctx context.Context, op operations.Operation,
	connectionID, accountID uuid.UUID, payload AccessReplacePayload, cause error) error {
	metadata, err := json.Marshal(map[string]any{
		"binding_id":     payload.BindingID,
		"assignment_key": payload.AssignmentKey,
		"error":          cause.Error(),
	})
	if err != nil {
		return fmt.Errorf("jobs: record access replacement failure %s: marshal audit metadata: %w", op.ID, err)
	}
	tx, err := e.deps.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: record access replacement failure %s: begin tx: %w", op.ID, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if err := e.deps.Inventory.MarkAccessReplacementFailed(ctx, tx,
		accessReplacementTransition(op.ID, payload)); err != nil {
		return fmt.Errorf("jobs: record access replacement failure %s: %w", op.ID, err)
	}
	if err := e.deps.Audit.Write(ctx, tx, audit.Event{
		ActorType:    op.ActorType,
		ActorID:      op.ActorID,
		Action:       auditActionAccessReplaceFailed,
		ConnectionID: &connectionID,
		AccountID:    &accountID,
		OperationID:  &op.ID,
		Result:       audit.ResultFailure,
		Metadata:     metadata,
	}); err != nil {
		return fmt.Errorf("jobs: record access replacement failure %s: %w", op.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: record access replacement failure %s: commit: %w", op.ID, err)
	}
	return nil
}

// ResourcePayload — payload операции resource.create.database (jsonb
// operations.payload; секретов не содержит). Спека сохраняется целиком: она,
// а не текущее состояние инвентаря, определяет, что именно создаётся при
// повторе job.
type ResourcePayload struct {
	ResourceID uuid.UUID `json:"resource_id"`
	Kind       string    `json:"kind"`
	Name       string    `json:"name"`
	// Options — опции создания как их принял API (owner/template/encoding/
	// locale/tablespace/connection_limit). Валидируются адаптером в Plan.
	Options                       map[string]any `json:"options,omitempty"`
	ExpectedTargetIdentity        string         `json:"expected_target_identity,omitempty"`
	ExpectedAdminIdentity         string         `json:"expected_admin_identity,omitempty"`
	ExpectedConfigIncarnation     string         `json:"expected_config_incarnation,omitempty"`
	ExpectedCredentialIncarnation int            `json:"expected_credential_incarnation,omitempty"`
	ExpectedDatabaseOwner         string         `json:"expected_database_owner,omitempty"`
	ExpectedDatabaseOwnerOID      uint32         `json:"expected_database_owner_oid,omitempty"`
}

// executeResourceCreate создаёт ресурс в целевой системе и переводит
// planned-строку инвентаря в observed по подтверждённому verify.
//
// Отката нет по решению architecture §11.2: DROP DATABASE не выполняется
// никогда. Провалившаяся операция оставляет planned-строку — она видна
// оператору и удаляется отдельным подтверждённым действием.
func (e *MainExecutor) executeResourceCreate(ctx context.Context, op operations.Operation) error {
	wrap := func(err error) error {
		return fmt.Errorf("jobs: resource.create operation %s: %w", op.ID, err)
	}
	var payload ResourcePayload
	if len(op.Payload) > 0 {
		if err := json.Unmarshal(op.Payload, &payload); err != nil {
			return wrap(fmt.Errorf("decode payload: %w", err))
		}
	}
	if payload.ResourceID == uuid.Nil || payload.Name == "" {
		return wrap(errors.New("payload must carry resource id and name"))
	}
	if op.ConnectionID == nil {
		return wrap(errors.New("operation has no connection"))
	}
	res, err := e.deps.Inventory.GetResource(ctx, e.deps.Pool, payload.ResourceID)
	if err != nil {
		return wrap(err)
	}
	// Повтор уже применённой операции (дубль job, восстановление после сбоя
	// между commit и завершением) — успешный no-op, а не конфликт.
	if res.Status == inventory.ResourceObserved {
		return nil
	}
	if res.Status != inventory.ResourcePlanned {
		return wrap(fmt.Errorf("resource %s is in status %q, want planned", res.ID, res.Status))
	}
	if err := e.preflightPostgresV2Connector(ctx, op.Kind, *op.ConnectionID); err != nil {
		return wrap(err)
	}

	conn, cfg, ad, viaConnector, err := e.mutationTarget(ctx, op.Kind, *op.ConnectionID)
	defer clear(cfg.AdminCredential.Secret)
	if err != nil {
		return wrap(err)
	}
	v2 := op.Kind == KindPostgresResourceCreateDatabaseV2 ||
		op.Kind == KindPostgresResourceCreateDatabaseForRolesV2
	if v2 {
		if err := validatePostgresRuntimePins(conn, cfg, payload.ExpectedAdminIdentity,
			payload.ExpectedTargetIdentity, payload.ExpectedConfigIncarnation,
			payload.ExpectedCredentialIncarnation); err != nil {
			return wrap(err)
		}
		if payload.ExpectedDatabaseOwner == "" || payload.ExpectedDatabaseOwnerOID == 0 ||
			payload.Options["owner"] != payload.ExpectedDatabaseOwner {
			return wrap(terminal(errors.New("PostgreSQL v2 database owner pin is incomplete")))
		}
		if op.Kind == KindPostgresResourceCreateDatabaseForRolesV2 && op.ParentID == nil {
			return wrap(terminal(errors.New("database-for-roles child has no root")))
		}
	}
	capabilityAdapter := ad
	if viaConnector {
		capabilityAdapter, err = adapter.New(conn.Engine)
		if err != nil {
			return wrap(err)
		}
	}
	// Defense in depth: API уже проверил capability, но операция могла
	// пролежать в очереди дольше, чем настройки подключения.
	if !capabilityAdapter.Manifest().HasCapability(adapter.ResourceCapability("create", payload.Kind)) {
		return wrap(fmt.Errorf("engine %q: %w", conn.Engine, adapter.ErrUnsupportedChange))
	}
	changeKind := adapter.ChangeResourceCreate
	if v2 {
		changeKind = adapter.ChangePostgresDatabaseCreateV2
	}
	change := adapter.DesiredChange{
		Kind:       changeKind,
		Connection: cfg,
		Resource: &adapter.ResourceSpec{
			Kind: payload.Kind, Name: payload.Name, Attributes: payload.Options,
		},
		ExpectedTargetIdentity:   payload.ExpectedTargetIdentity,
		ExpectedAdminIdentity:    payload.ExpectedAdminIdentity,
		ExpectedDatabaseOwner:    payload.ExpectedDatabaseOwner,
		ExpectedDatabaseOwnerOID: payload.ExpectedDatabaseOwnerOID,
	}
	actions := changeAuditActions[adapter.ChangeResourceCreate]
	if v2 && op.Kind == KindPostgresResourceCreateDatabaseForRolesV2 && op.ParentID != nil {
		// A read-only live Plan must pass while the durable marker still proves
		// that CREATE DATABASE could not have run. After BeginDatabase every
		// ambiguous error is forward-only/unconfirmed.
		if viaConnector {
			if err := e.requireActiveConnectorCapability(adapter.CapPostgresSuperuserDirectV1); err != nil {
				return wrap(err)
			}
			jobChange := connector.ChangeRef{
				Kind: string(change.Kind), Resource: change.Resource,
				ExpectedAdminIdentity:    payload.ExpectedAdminIdentity,
				ExpectedTargetIdentity:   payload.ExpectedTargetIdentity,
				ExpectedDatabaseOwner:    payload.ExpectedDatabaseOwner,
				ExpectedDatabaseOwnerOID: payload.ExpectedDatabaseOwnerOID,
			}
			job, buildErr := connectorMutationJobOfKind(op, conn, cfg, jobChange, connector.JobPlan, time.Now())
			if buildErr != nil {
				return wrap(buildErr)
			}
			result, dispatchErr := e.connectorDispatch(ctx, job, connectorJobCredentials(cfg))
			if dispatchErr != nil || result.Status != connector.JobSuccess {
				if dispatchErr == nil {
					dispatchErr = fmt.Errorf("connector plan status %q: %s", result.Status, result.Error)
				}
				return wrap(dispatchErr)
			}
		} else if _, err := ad.Plan(ctx, change); err != nil {
			return wrap(err)
		}
		if err := databaseprovisioning.NewStore().BeginDatabase(ctx, e.deps.Pool, *op.ParentID); err != nil {
			return wrap(err)
		}
	}
	var verification *adapter.Verification
	if viaConnector {
		verification, err = e.connectorPlanApplyVerify(ctx, op, conn, cfg, connector.ChangeRef{
			Kind: string(change.Kind), Resource: change.Resource,
			ExpectedAdminIdentity:    payload.ExpectedAdminIdentity,
			ExpectedTargetIdentity:   payload.ExpectedTargetIdentity,
			ExpectedDatabaseOwner:    payload.ExpectedDatabaseOwner,
			ExpectedDatabaseOwnerOID: payload.ExpectedDatabaseOwnerOID,
		}, connectorJobCredentials(cfg))
	} else {
		verification, err = e.planApplyVerify(ctx, op.ID, ad, change)
	}
	if err != nil {
		return errors.Join(wrap(err), e.recordMutationFailure(ctx, op, conn.ID, nil, nil, actions.failure, err))
	}
	metadata, err := json.Marshal(map[string]any{"kind": payload.Kind, "name": payload.Name})
	if err != nil {
		return wrap(fmt.Errorf("marshal audit metadata: %w", err))
	}
	var proof databaseCreationProof
	if v2 {
		proof, err = parseDatabaseCreationProof(verification, payload.Name, payload.ExpectedTargetIdentity)
		if err != nil || proof.Owner != payload.ExpectedDatabaseOwner || proof.OwnerOID != payload.ExpectedDatabaseOwnerOID {
			if err == nil {
				err = adapter.ErrTargetIdentityConflict
			}
			return wrap(err)
		}
	}
	return e.recordMutationSuccess(ctx, op, conn.ID, nil, actions.success, metadata, wrap,
		func(tx pgx.Tx) error {
			if err := e.deps.Inventory.MarkResourceObserved(ctx, tx, res.ID); err != nil {
				return err
			}
			if v2 && op.Kind == KindPostgresResourceCreateDatabaseForRolesV2 && op.ParentID != nil {
				return databaseprovisioning.NewStore().ConfirmDatabase(ctx, tx, *op.ParentID,
					proof.OID, proof.Owner, proof.OwnerOID, proof.TargetIdentity)
			}
			return nil
		})
}
