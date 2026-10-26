// Package inventory — сведение observed state из discovery snapshot в
// metadata database и чтение инвентаря (docs/architecture.md, разделы
// 6–9). Пакет владеет таблицами resources, accounts (observed-частью),
// permission_definitions и bindings в части наблюдаемого состояния;
// desired state и ownership задаются другими слоями и здесь не
// перезаписываются.
//
// Семантика status для bindings (раздел 8 архитектуры):
//   - drift — это расхождение observed state с desired state, поэтому
//     вычислять его можно только когда desired_state задан;
//   - binding с desired_state IS NULL — unmanaged: обнаружен в целевой
//     системе, решение (adopt / keep unmanaged / revoke) ещё не принято.
//     Его status не трогаем: значение по умолчанию pending читается как
//     «ждёт решения оператора», а UI отличает unmanaged по паре
//     source='external' + desired_state IS NULL, а не по status;
//   - desired='present' и observed='present' (или 'absent'/'absent') —
//     synced; несовпадение — drift;
//   - исчезнувший unmanaged binding получает observed_state='absent',
//     но status снова не меняется: внешний доступ пропал сам, дрейфа
//     относительно (отсутствующего) desired нет, строка остаётся для
//     истории до retention-очистки.
//
// Полные правила закодированы в ResolveBindingStatus; SQL-выражения в
// store.go обязаны совпадать с ней.
package inventory

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// BindingState — значение desired_state/observed_state binding.
// Совпадает с CHECK-ограничениями схемы.
type BindingState string

const (
	// BindingPresent — binding существует (или должен существовать).
	BindingPresent BindingState = "present"
	// BindingAbsent — binding отсутствует (или должен отсутствовать).
	BindingAbsent BindingState = "absent"
	// BindingUnknown — наблюдаемое состояние ещё не известно.
	BindingUnknown BindingState = "unknown"
)

// BindingStatus — значение колонки bindings.status.
type BindingStatus string

const (
	// BindingStatusSynced — observed совпадает с desired.
	BindingStatusSynced BindingStatus = "synced"
	// BindingStatusPending — применение ещё впереди: у binding есть
	// desired_state, и операция либо в очереди, либо будет поставлена.
	BindingStatusPending BindingStatus = "pending"
	// BindingStatusObserved — binding наблюдается в целевой системе и НЕ
	// находится под управлением (desired_state IS NULL). Отдельное значение
	// нужно, чтобы не выдавать за «ожидает применения» то, что применять
	// никто не собирается: решение оператора по такому праву ещё не принято.
	BindingStatusObserved BindingStatus = "observed"
	// BindingStatusDrift — observed расходится с desired.
	BindingStatusDrift BindingStatus = "drift"
	// BindingStatusFailed — последнее применение завершилось ошибкой.
	BindingStatusFailed BindingStatus = "failed"
)

// BindingSource — значение колонки bindings.source. Совпадает с
// CHECK-ограничением схемы; SQL-выражения store.go используют те же
// литералы.
type BindingSource string

const (
	// BindingSourceExternal — binding обнаружен discovery в целевой
	// системе; до принятия решения он unmanaged (source='external' и
	// desired_state IS NULL).
	BindingSourceExternal BindingSource = "external"
	// BindingSourceService — binding заведён сервисом grantor (desired
	// state задаётся явно).
	BindingSourceService BindingSource = "service"
	// BindingSourceInherited — право получено через цепочку ролей, прямого
	// ребра в целевой системе нет. Отзывать такой binding напрямую нельзя:
	// команда отзыва не находит что снимать и завершается no-op, а Verify
	// той же проверкой подтверждает «снято» (см. deleteBinding).
	BindingSourceInherited BindingSource = "inherited"
)

// AccountStatus — значение колонки accounts.status. Совпадает с
// CHECK-ограничением схемы; SQL-выражения store*.go используют те же
// литералы.
type AccountStatus string

const (
	// AccountActive — учётная запись активна.
	AccountActive AccountStatus = "active"
	// AccountDisabled — учётная запись отключена.
	AccountDisabled AccountStatus = "disabled"
	// AccountDeleted — учётная запись помечена удалённой (soft delete):
	// строка сохранена ради истории операций, её bindings удалены.
	AccountDeleted AccountStatus = "deleted"
	// AccountProvisioning — строка создана control plane как резервация
	// identity, но account.create ещё не подтвердил учётку в целевой
	// системе. Живым managed-аккаунтом такая запись не является: массовые
	// операции принципала (ротация, каскад статуса) её пропускают.
	// Провалившийся account.create оставляет аккаунт в этом статусе —
	// retry и повторный запрос доступа переиспользуют ту же строку.
	AccountProvisioning AccountStatus = "provisioning"
	// AccountMissing — discovery не нашёл managed-аккаунт в целевой
	// системе. Симметрично ResourceMissing: discovery не удаляет, а
	// фиксирует расхождение для отчёта дрифта.
	AccountMissing AccountStatus = "missing"
)

// IsLiveAccountStatus сообщает, что учётная запись считается существующей
// в целевой системе: только active и disabled. provisioning (ещё не
// создана), missing (исчезла) и deleted (tombstone) — не живые.
// Используется API-слоем для отбора аккаунтов массовых операций.
func IsLiveAccountStatus(s AccountStatus) bool {
	return s == AccountActive || s == AccountDisabled
}

// IdentityConflictReason объясняет, почему engine identity нельзя занять под
// новую учётную запись, и называет реальный выход. Общий текст для API и
// декларативного access-манифеста: оба упираются в одну и ту же коллизию, и
// расходящиеся формулировки уводили бы оператора по разным путям.
//
// Развилка принципиальна. Живую unmanaged-учётку берут под управление
// link/adopt. А identity, занятую tombstone (managed-аккаунт в статусе
// deleted), ни link, ни adopt не освобождают: строка сохранена ради истории
// операций, и единственная штатная операция, возвращающая её в строй, —
// account.restore. Она доступна только на движках, объявивших capability
// account.restore, поэтому restoreSupported определяет, называть её выходом
// или честно сказать, что выхода на этом движке нет.
//
// Второй выход есть всегда: purge tombstone (DELETE
// /api/v1/accounts/{id}/purge?confirm=true, admin) безвозвратно удаляет
// metadata-строку и вместе с ней освобождает identity. Он назван вторым,
// потому что теряет историю операций аккаунта, тогда как restore её
// сохраняет; на движке без account.restore он остаётся единственным.
func IdentityConflictReason(identity string, connectionID uuid.UUID, acct Account, restoreSupported bool) string {
	if acct.Status == AccountDeleted {
		if restoreSupported {
			return fmt.Sprintf(
				"identity %q in connection %s is held by the tombstone of deleted account %s; "+
					"restore that account (POST /api/v1/accounts/%s/restore, admin) to reuse the identity, "+
					"or drop the tombstone for good (DELETE /api/v1/accounts/%s/purge?confirm=true, admin)",
				identity, connectionID, acct.ID, acct.ID, acct.ID)
		}
		return fmt.Sprintf(
			"identity %q in connection %s is held by the tombstone of deleted account %s, "+
				"and this connection engine does not support account restore: "+
				"the identity is freed only by purging the tombstone "+
				"(DELETE /api/v1/accounts/%s/purge?confirm=true, admin)",
			identity, connectionID, acct.ID, acct.ID)
	}
	return fmt.Sprintf(
		"identity %q in connection %s is already taken by a %s/%s account; link or adopt it first",
		identity, connectionID, acct.Ownership, acct.Status)
}

// ResourceStatus — значение колонки resources.status. Совпадает с
// CHECK-ограничением схемы; SQL-выражения store.go используют те же
// литералы.
type ResourceStatus string

const (
	// ResourceObserved — ресурс наблюдался в последнем discovery.
	ResourceObserved ResourceStatus = "observed"
	// ResourcePlanned — ресурс существует только как desired state и в
	// снапшоте появиться ещё не мог (discovery его не трогает).
	ResourcePlanned ResourceStatus = "planned"
	// ResourceMissing — ресурс исчез из целевой системы; discovery не
	// удаляет, а помечает missing.
	ResourceMissing ResourceStatus = "missing"
	// ResourceStale — наблюдение устарело (refresh/retention).
	ResourceStale ResourceStatus = "stale"
)

// Ownership — принадлежность управления сущностью (колонки
// accounts.ownership и resources.ownership). Совпадает с
// CHECK-ограничением схемы.
type Ownership string

const (
	// OwnershipManaged — сущностью управляет grantor.
	OwnershipManaged Ownership = "managed"
	// OwnershipUnmanaged — сущность обнаружена в целевой системе, но под
	// управление grantor ещё не принята.
	OwnershipUnmanaged Ownership = "unmanaged"
)

// Режимы credential учётной записи (подмножество CHECK-ограничения
// accounts.credential_mode, которым оперирует сервис): generated — пароль
// создан адаптером, provided — задан оператором, existing_vault_ref —
// аккаунт делит общий секрет принципала (vault_path ведёт в раздел
// principals/<id>/…). Значения используются и API-слоем (тела запросов), и
// executor (фиксация применённого credential), поэтому живут в доменном
// пакете.
const (
	CredentialModeGenerated = "generated"
	CredentialModeProvided  = "provided"
	// CredentialModeExistingVaultRef означает ссылку account на общий
	// principal/environment secret, а не собственный per-account secret.
	CredentialModeExistingVaultRef = "existing_vault_ref"
)

// BindingNeedsRepair сообщает, что затребованное право ТОЧНО не работает:
// применение завершилось ошибкой, discovery увидел отсутствие права в
// целевой системе либо увидел его выданным, но недействующим (роль вне
// набора по умолчанию).
//
// Проверяется именно достоверно известная поломка, а не «не подтверждено».
// Свежий грант живёт с observed_state='unknown' до первого discovery, и
// считать его сломанным нельзя: повторная выдача плодила бы дубли операций
// на каждое нажатие. Зато известная поломка обязана чиниться штатной
// выдачей — иначе grantor показывает расхождение и не даёт его устранить
// (см. docs/audit-2026-07-fixes.md, раздел 2). Провал применения — поломка
// того же рода: исход достоверен, а до следующего discovery binding иначе
// неотличим от здорового и блокирует повторную выдачу впустую.
func BindingNeedsRepair(b Binding) bool {
	if b.DesiredState == nil || *b.DesiredState != BindingPresent {
		return false
	}
	// До switch по observed сознательно: failed возможен и поверх
	// observed=present/effective (грант упал на уже выданном праве), и
	// такой binding тоже обязан разблокироваться. Повторная выдача сама
	// вернёт строку в pending (EnsureBinding on conflict).
	if b.Status == BindingStatusFailed {
		return true
	}
	if b.AssignmentKey != "" && b.ObservedState == BindingPresent &&
		(b.ObservedPermissionDefinitionID == nil ||
			*b.ObservedPermissionDefinitionID != b.PermissionDefinitionID) {
		return true
	}
	switch b.ObservedState {
	case BindingAbsent:
		return true
	case BindingPresent:
		return !b.ObservedEffective
	default:
		return false // unknown: ещё не наблюдалось, поломка не доказана
	}
}

// ResolveBindingStatus вычисляет status binding после обновления его
// observed state. desired == nil означает unmanaged binding — его status
// не меняется (см. семантику в doc-комментарии пакета). Неизвестный
// observed тоже оставляет status прежним: без наблюдения сравнивать не с
// чем. Иначе совпадение desired и observed даёт synced, расхождение —
// drift (в том числе поверх прежнего failed: фактическое состояние
// важнее исхода последнего применения).
func ResolveBindingStatus(
	desired *BindingState,
	observed BindingState,
	effective bool,
	current BindingStatus,
) BindingStatus {
	if desired == nil {
		// Непринятое право: управлять им никто не начинал, поэтому статус
		// описывает наблюдение, а не ожидание применения.
		return BindingStatusObserved
	}
	if observed == BindingUnknown {
		return current
	}
	// Право, которое существует, но не действует, синхронизированным не
	// является: control plane обещал доступ, а доступа нет. Это дрифт, и
	// именно он был не виден, пока признак терялся между адаптером и
	// хранилищем (см. миграцию 00018).
	if *desired == BindingPresent && observed == BindingPresent && !effective {
		return BindingStatusDrift
	}
	if *desired == observed {
		return BindingStatusSynced
	}
	return BindingStatusDrift
}

// Resource зеркалит строку таблицы resources.
type Resource struct {
	ID            uuid.UUID
	ConnectionID  uuid.UUID
	ParentID      *uuid.UUID
	Kind          string
	ExternalID    string
	Name          string
	CanonicalPath string
	Attributes    json.RawMessage
	Fingerprint   string
	ObservedAt    *time.Time
	Status        ResourceStatus
	Ownership     Ownership
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ResourceTreeItem — облегчённая проекция ресурса для больших UI-деревьев.
// Не несёт attributes/fingerprint/timestamps: полная карточка читается по id.
type ResourceTreeItem struct {
	ID           uuid.UUID
	ConnectionID uuid.UUID
	ParentID     *uuid.UUID
	Kind         string
	Name         string
	Status       ResourceStatus
	Ownership    Ownership
}

// Account зеркалит строку таблицы accounts.
type Account struct {
	ID                  uuid.UUID
	PrincipalID         *uuid.UUID
	ConnectionID        uuid.UUID
	Kind                string
	EngineIdentity      string
	AuthenticationScope string
	CredentialMode      *string
	VaultPath           string
	Status              AccountStatus
	Ownership           Ownership
	Attributes          json.RawMessage
	// DeletedAt/DeletedBy/DeleteReason — информация об удалении tombstone
	// (status=deleted): момент, актор операции account.delete и
	// необязательная причина, заданная оператором или каскадом offboard.
	// NULL у живых аккаунтов и у старых tombstone'ов, удалённых до ввода
	// этих колонок.
	DeletedAt    *time.Time
	DeletedBy    *string
	DeleteReason *string
	// LifecycleVersion — монотонное поколение account lifecycle. API
	// резервирует следующую версию атомарно с постановкой операции, а worker
	// сверяет её до любого обращения к Vault или target.
	LifecycleVersion int64
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// PermissionStatus — значение колонки permission_definitions.status.
// Совпадает с CHECK-ограничением схемы (миграция 00026).
type PermissionStatus string

const (
	// PermissionObserved — право присутствует в последнем снапшоте.
	PermissionObserved PermissionStatus = "observed"
	// PermissionMissing — discovery перестал видеть право в целевой
	// системе. Строка не удаляется: на неё ссылаются bindings, включая
	// managed с desired=present — расхождение оператор обязан видеть.
	PermissionMissing PermissionStatus = "missing"
)

// Permission зеркалит строку таблицы permission_definitions.
type Permission struct {
	ID              uuid.UUID
	ConnectionID    uuid.UUID
	Engine          string
	ExternalID      string
	Name            string
	ScopeResourceID *uuid.UUID
	AssignmentKey   string
	Assignable      bool
	Dangerous       bool
	Attributes      json.RawMessage
	Status          PermissionStatus
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Binding зеркалит строку таблицы bindings. DesiredState == nil означает
// unmanaged binding (см. doc-комментарий пакета).
type Binding struct {
	ID                     uuid.UUID
	AccountID              uuid.UUID
	PermissionDefinitionID uuid.UUID
	ScopeResourceID        *uuid.UUID
	AssignmentKey          string
	// ObservedPermissionDefinitionID — exact permission/template последнего
	// discovery. Для exclusive slot может отличаться от desired
	// PermissionDefinitionID; nil означает, что фактическое право отсутствует
	// либо не удалось сопоставить каталогу.
	ObservedPermissionDefinitionID *uuid.UUID
	ObservedAttributes             json.RawMessage
	Source                         string
	DesiredState                   *BindingState
	ObservedState                  BindingState
	// ObservedEffective — наблюдаемый грант фактически действует. false
	// означает «право выдано, но доступа не даёт» (см.
	// adapter.AttrBindingEffective). Для движков без такого различия всегда
	// true.
	ObservedEffective     bool
	Status                BindingStatus
	ExpiresAt             *time.Time
	Version               int64
	TransitionOperationID *uuid.UUID
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// UpsertStats — счётчики одного сведения snapshot. Resources, Accounts,
// Permissions и Bindings — количество записей снапшота, прошедших через
// upsert (не количество фактически изменённых строк); MissingResources —
// количество ресурсов, помеченных missing в этом вызове.
type UpsertStats struct {
	Resources   int
	Accounts    int
	Permissions int
	Bindings    int
	// MissingResources / MissingAccounts / MissingPermissions — количество
	// строк, помеченных missing в этом вызове. Аккаунты и права помечаются
	// только когда снапшот действительно их перечисляет (capabilities
	// inventory.accounts / inventory.permissions).
	MissingResources   int
	MissingAccounts    int
	MissingPermissions int
}

// DriftCounters — сводка расхождений по connection для UI (раздел 20.7
// архитектуры).
type DriftCounters struct {
	// UnmanagedBindings — обнаруженные внешние bindings без принятого
	// решения: source='external' и desired_state IS NULL.
	UnmanagedBindings int
	// DriftBindings — bindings в статусе drift.
	DriftBindings int
	// MissingManagedResources — managed-ресурсы, исчезнувшие из целевой
	// системы (status='missing').
	MissingManagedResources int
	// MissingManagedAccounts — managed-аккаунты, которых discovery не
	// нашёл в целевой системе (status='missing'), и аккаунты, чей
	// account.create не подтвердился (status='provisioning'). Оба случая
	// означают одно: control plane считает учётку своей, а на target её
	// нет.
	MissingManagedAccounts int
}

// Виды расхождений в отчёте DriftFindings (раздел 20.7 архитектуры).
// Значения — стабильные идентификаторы для API и UI.
const (
	// DriftKindBindingDrift — observed state binding разошёлся с desired.
	DriftKindBindingDrift = "binding_drift"
	// DriftKindUnmanagedBinding — обнаруженный внешний binding без
	// принятого решения (source='external', desired IS NULL, observed
	// present).
	DriftKindUnmanagedBinding = "unmanaged_binding"
	// DriftKindMissingResource — managed-ресурс исчез из целевой системы.
	DriftKindMissingResource = "missing_resource"
	// DriftKindCredentialDiverged — версия секрета в Vault опередила ту,
	// которую grantor применил к целевой системе: пароль правили мимо
	// grantor (см. internal/core/credentialcheck). Выдаваемый оператору
	// пароль в этом случае может не работать.
	DriftKindCredentialDiverged = "credential_diverged"
	// DriftKindMissingAccount — managed-аккаунт отсутствует в целевой
	// системе: discovery не нашёл его (status='missing') либо его
	// account.create так и не подтвердился (status='provisioning').
	DriftKindMissingAccount = "missing_account"
)

// DriftFinding — одна строка отчёта о расхождениях для раздела «Дрифт»
// UI. Kind определяет заполненные ссылки: binding-виды несут
// binding/account/permission (и scope resource, если он задан),
// missing_resource — только resource. Строковые поля — денормализованные
// имена для отображения без дозапросов; Detail — готовое описание
// расхождения.
type DriftFinding struct {
	Kind            string
	ConnectionID    uuid.UUID
	BindingID       *uuid.UUID
	AccountID       *uuid.UUID
	ResourceID      *uuid.UUID
	PermissionID    *uuid.UUID
	AccountIdentity string
	PermissionName  string
	ResourceName    string
	Detail          string
}
