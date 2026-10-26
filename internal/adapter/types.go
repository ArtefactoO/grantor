package adapter

import (
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Capability — типизированное имя операции, которую adapter поддерживает.
// Полный список групп — docs/architecture.md, раздел 10.3. Наличие capability
// в manifest не означает разрешения операции: capabilities включаются для
// каждого connection отдельно.
type Capability string

const (
	CapInventoryResources   Capability = "inventory.resources"
	CapInventoryAccounts    Capability = "inventory.accounts"
	CapInventoryPermissions Capability = "inventory.permissions"
	CapInventoryBindings    Capability = "inventory.bindings"

	CapAccountCreate Capability = "account.create"
	// CapRoleCreate — создание роли-контейнера без логина (PostgreSQL
	// NOLOGIN): она не аутентифицируется, пароля не имеет и существует, чтобы
	// выдаваться другим учётным записям как право. Отдельная capability, а не
	// параметр account.create: не каждый движок с account.create умеет роли,
	// а флаг поверх общей capability сделал бы гейт слепым — adapter, не
	// знающий про флаг, создал бы обычную учётку с логином и без пароля.
	CapRoleCreate     Capability = "role.create"
	CapAccountDisable Capability = "account.disable"
	CapAccountEnable  Capability = "account.enable"
	CapAccountDelete  Capability = "account.delete"
	// CapAccountRestore разрешена только adapter'ам, которые могут доказать
	// аутентификацию конкретной target identity ровно переданным credential.
	CapAccountRestore Capability = "account.restore"

	CapCredentialRotate Capability = "credential.rotate"
	// CapCredentialProve означает, что adapter может независимо проверить:
	// target аутентифицировал ровно указанную identity переданным credential.
	// В отличие от account.restore, capability не создаёт/восстанавливает
	// аккаунт и используется общим link-and-manage flow после ротации.
	CapCredentialProve Capability = "credential.prove"

	CapAccessGrant  Capability = "access.grant"
	CapAccessRevoke Capability = "access.revoke"
	// CapPostgresStatsMembershipV1 negotiates the closed pg_read_all_stats
	// grant/revoke contract; SUPERUSER authority is independently required.
	CapPostgresStatsMembershipV1 Capability = "postgres.stats_membership.v1"
	// CapPostgresSuperuserDirectV1 is the explicit protocol/authority marker
	// for the closed PostgreSQL SUPERUSER-direct mutation vocabulary. Merely
	// listing the marker in a manifest must not enable mutations: the effective
	// connection capabilities retain it only after a current live authority proof.
	CapPostgresSuperuserDirectV1 Capability = "postgres.superuser_direct.v1"
	// CapRolePolicyApply позволяет материализовать и чинить заранее
	// описанную role-policy. Наличие одной inventory роли недостаточно:
	// PostgreSQL включает capability только после полного SUPERUSER-direct
	// discovery/connector attestation конкретного connection.
	CapRolePolicyApply Capability = "role.policy.apply"
	// CapRolePolicyCreate creates a missing fixed-profile role without
	// rewriting an existing role. Exact existing state is recovery-only.
	CapRolePolicyCreate Capability = "role.policy.create"
)

// ResourceCapability строит параметризованную capability вида
// "resource.<action>.<kind>", например resource.create.database.
func ResourceCapability(action, kind string) Capability {
	return Capability("resource." + action + "." + kind)
}

// AccountDisableEffect описывает, что account.disable движка делает с уже
// выданными правами учётной записи. Ядро обязано знать это, чтобы не
// утверждать observed-состояние bindings, которого на target больше нет, и
// чтобы понимать, должен ли account.enable вернуть права из desired state.
type AccountDisableEffect string

const (
	// DisableKeepsAccess — disable блокирует только вход, а выданные права
	// остаются на target (PostgreSQL NOLOGIN, Redis ACL SETUSER off,
	// ClickHouse HOST NONE). Нулевое значение Manifest означает именно это:
	// без явного заявления обратного ядро считает права сохранёнными и
	// bindings не трогает.
	DisableKeepsAccess AccountDisableEffect = ""
	// DisableClearsAccess — у движка нет нативной блокировки, поэтому
	// disable снимает саму авторизацию и выданные права исчезают с target
	// (RabbitMQ). Такой manifest обязывает ядро: после disable записать
	// bindings observed='absent', а после enable восстановить их обычным
	// grant-потоком из desired state — иначе учётная запись включится без
	// прав, а её bindings останутся ложно synced до следующего discovery.
	DisableClearsAccess AccountDisableEffect = "clears-access"
)

// Manifest описывает adapter для backend и UI (раздел 10.2 архитектуры).
type Manifest struct {
	Engine        string
	Version       string
	ResourceKinds []string
	Capabilities  []Capability
	// AccountDisableEffect — семантика disable движка; пустое значение
	// равно DisableKeepsAccess.
	AccountDisableEffect AccountDisableEffect
	ConnectionSchema     string
}

// DisableClearsAccess сообщает, уничтожает ли account.disable движка сами
// выданные права (см. AccountDisableEffect).
func (m Manifest) DisableClearsAccess() bool {
	return m.AccountDisableEffect == DisableClearsAccess
}

// CapabilityNames возвращает безопасную строковую копию capability-манифеста
// движка. Это engine-wide максимум: эффективный набор подключения уже он или
// его подмножество (см. CapabilitiesFor).
func (m Manifest) CapabilityNames() []string {
	return CapabilityNames(m.Capabilities)
}

// CapabilityNames возвращает строковую копию набора capabilities для хранения
// на connection. Хранимая копия нужна UI и API-гвардам, а источником истины
// остаётся зарегистрированный adapter.
func CapabilityNames(caps []Capability) []string {
	out := make([]string, len(caps))
	for i := range caps {
		out[i] = string(caps[i])
	}
	return out
}

// HasCapability сообщает, объявляет ли adapter данную capability.
func (m Manifest) HasCapability(c Capability) bool {
	return slices.Contains(m.Capabilities, c)
}

// HasManagedCredentialCapabilities проверяет включение минимального набора
// capability для общего link-and-manage flow на конкретном connection.
func HasManagedCredentialCapabilities(capabilities []string) bool {
	return slices.Contains(capabilities, string(CapCredentialRotate)) &&
		slices.Contains(capabilities, string(CapCredentialProve))
}

// Connection передаёт adapter доступ к целевой системе. Секретные поля живут
// только в памяти: core читает их из Vault непосредственно перед вызовом; они
// не логируются и не сохраняются в metadata database.
type Connection struct {
	ID                string
	Engine            string
	AuthMode          string // password (default) | none (Redis inventory only)
	Endpoints         []string
	TLS               TLSConfig
	Attributes        map[string]any
	ConfigIncarnation string

	AdminCredential            Credential
	AdminCredentialIncarnation int
}

// TLSConfig — параметры TLS подключения к целевой системе.
type TLSConfig struct {
	Mode          string // disabled|require|verify-ca|verify-full
	CACertPEM     []byte
	ClientCertPEM []byte
	// ClientKeyPEM — секрет: только в памяти.
	ClientKeyPEM []byte
	// InsecureSkipVerify требует отдельного подтверждения и отображается
	// как security finding (раздел 5.2 архитектуры).
	InsecureSkipVerify bool
}

// Credential — секретный материал учётной записи. Никогда не попадает в
// логи, plan descriptions, audit или metadata database.
type Credential struct {
	Kind     string // password|token|certificate|external
	Username string
	Secret   []byte
}

// CredentialPolicy — политика генерации credential.
type CredentialPolicy struct {
	Length int
}

// Account идентифицирует учётную запись в целевой системе. EngineIdentity
// уникален в рамках connection: adapter кодирует в него engine-специфичную
// дизамбигуацию (mysql user@host, mongo user@authdb).
type Account struct {
	Kind                string // login|group
	EngineIdentity      string
	AuthenticationScope string
}

// Snapshot — нормализованный результат discovery (раздел 9 архитектуры).
type Snapshot struct {
	ServerVersion string
	Topology      map[string]any
	Resources     []ObservedResource
	Accounts      []ObservedAccount
	Permissions   []ObservedPermission
	Bindings      []ObservedBinding
	RolePolicies  []ObservedRolePolicy
	ObservedAt    time.Time
	// A failed database probe cannot be interpreted as deletion of its inventory.
	IncompleteScopes []string
}

// MongoRoleRef is an unambiguous MongoDB role identity. Keeping the database
// mandatory prevents the short string form accepted by MongoDB commands from
// changing meaning when a policy is moved between role databases.
type MongoRoleRef struct {
	Role string `json:"role"`
	DB   string `json:"db"`
}

// MongoRoleResource is the complete, typed subset of MongoDB privilege
// resource documents understood by Grantor. Exactly one of Cluster,
// AnyResource or the DB/Collection pair is meaningful; the catalog validator
// rejects ambiguous combinations and currently forbids AnyResource templates.
type MongoRoleResource struct {
	DB          string `json:"db,omitempty"`
	Collection  string `json:"collection,omitempty"`
	Cluster     bool   `json:"cluster,omitempty"`
	AnyResource bool   `json:"any_resource,omitempty"`
}

// MarshalJSON emits exactly one MongoDB resource shape. In particular the
// all-databases namespace remains {"db":"","collection":""} rather
// than collapsing to an ambiguous empty object through omitempty.
func (r MongoRoleResource) MarshalJSON() ([]byte, error) {
	switch {
	case r.AnyResource:
		return json.Marshal(struct {
			AnyResource bool `json:"any_resource"`
		}{AnyResource: true})
	case r.Cluster:
		return json.Marshal(struct {
			Cluster bool `json:"cluster"`
		}{Cluster: true})
	default:
		return json.Marshal(struct {
			DB         string `json:"db"`
			Collection string `json:"collection"`
		}{DB: r.DB, Collection: r.Collection})
	}
}

// UnmarshalJSON requires the resource scope to be explicit. In particular,
// an omitted db/collection pair must never collapse to the zero value, which
// MongoDB interprets as all non-system collections in every database.
func (r *MongoRoleResource) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("mongodb role resource target is nil")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("mongodb role resource must be a JSON object")
	}
	*r = MongoRoleResource{}
	if len(fields) == 2 {
		db, hasDB := fields["db"]
		collection, hasCollection := fields["collection"]
		if !hasDB || !hasCollection {
			return errors.New("mongodb namespace resource requires explicit db and collection fields")
		}
		var dbValue, collectionValue *string
		if err := json.Unmarshal(db, &dbValue); err != nil || dbValue == nil {
			return errors.New("mongodb namespace resource db must be a string")
		}
		if err := json.Unmarshal(collection, &collectionValue); err != nil || collectionValue == nil {
			return errors.New("mongodb namespace resource collection must be a string")
		}
		r.DB = *dbValue
		r.Collection = *collectionValue
		return nil
	}
	if len(fields) != 1 {
		return errors.New("mongodb role resource must be exactly namespace, cluster, or any_resource")
	}
	if raw, ok := fields["cluster"]; ok {
		if err := json.Unmarshal(raw, &r.Cluster); err != nil || !r.Cluster {
			return errors.New("mongodb cluster resource must be true")
		}
		return nil
	}
	if raw, ok := fields["any_resource"]; ok {
		if err := json.Unmarshal(raw, &r.AnyResource); err != nil || !r.AnyResource {
			return errors.New("mongodb any_resource must be true")
		}
		return nil
	}
	return errors.New("mongodb role resource contains an unknown field")
}

// MongoRolePrivilege couples one typed resource with a bounded list of
// documented authorization actions. It deliberately cannot carry raw BSON.
type MongoRolePrivilege struct {
	Resource MongoRoleResource `json:"resource"`
	Actions  []string          `json:"actions"`
}

// RolePolicySpec — нормализованный, secret-free шаблон engine-роли.
// PostgreSQL and MongoDB share the lifecycle envelope. For MongoDB Database is
// the role database; engine-specific privileges remain typed so neither the
// API nor connector payload can smuggle raw SQL/BSON/target commands.
type RolePolicySpec struct {
	Engine              string               `json:"engine"`
	Key                 string               `json:"key"`
	Name                string               `json:"name"`
	Description         string               `json:"description"`
	RoleName            string               `json:"role_name"`
	Database            string               `json:"database"`
	Schemas             []string             `json:"schemas"`
	OwnerRoles          []string             `json:"owner_roles"`
	CreatorRoles        []string             `json:"creator_roles"`
	Profile             string               `json:"profile"`
	MongoInheritedRoles []MongoRoleRef       `json:"inherited_roles,omitempty"`
	MongoPrivileges     []MongoRolePrivilege `json:"privileges,omitempty"`
}

// ObservedRolePolicy — exact read-back одного настроенного шаблона. Summary
// содержит только безопасный, ограниченный preview расхождений; источником
// истины для сравнения служат непрозрачные fingerprints и Exact.
type ObservedRolePolicy struct {
	ExternalID          string         `json:"external_id"`
	Spec                RolePolicySpec `json:"spec"`
	ExpectedFingerprint string         `json:"expected_fingerprint"`
	ObservedFingerprint string         `json:"observed_fingerprint"`
	Exact               bool           `json:"exact"`
	// Dangerous is computed by the adapter from normalized privileges and
	// inheritance rather than trusted from a catalog display name.
	Dangerous      bool           `json:"dangerous"`
	ApplySupported bool           `json:"apply_supported"`
	BlockedReason  string         `json:"blocked_reason,omitempty"`
	Summary        map[string]any `json:"summary,omitempty"`
}

// ObservedResource — обнаруженный ресурс. ExternalID стабилен между
// discoveries и уникален в рамках connection.
type ObservedResource struct {
	Kind             string
	ExternalID       string
	ParentExternalID string // пусто для корневых ресурсов
	Name             string
	CanonicalPath    string
	Attributes       map[string]any
	Fingerprint      string
}

// ObservedAccount — обнаруженная учётная запись.
type ObservedAccount struct {
	Kind                string // login|group
	EngineIdentity      string
	AuthenticationScope string
	Disabled            bool
	Attributes          map[string]any
}

// ObservedPermission — обнаруженная роль или permission set.
type ObservedPermission struct {
	ExternalID      string
	Name            string
	ScopeExternalID string // external id ресурса; пусто для cluster-wide
	// AssignmentKey объединяет взаимоисключающие permissions в один slot.
	// Пустое значение сохраняет обычную модель независимых назначений.
	AssignmentKey string
	Assignable    bool
	Dangerous     bool
	Attributes    map[string]any
	// AccountEngineIdentity — заполняется, когда право и учётная запись в
	// движке ОДНА И ТА ЖЕ сущность. В PostgreSQL роль без LOGIN публикуется
	// как назначаемое право, но выключенная grantor учётка тоже становится
	// NOLOGIN — и внешне неотличима от роли.
	//
	// Ядро использует эту связь, чтобы не предлагать к выдаче собственную
	// учётную запись: выдача такого «права» другому принципалу передала бы
	// ему все привилегии её владельца. Пусто — право самостоятельно.
	AccountEngineIdentity string
}

// ObservedBinding — обнаруженная связь account/permission/scope.
type ObservedBinding struct {
	AccountEngineIdentity string
	PermissionExternalID  string
	ScopeExternalID       string
	// AssignmentKey должен совпадать с ключом наблюдаемого permission.
	// Пустое значение означает non-exclusive binding; store также умеет взять
	// backfilled key из permission definition для старых adapters.
	AssignmentKey string
	Inherited     bool
	Attributes    map[string]any
}

// AttrBindingEffective — ключ в ObservedBinding.Attributes, которым адаптер
// сообщает, что наблюдаемый грант ФАКТИЧЕСКИ ДЕЙСТВУЕТ.
//
// Существует потому, что «грант есть» и «грант даёт доступ» — разные вещи.
// В MySQL и ClickHouse роль, не входящая в набор ролей по умолчанию
// (SET DEFAULT ROLE NONE), числится выданной в системных таблицах и не даёт
// ничего: SHOW GRANTS её показывает, а запрос отвергается. Без явного
// признака ядро считало такой binding синхронизированным, оператор видел
// «доступ выдан», а пользователь получал отказ.
//
// Значение — bool. Отсутствие ключа означает «действует»: движок, который
// такого различия не делает, ничего сообщать не обязан.
const AttrBindingEffective = "effective"

// BindingEffective читает признак действенности из атрибутов наблюдаемого
// binding. Умолчание — true (см. AttrBindingEffective).
func BindingEffective(attrs map[string]any) bool {
	v, ok := attrs[AttrBindingEffective]
	if !ok {
		return true
	}
	effective, ok := v.(bool)
	return !ok || effective
}

// AttrConnectionAdmin — ключ в ObservedAccount.Attributes, которым ядро
// помечает учётную запись, под которой grantor сам управляет подключением
// (admin credential из Vault).
//
// Ставит его не adapter, а discovery-job: имя admin-учётки — свойство
// подключения, а не целевой системы, и движок о нём ничего не знает.
// Присвоение такой учётки под управление ломает само управление
// подключением, поэтому API её adopt отклоняет.
//
// Значение — bool. Отсутствие ключа означает обычную учётную запись.
const AttrConnectionAdmin = "connection_admin"

// Ключи Connection.Attributes с allowlists создания базы (architecture
// §11.2). Пустой или отсутствующий список запрещает задавать соответствующую
// опцию: расширение возможностей должно быть явным решением оператора.
const (
	AttrDatabaseCreateTemplates   = "database_create_templates"
	AttrDatabaseCreateOwners      = "database_create_owners"
	AttrDatabaseCreateTablespaces = "database_create_tablespaces"
)

// ChangeKind — тип изменения desired state.
type ChangeKind string

const (
	ChangeGrant          ChangeKind = "grant"
	ChangeRevoke         ChangeKind = "revoke"
	ChangeAccountCreate  ChangeKind = "account.create"
	ChangeRoleCreate     ChangeKind = "role.create"
	ChangeAccountDisable ChangeKind = "account.disable"
	ChangeAccountEnable  ChangeKind = "account.enable"
	ChangeAccountDelete  ChangeKind = "account.delete"
	ChangeAccountRestore ChangeKind = "account.restore"
	ChangeResourceCreate ChangeKind = "resource.create"
	// ChangeRolePolicyApply допускает target-side effect через строго
	// типизированный adapter plan. ChangeRolePolicyVerify используется adopt:
	// worker/connector выполняет только Verify и никогда не вызывает Apply.
	ChangeRolePolicyApply  ChangeKind = "role.policy.apply"
	ChangeRolePolicyVerify ChangeKind = "role.policy.verify"
	ChangeRolePolicyCreate ChangeKind = "role.policy.create"
	// ChangeRolePolicyCreateDatabase pins the newly created database incarnation.
	// A separate kind makes old connectors fail closed instead of ignoring OID.
	ChangeRolePolicyCreateDatabase ChangeKind = "role.policy.create_database"

	// PostgreSQL SUPERUSER-direct v2 kinds intentionally do not reuse the
	// generic lifecycle vocabulary. An older worker/connector therefore fails
	// closed before adapter dispatch instead of applying a newly broadened
	// PostgreSQL contract with legacy semantics. Generic kinds above remain the
	// wire contract for other engines.
	ChangePostgresAccountCreateV2            ChangeKind = "postgres.account.create.v2"
	ChangePostgresAccountRestoreV2           ChangeKind = "postgres.account.restore.v2"
	ChangePostgresRoleCreateV2               ChangeKind = "postgres.role.create.v2"
	ChangePostgresDatabaseCreateV2           ChangeKind = "postgres.resource.create.database.v2"
	ChangePostgresRolePolicyApplyV2          ChangeKind = "postgres.role.policy.apply.v2"
	ChangePostgresRolePolicyVerifyV2         ChangeKind = "postgres.role.policy.verify.v2"
	ChangePostgresRolePolicyAdoptV2          ChangeKind = "postgres.role.policy.adopt.v2"
	ChangePostgresRolePolicyRepairV2         ChangeKind = "postgres.role.policy.repair.v2"
	ChangePostgresRolePolicyCreateV2         ChangeKind = "postgres.role.policy.create.v2"
	ChangePostgresRolePolicyCreateDatabaseV2 ChangeKind = "postgres.role.policy.create_database.v2"
	ChangePostgresStatsMembershipGrantV1     ChangeKind = "postgres.stats_membership.grant.v1"
	ChangePostgresStatsMembershipRevokeV1    ChangeKind = "postgres.stats_membership.revoke.v1"
)

// IsPostgresSuperuserDirectChange reports whether kind belongs to the closed
// v2 PostgreSQL mutation namespace. It is shared by worker and connector
// gates; support for a generic capability must never authorize these kinds.
func IsPostgresSuperuserDirectChange(kind ChangeKind) bool {
	if IsPostgresObjectACLChange(kind) {
		return true
	}
	switch kind {
	case ChangePostgresAccountCreateV2, ChangePostgresAccountRestoreV2, ChangePostgresRoleCreateV2,
		ChangePostgresDatabaseCreateV2, ChangePostgresRolePolicyApplyV2,
		ChangePostgresRolePolicyVerifyV2, ChangePostgresRolePolicyAdoptV2,
		ChangePostgresRolePolicyRepairV2, ChangePostgresRolePolicyCreateV2,
		ChangePostgresRolePolicyCreateDatabaseV2, ChangePostgresStatsMembershipGrantV1, ChangePostgresStatsMembershipRevokeV1:
		return true
	default:
		return false
	}
}

// IsLegacyPostgresCreationChange identifies generic kinds that were once
// executable for PostgreSQL but are now history-only there. The same generic
// values remain valid contracts for other engines, so callers must combine
// this classifier with an exact engine check.
func IsLegacyPostgresCreationChange(kind ChangeKind) bool {
	switch kind {
	case ChangeAccountCreate, ChangeAccountRestore, ChangeRoleCreate,
		ChangeResourceCreate, ChangeRolePolicyApply, ChangeRolePolicyVerify,
		ChangeRolePolicyCreate, ChangeRolePolicyCreateDatabase:
		return true
	default:
		return false
	}
}

// DesiredChange — одно типизированное изменение desired state.
type DesiredChange struct {
	Kind       ChangeKind
	Connection Connection
	Account    Account
	Permission string // external id permission definition (grant/revoke)
	Scope      string // external id ресурса; пусто = cluster-wide
	Resource   *ResourceSpec
	// RolePolicySpec — immutable spec, pinned операцией до target-вызова.
	// nil для всех изменений вне role-policy lifecycle.
	RolePolicySpec *RolePolicySpec
	// StatsMembership pins the exact subject/builtin incarnations for the
	// protected statistics primitive. It is invalid for every other kind.
	StatsMembership *PostgresStatsMembershipPins
	ObjectACL       *PostgresObjectACLPins
	// ExpectedTargetIdentity pins the discovery-proven physical target for
	// mutations whose endpoint may be retargeted independently of metadata.
	// Adapters must verify it from the live target before side effects.
	ExpectedTargetIdentity string
	ExpectedDatabaseOID    uint32
	// ExpectedDatabaseOwner pins the direct owner of the policy database.
	// PostgreSQL SUPERUSER-direct policy mutations re-read it together with
	// the database OID before every target-side effect.
	ExpectedDatabaseOwner string
	// ExpectedDatabaseOwnerOID fences an owner role that was dropped and
	// recreated under the same name after the operation was reserved.
	ExpectedDatabaseOwnerOID uint32
	// ExpectedAdminIdentity is independent from the credential embedded in
	// Connection so a signed operation cannot silently follow an admin account
	// switch. PostgreSQL requires it to equal both session_user/current_user and
	// Connection.AdminCredential.Username on every v2 policy call.
	ExpectedAdminIdentity string
	Credential            *Credential
	// AccountPermissions — полный desired-набор external id назначаемых
	// permissions, которые аккаунт обязан иметь ПОСЛЕ применения изменения
	// (для grant включает Permission, для revoke — не включает). Заполняется
	// ядром из bindings grantor и осмыслен только для ChangeGrant/ChangeRevoke.
	//
	// Поле существует для движков, у которых права аккаунта — не независимые
	// гранты, а один неделимый набор правил: снять одно право там означает
	// переписать весь набор, и переписывать его нужно по desired-состоянию
	// control plane, а не по реконструкции из текущего состояния движка
	// (реконструкция теряет права, которые движок не представляет раздельно,
	// — см. пакет internal/adapters/redis).
	//
	// nil означает «ядро не передало desired-состояние»: адаптер обязан
	// остаться работоспособным и деградировать до реконструкции из движка.
	// Порядок незначим, дубликаты допустимы.
	AccountPermissions []string
	Attributes         map[string]any
}

// ResourceSpec описывает создаваемый ресурс для resource.create.<kind>.
type ResourceSpec struct {
	Kind       string
	Name       string
	Attributes map[string]any
}

// Plan — детерминированный список типизированных шагов, построенный из
// DesiredChange. Повторный Apply того же Plan обязан быть безопасен.
type Plan struct {
	Change DesiredChange
	Steps  []PlanStep
}

// PlanStep — один шаг плана. Description показывается в UI и не должен
// содержать секретных значений.
type PlanStep struct {
	Kind        string
	Description string
	Attributes  map[string]any
}

// StepStatus — результат применения одного шага.
type StepStatus string

const (
	StepApplied StepStatus = "applied"
	StepSkipped StepStatus = "skipped" // уже в целевом состоянии
	StepFailed  StepStatus = "failed"
	StepUnknown StepStatus = "unknown"
)

// Result — результат Apply.
type Result struct {
	Steps []StepResult
}

// StepResult — результат одного шага; Error не должен содержать секретов.
type StepResult struct {
	Step   PlanStep
	Status StepStatus
	Error  string
}

// Verification — результат read-back проверки после Apply.
type Verification struct {
	Verified bool
	Details  string
	// Observed contains only non-secret read-back metadata, never credentials.
	Observed map[string]any `json:"observed,omitempty"`
}
