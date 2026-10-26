// Типы DTO API grantor — зеркала structs *JSON из internal/api и
// meResponse из internal/auth. Статусы намеренно типизированы как string:
// бэкенд может расширять перечисления, UI обязан деградировать мягко
// (см. lib/status.ts — маппинг с fallback).

/** Ответ GET /auth/me. */
export interface Me {
  email: string
  role: string
  csrf_token: string
  /** Имя HTTP-заголовка для CSRF-токена (auth.CSRFHeader на бэкенде). */
  csrf_header?: string
}

/** Сводка расхождений connection (driftJSON). */
export interface Drift {
  unmanaged_bindings: number
  drift_bindings: number
  missing_managed_resources: number
  /**
   * Managed-аккаунты, которых нет в целевой системе: discovery их не нашёл
   * либо их account.create так и не подтвердился (provisioning). Поле
   * необязательно ради совместимости с ответами старого бэкенда.
   */
  missing_managed_accounts?: number
}

export type ConnectionAdminCredentialChangeMode = 'switch' | 'rotate'
export type ConnectionAuthMode = 'password' | 'none'

/** Secret-free progress projection for the latest admin credential change. */
export interface ConnectionAdminCredentialChange {
  operation_id: string
  mode: ConnectionAdminCredentialChangeMode
  phase: string
  status: string
  cancel_allowed: boolean
  target_side_effect_possible: boolean
  retryable: boolean
  error_code: string | null
  started_at: string | null
  updated_at: string
}

export interface PostgresProvisioningAuthority {
  status: 'confirmed' | 'insufficient' | 'unknown' | 'invalid_current_version' | string
  reason: string
  observed_at: string
  expected_admin_identity: string
  observed_admin_identity: string
  credential_incarnation: number
  config_incarnation: string
  target_identity: string
}

/** Подключение (connectionJSON). Секретов не содержит. */
export interface Connection {
  id: string
  display_name: string
  engine: string
  environment: string
  tags: string[]
  endpoints: string[]
  execution_mode: string
  tls_config: unknown
  admin_credential_mode: string
  /** Omitted by older servers, where password authentication is implicit. */
  auth_mode?: ConnectionAuthMode
  vault_admin_path: string
  capabilities: string[]
  discovery_config: unknown
  status: string
  server_version: string
  topology: unknown
  last_discovery_at: string | null
  created_at: string
  updated_at: string
  /** Active/latest terminal admin credential lifecycle; never contains credentials. */
  admin_credential_change?: ConnectionAdminCredentialChange | null
  /** Discovery-time proof for direct PostgreSQL provisioning; secret-free. */
  postgres_provisioning_authority?: PostgresProvisioningAuthority | null
  /** nil в ответе создания — у свежего connection инвентаря ещё нет. */
  drift?: Drift
}

/** Ресурс инвентаря (resourceJSON); дерево UI собирает сам по parent_id. */
export interface Resource {
  id: string
  connection_id: string
  parent_id: string | null
  kind: string
  external_id: string
  name: string
  canonical_path: string
  attributes: unknown
  fingerprint: string
  observed_at: string | null
  status: string
  ownership: string
  created_at: string
  updated_at: string
}

/** Облегчённая проекция дерева ресурсов (`?view=tree`). */
export interface ResourceTreeItem {
  id: string
  connection_id: string
  parent_id: string | null
  kind: string
  name: string
  status: string
  ownership: string
}

/** Учётная запись (accountJSON); vault_path — путь, не значение. */
export interface AccountProvisioningSummary {
  state: 'running' | 'verification_required' | 'failed' | 'unknown'
  operation_id?: string
  operation_status?: string
}

export interface Account {
  id: string
  principal_id: string | null
  connection_id: string
  kind: string
  engine_identity: string
  authentication_scope: string
  credential_mode: string | null
  vault_path: string
  status: string
  ownership: string
  attributes: unknown
  /** Read-only creation state included by the connection inventory in one batch. */
  provisioning_summary?: AccountProvisioningSummary
  /**
   * Кто, когда и почему удалил tombstone (status === 'deleted'). Бэкенд
   * опускает поля у живых аккаунтов и у старых tombstone'ов, удалённых до
   * ввода колонок (у них известен максимум deleted_at из истории операций).
   */
  deleted_at?: string | null
  deleted_by?: string | null
  delete_reason?: string | null
  created_at: string
  updated_at: string
  /**
   * Наблюдаемые + managed bindings аккаунта; присутствует только когда список
   * запрошен с ?include=bindings (иначе поле опущено бэкендом). Пустой список
   * — аккаунт без грантов; отсутствие поля — bindings не запрашивались.
   */
  bindings?: Binding[]
  bindings_projection?: 'roles'
  access_summary?: {
    direct_objects: number
    direct_bindings: number
    unmanaged_direct_bindings: number
    unmanaged_dangerous_direct_bindings: number
    readonly_direct_bindings: number
  }
}

/** Permission definition (permissionJSON). */
/** Одна специфичная для движка характеристика права (adapter.PermissionDetail). */
export interface PermissionDetail {
  /** Стабильный идентификатор характеристики; подпись подбирает UI. */
  key: string
  value: string
}

/**
 * Нормализованное представление права (adapter.PermissionView).
 *
 * Разбор нотации живёт в адаптере на backend — единственном месте, которое
 * её знает. UI ничего не парсит: пустые action/resource/scope означают «к
 * этому праву неприменимо» и просто не показываются.
 */
export interface PermissionView {
  /** role | privilege | acl | bundle | tag | vhost | topic | unknown. */
  category: string
  /** Действие в словаре движка: read, write, admin, SELECT, configure. */
  action: string
  /** Объект права: топик, база, таблица, vhost, шаблон ключей. */
  resource: string
  /** Область действия: база, схема, vhost, pattern, host. */
  scope: string
  dangerous: boolean
  /** Почему право опасно, в терминах движка. Пусто, если не опасно. */
  danger_reason: string
  details: PermissionDetail[] | null
  /** Полное исходное выражение права — то, что можно прочитать и скопировать. */
  raw: string
}

export interface Permission {
  id: string
  connection_id: string
  engine: string
  external_id: string
  name: string
  scope_resource_id: string | null
  assignable: boolean
  dangerous: boolean
  /**
   * Физический слот, в котором может быть только одно активное desired-право.
   * Например, все RabbitMQ templates одного vhost имеют общий assignment_key.
   */
  assignment_key?: string | null
  attributes: unknown
  normalized: PermissionView
  /** observed | missing — discovery перестал видеть право в целевой системе. */
  status: string
  created_at: string
  updated_at: string
}

/** Fixed PostgreSQL role-policy profiles supported by direct SUPERUSER provisioning. */
export type PostgresRolePolicyProfile = 'read' | 'read_write'

/**
 * Admin-managed template stored in connection.discovery_config.
 *
 * The template intentionally has no raw SQL or arbitrary ACL fields: the
 * backend expands one of the two fixed profiles into exact current/default ACL.
 */
export interface PostgresRolePolicyTemplate {
  key: string
  name: string
  description: string
  role_name: string
  database: string
  schemas: string[]
  owner_roles: string[]
  creator_roles: string[]
  profile: PostgresRolePolicyProfile
}

/** Desired target contract returned by GET /connections/{id}/role-policies. */
export interface PostgresRolePolicySpec {
  role_name: string
  database: string
  schemas: string[]
  owner_roles: string[]
  creator_roles: string[]
  profile: PostgresRolePolicyProfile
}

/** Exact current/default ACL delta. Values are safe identifiers/privileges, not SQL. */
export interface PostgresRolePolicyObservedSummary {
  missing: string[]
  extra: string[]
  missing_count?: number
  extra_count?: number
  truncated?: boolean
  role?: { exists?: boolean; safe?: boolean }
  read_only?: boolean
}

/** Read model of one PostgreSQL role-policy template and its observed state. */
export interface PostgresRolePolicy {
  id: string
  template_key: string
  name: string
  description: string
  external_id: string
  desired_spec: PostgresRolePolicySpec
  managed: boolean
  exact: boolean
  dangerous: boolean
  apply_supported: boolean
  repairable: boolean
  /** Server-authorized creation or recovery of a missing provisioning role. */
  creatable?: boolean
  /** True while the current transition still owns an automatic/manual retry. */
  transition_active: boolean
  blocked_reason: string
  status: string
  version: number
  observed_fingerprint: string
  observed_summary: PostgresRolePolicyObservedSummary
  transition_operation_id?: string | null
}

/** Mutation body shared by role-policy actions; target pin is create-only. */
export interface RolePolicyMutationRequest {
  request_id: string
  version: number
  observed_fingerprint: string
  confirm: boolean
  expected_target_identity?: string
}

export interface RolePolicyMutationResponse {
  operation_id: string
}

/** Compatibility aliases retained for the PostgreSQL surface. */
export type PostgresRolePolicyMutationRequest = RolePolicyMutationRequest
export type PostgresRolePolicyMutationResponse = RolePolicyMutationResponse

/** A MongoDB role reference is always disambiguated by its role database. */
export interface MongoDBRolePolicyRoleRef {
  role: string
  db: string
}

/**
 * MongoDB accepts exactly one of these normalized resource shapes. Raw BSON
 * documents are deliberately absent from the public editor contract.
 */
export type MongoDBRolePolicyResource =
  | { db?: string; collection?: string }
  | { cluster: true }
  | { any_resource: true }

export interface MongoDBRolePolicyPrivilege {
  resource: MongoDBRolePolicyResource
  actions: string[]
}

/** Admin-managed MongoDB custom-role template in discovery_config. */
export interface MongoDBRolePolicyTemplate {
  key: string
  name: string
  description: string
  role_name: string
  role_database: string
  inherited_roles: MongoDBRolePolicyRoleRef[]
  privileges: MongoDBRolePolicyPrivilege[]
}

/** Desired MongoDB custom-role contract returned by the generic policy API. */
export interface MongoDBRolePolicySpec {
  role_name: string
  role_database: string
  inherited_roles: MongoDBRolePolicyRoleRef[]
  privileges: MongoDBRolePolicyPrivilege[]
}

/**
 * Safe, bounded rolesInfo projection. The adapter may omit detail lists when
 * an observation failed; fingerprints and exact remain authoritative.
 */
export interface MongoDBRolePolicyObservedSummary {
  missing: string[]
  extra: string[]
  missing_count?: number
  extra_count?: number
  truncated?: boolean
  exists?: boolean
  builtin?: boolean
  direct_privileges?: MongoDBRolePolicyPrivilege[]
  direct_privileges_count?: number
  direct_inherited_roles?: MongoDBRolePolicyRoleRef[]
  direct_inherited_roles_count?: number
  inherited_roles?: MongoDBRolePolicyRoleRef[]
  inherited_roles_count?: number
  inherited_privileges?: MongoDBRolePolicyPrivilege[]
  inherited_privileges_count?: number
  dependency_blockers?: string[]
  auth_restrictions_count?: number
  inherited_auth_restrictions_count?: number
  danger_reasons?: string[]
}

/** Read model of one managed or observed MongoDB custom-role policy. */
export interface MongoDBRolePolicy {
  id: string
  template_key: string
  name: string
  description: string
  external_id: string
  desired_spec: MongoDBRolePolicySpec
  managed: boolean
  exact: boolean
  dangerous: boolean
  apply_supported: boolean
  repairable: boolean
  transition_active: boolean
  blocked_reason: string
  status: string
  version: number
  observed_fingerprint: string
  observed_summary: MongoDBRolePolicyObservedSummary
  transition_operation_id?: string | null
}

/** Binding (bindingJSON); desired_state == null означает unmanaged. */
export interface Binding {
  id: string
  account_id: string
  permission_definition_id: string
  assignment_key?: string | null
  /** Фактически наблюдаемое право слота; отличается во время replace/drift. */
  observed_permission_definition_id?: string | null
  observed_attributes?: unknown
  binding_version?: number
  transition_operation_id?: string | null
  scope_resource_id: string | null
  source: string
  desired_state: string | null
  observed_state: string
  observed_effective: boolean
  status: string
  expires_at: string | null
  created_at: string
  updated_at: string
}

/** Операция (operationJSON). */
/** Durable database-and-default-role orchestration; no raw target commands. */
export interface DatabaseProvisioningProgress {
  phase: string
  database_created: boolean
  read_created: boolean
  read_write_created: boolean
  database_name: string
  read_role: string
  read_write_role: string
  error_code?: string | null
}

export interface Operation {
  id: string
  parent_id: string | null
  idempotency_key: string | null
  kind: string
  status: string
  connection_id: string | null
  principal_id: string | null
  account_id: string | null
  resource_id: string | null
  binding_id: string | null
  payload: unknown
  plan?: unknown
  result?: unknown
  error: string
  actor_type: string
  actor_id: string
  approved_by: string | null
  approved_at: string | null
  /** Необязательная причина approve/reject из operationJSON. */
  decision_reason?: string
  correlation_id: string
  created_at: string
  started_at: string | null
  finished_at: string | null
  /** Operator acknowledgement; execution status/error remain unchanged. */
  resolved_at?: string | null
  resolved_by?: string | null
  updated_at: string
  children?: Operation[]
  /**
   * Сводный статус bulk parent по статусам children; заполняется только в
   * detail-ответе операции с children (omitempty на бэкенде).
   */
  aggregate_status?: string
  /** Server-authoritative top-level retry gate for specialized operations. */
  retryable?: boolean
  /** Detail API reports a scheduled automatic retry; absent on older APIs. */
  retry_pending?: boolean
  database_provisioning?: DatabaseProvisioningProgress | null
}

/** Ответ POST /api/v1/operations/{id}/retry (retryOperationResponse). */
export interface RetryOperationResponse {
  operation_id: string
  /** Дети, сброшенные в pending и заново поставленные в очередь. */
  retried: string[]
  /** Дети в терминальном cancelled, пропущенные retry. */
  skipped_cancelled: string[]
}

/** Audit-событие (auditEventJSON). */
export interface AuditEvent {
  id: number
  occurred_at: string
  actor_type: string
  actor_id: string
  action: string
  connection_id: string | null
  resource_id: string | null
  principal_id: string | null
  account_id: string | null
  operation_id: string | null
  result: string
  metadata: unknown
}

/** Тело POST /api/v1/connections (createConnectionRequest). */
export interface CreateConnectionRequest {
  display_name: string
  engine: string
  environment: string
  endpoints: string[]
  /** Режим выполнения: 'direct' (по умолчанию) или 'connector'. */
  execution_mode?: string
  discovery_config?: Record<string, unknown>
  auth_mode?: ConnectionAuthMode
  admin_credential?: {
    username: string
    password: string
  }
}

/**
 * Тело PATCH /api/v1/connections/{id}. updated_at — версия CAS из detail;
 * остальные поля отправляются только если пользователь действительно их
 * изменил. Engine, execution mode, capabilities и credentials намеренно не
 * входят в контракт: для них нужны отдельные lifecycle/security flows.
 */
export interface PatchConnectionRequest {
  updated_at: string
  display_name?: string
  tags?: string[]
  environment?: string
  endpoints?: string[]
  tls_config?: {
    mode: string
    ca_cert_pem: string
    client_cert_pem: string
    insecure_skip_verify: boolean
  }
  /** Только ключи движка подключения; состав задаёт lib/engine-form. */
  discovery_config?: Record<string, unknown>
}

/** Operational PATCH возвращает operation_id созданного discovery. */
export interface PatchConnectionResponse extends Connection {
  operation_id?: string
}

/** Тело POST /api/v1/bindings (createBindingRequest). */
export interface CreateBindingRequest {
  account_id: string
  permission_id: string
  scope_resource_id?: string
  expires_at?: string
  /** Явное подтверждение выдачи dangerous permission (admin). */
  confirm?: boolean
}

/**
 * Ответ 202 POST /api/v1/bindings и DELETE /api/v1/bindings/{id}:
 * операция поставлена в очередь worker.
 */
export interface BindingOperationResponse {
  operation_id: string
  binding_id: string
}

/** Элемент bulk-запроса (bulkBindingItem). */
export interface BulkBindingItem {
  account_id: string
  permission_id: string
  scope_resource_id?: string
}

/** Тело POST /api/v1/bindings/bulk (bulkCreateBindingsRequest). */
export interface BulkCreateBindingsRequest {
  items: BulkBindingItem[]
  /** Явное подтверждение, если в списке есть dangerous permission. */
  confirm?: boolean
}

/** Созданная пара binding + операция в ответе bulk (grantChild). */
export interface GrantChild {
  operation_id: string
  binding_id: string
  account_id: string
  permission_id: string
}

/** Ответ 202 POST /api/v1/bindings/bulk: parent-операция и children. */
export interface BulkCreateBindingsResponse {
  operation_id: string
  children: GrantChild[]
}

/** Дельта ролей одного аккаунта для POST /api/v1/accounts/{id}/roles. */
export interface ManageAccountRolesRequest {
  add_permission_ids: string[]
  remove_binding_ids: string[]
  /** Явное подтверждение, если среди добавлений есть dangerous permission. */
  confirm?: boolean
}

export interface AccountRoleChangeChild {
  operation_id: string
  binding_id: string
  permission_id: string
  action: 'grant' | 'revoke'
  status: string
}

export interface ManageAccountRolesResponse {
  operation_id: string
  children: AccountRoleChangeChild[]
}

/**
 * Блок credential создания account (accountCredentialRequest):
 * generated — пароль создаёт адаптер; provided — пароль задаёт оператор,
 * username необязателен (по умолчанию engine identity). Значения уходят
 * только в Vault.
 */
export type AccountCredentialRequest =
  | { mode: 'generated' }
  | { mode: 'provided'; username?: string; password: string }

/** Тело POST /api/v1/accounts (createAccountRequest). */
export interface CreateAccountRequest {
  connection_id: string
  engine_identity: string
  principal_id?: string
  credential: AccountCredentialRequest
}

/**
 * Ответ 202 мутаций account (create/disable/enable/rotate/delete):
 * операция поставлена в очередь worker.
 */
export interface AccountOperationResponse {
  account_id: string
  operation_id: string
  /**
   * Путь секрета, по которому окажется credential после успешной ротации
   * (только у POST /accounts/{id}/rotate). detached — ротация уводит аккаунт
   * с общего пароля принципала на собственный; attached — наоборот,
   * возвращает на общий.
   */
  vault_path?: string
  detached?: boolean
  attached?: boolean
}

/**
 * Тело POST /api/v1/accounts/{id}/rotate. Пустое тело — обычная ротация;
 * detach уводит аккаунт с общего пароля принципала на собственный, attach
 * возвращает обратно. Флаги взаимоисключающие.
 */
export interface RotateAccountRequest {
  detach?: boolean
  attach?: boolean
}

/** Подключение, которому сменит пароль ротация общего секрета принципала. */
export interface SharedCredentialConnection {
  connection_id: string
  display_name: string
  account_id: string
}

/**
 * Контекст 409 shared_credential_requires_choice: аккаунт сидит на общем
 * пароле принципала, и ротация «на месте» увела бы его с этого пароля молча.
 * requires_confirm — затронутых аккаунтов больше серверного порога
 * confirm_threshold, поэтому ротация общего пароля требует подтверждения.
 */
export interface SharedCredentialChoice {
  principal_id: string
  principal_display_name: string
  environment: string
  affected_accounts: number
  affected_connections: SharedCredentialConnection[]
  confirm_threshold: number
  requires_confirm: boolean
}

/** Машиночитаемый код 409 «ротация требует осознанного выбора». */
export const SHARED_CREDENTIAL_CHOICE_CODE = 'shared_credential_requires_choice'

/** Новый credential для восстановления удалённого managed login-account. */
export type RestoreAccountCredential =
  | { mode: 'generated' }
  | { mode: 'provided'; password: string }
  | { mode: 'existing_vault_ref' }

/** Тело POST /api/v1/accounts/{id}/restore. */
export interface RestoreAccountRequest {
  credential: RestoreAccountCredential
}

/** Ответ 202 восстановления: итог аккаунта определяется операцией. */
export interface RestoreAccountResponse {
  account_id: string
  operation_id: string
}

/** Безопасная allowlist фактических runtime-режимов API. */
export interface RuntimeConfig {
  scope_enforcement: 'enforce' | 'disabled'
}

/**
 * Тело POST /api/v1/accounts/{id}/adopt (adoptAccountRequest): принятие
 * unmanaged-аккаунта под управление.
 *
 * - metadata — только метаданные grantor, учётка не затрагивается;
 * - generate — grantor генерирует НОВЫЙ пароль и применяет его к учётке
 *   (пароль не проходит через клиент);
 * - set_password — оператор задаёт НОВЫЙ пароль, он применяется к учётке
 *   (прежний перестаёт работать; уходит только в Vault);
 * - verify_password — оператор подтверждает СУЩЕСТВУЮЩИЙ пароль: grantor
 *   доказывает его на целевой системе и ничего в ней не меняет.
 *
 * adopt_bindings дополнительно принимает все unmanaged bindings.
 *
 * Прежнее имя режима set_password — password; API продолжает его принимать как
 * синоним, но UI отправляет только канонические имена.
 */
export type AdoptAccountRequest =
  | { mode: 'metadata'; adopt_bindings?: boolean }
  | { mode: 'generate'; adopt_bindings?: boolean }
  | { mode: 'set_password'; password: string; adopt_bindings?: boolean }
  | { mode: 'verify_password'; password: string; adopt_bindings?: boolean }

/** Ответ 200 adopt (mode=metadata): аккаунт уже переведён в managed. */
export interface AdoptAccountMetadataResponse {
  account: Account
  adopted_bindings: number
}

/**
 * Ответ 202 adopt (mode=generate, set_password или verify_password): операция
 * поставлена в очередь worker; ownership станет managed на её успехе.
 */
export interface AdoptAccountOperationResponse {
  account_id: string
  operation_id: string
  adopted_bindings: number
}

/**
 * Ответ 201 POST /api/v1/accounts/{id}/share. Ссылка одноразовая,
 * возвращается ровно один раз и нигде не сохраняется.
 */
export interface ShareCredentialResponse {
  link: string
  expires_in_hours: number
  one_time: boolean
}

/** Принципал (principalJSON) — раздел «Пользователи». */
export type ExternalIdentityStatus = 'active' | 'disabled' | 'deleted'

export interface Principal {
  id: string
  type: string
  display_name: string
  external_provider: string
  external_subject: string
  /** Статус identity во внешнем провайдере; null до первой успешной проверки. */
  external_identity_status?: ExternalIdentityStatus | null
  external_identity_checked_at?: string | null
  external_identity_status_changed_at?: string | null
  status: string
  attributes: unknown
  /** Момент необратимого уничтожения выводимого пользователя; null у остальных. */
  purge_after?: string | null
  created_at: string
  updated_at: string
  /**
   * Счётчик учётных записей; присутствует только в списковом ответе
   * (в detail вместо счётчика отдаётся сам список accounts).
   */
  accounts_count?: number
}

/**
 * Ответ GET /api/v1/principals/{id} (principalDetailResponse): принципал
 * и его учётные записи по всем connections.
 */
export interface PrincipalDetail extends Principal {
  accounts: Account[]
}

/** Тип принципала (principals.Type) для тела создания. */
export type PrincipalType = 'human' | 'service' | 'group'

/** Тело POST /api/v1/principals (createPrincipalRequest). */
export interface CreatePrincipalRequest {
  type: PrincipalType
  display_name: string
  /** Внешняя identity необязательна, но задаётся только парой. */
  external_provider?: string
  external_subject?: string
}

/** Тело POST /api/v1/accounts/{id}/link (linkAccountRequest). */
export interface LinkAccountRequest {
  principal_id: string
}

/** Тело POST /api/v1/accounts/{id}/link-and-manage. */
export interface LinkAndManageAccountRequest {
  principal_id: string
  /** Нужен только при создании первого credential пользователя в окружении. */
  credential?: {
    mode: 'generated' | 'provided'
    password?: string
  }
}

/** Ответ 202 POST /api/v1/accounts/{id}/link-and-manage. */
export interface LinkAndManageAccountResponse {
  account_id: string
  principal_id: string
  environment: string
  operation_id: string
}

/**
 * Элемент principal-centric выдачи (principalAccessItem): роль в
 * подключении с опциональным scope. Сервис создаёт где надо локальный
 * managed-аккаунт принципала и выдаёт роль.
 */
export interface PrincipalAccessItem {
  connection_id: string
  permission_id: string
  scope_resource_id?: string
}

/** Тело POST /api/v1/principals/{id}/access (principalAccessRequest). */
export interface PrincipalAccessRequest {
  items: PrincipalAccessItem[]
  /**
   * Override engine_identity создаваемых аккаунтов; пусто — identity
   * выводится из принципала (external_subject или slug display name).
   */
  engine_identity?: string
  /** Явное подтверждение выдачи dangerous permission (роль admin). */
  confirm?: boolean
  /**
   * Срок действия всех выдаваемых прав (RFC 3339): по истечении maintenance
   * отзывает их автоматически. Отсутствие — бессрочно.
   */
  expires_at?: string
}

/** Один результат выдачи в ответе access (principalAccessChild). */
export interface PrincipalAccessChild {
  connection_id: string
  environment: string
  account_id: string
  credential_mode: string
  account_created: boolean
  /** Операция account.create — только для свежесозданного аккаунта. */
  account_create_operation_id?: string
  grant_operation_id: string
  binding_id: string
}

/** Ответ 202 POST /api/v1/principals/{id}/access: parent-операция и children. */
export interface PrincipalAccessResponse {
  operation_id: string
  children: PrincipalAccessChild[]
}

/** Дочерняя операция каскадного disable/enable (principalStatusChild). */
export interface PrincipalStatusChild {
  connection_id: string
  account_id: string
  operation_id: string
}

/**
 * Ответ POST /api/v1/principals/{id}/(disable|enable): поля принципала;
 * при каскаде по managed-аккаунтам (202) дополнительно operation_id и
 * children, без каскадных целей (200) — только принципал, как раньше.
 */
export interface PrincipalStatusResponse extends Principal {
  operation_id?: string
  children?: PrincipalStatusChild[]
}

/**
 * Unmanaged-аккаунт в ответе offboard (offboardUnmanagedAccount): он не
 * затрагивается и требует ручного внимания.
 */
export interface OffboardUnmanagedAccount {
  connection_id: string
  engine_identity: string
}

/** Дочерняя операция offboard (offboardChild): access.revoke | account.delete. */
export interface PrincipalOffboardChild {
  kind: string
  connection_id: string
  account_id: string
  binding_id?: string
  operation_id: string
  status: string
}

/**
 * Ответ POST /api/v1/principals/{id}/offboard: 202 — bulk parent
 * (operation_id/children/unmanaged_accounts); 200 (без managed-аккаунтов)
 * — поля tombstone-принципала с unmanaged_accounts, без operation_id.
 */
export interface PrincipalOffboardResponse {
  operation_id?: string
  children?: PrincipalOffboardChild[]
  unmanaged_accounts?: OffboardUnmanagedAccount[]
  /**
   * Аккаунты, чей пароль offboard не менял: grantor им не владеет, а
   * ротация присвоила бы чужой. Пусто, если запрос пришёл с
   * takeover_credentials.
   */
  credential_takeover_required?: OffboardUnmanagedAccount[]
  status?: string
}

/** Несекретный статус общего credential пользователя в окружении. */
export interface PrincipalCredentialEnvironment {
  environment: string
  connections: number
  /** null — метаданные окружения не прочитались, состояние неизвестно. */
  configured: boolean | null
}

/** Окружение из реестра (может существовать без подключений). */
export interface EnvironmentEntry {
  name: string
  created_at: string
}

export interface PrincipalCredentialCreateResponse {
  environment: string
  configured: true
  created: boolean
}

/** Одна дочерняя ротация в ответе rotate (principalRotateChild). */
export interface PrincipalRotateChild {
  connection_id: string
  environment: string
  account_id: string
  operation_id: string
}

/** Ответ 202 POST /api/v1/principals/{id}/rotate: parent-операция и children. */
export interface PrincipalRotateResponse {
  operation_id: string
  children: PrincipalRotateChild[]
}

/**
 * Одно расхождение отчёта «Дрифт» (driftFindingJSON). Ссылочные id и
 * подписи заполняются по виду finding; для connection_degraded задан
 * только connection_id.
 */
export interface DriftFinding {
  kind: string
  connection_id: string
  binding_id?: string
  account_id?: string
  resource_id?: string
  permission_id?: string
  account_identity?: string
  permission_name?: string
  resource_name?: string
  detail: string
  /** Заполнены только у baselined-находок (driftBaselinedJSON). */
  baseline_id?: string
  reason?: string
  created_by?: string
}

/** Сводка находок отчёта дрифта по видам (driftCountsJSON). */
export interface DriftCounts {
  binding_drift: number
  unmanaged_binding: number
  missing_resource: number
  missing_account: number
  degraded_connections: number
}

/** Ответ GET /api/v1/drift (driftResponse). */
export interface DriftReport {
  findings: DriftFinding[]
  /** Находки, принятые как ожидаемые: не шум, но и не сигнал. */
  baselined?: DriftFinding[]
  counts: DriftCounts
}

/**
 * Scope policy (scopePolicyJSON) — ограничивает operator и service-принципалов
 * окружениями connections. subject_kind: 'role' (subject — имя роли, обычно
 * 'operator') либо 'principal' (subject — uuid принципала). environment '*'
 * означает все окружения.
 */
export interface ScopePolicy {
  id: string
  subject_kind: string
  subject: string
  environment: string
  created_at: string
}

/** Subject kind scope policy (policy.SubjectRole/SubjectPrincipal). */
export type ScopeSubjectKind = 'role' | 'principal'

/** Тело POST /api/v1/scope-policies (createScopePolicyRequest). */
export interface CreateScopePolicyRequest {
  subject_kind: ScopeSubjectKind
  subject: string
  environment: string
}

/**
 * Действие плана манифеста доступов (accessmanifest.Action, ADR-0009).
 * kind: 'create_account' | 'grant' | 'revoke'; строковые поля — ссылки
 * манифеста как их ввёл оператор (не id).
 */
export interface ManifestPlanAction {
  kind: string
  principal: string
  connection: string
  role: string
  account_engine_identity?: string
  dangerous: boolean
  reason?: string
}

/** Нерезолвящаяся запись манифеста с причиной (accessmanifest.Unresolved). */
export interface ManifestUnresolved {
  principal: string
  connection: string
  role: string
  state?: string
  reason: string
}

/** Сводка плана по видам действий (manifestSummary). */
export interface ManifestPlanSummary {
  grants: number
  revokes: number
  creates: number
  dangerous: number
}

/** Ответ POST /api/v1/access/plan: dry-run diff манифеста. */
export interface ManifestPlanResponse {
  plan: {
    actions: ManifestPlanAction[]
    unresolved: ManifestUnresolved[]
  }
  summary: ManifestPlanSummary
}

/**
 * Одна запись экспорта выданных прав (accessmanifest.Entry): роль принципала
 * в подключении. Экспорт содержит только managed present-доступы; state всегда
 * "present". Секретов не несёт — только имена principal/connection/role.
 */
export interface ManifestEntry {
  principal: string
  connection: string
  role: string
  state: string
}

/**
 * Ответ GET /api/v1/access/export: текущее managed-состояние доступов как
 * манифест. С ?connection=<id> выгрузка сужена до одного подключения.
 */
export interface AccessManifest {
  version: string
  environment?: string
  prune?: boolean
  entries: ManifestEntry[]
}

/**
 * Секция экспорта доступов — значение query-параметра `sections=` у
 * GET /api/v1/access/export. Без параметра (или при ровно `managed`) ответ —
 * прежний манифест (AccessManifest); любая иная комбинация — AccessSnapshot.
 */
export type AccessExportSection = 'managed' | 'unmanaged' | 'roles' | 'accounts'

/**
 * Запись секции managed снапшота (snapshotManagedEntry): та же тройка
 * principal/role/state, что у записи манифеста; connection задан на верхнем
 * уровне снапшота и не дублируется.
 */
export interface SnapshotManagedEntry {
  /** Пуст, если managed-аккаунт не привязан к пользователю (такие права
   * видны в снапшоте, но в переприменяемый манифест не входят). */
  principal?: string
  /** Engine identity аккаунта; заполнен всегда. */
  account: string
  role: string
  /** Имя scope-ресурса; пуст для connection-wide грантов. */
  scope?: string
  state: string
}

/**
 * Запись секции unmanaged снапшота (snapshotUnmanagedBinding): обнаруженный
 * discovery binding без принятого решения. account — engine identity;
 * role — имя permission definition; scope опущен для connection-wide.
 */
export interface SnapshotUnmanagedBinding {
  account: string
  role: string
  scope?: string
  observed_state: string
}

/** Запись секции roles снапшота (snapshotRole): permission definition. */
export interface SnapshotRole {
  name: string
  external_id: string
  assignable: boolean
  dangerous: boolean
  scope?: string
}

/**
 * Запись секции accounts снапшота (snapshotAccount): инвентарь учётных
 * записей; principal — внешняя ссылка привязанного принципала (опущена,
 * если аккаунт не привязан). Vault paths в снапшот не входят.
 */
export interface SnapshotAccount {
  engine_identity: string
  kind: string
  ownership: string
  status: string
  principal?: string
}

/**
 * Ответ GET /api/v1/access/export?sections=... (accessSnapshot): фактический
 * аудит-снимок доступов одного подключения. НЕ манифест: повторно применить
 * его через POST /api/v1/access/apply нельзя. Присутствуют только
 * запрошенные секции (запрошенная пустая секция — []).
 */
export interface AccessSnapshot {
  kind: 'access_snapshot'
  connection: {
    id: string
    display_name: string
    engine: string
    environment: string
  }
  generated_at: string
  managed?: SnapshotManagedEntry[]
  unmanaged?: SnapshotUnmanagedBinding[]
  roles?: SnapshotRole[]
  accounts?: SnapshotAccount[]
}

/** Одно применённое действие в ответе apply (manifestApplyChild). */
export interface ManifestApplyChild {
  kind: string
  connection_id: string
  account_id: string
  account_create_operation_id?: string
  grant_operation_id?: string
  revoke_operation_id?: string
  binding_id?: string
}

/**
 * Ответ 202 POST /api/v1/access/apply: parent-операция bulk.manifest_apply
 * и применённые действия.
 */
export interface ManifestApplyResponse {
  operation_id: string
  actions_count: number
  children: ManifestApplyChild[]
}

/**
 * Service token без секрета (serviceTokenJSON): ни plaintext-токен, ни его хеш
 * в модель не входят. revoked_at != null означает отозванный токен.
 */
export interface ServiceToken {
  id: string
  principal_id: string
  name: string
  created_at: string
  last_used_at: string | null
  revoked_at: string | null
  permissions: string[]
}

/** Ответ GET /api/v1/principals/{id}/tokens (serviceTokenListResponse). */
export interface ServiceTokenList {
  tokens: ServiceToken[]
}

/**
 * Ответ 201 POST /api/v1/principals/{id}/tokens: plaintext-токен (grt_…)
 * возвращается ровно один раз и нигде больше не отдаётся.
 */
export interface IssueTokenResponse {
  id: string
  principal_id: string
  name: string
  token: string
  permissions: string[]
}

/** Кандидат на заведение из внешнего каталога (directoryCandidateJSON). */
export interface DirectoryCandidate {
  subject: string
  display_name: string
  /** Состояние в каталоге: active | disabled | missing. */
  status: string
  /** Принципал с такой внешней identity уже заведён. */
  imported: boolean
}

/** Ответ поиска по каталогу. */
export interface DirectorySearchResponse {
  candidates: DirectoryCandidate[]
  /** Фактически применённый предел выдачи. */
  limit: number
}

/** Ответ импорта: что завелось и что пропущено и почему. */
export interface DirectoryImportResponse {
  created: Principal[]
  skipped_existing: string[]
  skipped_missing: string[]
}

/** Наблюдаемое состояние execution connector (GET /api/v1/connectors). */
export interface ConnectorSession {
  connector_id: string
  /** online | stale | offline — по времени последнего кадра. */
  status: string
  connected_at: string
  last_seen_at: string
  certificate_not_after: string
  /** Отрицателен у истёкшего сертификата. */
  certificate_days_left: number
  capabilities: string[]
  protocol_version: string
  /** Имя, заданное оператором; пусто — показывается connector_id (CN серта). */
  display_name: string
  /** kubernetes | vm | other; пусто — тип неизвестен. */
  deployment_kind: string
  /** operator | agent — кто определил тип; пусто, если типа нет. */
  deployment_source: string
}
