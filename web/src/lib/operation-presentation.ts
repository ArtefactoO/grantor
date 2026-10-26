import type { AuditEvent, Operation } from './types'

interface OperationPresentation {
  label: string
  recentActivity: boolean
}

/**
 * Единственный пользовательский словарь операций. Технический kind остаётся
 * доступен в журнале и detail, но не просачивается в короткие продуктовые
 * сводки. Неизвестные kind намеренно не попадают в «Последние действия»:
 * сначала для них должна быть определена понятная семантика.
 */
const OPERATION_PRESENTATION: Readonly<Record<string, OperationPresentation>> = {
  'bulk.grant': { label: 'Массовая выдача доступов', recentActivity: true },
  'bulk.account_roles': { label: 'Изменение ролей аккаунта', recentActivity: true },
  'bulk.object_acl': { label: 'Изменение прямых прав', recentActivity: true },
  'postgres.object_acl.grant.v1': { label: 'Выдача прямого права', recentActivity: true },
  'postgres.object_acl.revoke.v1': { label: 'Отзыв прямого права', recentActivity: true },
  'bulk.principal_access': { label: 'Изменение доступов пользователя', recentActivity: true },
  'bulk.principal_rotate': { label: 'Обновление учётных данных', recentActivity: true },
  'bulk.principal_disable': { label: 'Отключение аккаунтов пользователя', recentActivity: true },
  'bulk.principal_enable': { label: 'Включение аккаунтов пользователя', recentActivity: true },
  'bulk.principal_offboard': { label: 'Удаление пользователя', recentActivity: true },
  'bulk.manifest_apply': { label: 'Применение манифеста', recentActivity: true },
  'account.create': { label: 'Создание аккаунта', recentActivity: true },
  'postgres.account.provision.v1': { label: 'Создание учётки PostgreSQL', recentActivity: true },
  'postgres.account.verify_creation.v1': { label: 'Проверка созданной учётки', recentActivity: true },
  'postgres.account.create.v2': { label: 'Создание PostgreSQL-аккаунта', recentActivity: true },
  'account.recover_provisioning': { label: 'Восстановление записи из кластера', recentActivity: true },
  'role.create': { label: 'Создание роли', recentActivity: true },
  'postgres.role.create.v2': { label: 'Создание PostgreSQL-роли', recentActivity: true },
  'resource.create': { label: 'Создание базы', recentActivity: true },
  'resource.create.database_with_roles': { label: 'Создание базы и ролей доступа', recentActivity: true },
  'postgres.resource.create.database.v2': { label: 'Создание PostgreSQL-базы', recentActivity: true },
  'postgres.resource.create.database_with_roles.v2': { label: 'Создание базы и ролей доступа', recentActivity: true },
  'postgres.resource.create.database_for_roles.v2': { label: 'Создание PostgreSQL-базы', recentActivity: false },
  'resource.create.prepared_database': { label: 'Создание подготовленной базы', recentActivity: false },
  'account.disable': { label: 'Отключение аккаунта', recentActivity: true },
  'account.enable': { label: 'Включение аккаунта', recentActivity: true },
  'account.delete': { label: 'Удаление аккаунта', recentActivity: true },
  'account.restore': { label: 'Восстановление аккаунта', recentActivity: true },
  'postgres.account.restore.v2': { label: 'Восстановление PostgreSQL-аккаунта', recentActivity: true },
  'account.adopt_verify': { label: 'Подтверждение пароля аккаунта', recentActivity: true },
  'access.grant': { label: 'Выдача доступа', recentActivity: true },
  'access.revoke': { label: 'Отзыв доступа', recentActivity: true },
  'postgres.stats_membership.grant.v1': { label: 'Выдача доступа', recentActivity: true },
  'postgres.stats_membership.revoke.v1': { label: 'Отзыв доступа', recentActivity: true },
  'role.policy.apply': { label: 'Применение политики роли', recentActivity: true },
  'postgres.role.policy.apply.v2': { label: 'Применение политики PostgreSQL-роли', recentActivity: true },
  'role.policy.create': { label: 'Создание роли доступа', recentActivity: true },
  'postgres.role.policy.create.v2': { label: 'Создание PostgreSQL-роли доступа', recentActivity: true },
  'postgres.role.policy.create_database.v2': { label: 'Создание PostgreSQL-роли доступа', recentActivity: false },
  'role.policy.create_database': { label: 'Создание роли доступа', recentActivity: false },
  'role.policy.adopt': { label: 'Принятие политики роли', recentActivity: true },
  'postgres.role.policy.adopt.v2': { label: 'Принятие политики PostgreSQL-роли', recentActivity: true },
  'role.policy.repair': { label: 'Исправление политики роли', recentActivity: true },
  'postgres.role.policy.repair.v2': { label: 'Исправление политики PostgreSQL-роли', recentActivity: true },
  'credential.rotate': { label: 'Обновление учётных данных', recentActivity: true },
  'connection.discover': { label: 'Обновление снимка подключения', recentActivity: false },
  'connection.admin_credential.switch': { label: 'Смена admin credential', recentActivity: true },
  'connection.admin_credential.rotate': { label: 'Ротация admin credential', recentActivity: true },
}

export const RECENT_ACTIVITY_KINDS = Object.freeze(
  Object.entries(OPERATION_PRESENTATION)
    .filter(([, presentation]) => presentation.recentActivity)
    .map(([kind]) => kind),
)

export function operationLabel(kind: string): string {
  const known = OPERATION_PRESENTATION[kind]?.label
  if (known !== undefined) return known
  // Незнакомый kind читается, а не показывается идентификатором.
  const parts = kind.split('.').map((part) => part.replaceAll('_', ' ').trim()).filter(Boolean)
  if (parts.length === 0) return kind
  return parts
    .map((part, index) => (index === 0 ? part.charAt(0).toUpperCase() + part.slice(1) : part))
    .join(' · ')
}

type UnknownRecord = Record<string, unknown>

function record(value: unknown): UnknownRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {}
  return value as UnknownRecord
}

function textValue(value: unknown): string | null {
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

function numberValue(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

export function isAccountAdoptOperation(
  operation: Pick<Operation, 'kind' | 'payload'>,
): boolean {
  return operation.kind === 'credential.rotate' && record(operation.payload).adopt === true
}

export function isAccountManagedLinkOperation(
  operation: Pick<Operation, 'kind' | 'payload'>,
): boolean {
  return operation.kind === 'credential.rotate' &&
    textValue(record(operation.payload).managed_link_principal_id) !== null
}

/** Уточняет продуктовый смысл generic operation kind по безопасным флагам payload. */
export function operationDisplayLabel(
  operation: Pick<Operation, 'kind' | 'payload'>,
): string {
  if (isAccountAdoptOperation(operation)) return 'Принятие аккаунта под управление'
  if (isAccountManagedLinkOperation(operation)) return 'Связать аккаунт и взять под управление'
  return operationLabel(operation.kind)
}

export interface AccountAdoptContext {
  account: string
  mode: string
  adoptedBindings: number | null
}

export interface AccountManagedLinkContext {
  account: string
  principal: string
  environment: string | null
  credentialSource: string | null
}

export function accountAdoptModeLabel(mode: string | null, generated = false): string {
  switch (mode) {
    case 'metadata': return 'Без смены пароля'
    case 'generate': return 'Новый пароль сгенерирован'
    case 'password': return 'Задан новый пароль'
    default: return generated ? 'Новый пароль сгенерирован' : 'Задан новый пароль'
  }
}

/**
 * Собирает только безопасный продуктовый контекст adopt. Audit служит
 * источником identity и счётчика уже существовавших доступов; payload —
 * fallback режима. Credential, Vault path и lifecycle guards сюда не входят.
 */
export function accountAdoptContext(
  operation: Pick<Operation, 'id' | 'kind' | 'payload' | 'account_id'>,
  events: readonly AuditEvent[],
): AccountAdoptContext | null {
  if (!isAccountAdoptOperation(operation)) return null

  const payload = record(operation.payload)
  const related = events.filter((event) => event.operation_id === operation.id)
  const metadata = related
    .map((event) => record(event.metadata))
    .find((value) => textValue(value.engine_identity) !== null || textValue(value.mode) !== null)
  const successMetadata = related
    .map((event) => record(event.metadata))
    .find((value) => textValue(value.account) !== null)
  const account = textValue(metadata?.engine_identity) ??
    textValue(successMetadata?.account) ??
    operation.account_id ??
    '—'
  const mode = textValue(metadata?.mode)
  const adoptedBindings = numberValue(metadata?.adopted_bindings)

  return {
    account,
    mode: accountAdoptModeLabel(mode, payload.adopt_generate === true),
    adoptedBindings,
  }
}

/** Безопасный контекст link-and-manage без Vault path и credential. */
export function accountManagedLinkContext(
  operation: Pick<Operation, 'id' | 'kind' | 'payload' | 'account_id' | 'principal_id'>,
  events: readonly AuditEvent[],
  principalNames: ReadonlyMap<string, string> = new Map(),
): AccountManagedLinkContext | null {
  if (!isAccountManagedLinkOperation(operation)) return null

  const payload = record(operation.payload)
  const related = events
    .filter((event) => event.operation_id === operation.id)
    .map((event) => record(event.metadata))
  const requested = related.find((value) =>
    textValue(value.engine_identity) !== null ||
    textValue(value.environment) !== null ||
    textValue(value.principal_display_name) !== null,
  )
  const completed = related.find((value) => textValue(value.account) !== null)
  const principalID = operation.principal_id ??
    textValue(payload.managed_link_principal_id)

  return {
    account: textValue(requested?.engine_identity) ??
      textValue(completed?.account) ??
      operation.account_id ??
      '—',
    principal: (principalID === null ? null : principalNames.get(principalID)) ??
      textValue(requested?.principal_display_name) ??
      'Удалённый пользователь',
    environment: textValue(requested?.environment),
    credentialSource: textValue(requested?.credential_source),
  }
}

export function isRecentActivityOperation(
  operation: Pick<Operation, 'actor_type' | 'kind' | 'parent_id'>,
): boolean {
  return operation.actor_type === 'user' &&
    operation.parent_id === null &&
    OPERATION_PRESENTATION[operation.kind]?.recentActivity === true
}

export function operationStatusLabel(status: string): string {
  switch (status) {
    case 'pending': return 'Pending'
    case 'pending_approval': return 'Approval'
    case 'running': return 'Running'
    case 'success': return 'Done'
    case 'partial': return 'Partial'
    case 'failed': return 'Failed'
    case 'cancelled': return 'Cancelled'
    case 'rejected': return 'Rejected'
    default: return status
  }
}

/** Короткая продуктовая формулировка известных adapter/API ошибок. */
export function operationErrorLabel(error: string): string {
  const accountNotFound = error.match(/account\s+"([^"]+)".*object not found/i)
  if (accountNotFound !== null) {
    return `Аккаунт «${accountNotFound[1]}» ещё не создан в подключении.`
  }
  const identityTaken = error.match(/identity\s+"([^"]+)".*already taken/i)
  if (identityTaken !== null) {
    return `Логин «${identityTaken[1]}» уже занят другим аккаунтом в подключении.`
  }
  return error
}

/** Ошибки parent и его children без дубликатов, в понятном UI-виде. */
export function operationFailureMessages(operation: Operation): string[] {
  const raw = [operation.error, ...(operation.children ?? []).map((child) => child.error)]
    .filter((value): value is string => typeof value === 'string' && value.trim() !== '')
  return [...new Set(raw.map(operationErrorLabel))]
}
