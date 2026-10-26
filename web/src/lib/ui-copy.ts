/** Канонические термины интерфейса. API-значения не должны просачиваться в UI. */
export const UI_COPY = {
  all: 'All',
  active: 'Active',
  approval: 'Approval',
  current: 'Current',
  configured: 'Configured',
  configuredUnknown: 'Unknown',
  deleted: 'Deleted',
  disabled: 'Disabled',
  enabled: 'Enabled',
  error: 'Error',
  failed: 'Failed',
  healthy: 'Healthy',
  loading: 'Loading',
  managed: 'Managed',
  manual: 'Manual',
  notConfigured: 'Not configured',
  unmanaged: 'Unmanaged',
  unavailable: 'Unavailable',
  roles: 'Roles',
  accounts: 'Accounts',
  drift: 'Drift',
  sync: 'Sync',
  apiTokens: 'API-токены',
} as const

const CONNECTION_STATUS_LABELS: Readonly<Record<string, string>> = {
  draft: 'Draft',
  validating: 'Validating',
  discovering: 'Syncing',
  credential_updating: 'Credential updating',
  active: 'Active',
  connection_failed: 'Connection error',
  discovery_failed: 'Sync error',
  degraded: 'Degraded',
  disabled: 'Disabled',
}

const INVENTORY_STATUS_LABELS: Readonly<Record<string, string>> = {
  active: 'Active',
  disabled: 'Disabled',
  deleted: 'Deleted',
  observed: 'Observed',
  planned: 'Planned',
  missing: 'Missing',
  stale: 'Stale',
}

const BINDING_STATUS_LABELS: Readonly<Record<string, string>> = {
  synced: 'Sync',
  pending: 'Pending',
  drift: 'Drift',
  failed: 'Failed',
  // Право наблюдается в целевой системе и под управлением не находится:
  // решение оператора по нему ещё не принято. Не «ожидает применения».
  observed: 'Observed',
}

const BINDING_STATE_LABELS: Readonly<Record<string, string>> = {
  present: 'Present',
  absent: 'Absent',
}

const PRINCIPAL_TYPE_LABELS: Readonly<Record<string, string>> = {
  human: 'Human',
  service: 'Service',
  group: 'Group',
}

const RESOURCE_KIND_LABELS: Readonly<Record<string, string>> = {
  database: 'Database',
  schema: 'Schema',
  table: 'Table',
  topic: 'Topic',
  vhost: 'Vhost',
  keyspace: 'Keyspace',
  cluster: 'Cluster',
}

const ACCOUNT_KIND_LABELS: Readonly<Record<string, string>> = {
  login: 'Login',
  service: 'Service',
  group: 'Group',
  role: 'Role',
}

function fallbackLabel(value: string): string {
  const normalized = value.replaceAll('_', ' ').trim()
  if (normalized === '') return value
  return normalized.charAt(0).toLocaleUpperCase() + normalized.slice(1)
}

export function connectionStatusLabel(status: string): string {
  return CONNECTION_STATUS_LABELS[status] ?? fallbackLabel(status)
}

export function inventoryStatusLabel(status: string): string {
  return INVENTORY_STATUS_LABELS[status] ?? fallbackLabel(status)
}

// Значения статусов в чипах — английские во всём интерфейсе (Active,
// Disabled, Sync). Русское «Не проверена» стояло в одном столбце с ними и
// читалось как другой вид сущности, хотя это тот же статус.
export function externalIdentityStatusLabel(status: string | null | undefined): string {
  return status === null || status === undefined || status === ''
    ? 'Not checked'
    : inventoryStatusLabel(status)
}

export function bindingStatusLabel(status: string): string {
  return BINDING_STATUS_LABELS[status] ?? fallbackLabel(status)
}

export function bindingStateLabel(state: string): string {
  return BINDING_STATE_LABELS[state] ?? fallbackLabel(state)
}

export function principalTypeLabel(type: string): string {
  return PRINCIPAL_TYPE_LABELS[type] ?? fallbackLabel(type)
}

export function resourceKindLabel(kind: string): string {
  return RESOURCE_KIND_LABELS[kind] ?? fallbackLabel(kind)
}

export function accountKindLabel(kind: string): string {
  return ACCOUNT_KIND_LABELS[kind] ?? fallbackLabel(kind)
}

export function connectionSyncLabel(drift: number): string {
  return drift > 0 ? `${UI_COPY.drift} ${drift}` : UI_COPY.sync
}

export function ownershipLabel(ownership: string): string {
  if (ownership === 'managed') return UI_COPY.managed
  if (ownership === 'unmanaged') return UI_COPY.unmanaged
  return fallbackLabel(ownership)
}

const AUDIT_ACTION_LABELS: Readonly<Record<string, string>> = {
  'account.managed_link_requested': 'Запрошена привязка аккаунта',
  'account.purged': 'Аккаунт удалён навсегда',
  'binding.expired': 'Срок доступа истёк',
  'connection.autodiscovery_requested': 'Запрошена авто-синхронизация',
  'principal.external_identity_status_changed': 'Статус в каталоге изменён',
  'principal.imported_from_directory': 'Пользователь заведён из каталога',
  'security.admin_credential_aged': 'Admin-credential устарел',
  'security.connector_certificate_expiring': 'Сертификат connector истекает',
  'security.credential_version_diverged': 'Пароль изменён мимо Grantor',
  'security.offboarding_incomplete': 'Offboarding не завершён',
  'access.grant_requested': 'Запрошена выдача доступа',
  'access.granted': 'Доступ выдан',
  'access.grant_failed': 'Ошибка выдачи доступа',
  'access.revoke_requested': 'Запрошен отзыв доступа',
  'access.revoked': 'Доступ отозван',
  'access.revoke_failed': 'Ошибка отзыва доступа',
  'access.manifest_applied': 'Манифест применён',
  'account.create_requested': 'Запрошено создание аккаунта',
  'account.created': 'Аккаунт создан',
  'account.create_failed': 'Ошибка создания аккаунта',
  'account.disable_requested': 'Запрошено отключение аккаунта',
  'account.disabled': 'Аккаунт отключён',
  'account.disable_failed': 'Ошибка отключения аккаунта',
  'account.enable_requested': 'Запрошено включение аккаунта',
  'account.enabled': 'Аккаунт включён',
  'account.enable_failed': 'Ошибка включения аккаунта',
  'account.delete_requested': 'Запрошено удаление аккаунта',
  'account.deleted': 'Аккаунт удалён',
  'account.delete_failed': 'Ошибка удаления аккаунта',
  'account.restore_requested': 'Запрошено восстановление аккаунта',
  'account.restored': 'Аккаунт восстановлен',
  'account.restore_failed': 'Ошибка восстановления аккаунта',
  'account.adopt_requested': 'Запрошено управление аккаунтом',
  'account.adopted': 'Аккаунт взят под управление',
  'account.adopt_failed': 'Ошибка принятия аккаунта под управление',
  'account.linked': 'Аккаунт связан с пользователем',
  'account.unlinked': 'Связь аккаунта удалена',
  'binding.adopted': 'Доступ взят под управление',
  'bulk.grant_requested': 'Запрошена массовая выдача доступов',
  'bulk.account_roles_requested': 'Запрошено изменение ролей аккаунта',
  'bulk.object_acl_requested': 'Запрошено изменение прямых прав',
  'connection.created': 'Подключение создано',
  'connection.updated': 'Подключение изменено',
  'connection.disabled': 'Подключение отключено',
  'connection.enabled': 'Подключение включено',
  'connection.deleted': 'Подключение удалено',
  'connection.refresh_requested': 'Запущена синхронизация',
  'connection.discovered': 'Снимок подключения обновлён',
  'connection.discovery_failed': 'Ошибка синхронизации подключения',
  'connection.admin_credential_switch_requested': 'Запрошена смена admin credential',
  'connection.admin_credential_rotate_requested': 'Запрошена ротация admin credential',
  'connection.admin_credential_switched': 'Admin credential подключения сменён',
  'connection.admin_credential_rotated': 'Admin credential подключения ротирован',
  'connection.admin_credential_change_failed': 'Ошибка изменения admin credential',
  'connection.admin_credential_change_cancelled': 'Изменение admin credential отменено',
  'credential.rotate_requested': 'Запрошено обновление учётных данных',
  'credential.rotated': 'Учётные данные обновлены',
  'credential.rotate_failed': 'Ошибка обновления учётных данных',
  'credential_shared': 'Учётные данные переданы',
  'operation.approved': 'Изменение подтверждено',
  'operation.rejected': 'Изменение отклонено',
  'operation.retry_requested': 'Запрошен повтор операции',
  'operation.resolved': 'Ошибка отмечена решённой',
  'principal.access_granted': 'Доступы пользователя изменены',
  'principal.created': 'Пользователь создан',
  'principal.credential_created': 'Credential пользователя создан',
  'principal.disabled': 'Пользователь отключён',
  'principal.enabled': 'Пользователь включён',
  'principal.offboarded': 'Пользователь выведен из системы',
  'principal.purged': 'Пользователь удалён навсегда',
  'principal.rotate_requested': 'Запрошено обновление учётных данных пользователя',
  'scope_policy.created': 'Правило доступа к окружению создано',
  'scope_policy.deleted': 'Правило доступа к окружению удалено',
  'service_token.created': 'API-токен создан',
  'service_token.revoked': 'API-токен отозван',
  'security.reveal_rate_anomaly': 'Обнаружена аномалия раскрытия секретов',
}

export function auditActionLabel(action: string): string {
  return AUDIT_ACTION_LABELS[action] ?? humanizeAction(action)
}

// Событие без записи в словаре читается как «Principal · external identity
// status changed», а не сырым идентификатором.
function humanizeAction(action: string): string {
  const parts = action.split('.').map((part) => part.replaceAll('_', ' ').trim()).filter(Boolean)
  if (parts.length === 0) return action
  return parts.map((part, index) => (index === 0 ? capitalize(part) : part)).join(' · ')
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

export function auditResultLabel(result: string): string {
  if (result === 'success') return 'Success'
  if (result === 'failure' || result === 'failed' || result === 'error') return 'Failed'
  if (result === 'alert') return 'Attention'
  return result
}

export function driftKindLabel(kind: string): string {
  if (kind === 'connection_degraded') return 'Подключение недоступно'
  if (kind === 'binding_drift') return 'Расхождение доступа'
  if (kind === 'unmanaged_binding') return 'Неуправляемый доступ'
  if (kind === 'missing_resource') return 'Ресурс не найден'
  if (kind === 'missing_account') return 'Учётная запись не найдена'
  return kind
}
