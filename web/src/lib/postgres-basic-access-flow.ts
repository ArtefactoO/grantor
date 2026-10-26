import { api, apiList } from './api'
import { postgresBasicRoleDrafts, mergePostgresBasicRoleDrafts } from './postgres-basic-access-roles'
import { readPostgresRolePolicyTemplates } from './postgres-role-policy-templates'
import type {
  Connection, PatchConnectionResponse, PostgresRolePolicy, PostgresRolePolicySpec,
  PostgresRolePolicyTemplate, Resource, ResourceTreeItem, RolePolicyMutationResponse,
} from './types'
import { postgresProvisioningIssue, postgresProvisioningReady } from './postgres-provisioning-authority'

export type BasicRolesStage = 'checking' | 'saving' | 'discovering' | 'creating'

export interface BasicRolesIntent {
  connection: Connection
  database: Resource
  config: Record<string, unknown>
  selected: PostgresRolePolicyTemplate[]
  requestIds: Map<string, string>
  operations: Map<string, string>
  targetIdentity: string | null
}

function object(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {}
}

function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return item
    const record = item as Record<string, unknown>
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, record[key]]))
  })
}

function targetIdentity(connection: Connection): string | null {
  const value = object(connection.topology).system_identifier
  // Legacy numeric JSON cannot safely represent a 64-bit PostgreSQL identity.
  // A fresh discovery emits the lossless decimal string.
  return typeof value === 'string' && /^[0-9]{1,20}$/.test(value)
    ? `postgres:system:${value}` : null
}

function spec(template: PostgresRolePolicySpec): PostgresRolePolicySpec {
  return {
    role_name: template.role_name, database: template.database, profile: template.profile,
    schemas: [...template.schemas].sort(), owner_roles: [...template.owner_roles].sort(),
    creator_roles: [...template.creator_roles].sort(),
  }
}

export function basicRoleDiscoveryIssue(connection: Connection, databaseName: string): string | null {
  const skipped = object(connection.topology).skipped_databases
  if (skipped !== undefined && !Array.isArray(skipped)) return 'Не удалось проверить полноту инвентаря базы. Синхронизируйте подключение.'
  if (Array.isArray(skipped) && skipped.some((entry) => object(entry).name === databaseName)) {
    return 'Объекты этой базы не удалось обнаружить. Исправьте доступ Grantor к базе и синхронизируйте подключение.'
  }
  return null
}

export function basicRoleIntent(
  connection: Connection, database: Resource, tree: readonly ResourceTreeItem[],
): BasicRolesIntent {
  if (connection.engine !== 'postgres' || connection.status !== 'active' ||
    ['pending', 'pending_approval', 'running'].includes(connection.admin_credential_change?.status ?? '')) {
    throw new Error('Создание ролей доступно только для активного PostgreSQL-подключения.')
  }
	if (!postgresProvisioningReady(connection)) {
		throw new Error(postgresProvisioningIssue(connection) ?? 'PostgreSQL SUPERUSER не подтверждён.')
	}
  const issue = basicRoleDiscoveryIssue(connection, database.name)
  if (issue !== null) throw new Error(issue)
  const drafts = postgresBasicRoleDrafts(connection.id, database, tree)
  const original = object(connection.discovery_config)
  const merged = mergePostgresBasicRoleDrafts(readPostgresRolePolicyTemplates(original), drafts)
  return {
    connection: structuredClone(connection), database: structuredClone(database),
    config: structuredClone({ ...original, postgres_role_policy_templates: merged.templates }),
    selected: structuredClone(merged.selected), requestIds: new Map(), operations: new Map(),
    targetIdentity: targetIdentity(connection),
  }
}

function sameTarget(left: Connection, right: Connection): boolean {
  return left.id === right.id && left.engine === right.engine && left.environment === right.environment &&
    left.execution_mode === right.execution_mode && canonical(left.endpoints) === canonical(right.endpoints) &&
    canonical(left.tls_config) === canonical(right.tls_config) && left.vault_admin_path === right.vault_admin_path &&
    left.admin_credential_mode === right.admin_credential_mode &&
    left.admin_credential_change?.operation_id === right.admin_credential_change?.operation_id
}

function checkConnection(intent: BasicRolesIntent, current: Connection) {
  if (!sameTarget(intent.connection, current) ||
    ['pending', 'pending_approval', 'running'].includes(current.admin_credential_change?.status ?? '')) {
    throw new Error('Подключение изменилось. Закройте окно и проверьте базу заново.')
  }
	if (current.status === 'active' && !postgresProvisioningReady(current)) {
		throw new Error(postgresProvisioningIssue(current) ?? 'PostgreSQL SUPERUSER не подтверждён.')
	}
  const actual = targetIdentity(current)
  const discovering = current.status === 'discovering' || current.status === 'validating'
  if (intent.targetIdentity !== null &&
    (actual !== null || !discovering) && actual !== intent.targetIdentity) {
    throw new Error('Идентичность PostgreSQL-кластера изменилась или не подтверждена. Создание остановлено; проверьте подключение заново.')
  }
}

async function delay(ms: number, signal: AbortSignal) {
  signal.throwIfAborted()
  await new Promise<void>((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer)
      signal.removeEventListener('abort', abort)
      reject(new DOMException('Operation aborted', 'AbortError'))
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort)
      resolve()
    }, ms)
    signal.addEventListener('abort', abort, { once: true })
  })
}

export interface BasicRolesRunOptions {
  signal: AbortSignal
  onStage: (stage: BasicRolesStage) => void
  onOperation: (label: string, id: string) => void
  /** Poll timing is injectable for deterministic tests, never changes server intent. */
  pollMs?: number
  timeoutMs?: number
}

/** One UI action, existing durable catalog/discovery jobs, then guarded create-only jobs. */
export async function createBasicPostgresRoles(
  intent: BasicRolesIntent, { signal, onStage, onOperation, pollMs = 1500, timeoutMs = 120_000 }: BasicRolesRunOptions,
): Promise<{ ready: number; operationIds: string[]; confirmationRequired?: Connection }> {
  const id = intent.connection.id
  const connectionURL = `/api/v1/connections/${id}`
  const loadConnection = () => api<Connection>(connectionURL, { signal })
  signal.throwIfAborted()
  onStage('checking')
  let current = await loadConnection()
  checkConnection(intent, current)

  if (canonical(current.discovery_config) !== canonical(intent.config)) {
    if (current.status !== 'active' || current.updated_at !== intent.connection.updated_at ||
      canonical(current.discovery_config) !== canonical(intent.connection.discovery_config)) {
      throw new Error('Настройки подключения изменились. Закройте окно и откройте его заново; чужие изменения не перезаписаны.')
    }
    onStage('saving')
    signal.throwIfAborted()
    try {
      const response = await api<PatchConnectionResponse>(connectionURL, {
        method: 'PATCH', body: { updated_at: intent.connection.updated_at, discovery_config: intent.config }, signal,
      })
      current = response
      if (response.operation_id !== undefined) onOperation('Синхронизация', response.operation_id)
    } catch (error) {
      signal.throwIfAborted()
      // A lost PATCH response must not make us blindly replay its stale CAS.
      current = await loadConnection()
      checkConnection(intent, current)
      if (canonical(current.discovery_config) !== canonical(intent.config)) throw error
    }
  }

  onStage('discovering')
  const deadline = Date.now() + timeoutMs
  while (current.status === 'discovering' || current.status === 'validating') {
    if (Date.now() >= deadline) throw new Error('Синхронизация ещё выполняется. Можно закрыть окно и продолжить создание ролей позже.')
    await delay(pollMs, signal)
    current = await loadConnection()
    checkConnection(intent, current)
    if (canonical(current.discovery_config) !== canonical(intent.config)) {
      throw new Error('Каталог изменился во время синхронизации. Закройте окно и проверьте его заново.')
    }
  }
  checkConnection(intent, current)
  if (canonical(current.discovery_config) !== canonical(intent.config)) {
    throw new Error('Каталог изменился. Закройте окно и проверьте настройки заново.')
  }
  if (current.status !== 'active') {
    throw new Error('Подключение не готово к созданию ролей. Проверьте результат синхронизации; настройки пары сохранены только если запись каталога завершилась.')
  }

  const [database, tree, policies] = await Promise.all([
    api<Resource>(`/api/v1/resources/${intent.database.id}`, { signal }),
    apiList<ResourceTreeItem>(`${connectionURL}/resources?view=tree`, 'resources', signal),
    apiList<PostgresRolePolicy>(`${connectionURL}/role-policies`, 'policies', signal),
  ])
  const issue = basicRoleDiscoveryIssue(current, database.name)
  if (issue !== null) throw new Error(issue)
  const refreshedDrafts = postgresBasicRoleDrafts(id, database, tree)
  if (database.id !== intent.database.id || database.name !== intent.database.name ||
    canonical(refreshedDrafts.map(spec)) !== canonical(intent.selected.map(spec))) {
    throw new Error('Владелец или схемы базы изменились. Права не применены; проверьте базу заново.')
  }
  const selected = intent.selected.map((template) => {
    const matches = policies.filter((policy) => policy.template_key === template.key)
    if (matches.length !== 1 || canonical(spec(matches[0].desired_spec)) !== canonical(spec(template))) {
      throw new Error('Синхронизация не подтвердила настройки обеих ролей. Проверьте каталог и повторите синхронизацию.')
    }
    return matches[0]
  })

  // Check both members before queuing either one. Repair/adopt are not implied
  // by basic creation, and a partial previous run resumes by operation identity.
  for (const policy of selected) {
    if (policy.transition_operation_id) {
      intent.operations.set(policy.template_key, policy.transition_operation_id)
      onOperation(policy.desired_spec.role_name, policy.transition_operation_id)
    }
    if (policy.status === 'failed' && policy.creatable !== true) {
      throw new Error('Предыдущая операция роли не завершилась. Откройте её и повторите. Новая операция не создаётся.')
    }
    if (policy.transition_active && policy.transition_operation_id) {
      continue
    }
    if (policy.managed && policy.exact && policy.status === 'synced') continue
    if (policy.transition_active) throw new Error('Предыдущая операция роли ещё выполняется. Проверьте журнал операций.')
    if (!policy.apply_supported || policy.blocked_reason !== '' || policy.observed_fingerprint === '') {
      throw new Error('Создание роли заблокировано проверкой базы. Подробности доступны в разделе ролей; существующие права не изменены.')
    }
    if (!current.capabilities.includes('role.policy.create')) {
      throw new Error('Безопасное создание ролей недоступно. Обновите приложение и connector, затем синхронизируйте подключение.')
    }
    if ((policy.managed && policy.creatable !== true) || policy.observed_summary.role?.exists !== false) {
      throw new Error('Одноимённая роль уже существует. Проверьте её права в разделе ролей; автоматическая перезапись не выполняется.')
    }
  }

  const needsCreation = selected.some((policy) => !policy.transition_active && !(policy.managed && policy.exact && policy.status === 'synced'))
  if (needsCreation && intent.targetIdentity === null) {
    if (targetIdentity(current) === null) {
      throw new Error('Не удалось подтвердить идентичность PostgreSQL-кластера. Проверьте доступ Grantor и синхронизируйте подключение.')
    }
    // Preparation may establish identity for the first time. It cannot silently
    // upgrade an unproven preview into consent to mutate a physical cluster.
    return { ready: 0, operationIds: [...intent.operations.values()], confirmationRequired: current }
  }

  onStage('creating')
  let ready = 0
  for (const policy of selected) {
    signal.throwIfAborted()
    if (policy.managed && policy.exact && policy.status === 'synced') { ready++; continue }
    if (policy.transition_active) continue
    const requestId = intent.requestIds.get(policy.template_key) ?? globalThis.crypto.randomUUID()
    intent.requestIds.set(policy.template_key, requestId)
    try {
      const result = await api<RolePolicyMutationResponse>(
        `${connectionURL}/role-policies/${encodeURIComponent(policy.template_key)}/create`, {
          method: 'POST', body: { request_id: requestId, version: policy.version,
            observed_fingerprint: policy.observed_fingerprint, confirm: true,
            expected_target_identity: intent.targetIdentity }, signal,
        },
      )
      intent.operations.set(policy.template_key, result.operation_id)
      onOperation(policy.desired_spec.role_name, result.operation_id)
    } catch (error) {
      signal.throwIfAborted()
      // Do not enqueue a second member after an ambiguous first response. A
      // retry re-reads the persisted transition and reuses this request_id.
      throw error
    }
  }
  return { ready, operationIds: [...intent.operations.values()] }
}
