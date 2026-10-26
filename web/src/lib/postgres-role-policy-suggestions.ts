import type { Connection, Resource } from './types'

/** A discovery observation, never a live ACL check or a desired policy. */
export interface PostgresPolicySuggestionSnapshot {
  connection: Pick<Connection, 'id' | 'engine' | 'status' | 'last_discovery_at' | 'topology'>
  resources: readonly Resource[]
}

export interface PostgresPolicyOwnerEvidence {
  role: string
  schemaNames: string[]
  objectsBySchema: { schema: string; count: number }[]
}

export interface PostgresPolicySuggestions {
  candidates: PostgresPolicyOwnerEvidence[]
  blockers: string[]
  emptySchemas: string[]
  missingObjectCount: number
}

const OBJECT_KINDS = new Set(['table', 'partition', 'view', 'materialized_view', 'sequence'])

interface ConnectionResourceIndex {
  databases: Map<string, Resource[]>
  schemas: Map<string, Map<string, Resource[]>>
  objects: Map<string, Resource[]>
}

function appendResource(index: Map<string, Resource[]>, key: string, resource: Resource): void {
  const entries = index.get(key)
  if (entries === undefined) index.set(key, [resource])
  else entries.push(resource)
}

function indexResources(resources: readonly Resource[]): Map<string, ConnectionResourceIndex> {
  const connections = new Map<string, ConnectionResourceIndex>()
  for (const resource of resources) {
    let index = connections.get(resource.connection_id)
    if (index === undefined) {
      index = { databases: new Map(), schemas: new Map(), objects: new Map() }
      connections.set(resource.connection_id, index)
    }
    if (resource.kind === 'database') {
      appendResource(index.databases, resource.name, resource)
    } else if (resource.kind === 'schema' && resource.parent_id !== null) {
      let schemas = index.schemas.get(resource.parent_id)
      if (schemas === undefined) {
        schemas = new Map()
        index.schemas.set(resource.parent_id, schemas)
      }
      appendResource(schemas, resource.name, resource)
    } else if (resource.parent_id !== null && OBJECT_KINDS.has(resource.kind)) {
      appendResource(index.objects, resource.parent_id, resource)
    }
  }
  return connections
}

function record(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {}
}

function owner(resource: Resource): string | null {
  const value = record(resource.attributes).owner
  // Policy identifiers reject surrounding whitespace. Never turn a quoted
  // target role into a different identity when the form normalizes its fields.
  return typeof value === 'string' && value.trim() !== '' && value === value.trim() ? value : null
}

/**
 * Scope through exact parent IDs, not canonical-path prefixes or database
 * ownership. All offered facts must belong to one successful observation.
 * Object ownership can suggest a creator, but cannot prove a future migrator:
 * ownership may have changed and discovery does not expose CREATE/default ACL.
 */
export function postgresRolePolicySuggestions(
  snapshot: PostgresPolicySuggestionSnapshot,
  connectionId: string,
  database: string,
  schemaNames: readonly string[],
): PostgresPolicySuggestions {
  return createPostgresPolicySuggestionResolver(snapshot)(connectionId, database, schemaNames)
}

/**
 * One immutable discovery response can serve many policies and keystrokes.
 * Index once, cache only scoped evidence, and recheck admission metadata on
 * every call. A new resources array invalidates both the index and evidence.
 */
export function createPostgresPolicySuggestionResolver(snapshot: PostgresPolicySuggestionSnapshot) {
  let indexedResources: readonly Resource[] | undefined
  let resourceIndex: Map<string, ConnectionResourceIndex> | undefined
  const scopes = new Map<string, PostgresPolicySuggestions>()
  return (connectionId: string, database: string, schemaNames: readonly string[]): PostgresPolicySuggestions => {
    // React Query publishes new immutable arrays for a changed observation.
    // Also honor replacement on a retained envelope in direct callers.
    if (indexedResources !== snapshot.resources) {
      indexedResources = snapshot.resources
      resourceIndex = undefined
      scopes.clear()
    }
    const connection = snapshot.connection
    const observedAt = connection.last_discovery_at
    const selectedSchemas = [...new Set(schemaNames.map((name) => name.trim()).filter(Boolean))]
    const key = JSON.stringify([connectionId, observedAt, database.trim(), selectedSchemas])
    const gate = suggestionAdmissionBlocker(connection, connectionId, database, selectedSchemas)
    if (gate !== null) return { candidates: [], blockers: [gate], emptySchemas: [], missingObjectCount: 0 }
    const cached = scopes.get(key)
    if (cached !== undefined) return cached
    resourceIndex ??= indexResources(snapshot.resources)
    const result = scopedPostgresRolePolicySuggestions(resourceIndex.get(connectionId), database.trim(), selectedSchemas, observedAt)
    // Editing many different scopes must not retain an unbounded session cache.
    if (scopes.size >= 128) {
      const oldest = scopes.keys().next().value
      if (oldest !== undefined) scopes.delete(oldest)
    }
    scopes.set(key, result)
    return result
  }
}

function suggestionAdmissionBlocker(
  connection: PostgresPolicySuggestionSnapshot['connection'],
  connectionId: string,
  database: string,
  selectedSchemas: readonly string[],
): string | null {
  const observedAt = connection.last_discovery_at
  if (connection.id !== connectionId || connection.engine !== 'postgres') {
    return 'Снимок относится к другому подключению. Загрузите подсказки заново.'
  }
  if (observedAt === null || !Number.isFinite(Date.parse(observedAt)) ||
    !['active', 'degraded'].includes(connection.status)) {
    return 'Нет подтвержденного снимка подключения. Дождитесь успешной синхронизации.'
  }
  if (database.trim() === '' || selectedSchemas.length === 0) {
    return 'Укажите существующую базу и хотя бы одну схему для подсказок.'
  }
  const skipped = record(connection.topology).skipped_databases
  if (Array.isArray(skipped) && skipped.some((item) => record(item).name === database.trim())) {
    return 'Не удалось проверить объекты этой базы при синхронизации. Устраните ошибку подключения и синхронизируйте снова.'
  }
  return null
}

function scopedPostgresRolePolicySuggestions(
  resources: ConnectionResourceIndex | undefined,
  database: string,
  selectedSchemas: readonly string[],
  observedAt: string | null,
): PostgresPolicySuggestions {
  const result: PostgresPolicySuggestions = {
    candidates: [], blockers: [], emptySchemas: [], missingObjectCount: 0,
  }
  const databases = resources?.databases.get(database) ?? []
  if (databases.length !== 1 || databases[0].status !== 'observed') {
    result.blockers.push('База не обнаружена однозначно в снимке. Синхронизируйте подключение или проверьте имя базы.')
    return result
  }
  const db = databases[0]
  const current = (resource: Resource) => resource.status === 'observed' && resource.observed_at === observedAt
  if (!current(db)) {
    result.blockers.push('Снимок базы устарел или не совпадает с последней синхронизацией. Загрузите подсказки заново.')
    return result
  }
  const evidence = new Map<string, PostgresPolicyOwnerEvidence>()
  const candidate = (role: string) => {
    let value = evidence.get(role)
    if (value === undefined) {
      value = { role, schemaNames: [], objectsBySchema: [] }
      evidence.set(role, value)
    }
    return value
  }
  for (const schemaName of selectedSchemas) {
    const matches = resources?.schemas.get(db.id)?.get(schemaName) ?? []
    if (matches.length !== 1 || !current(matches[0])) {
      result.blockers.push(`Схема ${schemaName} отсутствует или ее снимок устарел. Синхронизируйте подключение.`)
      continue
    }
    const schema = matches[0]
    const schemaOwner = owner(schema)
    if (schemaOwner === null) {
      result.blockers.push(`Не удалось подобрать владельца схемы ${schemaName}.`)
    } else {
      candidate(schemaOwner).schemaNames.push(schemaName)
    }
    const objects = resources?.objects.get(schema.id) ?? []
    result.missingObjectCount += objects.filter((resource) => resource.status === 'missing').length
    const present = objects.filter((resource) => resource.status !== 'missing')
    if (present.length === 0) result.emptySchemas.push(schemaName)
    for (const object of present) {
      if (!current(object)) {
        result.blockers.push(`Снимок объектов схемы ${schemaName} неполный или устарел. Синхронизируйте подключение.`)
        break
      }
      const objectOwner = owner(object)
      if (objectOwner === null) {
        result.blockers.push(`Не удалось подобрать владельца объекта ${schemaName}.${object.name}.`)
        continue
      }
      const roleEvidence = candidate(objectOwner)
      const count = roleEvidence.objectsBySchema.find((item) => item.schema === schemaName)
      if (count === undefined) roleEvidence.objectsBySchema.push({ schema: schemaName, count: 1 })
      else count.count += 1
    }
  }
  // A partially observed scope must not look like a complete owner list.
  if (result.blockers.length === 0) {
    result.candidates = [...evidence.values()].sort((left, right) => left.role.localeCompare(right.role))
  }
  return result
}

/** Explicit acceptance adds a candidate without replacing manually entered roles. */
export function addPostgresPolicyRole(roles: readonly string[], candidate: string): string[] {
  return roles.some((role) => role.trim() === candidate) ? [...roles] : [...roles, candidate]
}
