import type {
  MongoDBRolePolicyPrivilege,
  MongoDBRolePolicyResource,
  MongoDBRolePolicyRoleRef,
  MongoDBRolePolicyTemplate,
} from './types'

export const EMPTY_MONGODB_ROLE_POLICY_TEMPLATE: MongoDBRolePolicyTemplate = {
  key: '',
  name: '',
  description: '',
  role_name: '',
  role_database: '',
  inherited_roles: [],
  privileges: [],
}

export const EMPTY_MONGODB_ROLE_POLICY_ROLE_REF: MongoDBRolePolicyRoleRef = {
  role: '',
  db: '',
}

export const EMPTY_MONGODB_ROLE_POLICY_PRIVILEGE: MongoDBRolePolicyPrivilege = {
  resource: { db: '', collection: '' },
  actions: [],
}

/** Fixed, documented actions accepted by the template editor and backend. */
export const MONGODB_ROLE_POLICY_ACTIONS = [
  'addShard',
  'analyzeShardKey',
  'appendOplogNote',
  'applicationMessage',
  'authSchemaUpgrade',
  'bypassDefaultMaxTimeMS',
  'bypassDocumentValidation',
  'bypassWriteBlockingMode',
  'changeCustomData',
  'changeOwnCustomData',
  'changeOwnPassword',
  'changePassword',
  'changeStream',
  'checkMetadataConsistency',
  'cleanupOrphaned',
  'clearJumboFlag',
  'closeAllDatabases',
  'collMod',
  'collStats',
  'compact',
  'compactStructuredEncryptionData',
  'connPoolStats',
  'connPoolSync',
  'convertToCapped',
  'cpuProfiler',
  'createCollection',
  'createIndex',
  'createRole',
  'createSearchIndexes',
  'createUser',
  'dbHash',
  'dbStats',
  'dropCollection',
  'dropConnections',
  'dropDatabase',
  'dropIndex',
  'dropRole',
  'dropSearchIndex',
  'dropUser',
  'enableProfiler',
  'enableSharding',
  'find',
  'flushRouterConfig',
  'forceUUID',
  'fsync',
  'getClusterParameter',
  'getCmdLineOpts',
  'getDefaultRWConcern',
  'getLog',
  'getParameter',
  'getShardMap',
  'grantRole',
  'hostInfo',
  'impersonate',
  'indexStats',
  'inprog',
  'insert',
  'invalidateUserCache',
  'killAnyCursor',
  'killAnySession',
  'killCursors',
  'killop',
  'listClusterCatalog',
  'listCollections',
  'listDatabases',
  'listIndexes',
  'listSearchIndexes',
  'listSessions',
  'listShards',
  'logRotate',
  'moveChunk',
  'moveCollection',
  'oidReset',
  'planCacheIndexFilter',
  'planCacheRead',
  'planCacheWrite',
  'querySettings',
  'queryStatsRead',
  'queryStatsReadTransformed',
  'reIndex',
  'refineCollectionShardKey',
  'remove',
  'removeShard',
  'renameCollectionSameDB',
  'replSetConfigure',
  'replSetGetConfig',
  'replSetGetStatus',
  'replSetHeartbeat',
  'replSetStateChange',
  'reshardCollection',
  'resync',
  'revokeRole',
  'rewriteCollection',
  'rotateCertificates',
  'serverStatus',
  'setAuthenticationRestriction',
  'setDefaultRWConcern',
  'setFeatureCompatibilityVersion',
  'setParameter',
  'setUserWriteBlockMode',
  'shardedDataDistribution',
  'shardingState',
  'shutdown',
  'splitChunk',
  'top',
  'touch',
  'transitionFromDedicatedConfigServer',
  'transitionToDedicatedConfigServer',
  'unlock',
  'unshardCollection',
  'update',
  'updateSearchIndex',
  'useUUID',
  'validate',
  'viewRole',
  'viewUser',
] as const

export type MongoDBRolePolicyActionName = typeof MONGODB_ROLE_POLICY_ACTIONS[number]

const MONGODB_CLUSTER_ACTIONS = new Set<MongoDBRolePolicyActionName>([
  'addShard', 'appendOplogNote', 'applicationMessage', 'authSchemaUpgrade',
  'bypassDefaultMaxTimeMS', 'bypassWriteBlockingMode', 'checkMetadataConsistency',
  'cleanupOrphaned', 'closeAllDatabases', 'compact', 'connPoolStats', 'connPoolSync',
  'cpuProfiler', 'dropConnections', 'enableSharding', 'flushRouterConfig', 'forceUUID',
  'fsync', 'getClusterParameter', 'getCmdLineOpts', 'getDefaultRWConcern', 'getLog',
  'getParameter', 'getShardMap', 'hostInfo', 'impersonate', 'inprog',
  'invalidateUserCache', 'killAnySession', 'killop', 'listClusterCatalog',
  'listDatabases', 'listSessions', 'listShards', 'logRotate', 'moveCollection',
  'oidReset', 'queryStatsRead', 'queryStatsReadTransformed', 'removeShard',
  'replSetConfigure', 'replSetGetConfig', 'replSetGetStatus', 'replSetHeartbeat',
  'replSetStateChange', 'resync', 'rotateCertificates', 'serverStatus',
  'setDefaultRWConcern', 'setFeatureCompatibilityVersion', 'setParameter',
  'setUserWriteBlockMode', 'shardedDataDistribution', 'shardingState', 'shutdown',
  'splitChunk', 'top', 'touch', 'transitionFromDedicatedConfigServer',
  'transitionToDedicatedConfigServer', 'unlock', 'unshardCollection', 'useUUID',
])

const MONGODB_NAMESPACE_FORBIDDEN_ACTIONS = new Set<MongoDBRolePolicyActionName>([
  'addShard', 'appendOplogNote', 'applicationMessage', 'authSchemaUpgrade',
  'bypassDefaultMaxTimeMS', 'bypassWriteBlockingMode', 'cleanupOrphaned',
  'closeAllDatabases', 'connPoolStats', 'connPoolSync', 'cpuProfiler',
  'dropConnections', 'flushRouterConfig', 'forceUUID', 'fsync', 'getClusterParameter',
  'getCmdLineOpts', 'getDefaultRWConcern', 'getLog', 'getParameter', 'getShardMap',
  'hostInfo', 'impersonate', 'inprog', 'invalidateUserCache', 'killAnySession',
  'killop', 'listClusterCatalog', 'listDatabases', 'listSessions', 'listShards',
  'logRotate', 'moveCollection', 'oidReset', 'queryStatsRead',
  'queryStatsReadTransformed', 'removeShard', 'replSetConfigure', 'replSetGetConfig',
  'replSetGetStatus', 'replSetHeartbeat', 'replSetStateChange', 'resync',
  'rotateCertificates', 'serverStatus', 'setDefaultRWConcern',
  'setFeatureCompatibilityVersion', 'setParameter', 'setUserWriteBlockMode',
  'shardedDataDistribution', 'shardingState', 'shutdown', 'splitChunk', 'top',
  'touch', 'transitionFromDedicatedConfigServer', 'transitionToDedicatedConfigServer',
  'unlock', 'unshardCollection', 'useUUID',
])

const MONGODB_COLLECTION_FORBIDDEN_ACTIONS = new Set<MongoDBRolePolicyActionName>([
  'changeCustomData', 'changeOwnCustomData', 'changeOwnPassword', 'changePassword',
  'compactStructuredEncryptionData', 'createRole', 'createUser', 'dbStats',
  'dropDatabase', 'dropRole', 'dropUser', 'enableProfiler', 'grantRole',
  'listCollections', 'renameCollectionSameDB', 'revokeRole',
  'setAuthenticationRestriction', 'viewRole', 'viewUser',
])

const MONGODB_COLLECTION_REQUIRED_ACTIONS = new Set<MongoDBRolePolicyActionName>([
  'killAnyCursor', 'planCacheIndexFilter',
])

const MONGODB_CONCRETE_DATABASE_ACTIONS = MONGODB_COLLECTION_FORBIDDEN_ACTIONS

export function mongoDBActionSupportsResource(
  action: string,
  kind: MongoDBResourceKind,
): boolean {
  if (!MONGODB_ROLE_POLICY_ACTIONS.includes(action as MongoDBRolePolicyActionName)) return false
  if (kind === 'any_resource') return false
  const allowedAction = action as MongoDBRolePolicyActionName
  if (kind === 'cluster') return MONGODB_CLUSTER_ACTIONS.has(allowedAction)
  if (MONGODB_NAMESPACE_FORBIDDEN_ACTIONS.has(allowedAction)) return false
  if ((kind === 'collection' || kind === 'collection_across_databases') &&
    MONGODB_COLLECTION_FORBIDDEN_ACTIONS.has(allowedAction)) return false
  if (MONGODB_COLLECTION_REQUIRED_ACTIONS.has(allowedAction) &&
    kind !== 'collection' && kind !== 'collection_across_databases') return false
  if ((kind === 'all_databases' || kind === 'collection_across_databases') &&
    MONGODB_CONCRETE_DATABASE_ACTIONS.has(allowedAction)) return false
  return true
}

export function cloneMongoDBRolePolicyResource(
  resource: MongoDBRolePolicyResource,
): MongoDBRolePolicyResource {
  if ('cluster' in resource) return { cluster: true }
  if ('any_resource' in resource) return { any_resource: true }
  return { db: resource.db ?? '', collection: resource.collection ?? '' }
}

export function cloneMongoDBRolePolicyTemplate(
  template: MongoDBRolePolicyTemplate,
): MongoDBRolePolicyTemplate {
  return {
    ...template,
    inherited_roles: template.inherited_roles.map((role) => ({ ...role })),
    privileges: template.privileges.map((privilege) => ({
      resource: cloneMongoDBRolePolicyResource(privilege.resource),
      actions: [...privilege.actions],
    })),
  }
}

function object(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

function text(record: Record<string, unknown>, key: string): string {
  return typeof record[key] === 'string' ? record[key] as string : ''
}

function readRoleRefs(value: unknown): MongoDBRolePolicyRoleRef[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    const record = object(item)
    if (record === null) return []
    return [{ role: text(record, 'role'), db: text(record, 'db') }]
  })
}

function readResource(value: unknown): MongoDBRolePolicyResource | null {
  const resource = object(value)
  if (resource === null) return null
  const keys = Object.keys(resource)
  if (resource.cluster === true) return keys.length === 1 ? { cluster: true } : null
  if (resource.any_resource === true) return keys.length === 1 ? { any_resource: true } : null
  if (keys.every((key) => key === 'db' || key === 'collection') &&
    (resource.db === undefined || typeof resource.db === 'string') &&
    (resource.collection === undefined || typeof resource.collection === 'string')) {
    return {
      db: typeof resource.db === 'string' ? resource.db : '',
      collection: typeof resource.collection === 'string' ? resource.collection : '',
    }
  }
  return null
}

function readPrivileges(value: unknown): MongoDBRolePolicyPrivilege[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    const record = object(item)
    if (record === null) return []
    const resource = readResource(record.resource)
    if (resource === null || !Array.isArray(record.actions)) return []
    return [{
      resource,
      actions: record.actions.filter((action): action is string => typeof action === 'string'),
    }]
  })
}

/**
 * Keeps malformed scalar values editable while refusing arbitrary BSON
 * resource shapes. The backend remains authoritative for full validation.
 */
export function readMongoDBRolePolicyTemplates(value: unknown): MongoDBRolePolicyTemplate[] {
  const config = object(value)
  if (config === null || !Array.isArray(config.mongodb_role_policy_templates)) return []
  return config.mongodb_role_policy_templates.flatMap((item) => {
    const record = object(item)
    if (record === null) return []
    return [{
      key: text(record, 'key'),
      name: text(record, 'name'),
      description: text(record, 'description'),
      role_name: text(record, 'role_name'),
      role_database: text(record, 'role_database'),
      inherited_roles: readRoleRefs(record.inherited_roles),
      privileges: readPrivileges(record.privileges),
    }]
  })
}

export type MongoDBResourceKind =
  | 'database'
  | 'collection'
  | 'all_databases'
  | 'collection_across_databases'
  | 'cluster'
  | 'any_resource'

const TEMPLATE_KEY_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/
const ROLE_NAME_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/
const DATABASE_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_-]{0,62}$/
const COLLECTION_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$/
const CONTROL_CHARACTER_PATTERN = /[\u0000-\u001f\u007f]/

function validDisplayText(value: string, maxBytes: number): boolean {
  return value !== '' && value === value.trim() &&
    !CONTROL_CHARACTER_PATTERN.test(value) && new TextEncoder().encode(value).length <= maxBytes
}

/** Client guard mirrors the shape checks needed before PATCH can be useful. */
export function mongoDBRolePolicyTemplateIssues(
  template: MongoDBRolePolicyTemplate,
): string[] {
  const issues: string[] = []
  if (!TEMPLATE_KEY_PATTERN.test(template.key)) issues.push('Укажите корректный key.')
  if (!validDisplayText(template.name, 128)) {
    issues.push('Название обязательно: без control characters и не более 128 bytes.')
  }
  if (!validDisplayText(template.description, 512)) {
    issues.push('Описание обязательно: одна строка без control characters, не более 512 bytes.')
  }
  if (!ROLE_NAME_PATTERN.test(template.role_name)) issues.push('Укажите корректное имя custom role.')
  if (!DATABASE_PATTERN.test(template.role_database)) issues.push('Укажите корректную role database.')
  if (template.inherited_roles.length > 64) issues.push('Максимум 64 inherited roles.')
  template.inherited_roles.forEach((role, index) => {
    if (!ROLE_NAME_PATTERN.test(role.role)) issues.push(`Inherited role ${index + 1}: некорректное имя.`)
    if (!DATABASE_PATTERN.test(role.db)) issues.push(`Inherited role ${index + 1}: некорректная database.`)
    if (template.role_database !== 'admin' && role.db !== template.role_database) {
      issues.push(`Inherited role ${index + 1}: database должна совпадать с role database.`)
    }
  })
  if (template.privileges.length > 128) issues.push('Максимум 128 privileges.')
  template.privileges.forEach((privilege, index) => {
    const prefix = `Privilege ${index + 1}`
    const kind = mongoDBResourceKind(privilege.resource)
    if (kind === 'any_resource') issues.push(`${prefix}: anyResource запрещён.`)
    if (template.role_database !== 'admin' &&
      (kind === 'cluster' || kind === 'all_databases' || kind === 'collection_across_databases')) {
      issues.push(`${prefix}: broad resource разрешён только роли в admin.`)
    }
    if (!('cluster' in privilege.resource) && !('any_resource' in privilege.resource)) {
      const database = privilege.resource.db ?? ''
      const collection = privilege.resource.collection ?? ''
      if (database !== '' && !DATABASE_PATTERN.test(database)) {
        issues.push(`${prefix}: некорректная database scope.`)
      }
      if (collection !== '' && !COLLECTION_PATTERN.test(collection)) {
        issues.push(`${prefix}: некорректная collection.`)
      }
      if (template.role_database !== 'admin' && database !== template.role_database) {
        issues.push(`${prefix}: database scope должна совпадать с role database.`)
      }
    }
    if (privilege.actions.length === 0) issues.push(`${prefix}: выберите хотя бы один action.`)
    const invalidActions = privilege.actions.filter(
      (action) => !mongoDBActionSupportsResource(action, kind),
    )
    if (invalidActions.length > 0) {
      issues.push(`${prefix}: actions не подходят resource: ${invalidActions.join(', ')}.`)
    }
  })
  return issues
}

export function mongoDBResourceKind(resource: MongoDBRolePolicyResource): MongoDBResourceKind {
  if ('cluster' in resource) return 'cluster'
  if ('any_resource' in resource) return 'any_resource'
  if ((resource.db ?? '') === '') {
    return (resource.collection ?? '') === '' ? 'all_databases' : 'collection_across_databases'
  }
  return (resource.collection ?? '') === '' ? 'database' : 'collection'
}

export function mongoDBResourceForKind(
  kind: MongoDBResourceKind,
  previous?: MongoDBRolePolicyResource,
): MongoDBRolePolicyResource {
  if (kind === 'cluster') return { cluster: true }
  if (kind === 'any_resource') return { any_resource: true }
  const db = previous !== undefined && !('cluster' in previous) && !('any_resource' in previous)
    ? previous.db ?? ''
    : ''
  const collection = previous !== undefined && !('cluster' in previous) && !('any_resource' in previous)
    ? previous.collection ?? ''
    : ''
  if (kind === 'all_databases') return { db: '', collection: '' }
  if (kind === 'collection_across_databases') return { db: '', collection }
  return { db, collection: kind === 'collection' ? collection : '' }
}

const DANGEROUS_INHERITED_ROLES = new Set([
  '__system',
  'backup',
  'clusterAdmin',
  'clusterManager',
  'clusterMonitor',
  'dbAdminAnyDatabase',
  'dbOwner',
  'hostManager',
  'readWriteAnyDatabase',
  'restore',
  'root',
  'userAdmin',
  'userAdminAnyDatabase',
])

const SAFE_MONGODB_DATA_ACTIONS = new Set([
  'changeStream', 'collStats', 'dbHash', 'dbStats', 'find', 'indexStats',
  'insert', 'killCursors', 'listCollections', 'listIndexes', 'listSearchIndexes',
  'planCacheRead', 'remove', 'update', 'validate',
])

/** Informational editor preview only; discovery computes the authoritative flag. */
export function mongoDBTemplateDangerPreview(
  template: MongoDBRolePolicyTemplate,
): string[] {
  const reasons: string[] = []
  if (template.inherited_roles.some((role) => DANGEROUS_INHERITED_ROLES.has(role.role))) {
    reasons.push('Наследуется административная или cluster-wide роль.')
  }
  if (template.privileges.some((privilege) => 'cluster' in privilege.resource)) {
    reasons.push('Есть действие на cluster-wide resource.')
  }
  if (template.privileges.some((privilege) => 'any_resource' in privilege.resource)) {
    reasons.push('Есть действие на anyResource во всех базах и коллекциях.')
  }
  if (template.privileges.some((privilege) =>
    !('cluster' in privilege.resource) && !('any_resource' in privilege.resource) &&
      (privilege.resource.db ?? '') === '')) {
    reasons.push('Есть cross/all-database resource.')
  }
  const actions = new Set(template.privileges.flatMap((privilege) => privilege.actions))
  const flagged = [...actions].filter((action) => !SAFE_MONGODB_DATA_ACTIONS.has(action)).sort()
  if (flagged.length > 0) reasons.push(`Чувствительные действия: ${flagged.join(', ')}.`)
  return reasons
}
