import {
  MONGODB_ROLE_POLICY_ACTIONS,
  mongoDBRolePolicyTemplateIssues,
} from './mongodb-role-policy-templates'
import type { RabbitMQPermissionTemplate } from './rabbitmq-permission-templates'
import type {
  MongoDBRolePolicyPrivilege,
  MongoDBRolePolicyResource,
  MongoDBRolePolicyTemplate,
  PostgresRolePolicyTemplate,
} from './types'

export type RoleTemplateCatalog =
  | { engine: 'postgres'; templates: PostgresRolePolicyTemplate[] }
  | { engine: 'rabbitmq'; templates: RabbitMQPermissionTemplate[] }
  | { engine: 'mongodb'; templates: MongoDBRolePolicyTemplate[] }

export type RoleTemplateEngine = RoleTemplateCatalog['engine']

// Matches the API request-body ceiling. PATCH additionally checks its full body.
export const MAX_ROLE_TEMPLATE_DOCUMENT_BYTES = 1 << 20
const MAX_TEMPLATES = 64
const KEY_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/
const POSTGRES_IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/
const MONGODB_BUILTIN_ROLES = new Set([
  '__system', 'backup', 'clusterAdmin', 'clusterManager', 'clusterMonitor',
  'dbAdmin', 'dbAdminAnyDatabase', 'dbOwner', 'directShardOperations',
  'enableSharding', 'hostManager', 'read', 'readAnyDatabase', 'readWrite',
  'readWriteAnyDatabase', 'restore', 'root', 'userAdmin', 'userAdminAnyDatabase',
  'searchCoordinator',
])
const MONGODB_INHERITABLE_BUILTINS = new Set(['read', 'readWrite'])
const MONGODB_ACTIONS: ReadonlySet<string> = new Set(MONGODB_ROLE_POLICY_ACTIONS)

function record(
  value: unknown,
  field: string,
  required: readonly string[],
  optional: readonly string[] = [],
): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${field}: ожидается JSON-объект.`)
  }
  const result = value as Record<string, unknown>
  if (Object.keys(result).some((key) => !required.includes(key) && !optional.includes(key))) {
    throw new Error(`${field}: есть неизвестные поля. SQL, BSON и команды не поддерживаются.`)
  }
  if (required.some((key) => !Object.hasOwn(result, key))) {
    throw new Error(`${field}: отсутствуют обязательные поля.`)
  }
  return result
}

function string(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new Error(`${field}: ожидается строка.`)
  return value
}

function array(value: unknown, field: string, max: number): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${field}: ожидается массив.`)
  if (value.length > max) throw new Error(`${field}: максимум ${max} элементов.`)
  return value
}

function strings(value: unknown, field: string, max: number): string[] {
  return array(value, field, max).map((item, index) => string(item, `${field}[${index}]`))
}

function postgresTemplate(value: unknown, field: string): PostgresRolePolicyTemplate {
  const item = record(value, field, [
    'key', 'name', 'description', 'role_name', 'database', 'schemas',
    'owner_roles', 'creator_roles', 'profile',
  ])
  if (item.profile !== 'read' && item.profile !== 'read_write') {
    throw new Error(`${field}.profile: разрешены только read и read_write.`)
  }
  return {
    key: string(item.key, `${field}.key`),
    name: string(item.name, `${field}.name`),
    description: string(item.description, `${field}.description`),
    role_name: string(item.role_name, `${field}.role_name`),
    database: string(item.database, `${field}.database`),
    schemas: strings(item.schemas, `${field}.schemas`, 64),
    owner_roles: strings(item.owner_roles, `${field}.owner_roles`, 64),
    creator_roles: strings(item.creator_roles, `${field}.creator_roles`, 64),
    profile: item.profile,
  }
}

function rabbitMQTemplate(value: unknown, field: string): RabbitMQPermissionTemplate {
  const item = record(value, field, [
    'key', 'name', 'description', 'vhost', 'configure', 'write', 'read', 'dangerous',
  ])
  if (typeof item.dangerous !== 'boolean') {
    throw new Error(`${field}.dangerous: ожидается true или false.`)
  }
  return {
    key: string(item.key, `${field}.key`),
    name: string(item.name, `${field}.name`),
    description: string(item.description, `${field}.description`),
    vhost: string(item.vhost, `${field}.vhost`),
    configure: string(item.configure, `${field}.configure`),
    write: string(item.write, `${field}.write`),
    read: string(item.read, `${field}.read`),
    dangerous: item.dangerous,
  }
}

function mongoDBResource(value: unknown, field: string): MongoDBRolePolicyResource {
  const item = record(value, field, [], ['db', 'collection', 'cluster', 'any_resource'])
  if (Object.hasOwn(item, 'cluster')) {
    record(item, field, ['cluster'])
    if (item.cluster !== true) throw new Error(`${field}.cluster: ожидается true.`)
    return { cluster: true }
  }
  if (Object.hasOwn(item, 'any_resource')) {
    record(item, field, ['any_resource'])
    if (item.any_resource !== true) throw new Error(`${field}.any_resource: ожидается true.`)
    // Kept editable for an existing invalid policy; semantic validation blocks Save.
    return { any_resource: true }
  }
  return {
    ...(Object.hasOwn(item, 'db') ? { db: string(item.db, `${field}.db`) } : {}),
    ...(Object.hasOwn(item, 'collection')
      ? { collection: string(item.collection, `${field}.collection`) }
      : {}),
  }
}

function mongoDBPrivilege(value: unknown, field: string): MongoDBRolePolicyPrivilege {
  const item = record(value, field, ['resource', 'actions'])
  return {
    resource: mongoDBResource(item.resource, `${field}.resource`),
    actions: strings(item.actions, `${field}.actions`, 128),
  }
}

function mongoDBTemplate(value: unknown, field: string): MongoDBRolePolicyTemplate {
  const item = record(value, field, [
    'key', 'name', 'description', 'role_name', 'role_database', 'inherited_roles', 'privileges',
  ])
  return {
    key: string(item.key, `${field}.key`),
    name: string(item.name, `${field}.name`),
    description: string(item.description, `${field}.description`),
    role_name: string(item.role_name, `${field}.role_name`),
    role_database: string(item.role_database, `${field}.role_database`),
    inherited_roles: array(item.inherited_roles, `${field}.inherited_roles`, 64)
      .map((raw, index) => {
        const refField = `${field}.inherited_roles[${index}]`
        const ref = record(raw, refField, ['role', 'db'])
        return { role: string(ref.role, `${refField}.role`), db: string(ref.db, `${refField}.db`) }
      }),
    privileges: array(item.privileges, `${field}.privileges`, 128)
      .map((raw, index) => mongoDBPrivilege(raw, `${field}.privileges[${index}]`)),
  }
}

function catalog(engine: unknown, templates: unknown): RoleTemplateCatalog {
  const items = array(templates, 'templates', MAX_TEMPLATES)
  switch (engine) {
    case 'postgres': return {
      engine,
      templates: items.map((item, index) => postgresTemplate(item, `templates[${index}]`)),
    }
    case 'rabbitmq': return {
      engine,
      templates: items.map((item, index) => rabbitMQTemplate(item, `templates[${index}]`)),
    }
    case 'mongodb': return {
      engine,
      templates: items.map((item, index) => mongoDBTemplate(item, `templates[${index}]`)),
    }
    default: throw new Error('Документы шаблонов поддерживаются только для PostgreSQL, RabbitMQ и MongoDB.')
  }
}

/** Copies typed template fields only, never a permission snapshot or connection config. */
export function serializeRoleTemplatesDocument(value: RoleTemplateCatalog): string {
  const parsed = catalog(value.engine, value.templates)
  const document = { version: 'v1', kind: 'role_templates', ...parsed }
  const pretty = `${JSON.stringify(document, null, 2)}\n`
  if (documentFits(pretty)) return pretty
  // Whitespace must not prevent a valid bounded catalog from being imported
  // again. Large exports retain the same JSON structure in compact form.
  const compact = `${JSON.stringify(document)}\n`
  if (documentFits(compact)) return compact
  throw new Error('Документ слишком большой: максимум 1 MiB.')
}

function documentFits(text: string): boolean {
  return text.length <= MAX_ROLE_TEMPLATE_DOCUMENT_BYTES &&
    new TextEncoder().encode(text).length <= MAX_ROLE_TEMPLATE_DOCUMENT_BYTES
}

/** Structural parsing is separate from completeness checks so drafts survive mode changes. */
export function parseRoleTemplatesDocument(
  text: string,
  expectedEngine: RoleTemplateEngine,
): RoleTemplateCatalog {
  if (!documentFits(text)) {
    throw new Error('Документ слишком большой: максимум 1 MiB.')
  }
  let raw: unknown
  try {
    raw = JSON.parse(text)
  } catch {
    // Native parse errors may contain arbitrary pasted text, including credentials.
    throw new Error('Некорректный JSON. Проверьте кавычки, запятые и скобки.')
  }
  // Snapshots deliberately have a different shape (`role`, not `templates`).
  // Explain the unsupported workflow before reporting those keys as unknown.
  if (typeof raw === 'object' && raw !== null && !Array.isArray(raw) &&
    (raw as Record<string, unknown>).kind === 'role_snapshot') {
    throw new Error('Это снимок роли, а не шаблон для создания. В нём нет полной спецификации прав. Скопируйте JSON готового шаблона или заполните поля.')
  }
  const document = record(raw, 'Документ', ['version', 'kind', 'engine', 'templates'])
  if (document.version !== 'v1') throw new Error('Поддерживается только version: "v1".')
  if (document.kind !== 'role_templates') {
    throw new Error('Ожидается kind: "role_templates". Снимки и access-манифесты не импортируются.')
  }
  if (document.engine !== expectedEngine) {
    throw new Error('Движок документа не совпадает с движком подключения.')
  }
  const parsed = catalog(document.engine, document.templates)
  const duplicates = duplicateIssues(parsed)
  if (duplicates.length > 0) throw new Error(duplicates[0])
  return parsed
}

function duplicateIssues(value: RoleTemplateCatalog): string[] {
  const issues: string[] = []
  const keys = new Set<string>()
  const names = new Set<string>()
  const identities = new Set<string>()
  value.templates.forEach((template, index) => {
    const prefix = `Шаблон ${index + 1}`
    // Empty identities are unfinished drafts, not duplicates of a published template.
    if (template.key !== '' && keys.has(template.key)) issues.push(`${prefix}: key повторяется в каталоге.`)
    if (template.name !== '' && names.has(template.name)) issues.push(`${prefix}: название повторяется в каталоге.`)
    keys.add(template.key)
    names.add(template.name)
    let identity: string | undefined
    if ('vhost' in template &&
      [template.vhost, template.configure, template.write, template.read].every((item) => item !== '')) {
      identity = JSON.stringify([template.vhost, template.configure, template.write, template.read])
    } else if ('role_database' in template && template.role_database !== '' && template.role_name !== '') {
      identity = JSON.stringify([template.role_database, template.role_name])
    } else if ('database' in template && template.role_name !== '') {
      identity = template.role_name
    }
    if (identity !== undefined && identities.has(identity)) {
      issues.push(`${prefix}: роль или точный набор прав уже представлен другим шаблоном.`)
    }
    if (identity !== undefined) identities.add(identity)
  })
  return issues
}

function textIssues(value: string, field: string, max: number, trim: boolean): string[] {
  if (value.trim() === '') return [`${field}: заполните обязательное поле.`]
  const issues: string[] = []
  if (trim && value !== value.trim()) issues.push(`${field}: уберите пробелы в начале и конце.`)
  if (new TextEncoder().encode(value).length > max) issues.push(`${field}: максимум ${max} байт.`)
  return issues
}

function postgresIssues(template: PostgresRolePolicyTemplate): string[] {
  const issues = [
    ...textIssues(template.name, 'Название', 128, true),
    ...textIssues(template.description, 'Описание', 512, true),
  ]
  if (!KEY_PATTERN.test(template.key)) issues.push('key: используйте 1–64 символа a-z, 0-9, _ или -, начиная с буквы или цифры.')
  if (!POSTGRES_IDENTIFIER_PATTERN.test(template.role_name)) issues.push('role_name: укажите SQL-идентификатор длиной до 63 символов.')
  if (template.role_name.toLowerCase().startsWith('pg_')) issues.push('role_name: префикс pg_ зарезервирован.')
  if (!POSTGRES_IDENTIFIER_PATTERN.test(template.database)) issues.push('database: укажите SQL-идентификатор длиной до 63 символов.')
  for (const key of ['schemas', 'owner_roles', 'creator_roles'] as const) {
    const values = template[key]
    if (values.length === 0 || values.length > 64) issues.push(`${key}: укажите от 1 до 64 идентификаторов.`)
    if (values.some((value) => !POSTGRES_IDENTIFIER_PATTERN.test(value))) {
      issues.push(`${key}: разрешены SQL-идентификаторы длиной до 63 символов.`)
    }
    if (new Set(values).size !== values.length) issues.push(`${key}: идентификаторы не должны повторяться.`)
  }
  if (template.schemas.some((schema) =>
    schema.toLowerCase().startsWith('pg_') || ['information_schema', 'grantor'].includes(schema.toLowerCase()))) {
    issues.push('schemas: системные схемы и схема grantor запрещены.')
  }
  for (const key of ['owner_roles', 'creator_roles'] as const) {
    if (template[key].includes(template.role_name)) issues.push(`${key}: policy-роль не может быть владельцем или создателем объектов.`)
  }
  if (template.profile !== 'read' && template.profile !== 'read_write') {
    issues.push('profile: разрешены только read и read_write.')
  }
  return issues
}

/** A bounded syntax scan of the backend subset; never evaluates a user expression. */
function permissionRegex(expression: string): { valid: boolean; unrestricted: boolean } {
  if (expression === '.*') return { valid: true, unrestricted: true }
  if (expression === '^$') return { valid: true, unrestricted: false }
  const invalid = { valid: false, unrestricted: false }
  if (expression.length < 3 || !expression.startsWith('^') || !expression.endsWith('$')) return invalid
  let body = expression.slice(1, -1)
  let escapes = 0
  for (let index = body.length - 2; index >= 0 && body[index] === '\\'; index--) escapes++
  const startsGroup = body.startsWith('(')
  const endsGroup = body.endsWith(')') && escapes % 2 === 0
  const grouped = startsGroup || endsGroup
  if (grouped) {
    if (body.length < 3 || !startsGroup || !endsGroup) return invalid
    body = body.slice(1, -1)
  }
  const arms: string[] = []
  let start = 0
  for (let index = 0; index < body.length; index++) {
    if (body[index] === '\\') {
      if (++index >= body.length) return invalid
    } else if (body[index] === '(' || body[index] === ')') {
      return invalid
    } else if (body[index] === '|') {
      if (start === index) return invalid
      arms.push(body.slice(start, index))
      start = index + 1
    }
  }
  if (start === body.length) return invalid
  arms.push(body.slice(start))
  if ((!grouped && arms.length !== 1) || (grouped && arms.length === 1 && arms[0] !== '.*')) return invalid
  for (const arm of arms) {
    for (let index = 0; index < arm.length; index++) {
      const ch = arm[index]
      if (/[A-Za-z0-9_/:\-]/.test(ch)) continue
      if (ch === '.' && arm[index + 1] === '*') {
        index++
      } else if (ch === '\\' && index + 1 < arm.length) {
        const code = arm.charCodeAt(++index)
        if (!((code >= 33 && code <= 47) || (code >= 58 && code <= 64) ||
          (code >= 91 && code <= 96) || (code >= 123 && code <= 126))) return invalid
      } else {
        return invalid
      }
    }
  }
  return { valid: true, unrestricted: arms.some((arm) => arm.split('.*').join('') === '') }
}

function rabbitMQIssues(template: RabbitMQPermissionTemplate): string[] {
  const issues = [
    ...textIssues(template.name, 'Название', 128, false),
    ...textIssues(template.description, 'Описание', 512, false),
    ...textIssues(template.vhost, 'vhost', 255, false),
  ]
  if (!KEY_PATTERN.test(template.key)) issues.push('key: используйте 1–64 символа a-z, 0-9, _ или -, начиная с буквы или цифры.')
  const parsed = (['configure', 'write', 'read'] as const).map((key) => {
    const expression = template[key]
    issues.push(...textIssues(expression, key, 512, false))
    if (expression.length > 512) return { valid: false, unrestricted: false }
    const result = permissionRegex(expression)
    if (!result.valid) issues.push(`${key}: разрешены .* или ^…$ с ASCII-литералами, wildcard .* и одной группой alternation.`)
    return result
  })
  if (parsed.every((item) => item.valid && item.unrestricted)) {
    issues.push('Полный доступ .*/.*/.* уже доступен как legacy vhost-access; отдельный шаблон не нужен.')
  }
  return issues
}

function mongoIdentity(database: string, role: string): string {
  return JSON.stringify([database, role])
}

function mongoDBCatalogIssues(templates: MongoDBRolePolicyTemplate[]): string[] {
  const issues: string[] = []
  const identities = new Set(templates.map((item) => mongoIdentity(item.role_database, item.role_name)))
  const graph = new Map<string, string[]>()
  templates.forEach((template, index) => {
    const prefix = `Шаблон ${index + 1}`
    // The existing shape guard prints unsupported actions. Replace them before
    // calling it so pasted arbitrary text cannot enter an error message.
    const safeTemplate = {
      ...template,
      privileges: template.privileges.map((privilege) => ({
        ...privilege,
        actions: privilege.actions.filter((action) => MONGODB_ACTIONS.has(action)),
      })),
    }
    issues.push(...mongoDBRolePolicyTemplateIssues(safeTemplate).map((issue) => `${prefix}: ${issue}`))
    if (MONGODB_BUILTIN_ROLES.has(template.role_name)) issues.push(`${prefix}: role_name совпадает со встроенной MongoDB-ролью.`)
    template.privileges.forEach((privilege, privilegeIndex) => {
      if (privilege.actions.length > 128) issues.push(`${prefix}, privilege ${privilegeIndex + 1}: максимум 128 actions.`)
      if (privilege.actions.some((action) => !MONGODB_ACTIONS.has(action))) {
        issues.push(`${prefix}, privilege ${privilegeIndex + 1}: есть неподдерживаемые actions.`)
      }
    })
    const identity = mongoIdentity(template.role_database, template.role_name)
    const dependencies: string[] = []
    template.inherited_roles.forEach((ref, refIndex) => {
      const dependency = mongoIdentity(ref.db, ref.role)
      if (dependency === identity) issues.push(`${prefix}: роль не может наследовать саму себя.`)
      if (MONGODB_INHERITABLE_BUILTINS.has(ref.role)) return
      if (MONGODB_BUILTIN_ROLES.has(ref.role)) {
        issues.push(`${prefix}, inherited role ${refIndex + 1}: разрешены только built-in read/readWrite или роль из этого каталога.`)
      } else if (!identities.has(dependency)) {
        issues.push(`${prefix}, inherited role ${refIndex + 1}: добавьте custom role в тот же каталог.`)
      } else {
        dependencies.push(dependency)
      }
    })
    graph.set(identity, dependencies)
  })
  const active = new Set<string>()
  const visited = new Set<string>()
  const cycle = (identity: string): boolean => {
    if (active.has(identity)) return true
    if (visited.has(identity)) return false
    active.add(identity)
    if ((graph.get(identity) ?? []).some(cycle)) return true
    active.delete(identity)
    visited.add(identity)
    return false
  }
  if ([...graph.keys()].some(cycle)) issues.push('Каталог содержит цикл наследования MongoDB-ролей.')
  return issues
}

/** The form and text editor use the same catalog guard before their existing PATCH. */
export function roleTemplateCatalogIssues(value: RoleTemplateCatalog): string[] {
  if (value.templates.length > MAX_TEMPLATES) return ['В каталоге может быть не более 64 шаблонов.']
  const issues = duplicateIssues(value)
  switch (value.engine) {
    case 'postgres': value.templates.forEach((template, index) => {
      issues.push(...postgresIssues(template).map((issue) => `Шаблон ${index + 1}: ${issue}`))
    }); break
    case 'rabbitmq': value.templates.forEach((template, index) => {
      issues.push(...rabbitMQIssues(template).map((issue) => `Шаблон ${index + 1}: ${issue}`))
    }); break
    case 'mongodb': issues.push(...mongoDBCatalogIssues(value.templates)); break
  }
  return issues
}
