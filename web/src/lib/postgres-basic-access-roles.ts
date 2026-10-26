import { pairedPostgresRolePolicyDrafts } from './postgres-role-policy-templates'
import { roleTemplateCatalogIssues } from './role-template-document'
import type { PostgresRolePolicyTemplate, Resource, ResourceTreeItem } from './types'

// The direct PostgreSQL executor accepts the same portable identifier subset as the policy API.
const IDENTIFIER_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/

function reservedSchema(name: string): boolean {
  const lower = name.toLowerCase()
  return lower.startsWith('pg_') || lower === 'information_schema' || lower === 'grantor'
}

function validateCatalog(templates: readonly PostgresRolePolicyTemplate[]): void {
  const issues = roleTemplateCatalogIssues({ engine: 'postgres', templates: [...templates] })
  if (issues.length > 0) throw new Error(issues[0])
}

/**
 * The basic flow assumes the existing database owner creates its objects.
 * It never infers a different owner, a public schema, or a truncated role name.
 */
export function postgresBasicRoleDrafts(
  connectionId: string,
  database: Resource,
  tree: readonly ResourceTreeItem[],
): PostgresRolePolicyTemplate[] {
  if (connectionId === '' || database.connection_id !== connectionId || database.id === '' ||
    database.kind !== 'database' || database.status !== 'observed') {
    throw new Error('Выберите обнаруженную базу этого подключения.')
  }
  if (!IDENTIFIER_PATTERN.test(database.name)) {
    throw new Error('Имя базы не поддерживается: нужны латинские буквы, цифры и подчёркивания, без цифры в начале.')
  }
  if (database.name.length > 60) {
    throw new Error('Имя базы слишком длинное для пары r_/rw_: максимум 60 символов. Используйте расширенные шаблоны.')
  }
  const databaseRows = tree.filter((item) => item.id === database.id)
  if (databaseRows.length !== 1 || databaseRows[0].connection_id !== connectionId ||
    databaseRows[0].kind !== 'database' || databaseRows[0].status !== 'observed' ||
    databaseRows[0].name !== database.name) {
    throw new Error('Данные выбранной базы изменились. Обновите инвентарь и выберите базу снова.')
  }
  const attributes = database.attributes
  const owner = typeof attributes === 'object' && attributes !== null && !Array.isArray(attributes)
    ? (attributes as Record<string, unknown>).owner : undefined
  if (typeof owner !== 'string' || !IDENTIFIER_PATTERN.test(owner)) {
    throw new Error('Владелец базы не определён или его имя не поддерживается. Обновите инвентарь базы.')
  }

  const schemas: string[] = []
  const schemaIDs = new Set<string>()
  for (const item of tree) {
    if (item.parent_id !== database.id || item.kind !== 'schema' || item.status !== 'observed') continue
    if (item.connection_id !== connectionId) {
      throw new Error('Схемы базы относятся к другому подключению. Обновите инвентарь базы.')
    }
    if (reservedSchema(item.name)) continue
    if (item.id === '' || !IDENTIFIER_PATTERN.test(item.name) || schemaIDs.has(item.id) || schemas.includes(item.name)) {
      throw new Error('Список схем базы неоднозначен или содержит неподдерживаемые имена. Обновите инвентарь базы.')
    }
    schemaIDs.add(item.id)
    schemas.push(item.name)
  }
  if (schemas.length === 0) {
    throw new Error('У базы нет обнаруженных пользовательских схем. Обновите инвентарь базы.')
  }
  schemas.sort()

  const drafts = pairedPostgresRolePolicyDrafts(database.name).map((draft) => ({
    ...draft,
    // Keys are metadata, not SQL identifiers. Prefixing also supports _db names;
    // any collision caused by case folding or truncation is rejected on merge.
    key: `pg-${database.name.toLowerCase().slice(0, 48)}-${draft.profile === 'read' ? 'read' : 'read-write'}`,
    // Keep physical identity exact; the generic draft builder sanitizes its placeholder.
    role_name: `${draft.profile === 'read' ? 'r_' : 'rw_'}${database.name}`,
    description: draft.profile === 'read'
      ? 'Чтение существующих и будущих объектов владельца базы в выбранных схемах.'
      : 'Чтение и запись существующих и будущих объектов владельца базы в выбранных схемах.',
    schemas: [...schemas],
    owner_roles: [owner],
    creator_roles: [owner],
  }))
  validateCatalog(drafts)
  return drafts
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item) => right.includes(item))
}

function samePolicy(left: PostgresRolePolicyTemplate, right: PostgresRolePolicyTemplate): boolean {
  return left.role_name === right.role_name && left.database === right.database && left.profile === right.profile &&
    sameSet(left.schemas, right.schemas) && sameSet(left.owner_roles, right.owner_roles) &&
    sameSet(left.creator_roles, right.creator_roles)
}

/**
 * Add only missing specs. Reusing an exact role keeps its published identity,
 * text, ordering and metadata untouched; changed scope is never overwritten.
 */
export function mergePostgresBasicRoleDrafts(
  existing: readonly PostgresRolePolicyTemplate[],
  drafts: readonly PostgresRolePolicyTemplate[],
): { templates: PostgresRolePolicyTemplate[]; selected: PostgresRolePolicyTemplate[]; changed: boolean } {
  validateCatalog(existing)
  validateCatalog(drafts)
  const templates = [...existing]
  const selected: PostgresRolePolicyTemplate[] = []
  for (const draft of drafts) {
    const sameRole = templates.find((template) => template.role_name === draft.role_name)
    if (sameRole !== undefined) {
      if (!samePolicy(sameRole, draft)) {
        throw new Error('Для базовой роли уже есть шаблон с другими правами или областью доступа. Проверьте его в расширенных шаблонах.')
      }
      selected.push(sameRole)
      continue
    }
    if (templates.some((template) => template.key === draft.key || template.name === draft.name)) {
      throw new Error('Ключ или название базового шаблона уже заняты. Существующие шаблоны не изменены; проверьте расширенные шаблоны.')
    }
    templates.push(draft)
    selected.push(draft)
  }
  validateCatalog(templates)
  return { templates, selected, changed: templates.length !== existing.length }
}
