import type {
  PostgresRolePolicyProfile,
  PostgresRolePolicyTemplate,
} from './types'

export const EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE: PostgresRolePolicyTemplate = {
  key: '',
  name: '',
  description: '',
  role_name: '',
  database: '',
  schemas: ['public'],
  owner_roles: [],
  creator_roles: [],
  profile: 'read',
}

export function clonePostgresRolePolicyTemplate(
  template: PostgresRolePolicyTemplate,
): PostgresRolePolicyTemplate {
  return {
    ...template,
    schemas: [...template.schemas],
    owner_roles: [...template.owner_roles],
    creator_roles: [...template.creator_roles],
  }
}

/** Explicit drafts only: neither catalog editing nor rendering creates target roles. */
export function pairedPostgresRolePolicyDrafts(databaseHint: string): PostgresRolePolicyTemplate[] {
  const database = databaseHint.trim()
  const keyBase = database
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48)
  const roleBase = database
    .replace(/[^A-Za-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60)
  const shared = {
    ...clonePostgresRolePolicyTemplate(EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE),
    database,
  }
  return [
    {
      ...clonePostgresRolePolicyTemplate(shared),
      key: keyBase === '' ? '' : `${keyBase}-read`,
      name: database === '' ? 'Чтение базы' : `${database}: чтение`,
      role_name: roleBase === '' ? '' : `r_${roleBase}`,
      profile: 'read',
    },
    {
      ...clonePostgresRolePolicyTemplate(shared),
      key: keyBase === '' ? '' : `${keyBase}-read-write`,
      name: database === '' ? 'Чтение и запись базы' : `${database}: чтение и запись`,
      role_name: roleBase === '' ? '' : `rw_${roleBase.slice(0, 59)}`,
      profile: 'read_write',
    },
  ]
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return []
  return value.filter((item): item is string => typeof item === 'string')
}

function profile(value: unknown): PostgresRolePolicyProfile {
  return value === 'read_write' ? 'read_write' : 'read'
}

/**
 * Reads the structured admin catalog without interpreting SQL/ACL syntax.
 * Invalid scalar fields stay editable as empty values; the backend remains
 * authoritative for connection-level validation.
 */
export function readPostgresRolePolicyTemplates(value: unknown): PostgresRolePolicyTemplate[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return []
  const raw = (value as Record<string, unknown>).postgres_role_policy_templates
  if (!Array.isArray(raw)) return []

  return raw.flatMap((item) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return []
    const record = item as Record<string, unknown>
    const text = (key: string) => typeof record[key] === 'string' ? record[key] as string : ''
    return [{
      key: text('key'),
      name: text('name'),
      description: text('description'),
      role_name: text('role_name'),
      database: text('database'),
      schemas: stringArray(record.schemas),
      owner_roles: stringArray(record.owner_roles),
      creator_roles: stringArray(record.creator_roles),
      profile: profile(record.profile),
    }]
  })
}

/** One-name-per-line controls keep identifiers structured and predictable. */
export function postgresRolePolicyLines(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '')
}
