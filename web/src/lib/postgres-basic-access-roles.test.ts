import { describe, expect, it } from 'vitest'
import { mergePostgresBasicRoleDrafts, postgresBasicRoleDrafts } from './postgres-basic-access-roles'
import { roleTemplateCatalogIssues } from './role-template-document'
import type { PostgresRolePolicyTemplate, Resource, ResourceTreeItem } from './types'

const CONNECTION_ID = 'connection-1'

function database(overrides: Partial<Resource> = {}): Resource {
  return {
    id: 'database-1', connection_id: CONNECTION_ID, parent_id: null, kind: 'database',
    external_id: 'database:appdb', name: 'appdb', canonical_path: 'appdb',
    attributes: { owner: 'app_owner' }, fingerprint: 'database-fingerprint',
    observed_at: '2026-08-26T10:00:00Z', status: 'observed', ownership: 'unmanaged',
    created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00Z', ...overrides,
  }
}

function schema(name = 'public', overrides: Partial<ResourceTreeItem> = {}): ResourceTreeItem {
  return {
    id: `schema-${name}`, connection_id: CONNECTION_ID, parent_id: 'database-1',
    kind: 'schema', name, status: 'observed', ownership: 'unmanaged', ...overrides,
  }
}

function inventory(db: Resource = database(), schemas: ResourceTreeItem[] = [schema()]): ResourceTreeItem[] {
  return [db, ...schemas]
}

function pair(): PostgresRolePolicyTemplate[] {
  return postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory())
}

function otherTemplate(index = 1): PostgresRolePolicyTemplate {
  return {
    ...pair()[0], key: `other-${index}`, name: `Other ${index}`, role_name: `other_reader_${index}`,
  }
}

describe('basic PostgreSQL role drafts', () => {
  it('fills both fixed profiles from the selected database and its existing owner', () => {
    const drafts = pair()
    expect(drafts).toEqual([
      {
        key: 'pg-appdb-read', name: 'appdb: чтение',
        description: 'Чтение существующих и будущих объектов владельца базы в выбранных схемах.',
        database: 'appdb', role_name: 'r_appdb', profile: 'read', schemas: ['public'],
        owner_roles: ['app_owner'], creator_roles: ['app_owner'],
      },
      {
        key: 'pg-appdb-read-write', name: 'appdb: чтение и запись',
        description: 'Чтение и запись существующих и будущих объектов владельца базы в выбранных схемах.',
        database: 'appdb', role_name: 'rw_appdb', profile: 'read_write', schemas: ['public'],
        owner_roles: ['app_owner'], creator_roles: ['app_owner'],
      },
    ])
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: drafts })).toEqual([])
    expect(drafts[0].schemas).not.toBe(drafts[1].schemas)
    expect(drafts[0].owner_roles).not.toBe(drafts[1].owner_roles)
    expect(drafts[0].owner_roles).not.toBe(drafts[0].creator_roles)
  })

  it('takes all currently observed direct user schemas without guessing public', () => {
    const tree = inventory(database(), [
      schema('events'), schema('reports'),
      schema('public', { status: 'missing' }), schema('private', { status: 'deleted' }),
      schema('nested', { parent_id: 'schema-reports' }), schema('unrelated', { parent_id: 'other-db' }),
      schema('relation', { kind: 'table' }), schema('foreign-db', { parent_id: 'other-db', connection_id: 'other' }),
      schema('information_schema'), schema('grantor'), schema('Grantor'), schema('pg_catalog'),
      schema('pg_temp_2'), schema('PG_TOAST'),
    ])

    const drafts = postgresBasicRoleDrafts(CONNECTION_ID, database(), tree)
    expect(drafts.map((template) => template.schemas)).toEqual([
      ['events', 'reports'], ['events', 'reports'],
    ])
  })

  it('keeps case and underscores in physical database/role identities', () => {
    const db = database({ name: '_App_DB_' })
    const drafts = postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))
    expect(drafts.map((template) => template.role_name)).toEqual(['r__App_DB_', 'rw__App_DB_'])
    expect(drafts.map((template) => template.database)).toEqual(['_App_DB_', '_App_DB_'])
    expect(drafts.map((template) => template.key)).toEqual(['pg-_app_db_-read', 'pg-_app_db_-read-write'])
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: drafts })).toEqual([])
  })

  it('supports the longest exact pair without silently truncating SQL identifiers', () => {
    const name = 'd'.repeat(60)
    const db = database({ name })
    const drafts = postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))
    expect(drafts[1].role_name).toBe(`rw_${name}`)
    expect(drafts[1].role_name).toHaveLength(63)
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: drafts })).toEqual([])
    for (const length of [61, 62, 63]) {
      const tooLong = database({ name: 'd'.repeat(length) })
      expect(() => postgresBasicRoleDrafts(CONNECTION_ID, tooLong, inventory(tooLong))).toThrow('максимум 60')
    }
  })

  it.each([
    { connection_id: 'other-connection' }, { kind: 'schema' }, { kind: 'table' }, { id: '' },
    { status: 'missing' }, { status: 'deleted' }, { status: 'provisioning' },
  ])('rejects an unobserved or out-of-scope database %#', (overrides) => {
    const db = database(overrides)
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))).toThrow('обнаруженную базу')
  })

  it('rejects an unspecified connection', () => {
    const db = database({ connection_id: '' })
    expect(() => postgresBasicRoleDrafts('', db, inventory(db))).toThrow('обнаруженную базу')
  })

  it.each(['', ' ', 'app-db', '123db', 'app db', ' appdb', 'appdb ', 'db;DROP', 'база', 'd'.repeat(64)])(
    'rejects unsupported database identifiers without echoing them: %#',
    (name) => {
      const db = database({ name })
      expect(() => postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))).toThrow('Имя базы не поддерживается')
    },
  )

  it.each([
    null, [], '', {}, { owner: null }, { owner: [] }, { owner: 3 }, { owner: '' },
    { owner: ' app_owner' }, { owner: 'app-owner' }, { owner: 'a'.repeat(64) },
    { owner: { name: 'app_owner' } }, { username: 'connection_admin' },
  ])('requires an explicit supported owner without falling back to the admin or database name: %#', (attributes) => {
    const db = database({ attributes })
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))).toThrow('Владелец базы не определён')
  })

  it.each(['r_appdb', 'rw_appdb'])('never makes the generated policy role its own owner: %s', (owner) => {
    const db = database({ attributes: { owner } })
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, db, inventory(db))).toThrow('не может быть владельцем')
  })

  it.each([
    { connection_id: 'other' }, { kind: 'schema' }, { status: 'missing' }, { name: 'renamed' },
  ])('rejects a changed database tree row %#', (overrides) => {
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(overrides))))
      .toThrow('Данные выбранной базы изменились')
  })

  it('rejects a missing or ambiguous database row', () => {
    for (const tree of [[schema()], [database(), database(), schema()]]) {
      expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), tree)).toThrow('Данные выбранной базы изменились')
    }
  })

  it.each([
    { schemas: [] }, { schemas: [schema('public', { status: 'missing' })] },
    { schemas: [schema('pg_catalog')] }, { schemas: [schema('grantor')] },
    { schemas: [schema('public', { parent_id: 'other-db' })] },
  ])('does not invent a scope when there are no user schemas %#', ({ schemas }) => {
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(), schemas)))
      .toThrow('нет обнаруженных пользовательских схем')
  })

  it.each(['', 'bad-schema', 'bad schema', ' public ', '3schema', 'схема', 's'.repeat(64)])(
    'rejects unsupported observed user schemas: %#', (name) => {
      expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(), [schema(name)])))
        .toThrow('Список схем базы неоднозначен')
    },
  )

  it('rejects schemas from a different connection even with the same parent ID', () => {
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(), [
      schema(), schema('foreign', { connection_id: 'other-connection' }),
    ]))).toThrow('Схемы базы относятся к другому подключению')
  })

  it.each([
    { schemas: [schema(), schema('public', { id: 'different-schema-id' })] },
    { schemas: [schema(), schema('reports', { id: 'schema-public' })] },
    { schemas: [schema('public', { id: '' })] },
  ])('fails closed for ambiguous schema inventory %#', ({ schemas }) => {
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(), schemas)))
      .toThrow('Список схем базы неоднозначен')
  })

  it('enforces the existing schema count limit instead of dropping scopes', () => {
    const scopes = Array.from({ length: 65 }, (_, index) => schema(`schema_${index}`))
    expect(() => postgresBasicRoleDrafts(CONNECTION_ID, database(), inventory(database(), scopes)))
      .toThrow('от 1 до 64 идентификаторов')
  })

  it('does not mutate the discovered database or tree', () => {
    const db = database()
    const tree = inventory(db, [schema('zebra'), schema('public'), schema('alpha')])
    const before = structuredClone({ db, tree })
    Object.freeze(db.attributes)
    Object.freeze(db)
    tree.forEach(Object.freeze)
    Object.freeze(tree)

    postgresBasicRoleDrafts(CONNECTION_ID, db, tree)
    expect({ db, tree }).toEqual(before)
  })
})

describe('merging basic PostgreSQL role drafts', () => {
  it('appends the pair to an existing catalog without changing entries or their ordering', () => {
    const existing = [otherTemplate(2), otherTemplate(1)]
    const drafts = pair()
    const result = mergePostgresBasicRoleDrafts(existing, drafts)
    expect(result).toEqual({ templates: [...existing, ...drafts], selected: drafts, changed: true })
    expect(result.templates[0]).toBe(existing[0])
    expect(result.templates[1]).toBe(existing[1])
    expect(result.templates).not.toBe(existing)
  })

  it('reuses exact roles with different published keys, names, descriptions and set order', () => {
    const drafts = pair().map((template) => ({ ...template, schemas: ['events', 'public'] }))
    const existing = drafts.map((template, index) => ({
      ...template, key: `published-${index}`, name: `Published ${index}`, description: 'Do not rewrite this',
      schemas: ['public', 'events'], extra_metadata: { retained: true },
    })).reverse()
    const result = mergePostgresBasicRoleDrafts(existing, drafts)
    expect(result).toEqual({ templates: existing, selected: [existing[1], existing[0]], changed: false })
    expect(JSON.stringify(result.templates)).toBe(JSON.stringify(existing))
    expect(result.selected[0]).toBe(existing[1])
  })

  it.each([0, 1])('adds only the missing half of a previously saved pair %#', (existingIndex) => {
    const drafts = pair()
    const existing = [{ ...drafts[existingIndex], key: 'already-published', name: 'Already published' }]
    const result = mergePostgresBasicRoleDrafts(existing, drafts)
    expect(result.templates).toEqual([existing[0], drafts[1 - existingIndex]])
    expect(result.selected.map((template) => template.role_name)).toEqual(['r_appdb', 'rw_appdb'])
    expect(result.selected[existingIndex]).toBe(existing[0])
    expect(result.changed).toBe(true)
  })

  it.each([
    { database: 'other_database' }, { profile: 'read_write' as const }, { schemas: ['reports'] },
    { schemas: ['public', 'events'] }, { owner_roles: ['another_owner'] }, { creator_roles: ['migration_user'] },
  ])('rejects an existing role with a different technical specification %#', (change) => {
    const drafts = pair()
    const existing = [{ ...drafts[0], ...change }]
    expect(() => mergePostgresBasicRoleDrafts(existing, drafts)).toThrow('другими правами или областью доступа')
  })

  it('does not treat a differently named role as the requested basic role', () => {
    const drafts = pair()
    const existing = [{ ...drafts[0], role_name: 'custom_reader', key: 'custom-reader', name: 'Custom reader' }]
    expect(mergePostgresBasicRoleDrafts(existing, drafts)).toEqual({
      templates: [...existing, ...drafts], selected: drafts, changed: true,
    })
  })

  it.each(['key', 'name'] as const)('rejects a generated %s already used by a different role', (field) => {
    const drafts = pair()
    const existing = [{ ...otherTemplate(), [field]: drafts[0][field] }]
    expect(() => mergePostgresBasicRoleDrafts(existing, drafts)).toThrow('Ключ или название базового шаблона уже заняты')
  })

  it('does not rename an exact published role when the unused generated key is occupied', () => {
    const drafts = pair()
    const existing = [
      { ...drafts[0], key: 'reader-published', name: 'Published reader' },
      { ...otherTemplate(), key: drafts[0].key },
    ]
    const result = mergePostgresBasicRoleDrafts(existing, drafts)
    expect(result.templates).toEqual([...existing, drafts[1]])
    expect(result.selected[0].key).toBe('reader-published')
  })

  it('detects generated metadata collisions across case-sensitive database identities', () => {
    const lower = pair()
    const upperDB = database({ name: 'Appdb' })
    const upper = postgresBasicRoleDrafts(CONNECTION_ID, upperDB, inventory(upperDB))
    expect(upper[0].role_name).toBe('r_Appdb')
    expect(() => mergePostgresBasicRoleDrafts(lower, upper)).toThrow('Ключ или название базового шаблона уже заняты')
  })

  it('detects metadata truncation collisions without changing physical role names', () => {
    const prefix = 'd'.repeat(48)
    const firstDB = database({ name: `${prefix}_first` })
    const secondDB = database({ name: `${prefix}_second` })
    const first = postgresBasicRoleDrafts(CONNECTION_ID, firstDB, inventory(firstDB))
    const second = postgresBasicRoleDrafts(CONNECTION_ID, secondDB, inventory(secondDB))
    expect(second[1].role_name).toBe(`rw_${prefix}_second`)
    expect(() => mergePostgresBasicRoleDrafts(first, second)).toThrow('Ключ или название базового шаблона уже заняты')
  })

  it('permits exactly 64 catalog entries and rejects additions beyond the limit', () => {
    const existing = Array.from({ length: 62 }, (_, index) => otherTemplate(index))
    const drafts = pair()
    const result = mergePostgresBasicRoleDrafts(existing, drafts)
    expect(result.templates).toHaveLength(64)
    expect(() => mergePostgresBasicRoleDrafts([...existing, otherTemplate(62)], drafts)).toThrow('не более 64')
    expect(() => mergePostgresBasicRoleDrafts([...existing, ...drafts, otherTemplate(62)], [])).toThrow('не более 64')
  })

  it('reuses a full pair at the catalog limit or adds a missing half at 63 entries', () => {
    const unrelated = Array.from({ length: 62 }, (_, index) => otherTemplate(index))
    const drafts = pair()
    const half = mergePostgresBasicRoleDrafts([...unrelated, drafts[0]], drafts)
    expect(half.templates).toHaveLength(64)
    expect(half.changed).toBe(true)
    const full = mergePostgresBasicRoleDrafts(half.templates, drafts)
    expect(full.templates).toHaveLength(64)
    expect(full.changed).toBe(false)
  })

  it('rejects invalid or ambiguous existing catalogs and drafts', () => {
    const drafts = pair()
    expect(() => mergePostgresBasicRoleDrafts([drafts[0], drafts[0]], drafts)).toThrow('повторяется')
    expect(() => mergePostgresBasicRoleDrafts([], [drafts[0], drafts[0]])).toThrow('повторяется')
    expect(() => mergePostgresBasicRoleDrafts([{ ...otherTemplate(), schemas: [] }], drafts)).toThrow('от 1 до 64')
    expect(() => mergePostgresBasicRoleDrafts([], [{ ...drafts[0], description: '' }])).toThrow('обязательное поле')
  })

  it('does not mutate either input when a later draft conflicts', () => {
    const drafts = pair()
    const existing = [{ ...otherTemplate(), key: drafts[1].key }]
    const before = structuredClone({ existing, drafts })
    for (const template of [...existing, ...drafts]) {
      Object.freeze(template.schemas)
      Object.freeze(template.owner_roles)
      Object.freeze(template.creator_roles)
      Object.freeze(template)
    }
    Object.freeze(existing)
    Object.freeze(drafts)

    expect(() => mergePostgresBasicRoleDrafts(existing, drafts)).toThrow('Ключ или название базового шаблона уже заняты')
    expect({ existing, drafts }).toEqual(before)
  })
})
