import { describe, expect, it } from 'vitest'
import type { Resource } from './types'
import { addPostgresPolicyRole, createPostgresPolicySuggestionResolver, postgresRolePolicySuggestions } from './postgres-role-policy-suggestions'
import type { PostgresPolicySuggestionSnapshot } from './postgres-role-policy-suggestions'

const observedAt = '2026-10-12T09:00:00.123456Z'
function resource(id: string, kind: string, name: string, parent: string | null, owner: string): Resource {
  return {
    id, kind, name, parent_id: parent, connection_id: 'connection-1', external_id: id,
    canonical_path: name, attributes: { owner }, fingerprint: id, observed_at: observedAt,
    status: 'observed', ownership: 'unmanaged', created_at: observedAt, updated_at: observedAt,
  }
}
function snapshot(resources: Resource[]): PostgresPolicySuggestionSnapshot {
  return {
    connection: { id: 'connection-1', engine: 'postgres', status: 'active', last_discovery_at: observedAt, topology: {} },
    resources,
  }
}
function selection(source: PostgresPolicySuggestionSnapshot, database = 'app', schemas = ['public']) {
  return postgresRolePolicySuggestions(source, 'connection-1', database, schemas)
}
const db = resource('db', 'database', 'app', null, 'database_owner')
const schema = resource('public', 'schema', 'public', db.id, 'schema_owner')
const table = resource('table', 'table', 'events', schema.id, 'object_owner')

describe('postgresRolePolicySuggestions', () => {
  it('does not normalize a quoted owner into a different role identity', () => {
    const quoted = { ...schema, attributes: { owner: ' owner ' } }
    const ordinary = { ...table, attributes: { owner: 'owner' } }
    const result = selection(snapshot([db, quoted, ordinary]))
    expect(result.blockers).toHaveLength(1)
    expect(result.candidates).toEqual([])
  })

  it('uses exact connection/database/schema ancestry and never substitutes the database owner', () => {
    const otherDb = resource('db-other', 'database', 'app_archive', null, 'other_db_owner')
    const otherSchema = resource('public-other', 'schema', 'public', otherDb.id, 'other_schema_owner')
    const otherSelectedSchema = resource('private', 'schema', 'private', db.id, 'private_owner')
    const result = selection(snapshot([
      db, schema, table, otherDb, otherSchema, otherSelectedSchema,
      resource('other-table', 'table', 'events', otherSchema.id, 'other_owner'),
      resource('private-table', 'table', 'events', otherSelectedSchema.id, 'private_owner'),
      { ...resource('foreign', 'table', 'events', schema.id, 'foreign_owner'), connection_id: 'connection-2' },
      { ...resource('path-only', 'table', 'events', 'unrelated', 'path_owner'), canonical_path: 'app.public.events' },
    ]))
    expect(result.blockers).toEqual([])
    expect(result.candidates).toEqual([
      { role: 'object_owner', schemaNames: [], objectsBySchema: [{ schema: 'public', count: 1 }] },
      { role: 'schema_owner', schemaNames: ['public'], objectsBySchema: [] },
    ])
  })

  it('groups all supported relation owners, including partitions, without claiming creator facts', () => {
    const objects = ['table', 'partition', 'view', 'materialized_view', 'sequence'].map((kind) =>
      resource(kind, kind, kind, schema.id, 'shared_owner'))
    const result = selection(snapshot([
      db, schema, ...objects,
      resource('index', 'index', 'events_idx', objects[0].id, 'index_owner'),
    ]), 'app', ['public', 'public'])
    expect(result.candidates.find((candidate) => candidate.role === 'shared_owner')).toEqual({
      role: 'shared_owner', schemaNames: [], objectsBySchema: [{ schema: 'public', count: 5 }],
    })
    expect(result.candidates.map((candidate) => candidate.role)).not.toContain('index_owner')
    expect(result.candidates.every((candidate) => !('creator' in candidate))).toBe(true)
  })

  it('reports an empty schema without concluding that future creators do not exist', () => {
    const result = selection(snapshot([db, schema, { ...table, status: 'missing', observed_at: '2026-09-01T00:00:00Z' }]))
    expect(result.emptySchemas).toEqual(['public'])
    expect(result.missingObjectCount).toBe(1)
    expect(result.candidates).toEqual([{ role: 'schema_owner', schemaNames: ['public'], objectsBySchema: [] }])
  })

  it.each([
    ['missing schema', { ...schema, status: 'missing' }, table],
    ['stale schema', { ...schema, observed_at: '2026-10-12T08:00:00Z' }, table],
    ['stale relation', schema, { ...table, status: 'stale' }],
    ['different observation', schema, { ...table, observed_at: '2026-10-12T09:00:00.123457Z' }],
    ['unknown schema owner', { ...schema, attributes: {} }, table],
    ['unknown relation owner', schema, { ...table, attributes: { owner: null } }],
  ])('does not offer a partial list for %s', (_name, selectedSchema, selectedTable) => {
    const result = selection(snapshot([db, selectedSchema as Resource, selectedTable as Resource]))
    expect(result.blockers.length).toBeGreaterThan(0)
    expect(result.candidates).toEqual([])
  })

  it('honors skipped database discovery even if old object rows still exist', () => {
    const source = snapshot([db, schema, table])
    source.connection.topology = { skipped_databases: [{ name: 'app', error: 'unavailable' }] }
    expect(selection(source).blockers.join(' ')).toMatch(/Не удалось проверить объекты/)
    expect(selection(source).candidates).toEqual([])
    source.connection.topology = { skipped_databases: [{ name: 'other', error: 'unavailable' }] }
    expect(selection(source).blockers).toEqual([])
  })

  it.each([
    { id: 'connection-2' }, { engine: 'mysql' }, { status: 'discovering' }, { last_discovery_at: null },
  ])('rejects an unavailable or foreign snapshot %j', (changes) => {
    const source = snapshot([db, schema, table])
    source.connection = { ...source.connection, ...changes }
    expect(selection(source).candidates).toEqual([])
    expect(selection(source).blockers.length).toBeGreaterThan(0)
  })

  it('requires an observed existing database and explicit selected schemas', () => {
    expect(selection(snapshot([db, schema]), '', []).blockers.join(' ')).toMatch(/Укажите/)
    expect(selection(snapshot([db, schema]), 'new_database').blockers.join(' ')).toMatch(/База не обнаружена/)
    expect(selection(snapshot([{ ...db, status: 'planned' }, schema])).candidates).toEqual([])
    expect(selection(snapshot([{ ...db, observed_at: '2026-10-11T09:00:00Z' }, schema])).blockers.join(' ')).toMatch(/устарел/)
    expect(selection(snapshot([db, schema]), 'app', ['not_discovered']).blockers.join(' ')).toMatch(/отсутствует/)
  })
})

describe('snapshot-scoped suggestion resolver', () => {
  it('indexes the inventory once and reuses evidence for normalized equivalent scopes', () => {
    let inventoryReads = 0
    const resources = [db, schema, table].map((item) => new Proxy(item, {
      get(target, property, receiver) {
        if (property === 'connection_id') inventoryReads += 1
        return Reflect.get(target, property, receiver)
      },
    }))
    const source = snapshot(resources)
    const resolve = createPostgresPolicySuggestionResolver(source)
    const first = resolve('connection-1', 'app', ['public'])
    expect(first).toEqual(selection(snapshot([db, schema, table])))
    const firstReads = inventoryReads
    expect(firstReads).toBeGreaterThan(0)
    expect(resolve('connection-1', ' app ', [' public ', 'public'])).toBe(first)
    expect(resolve('connection-1', 'app', ['unobserved']).candidates).toEqual([])
    expect(inventoryReads).toBe(firstReads)
  })

  it('checks current connection and skipped-database admission before serving cached evidence', () => {
    const source = snapshot([db, schema, table])
    const resolve = createPostgresPolicySuggestionResolver(source)
    const first = resolve('connection-1', 'app', ['public'])
    source.connection.status = 'discovering'
    expect(resolve('connection-1', 'app', ['public']).candidates).toEqual([])
    source.connection.status = 'active'
    source.connection.topology = { skipped_databases: [{ name: 'app' }] }
    expect(resolve('connection-1', 'app', ['public']).blockers.join(' ')).toMatch(/Не удалось проверить/)
    source.connection.topology = {}
    expect(resolve('connection-1', 'app', ['public'])).toBe(first)
    expect(resolve('connection-2', 'app', ['public']).blockers.join(' ')).toMatch(/другому подключению/)
  })

  it('invalidates cached ownership and incompleteness when the observation array changes', () => {
    const source = snapshot([db, schema, table])
    const resolve = createPostgresPolicySuggestionResolver(source)
    const first = resolve('connection-1', 'app', ['public'])
    source.resources = [db, schema, { ...table, attributes: { owner: 'replacement_owner' } }]
    const updated = resolve('connection-1', 'app', ['public'])
    expect(updated).not.toBe(first)
    expect(updated.candidates.map((candidate) => candidate.role)).toEqual(['replacement_owner', 'schema_owner'])
    source.resources = [db, schema, { ...table, observed_at: '2026-10-11T09:00:00Z' }]
    const incomplete = resolve('connection-1', 'app', ['public'])
    expect(incomplete.blockers.length).toBeGreaterThan(0)
    expect(incomplete.candidates).toEqual([])
    source.resources = [db, { ...db, id: 'duplicate-db' }, schema, table]
    expect(resolve('connection-1', 'app', ['public']).blockers.join(' ')).toMatch(/однозначно/)
  })

  it('never serves the previous discovery timestamp or another schema scope from cache', () => {
    const empty = resource('empty', 'schema', 'empty', db.id, 'empty_owner')
    const source = snapshot([db, schema, table, empty])
    const resolve = createPostgresPolicySuggestionResolver(source)
    resolve('connection-1', 'app', ['public'])
    expect(resolve('connection-1', 'app', ['empty']).candidates.map((candidate) => candidate.role)).toEqual(['empty_owner'])
    source.connection.last_discovery_at = '2026-10-12T10:00:00Z'
    expect(resolve('connection-1', 'app', ['public']).blockers.join(' ')).toMatch(/устарел/)
    source.resources = source.resources.map((item) => ({ ...item, observed_at: source.connection.last_discovery_at }))
    expect(resolve('connection-1', 'app', ['public']).blockers).toEqual([])
  })
})

describe('addPostgresPolicyRole', () => {
  it('keeps manual values, avoids duplicates and never changes the input', () => {
    const roles = ['manual_owner', ' observed_owner ']
    expect(addPostgresPolicyRole(roles, 'observed_owner')).toEqual(roles)
    expect(addPostgresPolicyRole(roles, 'new_owner')).toEqual([...roles, 'new_owner'])
    expect(roles).toEqual(['manual_owner', ' observed_owner '])
  })
})
