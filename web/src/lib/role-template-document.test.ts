import { describe, expect, it } from 'vitest'
import { EMPTY_MONGODB_ROLE_POLICY_TEMPLATE } from './mongodb-role-policy-templates'
import { EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE } from './postgres-role-policy-templates'
import { EMPTY_RABBITMQ_PERMISSION_TEMPLATE } from './rabbitmq-permission-templates'
import type { RabbitMQPermissionTemplate } from './rabbitmq-permission-templates'
import type { MongoDBRolePolicyTemplate, PostgresRolePolicyTemplate } from './types'
import {
  MAX_ROLE_TEMPLATE_DOCUMENT_BYTES,
  parseRoleTemplatesDocument,
  roleTemplateCatalogIssues,
  serializeRoleTemplatesDocument,
} from './role-template-document'
import type { RoleTemplateCatalog, RoleTemplateEngine } from './role-template-document'

function postgres(overrides: Partial<PostgresRolePolicyTemplate> = {}): PostgresRolePolicyTemplate {
  return {
    key: 'events-read', name: 'Чтение событий', description: 'Только текущие и будущие события',
    role_name: 'r_events', database: 'events', schemas: ['public', 'reports'],
    owner_roles: ['event_owner'], creator_roles: ['event_writer'], profile: 'read',
    ...overrides,
  }
}

function rabbit(overrides: Partial<RabbitMQPermissionTemplate> = {}): RabbitMQPermissionTemplate {
  return {
    key: 'etl-worker', name: 'ETL worker', description: 'Только очереди ETL',
    vhost: 'sl-project',
    configure: '^(status_changes|project_etl_match_state_updates)$',
    write: '^project_etl_match_state_updates$',
    read: '^(status_changes|project_etl_match_state_updates)$', dangerous: false,
    ...overrides,
  }
}

function mongo(overrides: Partial<MongoDBRolePolicyTemplate> = {}): MongoDBRolePolicyTemplate {
  return {
    key: 'events-read', name: 'Чтение событий', description: 'Только events',
    role_name: 'eventsReader', role_database: 'events',
    inherited_roles: [{ role: 'read', db: 'events' }],
    privileges: [{ resource: { db: 'events', collection: 'events' }, actions: ['find'] }],
    ...overrides,
  }
}

function document(engine: string, templates: unknown, envelope: Record<string, unknown> = {}): string {
  return JSON.stringify({ version: 'v1', kind: 'role_templates', engine, templates, ...envelope })
}

describe('role template document', () => {
  const catalogs: RoleTemplateCatalog[] = [
    { engine: 'postgres', templates: [postgres()] },
    { engine: 'rabbitmq', templates: [rabbit()] },
    { engine: 'mongodb', templates: [mongo()] },
  ]

  it.each(catalogs)('round-trips the complete $engine catalog without normalization', (catalog) => {
    const text = serializeRoleTemplatesDocument(catalog)
    expect(JSON.parse(text)).toEqual({ version: 'v1', kind: 'role_templates', ...catalog })
    expect(parseRoleTemplatesDocument(text, catalog.engine)).toEqual(catalog)
    expect(roleTemplateCatalogIssues(catalog)).toEqual([])
    expect(text.endsWith('\n')).toBe(true)
  })

  it('returns detached arrays and preserves ordering, text and regex escaping exactly', () => {
    const template = rabbit({ configure: '^literal\\(group\\)\\|pipe$', write: '^amq\\.gen-.*$' })
    const parsed = parseRoleTemplatesDocument(serializeRoleTemplatesDocument({
      engine: 'rabbitmq', templates: [template],
    }), 'rabbitmq')
    expect(parsed).toEqual({ engine: 'rabbitmq', templates: [template] })
    expect(parsed.templates[0]).not.toBe(template)
    const pg = postgres({ schemas: ['reports', 'public'], profile: 'read_write' })
    const pgParsed = parseRoleTemplatesDocument(serializeRoleTemplatesDocument({
      engine: 'postgres', templates: [pg],
    }), 'postgres')
    expect(pgParsed).toEqual({ engine: 'postgres', templates: [pg] })
    if (pgParsed.engine !== 'postgres') throw new Error('unexpected engine')
    expect(pgParsed.templates[0].schemas).not.toBe(pg.schemas)
  })

  it.each([
    { engine: 'postgres', templates: [EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE, EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE] },
    { engine: 'rabbitmq', templates: [EMPTY_RABBITMQ_PERMISSION_TEMPLATE, EMPTY_RABBITMQ_PERMISSION_TEMPLATE] },
    { engine: 'mongodb', templates: [EMPTY_MONGODB_ROLE_POLICY_TEMPLATE, EMPTY_MONGODB_ROLE_POLICY_TEMPLATE] },
  ] satisfies RoleTemplateCatalog[])('keeps unfinished $engine drafts across mode changes', (catalog) => {
    expect(parseRoleTemplatesDocument(serializeRoleTemplatesDocument(catalog), catalog.engine)).toEqual(catalog)
    expect(roleTemplateCatalogIssues(catalog).length).toBeGreaterThan(0)
  })

  it.each(['postgres', 'rabbitmq', 'mongodb'] as const)('allows an empty %s catalog for explicit removal', (engine) => {
    expect(parseRoleTemplatesDocument(document(engine, []), engine)).toEqual({ engine, templates: [] })
    expect(roleTemplateCatalogIssues({ engine, templates: [] })).toEqual([])
  })

  it.each([
    null, [], 'plain text',
    { version: 'v1', kind: 'role_templates', engine: 'postgres' },
    { version: 'v1', kind: 'role_templates', engine: 'postgres', templates: null },
    { version: 'v1', kind: 'role_templates', engine: 'postgres', templates: {} },
    { version: 'v1', kind: 'role_templates', engine: 'postgres', templates: [], sql: 'forbidden' },
  ])('rejects malformed envelopes %#', (raw) => {
    expect(() => parseRoleTemplatesDocument(JSON.stringify(raw), 'postgres')).toThrow()
  })

  it.each([
    { version: 'v2' }, { version: 1 }, { kind: 'snapshot' }, { kind: 'access_manifest' },
    { engine: 'mongodb' }, { engine: 'mysql' },
  ])('rejects incompatible envelope %#', (overrides) => {
    expect(() => parseRoleTemplatesDocument(document('postgres', [postgres()], overrides), 'postgres')).toThrow()
  })

  it('fails closed even when the caller supplies an unsupported engine', () => {
    expect(() => parseRoleTemplatesDocument(document('mysql', []), 'mysql' as RoleTemplateEngine))
      .toThrow('поддерживаются только')
  })

  it.each(['postgres', 'rabbitmq', 'mongodb'] as const)('explains a real %s snapshot before checking template-only fields', (engine) => {
    const snapshot = JSON.stringify({
      version: 'v1', kind: 'role_snapshot', engine,
      role: { external_id: 'role:existing_reader', name: 'existing_reader', observed: { superuser: false } },
    })
    expect(() => parseRoleTemplatesDocument(snapshot, engine)).toThrow('Это снимок роли, а не шаблон для создания.')
    try {
      parseRoleTemplatesDocument(snapshot, engine)
    } catch (error) {
      expect((error as Error).message).not.toMatch(/SQL|BSON|неизвестные поля|existing_reader/)
    }
  })

  it('does not expose pasted text or unexpected field names in errors', () => {
    const sensitive = 'do-not-echo-pasted-content'
    for (const text of [
      `{"password":"${sensitive}",`,
      document('postgres', [{ ...postgres(), [sensitive]: 'value' }]),
      document('postgres', [{ ...postgres(), role_name: { password: sensitive } }]),
    ]) {
      let error: unknown
      try { parseRoleTemplatesDocument(text, 'postgres') } catch (caught) { error = caught }
      expect(error).toBeInstanceOf(Error)
      expect((error as Error).message).not.toContain(sensitive)
    }
  })

  it.each([
    { key: 123 }, { description: null }, { schemas: ['public', 1] }, { schemas: 'public' },
    { creator_roles: null }, { profile: 'owner' }, { profile: '' }, { sql: 'GRANT ALL' },
  ])('rejects malformed PostgreSQL fields %#', (overrides) => {
    expect(() => parseRoleTemplatesDocument(document('postgres', [{ ...postgres(), ...overrides }]), 'postgres')).toThrow()
  })

  it('requires all fields, including an explicit dangerous flag', () => {
    const { dangerous: _dangerous, ...withoutDangerous } = rabbit()
    expect(() => parseRoleTemplatesDocument(document('rabbitmq', [withoutDangerous]), 'rabbitmq')).toThrow('обязательные')
    expect(() => parseRoleTemplatesDocument(document('rabbitmq', [{ ...rabbit(), dangerous: 'false' }]), 'rabbitmq')).toThrow('true или false')
  })

  it.each([
    { raw: { $where: 'arbitraryCommand' } }, { cluster: true, db: 'events' },
    { any_resource: true, collection: 'events' }, { cluster: false },
    { any_resource: false }, { db: { $ne: '' } }, { collection: null },
    { anyResource: true },
  ])('rejects raw BSON and mixed MongoDB resources %#', (resource) => {
    expect(() => parseRoleTemplatesDocument(document('mongodb', [{
      ...mongo(), privileges: [{ resource, actions: ['find'] }],
    }]), 'mongodb')).toThrow()
  })

  it.each([
    { inherited_roles: [{ role: 'read', db: 'events', command: {} }] },
    { inherited_roles: [{ role: 1, db: 'events' }] },
    { privileges: [{ resource: { db: 'events' }, actions: [1] }] },
    { privileges: [{ resource: { db: 'events' }, actions: ['find'], command: {} }] },
  ])('rejects malformed nested MongoDB fields %#', (overrides) => {
    expect(() => parseRoleTemplatesDocument(document('mongodb', [{ ...mongo(), ...overrides }]), 'mongodb')).toThrow()
  })

  it('preserves each typed MongoDB resource shape without inventing missing namespace fields', () => {
    const template = mongo({ role_database: 'admin', privileges: [
      { resource: {}, actions: ['find'] },
      { resource: { db: 'events' }, actions: ['find'] },
      { resource: { cluster: true }, actions: ['serverStatus'] },
      { resource: { any_resource: true }, actions: ['find'] },
    ] })
    const catalog: RoleTemplateCatalog = { engine: 'mongodb', templates: [template] }
    expect(parseRoleTemplatesDocument(serializeRoleTemplatesDocument(catalog), 'mongodb')).toEqual(catalog)
    expect(roleTemplateCatalogIssues(catalog).join(' ')).toContain('anyResource запрещён')
  })

  it('does not serialize unexpected DTO fields', () => {
    expect(() => serializeRoleTemplatesDocument({
      engine: 'postgres', templates: [{ ...postgres(), password: 'not-a-policy-field' } as PostgresRolePolicyTemplate],
    })).toThrow('неизвестные поля')
  })

  it('enforces UTF-8 bytes, not only JavaScript character count', () => {
    expect(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES).toBe(1 << 20)
    const multibyte = document('postgres', [], { note: 'я'.repeat(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES / 2) })
    expect(multibyte.length).toBeLessThan(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES)
    expect(() => parseRoleTemplatesDocument(multibyte, 'postgres')).toThrow('1 MiB')
    expect(() => parseRoleTemplatesDocument(' '.repeat(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES + 1), 'postgres')).toThrow('1 MiB')
  })

  it('exports large valid catalogs compactly so its own parser can import them again', () => {
    const catalog: RoleTemplateCatalog = {
      engine: 'mongodb',
      templates: Array.from({ length: 64 }, (_, index) => mongo({
        key: `reader-${index}`, name: `Reader ${index}`, role_name: `eventsReader_${index}`,
        privileges: Array.from({ length: 128 }, (_, privilegeIndex) => ({
          resource: { db: 'events', collection: `event_${privilegeIndex}` }, actions: ['find'],
        })),
      })),
    }
    const payload = { version: 'v1', kind: 'role_templates', ...catalog }
    expect(new TextEncoder().encode(JSON.stringify(payload, null, 2)).length)
      .toBeGreaterThan(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES)
    expect(new TextEncoder().encode(JSON.stringify(payload)).length)
      .toBeLessThan(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES)
    expect(roleTemplateCatalogIssues(catalog)).toEqual([])
    const serialized = serializeRoleTemplatesDocument(catalog)
    expect(serialized).toBe(`${JSON.stringify(payload)}\n`)
    expect(new TextEncoder().encode(serialized).length).toBeLessThanOrEqual(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES)
    expect(parseRoleTemplatesDocument(serialized, 'mongodb')).toEqual(catalog)
  })

  it('rejects exports that exceed the byte ceiling even in compact form', () => {
    expect(() => serializeRoleTemplatesDocument({
      engine: 'postgres', templates: [postgres({ description: 'я'.repeat(MAX_ROLE_TEMPLATE_DOCUMENT_BYTES / 2) })],
    })).toThrow('Документ слишком большой: максимум 1 MiB.')
  })

  it('bounds all nested arrays before decoding them', () => {
    expect(() => parseRoleTemplatesDocument(document('postgres', Array(65).fill(postgres())), 'postgres')).toThrow('максимум 64')
    expect(() => parseRoleTemplatesDocument(document('postgres', [postgres({ schemas: Array(65).fill('public') })]), 'postgres')).toThrow('максимум 64')
    expect(() => parseRoleTemplatesDocument(document('mongodb', [mongo({ inherited_roles: Array(65).fill({ role: 'read', db: 'events' }) })]), 'mongodb')).toThrow('максимум 64')
    expect(() => parseRoleTemplatesDocument(document('mongodb', [mongo({ privileges: Array(129).fill({ resource: {}, actions: ['find'] }) })]), 'mongodb')).toThrow('максимум 128')
    expect(() => parseRoleTemplatesDocument(document('mongodb', [mongo({ privileges: [{ resource: {}, actions: Array(129).fill('find') }] })]), 'mongodb')).toThrow('максимум 128')
  })

  it('rejects duplicate keys, display names and physical roles in both modes', () => {
    const duplicateCatalogs: RoleTemplateCatalog[] = [
      { engine: 'postgres', templates: [postgres(), postgres({ name: 'Other', role_name: 'other' })] },
      { engine: 'postgres', templates: [postgres(), postgres({ key: 'other', role_name: 'other' })] },
      { engine: 'postgres', templates: [postgres(), postgres({ key: 'other', name: 'Other', database: 'another_db' })] },
      { engine: 'rabbitmq', templates: [rabbit(), rabbit({ key: 'other', name: 'Other' })] },
      { engine: 'mongodb', templates: [mongo(), mongo({ key: 'other', name: 'Other' })] },
    ]
    for (const catalog of duplicateCatalogs) {
      expect(() => parseRoleTemplatesDocument(document(catalog.engine, catalog.templates), catalog.engine)).toThrow(/повторяется|уже представлен/)
      expect(roleTemplateCatalogIssues(catalog).join(' ')).toMatch(/повторяется|уже представлен/)
    }
  })

  it('permits different exact RabbitMQ templates on one vhost and MongoDB names in different databases', () => {
    const rabbitCatalog: RoleTemplateCatalog = { engine: 'rabbitmq', templates: [rabbit(), rabbit({ key: 'other', name: 'Other', read: '^other$' })] }
    const mongoCatalog: RoleTemplateCatalog = { engine: 'mongodb', templates: [mongo(), mongo({
      key: 'other', name: 'Other', role_database: 'another',
      inherited_roles: [{ role: 'read', db: 'another' }], privileges: [],
    })] }
    for (const catalog of [rabbitCatalog, mongoCatalog]) {
      expect(parseRoleTemplatesDocument(serializeRoleTemplatesDocument(catalog), catalog.engine)).toEqual(catalog)
      expect(roleTemplateCatalogIssues(catalog)).toEqual([])
    }
  })
})

describe('shared role template semantic validation', () => {
  it.each([
    { role_name: 'pg_reader' }, { role_name: 'PG_READER' }, { role_name: 'r_имя' },
    { database: 'bad-name' }, { schemas: [] }, { owner_roles: [] }, { creator_roles: [] },
    { schemas: ['Public', 'Public'] }, { schemas: ['pg_catalog'] },
    { schemas: ['information_schema'] }, { schemas: ['Grantor'] },
    { owner_roles: ['r_events'] }, { creator_roles: ['r_events'] },
    { name: ' name ' }, { name: 'я'.repeat(65) }, { description: '' },
    { description: 'я'.repeat(257) },
  ])('mirrors PostgreSQL identifiers, reserved names and byte limits %#', (overrides) => {
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: [postgres(overrides)] }).length).toBeGreaterThan(0)
  })

  it('accepts PostgreSQL multiline descriptions without modifying them', () => {
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: [postgres({ description: 'Current objects\nand future defaults' })] })).toEqual([])
  })

  it.each([
    '.*', '^$', '^queue$', '^queue/name:status-v1$', '^amq\\.gen-.*$',
    '^literal\\(group\\)\\|pipe$', '^literal\\)$', '^\\.\\*$',
    '^(status_changes|project_etl_match_state_updates)$',
    '^(foo|amq\\.gen-.*|bar/baz:qux)$', '^(.*)$',
  ])('accepts the RabbitMQ backend safe subset: %s', (expression) => {
    expect(roleTemplateCatalogIssues({ engine: 'rabbitmq', templates: [rabbit({ read: expression })] })).toEqual([])
  })

  it.each([
    'queue', '^queue', 'queue$', '^foo|bar$', '^(foo|)$', '^(|foo)$',
    '^(foo||bar)$', '^[a-z]+$', '^foo+$', '^foo?$', '^foo{1,3}$', '^(foo)$',
    '^((foo|bar))$', '^(?=foo)foo$', '^(foo)\\1$', '^foo\\$',
    '^(a+)+$', '^(a|aa)+$', '^(.*)*$', '^пример$',
  ])('rejects outside the RabbitMQ backend safe subset without executing it: %s', (expression) => {
    const catalog: RoleTemplateCatalog = { engine: 'rabbitmq', templates: [rabbit({ read: expression })] }
    // Even an invalid expression remains exact when switching editors.
    expect(parseRoleTemplatesDocument(serializeRoleTemplatesDocument(catalog), 'rabbitmq')).toEqual(catalog)
    expect(roleTemplateCatalogIssues(catalog).join(' ')).toContain('ASCII-литералами')
  })

  it.each([
    ['.*', '.*', '.*'], ['^.*$', '^(.*)$', '.*'],
    ['^(queue|.*)$', '^.*.*$', '^(.*|exchange)$'],
  ])('keeps legacy full access separate for every unrestricted spelling %#', (configure, write, read) => {
    expect(roleTemplateCatalogIssues({ engine: 'rabbitmq', templates: [rabbit({ configure, write, read })] }).join(' ')).toContain('legacy vhost-access')
  })

  it('enforces RabbitMQ text/regex limits without trimming valid vhost names', () => {
    expect(roleTemplateCatalogIssues({ engine: 'rabbitmq', templates: [rabbit({ vhost: ' /with spaces ' })] })).toEqual([])
    for (const template of [rabbit({ vhost: 'я'.repeat(128) }), rabbit({ configure: `^${'a'.repeat(511)}$` }), rabbit({ name: '' })]) {
      expect(roleTemplateCatalogIssues({ engine: 'rabbitmq', templates: [template] }).length).toBeGreaterThan(0)
    }
  })

  it.each([
    { role_name: 'read' }, { role_name: 'root' },
    { inherited_roles: [{ role: 'root', db: 'events' }] },
    { inherited_roles: [{ role: 'unmanaged', db: 'events' }] },
    { inherited_roles: [{ role: 'eventsReader', db: 'events' }] },
    { inherited_roles: [{ role: 'read', db: 'another' }] },
    { privileges: [{ resource: { cluster: true as const }, actions: ['find'] }] },
    { privileges: [{ resource: { db: 'events', collection: 'events' }, actions: ['createRole'] }] },
  ])('enforces MongoDB policy scope and catalog dependencies %#', (overrides) => {
    expect(roleTemplateCatalogIssues({ engine: 'mongodb', templates: [mongo(overrides)] }).length).toBeGreaterThan(0)
  })

  it('detects indirect MongoDB inheritance cycles and permits acyclic dependencies', () => {
    const a = mongo({ inherited_roles: [{ role: 'otherReader', db: 'events' }] })
    const b = mongo({ key: 'other', name: 'Other', role_name: 'otherReader' })
    expect(roleTemplateCatalogIssues({ engine: 'mongodb', templates: [a, b] })).toEqual([])
    b.inherited_roles = [{ role: a.role_name, db: 'events' }]
    expect(roleTemplateCatalogIssues({ engine: 'mongodb', templates: [a, b] }).join(' ')).toContain('цикл наследования')
  })

  it('rejects unknown MongoDB actions without repeating pasted action text', () => {
    const issues = roleTemplateCatalogIssues({ engine: 'mongodb', templates: [mongo({
      privileges: [{ resource: { db: 'events', collection: '' }, actions: ['secret-like-pasted-text'] }],
    })] })
    expect(issues.join(' ')).toContain('неподдерживаемые actions')
    expect(issues.join(' ')).not.toContain('secret-like-pasted-text')
  })

  it('enforces form-side bounds even when no text parser was used', () => {
    expect(roleTemplateCatalogIssues({ engine: 'postgres', templates: Array(65).fill(postgres()) })).toEqual(['В каталоге может быть не более 64 шаблонов.'])
    expect(roleTemplateCatalogIssues({ engine: 'mongodb', templates: [mongo({
      privileges: [{ resource: { db: 'events', collection: '' }, actions: Array(129).fill('find') }],
    })] }).join(' ')).toContain('максимум 128 actions')
  })
})
