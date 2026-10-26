import { describe, expect, it } from 'vitest'
import type { RoleTemplateCatalog } from './role-template-document'
import {
  roleSnapshotDocument,
  roleTemplateByKey,
  roleTemplateForPermission,
} from './role-template-selection'
import type { Connection, Permission } from './types'

const catalogs: RoleTemplateCatalog[] = [
  {
    engine: 'postgres',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event data',
      role_name: 'r_events', database: 'events', schemas: ['public'],
      owner_roles: ['events_owner'], creator_roles: ['events_migrations'], profile: 'read',
    }],
  },
  {
    engine: 'rabbitmq',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event queues',
      vhost: 'sl-project', configure: '^$', write: '^events_out$',
      read: '^(status_changes|events_out)$', dangerous: false,
    }],
  },
  {
    engine: 'mongodb',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event data',
      role_name: 'eventsReader', role_database: 'admin',
      inherited_roles: [{ role: 'read', db: 'events' }],
      privileges: [{ resource: { db: 'events', collection: 'updates' }, actions: ['find'] }],
    }],
  },
]

const catalogKeys = {
  postgres: 'postgres_role_policy_templates',
  rabbitmq: 'rabbitmq_permission_templates',
  mongodb: 'mongodb_role_policy_templates',
} as const

function connection(catalog: RoleTemplateCatalog): Connection {
  return {
    id: 'connection-1', display_name: 'Role document fixture', engine: catalog.engine,
    environment: 'test', tags: [], endpoints: [], execution_mode: 'direct', tls_config: {},
    admin_credential_mode: 'vault', vault_admin_path: '', capabilities: ['discover'],
    discovery_config: {
      [catalogKeys[catalog.engine]]: catalog.templates,
      unrelated_config: { keep_private: 'not-a-template-field' },
    },
    status: 'active', server_version: '', topology: {}, last_discovery_at: null,
    created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00Z',
  }
}

function identity(catalog: RoleTemplateCatalog): string {
  switch (catalog.engine) {
    case 'postgres': return `role:${catalog.templates[0].role_name}`
    case 'mongodb': return `role:${catalog.templates[0].role_database}.${catalog.templates[0].role_name}`
    case 'rabbitmq': return `rabbitmq-template:${catalog.templates[0].key}`
  }
}

function permission(catalog: RoleTemplateCatalog, overrides: Partial<Permission> = {}): Permission {
  return {
    id: 'permission-1', connection_id: 'connection-1', engine: catalog.engine,
    external_id: identity(catalog), name: 'Observed display name', scope_resource_id: null,
    assignable: true, dangerous: false,
    attributes: {
      [catalog.engine === 'rabbitmq' ? 'template_key' : 'role_policy_key']: catalog.templates[0].key,
    },
    normalized: {
      category: 'role', action: '', resource: '', scope: '', dangerous: false,
      danger_reason: '', details: null, raw: identity(catalog),
    },
    status: 'observed', created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00Z',
    ...overrides,
  }
}

describe('published role template selection', () => {
  it.each(catalogs)('selects only the published $engine template with one matching key', (catalog) => {
    const source = connection(catalog)
    const spec = catalog.templates[0]
    source.discovery_config = {
      [catalogKeys[catalog.engine]]: [
        { ...spec, key: 'another-template', name: 'Other template' }, spec,
      ],
      unrelated_config: { keep_private: 'not-a-template-field' },
    }

    expect(roleTemplateByKey(source, spec.key)).toEqual(catalog)
    expect(roleTemplateByKey(source, 'missing')).toBeNull()
    expect(JSON.stringify(roleTemplateByKey(source, spec.key))).not.toContain('unrelated_config')
  })

  it.each(catalogs)('fails closed for ambiguous duplicate $engine template keys', (catalog) => {
    const source = connection(catalog)
    source.discovery_config = { [catalogKeys[catalog.engine]]: [catalog.templates[0], catalog.templates[0]] }

    expect(roleTemplateByKey(source, catalog.templates[0].key)).toBeNull()
    expect(roleTemplateForPermission(source, permission(catalog))).toBeNull()
  })

  it.each(catalogs)('requires matching connection, engine, key and physical identity for $engine', (catalog) => {
    const source = connection(catalog)
    const observed = permission(catalog)

    expect(roleTemplateForPermission(source, observed)).toEqual(catalog)
    expect(roleTemplateForPermission(source, { ...observed, connection_id: 'other-connection' })).toBeNull()
    expect(roleTemplateForPermission(source, { ...observed, engine: 'redis' })).toBeNull()
    expect(roleTemplateForPermission(source, { ...observed, external_id: `${observed.external_id}-other` })).toBeNull()
    expect(roleTemplateForPermission(source, { ...observed, attributes: {} })).toBeNull()
    expect(roleTemplateForPermission(source, {
      ...observed,
      attributes: { [catalog.engine === 'rabbitmq' ? 'template_key' : 'role_policy_key']: 'unknown' },
    })).toBeNull()
  })

  it('does not infer a template from a role name or a different engine catalog', () => {
    const catalog = catalogs[0]
    const source = connection(catalog)
    const observed = permission(catalog, {
      name: catalog.templates[0].name,
      attributes: { template_key: catalog.templates[0].key },
    })

    expect(roleTemplateForPermission(source, observed)).toBeNull()
    expect(roleTemplateByKey({ ...source, engine: 'mysql' }, catalog.templates[0].key)).toBeNull()
    expect(roleTemplateByKey({ ...source, engine: 'mongodb' }, catalog.templates[0].key)).toBeNull()
  })

  it.each([null, [], 'not-an-object', { role_policy_key: 42 }, { role_policy_key: null }])(
    'does not select from malformed attributes %j',
    (attributes) => {
      const catalog = catalogs[0]
      expect(roleTemplateForPermission(connection(catalog), permission(catalog, { attributes }))).toBeNull()
    },
  )

  it('checks the MongoDB role database as part of physical identity', () => {
    const catalog = catalogs[2]
    const observed = permission(catalog, { external_id: 'role:events.eventsReader' })

    expect(roleTemplateForPermission(connection(catalog), observed)).toBeNull()
  })
})

describe('non-importable role snapshots', () => {
  it('exports only observed PostgreSQL flags, not account/config/attribute payloads', () => {
    const observed = permission(catalogs[0], {
      attributes: {
        superuser: false, createdb: true, createrole: false, replication: false, bypassrls: false,
        can_login: true, role_policy_key: 'events-read', password: 'excluded-field-fixture',
        private_metadata: { token: 'excluded-field-fixture' },
      },
    })

    expect(JSON.parse(roleSnapshotDocument(observed))).toEqual({
      version: 'v1', kind: 'role_snapshot', engine: 'postgres',
      role: {
        external_id: 'role:r_events', name: 'Observed display name', status: 'observed',
        assignable: true, dangerous: false,
        observed: { superuser: false, createdb: true, createrole: false, replication: false, bypassrls: false },
      },
    })
    expect(roleSnapshotDocument(observed)).not.toContain('excluded-field-fixture')
  })

  it('exports only MongoDB public role metadata, without unsupported direct privileges or BSON', () => {
    const observed = permission(catalogs[2], {
      attributes: {
        role_db: 'admin', builtin: false, privileges_observed: true,
        observation_incomplete: false, inherited_roles: ['events.read'],
        direct_privileges: [{ raw: 'excluded-field-fixture' }],
        authenticationRestrictions: [{ raw: 'excluded-field-fixture' }],
        custom_command: { raw: 'excluded-field-fixture' },
      },
    })
    const document = JSON.parse(roleSnapshotDocument(observed))

    expect(document.kind).toBe('role_snapshot')
    expect(document.role.observed).toEqual({
      role_db: 'admin', builtin: false, privileges_observed: true,
      observation_incomplete: false, inherited_roles: ['events.read'],
    })
    expect(roleSnapshotDocument(observed)).not.toContain('excluded-field-fixture')
  })

  it('preserves exact RabbitMQ regex strings but excludes unknown fields', () => {
    const observed = permission(catalogs[1], {
      attributes: {
        kind: 'vhost', vhost: 'sl-project', configure: '^$', write: '^events_out$',
        read: '^(status_changes|events_out)$', tag: 'management', broad: false, broad_configure: false,
        password_hash: 'excluded-field-fixture', arbitrary: ['excluded-field-fixture'],
      },
    })
    const document = JSON.parse(roleSnapshotDocument(observed))

    expect(document.kind).toBe('role_snapshot')
    expect(document.role.observed).toEqual({
      kind: 'vhost', vhost: 'sl-project', configure: '^$', write: '^events_out$',
      read: '^(status_changes|events_out)$', tag: 'management', broad: false, broad_configure: false,
    })
    expect(roleSnapshotDocument(observed)).not.toContain('excluded-field-fixture')
  })

  it('omits whitelisted fields when their actual types are wrong', () => {
    const observed = permission(catalogs[2], {
      attributes: {
        role_db: ['admin'], builtin: 'false', privileges_observed: 1,
        observation_incomplete: null, inherited_roles: ['events.read', { role: 'root' }],
      },
    })

    expect(JSON.parse(roleSnapshotDocument(observed)).role.observed).toEqual({})
  })

  it('does not expose engine attributes for unsupported adapters', () => {
    const observed = permission(catalogs[0], {
      engine: 'mysql', attributes: { superuser: true, role_db: 'admin', arbitrary: 'excluded-field-fixture' },
    })

    expect(JSON.parse(roleSnapshotDocument(observed)).role.observed).toEqual({})
  })
})
