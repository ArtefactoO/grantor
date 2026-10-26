import { describe, expect, it } from 'vitest'
import {
  MONGODB_ROLE_POLICY_ACTIONS,
  mongoDBActionSupportsResource,
  mongoDBResourceKind,
  mongoDBRolePolicyTemplateIssues,
  mongoDBTemplateDangerPreview,
  readMongoDBRolePolicyTemplates,
} from './mongodb-role-policy-templates'

describe('MongoDB role policy template contract', () => {
  it('mirrors the closed backend action allowlist in canonical order', () => {
    expect(MONGODB_ROLE_POLICY_ACTIONS).toHaveLength(116)
    expect(MONGODB_ROLE_POLICY_ACTIONS).toEqual(
      [...MONGODB_ROLE_POLICY_ACTIONS].sort(),
    )
    expect(MONGODB_ROLE_POLICY_ACTIONS).toEqual(expect.arrayContaining([
      'find',
      'killCursors',
      'createRole',
      'replSetConfigure',
      'setFeatureCompatibilityVersion',
      'viewUser',
    ]))
    expect(MONGODB_ROLE_POLICY_ACTIONS).not.toEqual(expect.arrayContaining([
      'anyAction',
      'applyOps',
      'internal',
    ]))
  })

  it('applies the same namespace/cluster compatibility guard as the backend', () => {
    expect(mongoDBActionSupportsResource('find', 'collection')).toBe(true)
    expect(mongoDBActionSupportsResource('find', 'cluster')).toBe(false)
    expect(mongoDBActionSupportsResource('replSetConfigure', 'cluster')).toBe(true)
    expect(mongoDBActionSupportsResource('replSetConfigure', 'database')).toBe(false)
    expect(mongoDBActionSupportsResource('createRole', 'database')).toBe(true)
    expect(mongoDBActionSupportsResource('createRole', 'collection')).toBe(false)
    expect(mongoDBActionSupportsResource('createRole', 'all_databases')).toBe(false)
    expect(mongoDBActionSupportsResource('killAnyCursor', 'collection')).toBe(true)
    expect(mongoDBActionSupportsResource('killAnyCursor', 'collection_across_databases')).toBe(true)
    expect(mongoDBActionSupportsResource('killAnyCursor', 'database')).toBe(false)
    expect(mongoDBActionSupportsResource('planCacheIndexFilter', 'collection')).toBe(true)
    expect(mongoDBActionSupportsResource('planCacheIndexFilter', 'all_databases')).toBe(false)
    expect(mongoDBActionSupportsResource('unknownCommand', 'database')).toBe(false)
    expect(mongoDBActionSupportsResource('find', 'any_resource')).toBe(false)
  })

  it('mirrors the adapter narrowed safe-action set in dangerous preview', () => {
    const base = {
      key: 'reader',
      name: 'Reader',
      description: 'Reader',
      role_name: 'reader',
      role_database: 'appdb',
      inherited_roles: [],
    }
    expect(mongoDBTemplateDangerPreview({
      ...base,
      privileges: [{ resource: { db: 'appdb', collection: 'events' }, actions: ['find'] }],
    })).toEqual([])
    expect(mongoDBTemplateDangerPreview({
      ...base,
      privileges: [{
        resource: { db: 'appdb', collection: 'events' },
        actions: ['bypassDocumentValidation'],
      }],
    })).toContain('Чувствительные действия: bypassDocumentValidation.')
  })

  it('validates backend byte/control rules and nonempty compatible actions', () => {
    const issues = mongoDBRolePolicyTemplateIssues({
      key: 'reader',
      name: 'я'.repeat(65),
      description: 'first\nsecond',
      role_name: 'reader',
      role_database: 'appdb',
      inherited_roles: [],
      privileges: [{ resource: { db: 'appdb', collection: 'events' }, actions: [] }],
    })

    expect(issues).toContain('Название обязательно: без control characters и не более 128 bytes.')
    expect(issues).toContain('Описание обязательно: одна строка без control characters, не более 512 bytes.')
    expect(issues).toContain('Privilege 1: выберите хотя бы один action.')
  })

  it('reads only typed resources and keeps forbidden anyResource observable for repair', () => {
    const [template] = readMongoDBRolePolicyTemplates({
      mongodb_role_policy_templates: [{
        key: 'etl-reader',
        name: 'ETL reader',
        description: 'Read event data',
        role_name: 'etlReader',
        role_database: 'appdb',
        inherited_roles: [{ role: 'read', db: 'appdb' }],
        privileges: [
          { resource: { db: 'appdb', collection: 'events' }, actions: ['find'] },
          { resource: { cluster: true }, actions: ['serverStatus'] },
          { resource: { any_resource: true }, actions: ['find'] },
          { resource: { cluster: true, db: 'smuggled' }, actions: ['serverStatus'] },
          { resource: { raw: { $where: 'forbidden' } }, actions: ['find'] },
        ],
      }],
    })

    expect(template).toEqual(expect.objectContaining({
      role_name: 'etlReader',
      role_database: 'appdb',
      inherited_roles: [{ role: 'read', db: 'appdb' }],
    }))
    expect(template?.privileges).toHaveLength(3)
    expect(template?.privileges.map((privilege) => mongoDBResourceKind(privilege.resource)))
      .toEqual(['collection', 'cluster', 'any_resource'])
  })
})
