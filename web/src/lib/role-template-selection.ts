import { readMongoDBRolePolicyTemplates } from './mongodb-role-policy-templates'
import { readPostgresRolePolicyTemplates } from './postgres-role-policy-templates'
import { readRabbitMQPermissionTemplates } from './rabbitmq-permission-templates'
import type { RoleTemplateCatalog } from './role-template-document'
import type { Connection, Permission } from './types'

/** Export the published specification, never a possibly truncated observation. */
export function roleTemplateByKey(connection: Connection, key: string): RoleTemplateCatalog | null {
  let catalog: RoleTemplateCatalog
  switch (connection.engine) {
    case 'postgres': catalog = {
      engine: 'postgres', templates: readPostgresRolePolicyTemplates(connection.discovery_config).filter((t) => t.key === key),
    }; break
    case 'rabbitmq': catalog = {
      engine: 'rabbitmq', templates: readRabbitMQPermissionTemplates(connection.discovery_config).filter((t) => t.key === key),
    }; break
    case 'mongodb': catalog = {
      engine: 'mongodb', templates: readMongoDBRolePolicyTemplates(connection.discovery_config).filter((t) => t.key === key),
    }; break
    default: return null
  }
  return catalog.templates.length === 1 ? catalog : null
}

function attributes(permission: Permission): Record<string, unknown> {
  return typeof permission.attributes === 'object' && permission.attributes !== null && !Array.isArray(permission.attributes)
    ? permission.attributes as Record<string, unknown> : {}
}

export function roleTemplateForPermission(connection: Connection, permission: Permission): RoleTemplateCatalog | null {
  if (connection.id !== permission.connection_id || connection.engine !== permission.engine) return null
  const record = attributes(permission)
  const key = connection.engine === 'rabbitmq' ? record.template_key : record.role_policy_key
  if (typeof key !== 'string') return null
  const catalog = roleTemplateByKey(connection, key)
  if (catalog === null) return null
  let identity: string
  switch (catalog.engine) {
    case 'postgres': identity = `role:${catalog.templates[0].role_name}`; break
    case 'mongodb': identity = `role:${catalog.templates[0].role_database}.${catalog.templates[0].role_name}`; break
    case 'rabbitmq': identity = `rabbitmq-template:${catalog.templates[0].key}`; break
  }
  return permission.external_id === identity ? catalog : null
}

/** A discovery snapshot is deliberately a different, non-importable document. */
export function roleSnapshotDocument(permission: Permission): string {
  const raw = attributes(permission)
  const observed: Record<string, string | boolean | string[]> = {}
  const booleanKeys: Record<string, string[]> = {
    postgres: ['superuser', 'createdb', 'createrole', 'replication', 'bypassrls'],
    mongodb: ['builtin', 'privileges_observed', 'observation_incomplete'],
    rabbitmq: ['broad', 'broad_configure'],
  }
  const stringKeys: Record<string, string[]> = {
    mongodb: ['role_db'],
    rabbitmq: ['kind', 'vhost', 'configure', 'write', 'read', 'tag'],
  }
  for (const key of booleanKeys[permission.engine] ?? []) {
    if (typeof raw[key] === 'boolean') observed[key] = raw[key]
  }
  for (const key of stringKeys[permission.engine] ?? []) {
    if (typeof raw[key] === 'string') observed[key] = raw[key]
  }
  if (permission.engine === 'mongodb' && Array.isArray(raw.inherited_roles) &&
    raw.inherited_roles.every((role) => typeof role === 'string')) {
    observed.inherited_roles = raw.inherited_roles
  }
  return JSON.stringify({
    version: 'v1',
    kind: 'role_snapshot',
    engine: permission.engine,
    role: {
      external_id: permission.external_id,
      name: permission.name,
      status: permission.status,
      assignable: permission.assignable,
      dangerous: permission.dangerous,
      observed,
    },
  }, null, 2)
}
