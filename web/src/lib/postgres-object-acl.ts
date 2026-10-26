import type { Account, Binding, Permission } from './types'

export function objectRecord(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : {}
}

export function bindingManagementEligible(binding: Binding): boolean {
  return objectRecord(binding.observed_attributes).managed_binding_eligible !== false
}

export function objectACLIncomplete(topology: unknown): boolean {
  const scopes = objectRecord(topology).postgres_object_acl_incomplete_scopes
  return Array.isArray(scopes) && scopes.length > 0
}

export function directObjectSummary(count: number, topology: unknown): string {
  if (objectRecord(topology).postgres_object_acl_version !== 1) return 'Нет снимка'
  if (objectACLIncomplete(topology)) return count === 0 ? 'Недостаточно данных' : `${count} объектов · неполно`
  return `${count} объектов`
}

export function isPostgresObjectPrivilege(permission: Permission | undefined): boolean {
  if (permission?.engine !== 'postgres' || permission.normalized.category !== 'privilege') return false
  const attributes = permission.attributes
  return typeof attributes === 'object' && attributes !== null &&
    (attributes as Record<string, unknown>).kind === 'postgres_object_privilege'
}

export function objectPrivilegeBindings(bindings: readonly Binding[], permissions: ReadonlyMap<string, Permission>): Binding[] {
  return bindings.filter(binding => isPostgresObjectPrivilege(permissions.get(binding.permission_definition_id)))
}

export function withoutObjectPrivileges(bindings: readonly Binding[], permissions: ReadonlyMap<string, Permission>): Binding[] {
  return bindings.filter(binding => !isPostgresObjectPrivilege(permissions.get(binding.permission_definition_id)))
}

export function directObjectCount(bindings: readonly Binding[], permissions: ReadonlyMap<string, Permission>): number {
  return new Set(objectPrivilegeBindings(bindings, permissions)
    .filter(binding => binding.observed_state === 'present')
    .map(binding => binding.scope_resource_id ?? binding.permission_definition_id)).size
}

export function accountDirectObjectCount(account: Account, bindings: readonly Binding[], permissions: ReadonlyMap<string, Permission>): number {
  return account.access_summary?.direct_objects ?? directObjectCount(bindings, permissions)
}

export interface ObjectPrivilegeGroup {
  key: string
  resource: string
  scopeId: string
  kind: string
  permissions: Permission[]
  bindings: Binding[]
  owner?: string
  public_privileges?: string[]
}

export function groupObjectPrivileges(permissions: readonly Permission[], bindings: readonly Binding[]): ObjectPrivilegeGroup[] {
  const groups = new Map<string, ObjectPrivilegeGroup>()
  const byPermission = new Map<string, Binding[]>()
  for (const binding of bindings) {
    const existing = byPermission.get(binding.permission_definition_id) ?? []
    existing.push(binding)
    byPermission.set(binding.permission_definition_id, existing)
  }
  for (const permission of permissions) {
    if (!isPostgresObjectPrivilege(permission) || permission.scope_resource_id === null) continue
    if (permission.status === 'missing' && !(byPermission.get(permission.id) ?? []).some(b => b.observed_state === 'present')) continue
    const attrs = permission.attributes as Record<string, unknown>
    const kind = String(attrs.object_kind ?? '')
    const key = `${permission.scope_resource_id}:${permission.normalized.resource}`
    const group = groups.get(key) ?? { key, resource: permission.normalized.resource,
      scopeId: permission.scope_resource_id, kind, permissions: [], bindings: [] }
    group.permissions.push(permission)
    group.bindings.push(...(byPermission.get(permission.id) ?? []))
    groups.set(key, group)
  }
  return [...groups.values()].sort((a, b) => a.resource.localeCompare(b.resource))
}
