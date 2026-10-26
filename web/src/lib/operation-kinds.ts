// Каталог kind операций для фильтра экрана «Операции» — зеркало констант
// бэкенда (internal/jobs: executor.go, mutations.go), сгруппированное по
// префиксу. Неизвестные kind из данных не ломают фильтр: они добавляются
// в группу «прочие» (см. mergeUnknownKinds).

/** Группа kind в дропдауне фильтра: подпись optgroup + значения. */
export interface OperationKindGroup {
  label: string
  kinds: string[]
}

/** Известные kind по группам; порядок групп — как в сайдбаре смыслов:
 * bulk-оркестрации, затем целевые мутации, затем discovery. */
export const OPERATION_KIND_GROUPS: OperationKindGroup[] = [
  {
    label: 'bulk',
    kinds: [
      'bulk.grant',
      'bulk.account_roles',
      'bulk.object_acl',
      'bulk.principal_access',
      'bulk.principal_rotate',
      'bulk.principal_disable',
      'bulk.principal_enable',
      'bulk.principal_offboard',
      'bulk.manifest_apply',
    ],
  },
  {
    label: 'account',
    kinds: [
      'account.create',
      'postgres.account.create.v2',
      'postgres.account.provision.v1',
      'postgres.account.verify_creation.v1',
      'role.create',
      'postgres.role.create.v2',
      'account.disable',
      'account.enable',
      'account.delete',
      'account.restore',
      'postgres.account.restore.v2',
      'account.adopt_verify',
    ],
  },
  {
    label: 'access',
    kinds: [
      'access.grant',
      'access.revoke',
      'postgres.stats_membership.grant.v1',
      'postgres.stats_membership.revoke.v1',
      'postgres.object_acl.grant.v1',
      'postgres.object_acl.revoke.v1',
      'role.policy.apply',
      'postgres.role.policy.apply.v2',
      'role.policy.create',
      'postgres.role.policy.create.v2',
      'role.policy.create_database',
      'postgres.role.policy.create_database.v2',
      'role.policy.adopt',
      'postgres.role.policy.adopt.v2',
      'role.policy.repair',
      'postgres.role.policy.repair.v2',
    ],
  },
  {
    label: 'resource',
    kinds: [
      'resource.create', 'resource.create.database_with_roles', 'resource.create.prepared_database',
      'postgres.resource.create.database.v2',
      'postgres.resource.create.database_with_roles.v2', 'postgres.resource.create.database_for_roles.v2',
    ],
  },
  {
    label: 'credential',
    kinds: ['credential.rotate'],
  },
  {
    label: 'connection',
    kinds: [
      'connection.discover',
      'connection.admin_credential.switch',
      'connection.admin_credential.rotate',
    ],
  },
]

/**
 * Дополняет каталог групп kind'ами, встреченными в данных, но
 * отсутствующими в статическом каталоге (новый kind бэкенда не должен
 * пропасть из фильтра до обновления UI). Возвращает исходные группы плюс
 * «прочие», если было что добавить.
 */
export function mergeUnknownKinds(observed: Iterable<string>): OperationKindGroup[] {
  const known = new Set<string>()
  for (const group of OPERATION_KIND_GROUPS) {
    for (const kind of group.kinds) {
      known.add(kind)
    }
  }
  const unknown = new Set<string>()
  for (const kind of observed) {
    if (kind !== '' && !known.has(kind)) {
      unknown.add(kind)
    }
  }
  if (unknown.size === 0) {
    return OPERATION_KIND_GROUPS
  }
  return [...OPERATION_KIND_GROUPS, { label: 'прочие', kinds: [...unknown].sort() }]
}
