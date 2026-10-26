import { describe, expect, it } from 'vitest'
import type { Account, Permission } from './types'
import {
  accountActions,
  isConnectionAdminAccount,
  sharedRolePermission,
} from './account-actions'

const roleAccount: Pick<Account, 'connection_id' | 'engine_identity' | 'kind'> = {
  connection_id: 'connection-1',
  engine_identity: 'report_reader',
  kind: 'group',
}

function permission(
  id: string,
  overrides: Partial<Permission> = {},
): Permission {
  return {
    id,
    connection_id: 'connection-1',
    engine: 'postgres',
    external_id: 'role:report_reader',
    name: 'report_reader',
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: false,
    attributes: {},
    created_at: '2026-07-23T00:00:00Z',
    updated_at: '2026-07-23T00:00:00Z',
    ...overrides,
    normalized: {
      category: 'role', action: '', resource: 'report_reader', scope: '',
      dangerous: false, danger_reason: '', details: null, raw: 'report_reader',
    },
  }
}

describe('sharedRolePermission', () => {
  it('matches a group account to its assignable permission', () => {
    const expected = permission('permission-1')

    expect(sharedRolePermission(roleAccount, [expected])).toBe(expected)
  })

  it('does not match login accounts or permissions from another connection', () => {
    expect(
      sharedRolePermission({ ...roleAccount, kind: 'login' }, [
        permission('permission-1'),
      ]),
    ).toBeNull()
    expect(
      sharedRolePermission(roleAccount, [
        permission('permission-2', { connection_id: 'connection-2' }),
      ]),
    ).toBeNull()
  })

  it('fails closed when an external role id is ambiguous', () => {
    expect(
      sharedRolePermission(roleAccount, [
        permission('permission-1'),
        permission('permission-2'),
      ]),
    ).toBeNull()
  })
})

// Missing — учётки на target больше нет: adopt/link скрываются (зеркало 409
// бэкенда), пока discovery не увидит её снова.
describe('accountActions for a missing account', () => {
  function unmanagedAccount(status: string): Account {
    return {
      id: 'account-1',
      principal_id: null,
      connection_id: 'connection-1',
      kind: 'login',
      engine_identity: 'ext_user',
      authentication_scope: '',
      credential_mode: null,
      vault_path: '',
      status,
      ownership: 'unmanaged',
      attributes: {},
      created_at: '2026-08-01T00:00:00Z',
      updated_at: '2026-08-01T00:00:00Z',
    }
  }

  it('hides adopt and link when the account is missing from the target', () => {
    const actions = accountActions(unmanagedAccount('missing'), 'operator')
    expect(actions.adopt).toBe(false)
    expect(actions.link).toBe(false)
  })

  it('keeps adopt and link for a live unmanaged account', () => {
    const actions = accountActions(unmanagedAccount('active'), 'operator')
    expect(actions.adopt).toBe(true)
    expect(actions.link).toBe(true)
  })
})

// Служебная учётка подключения (attributes.connection_admin от discovery):
// adopt и link-and-manage отвечают 409, поэтому кнопки не показываются.
describe('accountActions for the connection admin account', () => {
  const adminAccount: Account = {
    id: 'account-admin',
    principal_id: null,
    connection_id: 'connection-1',
    kind: 'login',
    engine_identity: 'grantor',
    authentication_scope: '',
    credential_mode: null,
    vault_path: '',
    status: 'active',
    ownership: 'unmanaged',
    attributes: { connection_admin: true },
    created_at: '2026-08-01T00:00:00Z',
    updated_at: '2026-08-01T00:00:00Z',
  }

  it('recognises the discovery marker', () => {
    expect(isConnectionAdminAccount(adminAccount)).toBe(true)
    expect(isConnectionAdminAccount({ ...adminAccount, attributes: {} })).toBe(false)
    expect(isConnectionAdminAccount({ ...adminAccount, attributes: null })).toBe(false)
  })

  it('hides adopt and link for the connection admin', () => {
    const actions = accountActions(adminAccount, 'operator')
    expect(actions.adopt).toBe(false)
    expect(actions.link).toBe(false)
  })
})

describe('accountActions for a provisioning reservation', () => {
  const pendingAccount: Account = {
    id: 'pending-account',
    principal_id: null,
    connection_id: 'connection-1',
    kind: 'login',
    engine_identity: 'existing_target_user',
    authentication_scope: '',
    credential_mode: 'provided',
    vault_path: 'accounts/pending-account/credential',
    status: 'provisioning',
    ownership: 'managed',
    attributes: {},
    created_at: '2026-08-26T00:00:00Z',
    updated_at: '2026-08-26T00:00:00Z',
  }

  it.each(['login', 'group', 'role'])('blocks all ordinary actions for a %s until recovery', (kind) => {
    for (const role of ['admin', 'operator', 'viewer']) {
      const actions = accountActions({ ...pendingAccount, kind }, role)
      expect(Object.values(actions).filter((value) => typeof value === 'boolean'))
        .not.toContain(true)
      expect(actions.shareReason).toBeUndefined()
    }
  })

  it('keeps existing active account actions unchanged', () => {
    const actions = accountActions({ ...pendingAccount, status: 'active' }, 'admin')
    expect(actions.grant).toBe(true)
    expect(actions.share).toBe(true)
    expect(actions.rotate).toBe(true)
    expect(actions.delete).toBe(true)
    expect(actions.link).toBe(true)
  })
})
