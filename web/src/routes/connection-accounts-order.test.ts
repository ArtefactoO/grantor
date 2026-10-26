import { describe, expect, it } from 'vitest'
import type { Account } from '../lib/types'
import {
  accountDisplayCategory,
  accountMatchesDirectorySearch,
  isAccountCategoryBoundary,
  sortAccountsForDisplay,
} from './connection-accounts'

type DisplayAccount = Pick<Account, 'id' | 'kind' | 'principal_id' | 'engine_identity'>

function account(
  id: string,
  kind: string,
  principalId: string | null = null,
): DisplayAccount {
  return {
    id,
    kind,
    principal_id: principalId,
    engine_identity: id,
  }
}

describe('connection account display order', () => {
  const principalTypes = new Map([
    ['human-principal', 'human'],
    ['service-principal', 'service'],
    ['group-principal', 'group'],
  ])

  it('orders logins, service accounts and groups while sorting names inside each category', () => {
    const values = [
      account('z-group', 'group'),
      account('b-login', 'login', 'human-principal'),
      account('a-service', 'login', 'service-principal'),
      account('a-login', 'login'),
      account('b-service', 'service'),
      account('a-group', 'login', 'group-principal'),
    ]

    expect(sortAccountsForDisplay(values, principalTypes).map((item) => item.id)).toEqual([
      'a-login',
      'b-login',
      'a-service',
      'b-service',
      'a-group',
      'z-group',
    ])
  })

  it('recognises category boundaries used by the compact visual separators', () => {
    const login = account('login', 'login')
    const service = account('service', 'login', 'service-principal')
    const group = account('group', 'role')

    expect(accountDisplayCategory(service, principalTypes)).toBe('service')
    expect(isAccountCategoryBoundary(login, service, principalTypes)).toBe(true)
    expect(isAccountCategoryBoundary(service, group, principalTypes)).toBe(true)
    expect(isAccountCategoryBoundary(login, account('second-login', 'login'), principalTypes)).toBe(false)
  })
})

describe('connection account directory search', () => {
  const principalTypes = new Map<string, string>([
    ['principal-human', 'human'],
    ['principal-service', 'service'],
  ])
  const permissions = new Map([
    ['permission-read', {
      id: 'permission-read',
      connection_id: 'connection-1',
      engine: 'postgres',
      external_id: 'role:report_reader',
      name: 'report_reader',
      scope_resource_id: null,
      assignable: true,
      status: 'observed',
      dangerous: false,
      attributes: {},
      created_at: '',
      updated_at: '',
    normalized: {
      category: 'role', action: '', resource: 'report_reader', scope: '',
      dangerous: false, danger_reason: '', details: null, raw: 'report_reader',
    },
    }],
  ])
  const searchableAccount = {
    engine_identity: 'analytics_bot',
    kind: 'login',
    principal_id: 'principal-service',
    bindings: [{
      id: 'binding-1',
      account_id: 'account-1',
      permission_definition_id: 'permission-read',
      scope_resource_id: null,
      source: 'managed',
      desired_state: 'present',
      observed_state: 'present',
      observed_effective: true,
      status: 'active',
      expires_at: null,
      created_at: '',
      updated_at: '',
    }],
  }

  it.each(['analytics', 'service', 'сервис', 'report_reader', 'role:report_reader'])(
    'matches identity, category and role terms: %s',
    (query) => {
      expect(accountMatchesDirectorySearch(
        searchableAccount,
        query,
        principalTypes,
        permissions,
      )).toBe(true)
    },
  )

  it('does not match an unrelated login, group or role', () => {
    expect(accountMatchesDirectorySearch(
      searchableAccount,
      'database_owner',
      principalTypes,
      permissions,
    )).toBe(false)
  })

  it('does not match a role that has already been revoked', () => {
    expect(accountMatchesDirectorySearch(
      {
        ...searchableAccount,
        bindings: [{
          ...searchableAccount.bindings[0],
          desired_state: 'absent',
        }],
      },
      'report_reader',
      principalTypes,
      permissions,
    )).toBe(false)
  })
})
