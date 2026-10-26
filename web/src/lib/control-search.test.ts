import { describe, expect, it } from 'vitest'
import {
  CONTROL_TABS,
  DEFAULT_CONTROL_TAB,
  auditMatchesQuery,
  controlFilterForTab,
  controlTabsForRole,
  findingLinkTarget,
  groupFindings,
  findingMatchesFilter,
  findingMatchesQuery,
  legacyControlSearch,
  operationMatchesFilter,
  operationMatchesQuery,
  validateControlSearch,
} from './control-search'
import type { Operation } from './types'

const operation = (status: string) => ({ status } as Operation)

describe('control search', () => {
  it('puts operations first and uses it as the default tab', () => {
    expect(DEFAULT_CONTROL_TAB).toBe('operations')
    expect(CONTROL_TABS.map(([tab]) => tab)).toEqual([
      'operations',
      'attention',
      'findings',
      'connectors',
      'environments',
    ])
    expect(controlTabsForRole(false).map(([tab]) => tab)).not.toContain('environments')
    expect(controlTabsForRole(true).map(([tab]) => tab)).toContain('environments')
  })

  it('keeps only supported URL filters', () => {
    expect(validateControlSearch({ connection: ' c-1 ', tab: 'operations', status: 'errors', query: ' fail ', operation: ' op-1 ' }))
      .toEqual({ connection: 'c-1', tab: 'operations', status: 'errors', query: 'fail', operation: 'op-1' })
    // Аудит слился с операциями: старая закладка ведёт в «Журнал» с фильтром
    // «События», а не в несуществующую вкладку.
    expect(validateControlSearch({ tab: 'audit', status: 'errors' }))
      .toEqual({ tab: 'operations', status: 'events' })
    expect(validateControlSearch({ tab: 'unknown', status: 4 })).toEqual({})
    expect(validateControlSearch({ tab: 'findings', status: 'resources' }))
      .toEqual({ tab: 'findings', status: 'resources' })
    expect(validateControlSearch({ tab: 'environments' }))
      .toEqual({ tab: 'environments' })
  })

  it('normalizes one URL filter against the active tab', () => {
    expect(controlFilterForTab('attention', 'drift')).toBe('all')
    expect(controlFilterForTab('operations', 'drift')).toBe('all')
    expect(controlFilterForTab('operations', 'events')).toBe('events')
    expect(controlFilterForTab('findings', 'resources')).toBe('resources')
    expect(controlFilterForTab('environments', 'errors')).toBe('all')
  })

  it('maps legacy routes without losing connection scope', () => {
    expect(legacyControlSearch({ connection: 'c-1' }, 'operations', 'approval'))
      .toEqual({ connection: 'c-1', tab: 'operations', status: 'approval' })
  })

  it('uses stable status groups', () => {
    expect(operationMatchesFilter(operation('pending_approval'), 'active')).toBe(true)
    expect(operationMatchesFilter(operation('failed'), 'errors')).toBe(true)
    expect(operationMatchesFilter(operation('done'), 'all')).toBe(true)
    expect(operationMatchesFilter(operation('running'), 'approval')).toBe(false)
    expect(operationMatchesFilter({ status: 'failed', resolved_at: '2026-07-22T12:00:00Z' } as Operation, 'errors')).toBe(false)
    expect(operationMatchesFilter({ status: 'failed', resolved_at: '2026-07-22T12:00:00Z' } as Operation, 'all')).toBe(true)
  })

  it('searches the same localized labels that are visible in Control', () => {
    const visibleOperation = {
      id: 'op-1',
      kind: 'access.grant',
      status: 'pending_approval',
      actor_id: 'operator',
      connection_id: 'connection-1',
      error: null,
    } as unknown as Operation

    expect(operationMatchesQuery(visibleOperation, 'Выдача доступа')).toBe(true)
    expect(operationMatchesQuery(visibleOperation, 'Approval')).toBe(true)
    expect(findingMatchesQuery({ kind: 'missing_resource' } as never, 'Ресурс не найден')).toBe(true)
    expect(auditMatchesQuery({ action: 'account.deleted', result: 'success' } as never, 'Аккаунт удалён')).toBe(true)
    expect(auditMatchesQuery({ action: 'account.deleted', result: 'success' } as never, 'Success')).toBe(true)
  })

  // Manual отделяет действия людей от системных: rediscovery и maintenance
  // ставятся сервисным актором и при фильтре прячутся.
  it('keeps only human-started operations under the manual filter', () => {
    expect(operationMatchesFilter({ actor_type: 'user', status: 'success' } as never, 'manual')).toBe(true)
    expect(operationMatchesFilter({ actor_type: 'service', status: 'success' } as never, 'manual')).toBe(false)
    expect(operationMatchesFilter({ actor_type: 'system', status: 'success' } as never, 'manual')).toBe(false)
  })

  it('applies contextual filters without changing tabs', () => {
    expect(findingMatchesFilter({ kind: 'binding_drift' } as never, 'access')).toBe(true)
    expect(findingMatchesFilter({ kind: 'missing_resource' } as never, 'access')).toBe(false)
    expect(findingMatchesFilter({ kind: 'missing_resource' } as never, 'resources')).toBe(true)
  })

  // Группировка сохраняет порядок первого появления и не смешивает виды и
  // подключения между собой.
  it('groups findings by kind and connection', () => {
    const finding = (kind: string, connection: string, identity: string) =>
      ({ kind, connection_id: connection, account_identity: identity, detail: '' }) as never
    const groups = groupFindings([
      finding('unmanaged_binding', 'conn-1', 'a'),
      finding('missing_resource', 'conn-1', 'b'),
      finding('unmanaged_binding', 'conn-1', 'c'),
      finding('unmanaged_binding', 'conn-2', 'd'),
    ])
    expect(groups.map((group) => [group.kind, group.connectionId, group.items.length])).toEqual([
      ['unmanaged_binding', 'conn-1', 2],
      ['missing_resource', 'conn-1', 1],
      ['unmanaged_binding', 'conn-2', 1],
    ])
  })

  // Deep-link находки: аккаунт приоритетнее ресурса, без обоих — просто
  // подключение.
  it('builds the deep-link target for a finding', () => {
    const base = { kind: 'unmanaged_binding', connection_id: 'conn-1', detail: '' }
    expect(findingLinkTarget({ ...base, account_id: 'acc-1', resource_id: 'res-1' })).toEqual({
      connectionId: 'conn-1',
      search: { tab: 'accounts', account: 'acc-1' },
    })
    expect(findingLinkTarget({ ...base, resource_id: 'res-1' })).toEqual({
      connectionId: 'conn-1',
      search: { tab: 'resources', resource: 'res-1' },
    })
    expect(findingLinkTarget(base)).toEqual({ connectionId: 'conn-1', search: {} })
    // Пустые строки от бэкенда равны отсутствию ссылки.
    expect(findingLinkTarget({ ...base, account_id: '' }).search).toEqual({})
  })
})
