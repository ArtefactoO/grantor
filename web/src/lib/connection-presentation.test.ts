import { describe, expect, it } from 'vitest'
import type { Connection } from './types'
import {
  connectionEngineLabel,
  connectionListFilterCounts,
  connectionMatchesFacets,
  connectionMatchesListFilter,
  connectionMatchesSearch,
  formatCompactRelative,
  groupConnectionsByEnvironment,
  shortServerVersion,
} from './connection-presentation'

function connection(
  id: string,
  displayName: string,
  environment: string,
  status = 'active',
  unmanaged = 0,
): Connection {
  return {
    id,
    display_name: displayName,
    engine: 'postgres',
    environment,
    tags: id === 'tagged' ? ['critical'] : [],
    endpoints: [],
    execution_mode: 'direct',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: '',
    capabilities: [],
    discovery_config: {},
    status,
    server_version: '',
    topology: {},
    last_discovery_at: null,
    created_at: '',
    updated_at: '',
    drift: { unmanaged_bindings: unmanaged, drift_bindings: 0, missing_managed_resources: 0 },
  }
}

describe('connection presentation', () => {
  it('uses the shared product name for a known engine and preserves unknown engines', () => {
    expect(connectionEngineLabel('postgres')).toBe('PostgreSQL')
    expect(connectionEngineLabel('future-db')).toBe('future-db')
  })

  it('maps lifecycle statuses to the approved synced/error filters and counts', () => {
    const syncedWithDrift = connection('active', 'Active', 'prod', 'active', 2)
    const failed = connection('failed', 'Failed', 'prod', 'discovery_failed')
    const discovering = connection('syncing', 'Syncing', 'prod', 'discovering')

    expect(connectionMatchesListFilter(syncedWithDrift, 'synced')).toBe(true)
    expect(connectionMatchesListFilter(failed, 'error')).toBe(true)
    expect(connectionMatchesListFilter(discovering, 'synced')).toBe(false)
    expect(connectionMatchesListFilter(discovering, 'error')).toBe(false)
    expect(connectionListFilterCounts([syncedWithDrift, failed, discovering])).toEqual({
      all: 3,
      synced: 1,
      error: 1,
    })
  })
  it('groups known aliases in operational order and leaves an empty environment last', () => {
    const groups = groupConnectionsByEnvironment([
      connection('empty', 'empty', ''),
      connection('dev', 'dev', 'development'),
      connection('test', 'test', 'test'),
      connection('prod', 'prod', 'production'),
      connection('stage', 'stage', 'stage'),
    ])
    expect(groups.map((group) => group.label)).toEqual([
      'PROD',
      'STAGE',
      'TEST',
      'DEV',
      'БЕЗ ОКРУЖЕНИЯ',
    ])
  })

  it('sorts attention first and then by display name inside a group', () => {
    const [group] = groupConnectionsByEnvironment([
      connection('z', 'Zulu', 'prod'),
      connection('b', 'Beta', 'prod', 'active', 1),
      connection('a', 'Alpha', 'prod', 'degraded'),
    ])
    expect(group.connections.map((item) => item.display_name)).toEqual([
      'Alpha',
      'Beta',
      'Zulu',
    ])
  })

  it('searches factual connection metadata', () => {
    const item = connection('tagged', 'Billing primary', 'prod')
    expect(connectionMatchesSearch(item, 'billing')).toBe(true)
    expect(connectionMatchesSearch(item, 'postgres')).toBe(true)
    expect(connectionMatchesSearch(item, 'critical')).toBe(true)
    expect(connectionMatchesSearch(item, 'rabbit')).toBe(false)
  })

  it('combines normalized environment and engine facets independently', () => {
    const item = connection('prod', 'Billing primary', 'production')
    expect(connectionMatchesFacets(item, 'PROD', 'postgres')).toBe(true)
    expect(connectionMatchesFacets(item, 'TEST', 'postgres')).toBe(false)
    expect(connectionMatchesFacets(item, 'PROD', 'redis')).toBe(false)
    expect(connectionMatchesFacets(item, null, null)).toBe(true)
  })

  it('formats the compact snapshot age without redundant suffixes', () => {
    const now = Date.parse('2026-07-20T12:00:00Z')
    expect(formatCompactRelative('2026-07-20T11:59:45Z', now)).toBe('сейчас')
    expect(formatCompactRelative('2026-07-20T11:55:00Z', now)).toBe('5 мин')
    expect(formatCompactRelative('2026-07-20T10:00:00Z', now)).toBe('2 ч')
    expect(formatCompactRelative('2026-07-17T12:00:00Z', now)).toBe('3 д')
    expect(formatCompactRelative(null, now)).toBe('—')
  })
})

// Подпись версии живёт в плотной строке: PostgreSQL отдаёт номер вместе со
// строкой сборки, и целиком она вытесняет остальное содержимое.
describe('shortServerVersion', () => {
  it('keeps only the version number', () => {
    expect(shortServerVersion('16.14 (Debian 16.14-1.pgdg13+1)')).toBe('16.14')
  })

  it('leaves plain versions untouched', () => {
    expect(shortServerVersion('8.4.0')).toBe('8.4.0')
    expect(shortServerVersion('')).toBe('')
  })
})
