import { describe, expect, it } from 'vitest'
import type { Connection } from './types'
import { catalogPage, connectionCatalog, DEFAULT_CATALOG_STATE, restoreCatalogState } from './connection-catalog'

const connection = (id: string, environment: string, engine: string, status = 'active') => ({
  id, display_name: id, environment, engine, status, tags: [],
} as unknown as Connection)
const connections = [
  connection('pg-prod', 'prod', 'postgres'),
  connection('redis-test', 'test', 'redis'),
  connection('redis-broken', 'TEST', 'redis', 'discovery_failed'),
  connection('mongo-test', 'test', 'mongodb'),
]

describe('connection catalog projection', () => {
  it('counts environments once, scopes engines before their own filter and ignores pages', () => {
    const result = connectionCatalog(connections, new Set(), { ...DEFAULT_CATALOG_STATE, environment: 'TEST', engine: 'redis', pages: { 'engine:redis': 99 } })
    expect(result.environments.map(o => o.value)).toEqual(['PROD', 'TEST'])
    expect(result.engineTotal).toBe(3)
    expect(result.engines).toEqual([
      { value: 'mongodb', label: 'MongoDB', count: 1 }, { value: 'redis', label: 'Redis', count: 2 },
    ])
    expect(result.total).toBe(2)
    expect(result.statusCounts).toEqual({ all: 2, synced: 1, error: 1 })
  })

  it('combines search, status and favorite mode before engine counts without duplicating favorites', () => {
    const favorites = new Set(['redis-test', 'pg-prod'])
    const result = connectionCatalog(connections, favorites, { ...DEFAULT_CATALOG_STATE, search: 'redis', filter: 'synced', favoritesOnly: true })
    expect(result.engines).toEqual([{ value: 'redis', label: 'Redis', count: 1 }])
    expect(result.favoriteConnections.map(c => c.id)).toEqual(['redis-test'])
    expect(result.groups).toHaveLength(0)
    expect(result.total).toBe(1)
    const all = connectionCatalog(connections, favorites, DEFAULT_CATALOG_STATE)
    const ids = [...all.favoriteConnections, ...all.groups.flatMap(g => g.engines.flatMap(e => e.connections))].map(c => c.id)
    expect(ids).toHaveLength(connections.length)
    expect(new Set(ids).size).toBe(ids.length)
    expect(all.modeCounts).toEqual({ all: 4, favorites: 2 })
  })

  it('clamps pages when data shrinks and covers every item once', () => {
    const items = Array.from({ length: 47 }, (_, i) => i)
    const pages = [1, 2, 3].flatMap(page => catalogPage(items, page, 20).items)
    expect(pages).toEqual(items)
    expect(catalogPage(items.slice(0, 3), 3, 20)).toMatchObject({ page: 1, pageCount: 1, start: 1, end: 3 })
    expect(catalogPage([], 3, 20)).toMatchObject({ page: 1, start: 0, end: 0, total: 0 })
  })

  it('restores navigation state safely and rejects corrupt persisted values', () => {
    const state = { ...DEFAULT_CATALOG_STATE, search: 'redis', environment: 'TEST', expanded: { TEST: false }, pages: { redis: 2 } }
    expect(restoreCatalogState(JSON.stringify(state))).toEqual(state)
    expect(restoreCatalogState('not json')).toEqual(DEFAULT_CATALOG_STATE)
    expect(restoreCatalogState('{"pages":{"redis":-1},"pageSize":0,"expanded":{"TEST":"false"}}')).toEqual(DEFAULT_CATALOG_STATE)
  })
})
