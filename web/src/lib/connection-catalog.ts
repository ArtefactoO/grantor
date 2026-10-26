import type { Connection } from './types'
import {
  connectionEngineLabel,
  connectionListFilterCounts,
  connectionMatchesFacets,
  connectionMatchesListFilter,
  connectionMatchesSearch,
  groupConnectionsByEnvironment,
  sortConnections,
} from './connection-presentation'
import type { ConnectionListFilter } from './connection-presentation'

export const ALL_CONNECTION_FACETS = '__all__'
export interface ConnectionFacetOption { value: string; label: string; count: number }
export interface CatalogState {
  search: string
  filter: ConnectionListFilter
  environment: string
  engine: string
  favoritesOnly: boolean
  expanded: Record<string, boolean>
  pages: Record<string, number>
  pageSize: number
}

export const DEFAULT_CATALOG_STATE: CatalogState = {
  search: '', filter: 'all', environment: ALL_CONNECTION_FACETS, engine: ALL_CONNECTION_FACETS,
  favoritesOnly: false, expanded: {}, pages: {}, pageSize: 20,
}

/** Persist view choices only. Favorite ownership and visibility belong to the API. */
export function restoreCatalogState(raw: string | null): CatalogState {
  const initial = { ...DEFAULT_CATALOG_STATE, expanded: {}, pages: {} }
  if (raw === null) return initial
  try {
    const value: unknown = JSON.parse(raw)
    if (value === null || typeof value !== 'object') return initial
    const state = value as Partial<CatalogState>
    const validRecord = (candidate: unknown): candidate is Record<string, unknown> =>
      candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate)
    return {
      search: typeof state.search === 'string' ? state.search.slice(0, 300) : '',
      filter: state.filter === 'synced' || state.filter === 'error' ? state.filter : 'all',
      environment: typeof state.environment === 'string' ? state.environment : ALL_CONNECTION_FACETS,
      engine: typeof state.engine === 'string' ? state.engine : ALL_CONNECTION_FACETS,
      favoritesOnly: state.favoritesOnly === true,
      expanded: validRecord(state.expanded)
        ? Object.fromEntries(Object.entries(state.expanded).filter(([, v]) => typeof v === 'boolean')) as Record<string, boolean>
        : {},
      pages: validRecord(state.pages)
        ? Object.fromEntries(Object.entries(state.pages).filter(([, v]) => typeof v === 'number' && Number.isSafeInteger(v) && v > 0)) as Record<string, number>
        : {},
      pageSize: state.pageSize === 50 ? 50 : 20,
    }
  } catch { return initial }
}

export function connectionFacetOptions(connections: Connection[]) {
  const engineCounts = new Map<string, number>()
  for (const connection of connections) engineCounts.set(connection.engine, (engineCounts.get(connection.engine) ?? 0) + 1)
  return {
    environments: groupConnectionsByEnvironment(connections).map(group => ({
      value: group.label, label: group.label, count: group.connections.length,
    })),
    engines: [...engineCounts.entries()]
      .sort(([a], [b]) => connectionEngineLabel(a).localeCompare(connectionEngineLabel(b), 'ru'))
      .map(([engine, count]) => ({ value: engine, label: connectionEngineLabel(engine), count })),
  }
}

/** Each facet excludes its own selection and pagination never changes counts. */
export function connectionCatalog(connections: Connection[], favorites: ReadonlySet<string>, state: CatalogState) {
  const environment = state.environment === ALL_CONNECTION_FACETS ? null : state.environment
  const engine = state.engine === ALL_CONNECTION_FACETS ? null : state.engine
  const searched = connections.filter(c => connectionMatchesSearch(c, state.search))
  const modeBase = searched.filter(c => !state.favoritesOnly || favorites.has(c.id))
  const engineBase = modeBase.filter(c =>
    connectionMatchesListFilter(c, state.filter) && connectionMatchesFacets(c, environment, null),
  )
  const statusBase = modeBase.filter(c => connectionMatchesFacets(c, environment, engine))
  const modeCountsBase = searched.filter(c =>
    connectionMatchesListFilter(c, state.filter) && connectionMatchesFacets(c, environment, engine),
  )
  const visible = engineBase.filter(c => engine === null || c.engine === engine)
  const favoriteConnections = sortConnections(visible.filter(c => favorites.has(c.id)))
  const remaining = visible.filter(c => !favorites.has(c.id))
  return {
    environments: connectionFacetOptions(connections).environments,
    engines: connectionFacetOptions(engineBase).engines,
    engineTotal: engineBase.length,
    statusCounts: connectionListFilterCounts(statusBase),
    modeCounts: { all: modeCountsBase.length, favorites: modeCountsBase.filter(c => favorites.has(c.id)).length },
    favoriteConnections,
    total: visible.length,
    groups: groupConnectionsByEnvironment(remaining).map(group => ({
      ...group,
      engines: connectionFacetOptions(group.connections).engines.map(option => ({
        ...option,
        connections: sortConnections(group.connections.filter(c => c.engine === option.value)),
      })),
    })),
  }
}

export function catalogPage<T>(items: readonly T[], requestedPage: number, pageSize: number) {
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize))
  const page = Math.max(1, Math.min(requestedPage, pageCount))
  const start = (page - 1) * pageSize
  return { items: items.slice(start, start + pageSize), page, pageCount, start: items.length ? start + 1 : 0, end: Math.min(start + pageSize, items.length), total: items.length }
}
