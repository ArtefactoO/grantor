import { useQuery } from '@tanstack/react-query'
import { apiList } from './api'
import { qk } from './queryKeys'
import type { Connection } from './types'

export interface ConnectionSearch {
  connection?: string
}

/**
 * Общий URL-контракт connection-scoped экранов. Невалидный по типу параметр
 * отбрасывается, но неизвестный строковый id сохраняется: экран обязан честно
 * показать, что такое подключение недоступно, а не выбрать другое.
 */
export function validateConnectionSearch(search: Record<string, unknown>): ConnectionSearch {
  if (typeof search.connection !== 'string') {
    return {}
  }
  const connection = search.connection.trim()
  return connection === '' ? {} : { connection }
}

export type ConnectionScopeResolution =
  | { kind: 'all'; connectionId: '' }
  | { kind: 'required'; connectionId: '' }
  | { kind: 'selected'; connectionId: string; connection: Connection }
  | { kind: 'unavailable'; connectionId: string }

/** Чистая часть резолва используется и страницами, и route-тестами. */
export function resolveConnectionScope(
  requestedId: string | undefined,
  connections: Connection[],
  allowAll: boolean,
): ConnectionScopeResolution {
  if (requestedId === undefined || requestedId === '') {
    return allowAll
      ? { kind: 'all', connectionId: '' }
      : { kind: 'required', connectionId: '' }
  }
  const connection = connections.find((item) => item.id === requestedId)
  return connection === undefined
    ? { kind: 'unavailable', connectionId: requestedId }
    : { kind: 'selected', connectionId: connection.id, connection }
}

export function useConnectionScope(requestedId: string | undefined, allowAll: boolean) {
  const query = useQuery({
    queryKey: qk.connections(),
    queryFn: ({ signal }) =>
      apiList<Connection>('/api/v1/connections', 'connections', signal),
  })
  const connections = query.data ?? []
  return {
    query,
    connections,
    resolution: resolveConnectionScope(requestedId, connections, allowAll),
  }
}

/** Значение для router.navigate: пустая строка канонизируется в отсутствие param. */
export function connectionSearchValue(value: string): string | undefined {
  return value === '' ? undefined : value
}

const CONNECTION_CONTEXT_ROUTES = new Set([
  '/drift',
  '/operations',
  '/audit',
  '/control',
])

/** Scope текущего location: detail path авторитетнее унаследованного search. */
export function connectionFromLocation(
  pathname: string,
  search: Record<string, unknown>,
): string | undefined {
  const detailConnection = pathname.match(/^\/connections\/([^/]+)(?:\/|$)/)?.[1]
  return detailConnection ?? validateConnectionSearch(search).connection
}

/** Search для sidebar-ссылки; глобальные разделы не получают скрытый scope. */
export function connectionSearchForRoute(
  to: string,
  connection: string | undefined,
): ConnectionSearch {
  return CONNECTION_CONTEXT_ROUTES.has(to) && connection !== undefined
    ? { connection }
    : {}
}
