import type { Connection } from './types'
import { connectionIsStale, driftTotal } from './status'

const ENVIRONMENT_ALIASES: Record<string, string> = {
  production: 'PROD',
  prod: 'PROD',
  staging: 'STAGE',
  stage: 'STAGE',
  testing: 'TEST',
  test: 'TEST',
  development: 'DEV',
  dev: 'DEV',
}

const ENVIRONMENT_ORDER = ['PROD', 'STAGE', 'TEST', 'DEV']

const ENGINE_LABELS: Readonly<Record<string, string>> = {
  postgres: 'PostgreSQL',
  mongodb: 'MongoDB',
  mysql: 'MySQL',
  rabbitmq: 'RabbitMQ',
  clickhouse: 'ClickHouse',
  kafka: 'Kafka',
  redis: 'Redis',
}

export interface ConnectionEnvironmentGroup {
  key: string
  label: string
  connections: Connection[]
}

export function connectionNeedsAttention(connection: Connection): boolean {
  return connectionIsStale(connection.status) || driftTotal(connection.drift) > 0
}

export function connectionEngineLabel(engine: string): string {
  return ENGINE_LABELS[engine] ?? engine
}

export type ConnectionListFilter = 'all' | 'synced' | 'error'

/**
 * Фильтр approved connection-list. «Синхронно» относится к lifecycle
 * подключения (последний discovery завершился успешно); drift остаётся
 * отдельным фактическим признаком строки и не превращает active в ошибку.
 */
export function connectionMatchesListFilter(connection: Connection, filter: ConnectionListFilter): boolean {
  if (filter === 'synced') return connection.status === 'active'
  if (filter === 'error') return connectionIsStale(connection.status)
  return true
}

export function connectionListFilterCounts(connections: Connection[]): Record<ConnectionListFilter, number> {
  return {
    all: connections.length,
    synced: connections.filter((connection) => connectionMatchesListFilter(connection, 'synced')).length,
    error: connections.filter((connection) => connectionMatchesListFilter(connection, 'error')).length,
  }
}

export function connectionEnvironmentLabel(environment: string): string {
  const normalized = environment.trim().toLocaleLowerCase()
  if (normalized === '') return 'БЕЗ ОКРУЖЕНИЯ'
  return ENVIRONMENT_ALIASES[normalized] ?? environment.trim().toLocaleUpperCase()
}

export function sortConnections(connections: Connection[]): Connection[] {
  return [...connections].sort((left, right) => {
    const attention =
      Number(connectionNeedsAttention(right)) - Number(connectionNeedsAttention(left))
    if (attention !== 0) return attention
    return left.display_name.localeCompare(right.display_name, 'ru', { sensitivity: 'base' })
  })
}

export function groupConnectionsByEnvironment(
  connections: Connection[],
): ConnectionEnvironmentGroup[] {
  const groups = new Map<string, Connection[]>()
  for (const connection of connections) {
    const label = connectionEnvironmentLabel(connection.environment)
    const current = groups.get(label) ?? []
    current.push(connection)
    groups.set(label, current)
  }

  return [...groups.entries()]
    .sort(([left], [right]) => {
      const leftIndex = ENVIRONMENT_ORDER.indexOf(left)
      const rightIndex = ENVIRONMENT_ORDER.indexOf(right)
      const leftRank = left === 'БЕЗ ОКРУЖЕНИЯ' ? Number.MAX_SAFE_INTEGER : leftIndex >= 0 ? leftIndex : ENVIRONMENT_ORDER.length
      const rightRank = right === 'БЕЗ ОКРУЖЕНИЯ' ? Number.MAX_SAFE_INTEGER : rightIndex >= 0 ? rightIndex : ENVIRONMENT_ORDER.length
      return leftRank - rightRank || left.localeCompare(right, 'ru')
    })
    .map(([label, items]) => ({ key: label, label, connections: sortConnections(items) }))
}

export function connectionMatchesSearch(connection: Connection, query: string): boolean {
  const normalized = query.trim().toLocaleLowerCase()
  if (normalized === '') return true
  return [
    connection.display_name,
    connection.engine,
    connection.environment,
    ...connection.tags,
  ].some((value) => value.toLocaleLowerCase().includes(normalized))
}

export function connectionMatchesFacets(
  connection: Connection,
  environment: string | null,
  engine: string | null,
): boolean {
  return (
    (environment === null || connectionEnvironmentLabel(connection.environment) === environment) &&
    (engine === null || connection.engine === engine)
  )
}

/**
 * Короткая версия целевой системы для подписи: PostgreSQL отдаёт
 * `16.14 (Debian 16.14-1.pgdg13+1)`, и в плотной строке важен только номер.
 * Полное значение остаётся в title.
 */
export function shortServerVersion(version: string): string {
  return version.split(' ')[0]
}

export function formatCompactRelative(
  iso: string | null | undefined,
  now = Date.now(),
): string {
  if (iso === null || iso === undefined || iso === '') return '—'
  const then = new Date(iso).getTime()
  if (Number.isNaN(then)) return '—'
  const diffSeconds = Math.max(0, Math.floor((now - then) / 1000))
  // «сейчас», а не «только что»: подпись живёт в чипе фиксированной ширины
  // рядом с остальными интервалами, и длинный вариант переносился на две
  // строки, ломая высоту строки подключения.
  if (diffSeconds < 60) return 'сейчас'
  const minutes = Math.floor(diffSeconds / 60)
  if (minutes < 60) return `${minutes} мин`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} ч`
  return `${Math.floor(hours / 24)} д`
}
