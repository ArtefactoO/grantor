import { shortId } from './status'
import type { Account, AuditEvent } from './types'

/** Домен события — префикс action до первой точки. */
export type AuditDomain =
  | 'access'
  | 'account'
  | 'binding'
  | 'connection'
  | 'operation'
  | 'principal'
  | 'security'
  | 'other'

const DOMAINS: ReadonlySet<string> = new Set([
  'access',
  'account',
  'binding',
  'connection',
  'operation',
  'principal',
  'security',
])

export function auditDomain(action: string): AuditDomain {
  const prefix = action.split('.')[0] ?? ''
  return DOMAINS.has(prefix) ? (prefix as AuditDomain) : 'other'
}

/** Актор — процесс grantor, а не человек. */
export function isServiceActor(actorType: string): boolean {
  return actorType === 'service' || actorType === 'system'
}

/**
 * Заголовок группы ленты по дню события.
 *
 * Абсолютная дата рядом с «15 мин назад» в каждой строке избыточна, но без
 * какого-либо якоря лента из сотни событий теряет ощущение времени.
 */
export function auditDayLabel(iso: string, now: Date = new Date()): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return 'Без даты'
  const day = startOfDay(date)
  const today = startOfDay(now)
  const diffDays = Math.round((today.getTime() - day.getTime()) / 86_400_000)
  if (diffDays === 0) return 'Сегодня'
  if (diffDays === 1) return 'Вчера'
  return date.toLocaleDateString('ru-RU', { day: '2-digit', month: 'long', year: 'numeric' })
}

function startOfDay(value: Date): Date {
  return new Date(value.getFullYear(), value.getMonth(), value.getDate())
}

/** Группирует события по дню, сохраняя исходный порядок. */
export function groupByDay<T>(
  items: readonly T[],
  timestampOf: (item: T) => string = (item) => (item as { occurred_at: string }).occurred_at,
  now?: Date,
): Array<{ label: string; items: T[] }> {
  const groups: Array<{ label: string; items: T[] }> = []
  for (const item of items) {
    const label = auditDayLabel(timestampOf(item), now)
    const last = groups.at(-1)
    if (last !== undefined && last.label === label) {
      last.items.push(item)
      continue
    }
    groups.push({ label, items: [item] })
  }
  return groups
}

/**
 * Кого касается событие.
 *
 * Без субъекта два события подряд от одного исполнителя в одну минуту
 * неразличимы, хотя относятся к разным людям.
 */
export function auditSubject(event: AuditEvent, connectionName: (id: string | null) => string, principalNames: ReadonlyMap<string, string>, accountsById: ReadonlyMap<string, Account>): string | null {
  if (event.principal_id !== null) {
    return principalNames.get(event.principal_id) ?? shortId(event.principal_id)
  }
  if (event.account_id !== null) {
    return accountsById.get(event.account_id)?.engine_identity ?? shortId(event.account_id)
  }
  if (event.connection_id !== null) return connectionName(event.connection_id)
  return null
}
