// Объединённая лента «Контроля»: операции верхнего уровня и audit-события,
// не принадлежащие ни одной операции. События самой операции живут в её
// детальной панели, поэтому в ленте каждая операция ровно одна строка.
import type { AuditEvent, Operation } from './types'

export interface JournalOperationRow {
  type: 'operation'
  id: string
  at: string
  operation: Operation
}

export interface JournalEventRow {
  type: 'event'
  id: string
  at: string
  event: AuditEvent
}

export type JournalRow = JournalOperationRow | JournalEventRow

/** Время строки ленты: для операции — момент постановки, для события — его. */
function operationRow(operation: Operation): JournalOperationRow {
  return { type: 'operation', id: operation.id, at: operation.created_at, operation }
}

function eventRow(event: AuditEvent): JournalEventRow {
  return { type: 'event', id: `audit-${event.id}`, at: event.occurred_at, event }
}

/**
 * Сливает две выборки от новых к старым.
 *
 * Каждая выборка ограничена своим limit, поэтому за пределами более короткой
 * из них лента была бы неполной: там, где у одного источника строки
 * закончились, у другого они ещё есть, и хронология молча теряла бы часть
 * событий. Поэтому при упоре хотя бы одного источника в limit результат
 * обрезается по более поздней из двух «последних» отметок — до этой границы
 * обе выборки полны.
 */
export function mergeJournal(
  operations: readonly Operation[],
  events: readonly AuditEvent[],
  limit: number,
): JournalRow[] {
  const rows: JournalRow[] = [
    ...operations.map(operationRow),
    ...events.map(eventRow),
  ]
  rows.sort(compareRows)

  const boundary = truncationBoundary(operations, events, limit)
  return boundary === null ? rows : rows.filter((row) => row.at >= boundary)
}

/**
 * Порядок ленты: сначала по времени убыванием, затем детерминированный
 * tiebreak — операции выше событий той же секунды (событие обычно фиксирует
 * следствие), дальше по id. Без tiebreak порядок одинаковых меток времени
 * плавал бы между рендерами.
 */
function compareRows(left: JournalRow, right: JournalRow): number {
  if (left.at !== right.at) return left.at < right.at ? 1 : -1
  if (left.type !== right.type) return left.type === 'operation' ? -1 : 1
  return left.id < right.id ? 1 : -1
}

/**
 * Нижняя граница полноты: null — обе выборки исчерпаны и обрезать нечего.
 */
function truncationBoundary(
  operations: readonly Operation[],
  events: readonly AuditEvent[],
  limit: number,
): string | null {
  const opsFull = operations.length >= limit
  const eventsFull = events.length >= limit
  if (!opsFull && !eventsFull) return null
  const oldestOp = operations.at(-1)?.created_at
  const oldestEvent = events.at(-1)?.occurred_at
  if (opsFull && eventsFull && oldestOp !== undefined && oldestEvent !== undefined) {
    return oldestOp > oldestEvent ? oldestOp : oldestEvent
  }
  return (opsFull ? oldestOp : oldestEvent) ?? null
}

/**
 * Есть ли ещё строки за пределами показанного: сравниваем загруженное с
 * серверными total обеих выборок.
 */
export function journalHasMore(
  loaded: { operations: number; events: number },
  totals: { operations: number | undefined; events: number | undefined },
): boolean {
  return (totals.operations !== undefined && loaded.operations < totals.operations)
    || (totals.events !== undefined && loaded.events < totals.events)
}
