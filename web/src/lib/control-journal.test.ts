import { describe, expect, it } from 'vitest'
import { journalHasMore, mergeJournal } from './control-journal'
import type { AuditEvent, Operation } from './types'

const op = (id: string, createdAt: string) => ({ id, created_at: createdAt } as Operation)
const event = (id: number, occurredAt: string) =>
  ({ id, occurred_at: occurredAt } as AuditEvent)

describe('лента контроля', () => {
  it('сливает операции и события в одну хронологию', () => {
    const rows = mergeJournal(
      [op('o1', '2026-07-30T12:00:00Z'), op('o2', '2026-07-30T10:00:00Z')],
      [event(1, '2026-07-30T11:00:00Z'), event(2, '2026-07-30T09:00:00Z')],
      100,
    )

    expect(rows.map((row) => row.id)).toEqual(['o1', 'audit-1', 'o2', 'audit-2'])
    expect(rows.map((row) => row.type)).toEqual(['operation', 'event', 'operation', 'event'])
  })

  // Одинаковая метка времени не должна давать плавающий порядок между
  // рендерами: операция идёт первой, событие фиксирует её следствие.
  it('разрешает совпадение времени детерминированно', () => {
    const rows = mergeJournal(
      [op('o1', '2026-07-30T12:00:00Z')],
      [event(1, '2026-07-30T12:00:00Z')],
      100,
    )
    expect(rows.map((row) => row.id)).toEqual(['o1', 'audit-1'])
  })

  // Обе выборки ограничены своим limit. За «дном» более короткой из них лента
  // была бы неполной, поэтому результат обрезается по границе полноты.
  it('обрезает ленту по границе полноты выборок', () => {
    const operations = [
      op('o1', '2026-07-30T12:00:00Z'),
      op('o2', '2026-07-30T11:00:00Z'),
    ]
    const events = [
      event(1, '2026-07-30T10:00:00Z'),
      event(2, '2026-07-30T09:00:00Z'),
    ]

    const rows = mergeJournal(operations, events, 2)

    // Операции кончились на 11:00, события — на 09:00; ниже 11:00 полнота не
    // гарантирована, поэтому события 10:00 и 09:00 в ленту не попадают.
    expect(rows.map((row) => row.id)).toEqual(['o1', 'o2'])
  })

  it('не обрезает, пока ни одна выборка не упёрлась в limit', () => {
    const rows = mergeJournal(
      [op('o1', '2026-07-30T12:00:00Z')],
      [event(1, '2026-07-30T09:00:00Z')],
      100,
    )
    expect(rows).toHaveLength(2)
  })

  it('сообщает о наличии следующей страницы по серверным total', () => {
    expect(journalHasMore({ operations: 100, events: 20 }, { operations: 250, events: 20 })).toBe(true)
    expect(journalHasMore({ operations: 10, events: 100 }, { operations: 10, events: 140 })).toBe(true)
    expect(journalHasMore({ operations: 10, events: 20 }, { operations: 10, events: 20 })).toBe(false)
    expect(journalHasMore({ operations: 10, events: 20 }, { operations: undefined, events: undefined })).toBe(false)
  })
})
