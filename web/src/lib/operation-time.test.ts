import { describe, expect, it } from 'vitest'
import {
  localDayRange,
  operationsTodaySearch,
  validateOperationTimeSearch,
} from './operation-time'

describe('operations today boundaries', () => {
  it('builds inclusive/exclusive UTC instants from the browser calendar day', () => {
    const now = new Date(2026, 6, 20, 15, 45, 12)
    const range = localDayRange(now)
    expect(range.createdFrom).toBe(new Date(2026, 6, 20).toISOString())
    expect(range.createdBefore).toBe(new Date(2026, 6, 21).toISOString())
    expect(new Date(range.createdBefore).getTime()).toBeGreaterThan(
      new Date(range.createdFrom).getTime(),
    )
    expect(range.timeZone).not.toBe('')
  })

  it('builds a copied overview URL with connection and both boundaries', () => {
    const range = {
      createdFrom: '2026-07-19T21:00:00.000Z',
      createdBefore: '2026-07-20T21:00:00.000Z',
      timeZone: 'Europe/Moscow',
    }
    const search = operationsTodaySearch(range, 'conn-b')
    const params = new URLSearchParams({
      connection: search.connection ?? '',
      created_from: search.created_from,
      created_before: search.created_before,
    })
    expect(`/operations?${params.toString()}`).toBe(
      '/operations?connection=conn-b&created_from=2026-07-19T21%3A00%3A00.000Z&created_before=2026-07-20T21%3A00%3A00.000Z',
    )
  })

  it('preserves malformed string boundaries for truthful server validation', () => {
    expect(
      validateOperationTimeSearch({
        created_from: 'not-a-date',
        created_before: '2026-07-20',
      }),
    ).toEqual({
      created_from: 'not-a-date',
      created_before: '2026-07-20',
    })
  })
})
