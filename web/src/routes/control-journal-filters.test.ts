import { describe, expect, it } from 'vitest'
import { journalActivePreset, journalRangeWindow } from './control-journal-filters'

const now = new Date('2026-07-30T12:00:00Z')

describe('период журнала', () => {
  it('«всё время» снимает границы', () => {
    expect(journalRangeWindow('all', now)).toEqual({})
    expect(journalActivePreset({}, now)).toBe('all')
  })

  it('относительные пресеты задают только нижнюю границу', () => {
    const day = journalRangeWindow('day', now)
    expect(day.created_from).toBe('2026-07-29T12:00:00.000Z')
    expect(day.created_before).toBeUndefined()

    const week = journalRangeWindow('week', now)
    expect(week.created_from).toBe('2026-07-23T12:00:00.000Z')
  })

  it('узнаёт свой пресет по границам в URL', () => {
    expect(journalActivePreset(journalRangeWindow('week', now), now)).toBe('week')
    expect(journalActivePreset(journalRangeWindow('today', now), now)).toBe('today')
  })

  // Плитка «Операций сегодня» на обзоре приводит со своими границами: они
  // законны, но пресетом не являются — подсветка обещала бы обратное.
  it('не подсвечивает чужое окно', () => {
    expect(journalActivePreset({ created_from: '2026-07-01T00:00:00.000Z' }, now)).toBeNull()
  })
})
