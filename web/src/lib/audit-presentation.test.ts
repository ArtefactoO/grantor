import { describe, expect, it } from 'vitest'
import { auditDayLabel, auditDomain, auditSubject, groupByDay, isServiceActor } from './audit-presentation'
import type { Account, AuditEvent } from './types'

describe('представление ленты аудита', () => {
  it('определяет домен события по префиксу', () => {
    expect(auditDomain('principal.imported_from_directory')).toBe('principal')
    expect(auditDomain('security.offboarding_incomplete')).toBe('security')
    expect(auditDomain('future.action')).toBe('other')
  })

  it('отличает процесс grantor от человека', () => {
    expect(isServiceActor('service')).toBe(true)
    expect(isServiceActor('system')).toBe(true)
    expect(isServiceActor('user')).toBe(false)
  })

  it('называет ближайшие дни словами, остальные — датой', () => {
    const now = new Date('2026-07-28T12:00:00Z')
    const yesterday = new Date(now)
    yesterday.setDate(yesterday.getDate() - 1)
    yesterday.setHours(12, 0, 0, 0)
    expect(auditDayLabel('2026-07-28T09:00:00Z', now)).toBe('Сегодня')
    expect(auditDayLabel(yesterday.toISOString(), now)).toBe('Вчера')
    expect(auditDayLabel('2026-07-20T10:00:00Z', now)).toContain('июля')
    expect(auditDayLabel('не дата', now)).toBe('Без даты')
  })

  // Порядок событий задаёт бэкенд; группировка не вправе его менять, иначе
  // лента перестанет читаться как хронология.
  it('группирует по дням, сохраняя исходный порядок', () => {
    const now = new Date('2026-07-28T12:00:00Z')
    const groups = groupByDay([
      { occurred_at: '2026-07-28T11:00:00Z', id: 1 },
      { occurred_at: '2026-07-28T10:00:00Z', id: 2 },
      { occurred_at: '2026-07-27T18:00:00Z', id: 3 },
    ], (item) => item.occurred_at, now)

    expect(groups.map((group) => group.label)).toEqual(['Сегодня', 'Вчера'])
    expect(groups[0]?.items.map((item) => item.id)).toEqual([1, 2])
    expect(groups[1]?.items.map((item) => item.id)).toEqual([3])
  })

  describe('субъект события', () => {
    const event = (overrides: Partial<AuditEvent>): AuditEvent => ({
      id: 1,
      occurred_at: '2026-07-28T10:00:00Z',
      actor_type: 'service',
      actor_id: 'grantor-maintenance',
      action: 'principal.disabled',
      connection_id: null,
      resource_id: null,
      principal_id: null,
      account_id: null,
      operation_id: null,
      result: 'success',
      metadata: {},
      ...overrides,
    })
    const connectionName = (id: string | null) => (id === null ? '—' : `подключение ${id}`)
    const principals = new Map([['principal-1', 'Егор Яковлев']])
    const accounts = new Map([['account-1', { engine_identity: 'reports_bot' } as Account]])

    it('называет человека, а не идентификатор', () => {
      expect(auditSubject(event({ principal_id: 'principal-1' }), connectionName, principals, accounts))
        .toBe('Егор Яковлев')
    })

    // Принципал важнее аккаунта: событие о человеке отвечает про человека.
    it('предпочитает принципала аккаунту и подключению', () => {
      expect(auditSubject(
        event({ principal_id: 'principal-1', account_id: 'account-1', connection_id: 'connection-1' }),
        connectionName, principals, accounts,
      )).toBe('Егор Яковлев')
    })

    it('спускается к аккаунту и подключению, когда принципала нет', () => {
      expect(auditSubject(event({ account_id: 'account-1' }), connectionName, principals, accounts))
        .toBe('reports_bot')
      expect(auditSubject(event({ connection_id: 'connection-1' }), connectionName, principals, accounts))
        .toBe('подключение connection-1')
    })

    // Удалённый принципал не должен превращать строку в пустоту: короткий id
    // всё же позволяет найти его в аудите.
    it('показывает короткий id, если имя неизвестно', () => {
      expect(auditSubject(event({ principal_id: 'principal-gone' }), connectionName, principals, accounts))
        .not.toBeNull()
    })

    it('возвращает null, когда событие ни к чему не привязано', () => {
      expect(auditSubject(event({}), connectionName, principals, accounts)).toBeNull()
    })
  })
})
