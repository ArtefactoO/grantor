import { render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { AccountHBASection, accountHBARules } from './connection-hba-section'
import type { HBARule } from './connection-hba-section'

function rule(number: number, users: string[], overrides: Partial<HBARule> = {}): HBARule {
  return { number, type: 'host', databases: ['app'], users, address: '10.0.0.1', netmask: '255.255.255.255',
    auth_method: 'scram-sha-256', options: [], error: '', ...overrides }
}

describe('account HBA snapshot', () => {
  it('keeps file order and relevant explicit, general, group and uncertain rules, including reject', () => {
    const rules = [rule(8, ['other']), rule(4, ['+writers']), rule(2, ['alice'], { auth_method: 'reject' }),
      rule(6, ['all']), rule(1, ['@users']), rule(3, ['/ali.*']), rule(5, ['+unrelated'])]
    expect(accountHBARules(rules, 'alice', new Set(['writers'])).map(x => x.number)).toEqual([1, 2, 3, 4, 6])
    expect(rules.map(x => x.number)).toEqual([8, 4, 2, 6, 1, 3, 5])
  })

  it('uses supplied snapshot without fetching or claiming successful authentication', () => {
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)
    const rules = [rule(1, ['alice'], { auth_method: 'reject', options: ['private-option'], error: 'private-error' })]
    render(<AccountHBASection identity="alice" roles={new Set()} observedAt="2026-10-22T12:00:00Z"
      query={{ isPending: false, isError: false, data: { supported: true, customized: true, truncated: true, rules, uncovered_accounts: [] } }} />)
    expect(screen.getByText('Правила pg_hba · 1')).toBeInTheDocument()
    expect(screen.getByText(/не подтверждает загрузку правил сервером или успешный вход/)).toBeInTheDocument()
    expect(screen.getByText(/Снимок HBA неполный/)).toBeInTheDocument()
    expect(screen.getByText('Ошибка правила')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('private-option')
    expect(document.body.textContent).not.toContain('private-error')
    expect(fetch).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
  })

  it.each([
    [{ isPending: true, isError: false }, 'Загружаются правила подключения…'],
    [{ isPending: false, isError: true }, 'Не удалось загрузить HBA. Повторите загрузку страницы подключения.'],
    [{ isPending: false, isError: false }, 'В текущем снимке нет данных HBA.'],
  ])('distinguishes missing and failed snapshots', (query, text) => {
    render(<AccountHBASection identity="alice" roles={new Set()} observedAt={null} query={{ ...query, data: undefined }} />)
    expect(screen.getByText(text)).toBeInTheDocument()
  })
})
