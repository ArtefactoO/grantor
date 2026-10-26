import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/control">{children}</a>,
}))
vi.mock('../auth/AuthProvider', async (importOriginal) => ({
  ...await importOriginal<typeof import('../auth/AuthProvider')>(),
  useAuth: () => ({ role: 'viewer', email: 'viewer@example.test' }),
}))
vi.mock('./connection-directory', () => ({ ConnectionDirectory: () => null }))

import { OverviewPage } from './overview'

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

let failedSource = ''
let pendingSource = ''

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><OverviewPage /></QueryClientProvider>)
  return client
}

function connectionTile() {
  return within(screen.getByText('Подключения', { selector: 'div' }).closest('a')!)
}

describe('overview source availability', () => {
  beforeEach(() => {
    failedSource = ''
    pendingSource = ''
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = new URL(String(input), 'https://grantor.example.test')
      const source = url.pathname.endsWith('/connections') ? 'connections'
        : url.searchParams.get('status') === 'pending_approval' ? 'approvals'
        : url.searchParams.get('status')?.includes('failed') ? 'errors'
        : url.searchParams.has('created_from') ? 'today' : 'recent'
      if (pendingSource === source) return new Promise<Response>(() => {})
      if (failedSource === source) return Promise.resolve(response({ error: 'source unavailable' }, 503))
      return Promise.resolve(response(source === 'connections'
        ? { connections: [] }
        : { operations: [], total: 0 }))
    })
  })

  it('does not turn a pending inventory into a healthy zero', async () => {
    pendingSource = 'connections'
    setup()
    expect(await screen.findByText('Проверка состояния…')).toBeVisible()
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
    expect(connectionTile().getByLabelText('Нет актуальных данных')).toBeVisible()
    expect(connectionTile().queryByText('0')).not.toBeInTheDocument()
  })

  it.each(['connections', 'approvals', 'errors'])('does not report healthy when %s fails', async (source) => {
    failedSource = source
    setup()
    expect(await screen.findByText('Не удалось проверить состояние')).toBeVisible()
    expect(screen.queryByText('Healthy')).not.toBeInTheDocument()
    const attentionTile = within(screen.getByText('Требует внимания').closest('a')!)
    expect(attentionTile.getByLabelText('Нет актуальных данных')).toBeVisible()
    expect(attentionTile.queryByText('0')).not.toBeInTheDocument()
  })

  it('restores a verified healthy state after retry without implying that an empty inventory is running', async () => {
    failedSource = 'connections'
    setup()
    const user = userEvent.setup()
    await screen.findByText('Не удалось проверить состояние')
    failedSource = ''
    await user.click(screen.getByRole('button', { name: 'Повторить проверку' }))
    expect(await screen.findByText('Healthy')).toBeVisible()
    expect(connectionTile().getByText('0')).toBeVisible()
    expect(connectionTile().getByText('Подключений пока нет')).toBeVisible()
    expect(screen.queryByText('Все работают штатно')).not.toBeInTheDocument()
  })

  it('does not show today as zero when its independent source fails', async () => {
    failedSource = 'today'
    setup()
    await screen.findByText('Не удалось загрузить число операций')
    const tile = within(screen.getByText('Операций сегодня').closest('a')!)
    expect(tile.getByLabelText('Нет актуальных данных')).toBeVisible()
    expect(tile.queryByText('0')).not.toBeInTheDocument()
  })

  it('stops presenting cached data as healthy after a failed refetch', async () => {
    const client = setup()
    await screen.findByText('Healthy')
    failedSource = 'connections'
    await client.invalidateQueries({ queryKey: ['connections'] })
    await waitFor(() => expect(screen.queryByText('Healthy')).not.toBeInTheDocument())
    expect(screen.getByText('Не удалось проверить состояние')).toBeVisible()
  })
})
