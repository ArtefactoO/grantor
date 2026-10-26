import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({ useParams: () => ({ connectionId: 'connection-1' }) }),
  Link: ({ children }: { children: ReactNode }) => <>{children}</>,
  useNavigate: () => vi.fn(),
}))

import { GrantedAccessTab } from './connection-detail'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('GrantedAccessTab selection chips', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('uses the shared master chip and allows zero selected sections', async () => {
    const fetchMock = vi.fn(async (path: string) => {
      const url = String(path)
      if (url.includes('sections=managed%2Cunmanaged%2Croles%2Caccounts')) {
        return jsonResponse({
          kind: 'access_snapshot',
          connection: {
            id: 'connection-1',
            display_name: 'test rabbitmq',
            engine: 'rabbitmq',
            environment: 'test',
          },
          managed: [],
          unmanaged: [],
          roles: [],
          accounts: [],
        })
      }
      return jsonResponse({ version: 'v1', entries: [] })
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    render(
      <GrantedAccessTab
        connectionId="connection-1"
        connectionName="test rabbitmq"
      />,
      { wrapper: Wrapper },
    )

    const all = screen.getByRole('checkbox', { name: 'All' })
    const managed = screen.getByRole('checkbox', { name: 'Managed' })
    expect(screen.getByRole('checkbox', { name: 'Roles' })).toBeVisible()
    expect(screen.getByRole('checkbox', { name: 'Accounts' })).toBeVisible()
    expect(all).toHaveAttribute('aria-checked', 'mixed')
    expect(all.querySelector('svg')).not.toBeNull()
    expect(managed).toHaveAttribute('aria-checked', 'true')
    expect(managed.querySelector('svg')).not.toBeNull()

    await user.click(managed)
    expect(await screen.findByText('Секции не выбраны')).toBeInTheDocument()
    expect(all).toHaveAttribute('aria-checked', 'false')
    expect(screen.getByRole('button', { name: 'Скачать JSON' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Скачать YAML' })).toBeDisabled()

    const callsWithNoSelection = fetchMock.mock.calls.length
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(fetchMock).toHaveBeenCalledTimes(callsWithNoSelection)

    await user.click(all)
    expect(all).toHaveAttribute('aria-checked', 'true')
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/access/export?connection=connection-1&sections=managed,unmanaged,roles,accounts',
      expect.anything(),
    ))

    await user.click(all)
    expect(await screen.findByText('Секции не выбраны')).toBeInTheDocument()
    expect(all).toHaveAttribute('aria-checked', 'false')
  })
})
