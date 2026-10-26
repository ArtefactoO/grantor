import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../auth/AuthProvider', () => ({
  roleAtLeast: () => true,
  useAuth: () => ({ role: 'admin' }),
}))

import { ScopePoliciesPage } from './scope-policies'

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('ScopePoliciesPage matrix', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('shows inherited cells as non-actionable and confirms a denied-cell change in drawer', async () => {
    let policies = [
      {
        id: 'policy-all',
        subject_kind: 'principal',
        subject: 'service-1',
        environment: '*',
        created_at: '2026-07-20T00:00:00Z',
      },
    ]
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      const url = String(path)
      if (url === '/api/v1/scope-policies' && (options?.method ?? 'GET') === 'GET') {
        return json({ policies })
      }
      if (url === '/api/v1/runtime-config') return json({ scope_enforcement: 'enforce' })
      if (url === '/api/v1/principals') {
        return json({
          principals: [
            {
              id: 'service-1',
              type: 'service',
              display_name: 'Deploy Bot',
              external_provider: '',
              external_subject: '',
              status: 'active',
              attributes: {},
              created_at: '2026-07-20T00:00:00Z',
              updated_at: '2026-07-20T00:00:00Z',
            },
          ],
        })
      }
      if (url === '/api/v1/connections') {
        return json({
          connections: [
            {
              id: 'test-db',
              display_name: 'test postgres',
              engine: 'postgres',
              environment: 'test',
              tags: [],
              endpoints: [],
              execution_mode: 'direct',
              tls_config: {},
              admin_credential_mode: 'vault',
              vault_admin_path: '',
              capabilities: [],
              discovery_config: {},
              status: 'active',
              server_version: '',
              topology: {},
              last_discovery_at: null,
              created_at: '2026-07-20T00:00:00Z',
              updated_at: '2026-07-20T00:00:00Z',
            },
          ],
        })
      }
      if (url === '/api/v1/scope-policies' && options?.method === 'POST') {
        const payload = JSON.parse(String(options.body)) as { subject: string; environment: string }
        expect(payload).toMatchObject({ subject: 'operator', environment: 'test' })
        const created = {
          id: 'policy-operator-test',
          subject_kind: 'role',
          subject: payload.subject,
          environment: payload.environment,
          created_at: '2026-07-20T00:00:00Z',
        }
        policies = [...policies, created]
        return json(created, 201)
      }
      throw new Error(`unexpected path ${url}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    render(<ScopePoliciesPage />, { wrapper: Wrapper })

    expect(await screen.findByText('Ограничение включено')).toBeInTheDocument()
    const inherited = screen.getByRole('button', {
      name: 'Deploy Bot: test, разрешено через все окружения',
    })
    expect(inherited).toBeDisabled()
    expect(inherited).toHaveAttribute('aria-pressed', 'true')

    const denied = screen.getByRole('button', { name: 'Все операторы: test, запрещено' })
    expect(denied).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    denied.focus()
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: 'Разрешить доступ' })).toBeInTheDocument()
    expect(screen.getByText('test postgres')).toBeInTheDocument()
    expect(fetchMock.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(denied).toHaveFocus())
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: 'Разрешить доступ' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Разрешить' }))

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Все операторы: test, разрешено явно' }),
      ).toBeInTheDocument(),
    )
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/scope-policies',
      expect.objectContaining({ method: 'POST' }),
    )
    expect(screen.getByRole('button', { name: 'Все операторы: test, разрешено явно' }))
      .not.toHaveClass('shadow-sm')
  })
})
