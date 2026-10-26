// Страница «Контроль» целиком: до этого теста ни один тест её не монтировал
// (в router.test.tsx она замокана), и ошибка порядка объявлений внутри
// компонента — обращение к переменной из фабрики useMemo раньше, чем она
// объявлена, — прошла все 400+ проверок и уронила экран в production.
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const routeState = vi.hoisted(() => ({ search: {} as Record<string, string>, role: 'admin' }))
vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({ useSearch: () => routeState.search }),
  Link: ({ children }: { children: ReactNode }) => <>{children}</>,
  useNavigate: () => vi.fn(),
}))

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ role: routeState.role, email: 'admin@grantor.dev', status: 'authenticated' }),
  }
})

import { ControlPage } from './control'

const CONNECTION = {
  id: 'c-1', display_name: 'RabbitMQ (prod)', engine: 'rabbitmq', environment: 'prod',
  status: 'active', endpoints: [], tags: [], execution_mode: 'direct',
}

const OPERATION = {
  id: 'op-1', kind: 'access.grant', status: 'success', connection_id: 'c-1',
  actor_type: 'user', actor_id: 'admin@grantor.dev',
  created_at: '2026-07-31T10:00:00Z', finished_at: '2026-07-31T10:00:05Z',
  resolved_at: null, error: '', payload: {},
}

const EVENT = {
  id: 7, occurred_at: '2026-07-31T09:00:00Z', actor_type: 'user',
  actor_id: 'admin@grantor.dev', action: 'credential.shared', connection_id: 'c-1',
  resource_id: null, principal_id: null, account_id: null, operation_id: null,
  result: 'success', metadata: {},
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200, headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('страница «Контроль»', () => {
  beforeEach(() => {
    routeState.search = {}
    routeState.role = 'admin'
    vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/api/v1/connections')) {
        return Promise.resolve(jsonResponse({ connections: [CONNECTION] }))
      }
      if (url.includes('/api/v1/operations')) {
        return Promise.resolve(jsonResponse({ operations: [OPERATION], total: 1 }))
      }
      if (url.includes('/api/v1/audit')) {
        return Promise.resolve(jsonResponse({ events: [EVENT], total: 1 }))
      }
      if (url.includes('/api/v1/drift')) {
        return Promise.resolve(jsonResponse({ findings: [], baselined: [], counts: {} }))
      }
      if (url.includes('/api/v1/approvals')) {
        return Promise.resolve(jsonResponse({ operations: [] }))
      }
      if (url.includes('/api/v1/principals')) {
        return Promise.resolve(jsonResponse({ principals: [] }))
      }
      return Promise.resolve(jsonResponse({}))
    })
  })

  it.each(['approvals', 'approval-count'])('shows a source error instead of an empty attention feed when %s fails', async (source) => {
    routeState.search = { tab: 'attention' }
    const successfulFetch = vi.mocked(globalThis.fetch).getMockImplementation()!
    vi.mocked(globalThis.fetch).mockImplementation((input, init) => {
      const url = String(input)
      if ((source === 'approvals' && url.includes('/api/v1/approvals'))
        || (source === 'approval-count' && url.includes('status=pending_approval'))) {
        return Promise.resolve(new Response(JSON.stringify({ error: 'approval source unavailable' }), {
          status: 503, headers: { 'Content-Type': 'application/json' },
        }))
      }
      return successfulFetch(input, init)
    })
    render(<ControlPage />, { wrapper: Wrapper })
    expect(await screen.findByText('approval source unavailable')).toBeVisible()
    expect(screen.queryByText('Внимание не требуется')).not.toBeInTheDocument()
  })

  it('waits for the approval list before deciding that attention is empty', async () => {
    routeState.search = { tab: 'attention' }
    const successfulFetch = vi.mocked(globalThis.fetch).getMockImplementation()!
    vi.mocked(globalThis.fetch).mockImplementation((input, init) =>
      String(input).includes('/api/v1/approvals')
        ? new Promise<Response>(() => {}) : successfulFetch(input, init))
    render(<ControlPage />, { wrapper: Wrapper })
    expect(await screen.findByText('Загрузка данных…')).toBeInTheDocument()
    expect(screen.queryByText('Внимание не требуется')).not.toBeInTheDocument()
  })

  it('keeps the errors filter usable when only the approval list is unavailable', async () => {
    routeState.search = { tab: 'attention', status: 'errors' }
    const successfulFetch = vi.mocked(globalThis.fetch).getMockImplementation()!
    vi.mocked(globalThis.fetch).mockImplementation((input, init) =>
      String(input).includes('/api/v1/approvals')
        ? Promise.reject(new Error('approval source unavailable')) : successfulFetch(input, init))
    render(<ControlPage />, { wrapper: Wrapper })
    expect(await screen.findByText('Выдача доступа')).toBeVisible()
    expect(screen.queryByText('approval source unavailable')).not.toBeInTheDocument()
  })

  it('монтируется и показывает объединённую ленту', async () => {
    render(<ControlPage />, { wrapper: Wrapper })

    expect(screen.getByRole('heading', { name: 'Контроль' })).toBeInTheDocument()
    // Операция и событие вне операции — в одной ленте.
    expect(await screen.findByText('Выдача доступа')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText(/Credential.*shared/i)).toBeInTheDocument())
    // Подпись подключения в строках берётся из справочника подключений: её
    // читает та самая фабрика useMemo, что и уронила страницу.
    expect(screen.getAllByText(/RabbitMQ \(prod\)/).length).toBeGreaterThan(0)
  })

  it('retries a failed top-level admin credential operation from its detail panel', async () => {
    const failedOperation = {
      ...OPERATION,
      id: 'operation-admin-credential',
      parent_id: null,
      kind: 'connection.admin_credential.rotate',
      status: 'failed',
      retryable: true,
      error: 'connector unavailable',
      finished_at: '2026-07-31T10:00:05Z',
    }
    const retryRequests: string[] = []
    vi.mocked(globalThis.fetch).mockImplementation((input, init) => {
      const url = String(input)
      if (url.endsWith('/api/v1/operations/operation-admin-credential/retry')) {
        retryRequests.push(url)
        expect(init?.method).toBe('POST')
        return Promise.resolve(jsonResponse({
          operation_id: failedOperation.id,
          retried: [failedOperation.id],
          skipped_cancelled: [],
        }))
      }
      if (url.includes('/api/v1/connections')) {
        return Promise.resolve(jsonResponse({ connections: [CONNECTION] }))
      }
      if (url.includes('/api/v1/operations')) {
        return Promise.resolve(jsonResponse({ operations: [failedOperation], total: 1 }))
      }
      if (url.includes('/api/v1/audit')) {
        return Promise.resolve(jsonResponse({ events: [], total: 0 }))
      }
      if (url.includes('/api/v1/drift')) {
        return Promise.resolve(jsonResponse({ findings: [], baselined: [], counts: {} }))
      }
      if (url.includes('/api/v1/approvals')) {
        return Promise.resolve(jsonResponse({ operations: [] }))
      }
      if (url.includes('/api/v1/principals')) {
        return Promise.resolve(jsonResponse({ principals: [] }))
      }
      return Promise.resolve(jsonResponse({}))
    })
    const user = userEvent.setup()
    render(<ControlPage />, { wrapper: Wrapper })

    await user.click(await screen.findByText('Ротация admin credential'))
    await user.click(await screen.findByRole('button', { name: 'Повторить credential operation' }))
    await waitFor(() => expect(retryRequests).toHaveLength(1))
  })
})
