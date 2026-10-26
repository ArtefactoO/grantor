import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Operation } from '../lib/types'
import { bulkOperationInProgress, effectiveOperationStatus } from '../lib/status'
import { ControlPage, isRetryableDatabaseProvisioningOperation, shouldPollOperation } from './control'

const authState = vi.hoisted(() => ({ role: 'admin' }))

vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({ useSearch: () => ({ operation: 'database-root' }) }),
  Link: ({ children }: { children: ReactNode }) => <>{children}</>,
  useNavigate: () => vi.fn(),
}))

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ role: authState.role, email: 'admin@grantor.dev', status: 'authenticated' }),
  }
})

const root: Operation = {
  id: 'database-root', parent_id: null, idempotency_key: null,
  kind: 'postgres.resource.create.database_with_roles.v2', status: 'partial', connection_id: 'connection-1',
  account_id: null, resource_id: 'database-1', binding_id: null, principal_id: null,
  actor_type: 'user', actor_id: 'admin@grantor.dev', approved_by: null, approved_at: null,
  correlation_id: 'correlation-1', created_at: '2026-08-26T10:00:00Z',
  started_at: '2026-08-26T10:00:01Z', finished_at: '2026-08-26T10:00:05Z',
  updated_at: '2026-08-26T10:00:05Z', error: 'read_write_role_failed', payload: {},
  // Existing children can be done while later durable stages are still pending.
  aggregate_status: 'success', retryable: true,
  database_provisioning: {
    phase: 'read_created', database_created: true, read_created: true, read_write_created: false,
    database_name: 'appdb', read_role: 'r_appdb', read_write_role: 'rw_appdb',
    error_code: 'read_write_role_failed',
  },
}

function response(body: unknown) {
  return new Response(JSON.stringify(body), {
    status: 200, headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

let current = root
let retryRequests: string[] = []

beforeEach(() => {
  authState.role = 'admin'
  current = root
  retryRequests = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    if (url === '/api/v1/operations/database-root/retry') {
      expect(init?.method).toBe('POST')
      retryRequests.push(url)
      current = { ...current, status: 'running', retryable: false, error: '', finished_at: null }
      return response({ operation_id: root.id, retried: [root.id], skipped_cancelled: [] })
    }
    if (url === '/api/v1/operations/database-root') return response(current)
    if (url.includes('/api/v1/operations')) return response({ operations: [current], total: 1 })
    if (url.includes('/api/v1/connections')) return response({ connections: [{
      id: 'connection-1', display_name: 'PostgreSQL test', engine: 'postgres', environment: 'test',
      status: 'active', endpoints: [], tags: [], execution_mode: 'direct',
    }] })
    if (url.includes('/api/v1/audit')) return response({ events: [], total: 0 })
    if (url.includes('/api/v1/drift')) return response({ findings: [], baselined: [], counts: {} })
    if (url.includes('/api/v1/approvals')) return response({ operations: [] })
    if (url.includes('/api/v1/principals')) return response({ principals: [] })
    return response({})
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('durable database-and-role operation', () => {
  it.each(['failed', 'partial'])('resumes a %s root from its saved progress', async (status) => {
    current = { ...root, status }
    const user = userEvent.setup()
    render(<ControlPage />, { wrapper: Wrapper })

    const progress = await screen.findByRole('region', { name: 'Создание базы и ролей' })
    expect(within(progress).getByText('Роль чтения создана')).toBeInTheDocument()
    expect(within(progress).getByText('r_appdb').closest('li')).toHaveTextContent('Создано')
    expect(within(progress).getByText('rw_appdb').closest('li')).toHaveTextContent('Не завершено')
    expect(within(progress).getByText(/Уже созданные объекты сохраняются/)).toBeInTheDocument()
    expect(screen.queryByText('Done')).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    await waitFor(() => expect(retryRequests).toEqual(['/api/v1/operations/database-root/retry']))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument())
    expect(await screen.findAllByText('Running')).not.toHaveLength(0)
  })

  it.each(['operator', 'viewer'])('keeps continuation admin-only for %s', async (role) => {
    authState.role = role
    render(<ControlPage />, { wrapper: Wrapper })
    await screen.findByRole('region', { name: 'Создание базы и ролей' })
    expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
    expect(retryRequests).toEqual([])
  })

  it('requires the root kind, failed/partial status and server retry permission', () => {
    expect(isRetryableDatabaseProvisioningOperation(root)).toBe(true)
    expect(isRetryableDatabaseProvisioningOperation({ ...root, status: 'failed' })).toBe(true)
    for (const status of ['pending', 'running', 'success', 'cancelled']) {
      expect(isRetryableDatabaseProvisioningOperation({ ...root, status })).toBe(false)
    }
    expect(isRetryableDatabaseProvisioningOperation({ ...root, retryable: false })).toBe(false)
    expect(isRetryableDatabaseProvisioningOperation({ ...root, retryable: undefined })).toBe(false)
    expect(isRetryableDatabaseProvisioningOperation({ ...root, parent_id: 'parent' })).toBe(false)
    expect(isRetryableDatabaseProvisioningOperation({ ...root, kind: 'role.policy.create_database' })).toBe(false)
    expect(isRetryableDatabaseProvisioningOperation({ ...root, kind: 'resource.create.prepared_database' })).toBe(false)
  })

  it('uses the durable root status for presentation and polling without changing ordinary bulk behavior', () => {
    const running = { ...root, status: 'running', finished_at: null }
    expect(effectiveOperationStatus(running)).toBe('running')
    expect(shouldPollOperation(running)).toBe(true)
    expect(bulkOperationInProgress(running)).toBe(true)
    expect(shouldPollOperation(root)).toBe(false)
    const bulk = { ...running, kind: 'bulk.account_roles' }
    expect(effectiveOperationStatus(bulk)).toBe('success')
    expect(shouldPollOperation(bulk)).toBe(false)
    expect(bulkOperationInProgress(bulk)).toBe(false)
  })
})
