import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { qk } from '../lib/queryKeys'
import type { Connection, Operation } from '../lib/types'

const route = vi.hoisted(() => ({ connectionId: 'connection-1' }))
vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({
    useParams: () => route,
    useSearch: () => ({ tab: 'resources' }),
  }),
  Link: ({ children, to, search }: { children: ReactNode; to: string; search?: Record<string, string> }) => (
    <a href={search === undefined ? to : `${to}?${new URLSearchParams(search)}`}>{children}</a>
  ),
  useNavigate: () => vi.fn(),
}))
vi.mock('../auth/AuthProvider', async (original) => ({
  ...await original<typeof import('../auth/AuthProvider')>(),
  useAuth: () => ({ role: 'admin', email: 'admin@example.invalid', status: 'authenticated' }),
}))
import { ConnectionDetailPage } from './connection-detail'

const connection: Connection = {
  id: 'connection-1', display_name: 'Primary PG', engine: 'postgres', environment: 'test',
  tags: [], endpoints: [], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: '',
  capabilities: ['resource.create.database', 'account.create', 'access.grant', 'postgres.superuser_direct.v1'],
  discovery_config: {}, status: 'active', server_version: '16',
  topology: { system_identifier: '42' }, last_discovery_at: null,
  created_at: '2026-10-12T10:00:00Z', updated_at: '2026-10-12T10:00:00Z',
  postgres_provisioning_authority: {
    status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-10-12T10:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
  },
}
const operation: Operation = {
  id: 'database-root', parent_id: null, idempotency_key: null,
  kind: 'postgres.resource.create.database_with_roles.v2', status: 'running', connection_id: connection.id,
  account_id: null, resource_id: 'database-1', binding_id: null, principal_id: null,
  actor_type: 'user', actor_id: 'admin@example.invalid', approved_by: null, approved_at: null,
  correlation_id: 'correlation-1', created_at: '2026-10-12T10:00:00Z',
  started_at: '2026-10-12T10:00:01Z', finished_at: null,
  updated_at: '2026-10-12T10:00:01Z', error: '', payload: {},
  retry_pending: false,
}
const scopedKeys = (id: string) => [
  qk.connectionAccounts(id, 'summary'), qk.connectionRolePolicies(id), qk.connectionAccess(id),
]
const clients: QueryClient[] = []
function response(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
}
function renderPage(operationRequest: (signal?: AbortSignal | null) => Promise<Response>, override: Partial<Connection> = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  clients.push(client)
  for (const id of ['connection-1', 'connection-2']) {
    for (const key of scopedKeys(id)) client.setQueryData(key, [])
    client.setQueryData(qk.connectionPermissions(id, 'roles'), [])
  }
  const requests: Array<{ path: string; method: string }> = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    const url = new URL(path, 'https://grantor.test')
    const method = init?.method ?? 'GET'
    requests.push({ path, method })
    if (path === '/api/v1/operations/database-root') return operationRequest(init?.signal)
    if (method === 'POST' && path.endsWith('/resources')) {
      return response({ resource_id: 'database-1', operation_id: 'database-root' })
    }
    if (url.pathname.endsWith('/permissions')) {
      expect(url.searchParams.get('category')).toBe('roles')
      return response({ permissions: [] })
    }
    if (path.endsWith('/role-policies')) return response({ policies: [] })
    if (url.pathname.endsWith('/accounts')) {
      expect(url.searchParams.get('view')).toBe('summary')
      expect(url.searchParams.get('include')).toBe('bindings,provisioning')
      return response({ accounts: [] })
    }
    if (path.endsWith('/hba')) return response({ customized: false, rules: [] })
    if (url.pathname.endsWith('/resources')) {
      if (url.searchParams.get('view') !== 'tree') expect(url.searchParams.get('kind')).toBe((override.engine ?? connection.engine) === 'postgres' ? 'database' : null)
      return response({ resources: [] })
    }
    if (url.pathname.match(/\/connections\/connection-[12]$/)) {
      expect(url.searchParams.get('view')).toBe('summary')
      return response({ ...connection, ...override, id: url.pathname.endsWith('2') ? 'connection-2' : connection.id })
    }
    return response({})
  }))
  const view = render(<QueryClientProvider client={client}><ConnectionDetailPage /></QueryClientProvider>)
  return { client, requests, ...view }
}
async function startDatabase() {
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: 'Создать базу' }))
  await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
  await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Создать базу' }))
}
afterEach(() => {
  cleanup()
  clients.splice(0).forEach((client) => client.clear())
  route.connectionId = 'connection-1'
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('database creation projection refresh', () => {
  it('keeps a PLAIN connection without ACL usable for inventory without offering account or access mutations', async () => {
    const user = userEvent.setup()
    const { requests } = renderPage(async () => response(operation), {
      engine: 'kafka', capabilities: ['inventory.resources', 'inventory.accounts'],
      discovery_config: { sasl_mechanism: 'plain', security_protocol: 'sasl_plaintext' },
      topology: { acl_authorizer: 'disabled' },
    })
    expect(await screen.findByText(/Kafka подключён для просмотра топиков/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать учётку' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать доступ' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /^Аккаунты$/ }))
    expect(await screen.findByText('Каталог учёток недоступен')).toBeInTheDocument()
    expect(screen.getByText(/Kafka не публикует список учёток PLAIN/)).toBeInTheDocument()
    expect(requests.filter(({ method }) => method !== 'GET')).toHaveLength(0)
  })

  it('opens each task directly from another tab and preserves the database draft', async () => {
    const user = userEvent.setup()
    const { requests } = renderPage(async () => response(operation))
    await user.click(await screen.findByRole('button', { name: /^Роли$/ }))
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await user.type(screen.getByLabelText(/^Имя базы/), 'draftdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отмена' }))
    await user.click(screen.getByRole('button', { name: /^Аккаунты$/ }))
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('draftdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    await user.keyboard('{Escape}')

    const createAccount = screen.getByRole('button', { name: 'Создать учётку' })
    await user.click(createAccount)
    const local = await screen.findByRole('dialog', { name: 'Создать учётку' })
    await waitFor(() => expect(within(local).getByLabelText(/^Логин в подключении/)).toBeVisible())
    expect(within(local).getByLabelText(/^Логин в подключении/)).toHaveFocus()
    expect(within(local).queryByRole('combobox', { name: 'Аккаунт или пользователь' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(createAccount).toHaveFocus()
    await user.click(screen.getByRole('button', { name: 'Выдать доступ' }))
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Выдать доступ' })).toBeVisible())
    expect(requests.filter((request) => request.method === 'POST')).toHaveLength(0)
  })

  it('preserves the operation through ordinary tab navigation and refreshes its result once', async () => {
    const user = userEvent.setup()
    let current = operation
    const { client, requests } = renderPage(async () => response(current))
    await startDatabase()
    await screen.findByText('Выполняется')
    await user.click(screen.getByRole('button', { name: /^Роли$/ }))
    expect(screen.getByText('Создание базы appdb')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Открыть операцию' })).toHaveAttribute(
      'href', '/control?tab=operations&operation=database-root',
    )
    current = { ...operation, status: 'success', finished_at: '2026-10-12T10:00:05Z' }
    await client.refetchQueries({ queryKey: qk.operation(operation.id) })
    await screen.findByText('Создано')
    await waitFor(() => expect(client.getQueryState(qk.connectionAccounts('connection-1', 'summary'))?.isInvalidated).toBe(true))
    const permissionsAfterSettlement = requests.filter((request) => new URL(request.path, 'https://grantor.test').pathname.endsWith('/permissions')).length
    await user.click(screen.getByRole('button', { name: /^Ресурсы$/ }))
    expect(screen.getByText('Создание базы appdb')).toBeInTheDocument()
    expect(screen.getByText('Создано')).toBeInTheDocument()
    expect(requests.filter((request) => new URL(request.path, 'https://grantor.test').pathname.endsWith('/permissions'))).toHaveLength(permissionsAfterSettlement)
    expect(requests.filter((request) => request.method === 'POST')).toHaveLength(1)
  })

  it.each(['success', 'partial', 'failed', 'cancelled'])('refreshes only the owning connection after %s', async (status) => {
    let current = operation
    const { client, requests } = renderPage(async () => response(current))
    await startDatabase()
    await screen.findByText('Выполняется')
    for (const key of scopedKeys('connection-1')) expect(client.getQueryState(key)?.isInvalidated).toBe(false)
    const resourcesBefore = requests.filter((request) => request.path.includes('/resources?')).length
    const permissionsBefore = requests.filter((request) => new URL(request.path, 'https://grantor.test').pathname.endsWith('/permissions')).length

    current = { ...operation, status, finished_at: '2026-10-12T10:00:05Z' }
    await client.refetchQueries({ queryKey: qk.operation(operation.id) })
    await waitFor(() => {
      for (const key of scopedKeys('connection-1')) expect(client.getQueryState(key)?.isInvalidated).toBe(true)
      expect(requests.filter((request) => request.path.includes('/resources?')).length).toBeGreaterThan(resourcesBefore)
      expect(requests.filter((request) => new URL(request.path, 'https://grantor.test').pathname.endsWith('/permissions')).length).toBeGreaterThan(permissionsBefore)
    })
    for (const key of [...scopedKeys('connection-2'), qk.connectionPermissions('connection-2', 'roles')]) {
      expect(client.getQueryState(key)?.isInvalidated).toBe(false)
    }
    expect(requests.filter((request) => request.method === 'POST')).toEqual([
      { path: '/api/v1/connections/connection-1/resources', method: 'POST' },
    ])
  })

  it('drops the old tracker and aborts its read when navigating to another connection', async () => {
    let signal: AbortSignal | null | undefined
    const { client, rerender, requests } = renderPage((value) => {
      signal = value
      return new Promise<Response>(() => {})
    })
    await startDatabase()
    await waitFor(() => expect(signal).toBeDefined())
    route.connectionId = 'connection-2'
    rerender(<QueryClientProvider client={client}><ConnectionDetailPage /></QueryClientProvider>)
    await screen.findByRole('button', { name: 'Создать базу' })
    expect(signal?.aborted).toBe(true)
    expect(screen.queryByText('Создание базы appdb')).not.toBeInTheDocument()
    expect(requests.filter((request) => request.method === 'POST')).toHaveLength(1)
  })
})
