import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection } from '../lib/types'
import { qk } from '../lib/queryKeys'

const route = vi.hoisted(() => ({ connectionId: 'connection-1', tab: 'accounts' }))
vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({ useParams: () => ({ connectionId: route.connectionId }), useSearch: () => ({ tab: route.tab }) }),
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
  useNavigate: () => vi.fn(),
}))

import { AuthProvider } from '../auth/AuthProvider'
import { ConnectionDetailPage } from './connection-detail'

const account: Account = {
  id: 'account-1', principal_id: null, connection_id: 'connection-1', kind: 'login',
  engine_identity: 'qa_stored_account', authentication_scope: '', credential_mode: null, vault_path: '',
  status: 'active', ownership: 'unmanaged', attributes: {}, bindings: [], bindings_projection: 'roles',
  access_summary: { direct_objects: 770, direct_bindings: 870, unmanaged_direct_bindings: 870,
    unmanaged_dangerous_direct_bindings: 0, readonly_direct_bindings: 0 }, created_at: '', updated_at: '',
}
const connection: Connection = {
  id: 'connection-1', display_name: 'Local stored inventory', engine: 'postgres', environment: 'test',
  tags: [], endpoints: [], execution_mode: 'connector', tls_config: {}, admin_credential_mode: 'provided',
  vault_admin_path: '', capabilities: [], discovery_config: {}, status: 'active', server_version: '16',
  topology: { postgres_object_acl_version: 1 }, last_discovery_at: null, created_at: '', updated_at: '',
}
function response(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } })
}
function deferred<T>() {
  let resolve!: (value: T) => void
  return { promise: new Promise<T>(accept => { resolve = accept }), resolve: (value: T) => resolve(value) }
}

const clients: QueryClient[] = []
const unexpected: string[] = []
let originalLocation: Location

function renderPage(cachedAccounts?: Account[]) {
  const session = deferred<Response>(), header = deferred<Response>(), accounts = deferred<Response>()
  const requests: URL[] = []
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0, gcTime: 0, refetchOnWindowFocus: false } } })
  clients.push(client)
  if (cachedAccounts !== undefined) client.setQueryData(qk.connectionAccounts(route.connectionId, 'summary'), cachedAccounts)
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'https://grantor.test')
    requests.push(url)
    expect(init?.method ?? 'GET').toBe('GET')
    if (url.pathname === '/auth/me') return session.promise
    if (url.pathname === '/api/v1/connections/connection-1') {
      expect(url.searchParams.get('view')).toBe('summary')
      return header.promise
    }
    if (url.pathname === '/api/v1/connections/connection-1/accounts') {
      expect(url.searchParams.get('view')).toBe('summary')
      expect(url.searchParams.get('include')).toBe('bindings,provisioning')
      return accounts.promise
    }
    if (url.pathname === '/api/v1/connections/connection-1/permissions') {
      expect(url.searchParams.get('category')).toBe('roles')
      return response({ permissions: [] })
    }
    if (url.pathname === '/api/v1/connections/connection-1/resources') {
      expect(url.searchParams.get('kind') === 'database' || url.searchParams.get('view') === 'tree').toBe(true)
      return response({ resources: [] })
    }
    if (url.pathname === '/api/v1/connections/connection-1/hba') return response({ supported: true, customized: true, rules: [], uncovered_accounts: [], truncated: false })
    if (url.pathname === '/api/v1/connections/connection-1/role-policies') return response({ policies: [] })
    if (url.pathname === '/api/v1/principals') return response({ principals: [] })
    unexpected.push(url.pathname + url.search)
    throw new Error(`Unexpected fixture request: ${url.pathname}${url.search}`)
  }))
  render(<QueryClientProvider client={client}><AuthProvider><ConnectionDetailPage /></AuthProvider></QueryClientProvider>)
  return { session, header, accounts, client, requests,
    accountRequests: () => requests.filter(request => request.pathname.endsWith('/accounts')),
    allowSession: () => session.resolve(response({ email: 'qa@example.invalid', role: 'viewer', csrf_token: 'local-fixture' })),
  }
}

beforeEach(() => {
  route.tab = 'accounts'
  unexpected.length = 0
  originalLocation = window.location
  Object.defineProperty(window, 'location', { configurable: true,
    value: { ...originalLocation, pathname: '/connections/connection-1', href: 'https://grantor.test/connections/connection-1' } })
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({ matches: false, media: query, onchange: null,
    addEventListener: vi.fn(), removeEventListener: vi.fn(), addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn() })))
})
afterEach(() => {
  cleanup()
  clients.splice(0).forEach(client => client.clear())
  Object.defineProperty(window, 'location', { configurable: true, value: originalLocation })
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  expect(unexpected).toEqual([])
})

describe('Connection accounts critical path', () => {
  it('starts one summary-account GET before the header resolves, after the session gate', async () => {
    const fixture = renderPage()
    expect(fixture.requests.map(request => request.pathname)).toEqual(['/auth/me'])
    expect(fixture.accountRequests()).toHaveLength(0)
    await act(async () => fixture.allowSession())
    await waitFor(() => expect(fixture.accountRequests()).toHaveLength(1))
    expect(fixture.requests.some(request => request.pathname === '/api/v1/connections/connection-1')).toBe(true)
    await act(async () => fixture.accounts.resolve(response({ accounts: [account] })))
    await waitFor(() => expect(fixture.client.getQueryData(qk.connectionAccounts(connection.id, 'summary'))).toEqual([account]))
    expect(screen.queryByText(account.engine_identity)).not.toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Аккаунты подключения' })).not.toBeInTheDocument()
    await act(async () => fixture.header.resolve(response(connection)))
    expect(await screen.findByText(account.engine_identity)).toBeInTheDocument()
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)) })
    expect(fixture.accountRequests()).toHaveLength(1)
  })

  it('reuses the in-flight account request when the header resolves first', async () => {
    const fixture = renderPage()
    await act(async () => fixture.allowSession())
    await waitFor(() => expect(fixture.accountRequests()).toHaveLength(1))
    await act(async () => fixture.header.resolve(response(connection)))
    await screen.findByText(connection.display_name)
    expect(screen.queryByText(account.engine_identity)).not.toBeInTheDocument()
    expect(fixture.accountRequests()).toHaveLength(1)
    await act(async () => fixture.accounts.resolve(response({ accounts: [account] })))
    expect(await screen.findByText(account.engine_identity)).toBeInTheDocument()
    expect(fixture.accountRequests()).toHaveLength(1)
  })

  it.each([
    { status: 401, message: 'unauthorized' },
    { status: 403, message: 'connection scope denied' },
    { status: 404, message: 'unknown connection' },
  ])('hides prefetched rows when the header fails with $status', async ({ status, message }) => {
    const fixture = renderPage()
    await act(async () => fixture.allowSession())
    await waitFor(() => expect(fixture.accountRequests()).toHaveLength(1))
    await act(async () => fixture.accounts.resolve(response({ accounts: [account] })))
    await waitFor(() => expect(fixture.client.getQueryData(qk.connectionAccounts(connection.id, 'summary'))).toEqual([account]))
    await act(async () => fixture.header.resolve(response({ error: message }, status)))
    expect(await screen.findByText(message)).toBeInTheDocument()
    expect(screen.queryByText(account.engine_identity)).not.toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Аккаунты подключения' })).not.toBeInTheDocument()
    expect(fixture.accountRequests()).toHaveLength(1)
    expect(fixture.client.getQueryCache().find({ queryKey: qk.connectionAccounts(connection.id, 'summary'), exact: true })?.isActive()).toBe(false)
    if (status === 401) expect(window.location.href).toBe('/auth/login')
  })

  it('shows cached stored rows behind a confirmed header while their shared query refreshes', async () => {
    const fixture = renderPage([account])
    await act(async () => fixture.allowSession())
    await waitFor(() => expect(fixture.accountRequests()).toHaveLength(1))
    expect(screen.queryByText(account.engine_identity)).not.toBeInTheDocument()
    await act(async () => fixture.header.resolve(response(connection)))
    expect(await screen.findByText(account.engine_identity)).toBeInTheDocument()
    expect(fixture.client.getQueryState(qk.connectionAccounts(connection.id, 'summary'))?.fetchStatus).toBe('fetching')
    expect(fixture.accountRequests()).toHaveLength(1)
    const updated = { ...account, engine_identity: 'qa_updated_stored_account' }
    await act(async () => fixture.accounts.resolve(response({ accounts: [updated] })))
    expect(await screen.findByText(updated.engine_identity)).toBeInTheDocument()
    expect(screen.queryByText(account.engine_identity)).not.toBeInTheDocument()
    expect(fixture.accountRequests()).toHaveLength(1)
  })

  it.each(['roles', 'resources', 'hba'])('does not start account preloading on the %s tab', async tab => {
    route.tab = tab
    const fixture = renderPage()
    await act(async () => fixture.allowSession())
    await waitFor(() => expect(fixture.requests.some(request => request.pathname === '/api/v1/connections/connection-1')).toBe(true))
    await act(async () => fixture.header.resolve(response(connection)))
    await screen.findByText(connection.display_name)
    expect(fixture.accountRequests()).toHaveLength(0)
  })
})
