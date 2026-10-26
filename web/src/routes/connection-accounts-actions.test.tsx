import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection } from '../lib/types'
import { AccountsTab } from './connection-accounts'
import type { AccountsTabProps } from './connection-accounts'

const auth = vi.hoisted(() => ({ role: 'operator' as 'operator' | 'viewer' }))

vi.mock('../auth/AuthProvider', async (importOriginal) => ({
  ...await importOriginal<typeof import('../auth/AuthProvider')>(),
  useAuth: () => ({ email: 'operator@example.com', role: auth.role, csrfToken: 'csrf' }),
}))
vi.mock('@tanstack/react-router', async (importOriginal) => ({
  ...await importOriginal<typeof import('@tanstack/react-router')>(),
  useNavigate: () => vi.fn(),
}))
vi.mock('@formkit/auto-animate/react', () => ({ useAutoAnimate: () => [vi.fn(), vi.fn()] }))
vi.mock('../components/operation-progress-notice', () => ({
  OperationProgressNotice: ({ label }: { label: string }) => <span role="status">{label}</span>,
}))

const connection: Connection = {
  id: 'connection-1', display_name: 'postgres-test', engine: 'postgres', environment: 'test',
  tags: [], endpoints: [], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: '',
  capabilities: ['account.create', 'access.grant', 'postgres.superuser_direct.v1'],
  discovery_config: {}, status: 'active', server_version: '16', topology: {},
  last_discovery_at: null, created_at: '2026-10-12T00:00:00Z', updated_at: '2026-10-12T00:00:00Z',
  postgres_provisioning_authority: {
    status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-10-12T00:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
  },
}

const account: Account = {
  id: 'account-1', principal_id: null, connection_id: connection.id, kind: 'login',
  engine_identity: 'service_reporting_with_a_long_identity', authentication_scope: '',
  credential_mode: null, vault_path: '', status: 'active', ownership: 'unmanaged',
  attributes: {}, bindings: [], created_at: '2026-10-12T00:00:00Z', updated_at: '2026-10-12T00:00:00Z',
}

function response(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
}

function renderAccounts(accounts: Account[] = [], props: Partial<AccountsTabProps> = {}) {
  let createdAccount: unknown = null
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    const url = new URL(path, 'https://grantor.test')
    if (url.pathname === `/api/v1/connections/${connection.id}/accounts`) {
      expect(url.searchParams.get('view')).toBe('summary')
      expect(url.searchParams.get('include')).toBe('bindings,provisioning')
      return response({ accounts })
    }
    if (url.pathname === `/api/v1/connections/${connection.id}/resources`) {
      expect(url.searchParams.get('kind')).toBe((props.connection ?? connection).engine === 'postgres' ? 'database' : null)
      return response({ resources: [] })
    }
    if (url.pathname === `/api/v1/connections/${connection.id}/permissions`) {
      expect(url.searchParams.get('category')).toBe('roles')
      return response({ permissions: [] })
    }
    if (path === '/api/v1/principals') return response({ principals: [] })
    if (path === '/api/v1/connections') return response({ connections: [connection] })
    if (path === '/api/v1/accounts' && init?.method === 'POST') {
      createdAccount = JSON.parse(String(init.body))
      return response({ operation_id: 'create-operation' })
    }
    if (path === `/api/v1/accounts/${account.id}/bindings?category=roles`) return response({ bindings: [] })
    throw new Error(`unexpected request: ${path}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={client}>
      <AccountsTab connection={connection} permissions={[]} permissionsById={new Map()} {...props} />
    </QueryClientProvider>,
  )
  return { fetchMock, createdAccount: () => createdAccount }
}

beforeEach(() => {
  auth.role = 'operator'
  vi.stubGlobal('matchMedia', vi.fn((query: string) => ({
    matches: false, media: query, onchange: null,
    addEventListener: vi.fn(), removeEventListener: vi.fn(),
    addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
  })))
})

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('AccountsTab task entry points', () => {
  it.each([false, true])('explains the unavailable PLAIN user catalog without offering broker mutations (shared header=%s)', async (sharedHeader) => {
    const plain: Connection = {
      ...connection, engine: 'kafka', display_name: 'kafka-test',
      capabilities: ['inventory.resources', 'inventory.accounts'],
      discovery_config: { sasl_mechanism: 'plain', security_protocol: 'sasl_plaintext' },
      topology: { acl_authorizer: 'disabled' },
    }
    renderAccounts([], {
      connection: plain,
      ...(sharedHeader ? { externalActions: { onCreateAccount: vi.fn(), onGrantAccess: vi.fn() } } : {}),
    })
    expect(await screen.findByText('Каталог учёток недоступен')).toBeInTheDocument()
    expect(screen.getByText(/Kafka не публикует список учёток PLAIN/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать учётку' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать доступ' })).not.toBeInTheDocument()
    expect(screen.queryByText(/Создайте учётку или выдайте доступ/)).not.toBeInTheDocument()
  })

  it.each([
    { capability: 'account.create', available: 'Создать учётку', unavailable: 'Выдать доступ' },
    { capability: 'access.grant', available: 'Выдать доступ', unavailable: 'Создать учётку' },
  ])('offers only the effective $capability action', async ({ capability, available, unavailable }) => {
    renderAccounts([], { connection: { ...connection, capabilities: [capability] } })
    expect(await screen.findByRole('button', { name: available })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: unavailable })).not.toBeInTheDocument()
  })

  it('creates a local account directly without choosing a global user or granting roles', async () => {
    const user = userEvent.setup()
    const { fetchMock, createdAccount } = renderAccounts()
    await user.click(await screen.findByRole('button', { name: 'Создать учётку' }))
    const drawer = await screen.findByRole('dialog', { name: 'Создать учётку' })
    expect(within(drawer).queryByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' })).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Выдать доступ' })).not.toBeInTheDocument()
    await user.type(within(drawer).getByLabelText('Логин в подключении'), 'reports_bot')
    await user.click(within(drawer).getByRole('button', { name: 'Создать учётку' }))
    await waitFor(() => expect(createdAccount()).toEqual({
      connection_id: connection.id, engine_identity: 'reports_bot', credential: { mode: 'generated' },
    }))
    expect(await screen.findByRole('status')).toHaveTextContent('Создание учётки reports_bot')
    expect(fetchMock.mock.calls.some(([input]) => String(input).includes('/principals/') && String(input).endsWith('/access'))).toBe(false)
  })

  it('opens grant access directly and offers no nested local account creation', async () => {
    const user = userEvent.setup()
    renderAccounts([account])
    await user.click(await screen.findByRole('button', { name: 'Выдать доступ' }))
    const drawer = await screen.findByRole('dialog', { name: 'Выдать доступ' })
    expect(within(drawer).getByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' })).toBeInTheDocument()
    expect(screen.queryByRole('dialog', { name: 'Создать учётку' })).not.toBeInTheDocument()
  })

  it.each([
    { state: 'empty', accounts: [] },
    { state: 'populated', accounts: [account] },
  ])('lets shared header actions own both entry points in a $state directory', async ({ accounts }) => {
    const externalActions = { onCreateAccount: vi.fn(), onGrantAccess: vi.fn() }
    renderAccounts(accounts, { externalActions })
    if (accounts.length === 0) {
      expect(await screen.findByText('Аккаунтов нет')).toBeInTheDocument()
      expect(screen.getByText('Создайте учётку или выдайте доступ с помощью кнопок наверху.')).toBeInTheDocument()
    } else {
      await screen.findByRole('table', { name: 'Аккаунты подключения' })
    }
    expect(screen.queryByRole('button', { name: 'Создать учётку' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать доступ' })).not.toBeInTheDocument()
    expect(externalActions.onCreateAccount).not.toHaveBeenCalled()
    expect(externalActions.onGrantAccess).not.toHaveBeenCalled()
  })

  it('keeps mutation entry points unavailable to a viewer', async () => {
    auth.role = 'viewer'
    renderAccounts([account])
    await screen.findByRole('table', { name: 'Аккаунты подключения' })
    expect(screen.queryByRole('button', { name: 'Создать учётку' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Выдать доступ' })).not.toBeInTheDocument()
  })

  it('keeps one keyboard-selectable row with its identity, status and access', async () => {
    const user = userEvent.setup()
    renderAccounts([account])
    const table = await screen.findByRole('table', { name: 'Аккаунты подключения' })
    const row = within(table).getByText(account.engine_identity).closest('tr') as HTMLElement
    expect(within(table).getAllByText(account.engine_identity)).toHaveLength(1)
    expect(within(row).getByText('Active')).toBeInTheDocument()
    expect(within(row).getByText('Нет ролей')).toBeInTheDocument()
    expect(within(table).getByRole('columnheader', { name: 'Прямые права' })).toBeInTheDocument()
    expect(row).toHaveAttribute('tabindex', '0')
    row.focus()
    await user.keyboard('{Enter}')
    expect(await screen.findByRole('dialog', { name: `Детали: ${account.engine_identity}` })).toBeInTheDocument()
    expect(row).toHaveAttribute('aria-selected', 'true')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog', { name: `Детали: ${account.engine_identity}` })).not.toBeInTheDocument())
    expect(row).toHaveFocus()
  })

  it('reads provisioning states from the list projection without requesting each account', async () => {
    const states = [
      { state: 'running', label: 'Есть незавершенная операция' },
      { state: 'verification_required', label: 'Нужна проверка входа' },
      { state: 'failed', label: 'Ошибка создания' },
    ] as const
    const projectedAccounts: Account[] = states.map(({ state }, index) => ({
      ...account, id: `pending-${index}`, engine_identity: `pending_${index}`, status: 'provisioning',
      provisioning_summary: { state, operation_id: `operation-${index}` },
    }))
    projectedAccounts.push({ ...account, status: 'provisioning' })
    const { fetchMock } = renderAccounts(projectedAccounts)
    const table = await screen.findByRole('table', { name: 'Аккаунты подключения' })
    for (const { label } of states) expect(within(table).getByText(label)).toBeInTheDocument()
    expect(within(table).getByText('Результат не подтвержден')).toBeInTheDocument()
    expect(fetchMock.mock.calls.filter(([input]) => String(input).startsWith('/api/v1/accounts/'))).toHaveLength(0)
    expect(fetchMock.mock.calls.filter(([input]) => String(input).includes('/accounts?'))).toHaveLength(1)
  })
})
