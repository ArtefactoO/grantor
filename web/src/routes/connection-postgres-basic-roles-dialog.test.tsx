import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection, PostgresRolePolicyTemplate, Resource, ResourceTreeItem } from '../lib/types'
import { PostgresBasicRolesDialog } from './connection-postgres-basic-roles-dialog'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, search }: { children: ReactNode; search: { operation: string } }) =>
    <a href={`/control?operation=${search.operation}`}>{children}</a>,
}))

const connection: Connection = {
  id: 'c1', display_name: 'Postgres', engine: 'postgres', environment: 'test',
  tags: [], endpoints: ['postgres.invalid:5432'], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: 'connections/c1/admin',
  capabilities: ['discover', 'role.policy.create', 'postgres.superuser_direct.v1'], discovery_config: { future: { keep: true } },
  status: 'active', server_version: '16', topology: { system_identifier: '7429012345678901234' }, last_discovery_at: '2026-08-26T10:00:00Z',
  created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00.123Z',
  postgres_provisioning_authority: {
    status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-08-26T10:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:7429012345678901234',
  },
}
const database: Resource = {
  id: 'db1', connection_id: 'c1', kind: 'database', name: 'appdb', external_id: 'db:appdb',
  parent_id: null, canonical_path: 'appdb', status: 'observed', ownership: 'unmanaged',
  attributes: { owner: 'app_owner' }, fingerprint: 'database-fingerprint', observed_at: '', created_at: '', updated_at: '',
}
const tree: ResourceTreeItem[] = [database, {
  id: 'schema1', connection_id: 'c1', parent_id: 'db1', kind: 'schema', name: 'public', status: 'observed', ownership: 'unmanaged',
}]

function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function fixtures(options: { roleExists?: boolean; policyBlocked?: boolean } = {}) {
  let current = structuredClone(connection)
  const calls: { url: string; method: string; body: unknown }[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    const body = init?.body === undefined ? null : JSON.parse(String(init.body))
    calls.push({ url, method, body })
    if (url === '/api/v1/connections/c1' && method === 'GET') return response(current)
    if (url === '/api/v1/connections/c1' && method === 'PATCH') {
      current = { ...current, discovery_config: body.discovery_config, updated_at: 'new-version' }
      return response({ ...current, operation_id: 'discovery-op' }, 202)
    }
    if (url === '/api/v1/connections/c1/resources?view=tree') return response({ resources: tree })
    if (url === '/api/v1/resources/db1') return response(database)
    if (url === '/api/v1/connections/c1/role-policies') {
      const config = current.discovery_config as { postgres_role_policy_templates: PostgresRolePolicyTemplate[] }
      return response({ policies: (config.postgres_role_policy_templates ?? []).map((template) => ({
        template_key: template.key, desired_spec: template, managed: false, exact: false,
        status: 'missing', apply_supported: !options.policyBlocked, transition_active: false,
        blocked_reason: options.policyBlocked ? 'superuser_required' : '',
        observed_fingerprint: `absent-${template.key}`, version: 1,
        observed_summary: { missing: [], extra: [], role: { exists: options.roleExists ?? false } },
      })) })
    }
    if (url.endsWith('/create') && method === 'POST') return response({ operation_id: url.includes('read-write') ? 'rw-op' : 'r-op' }, 202)
    throw new Error(`Unexpected request: ${method} ${url}`)
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, fetchMock }
}

function renderDialog(isAdmin = true, initial = connection) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } } })
  const onClose = vi.fn()
  const onStarted = vi.fn()
  const result = render(<QueryClientProvider client={client}>
    <PostgresBasicRolesDialog connection={initial} isAdmin={isAdmin} open onClose={onClose} onStarted={onStarted} />
  </QueryClientProvider>)
  return { ...result, onClose, onStarted }
}

async function chooseDatabase() {
  await waitFor(() => expect(screen.getByRole('combobox', { name: 'База данных' })).toBeEnabled())
  await userEvent.click(screen.getByRole('combobox', { name: 'База данных' }))
  await userEvent.click(screen.getByRole('option', { name: 'appdb' }))
  await screen.findByText('r_appdb')
}

describe('PostgresBasicRolesDialog', () => {
  beforeEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })
  afterEach(() => cleanup())

  it('asks only for a database and closes an untouched selection without confirmation', async () => {
    const { calls } = fixtures()
    const { onClose } = renderDialog()
    expect(screen.getByRole('button', { name: 'Создать r_ / rw_' })).toBeDisabled()
    await chooseDatabase()
    expect(screen.getByText('rw_appdb')).toBeInTheDocument()
    expect(screen.getByText('app_owner')).toBeInTheDocument()
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByText('owner_roles')).not.toBeInTheDocument()
    expect(screen.queryByText('creator_roles')).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledOnce()
    expect(calls.every((call) => call.method === 'GET')).toBe(true)
  })

  it('prepares and queues both create-only roles from one click, without assigning any account', async () => {
    const { calls } = fixtures()
    const { onStarted, onClose } = renderDialog()
    await chooseDatabase()
    const create = screen.getByRole('button', { name: 'Создать r_ / rw_' })
    fireEvent.click(create)
    fireEvent.click(create)
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(['r_appdb', 'rw_appdb'], ['r-op', 'rw-op'], false))
    expect(onClose).toHaveBeenCalledOnce()
    const writes = calls.filter((call) => call.method !== 'GET')
    expect(writes.map((call) => [call.method, call.url])).toEqual([
      ['PATCH', '/api/v1/connections/c1'],
      ['POST', '/api/v1/connections/c1/role-policies/pg-appdb-read/create'],
      ['POST', '/api/v1/connections/c1/role-policies/pg-appdb-read-write/create'],
    ])
    const config = (writes[0].body as { discovery_config: { future: unknown; postgres_role_policy_templates: PostgresRolePolicyTemplate[] } }).discovery_config
    expect(config.future).toEqual({ keep: true })
    expect(config.postgres_role_policy_templates.map((template) => [template.owner_roles, template.creator_roles]))
      .toEqual([[['app_owner'], ['app_owner']], [['app_owner'], ['app_owner']]])
    expect(writes[1].body).toMatchObject({ version: 1, observed_fingerprint: 'absent-pg-appdb-read', confirm: true })
  })

  it.each([
    [{ roleExists: true }, /Одноимённая роль уже существует/],
    [{ policyBlocked: true }, /Создание роли заблокировано проверкой базы/],
  ] as const)('shows a blocker instead of claiming the roles were created: %j', async (options, message) => {
    const { calls } = fixtures(options)
    const { onStarted, onClose } = renderDialog()
    await chooseDatabase()
    await userEvent.click(screen.getByRole('button', { name: 'Создать r_ / rw_' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(message))
    expect(onStarted).not.toHaveBeenCalled()
    expect(onClose).not.toHaveBeenCalled()
    expect(calls.filter((call) => call.method === 'POST')).toEqual([])
    expect(screen.getByRole('link', { name: 'Синхронизация: открыть операцию' })).toHaveAttribute('href', '/control?operation=discovery-op')
  })

  it('does not let a viewer prepare a pair or fetch the owner through this form', () => {
    const { fetchMock } = fixtures()
    renderDialog(false)
    expect(screen.getByRole('button', { name: 'Создать r_ / rw_' })).toBeDisabled()
    expect(screen.getByRole('combobox', { name: 'База данных' })).toBeDisabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('blocks incomplete database discovery rather than silently creating public-only rights', async () => {
    const { calls } = fixtures()
    renderDialog(true, { ...connection, topology: { skipped_databases: [{ name: 'appdb', error: 'unavailable' }] } })
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'База данных' })).toBeEnabled())
    await userEvent.click(screen.getByRole('combobox', { name: 'База данных' }))
    await userEvent.click(screen.getByRole('option', { name: 'appdb' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent(/Объекты этой базы не удалось обнаружить/))
    expect(screen.getByRole('button', { name: 'Создать r_ / rw_' })).toBeDisabled()
    expect(calls.every((call) => call.method === 'GET')).toBe(true)
  })
})
