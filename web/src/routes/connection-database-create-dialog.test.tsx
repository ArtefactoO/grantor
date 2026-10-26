import { useState } from 'react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection } from '../lib/types'
import { CreateDatabaseDialog, DatabaseCreationNotice } from './connection-database-create-dialog'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, to, search }: { children: ReactNode; to: string; search: Record<string, string> }) => (
    <a href={`${to}?${new URLSearchParams(search)}`}>{children}</a>
  ),
}))

const connection: Connection = {
  id: 'connection-1', display_name: 'PG test', engine: 'postgres', environment: 'test',
  tags: [], endpoints: [], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: '',
  capabilities: ['resource.create.database', 'postgres.superuser_direct.v1'], discovery_config: {}, status: 'active',
  server_version: '16', topology: { system_identifier: '7584000000000000001' },
  last_discovery_at: '2026-08-26T10:00:00Z', created_at: '2026-08-26T00:00:00Z',
  updated_at: '2026-08-26T10:00:00Z',
  postgres_provisioning_authority: {
    status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-08-26T10:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:7584000000000000001',
  },
}

function Wrapper({ children }: { children: ReactNode }) {
  const [client] = useState(() => new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  }))
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function response(body: unknown, status = 202): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function mockFetch(mutate = vi.fn(), inventory: unknown = []) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    if (init?.method !== 'POST' && String(input).endsWith('/accounts')) {
      return typeof inventory === 'function' ? inventory(input, init) : response({ accounts: inventory }, 200)
    }
    return mutate(input, init)
  }))
}

function ownerAccount(overrides: Partial<Account> = {}): Account {
  return {
    id: 'owner-1', connection_id: connection.id, principal_id: null, kind: 'group',
    engine_identity: 'app_owner', authentication_scope: '', credential_mode: null,
    vault_path: '', status: 'active', ownership: 'unmanaged',
    attributes: { superuser: false, role_oid: 16391 },
    created_at: connection.created_at, updated_at: connection.updated_at,
    ...overrides,
  }
}

function open(onStarted = vi.fn(), onClose = vi.fn(), currentConnection = connection) {
  const view = render(
    <Wrapper>
      <CreateDatabaseDialog
        connection={currentConnection}
        open
        onClose={onClose}
        onStarted={onStarted}
      />
    </Wrapper>,
  )
  return { onStarted, onClose, ...view }
}

async function enableDefaultRoles(user: ReturnType<typeof userEvent.setup>) {
  const owner = screen.getByLabelText(/^Владелец/) as HTMLInputElement
  if (owner.value === '') await user.type(owner, 'app_owner')
  await user.click(screen.getByRole('checkbox'))
}

describe('CreateDatabaseDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    mockFetch()
  })

  it('posts the database name and reports the started operation', async () => {
    let posted: { path: string; body: unknown } | null = null
    mockFetch(vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = { path: String(input), body: JSON.parse(String(init?.body)) }
      return response({ resource_id: 'resource-1', operation_id: 'operation-1' })
    }))
    const user = userEvent.setup()
    const { onStarted } = open()
    expect(screen.getByRole('checkbox', { name: 'Создать роли чтения и записи вместе с базой' })).not.toBeChecked()

    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/connections/connection-1/resources',
      body: { name: 'appdb', owner: 'app_owner' },
    }))
    expect(onStarted).toHaveBeenCalledWith('operation-1', 'appdb')
  })

  it('requires an existing owner for every PostgreSQL database', async () => {
    let posted: unknown = null
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      posted = JSON.parse(String(init?.body))
      return response({ resource_id: 'resource-1', operation_id: 'operation-1' })
    }))
    const user = userEvent.setup()
    open()

    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), '   ')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))

    expect(await screen.findByText(/Укажите существующего владельца базы/)).toBeVisible()
    expect(posted).toBeNull()
  })

  it('sends the owner when it is set', async () => {
    let posted: unknown = null
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      posted = JSON.parse(String(init?.body))
      return response({ resource_id: 'resource-1', operation_id: 'operation-1' })
    }))
    const user = userEvent.setup()
    open()

    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))

    await waitFor(() => expect(posted).toEqual({ name: 'appdb', owner: 'app_owner' }))
  })

  it('rejects a name with whitespace without calling the API', async () => {
    const fetchSpy = vi.fn()
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    open()

    await user.type(screen.getByLabelText(/^Имя базы/), 'app db')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))

    expect(await screen.findByText(/не должно содержать пробельных символов/)).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  // Отката у создания базы нет — предупреждение обязано быть на виду.
  it('warns that there is no automatic rollback', () => {
    open()
    expect(screen.getByText(/без автоматического отката/)).toBeInTheDocument()
  })

  it.each(['mongodb', 'mysql', 'rabbitmq', 'clickhouse', 'redis', 'kafka'])(
    'keeps default roles unavailable for %s', (engine) => {
      open(vi.fn(), vi.fn(), { ...connection, engine })
      expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    },
  )

  it('posts one durable PG request with exact names, owner and pinned connection identity', async () => {
    const requests: Array<{ path: string; body: unknown }> = []
    mockFetch(vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({ path: String(input), body: JSON.parse(String(init?.body)) })
      return response({ resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true })
    }))
    const user = userEvent.setup()
    const { onStarted, onClose } = open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'project')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await enableDefaultRoles(user)

    expect(screen.getByText('r_project')).toBeInTheDocument()
    expect(screen.getByText('rw_project')).toBeInTheDocument()
    expect(screen.queryByText(/helper|template1/i)).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/creator|owner roles/i)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))

    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('root-operation', 'project', true))
    expect(onClose).toHaveBeenCalledOnce()
    expect(requests).toEqual([{
      path: '/api/v1/connections/connection-1/resources/database-with-roles',
      body: {
        name: 'project', owner: 'app_owner', create_default_roles: true,
        request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
        updated_at: connection.updated_at,
        expected_target_identity: 'postgres:system:7584000000000000001',
      },
    }])
  })

  it('accepts a 60-character database name without shortening either role', async () => {
    const fetchSpy = vi.fn(async () => response({
      resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true,
    }))
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    const { onStarted } = open()
    const name = 'a'.repeat(60)
    fireEvent.change(screen.getByLabelText(/^Имя базы/), { target: { value: name } })
    await enableDefaultRoles(user)
    expect(screen.getByText(`r_${name}`)).toBeInTheDocument()
    expect(screen.getByText(`rw_${name}`)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('root-operation', name, true))
  })

  it.each(['a'.repeat(61), 'база', 'app-data', '9database'])('rejects an unsupported name for the pair: %s', async (name) => {
    const fetchSpy = vi.fn()
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    open()
    fireEvent.change(screen.getByLabelText(/^Имя базы/), { target: { value: name } })
    await enableDefaultRoles(user)
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    expect(await screen.findByText(/^Для пары r_\/rw_ (нужны|имя базы)/)).toBeInTheDocument()
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue(name)
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('disables checked submission without a string cluster identity but preserves legacy creation', async () => {
    const fetchSpy = vi.fn()
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    open(vi.fn(), vi.fn(), { ...connection, topology: {} })
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    expect(screen.getByText(/Сначала синхронизируйте подключение/)).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
    await user.click(screen.getByRole('checkbox'))
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeEnabled()
  })

  it('reuses the complete intent after a lost response, refresh and close/reopen', async () => {
    const requests: unknown[] = []
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(JSON.parse(String(init?.body)))
      if (requests.length === 1) throw new TypeError('response lost')
      return response({ resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true })
    }))
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await enableDefaultRoles(user)
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await screen.findByText(/Результат запроса неизвестен/)
    expect(screen.getByLabelText(/^Имя базы/)).toBeDisabled()
    expect(screen.getByLabelText(/^Владелец/)).toBeDisabled()
    await user.click(screen.getByText('Закрыть'))
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open={false} onStarted={onStarted} onClose={onClose} /></Wrapper>)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={{
      ...connection, updated_at: '2026-08-26T11:00:00Z', topology: { system_identifier: 'different-cluster' },
    }} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    expect(screen.getByRole('checkbox')).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Повторить запрос' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('root-operation', 'appdb', true))
    expect(requests).toHaveLength(2)
    expect(requests[1]).toEqual(requests[0])
  })

  it.each([
    { topology: { system_identifier: '7584000000000000002' } },
    { endpoints: ['postgres://another-cluster:5432'] },
    { tls_config: { insecure_skip_verify: true } },
    { discovery_config: { postgres_database: 'other_maintenance_db' } },
    { environment: 'prod' },
    { execution_mode: 'connector' },
    { vault_admin_path: 'connections/replaced/admin' },
    { admin_credential_mode: 'provided' },
    { engine: 'mysql' },
    { status: 'credential_updating' },
    { capabilities: [] },
  ] satisfies Partial<Connection>[])('refuses a checked draft after its connection target/config changes: %o', async (change) => {
    const fetchSpy = vi.fn()
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)

    view.rerender(<Wrapper><CreateDatabaseDialog connection={{
      ...connection, ...change, updated_at: '2026-08-26T11:00:00Z',
    }} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByRole('checkbox')).toBeChecked()
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    expect(screen.getByText(/Подключение изменилось после открытия формы/)).toBeInTheDocument()
    fireEvent.submit(screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement)
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(onStarted).not.toHaveBeenCalled()
  })

  it('keeps the preview CAS timestamp on a metadata-only refresh instead of resnapshotting', async () => {
    let posted: unknown = null
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      posted = JSON.parse(String(init?.body))
      return response({ error: 'connection updated; refresh required' }, 409)
    }))
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={{
      ...connection, display_name: 'Renamed PG', tags: ['new-tag'],
      topology: { system_identifier: '7584000000000000001', observed_node: 'replica-2' },
      last_discovery_at: '2026-08-26T11:00:00Z', updated_at: '2026-08-26T11:00:00Z',
    }} open onStarted={onStarted} onClose={onClose} /></Wrapper>)

    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await screen.findByText('connection updated; refresh required')
    expect(posted).toEqual({
      name: 'appdb', owner: 'app_owner', create_default_roles: true,
      request_id: expect.any(String), updated_at: connection.updated_at,
      expected_target_identity: 'postgres:system:7584000000000000001',
    })
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(onStarted).not.toHaveBeenCalled()
  })

  it('preserves a stale draft on reopen until its connection context is explicitly reviewed', async () => {
    const requests: Array<Record<string, unknown>> = []
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      return response({ resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true })
    }))
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose, { ...connection, topology: {} })
    await user.type(screen.getByLabelText(/^Имя базы/), 'old_draft')
    await enableDefaultRoles(user)

    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    expect(screen.getByText(/затем обновите контекст/)).toBeInTheDocument()
    fireEvent.submit(screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement)
    expect(requests).toEqual([])

    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open={false} onStarted={onStarted} onClose={onClose} /></Wrapper>)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('old_draft')
    expect(screen.getByRole('checkbox')).toBeChecked()
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Обновить контекст подключения' }))
    await user.clear(screen.getByLabelText(/^Имя базы/))
    await user.type(screen.getByLabelText(/^Имя базы/), 'reviewed_database')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('root-operation', 'reviewed_database', true))
    expect(requests[0].expected_target_identity).toBe('postgres:system:7584000000000000001')
  })

  it('submits once when two submit events arrive before the pending render', async () => {
    let finish!: (value: Response) => void
    const fetchSpy = vi.fn(() => new Promise<Response>((resolve) => { finish = resolve }))
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    const { onStarted } = open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    const form = screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledOnce())
    expect(screen.getByRole('button', { name: 'Отправляем…' })).toBeDisabled()
    finish(response({ resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
  })

  it('preserves the editable draft after validation rejection and uses a new intent for a corrected owner', async () => {
    const requests: Array<Record<string, unknown>> = []
    mockFetch(vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      if (requests.length === 1) return response({ error: 'Owner is not allowed' }, 400)
      return response({ resource_id: 'resource-1', operation_id: 'root-operation', create_default_roles: true })
    }))
    const user = userEvent.setup()
    const { onStarted } = open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'blocked_owner')
    await enableDefaultRoles(user)
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await screen.findByText('Owner is not allowed')
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('blocked_owner')
    expect(screen.getByLabelText(/^Владелец/)).toBeEnabled()
    expect(screen.getByRole('checkbox')).toBeChecked()
    await user.clear(screen.getByLabelText(/^Владелец/))
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
    expect(requests[1].request_id).not.toBe(requests[0].request_id)
    expect(requests[1].owner).toBe('app_owner')
  })

  it('does not fall back to database-only creation when an older API returns 404', async () => {
    const fetchSpy = vi.fn(async (_input: RequestInfo | URL) => response({ error: 'Not found' }, 404))
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    const { onStarted } = open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await screen.findByText('Not found')
    expect(fetchSpy).toHaveBeenCalledOnce()
    expect(fetchSpy.mock.calls[0]?.[0]).toBe('/api/v1/connections/connection-1/resources/database-with-roles')
    expect(onStarted).not.toHaveBeenCalled()
    expect(screen.getByRole('checkbox')).toBeChecked()
  })

  it('leaves an unsubmitted database-and-role draft untouched on close', async () => {
    const fetchSpy = vi.fn()
    mockFetch(fetchSpy)
    const user = userEvent.setup()
    const { onClose, onStarted } = open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    await user.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledOnce()
    expect(onStarted).not.toHaveBeenCalled()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('finds an existing owner in this connection and posts its exact identity', async () => {
    const mutate = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({ resource_id: 'resource-1', operation_id: 'operation-1' }))
    mockFetch(mutate, [ownerAccount({ engine_identity: 'App_Owner' })])
    const user = userEvent.setup()
    open()
    expect(screen.getByText('PG test')).toBeInTheDocument()
    expect(screen.getByText('test')).toBeInTheDocument()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app')
    await user.click(await screen.findByRole('option', { name: /App_Owner/ }))
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('App_Owner')
    expect(screen.getByText('Выбрана существующая роль NOLOGIN.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(mutate).toHaveBeenCalledOnce())
    expect(JSON.parse(String(mutate.mock.calls[0]?.[1]?.body))).toEqual({ name: 'appdb', owner: 'App_Owner' })
  })

  it('does not infer eligibility from omitted SUPERUSER, stale roles or a foreign connection', async () => {
    mockFetch(vi.fn(), [
      ownerAccount({ id: 'login', engine_identity: 'login_owner', kind: 'login' }),
      ownerAccount({ id: 'unknown', engine_identity: 'unknown_owner', attributes: { role_oid: 16391 } }),
      ownerAccount({ id: 'super', engine_identity: 'super_owner', attributes: { superuser: true, role_oid: 16392 } }),
      ownerAccount({ id: 'missing', engine_identity: 'missing_owner', status: 'missing' }),
      ownerAccount({ id: 'foreign', engine_identity: 'foreign_owner', connection_id: 'other' }),
      ownerAccount({ id: 'no-oid', engine_identity: 'no_oid', attributes: { superuser: false } }),
    ])
    const user = userEvent.setup()
    open()
    await user.click(screen.getByLabelText(/^Владелец/))
    expect(await screen.findByRole('option', { name: /login_owner/ })).toBeInTheDocument()
    expect(screen.getAllByRole('option')).toHaveLength(1)
  })

  it('keeps manual owner entry available while the inventory loads', async () => {
    const mutate = vi.fn(async () => response({ resource_id: 'resource-1', operation_id: 'operation-1' }))
    mockFetch(mutate, () => new Promise<Response>(() => {}))
    const user = userEvent.setup()
    open()
    expect(screen.getByText(/Загружаем роли подключения/)).toBeInTheDocument()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'manual_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(mutate).toHaveBeenCalledOnce())
  })

  it('treats malformed inventory as unavailable instead of claiming there are no owners', async () => {
    mockFetch(vi.fn(), [null])
    open()
    expect(await screen.findByText(/Список ролей недоступен/)).toBeInTheDocument()
    expect(screen.queryByText(/В снимке нет подтверждённых кандидатов/)).not.toBeInTheDocument()
  })

  it('reports no search match and supports explicit owner selection from the keyboard', async () => {
    mockFetch(vi.fn(), [ownerAccount()])
    const user = userEvent.setup()
    open()
    await user.type(screen.getByLabelText(/^Владелец/), 'not_found')
    expect(await screen.findByText(/Роль не найдена в снимке/)).toBeInTheDocument()
    await user.clear(screen.getByLabelText(/^Владелец/))
    await user.type(screen.getByLabelText(/^Владелец/), 'app')
    await screen.findByRole('option', { name: /app_owner/ })
    await user.keyboard('{ArrowDown}{Enter}')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })

  it('distinguishes a failed inventory from an empty one and permits manual fallback', async () => {
    const mutate = vi.fn(async () => response({ resource_id: 'resource-1', operation_id: 'operation-1' }))
    mockFetch(mutate, () => response({ error: 'unavailable' }, 503))
    const user = userEvent.setup()
    open()
    expect(await screen.findByText(/Список ролей недоступен/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Обновить список ролей' })).toBeEnabled()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'manual_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(mutate).toHaveBeenCalledOnce())
  })

  it('honours the configured owner allowlist and blocks a selection when it changes', async () => {
    const mutate = vi.fn()
    mockFetch(mutate, [ownerAccount(), ownerAccount({ id: 'other', engine_identity: 'other_owner' })])
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose, { ...connection, discovery_config: { database_create_owners: ['app_owner'] } })
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.click(screen.getByLabelText(/^Владелец/))
    expect(await screen.findByRole('option', { name: /app_owner/ })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /other_owner/ })).not.toBeInTheDocument()
    await user.click(screen.getByRole('option', { name: /app_owner/ }))
    view.rerender(<Wrapper><CreateDatabaseDialog connection={{ ...connection, discovery_config: { database_create_owners: ['other_owner'] } }} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Обновить контекст подключения' }))
    await screen.findByText(/^Выбранная роль больше не подтверждена/)
    fireEvent.submit(screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement)
    expect(await screen.findByRole('alert')).toHaveTextContent(/Выбранная роль больше не подтверждена/)
    expect(mutate).not.toHaveBeenCalled()
  })

  it.each([' Team Owner ', 'app"owner'])('preserves a selected raw identifier without converting it to another role: %s', async (identity) => {
    const mutate = vi.fn()
    mockFetch(mutate, [ownerAccount({ engine_identity: identity })])
    const user = userEvent.setup()
    open()
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.click(screen.getByLabelText(/^Владелец/))
    await user.click(await screen.findByRole('option'))
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue(identity)
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Укажите существующего владельца базы/)
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue(identity)
    expect(mutate).not.toHaveBeenCalled()
  })

  it('preserves an ordinary draft on close/reopen and resets it for another connection', async () => {
    mockFetch()
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await enableDefaultRoles(user)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open={false} onStarted={onStarted} onClose={onClose} /></Wrapper>)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    expect(screen.getByRole('checkbox')).toBeChecked()
    view.rerender(<Wrapper><CreateDatabaseDialog connection={{ ...connection, id: 'connection-2', display_name: 'Other PG', environment: 'prod' }} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('')
    expect(screen.getByRole('checkbox')).not.toBeChecked()
    expect(screen.getByText('Other PG')).toBeInTheDocument()
    expect(screen.getByText('prod')).toBeInTheDocument()
  })

  it.each([false, true])('blocks a preserved draft after a target change until explicit context refresh; default roles=%s', async (withRoles) => {
    const mutate = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response({
      resource_id: 'resource-1', operation_id: 'operation-1', create_default_roles: withRoles,
    }))
    mockFetch(mutate)
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    if (withRoles) await user.click(screen.getByRole('checkbox'))
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open={false} onStarted={onStarted} onClose={onClose} /></Wrapper>)
    const changed = { ...connection, environment: 'prod', endpoints: ['pg-prod:5432'], updated_at: '2026-08-26T11:00:00Z' }
    view.rerender(<Wrapper><CreateDatabaseDialog connection={changed} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    expect(screen.getByRole('button', { name: 'Создать базу' })).toBeDisabled()
    fireEvent.submit(screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement)
    expect(await screen.findByRole('alert')).toHaveTextContent(/Подключение изменилось после открытия формы/)
    expect(mutate).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Обновить контекст подключения' }))
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('appdb')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
    const payload = JSON.parse(String(mutate.mock.calls[0]?.[1]?.body)) as Record<string, unknown>
    expect(payload.owner).toBe('app_owner')
    expect(payload.name).toBe('appdb')
    if (withRoles) expect(payload.updated_at).toBe(changed.updated_at)
  })

  it('clears a confirmed submitted draft before reopening the form', async () => {
    mockFetch(vi.fn(async () => response({ resource_id: 'resource-1', operation_id: 'operation-1' })))
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const view = open(onStarted, onClose)
    await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
    await user.type(screen.getByLabelText(/^Владелец/), 'app_owner')
    await user.click(screen.getByRole('button', { name: 'Создать базу' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open={false} onStarted={onStarted} onClose={onClose} /></Wrapper>)
    view.rerender(<Wrapper><CreateDatabaseDialog connection={connection} open onStarted={onStarted} onClose={onClose} /></Wrapper>)
    expect(screen.getByLabelText(/^Имя базы/)).toHaveValue('')
    expect(screen.getByLabelText(/^Владелец/)).toHaveValue('')
  })

  it('announces queued work with its root operation link, not completed creation', () => {
    mockFetch(vi.fn(() => new Promise<Response>(() => {})))
    render(<Wrapper><DatabaseCreationNotice operationId="root-operation" databaseName="appdb" createDefaultRoles onSettled={vi.fn()} onClose={vi.fn()} /></Wrapper>)
    expect(screen.getByRole('status')).toHaveTextContent('В очереди')
    expect(screen.getByRole('link', { name: 'Открыть операцию' })).toHaveAttribute('href', '/control?tab=operations&operation=root-operation')
    expect(screen.queryByText(/успешно создан|готовы/i)).not.toBeInTheDocument()
  })

  it.each(['', 'a'.repeat(64), 'владелец', 'app-owner', '1owner'])(
    'requires a portable existing owner for the pair: %s', async (owner) => {
      const fetchSpy = vi.fn()
      mockFetch(fetchSpy)
      const user = userEvent.setup()
      open()
      await user.type(screen.getByLabelText(/^Имя базы/), 'appdb')
      fireEvent.change(screen.getByLabelText(/^Владелец/), { target: { value: owner } })
      await user.click(screen.getByRole('checkbox'))
      expect(screen.getByLabelText(/^Владелец/)).toBeRequired()
      fireEvent.submit(screen.getByLabelText(/^Имя базы/).closest('form') as HTMLFormElement)
      expect(await screen.findByText(/^Укажите существующего владельца базы:/)).toBeInTheDocument()
      expect(screen.getByLabelText(/^Владелец/)).toHaveValue(owner)
      expect(fetchSpy).not.toHaveBeenCalled()
    },
  )
})
