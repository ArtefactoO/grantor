import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Binding, Connection, Operation, Permission, Principal } from '../lib/types'
import { qk } from '../lib/queryKeys'
import { expiryToTimestamp, GrantAccessDrawer } from './principal-access-drawer'

const auth = vi.hoisted(() => ({ role: 'admin' }))

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'admin@example.com', role: auth.role, csrfToken: 'csrf' }),
  }
})

const connection: Connection = {
  id: 'connection-1',
  display_name: 'postgres-test',
  engine: 'postgres',
  environment: 'test',
  tags: [],
  endpoints: [],
  execution_mode: 'direct',
  tls_config: {},
  admin_credential_mode: 'vault',
  vault_admin_path: '',
  capabilities: ['account.create', 'access.grant', 'postgres.superuser_direct.v1'],
  discovery_config: {},
  status: 'active',
  server_version: '16',
  topology: {},
  last_discovery_at: null,
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
  postgres_provisioning_authority: {
    status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-07-22T00:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
  },
}

const principal: Principal = {
  id: 'principal-1',
  type: 'human',
  display_name: 'Тестовый пользователь',
  external_provider: '',
  external_subject: '',
  status: 'active',
  attributes: {},
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
}

const permissions: Permission[] = [
  {
    id: 'permission-read',
    connection_id: connection.id,
    engine: 'postgres',
    external_id: 'readAnyDatabase',
    name: 'readAnyDatabase',
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: false,
    attributes: {},
    created_at: '2026-07-22T00:00:00Z',
    updated_at: '2026-07-22T00:00:00Z',
    normalized: {
      category: 'role', action: '', resource: 'readAnyDatabase', scope: '',
      dangerous: false, danger_reason: '', details: null, raw: 'readAnyDatabase',
    },
  },
  {
    id: 'permission-admin',
    connection_id: connection.id,
    engine: 'postgres',
    external_id: 'dbAdminAnyDatabase',
    name: 'dbAdminAnyDatabase',
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: true,
    attributes: {},
    created_at: '2026-07-22T00:00:00Z',
    updated_at: '2026-07-22T00:00:00Z',
    normalized: {
      category: 'role', action: '', resource: 'dbAdminAnyDatabase', scope: '',
      dangerous: true, danger_reason: 'широкие полномочия', details: null, raw: 'dbAdminAnyDatabase',
    },
  },
]

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('GrantAccessDrawer from a connection', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    auth.role = 'admin'
  })

  it('adds a global user to the fixed connection with multiple roles', async () => {
    let posted: unknown = null
    const invalidateSpy = vi.spyOn(QueryClient.prototype, 'invalidateQueries')
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      if (path === `/api/v1/principals/${principal.id}/access`) {
        posted = JSON.parse(String(init?.body))
        return response({
          operation_id: 'operation-1',
          children: [{ connection_id: connection.id }],
        })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const onStarted = vi.fn()
    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={onStarted}
        />
      </Wrapper>,
    )

    expect(screen.queryByLabelText('Поиск подключения')).not.toBeInTheDocument()
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    await user.click(await screen.findByText(principal.display_name))

    await user.click(await screen.findByRole('combobox', { name: `Роли для ${connection.display_name}` }))
    await user.click(await screen.findByRole('checkbox', { name: 'readAnyDatabase' }))
    await user.click(screen.getByRole('checkbox', { name: 'dbAdminAnyDatabase' }))
    await user.click(screen.getByRole('checkbox', { name: 'Я понимаю, что выдаю опасные права' }))
    await user.click(screen.getByRole('button', { name: 'Выдать доступ' }))

    await waitFor(() => expect(posted).toEqual({
      items: [
        { connection_id: connection.id, permission_id: 'permission-read' },
        { connection_id: connection.id, permission_id: 'permission-admin' },
      ],
      confirm: true,
    }))
    expect(onStarted).toHaveBeenCalledWith('operation-1', principal.display_name)
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: qk.connectionAccounts(connection.id),
    })
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: qk.connectionAccess(connection.id),
    })
  })

  it('does not offer a role already assigned to the user account', async () => {
    let posted: unknown = null
    const existingAccount: Account = {
      id: 'account-1',
      principal_id: principal.id,
      connection_id: connection.id,
      kind: 'login',
      engine_identity: 'test',
      authentication_scope: '',
      credential_mode: 'existing_vault_ref',
      vault_path: 'principals/principal-1/environments/test/credential',
      status: 'active',
      ownership: 'managed',
      attributes: {},
      bindings: [{
        id: 'binding-read',
        account_id: 'account-1',
        permission_definition_id: 'permission-read',
        scope_resource_id: null,
        source: 'service',
        desired_state: 'present',
        observed_state: 'present',
        observed_effective: true,
        status: 'synced',
        expires_at: null,
        created_at: '2026-07-22T00:00:00Z',
        updated_at: '2026-07-22T00:00:00Z',
      }],
      created_at: '2026-07-22T00:00:00Z',
      updated_at: '2026-07-22T00:00:00Z',
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [existingAccount] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      if (path === `/api/v1/principals/${principal.id}/access`) {
        posted = JSON.parse(String(init?.body))
        return response({ operation_id: 'operation-2', children: [{ connection_id: connection.id }] })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    await user.click(await screen.findByText(principal.display_name))
    await user.click(await screen.findByRole('combobox', { name: `Роли для ${connection.display_name}` }))
    expect(await screen.findByRole('option', { name: /readAnyDatabase.*Уже назначена/ })).toHaveAttribute(
      'aria-disabled',
      'true',
    )
    await user.click(screen.getByRole('checkbox', { name: 'dbAdminAnyDatabase' }))
    await user.click(screen.getByRole('checkbox', { name: 'Я понимаю, что выдаю опасные права' }))
    await user.click(screen.getByRole('button', { name: 'Выдать доступ' }))
    await waitFor(() => expect(posted).toEqual({
      items: [{ connection_id: connection.id, permission_id: 'permission-admin' }],
      confirm: true,
    }))
  })

  // Блокировка по одному desired_state держала «Уже назначена» навсегда:
  // после провала применения роль нельзя было выдать повторно, хотя именно
  // повторная выдача её и чинит (предикат — зеркало 409 API).
  it('offers a failed role for a repeat grant', async () => {
    const brokenAccount: Account = {
      id: 'account-1',
      principal_id: principal.id,
      connection_id: connection.id,
      kind: 'login',
      engine_identity: 'test',
      authentication_scope: '',
      credential_mode: 'existing_vault_ref',
      vault_path: 'principals/principal-1/environments/test/credential',
      status: 'active',
      ownership: 'managed',
      attributes: {},
      bindings: [{
        id: 'binding-read',
        account_id: 'account-1',
        permission_definition_id: 'permission-read',
        scope_resource_id: null,
        source: 'service',
        desired_state: 'present',
        observed_state: 'unknown',
        observed_effective: true,
        status: 'failed',
        expires_at: null,
        created_at: '2026-07-22T00:00:00Z',
        updated_at: '2026-07-22T00:00:00Z',
      }],
      created_at: '2026-07-22T00:00:00Z',
      updated_at: '2026-07-22T00:00:00Z',
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [brokenAccount] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    await user.click(await screen.findByText(principal.display_name))
    await user.click(await screen.findByRole('combobox', { name: `Роли для ${connection.display_name}` }))
    const option = await screen.findByRole('option', { name: /readAnyDatabase/ })
    expect(option).not.toHaveAttribute('aria-disabled', 'true')
    expect(option).not.toHaveTextContent('Уже назначена')
  })

  it('keeps a deleted global account selectable and opens restore from the same picker', async () => {
    const tombstone = {
      id: 'account-deleted',
      principal_id: principal.id,
      connection_id: connection.id,
      kind: 'login',
      engine_identity: 'test',
      authentication_scope: '',
      credential_mode: 'existing_vault_ref',
      vault_path: 'principal/test/dev',
      status: 'deleted',
      ownership: 'managed',
      attributes: {},
      bindings: [],
      created_at: '2026-07-22T00:00:00Z',
      updated_at: '2026-07-22T00:00:00Z',
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [tombstone] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(await screen.findByRole('heading', { name: 'Выдать доступ' })).toBeInTheDocument()
    expect(screen.queryByText('Удалённые аккаунты')).not.toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    const deletedOption = await screen.findByRole('option', {
      name: /Тестовый пользователь.*Удалённый аккаунт: test.*Deleted/,
    })
    expect(deletedOption).toBeEnabled()
    await user.click(deletedOption)

    expect(await screen.findByRole('dialog', { name: 'Восстановить аккаунт - test' })).toBeInTheDocument()
    expect(screen.getByText('Использовать пароль пользователя')).toBeInTheDocument()
  })

  it('keeps grant access focused on users without nested account creation', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    expect(await screen.findByRole('option', { name: principal.display_name })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: /Локальный аккаунт/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Создать учётку' })).not.toBeInTheDocument()
    expect(screen.queryByPlaceholderText('svc_reporting')).not.toBeInTheDocument()
  })

  it('blocks implicit PostgreSQL account creation while keeping the drawer browsable', async () => {
    const insufficient: Connection = {
      ...connection,
      capabilities: ['access.grant'],
      postgres_provisioning_authority: {
        ...connection.postgres_provisioning_authority!,
        status: 'insufficient', reason: 'superuser_required',
      },
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [insufficient] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) return response({ accounts: [] })
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) return response({ permissions })
      throw new Error(`unexpected fetch ${path}`)
    }))
    const user = userEvent.setup()
    render(<Wrapper><GrantAccessDrawer open fixedConnectionId={connection.id} onClose={vi.fn()} onStarted={vi.fn()} /></Wrapper>)
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    await user.click(await screen.findByRole('option', { name: /Тестовый пользователь/ }))
    expect(await screen.findByText(/не является PostgreSQL SUPERUSER/)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Выдать доступ' })).toBeDisabled()
  })

  it('does not mix deleted principals into the account picker', async () => {
    const deletedDuplicate: Principal = {
      ...principal,
      id: 'principal-deleted',
      status: 'deleted',
    }
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === '/api/v1/principals') {
        return response({ principals: [deletedDuplicate, principal] })
      }
      if (path === '/api/v1/connections') return response({ connections: [connection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [] })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) {
        return response({ permissions })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))

    const user = userEvent.setup()
    render(
      <Wrapper>
        <GrantAccessDrawer
          open
          fixedConnectionId={connection.id}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    expect(await screen.findAllByRole('option', { name: principal.display_name })).toHaveLength(1)
  })
})

const localAccount: Account = {
  id: 'local-account', principal_id: null, connection_id: connection.id, kind: 'login',
  engine_identity: 'reports_local', authentication_scope: '', credential_mode: 'provided',
  vault_path: 'accounts/local-account/credential', status: 'active', ownership: 'managed',
  attributes: {}, bindings: [], created_at: connection.created_at, updated_at: connection.updated_at,
}

describe('GrantAccessDrawer existing local accounts', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    auth.role = 'admin'
  })

  function renderLocalAccess({
    target = localAccount,
    targetConnection = connection,
    operations = [],
    bindingsError = false,
    roleResponse,
    principalResponse,
  }: {
    target?: Account
    targetConnection?: Connection
    operations?: Array<Pick<Operation, 'id' | 'account_id' | 'kind' | 'status'>>
    bindingsError?: boolean
    roleResponse?: Promise<Response>
    principalResponse?: Promise<Response>
  } = {}) {
    const posts: Array<{ path: string; body: unknown }> = []
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (init?.method === 'POST') {
        posts.push({ path, body: JSON.parse(String(init.body)) })
        if (path === `/api/v1/accounts/${target.id}/roles`) return roleResponse ?? response({ operation_id: 'local-grant-operation', children: [] })
        if (path === `/api/v1/principals/${principal.id}/access` && principalResponse !== undefined) return principalResponse
        throw new Error(`unexpected mutation ${path}`)
      }
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/connections') return response({ connections: [targetConnection] })
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) return response({ accounts: [target] })
      if (path === `/api/v1/connections/${connection.id}/permissions?category=roles`) return response({ permissions })
      if (path === `/api/v1/accounts/${target.id}/bindings?category=roles`) {
        if (bindingsError) throw new TypeError('unavailable')
        return response({ bindings: [] satisfies Binding[] })
      }
      if (path === `/api/v1/operations?connection_id=${connection.id}&status=pending,pending_approval,running`) return response({ operations })
      throw new Error(`unexpected fetch ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    const onStarted = vi.fn()
    const onClose = vi.fn()
    render(<Wrapper><GrantAccessDrawer open fixedConnectionId={connection.id} onClose={onClose} onStarted={onStarted} /></Wrapper>)
    return { fetchMock, posts, onStarted, onClose }
  }

  async function chooseLocal(user: ReturnType<typeof userEvent.setup>) {
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    await user.type(screen.getByRole('combobox', { name: 'Поиск учётки или пользователя' }), localAccount.engine_identity)
    await user.click(await screen.findByRole('option', { name: /reports_local.*Существующая локальная учётка/ }))
  }

  it('grants a local account in the same drawer with the existing account role delta API', async () => {
    const user = userEvent.setup()
    const { posts, onStarted, fetchMock } = renderLocalAccess()
    await chooseLocal(user)
    expect(screen.getAllByRole('dialog')).toHaveLength(1)
    expect(screen.queryByRole('textbox', { name: 'Логин в подключении' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: 'Срок действия' })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('checkbox', { name: /readAnyDatabase/ }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    await waitFor(() => expect(posts).toEqual([{
      path: '/api/v1/accounts/local-account/roles',
      body: { add_permission_ids: ['permission-read'], remove_binding_ids: [] },
    }]))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('local-grant-operation', localAccount.engine_identity))
    expect(fetchMock.mock.calls.some(([input]) =>
      /\/(credential|restore|provisioning)(\/|$)/.test(new URL(String(input), 'http://localhost').pathname),
    )).toBe(false)
  })

  it('cancels the local selection without a mutation', async () => {
    const user = userEvent.setup()
    const { posts, onClose } = renderLocalAccess()
    await chooseLocal(user)
    await user.click(await screen.findByRole('checkbox', { name: /readAnyDatabase/ }))
    await user.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledOnce()
    expect(posts).toEqual([])
  })

  it('locks the chooser and dismissal until the local HTTP acknowledgement settles', async () => {
    let finish!: (response: Response) => void
    const roleResponse = new Promise<Response>((resolve) => { finish = resolve })
    const user = userEvent.setup()
    const { posts, onStarted, onClose } = renderLocalAccess({ roleResponse })
    await chooseLocal(user)
    await user.click(await screen.findByRole('checkbox', { name: /readAnyDatabase/ }))
    const apply = screen.getByRole('button', { name: 'Применить изменения' })
    await user.click(apply)
    const chooser = screen.getByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' })
    expect(chooser).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Отмена' })).toBeDisabled()
    await user.click(chooser)
    expect(screen.queryByRole('option', { name: principal.display_name })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: 'Закрыть' }))
    await user.click(apply)
    expect(onClose).not.toHaveBeenCalled()
    expect(onStarted).not.toHaveBeenCalled()
    expect(posts).toHaveLength(1)
    await act(async () => { finish(response({ operation_id: 'local-grant-operation', children: [] })) })
    await waitFor(() => expect(onStarted).toHaveBeenCalledExactlyOnceWith('local-grant-operation', localAccount.engine_identity))
    expect(posts).toEqual([{
      path: '/api/v1/accounts/local-account/roles',
      body: { add_permission_ids: ['permission-read'], remove_binding_ids: [] },
    }])
    await waitFor(() => expect(chooser).toBeEnabled())
  })

  it('unlocks after a local request rejection while preserving the selected role draft', async () => {
    let fail!: (error: Error) => void
    const roleResponse = new Promise<Response>((_resolve, reject) => { fail = reject })
    const user = userEvent.setup()
    const { posts, onStarted, onClose } = renderLocalAccess({ roleResponse })
    await chooseLocal(user)
    await user.click(await screen.findByRole('checkbox', { name: /readAnyDatabase/ }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    const chooser = screen.getByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' })
    expect(chooser).toBeDisabled()
    await act(async () => { fail(new Error('target temporarily unavailable')) })
    await waitFor(() => expect(chooser).toBeEnabled())
    expect(screen.getByRole('checkbox', { name: /readAnyDatabase/ })).toBeChecked()
    expect(screen.getByRole('button', { name: 'Применить изменения' })).toBeEnabled()
    expect(screen.getByText(/сеть недоступна или API не отвечает/)).toBeInTheDocument()
    expect(onStarted).not.toHaveBeenCalled()
    expect(posts).toHaveLength(1)
    await user.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('locks the same chooser and dismissal during an existing global grant request', async () => {
    let finish!: (response: Response) => void
    const principalResponse = new Promise<Response>((resolve) => { finish = resolve })
    const user = userEvent.setup()
    const { posts, onStarted, onClose } = renderLocalAccess({ principalResponse })
    const chooser = await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' })
    await user.click(chooser)
    await user.click(await screen.findByRole('option', { name: principal.display_name }))
    await user.click(await screen.findByRole('combobox', { name: `Роли для ${connection.display_name}` }))
    await user.click(await screen.findByRole('checkbox', { name: 'readAnyDatabase' }))
    await user.click(screen.getByRole('button', { name: 'Выдать доступ' }))
    expect(chooser).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Отмена' })).toBeDisabled()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: 'Закрыть' }))
    expect(onClose).not.toHaveBeenCalled()
    expect(posts).toHaveLength(1)
    await act(async () => { finish(response({ operation_id: 'global-grant-operation', children: [{ connection_id: connection.id }] })) })
    await waitFor(() => expect(onStarted).toHaveBeenCalledExactlyOnceWith('global-grant-operation', principal.display_name))
    expect(posts).toEqual([{
      path: `/api/v1/principals/${principal.id}/access`,
      body: { items: [{ connection_id: connection.id, permission_id: 'permission-read' }] },
    }])
    await waitFor(() => expect(chooser).toBeEnabled())
  })

  it('retains the dangerous role confirmation in the embedded editor', async () => {
    const user = userEvent.setup()
    const { posts } = renderLocalAccess()
    await chooseLocal(user)
    await user.click(await screen.findByRole('checkbox', { name: /dbAdminAnyDatabase/ }))
    expect(screen.getByRole('button', { name: 'Применить изменения' })).toBeDisabled()
    await user.click(screen.getByRole('checkbox', { name: 'Я понимаю, что выдаю опасное право' }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    await waitFor(() => expect(posts[0]).toEqual({
      path: '/api/v1/accounts/local-account/roles',
      body: { add_permission_ids: ['permission-admin'], remove_binding_ids: [], confirm: true },
    }))
  })

  it('keeps dangerous local permissions unavailable to an operator', async () => {
    auth.role = 'operator'
    const user = userEvent.setup()
    const { posts } = renderLocalAccess()
    await chooseLocal(user)
    expect(await screen.findByRole('checkbox', { name: /dbAdminAnyDatabase/ })).toBeDisabled()
    expect(posts).toEqual([])
  })

  it.each([
    { case: 'provisioning', target: { ...localAccount, status: 'provisioning' } },
    { case: 'missing', target: { ...localAccount, status: 'missing' } },
    { case: 'connection admin', target: { ...localAccount, attributes: { connection_admin: true } } },
    { case: 'unsupported capability', targetConnection: { ...connection, capabilities: [] } },
    { case: 'inactive connection', targetConnection: { ...connection, status: 'degraded' } },
    { case: 'readonly role', role: 'viewer' },
  ])('blocks an ineligible local choice: $case', async ({ target, targetConnection, role }) => {
    auth.role = role ?? 'admin'
    const user = userEvent.setup()
    const { posts } = renderLocalAccess({ target, targetConnection })
    await user.click(await screen.findByRole('combobox', { name: 'Учётка или пользователь для выдачи доступа' }))
    const option = await screen.findByRole('option', { name: /reports_local/ })
    expect(option).toHaveAttribute('aria-disabled', 'true')
    expect(posts).toEqual([])
  })

  it('blocks a local lifecycle operation that is still active', async () => {
    const user = userEvent.setup()
    const { posts } = renderLocalAccess({ operations: [{ id: 'rotation', account_id: localAccount.id, kind: 'credential.rotate', status: 'pending' }] })
    await chooseLocal(user)
    await user.click(await screen.findByRole('checkbox', { name: /readAnyDatabase/ }))
    expect(screen.getByText(/Есть незавершённая операция/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Применить изменения' })).toBeDisabled()
    expect(posts).toEqual([])
  })

  it('fails closed when the current bindings cannot be read', async () => {
    const user = userEvent.setup()
    const { posts } = renderLocalAccess({ bindingsError: true })
    await chooseLocal(user)
    expect(await screen.findByText(/Не удалось проверить состояние учётки/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Применить изменения' })).not.toBeInTheDocument()
    expect(posts).toEqual([])
  })
})

// Срок действия: пресеты считаются от момента отправки, произвольная дата
// берётся как локальное время оператора, «бессрочно» не шлёт поле вовсе.
describe('expiryToTimestamp', () => {
  const now = new Date('2026-07-30T12:00:00Z')

  it('maps presets and custom dates to RFC 3339', () => {
    expect(expiryToTimestamp('none', '', now)).toBeNull()
    expect(expiryToTimestamp('24', '', now)).toBe('2026-07-31T12:00:00.000Z')
    expect(expiryToTimestamp('168', '', now)).toBe('2026-08-06T12:00:00.000Z')
    const custom = expiryToTimestamp('custom', '2026-08-01T10:30', now)
    expect(custom).not.toBeNull()
    expect(new Date(custom as string).getTime()).toBe(new Date('2026-08-01T10:30').getTime())
    expect(expiryToTimestamp('custom', '', now)).toBeNull()
    expect(expiryToTimestamp('custom', 'not-a-date', now)).toBeNull()
  })
})
