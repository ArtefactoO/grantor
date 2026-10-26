import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection, Operation, Permission, PrincipalDetail, Resource } from '../lib/types'
import { AccountDetailPanel } from './connection-account-panel'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, ...props }: { children: ReactNode }) => <a {...props}>{children}</a>,
}))

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'admin@example.com', role: 'admin', csrfToken: 'csrf' }),
  }
})

vi.mock('./connection-account-dialogs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./connection-account-dialogs')>()
  return {
    ...actual,
    ManageRolesDrawer: ({
      open,
      onStarted,
    }: {
      open: boolean
      onStarted: (
        operationId: string,
        changes: { added: string[]; removed: string[] },
      ) => void
    }) =>
      open ? (
        <button
          type="button"
          onClick={() =>
            onStarted('danger-operation-id', {
              added: ['superuser'],
              removed: [],
            })}
        >
          Завершить изменение ролей
        </button>
      ) : null,
  }
})

const account: Account = {
  id: 'account-1',
  principal_id: null,
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'reports_bot',
  authentication_scope: '',
  credential_mode: 'existing_vault_ref',
  vault_path: 'accounts/reports-bot',
  status: 'active',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

const connection: Connection = {
  id: 'connection-1',
  display_name: 'postgres-prod',
  engine: 'postgres',
  environment: 'prod',
  tags: [],
  endpoints: [],
  execution_mode: 'direct',
  tls_config: {},
  admin_credential_mode: 'vault',
  vault_admin_path: '',
  capabilities: [],
  discovery_config: {},
  status: 'active',
  server_version: '16',
  topology: {},
  last_discovery_at: null,
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

const permission: Permission = {
  id: 'permission-1',
  connection_id: connection.id,
  engine: 'postgres',
  external_id: 'superuser',
  name: 'superuser',
  scope_resource_id: null,
  assignable: true,
  status: 'observed',
  dangerous: true,
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
    normalized: {
      category: 'role', action: '', resource: 'superuser', scope: '',
      dangerous: true, danger_reason: 'широкие полномочия', details: null, raw: 'superuser',
    },
}

const operation: Operation = {
  id: 'danger-operation-id',
  parent_id: null,
  idempotency_key: null,
  kind: 'access.grant',
  status: 'pending_approval',
  connection_id: connection.id,
  principal_id: null,
  account_id: account.id,
  resource_id: null,
  binding_id: 'binding-1',
  payload: {},
  error: '',
  actor_type: 'user',
  actor_id: 'admin@example.com',
  approved_by: null,
  approved_at: null,
  correlation_id: 'correlation-1',
  created_at: '2026-07-20T00:00:00Z',
  started_at: null,
  finished_at: null,
  updated_at: '2026-07-20T00:00:00Z',
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('AccountDetailPanel grant source card', () => {
  it.each(['login', 'group'])('shows failed creation recovery instead of ordinary actions for a provisioning %s', async (kind) => {
    const pendingAccount = {
      ...account,
      kind,
      status: 'provisioning',
      engine_identity: kind === 'group' ? 'rw_external_events' : 'service_external_events',
    }
    const rolePermission = {
      ...permission,
      name: pendingAccount.engine_identity,
      external_id: `role:${pendingAccount.engine_identity}`,
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [] })
      if (path === '/api/v1/accounts/account-1/provisioning') return response({
        account_id: account.id,
        updated_at: account.updated_at,
        state: 'failed',
        operation_id: 'failed-create',
        operation_kind: kind === 'group' ? 'role.create' : 'account.create',
        operation_status: 'failed',
        recoverable: true,
      })
      throw new Error(`unexpected request: ${path}`)
    })
    render(
      <Wrapper>
        <AccountDetailPanel
          account={pendingAccount}
          connection={connection}
          permissions={[rolePermission]}
          permissionsById={new Map([[rolePermission.id, rolePermission]])}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )
    expect(await screen.findByText('Создание не удалось')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Восстановить из кластера' })).toBeInTheDocument()
    expect(screen.queryByText('Provisioning')).not.toBeInTheDocument()
    for (const name of [
      'Управление ролями', 'Получить учётные данные', 'Ротировать пароль', 'Удалить',
      'Назначить пользователям', 'Связать с пользователем', 'Взять под управление',
    ]) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
  })

  it('shows only databases directly owned by the selected PostgreSQL account', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation(() => ({
      matches: true,
      media: '(min-width: 1024px)',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [] })
      throw new Error(`unexpected request: ${path}`)
    })
    const database = (id: string, owner: string): Resource => ({
      id,
      connection_id: connection.id,
      parent_id: null,
      kind: 'database',
      external_id: `database:${id}`,
      name: id,
      canonical_path: id,
      attributes: { owner },
      fingerprint: id,
      observed_at: '2026-08-25T00:00:00Z',
      status: 'observed',
      ownership: 'unmanaged',
      created_at: '2026-08-25T00:00:00Z',
      updated_at: '2026-08-25T00:00:00Z',
    })

    render(
      <Wrapper>
        <AccountDetailPanel
          account={account}
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map([
            ['owned', database('analytics', account.engine_identity)],
            ['role-owned', database('team_data', 'reporting_team')],
          ])}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    const ownership = await screen.findByLabelText('Базы во владении')
    expect(ownership).toHaveTextContent('analytics')
    expect(ownership).not.toHaveTextContent('team_data')
  })

  it.each(['managed', 'unmanaged'])('treats a %s group as a role without account ownership metadata', async (ownership) => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
      matches: query === '(min-width: 1024px)',
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    const groupAccount: Account = {
      ...account,
      id: 'group-account',
      kind: 'group',
      engine_identity: 'report_reader',
      credential_mode: null,
      vault_path: '',
      ownership,
    }
    const groupPermission: Permission = {
      ...permission,
      id: 'group-permission',
      name: groupAccount.engine_identity,
      external_id: `role:${groupAccount.engine_identity}`,
      dangerous: false,
    }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/group-account/bindings?category=roles') {
        return response({ bindings: [] })
      }
      if (path === '/api/v1/principals') return response({ principals: [] })
      throw new Error(`unexpected request: ${path}`)
    })

    render(
      <Wrapper>
        <AccountDetailPanel
          account={groupAccount}
          connection={connection}
          permissions={[groupPermission]}
          permissionsById={new Map([[groupPermission.id, groupPermission]])}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(
      screen.getByRole('button', { name: 'Назначить пользователям' }),
    ).toBeInTheDocument()
    expect(screen.queryByText(/^(Managed|Unmanaged)$/)).not.toBeInTheDocument()
    if (ownership === 'unmanaged') {
      expect(screen.getByRole('button', { name: 'Взять под управление' }))
        .toBeInTheDocument()
    } else {
      expect(screen.queryByRole('button', { name: 'Взять под управление' }))
        .not.toBeInTheDocument()
    }
    expect(screen.queryByText('Пользователь')).not.toBeInTheDocument()
    expect(screen.queryByText('credential mode')).not.toBeInTheDocument()
    expect(screen.queryByText('vault path')).not.toBeInTheDocument()
    expect(screen.queryByText(/Групповая роль:/)).not.toBeInTheDocument()
  })

  it.each([
    { kind: 'login', ownership: 'managed', label: 'Managed' },
    { kind: 'login', ownership: 'unmanaged', label: 'Unmanaged' },
    { kind: 'service', ownership: 'managed', label: 'Managed' },
    { kind: 'service', ownership: 'unmanaged', label: 'Unmanaged' },
  ])('keeps the $ownership badge for $kind accounts', async ({ kind, ownership, label }) => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [] })
      throw new Error(`unexpected request: ${path}`)
    })
    render(
      <Wrapper>
        <AccountDetailPanel
          account={{ ...account, kind, ownership }}
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(await screen.findByText(label)).toBeInTheDocument()
  })

  it('reports the started operation to the shared account-list tracker', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
      matches: query === '(min-width: 1024px)',
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    const user = userEvent.setup()
    const onNotice = vi.fn()
    const onOperationStarted = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [] })
      if (path === '/api/v1/operations/danger-operation-id') return response(operation)
      throw new Error(`unexpected request: ${path}`)
    })

    const view = render(
      <Wrapper>
        <AccountDetailPanel
          account={account}
          connection={connection}
          permissions={[permission]}
          permissionsById={new Map([[permission.id, permission]])}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={onNotice}
          onOperationStarted={onOperationStarted}
        />
      </Wrapper>,
    )

    await user.click(screen.getByRole('button', { name: 'Управление ролями' }))
    await user.click(screen.getByRole('button', { name: 'Завершить изменение ролей' }))

    expect(screen.getAllByText('reports_bot').length).toBeGreaterThan(0)
    expect(onNotice).not.toHaveBeenCalled()
    expect(onOperationStarted).toHaveBeenCalledWith(
      'danger-operation-id',
      'Изменение ролей · +1 / −0: reports_bot',
      'access',
    )

    expect(screen.queryByText('Назначение роли superuser')).not.toBeInTheDocument()
    expect(view.container.querySelector('[data-slot="operation-progress-slot"]')).toBeNull()
  })

  it('starts link-and-manage for an existing metadata-linked account', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
      matches: query === '(min-width: 1024px)',
      media: query,
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    const linkedAccount: Account = {
      ...account,
      principal_id: 'principal-1',
      ownership: 'unmanaged',
      credential_mode: null,
      vault_path: '',
    }
    const capableConnection: Connection = {
      ...connection,
      capabilities: ['credential.rotate', 'credential.prove'],
    }
    const principal: PrincipalDetail = {
      id: 'principal-1',
      type: 'human',
      display_name: 'Анна Кутина',
      external_provider: 'ldap',
      external_subject: 'akutikina',
      external_identity_status: 'active',
      external_identity_checked_at: null,
      external_identity_status_changed_at: null,
      status: 'active',
      attributes: {},
      accounts: [linkedAccount],
      created_at: '2026-07-20T00:00:00Z',
      updated_at: '2026-07-20T00:00:00Z',
    }
    let posted: unknown = null
    const onNotice = vi.fn()
    const onOperationStarted = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/principals/principal-1/credentials') {
        return response({
          credentials: [{ environment: 'prod', connections: 1, configured: false }],
        })
      }
      if (path === '/api/v1/accounts/account-1/link-and-manage') {
        posted = JSON.parse(String(init?.body))
        return response({
          account_id: linkedAccount.id,
          principal_id: principal.id,
          environment: 'prod',
          operation_id: 'managed-link-operation',
        }, 202)
      }
      throw new Error(`unexpected request: ${path}`)
    })

    render(
      <Wrapper>
        <AccountDetailPanel
          account={linkedAccount}
          connection={capableConnection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={onNotice}
          onOperationStarted={onOperationStarted}
        />
      </Wrapper>,
    )

    const user = userEvent.setup()
    expect(screen.queryByRole('button', { name: 'Взять под управление' })).not.toBeInTheDocument()
    await user.click(await screen.findByRole('button', { name: 'Перевести под управление' }))
    expect((await screen.findAllByText('Анна Кутина')).length).toBeGreaterThan(1)
    await user.click(await screen.findByRole('button', { name: 'Связать и управлять' }))

    await waitFor(() => expect(posted).toEqual({
      principal_id: 'principal-1',
      credential: { mode: 'generated' },
    }))
    expect(onNotice).not.toHaveBeenCalled()
    expect(onOperationStarted).toHaveBeenCalledWith(
      'managed-link-operation',
      'Связь аккаунта reports_bot с пользователем Анна Кутина',
      'account',
    )
  })

  it('rotates the shared user credential through the server-driven choice', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation(() => ({
      matches: true,
      media: '(min-width: 1024px)',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    // Аккаунт сидит на общем пароле пользователя: ротация «на месте» увела бы
    // его с общего секрета, поэтому бэкенд отвечает 409 с контекстом выбора,
    // а панель показывает диалог. Вариант «общий пароль» уходит в ротацию
    // принципала и попадает в общий трекер операций.
    const linkedAccount: Account = {
      ...account,
      principal_id: 'principal-1',
      credential_mode: 'existing_vault_ref',
      vault_path: 'principals/principal-1/environments/prod/credential',
    }
    const principal: PrincipalDetail = {
      id: 'principal-1',
      type: 'human',
      display_name: 'Тестовый',
      external_provider: '',
      external_subject: '',
      external_identity_status: 'active',
      external_identity_checked_at: null,
      external_identity_status_changed_at: null,
      status: 'active',
      attributes: {},
      accounts: [linkedAccount],
      created_at: '2026-07-20T00:00:00Z',
      updated_at: '2026-07-20T00:00:00Z',
    }
    let postedPath = ''
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/accounts/account-1/rotate') {
        return response({
          error: 'account shares the credential of its principal',
          code: 'shared_credential_requires_choice',
          shared_credential: {
            principal_id: 'principal-1',
            principal_display_name: 'Тестовый',
            environment: 'prod',
            affected_accounts: 2,
            affected_connections: [
              { connection_id: 'connection-1', display_name: 'postgres-prod', account_id: 'account-1' },
              { connection_id: 'connection-2', display_name: 'redis-prod', account_id: 'account-2' },
            ],
            confirm_threshold: 0,
            requires_confirm: false,
          },
        }, 409)
      }
      if (path === '/api/v1/principals/principal-1/rotate?environment=prod') {
        postedPath = path
        return response({ operation_id: 'principal-rotate-op', children: [] }, 202)
      }
      throw new Error(`unexpected request: ${path}`)
    })
    const onOperationStarted = vi.fn()
    render(
      <Wrapper>
        <AccountDetailPanel
          account={linkedAccount}
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={onOperationStarted}
        />
      </Wrapper>,
    )

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Ротировать пароль' }))
    const dialog = await screen.findByRole('dialog', { name: /Ротация пароля: reports_bot/ })
    expect(dialog).toHaveTextContent('окружении')
    await user.click(within(dialog).getByText('Ротировать общий пароль'))
    await user.click(within(dialog).getByRole('button', { name: 'Ротировать' }))

    await waitFor(() => expect(postedPath).toBe(
      '/api/v1/principals/principal-1/rotate?environment=prod',
    ))
    expect(onOperationStarted).toHaveBeenCalledWith(
      'principal-rotate-op',
      'ротация общего пароля пользователя (аккаунтов: 2)',
      'account',
    )
  })

  it('permanently purges a deleted tombstone after an explicit confirmation', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation(() => ({
      matches: true,
      media: '(min-width: 1024px)',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    const deletedAccount: Account = {
      ...account,
      status: 'deleted',
      deleted_at: '2026-07-22T00:00:00Z',
      deleted_by: 'admin@example.com',
      delete_reason: 'cleanup',
    }
    const onClose = vi.fn()
    const onNotice = vi.fn()
    let deletedRequest: { path: string; method?: string } | null = null
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return response({ bindings: [] })
      if (path === '/api/v1/principals') return response({ principals: [] })
      if (path === '/api/v1/accounts/account-1/purge?confirm=true') {
        deletedRequest = { path, method: init?.method }
        return response({ account_id: deletedAccount.id, purged: true })
      }
      throw new Error(`unexpected request: ${path}`)
    })

    render(
      <Wrapper>
        <AccountDetailPanel
          account={deletedAccount}
          connection={{ ...connection, capabilities: ['account.restore'] }}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={onClose}
          onNotice={onNotice}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    const user = userEvent.setup()
    await user.click(await screen.findByRole('button', { name: 'Удалить навсегда' }))
    const dialog = await screen.findByRole('dialog', { name: 'Удалить аккаунт навсегда' })
    expect(dialog).toHaveTextContent(
      'Исторический audit сохранится',
    )
    await user.click(within(dialog).getByRole('button', { name: 'Удалить навсегда' }))

    await waitFor(() => expect(deletedRequest).toEqual({
      path: '/api/v1/accounts/account-1/purge?confirm=true',
      method: 'DELETE',
    }))
    expect(onClose).toHaveBeenCalledOnce()
    expect(onNotice).toHaveBeenCalledWith('Аккаунт reports_bot удалён из Grantor навсегда')
  })
})
