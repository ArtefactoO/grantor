import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  getRouteApi: () => ({
    useParams: () => ({ connectionId: 'connection-1' }),
    useSearch: () => ({ tab: 'roles' }),
  }),
  Link: ({ children, to, search, className }: {
    children: ReactNode
    to: string
    search?: { operation?: string }
    className?: string
  }) => (
    <a
      href={search?.operation === undefined ? to : `${to}?operation=${search.operation}`}
      className={className}
    >
      {children}
    </a>
  ),
  useNavigate: () => vi.fn(),
}))

import { AuthProvider } from '../auth/AuthProvider'
import type { Connection, ConnectionAdminCredentialChange, Permission } from '../lib/types'
import { ConnectionDetailPage } from './connection-detail'

const ACTIVE_CHANGE: ConnectionAdminCredentialChange = {
  operation_id: 'credential-operation-1',
  mode: 'switch',
  phase: 'candidate_proving',
  status: 'running',
  cancel_allowed: true,
  target_side_effect_possible: false,
  retryable: false,
  error_code: null,
  started_at: '2026-08-26T10:00:00Z',
  updated_at: '2026-08-26T10:00:05Z',
}

function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: 'connection-1',
    display_name: 'Primary DB',
    engine: 'postgres',
    environment: 'test',
    tags: [],
    endpoints: ['db.example.invalid:5432'],
    execution_mode: 'direct',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: 'connections/connection-1/admin',
    capabilities: [
      'connection.admin_credential.switch',
      'connection.admin_credential.rotate',
      'postgres.superuser_direct.v1',
      'role.policy.create',
    ],
    discovery_config: {},
    status: 'active',
    server_version: '16.4',
    topology: {},
    last_discovery_at: '2026-08-26T09:00:00Z',
    created_at: '2026-08-20T10:00:00Z',
    updated_at: '2026-08-26T09:30:00.123456Z',
    admin_credential_change: null,
    postgres_provisioning_authority: {
      status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-08-26T09:00:00Z',
      expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
      config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
    },
    ...overrides,
  }
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

interface WriteRequest {
  path: string
  method: string
  body: unknown
}

const clients: QueryClient[] = []
const unexpectedRequests: string[] = []

function renderPage(initial: Connection, role = 'admin', permissions: Permission[] = []) {
  let current = initial
  const writes: WriteRequest[] = []
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input)
    const url = new URL(path, 'https://grantor.test')
    const method = init?.method ?? 'GET'
    if (method !== 'GET') {
      writes.push({ path, method, body: JSON.parse(String(init?.body ?? 'null')) })
      if (method === 'POST' && (
        path === '/api/v1/connections/connection-1/admin-credential/switch' ||
        path === '/api/v1/connections/connection-1/admin-credential/rotate'
      )) {
        current = {
          ...current,
          status: 'credential_updating',
          admin_credential_change: {
            ...ACTIVE_CHANGE,
            mode: path.endsWith('/rotate') ? 'rotate' : 'switch',
          },
        }
        return response({ operation_id: ACTIVE_CHANGE.operation_id }, 202)
      }
    } else {
      switch (url.pathname) {
        case '/auth/me':
          return response({
            email: `${role}@example.invalid`, role,
            csrf_token: 'test-csrf', csrf_header: 'X-CSRF-Token',
          })
        case '/api/v1/connections/connection-1':
          expect(url.searchParams.get('view')).toBe('summary')
          return response(current)
        case '/api/v1/connections/connection-1/permissions':
          expect(url.searchParams.get('category')).toBe('roles')
          return response({ permissions })
        case '/api/v1/connections/connection-1/role-policies':
          return response({ policies: [] })
        case '/api/v1/connections/connection-1/resources':
          expect(url.searchParams.get('view')).toBe('tree')
          return response({ resources: [
            { id: 'db-1', connection_id: 'connection-1', parent_id: null, kind: 'database', name: 'appdb', status: 'observed', ownership: 'unmanaged' },
            { id: 'schema-1', connection_id: 'connection-1', parent_id: 'db-1', kind: 'schema', name: 'public', status: 'observed', ownership: 'unmanaged' },
          ] })
        case '/api/v1/resources/db-1':
          return response({ id: 'db-1', connection_id: 'connection-1', parent_id: null, kind: 'database', name: 'appdb',
            status: 'observed', ownership: 'unmanaged', attributes: { owner: 'app_owner' }, fingerprint: 'db-fp' })
        case '/api/v1/connections/connection-1/hba':
          return response({
            supported: false, customized: false, truncated: false,
            rules: [], uncovered_accounts: [],
          })
      }
    }
    unexpectedRequests.push(`${method} ${path}`)
    return response({ error: 'Unexpected test request' }, 500)
  }))

  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, refetchOnWindowFocus: false },
      mutations: { retry: false },
    },
  })
  clients.push(client)
  render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <ConnectionDetailPage />
      </AuthProvider>
    </QueryClientProvider>,
  )
  return { writes }
}

beforeEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  unexpectedRequests.length = 0
})

afterEach(() => {
  cleanup()
  for (const client of clients.splice(0)) client.clear()
  expect(unexpectedRequests).toEqual([])
})

describe('connection access settings navigation', () => {
  it('opens a RabbitMQ template and creates a separate JSON draft from it without a write', async () => {
    const user = userEvent.setup()
    const template = {
      key: 'etl-worker', name: 'ETL queues', description: 'ETL worker access',
      vhost: 'sl-project', configure: '^status_changes$',
      write: '^updates$', read: '^status_changes$', dangerous: false,
    }
    const { writes } = renderPage(connection({
      engine: 'rabbitmq', discovery_config: { rabbitmq_permission_templates: [template] },
    }))
    await user.click(await screen.findByRole('button', { name: 'Открыть шаблон ETL queues' }))
    const details = screen.getByRole('dialog', { name: 'Описание роли' })
    await waitFor(() => expect(details).toBeVisible())
    expect(JSON.parse((within(details).getByRole('textbox', { name: 'JSON роли' }) as HTMLTextAreaElement).value))
      .toEqual({ version: 'v1', kind: 'role_templates', engine: 'rabbitmq', templates: [template] })
    await user.click(within(details).getByRole('button', { name: 'Создать по образцу' }))
    expect(screen.queryByRole('dialog', { name: 'Описание роли' })).not.toBeInTheDocument()
    const editor = screen.getByRole('dialog', { name: 'Шаблоны доступа' })
    await waitFor(() => expect(editor).toBeVisible())
    expect(within(editor).getByRole('radio', { name: 'JSON' })).toHaveAttribute('aria-checked', 'true')
    expect(JSON.parse((within(editor).getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement).value).templates)
      .toEqual([template])
    await user.click(within(editor).getByRole('button', { name: 'Отмена' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(writes).toEqual([])
  })

  it('opens an ordinary discovered role as a non-importable snapshot for a viewer', async () => {
    const user = userEvent.setup()
    const observedRole: Permission = {
      id: 'permission-1', connection_id: 'connection-1', engine: 'postgres',
      external_id: 'role:existing_reader', name: 'existing_reader', scope_resource_id: null,
      assignable: true, dangerous: false, status: 'observed', created_at: '', updated_at: '',
      attributes: { superuser: false, secret: 'must-not-be-exported' },
      normalized: { category: 'role', action: '', resource: 'existing_reader', scope: '', dangerous: false, danger_reason: '', details: [], raw: 'existing_reader' },
    }
    const { writes } = renderPage(connection(), 'viewer', [observedRole])
    await user.click(await screen.findByRole('button', { name: 'Открыть роль existing_reader' }))
    const dialog = screen.getByRole('dialog', { name: 'Описание роли' })
    await waitFor(() => expect(dialog).toBeVisible())
    const document = (within(dialog).getByRole('textbox', { name: 'Снимок роли JSON' }) as HTMLTextAreaElement).value
    expect(JSON.parse(document).kind).toBe('role_snapshot')
    expect(document).not.toContain('must-not-be-exported')
    expect(within(dialog).getByRole('button', { name: 'Копировать снимок роли' })).toBeEnabled()
    expect(within(dialog).queryByRole('button', { name: 'Создать по образцу' })).not.toBeInTheDocument()
    expect(writes).toEqual([])
  })

  it('labels an observed LOGIN role as nonassignable rather than Missing', async () => {
    const loginRole: Permission = {
      id: 'login-permission', connection_id: 'connection-1', engine: 'postgres',
      external_id: 'role:service_predict_nba', name: 'service_predict_nba', scope_resource_id: null,
      assignable: false, dangerous: false, status: 'observed', created_at: '', updated_at: '',
      attributes: { login_role: true },
      normalized: { category: 'role', action: '', resource: 'service_predict_nba', scope: '', dangerous: false, danger_reason: '', details: [], raw: 'service_predict_nba' },
    }
    renderPage(connection(), 'viewer', [loginRole])
    expect(await screen.findByRole('button', { name: 'Открыть роль service_predict_nba' })).toBeVisible()
    expect(screen.getByText('LOGIN · не назначается')).toBeVisible()
    expect(screen.queryByText('Missing')).not.toBeInTheDocument()
  })

  it.each([
    ['rabbitmq', 'Шаблоны прав RabbitMQ'],
    ['mongodb', 'MongoDB custom-role policies'],
  ])('opens the %s template editor directly from the empty Roles tab', async (engine, editorTitle) => {
    const user = userEvent.setup()
    const { writes } = renderPage(connection({ engine }))

    const create = await screen.findByRole('button', { name: 'Создать шаблон' })
    expect(create).toBeEnabled()
    expect(screen.queryByRole('button', { name: 'Редактировать шаблоны' })).not.toBeInTheDocument()
    if (engine !== 'postgres') {
      expect(screen.queryByRole('button', { name: 'Создать пару READ/RW' })).not.toBeInTheDocument()
    }
    await user.click(create)

    const dialog = screen.getByRole('dialog', { name: 'Шаблоны доступа' })
    await waitFor(() => expect(dialog).toBeVisible())
    expect(within(dialog).getByRole('heading', { name: editorTitle })).toBeVisible()
    expect(within(dialog).getAllByRole('textbox', { name: /^Ключ/ })).toHaveLength(1)
    expect(screen.queryByRole('dialog', { name: 'Редактировать подключение' })).not.toBeInTheDocument()
    expect(writes).toEqual([])
  })

  it('opens PostgreSQL basic role creation with one database selector and automatic owner/scope', async () => {
    const user = userEvent.setup()
    const { writes } = renderPage(connection({ discovery_config: { database: 'appdb' } }))

    await user.click(await screen.findByRole('button', { name: 'Создать роли для базы' }))

    const dialog = screen.getByRole('dialog', { name: 'Роли доступа к базе' })
    await waitFor(() => expect(dialog).toBeVisible())
    await waitFor(() => expect(within(dialog).getByRole('combobox', { name: 'База данных' })).toBeEnabled())
    await user.click(within(dialog).getByRole('combobox', { name: 'База данных' }))
    await user.click(screen.getByRole('option', { name: 'appdb' }))
    expect(await within(dialog).findByText('r_appdb')).toBeVisible()
    expect(within(dialog).getByText('rw_appdb')).toBeVisible()
    expect(within(dialog).getByText('app_owner')).toBeVisible()
    expect(within(dialog).queryByRole('textbox')).not.toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Создать r_ / rw_' })).toBeEnabled()
    await user.click(within(dialog).getByRole('button', { name: 'Отмена' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Расширенные шаблоны' }))
    expect(screen.getByRole('dialog', { name: 'Шаблоны доступа' })).toBeInTheDocument()
    expect(writes).toEqual([])
  })

  it('opens an existing RabbitMQ catalog for editing beside its published templates', async () => {
    const user = userEvent.setup()
    const { writes } = renderPage(connection({
      engine: 'rabbitmq',
      discovery_config: {
        rabbitmq_permission_templates: [{
          key: 'etl-worker', name: 'ETL queues', description: 'ETL worker access',
          vhost: 'sl-project', configure: '^status_changes$',
          write: '^updates$', read: '^status_changes$', dangerous: false,
        }],
      },
    }))

    expect(await screen.findByText('ETL queues')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Редактировать шаблоны' }))
    const dialog = screen.getByRole('dialog', { name: 'Шаблоны доступа' })
    await waitFor(() => expect(dialog).toBeVisible())
    expect(within(dialog).getByRole('textbox', { name: /^Ключ/ })).toHaveValue('etl-worker')
    expect(within(dialog).getByRole('textbox', { name: 'Vhost' })).toHaveValue('sl-project')
    expect(within(dialog).getByRole('button', { name: 'Сохранить шаблоны' })).toBeDisabled()
    expect(writes).toEqual([])
  })

  it.each([
    ['postgres', 'viewer'], ['postgres', 'operator'],
    ['rabbitmq', 'viewer'], ['rabbitmq', 'operator'],
    ['mongodb', 'viewer'], ['mongodb', 'operator'],
  ])('does not expose %s catalog or connection editing to %s', async (engine, role) => {
    renderPage(connection({ engine }), role)

    await screen.findByText(engine === 'postgres' ? 'Роли доступа ещё не настроены' : 'Шаблоны доступа не настроены')
    expect(screen.queryByRole('button', { name: 'Создать шаблон' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать роли для базы' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Расширенные шаблоны' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать пару READ/RW' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Редактировать шаблоны' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Редактировать подключение' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Управление admin credential' })).not.toBeInTheDocument()
  })

  it.each(['mysql', 'clickhouse', 'kafka', 'redis'])(
    'does not invent an access-template capability for %s', async (engine) => {
      renderPage(connection({ engine }))

      await screen.findByRole('heading', { name: 'Роли подключения' })
      expect(screen.queryByRole('button', { name: 'Создать шаблон' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Создать пару READ/RW' })).not.toBeInTheDocument()
    },
  )

  it('keeps ID and Vault copy actions sized with their values, not stretched across the row', async () => {
    renderPage(connection())

    for (const label of [
      'Копировать идентификатор подключения',
      'Копировать путь admin credential в Vault',
    ]) {
      const copy = await screen.findByRole('button', { name: label })
      const value = copy.closest('.group\\/copyable')
      expect(value).toHaveClass('inline-flex', 'w-fit')
      expect(value).not.toHaveClass('w-full')
      expect(value?.firstElementChild).not.toHaveClass('flex-1')
    }
  })
})

describe('connection admin credential entry from Edit', () => {
  it('opens the credential dialog from Edit and returns focus through both Escape layers', async () => {
    const user = userEvent.setup()
    renderPage(connection())
    const editTrigger = await screen.findByRole('button', { name: 'Редактировать подключение' })
    expect(screen.queryByRole('button', { name: 'Управление admin credential' })).not.toBeInTheDocument()

    await user.click(editTrigger)
    const edit = screen.getByRole('dialog', { name: 'Редактировать подключение' })
    await waitFor(() => expect(edit).toBeVisible())
    const credentialTrigger = within(edit).getByRole('button', { name: 'Изменить учётку или пароль' })
    expect(credentialTrigger.closest('form')).toBeNull()
    await user.click(credentialTrigger)

    const credential = screen.getByRole('dialog', { name: 'Admin credential подключения' })
    await waitFor(() => expect(credential).toBeVisible())
    expect(credential.closest('#connection-edit-form')).toBeNull()
    await waitFor(() => expect(within(credential).getByRole('textbox', { name: /Username/ })).toHaveFocus())
    await user.keyboard('{Escape}')

    await waitFor(() => expect(credential).not.toBeInTheDocument())
    await waitFor(() => expect(credentialTrigger).toHaveFocus())
    expect(screen.getByRole('dialog', { name: 'Редактировать подключение' })).toBeVisible()
    await user.keyboard('{Escape}')
    await waitFor(() => expect(edit).not.toBeInTheDocument())
    expect(editTrigger).toHaveFocus()
  })

  it('blocks the credential transition while connection settings contain an unsaved change', async () => {
    const user = userEvent.setup()
    const { writes } = renderPage(connection())
    await user.click(await screen.findByRole('button', { name: 'Редактировать подключение' }))
    const edit = screen.getByRole('dialog', { name: 'Редактировать подключение' })
    await waitFor(() => expect(edit).toBeVisible())
    const name = within(edit).getByRole('textbox', { name: 'Отображаемое имя' })

    await user.type(name, ' renamed')
    const credentialTrigger = within(edit).getByRole('button', { name: 'Изменить учётку или пароль' })
    expect(credentialTrigger).toBeDisabled()
    expect(within(edit).getByText('Сначала сохраните или отмените изменения подключения.')).toBeVisible()
    await user.click(credentialTrigger)
    expect(screen.queryByRole('dialog', { name: 'Admin credential подключения' })).not.toBeInTheDocument()
    expect(writes).toEqual([])

    await user.clear(name)
    await user.type(name, 'Primary DB')
    expect(credentialTrigger).toBeEnabled()
    expect(within(edit).queryByText('Сначала сохраните или отмените изменения подключения.')).not.toBeInTheDocument()
  })

  it.each(['switch', 'rotate'] as const)(
    'submits %s through its dedicated operation without submitting the connection metadata form', async (mode) => {
      const user = userEvent.setup()
      const { writes } = renderPage(connection())
      await user.click(await screen.findByRole('button', { name: 'Редактировать подключение' }))
      await user.click(await screen.findByRole('button', { name: 'Изменить учётку или пароль' }))
      const credential = screen.getByRole('dialog', { name: 'Admin credential подключения' })
      await waitFor(() => expect(credential).toBeVisible())

      if (mode === 'switch') {
        await user.type(within(credential).getByRole('textbox', { name: /Username/ }), 'grantor_next')
        await user.type(within(credential).getByLabelText('Password'), 'test-candidate-password')
        await user.click(within(credential).getByRole('button', { name: 'Проверить и сменить' }))
      } else {
        await user.click(within(credential).getByRole('radio', { name: /Ротировать password/ }))
        await user.click(within(credential).getByRole('button', { name: 'Запустить ротацию' }))
      }

      await waitFor(() => expect(credential).not.toBeInTheDocument())
      expect(writes).toEqual([{
        path: `/api/v1/connections/connection-1/admin-credential/${mode}`,
        method: 'POST',
        body: mode === 'switch' ? {
          request_id: expect.any(String),
          updated_at: '2026-08-26T09:30:00.123456Z',
          username: 'grantor_next',
          password: 'test-candidate-password',
        } : {
          request_id: expect.any(String),
          updated_at: '2026-08-26T09:30:00.123456Z',
          mode: 'generated',
        },
      }])
      const edit = screen.getByRole('dialog', { name: 'Редактировать подключение' })
      expect(within(edit).getByRole('button', { name: 'Изменить учётку или пароль' })).toBeDisabled()
      expect(within(edit).getByRole('button', { name: 'Сохранить' })).toBeDisabled()
      expect(within(edit).getByText(/Прогресс и разрешённые действия доступны на странице подключения/)).toBeVisible()
      await user.keyboard('{Escape}')

      await waitFor(() => expect(edit).not.toBeInTheDocument())
      const progress = screen.getByRole('region', {
        name: mode === 'switch' ? 'Admin credential · Смена учётки' : 'Admin credential · Ротация пароля',
      })
      expect(progress).toBeVisible()
      expect(progress.closest('[role="dialog"]')).toBeNull()
      expect(within(progress).getByRole('link', { name: /^Операция/ }))
        .toHaveAttribute('href', '/control?operation=credential-operation-1')
      expect(screen.getByRole('button', { name: 'Редактировать подключение' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Удалить подключение' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Создать роли для базы' })).toBeDisabled()
      expect(screen.getByRole('button', { name: 'Синхронизировать Primary DB' })).toBeDisabled()
    },
  )

  it.each([
    {
      name: 'Vault recovery without capabilities',
      capabilities: [], vaultAdminPath: 'connections/connection-1/admin',
      visible: true, rotateAvailable: false,
    },
    {
      name: 'no capability or Vault credential',
      capabilities: [], vaultAdminPath: '',
      visible: false, rotateAvailable: false,
    },
    {
      name: 'rotation capability without switch',
      capabilities: ['connection.admin_credential.rotate'], vaultAdminPath: '',
      visible: true, rotateAvailable: true,
    },
  ])('preserves credential visibility for $name after moving the action', async ({
    capabilities, vaultAdminPath, visible, rotateAvailable,
  }) => {
    const user = userEvent.setup()
    renderPage(connection({ capabilities, vault_admin_path: vaultAdminPath }))
    await user.click(await screen.findByRole('button', { name: 'Редактировать подключение' }))
    const edit = screen.getByRole('dialog', { name: 'Редактировать подключение' })
    await waitFor(() => expect(edit).toBeVisible())
    const trigger = within(edit).queryByRole('button', { name: 'Изменить учётку или пароль' })
    if (!visible) {
      expect(trigger).not.toBeInTheDocument()
      return
    }
    expect(trigger).toBeEnabled()
    await user.click(within(edit).getByRole('button', { name: 'Изменить учётку или пароль' }))
    const credential = screen.getByRole('dialog', { name: 'Admin credential подключения' })
    await waitFor(() => expect(credential).toBeVisible())
    if (rotateAvailable) {
      expect(within(credential).getByRole('radio', { name: /Ротировать password/ })).toBeChecked()
      expect(within(credential).queryByRole('radio', { name: /Сменить учётку/ })).not.toBeInTheDocument()
    } else {
      expect(within(credential).getByRole('radio', { name: /Сменить учётку/ })).toBeChecked()
      expect(within(credential).queryByRole('radio', { name: /Ротировать password/ })).not.toBeInTheDocument()
    }
  })

  it('keeps an active operation visible on the page while the editor and mutations are locked', async () => {
    renderPage(connection({ status: 'credential_updating', admin_credential_change: ACTIVE_CHANGE }))

    const progress = await screen.findByRole('region', { name: 'Admin credential · Смена учётки' })
    expect(progress).toBeVisible()
    expect(within(progress).getByRole('list', { name: 'Этапы credential operation' })).toBeVisible()
    expect(within(progress).getByRole('button', { name: 'Отменить до side effect' })).toBeEnabled()
    expect(screen.getByRole('button', { name: 'Редактировать подключение' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Удалить подключение' })).toBeDisabled()
    expect(await screen.findByRole('button', { name: 'Создать роли для базы' })).toBeDisabled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })
})
