import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useState } from 'react'
import type { ComponentProps, ReactNode } from 'react'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type {
  Connection,
  MongoDBRolePolicyTemplate,
  PostgresRolePolicyTemplate,
  Resource,
} from '../lib/types'
import type { RabbitMQPermissionTemplate } from '../lib/rabbitmq-permission-templates'
import { serializeRoleTemplatesDocument } from '../lib/role-template-document'
import { pairedPostgresRolePolicyDrafts } from '../lib/postgres-role-policy-templates'
import * as roleDocuments from '../lib/role-template-document'
import type { RoleTemplateCatalog } from '../lib/role-template-document'
import {
  canEditAccessTemplates,
  ConnectionAccessTemplatesDialog,
} from './connection-access-templates-dialog'

const POSTGRES_TEMPLATE: PostgresRolePolicyTemplate = {
  key: 'appdb-read',
  name: 'App DB reader',
  description: 'Read application data',
  role_name: 'r_appdb',
  database: 'appdb',
  schemas: ['public'],
  owner_roles: ['app_owner'],
  creator_roles: ['app_migrations'],
  profile: 'read',
}

const RABBIT_TEMPLATE: RabbitMQPermissionTemplate = {
  key: 'etl-worker',
  name: 'ETL worker',
  description: 'Narrow queues',
  vhost: 'sl-project',
  configure: '^(status_changes|project_etl_match_state_updates)$',
  write: '^project_etl_match_state_updates$',
  read: '^(status_changes|project_etl_match_state_updates)$',
  dangerous: false,
}

const MONGO_TEMPLATE: MongoDBRolePolicyTemplate = {
  key: 'etl-reader',
  name: 'ETL reader',
  description: 'Read event data',
  role_name: 'etlReader',
  role_database: 'admin',
  inherited_roles: [{ role: 'read', db: 'appdb' }],
  privileges: [{ resource: { db: 'appdb', collection: 'events' }, actions: ['find'] }],
}

const baseConnection: Connection = {
  id: 'c49d856b-7862-4884-894d-993139232973',
  display_name: 'billing-postgres',
  engine: 'postgres',
  environment: 'prod',
  tags: ['payments'],
  endpoints: ['db.example.com:5432'],
  execution_mode: 'direct',
  tls_config: { mode: 'verify-full' },
  admin_credential_mode: 'vault',
  vault_admin_path: 'connections/c49d856b/admin',
  capabilities: ['discover'],
  discovery_config: { database: 'appdb', postgres_role_policy_templates: [POSTGRES_TEMPLATE] },
  status: 'active',
  server_version: '16.2',
  topology: {},
  last_discovery_at: '2026-08-26T12:00:00Z',
  created_at: '2026-08-26T10:00:00Z',
  updated_at: '2026-08-26T12:00:00.123456Z',
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderDialog(overrides: Partial<ComponentProps<typeof ConnectionAccessTemplatesDialog>> = {}) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const onClose = vi.fn()
  const onSaved = vi.fn()
  const props = { connection: baseConnection, open: true, isAdmin: true, onClose, onSaved, ...overrides }
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>
  }
  const result = render(<ConnectionAccessTemplatesDialog {...props} />, { wrapper: Wrapper })
  return {
    ...result,
    onClose,
    onSaved,
    rerenderDialog: (next: Partial<ComponentProps<typeof ConnectionAccessTemplatesDialog>>) => {
      result.rerender(<ConnectionAccessTemplatesDialog {...props} {...next} />)
    },
  }
}

function saveButton() {
  return screen.getByRole('button', { name: 'Сохранить шаблоны' })
}

function catalogForm(): HTMLFormElement {
  return document.getElementById(saveButton().getAttribute('form') ?? '') as HTMLFormElement
}

const ENGINE_CASES = [
  {
    engine: 'postgres',
    key: 'postgres_role_policy_templates',
    template: POSTGRES_TEMPLATE,
    originalConfig: { database: 'appdb' },
  },
  {
    engine: 'rabbitmq',
    key: 'rabbitmq_permission_templates',
    template: RABBIT_TEMPLATE,
    originalConfig: { vhost_discovery: ['sl-project'] },
  },
  {
    engine: 'mongodb',
    key: 'mongodb_role_policy_templates',
    template: MONGO_TEMPLATE,
    originalConfig: { auth_source: 'admin', replica_set: 'rs0' },
  },
] as const

describe('ConnectionAccessTemplatesDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('loads full scoped discovery evidence only on request and accepts candidates as an unsaved draft', async () => {
    const observedAt = baseConnection.last_discovery_at
    const resource = (id: string, kind: string, name: string, parent: string | null, owner: string): Resource => ({
      id, kind, name, parent_id: parent, connection_id: baseConnection.id, external_id: id,
      canonical_path: name, attributes: { owner }, fingerprint: id, observed_at: observedAt,
      status: 'observed', ownership: 'unmanaged', created_at: '', updated_at: '',
    })
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) =>
      String(input).endsWith('/resources')
        ? jsonResponse(200, { resources: [
          resource('db', 'database', 'appdb', null, 'db_owner'),
          resource('schema', 'schema', 'public', 'db', 'observed_owner'),
        ] })
        : jsonResponse(200, baseConnection))
    vi.stubGlobal('fetch', fetchMock)
    const { rerenderDialog } = renderDialog()
    expect(fetchMock).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Загрузить подсказки Owner/Creator' }))
    const accept = await screen.findByRole('button', { name: 'Добавить observed_owner в Owner-роли' })
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(fetchMock.mock.calls.map(([url]) => String(url)).sort()).toEqual([
      `/api/v1/connections/${baseConnection.id}`, `/api/v1/connections/${baseConnection.id}/resources`,
    ])
    expect(saveButton()).toBeDisabled()
    await userEvent.click(accept)
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('app_owner\nobserved_owner')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('app_migrations')
    expect(saveButton()).toBeEnabled()
    expect(fetchMock).toHaveBeenCalledTimes(2)

    // A different connection must start a new editor/suggestion session.
    rerenderDialog({ connection: { ...baseConnection, id: 'connection-2' } })
    expect(screen.queryByRole('button', { name: 'Добавить observed_owner в Owner-роли' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('app_owner')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('does not confuse an invalid or unavailable inventory response with an empty schema', async () => {
    const fetchMock = vi.fn().mockImplementation(async (input: RequestInfo | URL) =>
      String(input).endsWith('/resources') ? jsonResponse(200, {}) : jsonResponse(200, baseConnection))
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ intent: 'create' })
    await userEvent.click(screen.getByRole('button', { name: 'Загрузить подсказки Owner/Creator' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Не удалось загрузить подсказки')
    expect(alert).toHaveTextContent('Полный список объектов недоступен')
    expect(alert).not.toHaveTextContent('resource_inventory_unavailable')
    expect(screen.queryByText(/Без обнаруженных объектов/)).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toBeEnabled()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it.each(ENGINE_CASES)('saves the $engine catalog only, preserving the complete original config', async (testCase) => {
    const config: Record<string, unknown> = {
      ...testCase.originalConfig,
      future_feature: { enabled: false, scopes: ['primary', 'replica'], depth: { limit: 7 } },
      future_scalar: null,
      [testCase.key]: [testCase.template],
    }
    const connection = { ...baseConnection, engine: testCase.engine, discovery_config: config }
    const updated = { ...connection, status: 'discovering', operation_id: 'catalog-discovery' }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, updated))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onClose, onSaved } = renderDialog({ connection })

    expect(saveButton()).toBeDisabled()
    if (testCase.engine === 'mongodb') {
      await user.click(screen.getByRole('button', { name: 'Развернуть Policy: ETL reader' }))
    }
    expect(screen.queryByRole('textbox', { name: /SQL|BSON|password|пароль/i })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /^Название/ }), { target: { value: 'Updated template' } })
    await user.click(saveButton())

    await waitFor(() => expect(onSaved).toHaveBeenCalledWith(updated))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`/api/v1/connections/${connection.id}`)
    expect(options.method).toBe('PATCH')
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      discovery_config: {
        ...config,
        [testCase.key]: [{ ...testCase.template, name: 'Updated template' }],
      },
    })
    // No apply/adopt, role creation or access mutation is coupled to saving.
    expect(config[testCase.key]).toEqual([testCase.template])
  })

  it('keeps actions outside the scroll body and does not save an unchanged catalog', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const { onClose } = renderDialog()
    const dialog = screen.getByRole('dialog', { name: 'Шаблоны доступа' })
    const body = dialog.querySelector('[data-slot="dialog-body"]')
    const footer = dialog.querySelector('[data-slot="dialog-footer"]')
    expect(body).toHaveClass('overflow-y-auto')
    expect(body).toContainElement(catalogForm())
    expect(footer).toContainElement(saveButton())
    expect(body).not.toContainElement(saveButton())
    fireEvent.submit(catalogForm())
    await userEvent.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('pins the loaded CAS and full snapshot even when connection query data refreshes', async () => {
    const connection = {
      ...baseConnection,
      discovery_config: { ...baseConnection.discovery_config as object, future: { version: 'opened' } },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, connection))
    vi.stubGlobal('fetch', fetchMock)
    const { rerenderDialog } = renderDialog({ connection })
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
    rerenderDialog({
      connection: {
        ...connection,
        updated_at: '2026-08-26T12:01:00Z',
        discovery_config: {
          database: 'new_database',
          postgres_role_policy_templates: [{ ...POSTGRES_TEMPLATE, name: 'Server version' }],
          future: { version: 'refreshed' },
        },
      },
    })
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Local draft')
    await userEvent.click(saveButton())
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      discovery_config: {
        database: 'appdb',
        future: { version: 'opened' },
        postgres_role_policy_templates: [{ ...POSTGRES_TEMPLATE, name: 'Local draft' }],
      },
    })
  })

  it('does not retry or silently rebase a 409 and preserves the unsaved catalog', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(409, { error: 'connection version conflict' }))
    vi.stubGlobal('fetch', fetchMock)
    const { onClose, rerenderDialog } = renderDialog()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
    await userEvent.click(saveButton())
    expect(await screen.findByText(/Подключение изменилось. Закройте редактор/)).toBeInTheDocument()
    rerenderDialog({ connection: { ...baseConnection, updated_at: '2026-08-26T12:02:00Z' } })
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Local draft')
    expect(saveButton()).toBeDisabled()
    fireEvent.submit(catalogForm())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(onClose).not.toHaveBeenCalled()
  })

  it('refreshes only the connection detail after 409 and pins the refreshed version only after reopen', async () => {
    const serverConnection: Connection = {
      ...baseConnection,
      updated_at: '2026-08-26T12:03:00Z',
      discovery_config: {
        database: 'appdb',
        future: { source: 'refreshed' },
        postgres_role_policy_templates: [{ ...POSTGRES_TEMPLATE, name: 'Server version' }],
      },
    }
    const fetchMock = vi.fn(async (_url: string, options?: RequestInit) => (
      options?.method === 'PATCH'
        ? jsonResponse(409, { error: 'connection version conflict' })
        : jsonResponse(200, serverConnection)
    ))
    vi.stubGlobal('fetch', fetchMock)
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    client.setQueryData(qk.connectionPermissions(baseConnection.id), [])

    function QueryBackedDialog() {
      const [open, setOpen] = useState(true)
      const query = useQuery({
        queryKey: qk.connection(baseConnection.id),
        queryFn: () => api<Connection>(`/api/v1/connections/${baseConnection.id}`),
        initialData: baseConnection,
        staleTime: Infinity,
      })
      return (
        <>
          <button onClick={() => setOpen(true)}>Открыть шаблоны</button>
          <ConnectionAccessTemplatesDialog
            connection={query.data}
            isAdmin
            open={open}
            onClose={() => setOpen(false)}
          />
        </>
      )
    }

    render(<QueryClientProvider client={client}><QueryBackedDialog /></QueryClientProvider>)
    const user = userEvent.setup()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
    await user.click(saveButton())
    await waitFor(() => expect(client.getQueryData(qk.connection(baseConnection.id))).toEqual(serverConnection))
    expect(client.getQueryState(qk.connectionPermissions(baseConnection.id))?.isInvalidated).toBe(false)
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Local draft')
    expect(saveButton()).toBeDisabled()
    fireEvent.submit(catalogForm())
    expect(fetchMock.mock.calls.filter(([, options]) => options?.method === 'PATCH')).toHaveLength(1)

    await user.click(screen.getByRole('button', { name: 'Отмена' }))
    await user.click(screen.getByRole('button', { name: 'Отменить изменения' }))
    await user.click(screen.getByRole('button', { name: 'Открыть шаблоны' }))
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Server version')
    expect(saveButton()).toBeDisabled()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Reopened draft' } })
    await user.click(saveButton())
    await screen.findByText(/Подключение изменилось. Закройте редактор/)
    const patches = fetchMock.mock.calls.filter(([, options]) => options?.method === 'PATCH')
    expect(patches).toHaveLength(2)
    expect(JSON.parse(String(patches[1]?.[1]?.body))).toEqual({
      updated_at: serverConnection.updated_at,
      discovery_config: {
        database: 'appdb',
        future: { source: 'refreshed' },
        postgres_role_policy_templates: [{ ...POSTGRES_TEMPLATE, name: 'Reopened draft' }],
      },
    })
  })

  it('requires explicit discard after Escape or cancel on an unsaved draft', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onClose } = renderDialog({ intent: 'create', connection: { ...baseConnection, discovery_config: {} } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Ключ/ }), { target: { value: 'changed-draft' } })
    await user.keyboard('{Escape}')
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByText('Есть несохранённые изменения.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Продолжить редактирование' }))
    await user.click(screen.getByRole('button', { name: 'Отмена' }))
    await user.click(screen.getByRole('button', { name: 'Отменить изменения' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it.each(ENGINE_CASES)('closes an untouched automatic $engine draft without confirmation', async (testCase) => {
    const user = userEvent.setup()
    const { onClose } = renderDialog({
      intent: 'create', connection: { ...baseConnection, engine: testCase.engine, discovery_config: {} },
    })
    await user.click(screen.getByRole('button', { name: 'Закрыть' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Есть несохранённые изменения.')).not.toBeInTheDocument()
  })

  it('closes an untouched READ/RW pair on Escape without confirmation', async () => {
    const { onClose } = renderDialog({ intent: 'pair' })
    await userEvent.keyboard('{Escape}')
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Есть несохранённые изменения.')).not.toBeInTheDocument()
  })

  it.each(ENGINE_CASES)('switches an incomplete $engine draft to JSON and back without creating edits', async (testCase) => {
    const user = userEvent.setup()
    const { onClose } = renderDialog({
      intent: 'create', connection: { ...baseConnection, engine: testCase.engine, discovery_config: {} },
    })
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    const document = JSON.parse((screen.getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement).value)
    expect(document).toMatchObject({ version: 'v1', kind: 'role_templates', engine: testCase.engine })
    expect(document.templates).toHaveLength(1)
    await user.click(screen.getByRole('radio', { name: 'Поля' }))
    expect(screen.getByRole('textbox', { name: /^Ключ/ })).toHaveValue('')
    await user.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Есть несохранённые изменения.')).not.toBeInTheDocument()
  })

  it.each(ENGINE_CASES)('imports a new $engine template without replacing existing catalog entries or unrelated config', async (testCase) => {
    const user = userEvent.setup()
    const config = { ...testCase.originalConfig, [testCase.key]: [testCase.template], future: { keep: true } }
    const connection = { ...baseConnection, engine: testCase.engine, discovery_config: config }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, connection))
    vi.stubGlobal('fetch', fetchMock)
    const { onSaved } = renderDialog({ connection, intent: 'create' })
    const template = { ...testCase.template, key: 'new-template', name: 'New template' }
    if ('role_name' in template) template.role_name = 'new_role'
    if ('write' in template) template.write = '^new_queue$'
    const catalog = { engine: testCase.engine, templates: [template] } as RoleTemplateCatalog
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), {
      target: { value: serializeRoleTemplatesDocument(catalog) },
    })
    // The same document also populates the original structured form.
    await user.click(screen.getByRole('radio', { name: 'Поля' }))
    if (testCase.engine === 'mongodb') await user.click(screen.getByRole('button', { name: 'Развернуть Policy: New template' }))
    expect(screen.getByRole('textbox', { name: /^Ключ/ })).toHaveValue('new-template')
    expect(screen.getByRole('textbox', { name: /^Название/ })).toHaveValue('New template')
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    expect(JSON.parse((screen.getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement).value))
      .toMatchObject(catalog)
    await user.click(saveButton())
    await waitFor(() => expect(onSaved).toHaveBeenCalled())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(`/api/v1/connections/${connection.id}`)
    expect(options.method).toBe('PATCH')
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      discovery_config: { ...config, [testCase.key]: [testCase.template, template] },
    })
  })

  it('preserves edits and the current mode for invalid JSON instead of silently reverting to fields', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const { onClose } = renderDialog({ intent: 'create' })
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), { target: { value: '{invalid' } })
    await user.click(screen.getByRole('radio', { name: 'Поля' }))
    expect(screen.getByRole('textbox', { name: 'JSON шаблонов' })).toHaveValue('{invalid')
    expect(screen.getByRole('radio', { name: 'JSON' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('alert')).toBeInTheDocument()
    await user.click(saveButton())
    expect(fetchMock).not.toHaveBeenCalled()
    await user.keyboard('{Escape}')
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByText('Есть несохранённые изменения.')).toBeInTheDocument()
  })

  it('uses the shared semantic validator in JSON mode and rejects a duplicate role identity', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({
      intent: 'create', initialMode: 'json',
      initialTemplates: { engine: 'postgres', templates: [{ ...POSTGRES_TEMPLATE, key: 'another-key' }] },
    })
    await user.click(saveButton())
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), {
      target: { value: JSON.stringify({ version: 'v1', kind: 'role_snapshot', engine: 'postgres', role: {} }) },
    })
    await user.click(saveButton())
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('explains a pasted role snapshot and recovers the previous field draft only after explicit cancellation', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Unsaved field draft' } })
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    const snapshot = JSON.stringify({
      version: 'v1', kind: 'role_snapshot', engine: 'postgres',
      role: { external_id: 'role:existing_reader', name: 'existing_reader', observed: { superuser: false } },
    })
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), { target: { value: snapshot } })
    await user.click(screen.getByRole('radio', { name: 'Поля' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Это снимок роли, а не шаблон для создания.')
    expect(screen.getByRole('alert')).not.toHaveTextContent(/SQL|BSON|неизвестные поля/)
    expect(screen.getByRole('textbox', { name: 'JSON шаблонов' })).toHaveValue(snapshot)
    await user.click(saveButton())
    expect(fetchMock).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Отменить импорт и вернуться к полям' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Поля' })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Unsaved field draft')
    expect(screen.getByRole('textbox', { name: 'NOLOGIN-роль' })).toHaveValue(POSTGRES_TEMPLATE.role_name)
    await waitFor(() => expect(screen.getByRole('textbox', { name: /^Ключ/ })).toHaveFocus())
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    const recovered = JSON.parse((screen.getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement).value)
    expect(recovered.templates).toEqual([{ ...POSTGRES_TEMPLATE, name: 'Unsaved field draft' }])
    expect(recovered.kind).toBe('role_templates')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not offer discard-import recovery for a CAS error or accept a rejected snapshot as a draft', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(409, { error: 'connection version conflict' }))
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ initialMode: 'json' })
    const document = serializeRoleTemplatesDocument({ engine: 'postgres', templates: [{ ...POSTGRES_TEMPLATE, name: 'Updated' }] })
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), { target: { value: document } })
    await userEvent.click(saveButton())
    await screen.findByText(/Подключение изменилось/)
    expect(screen.queryByRole('button', { name: 'Отменить импорт и вернуться к полям' })).not.toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: 'JSON шаблонов' })).toHaveValue(document)
    expect(saveButton()).toBeDisabled()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('closes a seeded JSON draft without confirmation until the user changes it', async () => {
    const { onClose } = renderDialog({
      intent: 'create', initialMode: 'json',
      initialTemplates: { engine: 'postgres', templates: [POSTGRES_TEMPLATE] },
    })
    await userEvent.click(screen.getByRole('button', { name: 'Отмена' }))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Есть несохранённые изменения.')).not.toBeInTheDocument()
  })

  it('retains JSON edits and pins CAS after a 409; neither a retry nor target mutation is sent', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(409, { error: 'connection version conflict' }))
    vi.stubGlobal('fetch', fetchMock)
    const { rerenderDialog } = renderDialog({ initialMode: 'json' })
    const document = serializeRoleTemplatesDocument({
      engine: 'postgres', templates: [{ ...POSTGRES_TEMPLATE, name: 'JSON draft' }],
    })
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), { target: { value: document } })
    await userEvent.click(saveButton())
    await screen.findByText(/Подключение изменилось. Закройте редактор/)
    rerenderDialog({ connection: { ...baseConnection, updated_at: 'newer' } })
    expect(screen.getByRole('textbox', { name: 'JSON шаблонов' })).toHaveValue(document)
    expect(saveButton()).toBeDisabled()
    fireEvent.submit(catalogForm())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body)).updated_at).toBe(baseConnection.updated_at)
  })

  it.each(['catalog', 'create'] as const)('preserves RabbitMQ vhost identity and exact regex in %s mode', async (intent) => {
    const saved = { ...RABBIT_TEMPLATE, name: ' Existing name ', vhost: ' /existing with spaces ' }
    const imported = { ...RABBIT_TEMPLATE, key: 'new-etl', name: 'New ETL', vhost: ' /new with spaces ', read: '^queue\\.with\\.dots$' }
    const config = { future: { keep: true }, rabbitmq_permission_templates: [saved] }
    const connection = { ...baseConnection, engine: 'rabbitmq', discovery_config: config }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, connection))
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ connection, intent, initialMode: 'json' })
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), {
      target: { value: serializeRoleTemplatesDocument({ engine: 'rabbitmq', templates: [imported] }) },
    })
    await userEvent.click(saveButton())
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const body = JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))
    expect(body.discovery_config).toEqual({
      ...config,
      rabbitmq_permission_templates: intent === 'create' ? [saved, imported] : [imported],
    })
  })

  it('serializes only when entering JSON, not on form or JSON keystrokes', async () => {
    const serialize = vi.spyOn(roleDocuments, 'serializeRoleTemplatesDocument')
    const user = userEvent.setup()
    renderDialog()
    expect(serialize).not.toHaveBeenCalled()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Updated name' } })
    expect(serialize).not.toHaveBeenCalled()
    await user.click(screen.getByRole('radio', { name: 'JSON' }))
    expect(serialize).toHaveBeenCalledTimes(1)
    const editor = screen.getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement
    fireEvent.change(editor, { target: { value: `${editor.value} ` } })
    expect(serialize).toHaveBeenCalledTimes(1)
    await user.click(screen.getByRole('radio', { name: 'Поля' }))
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Updated name')
    expect(serialize).toHaveBeenCalledTimes(1)
  })

  it.each(ENGINE_CASES)('starts one explicit $engine draft and never appends it again on rerender', (testCase) => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const connection = { ...baseConnection, engine: testCase.engine, discovery_config: {} }
    const { rerenderDialog } = renderDialog({ connection, intent: 'create' })
    const key = screen.getByRole('textbox', { name: /^Ключ/ })
    fireEvent.change(key, { target: { value: 'one-draft' } })
    rerenderDialog({ connection: { ...connection, updated_at: 'newer' }, intent: 'create' })
    expect(screen.getAllByRole('textbox', { name: /^Ключ/ })).toHaveLength(1)
    expect(screen.getByRole('textbox', { name: /^Ключ/ })).toHaveValue('one-draft')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it.each(ENGINE_CASES)('opens only the new $engine draft, leaving existing templates out of the creation form', async (testCase) => {
    const connection = {
      ...baseConnection,
      engine: testCase.engine,
      discovery_config: { [testCase.key]: [testCase.template] },
    }
    renderDialog({ connection, intent: 'create' })
    const keys = screen.getAllByRole('textbox', { name: /^Ключ/ })
    expect(keys[0]).toHaveValue('')
    await waitFor(() => expect(keys[0]).toHaveFocus())
    expect(keys).toHaveLength(1)
    if (testCase.engine === 'mongodb') {
      expect(screen.getByRole('button', { name: 'Свернуть Policy: Policy 1' })).toHaveAttribute('aria-expanded', 'true')
      expect(screen.queryByRole('button', { name: 'Развернуть Policy: ETL reader' })).not.toBeInTheDocument()
    }
  })

  it('starts a PostgreSQL READ/RW pair once and resets only when reopened', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const connection = { ...baseConnection, discovery_config: { database: 'appdb' } }
    const { rerenderDialog } = renderDialog({ connection, intent: 'pair' })
    expect(screen.getAllByRole('textbox', { name: /^Ключ/ }).map((input) => (input as HTMLInputElement).value))
      .toEqual(['appdb-read', 'appdb-read-write'])
    expect(screen.getByRole('textbox', { name: 'READ · NOLOGIN-роль' })).toHaveValue('r_appdb')
    expect(screen.getByRole('textbox', { name: 'RW · NOLOGIN-роль' })).toHaveValue('rw_appdb')
    expect(screen.getByText('CONNECT, USAGE, SELECT')).toBeInTheDocument()
    expect(screen.getByText('READ + INSERT, UPDATE, DELETE')).toBeInTheDocument()
    expect(screen.getAllByRole('textbox', { name: 'База данных' })).toHaveLength(1)
    expect(screen.getAllByRole('textbox', { name: /^Owner-роли/ })).toHaveLength(1)
    rerenderDialog({ connection, intent: 'pair' })
    expect(screen.getAllByRole('textbox', { name: /^Ключ/ })).toHaveLength(2)
    rerenderDialog({ open: false })
    rerenderDialog({ connection, open: true, intent: 'pair' })
    expect(screen.getAllByRole('textbox', { name: /^Ключ/ })).toHaveLength(2)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('opens a PostgreSQL pair separately from existing policies and focuses its first draft', async () => {
    const existing = { ...POSTGRES_TEMPLATE, key: 'legacy-read', role_name: 'r_legacy' }
    renderDialog({
      intent: 'pair',
      connection: {
        ...baseConnection,
        discovery_config: { database: 'appdb', postgres_role_policy_templates: [existing] },
      },
    })
    const keys = screen.getAllByRole('textbox', { name: /^Ключ/ })
    expect(keys.map((input) => (input as HTMLInputElement).value))
      .toEqual(['appdb-read', 'appdb-read-write'])
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'READ · NOLOGIN-роль' })).toHaveFocus())
  })

  it('saves shared READ/RW edits as the same two independent API templates and preserves the existing catalog', async () => {
    const existing = { ...POSTGRES_TEMPLATE, key: 'legacy-read', role_name: 'r_legacy', database: 'legacy' }
    const config = { database: 'appdb', future: { unchanged: true }, postgres_role_policy_templates: [existing] }
    const connection = { ...baseConnection, discovery_config: config }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, connection))
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ connection, intent: 'pair' })

    fireEvent.change(screen.getByRole('textbox', { name: 'База данных' }), { target: { value: 'reporting' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Схемы/ }), { target: { value: 'reports\naudit' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Owner-роли/ }), { target: { value: 'manual_owner' } })
    fireEvent.change(screen.getByRole('textbox', { name: /^Creator-роли/ }), { target: { value: 'migration_role' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Описание READ' }), { target: { value: 'Analytics reader' } })
    fireEvent.change(screen.getByRole('textbox', { name: 'Описание RW' }), { target: { value: 'Analytics writer' } })
    await userEvent.click(saveButton())

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      updated_at: connection.updated_at,
      discovery_config: {
        ...config,
        postgres_role_policy_templates: [existing, ...pairedPostgresRolePolicyDrafts('appdb').map((draft, index) => ({
          ...draft, database: 'reporting', schemas: ['reports', 'audit'],
          owner_roles: ['manual_owner'], creator_roles: ['migration_role'],
          description: index === 0 ? 'Analytics reader' : 'Analytics writer',
        }))],
      },
    })
    expect(config.postgres_role_policy_templates).toEqual([existing])
  })

  it('keeps per-template scope differences when a pair is edited through JSON and returned to fields', async () => {
    const templates = pairedPostgresRolePolicyDrafts('appdb').map((draft, index) => ({
      ...draft, description: 'Imported role', database: index === 0 ? 'read_db' : 'write_db',
      schemas: index === 0 ? ['reports'] : ['public'], owner_roles: [`owner_${index}`], creator_roles: [`creator_${index}`],
    }))
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ connection: { ...baseConnection, discovery_config: { database: 'appdb' } }, intent: 'pair' })
    await userEvent.click(screen.getByRole('radio', { name: 'JSON' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'JSON шаблонов' }), {
      target: { value: serializeRoleTemplatesDocument({ engine: 'postgres', templates }) },
    })
    await userEvent.click(screen.getByRole('radio', { name: 'Поля' }))
    expect(screen.getByRole('textbox', { name: 'База данных' })).toHaveValue('read_db')
    await userEvent.click(screen.getByRole('button', { name: 'Редактировать шаблон: appdb: чтение и запись' }))
    expect(screen.getByRole('textbox', { name: 'База данных' })).toHaveValue('write_db')
    expect(screen.getByRole('textbox', { name: /^Owner-роли/ })).toHaveValue('owner_1')
    expect(screen.getByRole('textbox', { name: /^Creator-роли/ })).toHaveValue('creator_1')
    await userEvent.click(screen.getByRole('radio', { name: 'JSON' }))
    expect(JSON.parse((screen.getByRole('textbox', { name: 'JSON шаблонов' }) as HTMLTextAreaElement).value))
      .toEqual({ version: 'v1', kind: 'role_templates', engine: 'postgres', templates })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not interpret a PostgreSQL pair intent for RabbitMQ', () => {
    renderDialog({ intent: 'pair', connection: { ...baseConnection, engine: 'rabbitmq', discovery_config: {} } })
    expect(screen.queryByRole('textbox', { name: /^Ключ/ })).not.toBeInTheDocument()
    expect(saveButton()).toBeDisabled()
  })

  it.each(['validating', 'discovering', 'disabled', 'deleted', 'credential_updating', 'future_state'])(
    'blocks a dirty catalog when connection becomes %s', async (status) => {
      const fetchMock = vi.fn()
      vi.stubGlobal('fetch', fetchMock)
      const { rerenderDialog } = renderDialog()
      fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
      expect(saveButton()).toBeEnabled()
      rerenderDialog({ connection: { ...baseConnection, status } })
      expect(saveButton()).toBeDisabled()
      expect(screen.getByRole('textbox', { name: 'Название' })).toBeDisabled()
      fireEvent.submit(catalogForm())
      expect(fetchMock).not.toHaveBeenCalled()
    },
  )

  it.each(['pending', 'pending_approval', 'running'])('blocks an active credential operation with %s status', (status) => {
    const connection: Connection = {
      ...baseConnection,
      admin_credential_change: {
        operation_id: 'credential-op',
        mode: 'switch',
        phase: 'candidate_proving',
        status,
        cancel_allowed: true,
        target_side_effect_possible: false,
        retryable: false,
        error_code: null,
        started_at: null,
        updated_at: baseConnection.updated_at,
      },
    }
    renderDialog({ connection })
    expect(canEditAccessTemplates(connection, true)).toBe(false)
    expect(saveButton()).toBeDisabled()
    expect(screen.getByText(/Дождитесь завершения изменения учётки/)).toBeInTheDocument()
  })

  it.each(['draft', 'active', 'degraded', 'connection_failed', 'discovery_failed'])(
    'keeps operational recovery status %s editable', (status) => {
      expect(canEditAccessTemplates({ ...baseConnection, status }, true)).toBe(true)
    },
  )

  it('does not expose an editable catalog or send a PATCH for a non-admin', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ isAdmin: false, intent: 'create' })
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByText(/только администратор/)).toBeInTheDocument()
    expect(saveButton()).toBeDisabled()
    fireEvent.submit(catalogForm())
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('fails closed for an unsupported engine', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ connection: { ...baseConnection, engine: 'mysql' }, intent: 'create' })
    expect(screen.getByText(/шаблоны пока не поддерживаются/)).toBeInTheDocument()
    expect(saveButton()).toBeDisabled()
    fireEvent.submit(catalogForm())
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('does not append a 65th MongoDB draft or render the existing catalog in Create', () => {
    const templates = Array.from({ length: 64 }, (_, index) => ({
      ...MONGO_TEMPLATE,
      key: `reader-${index}`,
      name: `Reader ${index}`,
      role_name: `reader_${index}`,
    }))
    renderDialog({
      intent: 'create',
      connection: { ...baseConnection, engine: 'mongodb', discovery_config: { mongodb_role_policy_templates: templates } },
    })
    expect(screen.queryAllByRole('button', { name: /^Развернуть Policy:/ })).toHaveLength(0)
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.getByText(/В каталоге уже 64 шаблона/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Добавить policy' })).toBeDisabled()
    expect(saveButton()).toBeDisabled()
  })

  it('blocks an oversized stored MongoDB catalog even when all template entries are valid', async () => {
    const templates = Array.from({ length: 65 }, (_, index) => ({
      ...MONGO_TEMPLATE, key: `reader-${index}`, name: `Reader ${index}`, role_name: `reader_${index}`,
    }))
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({
      connection: { ...baseConnection, engine: 'mongodb', discovery_config: { mongodb_role_policy_templates: templates } },
    })
    await userEvent.click(screen.getByRole('button', { name: 'Развернуть Policy: Reader 0' }))
    fireEvent.change(screen.getByRole('textbox', { name: /^Название/ }), { target: { value: 'Updated reader' } })
    fireEvent.submit(catalogForm())
    expect(screen.getByRole('alert')).toHaveTextContent(/64/)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('preserves MongoDB malformed-edit validation before PATCH, including collapsed privileges', () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({
      connection: {
        ...baseConnection,
        engine: 'mongodb',
        discovery_config: {
          mongodb_role_policy_templates: [{
            ...MONGO_TEMPLATE,
            privileges: [{ resource: { db: 'appdb', collection: 'events' }, actions: ['unknownAction'] }],
          }],
        },
      },
    })
    expect(screen.getByText('Исправьте policy перед сохранением')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /^Название/ }), { target: { value: 'Updated reader' } })
    fireEvent.submit(catalogForm())
    expect(saveButton().closest('[data-slot="dialog-footer"]')).toHaveTextContent(/Privilege 1:/)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('shows asynchronous validation errors in the visible footer and keeps all edits', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(jsonResponse(400, { error: 'template is in use' })))
    renderDialog()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
    await userEvent.click(saveButton())
    const error = await screen.findByText('template is in use')
    expect(error.closest('[data-slot="dialog-footer"]')).not.toBeNull()
    expect(screen.getByRole('textbox', { name: 'Название' })).toHaveValue('Local draft')
    expect(saveButton()).toBeEnabled()
  })

  it('locks fields and close while a catalog save is pending', async () => {
    let finish: (response: Response) => void = () => undefined
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => { finish = resolve }))
    vi.stubGlobal('fetch', fetchMock)
    const { onClose } = renderDialog()
    fireEvent.change(screen.getByRole('textbox', { name: 'Название' }), { target: { value: 'Local draft' } })
    await userEvent.click(saveButton())
    expect(screen.getByRole('textbox', { name: 'Название' })).toBeDisabled()
    expect(saveButton()).toBeDisabled()
    await userEvent.keyboard('{Escape}')
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.submit(catalogForm())
    expect(fetchMock).toHaveBeenCalledTimes(1)
    await act(async () => finish(jsonResponse(202, baseConnection)))
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1))
  })

  it('removes the last catalog entry without deleting unrelated configuration', async () => {
    const connection = {
      ...baseConnection,
      discovery_config: { database: 'appdb', future: { keep: true }, postgres_role_policy_templates: [POSTGRES_TEMPLATE] },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, connection))
    vi.stubGlobal('fetch', fetchMock)
    renderDialog({ connection })
    await userEvent.click(screen.getByRole('button', { name: 'Удалить policy: App DB reader' }))
    await userEvent.click(saveButton())
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      discovery_config: { database: 'appdb', future: { keep: true } },
    })
  })
})
