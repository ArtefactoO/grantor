import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import type { Connection } from '../lib/types'
import { EditConnectionDialog, readPublicCertificateFile } from './connection-edit-dialog'

const connection: Connection = {
  id: 'c49d856b-7862-4884-894d-993139232973',
  display_name: 'billing-postgres',
  engine: 'postgres',
  environment: 'prod',
  tags: ['payments', 'critical'],
  endpoints: ['db-1.example.com:5432', 'db-2.example.com:5432'],
  execution_mode: 'direct',
  tls_config: {
    mode: 'verify-full',
    ca_cert_pem: '',
    client_cert_pem: '',
    insecure_skip_verify: false,
  },
  admin_credential_mode: 'vault',
  vault_admin_path: 'connections/c49d856b/admin',
  capabilities: ['discover'],
  discovery_config: {
    database: 'postgres',
    sasl_mechanism: '',
    security_protocol: '',
  },
  status: 'active',
  server_version: '16.2',
  topology: {},
  last_discovery_at: '2026-07-20T12:00:00Z',
  created_at: '2026-07-20T10:00:00Z',
  updated_at: '2026-07-20T12:00:00.123456Z',
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function renderDialog(
  props: Partial<React.ComponentProps<typeof EditConnectionDialog>> = {},
) {
  const onClose = vi.fn()
  const onSaved = vi.fn()
  render(
    <EditConnectionDialog
      connection={connection}
      open
      onClose={onClose}
      onSaved={onSaved}
      {...props}
    />,
    { wrapper: Wrapper },
  )
  return { onClose, onSaved }
}

describe('EditConnectionDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('prefills editable values, focuses the first field and keeps immutable data read-only', async () => {
    renderDialog()

    const dialog = screen.getByRole('dialog', { name: 'Редактировать подключение' })
    const body = dialog.querySelector('[data-slot="dialog-body"]')
    const footer = dialog.querySelector('[data-slot="dialog-footer"]')
    const form = document.getElementById('connection-edit-form')
    const save = screen.getByRole('button', { name: 'Сохранить' })
    expect(body).toHaveClass('overflow-y-auto')
    expect(form).not.toHaveClass('overflow-y-auto')
    expect(footer).toContainElement(save)
    expect(save).toHaveAttribute('form', 'connection-edit-form')

    const name = screen.getByRole('textbox', { name: 'Отображаемое имя' })
    await waitFor(() => expect(name).toHaveFocus())
    expect(name).toHaveValue('billing-postgres')
    expect(screen.getByRole('textbox', { name: /Endpoints/ })).toHaveValue(
      'db-1.example.com:5432\ndb-2.example.com:5432',
    )
    expect(screen.getByText('direct')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /парол/i })).not.toBeInTheDocument()
    expect(save).toBeDisabled()
  })

  it('sends a metadata-only partial patch with the loaded updated_at CAS version', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, { ...connection, display_name: 'billing-primary' }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onClose, onSaved } = renderDialog()

    const name = screen.getByRole('textbox', { name: 'Отображаемое имя' })
    await user.clear(name)
    await user.type(name, 'billing-primary')
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [path, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(path).toBe(`/api/v1/connections/${connection.id}`)
    expect(options.method).toBe('PATCH')
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      display_name: 'billing-primary',
    })
  })

  it('sends changed operational fields and accepts a queued discovery response', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(202, {
        ...connection,
        endpoints: ['db-new.example.com:5432'],
        status: 'discovering',
        operation_id: '2a0d6238-0a55-4573-90f0-d541ca0ace66',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onSaved } = renderDialog()

    const endpoints = screen.getByRole('textbox', { name: /Endpoints/ })
    await user.clear(endpoints)
    await user.type(endpoints, 'db-new.example.com:5432')
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      endpoints: ['db-new.example.com:5432'],
    })
  })

  it('keeps RabbitMQ templates out of settings and leaves the catalog untouched on metadata edits', async () => {
    const rabbitConnection: Connection = {
      ...connection,
      display_name: 'rabbitmq-prod',
      engine: 'rabbitmq',
      endpoints: ['rabbit.example.com:15672'],
      discovery_config: {
        rabbitmq_permission_templates: [{
          key: 'etl-worker',
          name: 'ETL worker',
          description: 'Narrow queues',
          vhost: 'sl-project',
          configure: '^status_changes$',
          write: '^project_etl_match_state_updates$',
          read: '^status_changes$',
          dangerous: false,
        }],
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, {
      ...rabbitConnection,
      status: 'discovering',
      operation_id: 'operation-rabbit-template',
    }))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderDialog({ connection: rabbitConnection })

    await user.click(screen.getByText('Discovery'))
    expect(screen.queryByRole('textbox', { name: /^Ключ|regex/ })).not.toBeInTheDocument()
    expect(screen.queryByText('RabbitMQ permission templates')).not.toBeInTheDocument()
    const displayName = screen.getByRole('textbox', { name: 'Отображаемое имя' })
    await user.clear(displayName)
    await user.type(displayName, 'rabbitmq-primary')
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: rabbitConnection.updated_at,
      display_name: 'rabbitmq-primary',
    })
  })

  it('preserves PostgreSQL templates and opaque config while changing discovery parameters', async () => {
    const postgresConnection: Connection = {
      ...connection,
      discovery_config: {
        database: 'appdb',
        future_discovery_option: { enabled: true },
        postgres_role_policy_templates: [{
          key: 'appdb-read',
          name: 'App DB — чтение',
          description: 'Для аналитики',
          role_name: 'r_appdb',
          database: 'appdb',
          schemas: ['public'],
          owner_roles: ['app_owner'],
          creator_roles: ['app_migrations'],
          profile: 'read',
        }],
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, {
      ...postgresConnection,
      status: 'discovering',
      operation_id: 'operation-postgres-policy',
    }))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderDialog({ connection: postgresConnection })

    await user.click(screen.getByText('Discovery'))
    expect(screen.queryByRole('textbox', { name: /SQL|ACL/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /^Creator-роли/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /READ\/RW/ })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /База для discovery/ }), {
      target: { value: 'postgres' },
    })
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: postgresConnection.updated_at,
      discovery_config: {
        database: 'postgres',
        future_discovery_option: { enabled: true },
        postgres_role_policy_templates: [{
          key: 'appdb-read',
          name: 'App DB — чтение',
          description: 'Для аналитики',
          role_name: 'r_appdb',
          database: 'appdb',
          schemas: ['public'],
          owner_roles: ['app_owner'],
          creator_roles: ['app_migrations'],
          profile: 'read',
        }],
      },
    })
  })

  it('preserves MongoDB custom-role templates exactly when editing replica discovery', async () => {
    const mongodbConnection: Connection = {
      ...connection,
      display_name: 'mongodb-prod',
      engine: 'mongodb',
      endpoints: ['mongo-1.example.com:27017'],
      discovery_config: {
        auth_source: 'admin',
        replica_set: 'rs0',
        mongodb_role_policy_templates: [{
          key: 'etl-reader',
          name: 'ETL reader',
          description: 'Read event data',
          role_name: 'etlReader',
          role_database: 'admin',
          inherited_roles: [{ role: 'read', db: 'appdb' }],
          privileges: [
            {
              resource: { db: 'appdb', collection: 'events' },
              actions: ['find'],
            },
            {
              resource: { cluster: true },
              actions: ['serverStatus'],
            },
          ],
        }],
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(202, {
      ...mongodbConnection,
      status: 'discovering',
      operation_id: 'operation-mongodb-policy',
    }))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderDialog({ connection: mongodbConnection })

    await user.click(screen.getByText('Discovery'))
    expect(screen.queryByRole('textbox', { name: /BSON|JSON|command/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Policy: ETL reader/ })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: /Replica set/ }), {
      target: { value: 'rs1' },
    })
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: mongodbConnection.updated_at,
      discovery_config: {
        auth_source: 'admin',
        replica_set: 'rs1',
        mongodb_role_policy_templates: [{
          key: 'etl-reader',
          name: 'ETL reader',
          description: 'Read event data',
          role_name: 'etlReader',
          role_database: 'admin',
          inherited_roles: [{ role: 'read', db: 'appdb' }],
          privileges: [
            {
              resource: { db: 'appdb', collection: 'events' },
              actions: ['find'],
            },
            {
              resource: { cluster: true },
              actions: ['serverStatus'],
            },
          ],
        }],
      },
    })
  })

  it('does not validate or rewrite hidden MongoDB catalogs during a metadata-only edit', async () => {
    const mongodbConnection: Connection = {
      ...connection,
      display_name: 'mongodb-prod',
      engine: 'mongodb',
      endpoints: ['mongo.example.com:27017'],
      discovery_config: {
        auth_source: 'admin',
        replica_set: 'rs0',
        mongodb_role_policy_templates: [{ key: 'invalid-legacy-policy' }],
      },
    }
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, mongodbConnection))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderDialog({ connection: mongodbConnection })

    await user.click(screen.getByText('Discovery'))
    expect(screen.queryByRole('button', { name: 'Добавить policy' })).not.toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Отображаемое имя' }), {
      target: { value: 'mongodb-renamed' },
    })
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: mongodbConnection.updated_at,
      display_name: 'mongodb-renamed',
    })
  })

  it('pins the opening CAS version instead of rebasing an unsaved form after a refetch', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(409, { error: 'updated_at conflict' }))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const props = { open: true, onClose: vi.fn(), connection }
    const { rerender } = render(<EditConnectionDialog {...props} />, { wrapper: Wrapper })
    fireEvent.change(screen.getByRole('textbox', { name: 'Отображаемое имя' }), {
      target: { value: 'my-unsaved-name' },
    })
    rerender(<EditConnectionDialog {...props} connection={{
      ...connection,
      updated_at: '2026-08-26T12:00:00Z',
      display_name: 'concurrently-renamed',
    }} />)
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(String(options.body))).toEqual({
      updated_at: connection.updated_at,
      display_name: 'my-unsaved-name',
    })
    expect(await screen.findByText(/Перезагрузите данные подключения/)).toBeVisible()
    expect(screen.getByRole('textbox', { name: 'Отображаемое имя' })).toHaveValue('my-unsaved-name')
  })

  it('maps a server validation error to the field and preserves unsaved input', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        jsonResponse(400, { error: 'endpoint must be host:port without a scheme' }),
      ),
    )
    const user = userEvent.setup()
    renderDialog()

    const endpoints = screen.getByRole('textbox', { name: /Endpoints/ })
    await user.clear(endpoints)
    await user.type(endpoints, 'https://db.example.com')
    await user.click(screen.getByRole('button', { name: 'Сохранить' }))

    expect(
      await screen.findByText('endpoint must be host:port without a scheme'),
    ).toBeInTheDocument()
    expect(endpoints).toHaveValue('https://db.example.com')
    expect(endpoints).toHaveAttribute('aria-invalid', 'true')
  })

  it('does not discard a dirty form on Escape without an explicit confirmation', async () => {
    const user = userEvent.setup()
    const { onClose } = renderDialog()
    const name = screen.getByRole('textbox', { name: 'Отображаемое имя' })

    await user.type(name, ' changed')
    await user.keyboard('{Escape}')

    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Есть несохранённые изменения.')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Отменить изменения' }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('keeps metadata editable but locks operational fields for a disabled connection', () => {
    renderDialog({ connection: { ...connection, status: 'disabled' } })

    expect(screen.getByRole('textbox', { name: 'Отображаемое имя' })).toBeEnabled()
    expect(screen.getByRole('textbox', { name: /Endpoints/ })).toBeDisabled()
    expect(
      screen.getByText(/Отключённое подключение можно переименовать/),
    ).toBeInTheDocument()
  })

  it('loads a public CA certificate from a local file', async () => {
    const user = userEvent.setup()
    renderDialog()
    await user.click(screen.getByText('TLS'))
    const pem = '-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n'
    const file = new File([pem], 'cluster-ca.pem', { type: 'application/x-pem-file' })

    await user.upload(screen.getByLabelText('Загрузить CA-сертификат из файла'), file)

    await waitFor(() =>
      expect(screen.getByRole('textbox', { name: /CA certificate/ })).toHaveValue(pem),
    )
    expect(screen.getByRole('button', { name: 'Сохранить' })).toBeEnabled()
  })

  it('rejects an unsupported certificate extension before reading the file', async () => {
    const text = vi.fn().mockResolvedValue(
      '-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n',
    )
    const file = {
      name: 'cluster-ca.txt',
      size: 64,
      text,
    } as unknown as File

    await expect(readPublicCertificateFile(file)).rejects.toThrow(
      'расширением .pem, .crt или .cer',
    )
    expect(text).not.toHaveBeenCalled()
  })

  it('accepts supported certificate extensions case-insensitively', async () => {
    const pem = '-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n'

    for (const name of ['cluster.PEM', 'cluster.CRT', 'cluster.CeR']) {
      const file = new File([pem], name, { type: 'application/x-pem-file' })
      await expect(readPublicCertificateFile(file)).resolves.toBe(pem)
    }
  })

  it('rejects a private key selected in the certificate file control', async () => {
    const user = userEvent.setup()
    renderDialog()
    await user.click(screen.getByText('TLS'))
    const file = new File(
      ['-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----'],
      'client-key.pem',
      { type: 'application/x-pem-file' },
    )

    await user.upload(screen.getByLabelText('Загрузить клиентский сертификат из файла'), file)

    expect(
      await screen.findByText(/Private key загружать нельзя/),
    ).toBeInTheDocument()
    expect(screen.getByRole('textbox', { name: /Client certificate/ })).toHaveValue('')
  })
})
