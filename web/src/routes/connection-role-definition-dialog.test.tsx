import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parseRoleTemplatesDocument } from '../lib/role-template-document'
import type { RoleTemplateCatalog } from '../lib/role-template-document'
import type { Connection, Permission } from '../lib/types'
import { ConnectionRoleDefinitionDialog } from './connection-role-definition-dialog'

const writeText = vi.fn().mockResolvedValue(undefined)

const catalogs: RoleTemplateCatalog[] = [
  {
    engine: 'postgres',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event data',
      role_name: 'r_events', database: 'events', schemas: ['public'],
      owner_roles: ['events_owner'], creator_roles: ['events_migrations'], profile: 'read',
    }],
  },
  {
    engine: 'rabbitmq',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event queues',
      vhost: 'sl-project', configure: '^$', write: '^events_out$',
      read: '^(status_changes|events_out)$', dangerous: false,
    }],
  },
  {
    engine: 'mongodb',
    templates: [{
      key: 'events-read', name: 'Event reader', description: 'Read event data',
      role_name: 'eventsReader', role_database: 'admin',
      inherited_roles: [{ role: 'read', db: 'events' }],
      privileges: [{ resource: { db: 'events', collection: 'updates' }, actions: ['find'] }],
    }],
  },
]

const catalogKeys = {
  postgres: 'postgres_role_policy_templates',
  rabbitmq: 'rabbitmq_permission_templates',
  mongodb: 'mongodb_role_policy_templates',
} as const

function connection(catalog: RoleTemplateCatalog): Connection {
  return {
    id: 'connection-1', display_name: 'Role document fixture', engine: catalog.engine,
    environment: 'test', tags: [], endpoints: [], execution_mode: 'direct', tls_config: {},
    admin_credential_mode: 'vault', vault_admin_path: '', capabilities: ['discover'],
    discovery_config: { [catalogKeys[catalog.engine]]: catalog.templates },
    status: 'active', server_version: '', topology: {}, last_discovery_at: null,
    created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00Z',
  }
}

function identity(catalog: RoleTemplateCatalog): string {
  switch (catalog.engine) {
    case 'postgres': return `role:${catalog.templates[0].role_name}`
    case 'mongodb': return `role:${catalog.templates[0].role_database}.${catalog.templates[0].role_name}`
    case 'rabbitmq': return `rabbitmq-template:${catalog.templates[0].key}`
  }
}

function permission(catalog: RoleTemplateCatalog, overrides: Partial<Permission> = {}): Permission {
  return {
    id: 'permission-1', connection_id: 'connection-1', engine: catalog.engine,
    external_id: identity(catalog), name: 'Observed role', scope_resource_id: null,
    assignable: true, dangerous: false,
    attributes: {
      [catalog.engine === 'rabbitmq' ? 'template_key' : 'role_policy_key']: catalog.templates[0].key,
      private_metadata: 'excluded-field-fixture',
    },
    normalized: {
      category: 'role', action: '', resource: '', scope: '', dangerous: false,
      danger_reason: '', details: null, raw: identity(catalog),
    },
    status: 'observed', created_at: '2026-08-26T10:00:00Z', updated_at: '2026-08-26T10:00:00Z',
    ...overrides,
  }
}

function jsonField(label = 'JSON роли'): HTMLTextAreaElement {
  return screen.getByLabelText(label) as HTMLTextAreaElement
}

describe('role definition document dialog', () => {
  const fetchMock = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    fetchMock.mockRejectedValue(new Error('Unexpected network access from a read-only document'))
    vi.stubGlobal('fetch', fetchMock)
    writeText.mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
  })

  afterEach(() => {
    cleanup()
    expect(fetchMock).not.toHaveBeenCalled()
    vi.unstubAllGlobals()
    Reflect.deleteProperty(navigator, 'clipboard')
  })

  it.each(catalogs)('shows a read-only, round-trippable $engine template document', async (catalog) => {
    render(<ConnectionRoleDefinitionDialog
      connection={connection(catalog)}
      templateKey={catalog.templates[0].key}
      onClose={vi.fn()}
    />)

    const field = jsonField()
    await waitFor(() => expect(field).toBeVisible())
    expect(field).toHaveAttribute('readonly')
    expect(parseRoleTemplatesDocument(field.value, catalog.engine)).toEqual(catalog)
    expect(screen.getByText('Шаблон для создания · JSON v1')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Создать по образцу' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Применить|Исправить|Отозвать/ })).not.toBeInTheDocument()
    expect(screen.getByText(/Это сохранённый шаблон желаемых прав/)).toBeVisible()
  })

  it.each(catalogs)('resolves a $engine permission to its published template and copies only that document', async (catalog) => {
    const onCreate = vi.fn()
    render(<ConnectionRoleDefinitionDialog
      connection={connection(catalog)}
      permission={permission(catalog)}
      onClose={vi.fn()}
      onCreate={onCreate}
    />)
    const field = jsonField()
    await waitFor(() => expect(field).toBeVisible())

    fireEvent.click(screen.getByRole('button', { name: 'Копировать JSON роли' }))

    await screen.findByRole('button', { name: 'Скопировано' })
    expect(writeText).toHaveBeenCalledOnce()
    expect(writeText).toHaveBeenCalledWith(field.value)
    expect(parseRoleTemplatesDocument(field.value, catalog.engine)).toEqual(catalog)
    expect(field.value).not.toContain('excluded-field-fixture')
    expect(onCreate).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: 'Создать по образцу' }))

    expect(onCreate).toHaveBeenCalledOnce()
    expect(onCreate).toHaveBeenCalledWith(catalog)
  })

  it.each(catalogs)('shows unmatched $engine roles as non-importable snapshots with no clone action', async (catalog) => {
    const onCreate = vi.fn()
    render(<ConnectionRoleDefinitionDialog
      connection={connection(catalog)}
      permission={permission(catalog, { attributes: { private_metadata: 'excluded-field-fixture' } })}
      onClose={vi.fn()}
      onCreate={onCreate}
    />)
    const field = jsonField('Снимок роли JSON')
    await waitFor(() => expect(field).toBeVisible())

    expect(field).toHaveAttribute('readonly')
    expect(JSON.parse(field.value).kind).toBe('role_snapshot')
    expect(() => parseRoleTemplatesDocument(field.value, catalog.engine)).toThrow()
    expect(field.value).not.toContain('excluded-field-fixture')
    expect(screen.getByText(/Копирование прав этой роли пока недоступно/)).toBeVisible()
    expect(screen.getByText('Метаданные · не для создания')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Создать по образцу' })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Копировать снимок роли' }))

    await screen.findByRole('button', { name: 'Скопировано' })
    expect(writeText).toHaveBeenCalledWith(field.value)
    expect(onCreate).not.toHaveBeenCalled()
  })

  it.each([
    { connection_id: 'another-connection' },
    { engine: 'mongodb' },
    { external_id: 'role:another_role' },
  ])('does not offer a clone when permission identity mismatches: %j', async (overrides) => {
    const catalog = catalogs[0]
    render(<ConnectionRoleDefinitionDialog
      connection={connection(catalog)}
      permission={permission(catalog, overrides)}
      onClose={vi.fn()}
      onCreate={vi.fn()}
    />)

    await waitFor(() => expect(jsonField('Снимок роли JSON')).toBeVisible())
    expect(screen.queryByRole('button', { name: 'Создать по образцу' })).not.toBeInTheDocument()
    expect(screen.queryByLabelText('JSON роли')).not.toBeInTheDocument()
  })

  it('explains a removed catalog entry without fabricating a document', async () => {
    const onClose = vi.fn()
    render(<ConnectionRoleDefinitionDialog
      connection={connection(catalogs[0])}
      templateKey="removed-key"
      onClose={onClose}
      onCreate={vi.fn()}
    />)

    await waitFor(() => expect(screen.getByText(/Шаблон больше не найден/)).toBeVisible())
    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Копировать|Создать по образцу/ })).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Закрыть описание' }))
    expect(onClose).toHaveBeenCalledOnce()
  })

  it('does not reuse a previous template document after the selected catalog changes', async () => {
    const source = connection(catalogs[0])
    const props = { connection: source, templateKey: 'events-read', onClose: vi.fn(), onCreate: vi.fn() }
    const result = render(<ConnectionRoleDefinitionDialog {...props} />)
    await waitFor(() => expect(jsonField()).toBeVisible())

    result.rerender(<ConnectionRoleDefinitionDialog {...props} connection={{ ...source, discovery_config: {} }} />)

    expect(screen.queryByRole('textbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать по образцу' })).not.toBeInTheDocument()
    expect(screen.getByText(/Шаблон больше не найден/)).toBeVisible()
  })
})
