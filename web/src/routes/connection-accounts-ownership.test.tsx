import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection, Resource } from '../lib/types'
import { AccountsTab } from './connection-accounts'

// jsdom has no Web Animations API; this suite verifies directory semantics.
vi.mock('@formkit/auto-animate/react', () => ({
  useAutoAnimate: () => [vi.fn(), vi.fn()],
}))

vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>()
  return { ...actual, useNavigate: () => vi.fn() }
})

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'viewer@example.com', role: 'viewer', csrfToken: 'csrf' }),
  }
})

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
  created_at: '2026-08-25T00:00:00Z',
  updated_at: '2026-08-25T00:00:00Z',
}

const account: Account = {
  id: 'account-1',
  principal_id: null,
  connection_id: connection.id,
  kind: 'login',
  engine_identity: 'reports_bot',
  authentication_scope: '',
  credential_mode: null,
  vault_path: '',
  status: 'active',
  ownership: 'unmanaged',
  attributes: {},
  created_at: '2026-08-25T00:00:00Z',
  updated_at: '2026-08-25T00:00:00Z',
  bindings: [],
}

const ownedDatabase: Resource = {
  id: 'database-owned',
  connection_id: connection.id,
  parent_id: null,
  kind: 'database',
  external_id: 'database:analytics',
  name: 'analytics',
  canonical_path: 'analytics',
  attributes: { owner: account.engine_identity },
  fingerprint: 'database-owned',
  observed_at: '2026-08-25T00:00:00Z',
  status: 'observed',
  ownership: 'unmanaged',
  created_at: '2026-08-25T00:00:00Z',
  updated_at: '2026-08-25T00:00:00Z',
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('AccountsTab database ownership', () => {
  it('shows direct ownership as compact metadata in the account row', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockImplementation(() => ({
      matches: false,
      media: '(prefers-reduced-motion: reduce)',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })))
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts: [account] })
      }
      if (path === '/api/v1/principals') return response({ principals: [] })
      if (path === `/api/v1/connections/${connection.id}/resources?kind=database`) {
        return response({ resources: [ownedDatabase] })
      }
      throw new Error(`unexpected request: ${path}`)
    }))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })

    render(
      <QueryClientProvider client={client}>
        <AccountsTab
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
        />
      </QueryClientProvider>,
    )

    const row = await screen.findByText(account.engine_identity)
    const tableRow = row.closest('tr')
    expect(tableRow).not.toBeNull()
    const ownership = await within(tableRow as HTMLElement).findByLabelText('Базы во владении')
    expect(ownership).toHaveTextContent('analytics')
    expect(within(ownership).getByText('analytics')).toHaveClass('truncate')
  })
})

describe('AccountsTab account ownership', () => {
  const managedLogin: Account = {
    ...account,
    id: 'managed-login',
    engine_identity: 'managed_login',
    ownership: 'managed',
  }
  const managedRole: Account = {
    ...account,
    id: 'managed-role',
    kind: 'group',
    engine_identity: 'created_role',
    ownership: 'managed',
  }
  const unmanagedRole: Account = {
    ...account,
    id: 'unmanaged-role',
    kind: 'role',
    engine_identity: 'existing_role',
  }

  function renderDirectory(accounts: Account[]) {
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
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input)
      if (path === `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`) {
        return response({ accounts })
      }
      if (path === '/api/v1/principals') return response({ principals: [] })
      if (path === `/api/v1/connections/${connection.id}/resources?kind=database`) {
        return response({ resources: [] })
      }
      if (path.startsWith('/api/v1/accounts/') && path.endsWith('/bindings?category=roles')) {
        return response({ bindings: [] })
      }
      throw new Error(`unexpected request: ${path}`)
    }))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <AccountsTab connection={connection} permissions={[]} permissionsById={new Map()} />
      </QueryClientProvider>,
    )
  }

  it('keeps roles in a neutral section and ownership filters count only target identities', async () => {
    const user = userEvent.setup()
    renderDirectory([managedRole, account, unmanagedRole, managedLogin])

    const table = await screen.findByRole('table')
    const rows = within(table)
    const filter = within(screen.getByRole('radiogroup', { name: 'Управление аккаунтами' }))
    expect(filter.getByRole('radio', { name: 'All 4' })).toBeChecked()
    expect(filter.getByRole('radio', { name: 'Managed 1' })).not.toBeChecked()
    expect(filter.getByRole('radio', { name: 'Unmanaged 1' })).not.toBeChecked()
    expect(rows.getByRole('row', { name: /^Роли\s*2$/ })).toHaveTextContent('Роли2')
    expect(rows.getAllByRole('row').map((row) => row.textContent)).toEqual([
      expect.stringContaining('Identity'),
      'Managed1',
      expect.stringContaining('managed_login'),
      'Unmanaged1',
      expect.stringContaining('reports_bot'),
      'Роли2',
      expect.stringContaining('created_role'),
      expect.stringContaining('existing_role'),
    ])

    for (const role of [managedRole, unmanagedRole]) {
      const row = rows.getByText(role.engine_identity).closest('tr') as HTMLElement
      expect(within(row).queryByText(/^(Managed|Unmanaged)$/)).not.toBeInTheDocument()
      expect(within(row).getByText(role.engine_identity).closest('td')).not.toHaveClass('text-muted')
    }
    const managedRow = rows.getByText(managedLogin.engine_identity).closest('tr') as HTMLElement
    const unmanagedRow = rows.getByText(account.engine_identity).closest('tr') as HTMLElement
    expect(within(managedRow).getByText('Managed')).toBeInTheDocument()
    expect(within(unmanagedRow).getByText('Unmanaged')).toBeInTheDocument()

    await user.click(filter.getByRole('radio', { name: 'Managed 1' }))
    expect(rows.getByText(managedLogin.engine_identity)).toBeInTheDocument()
    expect(rows.queryByText(account.engine_identity)).not.toBeInTheDocument()
    expect(rows.queryByRole('row', { name: /^Роли\s*\d+$/ })).not.toBeInTheDocument()
    expect(rows.queryByText(managedRole.engine_identity)).not.toBeInTheDocument()
    expect(rows.queryByText(unmanagedRole.engine_identity)).not.toBeInTheDocument()

    await user.click(filter.getByRole('radio', { name: 'Unmanaged 1' }))
    expect(rows.getByText(account.engine_identity)).toBeInTheDocument()
    expect(rows.queryByText(managedLogin.engine_identity)).not.toBeInTheDocument()
    expect(rows.queryByText(managedRole.engine_identity)).not.toBeInTheDocument()
    expect(rows.queryByText(unmanagedRole.engine_identity)).not.toBeInTheDocument()

    await user.click(filter.getByRole('radio', { name: 'All 4' }))
    await user.click(rows.getByText(managedRole.engine_identity))
    expect(await screen.findByRole('dialog', { name: 'Детали: created_role' })).toBeInTheDocument()
  })

  it('keeps All available when a role-only search has an active ownership filter', async () => {
    const user = userEvent.setup()
    renderDirectory([managedLogin, managedRole, unmanagedRole])
    await screen.findByText(managedLogin.engine_identity)
    await user.click(screen.getByRole('radio', { name: 'Managed 1' }))
    await user.type(screen.getByRole('textbox', { name: 'Поиск по login, группе или роли доступа' }), '_role')

    expect(screen.getByRole('radio', { name: 'All 2' })).not.toBeChecked()
    expect(screen.getByRole('radio', { name: 'Managed 0' })).toBeChecked()
    expect(screen.queryByText(managedRole.engine_identity)).not.toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'All 2' }))

    expect(screen.getByText(managedRole.engine_identity)).toBeInTheDocument()
    expect(screen.getByText(unmanagedRole.engine_identity)).toBeInTheDocument()
    expect(screen.queryByRole('radiogroup', { name: 'Управление аккаунтами' })).not.toBeInTheDocument()
    expect(screen.queryByRole('columnheader', { name: 'Ownership' })).not.toBeInTheDocument()
  })

  it('shows a role-only directory without an empty ownership filter or column', async () => {
    renderDirectory([managedRole, unmanagedRole])
    const table = await screen.findByRole('table')
    expect(within(table).getByRole('row', { name: /^Роли\s*2$/ })).toBeInTheDocument()
    expect(within(table).getByRole('columnheader', { name: 'Роли' })).toBeInTheDocument()
    expect(within(table).getByRole('columnheader', { name: 'Прямые права' })).toBeInTheDocument()
    expect(within(table).queryByText(/^(Managed|Unmanaged|Ownership)$/)).not.toBeInTheDocument()
    expect(screen.queryByRole('radiogroup', { name: 'Управление аккаунтами' })).not.toBeInTheDocument()
    expect(screen.getByRole('radio', { name: 'Current 2' })).toBeChecked()
    expect(screen.getByRole('textbox', { name: 'Поиск по login, группе или роли доступа' })).toBeInTheDocument()
  })
})

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
