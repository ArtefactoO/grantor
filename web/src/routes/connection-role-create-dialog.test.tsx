import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection } from '../lib/types'
import { CreateRoleDialog } from './connection-role-create-dialog'

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function response(body: unknown, status = 202): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

const insufficientPostgres: Connection = {
  id: 'connection-1', display_name: 'PostgreSQL', engine: 'postgres', environment: 'test',
  tags: [], endpoints: ['db:5432'], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: 'connections/connection-1/admin',
  capabilities: [], discovery_config: {}, status: 'active', server_version: '16', topology: {},
  last_discovery_at: '2026-08-27T10:00:00Z', created_at: '2026-08-27T09:00:00Z',
  updated_at: '2026-08-27T10:00:00Z', postgres_provisioning_authority: {
    status: 'insufficient', reason: 'superuser_required', observed_at: '2026-08-27T10:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 3,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
  },
}

describe('CreateRoleDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('posts the role name and reports the started operation', async () => {
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = { path: String(input), body: JSON.parse(String(init?.body)) }
      return response({ account_id: 'account-1', operation_id: 'operation-1' })
    }))
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const user = userEvent.setup()

    render(
      <Wrapper>
        <CreateRoleDialog
          connectionId="connection-1"
          open
          onClose={onClose}
          onStarted={onStarted}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('dialog', { name: 'Создать пустую роль' })).toBeInTheDocument()

    await user.type(screen.getByLabelText(/^Имя роли/), 'r_appdb')
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/connections/connection-1/roles',
      body: { name: 'r_appdb' },
    }))
    expect(onStarted).toHaveBeenCalledWith('operation-1', 'r_appdb')
    expect(onClose).toHaveBeenCalled()
  })

  // Имя уходит в CREATE ROLE идентификатором: пробел внутри отсекается до
  // запроса, чтобы отказ не приходил с бэкенда постфактум.
  it('rejects a name with whitespace without calling the API', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    const user = userEvent.setup()

    render(
      <Wrapper>
        <CreateRoleDialog
          connectionId="connection-1"
          open
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.type(screen.getByLabelText(/^Имя роли/), 'app read')
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    expect(await screen.findByText(/не должно содержать пробельных символов/)).toBeInTheDocument()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('surfaces the API refusal', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      response({ error: 'identity "r_appdb" already exists in this connection' }, 409),
    ))
    const user = userEvent.setup()

    render(
      <Wrapper>
        <CreateRoleDialog
          connectionId="connection-1"
          open
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.type(screen.getByLabelText(/^Имя роли/), 'r_appdb')
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    expect(await screen.findByText(/already exists/)).toBeInTheDocument()
  })

  it('shows the SUPERUSER blocker and disables submit before a request', async () => {
    const fetchSpy = vi.fn()
    vi.stubGlobal('fetch', fetchSpy)
    render(
      <Wrapper>
        <CreateRoleDialog connectionId="connection-1" connection={insufficientPostgres} open
          onClose={vi.fn()} onStarted={vi.fn()} />
      </Wrapper>,
    )
    await waitFor(() => expect(screen.getByText(/не является PostgreSQL SUPERUSER/)).toBeVisible())
    const submit = screen.getByRole('button', { name: 'Создать' })
    expect(submit).toBeDisabled()
    expect(document.getElementById(submit.getAttribute('aria-describedby') ?? '')).toHaveTextContent('SUPERUSER')
    expect(fetchSpy).not.toHaveBeenCalled()
  })
})
