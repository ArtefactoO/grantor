import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection } from '../lib/types'
import {
  RestoreAccountDialog,
  restorePasswordError,
} from './connection-account-restore'

const account: Account = {
  id: 'account-deleted',
  principal_id: null,
  connection_id: 'connection',
  kind: 'login',
  engine_identity: 'reporting_user',
  authentication_scope: '',
  credential_mode: 'vault',
  vault_path: 'accounts/account-deleted',
  status: 'deleted',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
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

function renderRestore() {
  const onClose = vi.fn()
  const onRestored = vi.fn()
  render(
    <RestoreAccountDialog
      open
      account={account}
      connectionId="connection"
      onClose={onClose}
      onRestored={onRestored}
    />,
    { wrapper: Wrapper },
  )
  return { onClose, onRestored }
}

function renderLinkedRestore() {
  const linkedAccount: Account = {
    ...account,
    principal_id: 'principal-1',
    credential_mode: 'existing_vault_ref',
    vault_path: 'principals/principal-1/environments/dev/credential',
  }
  const onClose = vi.fn()
  const onRestored = vi.fn()
  render(
    <RestoreAccountDialog
      open
      account={linkedAccount}
      connectionId="connection"
      onClose={onClose}
      onRestored={onRestored}
    />,
    { wrapper: Wrapper },
  )
  return { linkedAccount, onClose, onRestored }
}

const insufficientConnection: Connection = {
  id: 'connection', display_name: 'PostgreSQL', engine: 'postgres', environment: 'test',
  tags: [], endpoints: ['db:5432'], execution_mode: 'direct', tls_config: {},
  admin_credential_mode: 'vault', vault_admin_path: 'connections/connection/admin',
  capabilities: [], discovery_config: {}, status: 'active', server_version: '16', topology: {},
  last_discovery_at: '2026-08-27T10:00:00Z', created_at: '2026-08-27T09:00:00Z',
  updated_at: '2026-08-27T10:00:00Z', postgres_provisioning_authority: {
    status: 'insufficient', reason: 'superuser_required', observed_at: '2026-08-27T10:00:00Z',
    expected_admin_identity: 'grantor', observed_admin_identity: 'grantor', credential_incarnation: 1,
    config_incarnation: 'a'.repeat(64), target_identity: 'postgres:system:42',
  },
}

describe('RestoreAccountDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('waits for success and shares generated credentials only afterwards', async () => {
    const fetchMock = vi.fn(async (path: string, _options?: RequestInit) => {
      if (path.endsWith('/restore')) {
        return jsonResponse(202, { account_id: account.id, operation_id: 'operation-1' })
      }
      if (path === '/api/v1/operations/operation-1') {
        return jsonResponse(200, {
          id: 'operation-1',
          status: 'success',
          error: '',
        })
      }
      if (path.endsWith('/share')) {
        return jsonResponse(201, {
          link: 'https://secret.example/once',
          expires_in_hours: 24,
          one_time: true,
        })
      }
      throw new Error(`unexpected path ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onRestored } = renderRestore()

    expect(screen.getByText(/Прежние роли и права не восстанавливаются/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Восстановить' }))

    await waitFor(() => expect(onRestored).toHaveBeenCalledWith('operation-1'))
    expect(fetchMock.mock.calls.map(([path]) => path)).toEqual([
      `/api/v1/accounts/${account.id}/restore`,
      '/api/v1/operations/operation-1',
      `/api/v1/accounts/${account.id}/share`,
    ])
    expect(screen.getByText('https://secret.example/once')).toBeInTheDocument()
  })

  it('never shares or echoes a provided password and clears it at submit', async () => {
    const fetchMock = vi.fn(async (path: string, _options?: RequestInit) => {
      if (path.endsWith('/restore')) {
        return jsonResponse(202, { account_id: account.id, operation_id: 'operation-2' })
      }
      if (path === '/api/v1/operations/operation-2') {
        return jsonResponse(200, {
          id: 'operation-2',
          status: 'success',
          error: '',
        })
      }
      throw new Error(`unexpected path ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onRestored } = renderRestore()
    const secret = 'Very-safe-password-42'

    await user.click(screen.getByText('Задать пароль'))
    await user.type(screen.getByLabelText('Новый пароль'), secret)
    await user.click(screen.getByRole('button', { name: 'Восстановить' }))

    await waitFor(() => expect(onRestored).toHaveBeenCalledWith('operation-2'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
    const options = fetchMock.mock.calls[0][1]
    expect(JSON.parse(String(options?.body))).toEqual({
      credential: { mode: 'provided', password: secret },
    })
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument()
    expect(screen.queryByText(secret)).not.toBeInTheDocument()
  })

  it('turns a restore conflict into an actionable error without polling or sharing', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(409, { error: 'account still has bindings' }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderRestore()

    await user.click(screen.getByRole('button', { name: 'Восстановить' }))

    expect(
      await screen.findByText(/подключение активно, поддерживает восстановление/),
    ).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('restores a linked account with the current principal credential and does not share it', async () => {
    const fetchMock = vi.fn(async (path: string, options?: RequestInit) => {
      if (path.endsWith('/restore')) {
        expect(JSON.parse(String(options?.body))).toEqual({
          credential: { mode: 'existing_vault_ref' },
        })
        return jsonResponse(202, { account_id: 'account-deleted', operation_id: 'operation-3' })
      }
      if (path === '/api/v1/operations/operation-3') {
        return jsonResponse(200, { id: 'operation-3', status: 'success', error: '' })
      }
      throw new Error(`unexpected path ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onRestored } = renderLinkedRestore()

    expect(screen.getByText('Использовать пароль пользователя')).toBeInTheDocument()
    expect(screen.getByText(/актуальным паролем глобального пользователя/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Восстановить' }))

    await waitFor(() => expect(onRestored).toHaveBeenCalledWith('operation-3'))
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('blocks restore before submit when SUPERUSER is not confirmed', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    render(
      <RestoreAccountDialog open account={account} connectionId="connection"
        connection={insufficientConnection} onClose={vi.fn()} onRestored={vi.fn()} />,
      { wrapper: Wrapper },
    )
    await waitFor(() => expect(screen.getByText(/не является PostgreSQL SUPERUSER/)).toBeVisible())
    const submit = screen.getByRole('button', { name: 'Восстановить' })
    expect(submit).toBeDisabled()
    expect(document.getElementById(submit.getAttribute('aria-describedby') ?? '')).toHaveTextContent('SUPERUSER')
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('restore password validation', () => {
  it('enforces 12..256 Unicode characters', () => {
    expect(restorePasswordError('short')).toMatch(/не меньше 12/)
    expect(restorePasswordError('пароль-длиной-12')).toBeNull()
    expect(restorePasswordError('x'.repeat(257))).toMatch(/не больше 256/)
    expect(restorePasswordError(`valid-password\u0000`)).toMatch(/нулевой символ/)
  })
})
