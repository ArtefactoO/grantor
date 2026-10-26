import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection, Principal } from '../lib/types'
import { LinkPrincipalDialog } from './connection-account-dialogs'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, ...props }: { children: ReactNode }) => <a {...props}>{children}</a>,
}))

const account: Account = {
  id: 'account-1',
  principal_id: null,
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'reports_bot',
  authentication_scope: '',
  credential_mode: null,
  vault_path: '',
  status: 'active',
  ownership: 'unmanaged',
  attributes: {},
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
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
  capabilities: ['credential.rotate', 'credential.prove'],
  discovery_config: {},
  status: 'active',
  server_version: '16',
  topology: {},
  last_discovery_at: null,
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
}

const principal: Principal = {
  id: 'principal-1',
  type: 'human',
  display_name: 'Анна Кутина',
  external_provider: 'ldap',
  external_subject: 'akutikina',
  external_identity_status: 'active',
  external_identity_checked_at: '2026-07-22T00:00:00Z',
  external_identity_status_changed_at: null,
  status: 'active',
  attributes: {},
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
}

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

function renderDialog(onLinked = vi.fn()) {
  render(
    <Wrapper>
      <LinkPrincipalDialog
        open
        account={account}
        connection={connection}
        onClose={vi.fn()}
        onLinked={onLinked}
      />
    </Wrapper>,
  )
  return onLinked
}

describe('LinkPrincipalDialog modes', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('keeps metadata-only linking explicit and does not send credential data', async () => {
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/accounts/account-1/link') {
        posted = { path, body: JSON.parse(String(init?.body)) }
        return response(account)
      }
      throw new Error(`unexpected fetch ${path}`)
    }))
    const onLinked = renderDialog()
    const user = userEvent.setup()

    const principalList = await screen.findByRole('radiogroup', { name: 'Пользователь' })
    expect(principalList).not.toHaveClass('overflow-y-auto')
    const submit = screen.getByRole('button', { name: 'Связать для учёта' })
    expect(submit.closest('[data-slot="dialog-footer"]')).not.toBeNull()

    await user.click(await screen.findByRole('radio', { name: /Анна Кутина/ }))
    expect(screen.getByText(/пароль аккаунта и целевая система не меняются/)).toBeVisible()
    await user.click(submit)

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/accounts/account-1/link',
      body: { principal_id: 'principal-1' },
    }))
    expect(onLinked).toHaveBeenCalledWith('Анна Кутина', 'record', undefined)
  })

  it('creates the first environment credential and clears a provided password on submit', async () => {
    let postedBody: unknown = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/principals/principal-1/credentials') {
        return response({
          credentials: [{ environment: 'prod', connections: 1, configured: false }],
        })
      }
      if (path === '/api/v1/accounts/account-1/link-and-manage') {
        postedBody = JSON.parse(String(init?.body))
        return response({
          account_id: account.id,
          principal_id: principal.id,
          environment: 'prod',
          operation_id: 'operation-1',
        })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))
    renderDialog()
    const user = userEvent.setup()

    await user.click(await screen.findByRole('radio', { name: /Анна Кутина/ }))
    await user.click(screen.getByRole('radio', { name: /Связать и управлять/ }))
    await screen.findByText(/первый общий пароль/)
    await user.click(screen.getByRole('radio', { name: /Задать пароль/ }))
    const password = screen.getByLabelText(/^Пароль/)
    await user.type(password, 'correct horse battery')
    await user.click(screen.getByRole('button', { name: 'Связать и управлять' }))

    await waitFor(() => expect(postedBody).toEqual({
      principal_id: 'principal-1',
      credential: { mode: 'provided', password: 'correct horse battery' },
    }))
    expect(password).toHaveValue('')
  })

  it('reuses an existing shared credential without asking for another password', async () => {
    let postedBody: unknown = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals') return response({ principals: [principal] })
      if (path === '/api/v1/principals/principal-1/credentials') {
        return response({
          credentials: [{ environment: 'prod', connections: 1, configured: true }],
        })
      }
      if (path === '/api/v1/accounts/account-1/link-and-manage') {
        postedBody = JSON.parse(String(init?.body))
        return response({
          account_id: account.id,
          principal_id: principal.id,
          environment: 'prod',
          operation_id: 'operation-1',
        })
      }
      throw new Error(`unexpected fetch ${path}`)
    }))
    renderDialog()
    const user = userEvent.setup()

    await user.click(await screen.findByRole('radio', { name: /Анна Кутина/ }))
    await user.click(screen.getByRole('radio', { name: /Связать и управлять/ }))
    expect(await screen.findByText(/уже настроен и будет переиспользован/)).toBeVisible()
    expect(screen.queryByRole('radio', { name: /Задать пароль/ })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Связать и управлять' }))

    await waitFor(() => expect(postedBody).toEqual({
      principal_id: 'principal-1',
    }))
  })
})
