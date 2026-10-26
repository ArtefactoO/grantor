import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { MockInstance } from 'vitest'
import type { Account, Operation } from '../lib/types'
import { BulkOperationPanel } from './BulkOperationPanel'

const auth = vi.hoisted(() => ({ role: 'admin' }))

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'admin@example.com', role: auth.role, csrfToken: 'csrf' }),
  }
})

const account: Account = {
  id: 'account-1',
  principal_id: 'principal-1',
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

function operation(overrides: Partial<Operation> = {}): Operation {
  return {
    id: 'operation-1',
    parent_id: null,
    idempotency_key: null,
    kind: 'account.delete',
    status: 'pending_approval',
    connection_id: 'connection-1',
    principal_id: 'principal-1',
    account_id: account.id,
    resource_id: null,
    binding_id: null,
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
    ...overrides,
  }
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children, client }: { children: ReactNode; client: QueryClient }) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function setup(value: Operation) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input)
    if (path === `/api/v1/operations/${value.id}` && (init?.method ?? 'GET') === 'GET') {
      return response(value)
    }
    if (path.startsWith(`/api/v1/operations/${value.id}/`) && init?.method === 'POST') {
      return response({}, 202)
    }
    throw new Error(`unexpected request: ${path}`)
  })

  render(
    <Wrapper client={client}>
      <BulkOperationPanel operationId={value.id} accounts={[account]} onClose={vi.fn()} />
    </Wrapper>,
  )
  return { client, fetchMock }
}

function postCalls(fetchMock: MockInstance<typeof fetch>) {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')
}

beforeEach(() => {
  auth.role = 'admin'
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('BulkOperationPanel inline approval', () => {
  it('requires an explicit admin confirmation before posting a single approval', async () => {
    const user = userEvent.setup()
    const value = operation()
    const { fetchMock } = setup(value)

    expect(await screen.findByText('reports_bot')).toBeInTheDocument()
    expect(screen.getByText('Удаление аккаунта')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Подтвердить и выполнить' }))

    expect(postCalls(fetchMock)).toHaveLength(0)
    const dialog = screen.getByRole('dialog', { name: 'Подтвердить изменение' })
    expect(dialog).toHaveTextContent('Удаление аккаунта: изменение будет отправлено на выполнение')
    await user.click(within(dialog).getByRole('button', { name: 'Подтвердить и выполнить' }))

    await waitFor(() => expect(postCalls(fetchMock)).toHaveLength(1))
    expect(String(postCalls(fetchMock)[0][0])).toBe('/api/v1/operations/operation-1/approve')
  })

  it('uses approve-children for pending children of a parent operation', async () => {
    const user = userEvent.setup()
    const value = operation({
      status: 'pending',
      aggregate_status: 'pending_approval',
      children: [
        operation({ id: 'child-1', parent_id: 'operation-1', kind: 'binding.create' }),
        operation({ id: 'child-2', parent_id: 'operation-1', kind: 'account.create' }),
      ],
    })
    const { fetchMock } = setup(value)

    await user.click(await screen.findByRole('button', { name: 'Подтвердить и выполнить' }))
    const dialog = screen.getByRole('dialog', { name: 'Подтвердить изменение' })
    expect(dialog).toHaveTextContent('2 ожидающих операций пачки')
    await user.click(within(dialog).getByRole('button', { name: 'Подтвердить и выполнить' }))

    await waitFor(() => expect(postCalls(fetchMock)).toHaveLength(1))
    expect(String(postCalls(fetchMock)[0][0])).toBe(
      '/api/v1/operations/operation-1/approve-children',
    )
  })

  it.each(['operator', 'viewer'])('keeps pending approval read-only for %s', async (role) => {
    auth.role = role
    const { fetchMock } = setup(operation())

    expect(await screen.findByText(/Решение доступно только admin/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Подтвердить и выполнить' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Отклонить' })).not.toBeInTheDocument()
    expect(postCalls(fetchMock)).toHaveLength(0)
  })

  it('uses the supported reject endpoint only after a danger confirmation', async () => {
    const user = userEvent.setup()
    const { fetchMock } = setup(operation())

    await user.click(await screen.findByRole('button', { name: 'Отклонить' }))
    expect(postCalls(fetchMock)).toHaveLength(0)
    const dialog = screen.getByRole('dialog', { name: 'Отклонить изменение' })
    await user.click(within(dialog).getByRole('button', { name: 'Отклонить' }))

    await waitFor(() => expect(postCalls(fetchMock)).toHaveLength(1))
    expect(String(postCalls(fetchMock)[0][0])).toBe('/api/v1/operations/operation-1/reject')
  })

  it('invalidates detail, operation lists, approvals and audit after a decision', async () => {
    const user = userEvent.setup()
    const value = operation()
    const { client } = setup(value)
    const invalidate = vi.spyOn(client, 'invalidateQueries')

    await user.click(await screen.findByRole('button', { name: 'Подтвердить и выполнить' }))
    await user.click(
      within(screen.getByRole('dialog')).getByRole('button', {
        name: 'Подтвердить и выполнить',
      }),
    )

    await waitFor(() => expect(invalidate).toHaveBeenCalledWith({ queryKey: ['approvals'] }))
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: ['operations', 'detail', 'operation-1'],
    })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['operations'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['audit'] })
  })
})
