import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account, Binding, Permission, Principal } from '../lib/types'
import {
  AdoptAccountDialog,
  AssignSharedRoleDrawer,
} from './connection-account-dialogs'

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({
      email: 'admin@grantor.dev',
      role: 'admin',
      csrfToken: 'csrf',
    }),
  }
})

const roleAccount: Account = {
  id: 'role-account',
  principal_id: null,
  connection_id: 'connection-1',
  kind: 'group',
  engine_identity: 'report_reader',
  authentication_scope: '',
  credential_mode: null,
  vault_path: '',
  status: 'active',
  ownership: 'unmanaged',
  attributes: {},
  created_at: '2026-07-23T00:00:00Z',
  updated_at: '2026-07-23T00:00:00Z',
}

const rolePermission: Permission = {
  id: 'permission-role',
  connection_id: roleAccount.connection_id,
  engine: 'postgres',
  external_id: 'role:report_reader',
  name: 'report_reader',
  scope_resource_id: null,
  assignable: true,
  status: 'observed',
  dangerous: false,
  attributes: {},
  created_at: '2026-07-23T00:00:00Z',
  updated_at: '2026-07-23T00:00:00Z',
    normalized: {
      category: 'role', action: '', resource: 'report_reader', scope: '',
      dangerous: false, danger_reason: '', details: null, raw: 'report_reader',
    },
}

const principal: Principal = {
  id: 'principal-alice',
  type: 'human',
  display_name: 'alice',
  external_provider: '',
  external_subject: '',
  status: 'active',
  attributes: {},
  created_at: '2026-07-23T00:00:00Z',
  updated_at: '2026-07-23T00:00:00Z',
}

function account(
  id: string,
  identity: string,
  bindings: Binding[] = [],
): Account {
  return {
    id,
    principal_id: principal.id,
    connection_id: roleAccount.connection_id,
    kind: 'login',
    engine_identity: identity,
    authentication_scope: '',
    credential_mode: 'existing_vault_ref',
    vault_path: `principals/${principal.id}/environments/test/credential`,
    status: 'active',
    ownership: 'managed',
    attributes: {},
    created_at: '2026-07-23T00:00:00Z',
    updated_at: '2026-07-23T00:00:00Z',
    bindings,
  }
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('shared role account flows', () => {
  it('adopts a group as metadata without showing credential choices', async () => {
    const user = userEvent.setup()
    let posted: unknown = null
    vi.stubGlobal(
      'fetch',
      vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
        posted = JSON.parse(String(init?.body))
        return response({ account_id: roleAccount.id, adopted_bindings: 0 })
      }),
    )
    const onAdopted = vi.fn()

    render(
      <Wrapper>
        <AdoptAccountDialog
          open
          account={roleAccount}
          unmanagedBindings={[]}
          permissionsById={new Map()}
          onClose={vi.fn()}
          onAdopted={onAdopted}
        />
      </Wrapper>,
    )

    expect(screen.queryByText('Сгенерировать пароль')).not.toBeInTheDocument()
    expect(screen.queryByText('Задать пароль')).not.toBeInTheDocument()
    expect(screen.queryByText(/Текущий пароль нельзя прочитать/)).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Взять под управление' }))

    await waitFor(() =>
      expect(posted).toEqual({ mode: 'metadata', adopt_bindings: false }),
    )
    expect(onAdopted).toHaveBeenCalledWith({
      operationId: null,
      adoptedBindings: 0,
    })
  })

  it('assigns the role to selected accounts through the shared bulk endpoint', async () => {
    const assignedBinding: Binding = {
      id: 'binding-existing',
      account_id: 'account-existing',
      permission_definition_id: rolePermission.id,
      scope_resource_id: null,
      source: 'service',
      desired_state: 'present',
      observed_state: 'present',
      observed_effective: true,
      status: 'synced',
      expires_at: null,
      created_at: '2026-07-23T00:00:00Z',
      updated_at: '2026-07-23T00:00:00Z',
    }
    const existing = account('account-existing', 'alice_existing', [assignedBinding])
    const target = account('account-target', 'alice_reporting')
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input)
        if (init?.method === 'POST') {
          posted = { path, body: JSON.parse(String(init.body)) }
          return response(
            {
              operation_id: 'bulk-operation',
              children: [
                {
                  operation_id: 'child-operation',
                  binding_id: 'binding-new',
                  account_id: target.id,
                  permission_id: rolePermission.id,
                },
              ],
            },
            202,
          )
        }
        return response({ accounts: [existing, target] })
      }),
    )
    const onStarted = vi.fn()
    const user = userEvent.setup()

    render(
      <Wrapper>
        <AssignSharedRoleDrawer
          open
          roleAccount={roleAccount}
          permission={rolePermission}
          principals={[principal]}
          onClose={vi.fn()}
          onStarted={onStarted}
        />
      </Wrapper>,
    )

    expect(await screen.findByText('Назначена')).toBeInTheDocument()
    const checkboxes = await screen.findAllByRole('checkbox')
    expect(checkboxes[0]).toBeChecked()
    expect(checkboxes[0]).toBeDisabled()
    await user.click(checkboxes[1])
    await user.click(screen.getByRole('button', { name: 'Назначить роль' }))

    await waitFor(() =>
      expect(posted).toEqual({
        path: '/api/v1/bindings/bulk',
        body: {
          items: [
            {
              account_id: target.id,
              permission_id: rolePermission.id,
            },
          ],
        },
      }),
    )
    expect(onStarted).toHaveBeenCalledWith('bulk-operation', ['alice_reporting'])
  })
})
