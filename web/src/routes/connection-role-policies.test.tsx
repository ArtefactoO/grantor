import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection, PostgresRolePolicy } from '../lib/types'
import {
  PostgresRolePoliciesSection,
  postgresRolePolicyAction,
  postgresRolePolicyRefreshInterval,
} from './connection-role-policies'

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function policy(overrides: Partial<PostgresRolePolicy> = {}): PostgresRolePolicy {
  return {
    id: 'policy-1',
    template_key: 'appdb-read',
    name: 'App DB — чтение',
    description: 'Доступ аналитики без записи',
    external_id: 'role:r_appdb',
    desired_spec: {
      role_name: 'r_appdb',
      database: 'appdb',
      schemas: ['public'],
      owner_roles: ['app_owner'],
      creator_roles: ['app_migrations'],
      profile: 'read',
    },
    managed: true,
    exact: false,
    dangerous: false,
    apply_supported: true,
    repairable: true,
    transition_active: false,
    blocked_reason: '',
    status: 'drift',
    version: 4,
    observed_fingerprint: 'sha256:observed',
    observed_summary: {
      missing: [
        'acl:["table","public","orders"]:SELECT',
        'acl:["default","app_migrations","public","tables"]:SELECT',
      ],
      extra: ['acl:["table","public","orders"]:UPDATE'],
      missing_count: 2,
      extra_count: 1,
      truncated: false,
    },
    ...overrides,
  }
}

describe('PostgresRolePoliciesSection', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('uses Apply for a safe mismatched unmanaged role and reserves Adopt for exact state', () => {
    expect(postgresRolePolicyAction(policy({
      managed: false,
      exact: false,
      repairable: false,
      status: 'observed',
    }))).toBe('apply')
    expect(postgresRolePolicyAction(policy({
      managed: false,
      exact: true,
      repairable: false,
      status: 'observed',
    }))).toBe('adopt')
    expect(postgresRolePolicyAction(policy({
      transition_active: true,
      transition_operation_id: 'operation-retrying',
    }))).toBeNull()
    expect(postgresRolePolicyAction(policy({
      status: 'failed',
      exact: true,
      transition_active: false,
      transition_operation_id: 'operation-exhausted',
      repairable: true,
    }))).toBe('repair')
  })

  it('polls only while a role-policy transition is active', () => {
    expect(postgresRolePolicyRefreshInterval([policy({ transition_active: true })])).toBe(1_500)
    expect(postgresRolePolicyRefreshInterval([policy({ transition_active: false })])).toBe(false)
    expect(postgresRolePolicyRefreshInterval(undefined)).toBe(false)
  })

  it.each([
    { managed: true, exact: true, status: 'synced', label: 'Синхронизировано', action: null },
    { managed: true, exact: false, status: 'drift', label: 'Расхождение', action: 'Исправить drift' },
    { managed: false, exact: true, status: 'observed', label: 'Готово к принятию', action: 'Принять под управление' },
    { managed: false, exact: false, status: 'missing', label: 'Не применена', action: 'Создать роль с правами' },
  ])('shows policy state $label without an ownership badge and preserves its action', async (state) => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ policies: [policy({
      managed: state.managed, exact: state.exact, status: state.status,
      repairable: state.managed && !state.exact,
      creatable: state.status === 'missing',
    })] })))
    render(<PostgresRolePoliciesSection connectionId="connection-1" isAdmin />, { wrapper: Wrapper })
    expect(await screen.findByText(state.label)).toBeVisible()
    expect(screen.queryByText(/^(?:Managed ·|Exact · unmanaged)/)).not.toBeInTheDocument()
    if (state.action !== null) {
      expect(screen.getByRole('button', { name: `${state.action}: App DB — чтение` })).toBeEnabled()
    } else {
      expect(screen.queryByRole('button', { name: /^Исправить drift:/ })).not.toBeInTheDocument()
    }
  })

  it('never applies a missing role without server creation approval', () => {
    expect(postgresRolePolicyAction(policy({ managed: false, status: 'missing', observed_summary: { role: { exists: false }, missing: [], extra: [] } }))).toBeNull()
    expect(postgresRolePolicyAction(policy({ managed: true, status: 'failed', creatable: true, observed_summary: { role: { exists: false }, missing: [], extra: [] } }))).toBe('create')
  })

  it('shows drift and current/default ACL preview to an operator without mutations', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ policies: [policy()] })))
    const user = userEvent.setup()
    render(<PostgresRolePoliciesSection connectionId="connection-1" isAdmin={false} />, {
      wrapper: Wrapper,
    })

    expect(await screen.findByText('Расхождение')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Исправить drift' })).not.toBeInTheDocument()
    await user.click(screen.getByText(/ACL diff:/))
    expect(screen.getByText('current · table · public.orders: SELECT')).toBeVisible()
    expect(screen.getByText('default · app_migrations · public · tables: SELECT')).toBeVisible()
    expect(screen.getByText('current · table · public.orders: UPDATE')).toBeVisible()
  })

  it('fails closed when the SUPERUSER authority is unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      policies: [policy({
        managed: false,
        exact: true,
        apply_supported: false,
        repairable: false,
        blocked_reason: 'superuser_required',
        status: 'unmanaged',
      })],
    })))
    render(<PostgresRolePoliciesSection connectionId="connection-1" isAdmin />, {
      wrapper: Wrapper,
    })

    expect(await screen.findByText('Мутация недоступна')).toBeVisible()
    expect(screen.getByText('Admin credential подключения не является PostgreSQL SUPERUSER.')).toBeVisible()
    expect(screen.queryByRole('button', { name: 'Принять под управление' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Применить policy' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Исправить drift' })).not.toBeInTheDocument()
  })

  it('previews a repair and posts the pinned version and fingerprint', async () => {
    const requests: Array<{ path: string; method: string; body: unknown }> = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      const method = init?.method ?? 'GET'
      if (method === 'POST') {
        requests.push({ path, method, body: JSON.parse(String(init?.body)) })
        return response({ operation_id: 'operation-repair' }, 202)
      }
      return response({ policies: [policy()] })
    }))
    const user = userEvent.setup()
    render(<PostgresRolePoliciesSection connectionId="connection-1" isAdmin />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Исправить drift:/ }))
    const repairDialog = screen.getByRole('dialog', { name: 'Исправить PostgreSQL policy?' })
    await waitFor(() => expect(repairDialog).toBeVisible())
    expect(screen.getByText('Добавится (2)')).toBeVisible()
    expect(screen.getByText('Будет удалено (1)')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Исправить' }))

    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0]).toEqual({
      path: '/api/v1/connections/connection-1/role-policies/appdb-read/repair',
      method: 'POST',
      body: {
        request_id: expect.any(String),
        version: 4,
        observed_fingerprint: 'sha256:observed',
        confirm: true,
      },
    })
    expect(await screen.findByText(/operation-repair поставлена в очередь/)).toBeVisible()
  })

  it('uses pinned create for a missing role and exact adopt for an existing role', async () => {
    const posted: string[] = []
    const policies = [
      policy({
        id: 'policy-adopt',
        template_key: 'appdb-read',
        managed: false,
        exact: true,
        repairable: false,
        status: 'unmanaged',
        observed_summary: { missing: [], extra: [] },
      }),
      policy({
        id: 'policy-create',
        template_key: 'appdb-write',
        name: 'App DB — запись',
        managed: false,
        exact: false,
        repairable: false,
        status: 'missing',
        observed_fingerprint: 'missing-role',
        creatable: true,
        observed_summary: { missing: [], extra: [], role: { exists: false } },
      }),
    ]
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        posted.push(String(input))
        if (String(input).endsWith('/create')) expect(JSON.parse(String(init?.body)).expected_target_identity).toBe('postgres:system:7429012345678901234')
        return response({ operation_id: `operation-${posted.length}` }, 202)
      }
      return response({ policies })
    }))
    const user = userEvent.setup()
    render(<PostgresRolePoliciesSection connectionId="connection-1" isAdmin connection={{ topology: { system_identifier: '7429012345678901234' } } as Connection} />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Принять под управление:/ }))
    await user.click(screen.getByRole('button', { name: 'Принять' }))
    await waitFor(() => expect(posted).toContain(
      '/api/v1/connections/connection-1/role-policies/appdb-read/adopt',
    ))

    await user.click(await screen.findByRole('button', { name: /^Создать роль с правами:/ }))
    await user.click(screen.getByRole('button', { name: 'Создать' }))
    await waitFor(() => expect(posted).toContain(
      '/api/v1/connections/connection-1/role-policies/appdb-write/create',
    ))
  })
})
