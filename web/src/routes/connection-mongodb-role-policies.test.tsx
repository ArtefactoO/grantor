import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { MongoDBRolePolicy } from '../lib/types'
import {
  MongoDBRolePoliciesSection,
  mongoDBRolePolicyAction,
  mongoDBRolePolicyRefreshInterval,
} from './connection-mongodb-role-policies'

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

function policy(overrides: Partial<MongoDBRolePolicy> = {}): MongoDBRolePolicy {
  return {
    id: 'policy-mongo-1',
    template_key: 'etl-reader',
    name: 'ETL reader',
    description: 'Read event data',
    external_id: 'role:appdb.etlReader',
    desired_spec: {
      role_name: 'etlReader',
      role_database: 'appdb',
      inherited_roles: [{ role: 'read', db: 'archive' }],
      privileges: [{
        resource: { db: 'appdb', collection: 'events' },
        actions: ['find'],
      }],
    },
    managed: true,
    exact: false,
    dangerous: true,
    apply_supported: true,
    repairable: true,
    transition_active: false,
    blocked_reason: '',
    status: 'drift',
    version: 7,
    observed_fingerprint: 'sha256:mongo-observed',
    observed_summary: {
      exists: true,
      builtin: false,
      direct_privileges: [{
        resource: { db: 'appdb', collection: 'events' },
        actions: ['find', 'update'],
      }],
      direct_inherited_roles: [{ role: 'read', db: 'archive' }],
      inherited_privileges: [{
        resource: { db: 'archive', collection: '' },
        actions: ['find'],
      }],
      inherited_roles: [{ role: 'read', db: 'archive' }],
      missing: ['effective_inherits:archive.read'],
      extra: ['effective_privilege:namespace:appdb.events:update'],
      missing_count: 1,
      extra_count: 1,
      truncated: false,
      danger_reasons: [
        'effective privilege reaches a protected namespace',
        'direct:unsupported_resource_shape',
      ],
    },
    ...overrides,
  }
}

describe('MongoDBRolePoliciesSection', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('uses Apply for mismatch, Adopt for exact and Repair for managed drift', () => {
    expect(mongoDBRolePolicyAction(policy({ managed: false, exact: false, repairable: false })))
      .toBe('apply')
    expect(mongoDBRolePolicyAction(policy({ managed: false, exact: true, repairable: false })))
      .toBe('adopt')
    expect(mongoDBRolePolicyAction(policy())).toBe('repair')
    expect(mongoDBRolePolicyAction(policy({ transition_active: true }))).toBeNull()
    expect(mongoDBRolePolicyAction(policy({ apply_supported: false }))).toBeNull()
  })

  it('polls only while a MongoDB policy transition is active', () => {
    expect(mongoDBRolePolicyRefreshInterval([policy({ transition_active: true })])).toBe(1_500)
    expect(mongoDBRolePolicyRefreshInterval([policy({ transition_active: false })])).toBe(false)
    expect(mongoDBRolePolicyRefreshInterval(undefined)).toBe(false)
  })

  it.each([
    { managed: true, exact: true, status: 'synced', label: 'Синхронизировано', action: null },
    { managed: true, exact: false, status: 'drift', label: 'Расхождение', action: 'Исправить drift' },
    { managed: false, exact: true, status: 'observed', label: 'Готово к принятию', action: 'Принять под управление' },
    { managed: false, exact: false, status: 'missing', label: 'Не применена', action: 'Применить policy' },
  ])('shows policy state $label without an ownership badge and preserves its action', async (state) => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ policies: [policy({
      managed: state.managed, exact: state.exact, status: state.status,
      repairable: state.managed && !state.exact,
    })] })))
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, { wrapper: Wrapper })
    expect(await screen.findByText(state.label)).toBeVisible()
    expect(screen.queryByText(/^(?:Managed ·|Exact · unmanaged)/)).not.toBeInTheDocument()
    if (state.action !== null) {
      expect(screen.getByRole('button', { name: `${state.action}: ETL reader` })).toBeEnabled()
    } else {
      expect(screen.queryByRole('button', { name: /^Исправить drift:/ })).not.toBeInTheDocument()
    }
  })

  it('shows direct, inherited and danger state to an operator without mutation controls', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ policies: [policy()] })))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin={false} connectionActive />, {
      wrapper: Wrapper,
    })

    expect(await screen.findByText('Расхождение')).toBeVisible()
    expect(screen.getByText('Dangerous')).toBeVisible()
    expect(screen.queryByRole('button', { name: /Исправить drift/ })).not.toBeInTheDocument()

    await user.click(screen.getByText(/Role diff:/))
    expect(screen.getByText('Effective inheritance: archive.read')).toBeVisible()
    expect(screen.getByText('Effective · namespace:appdb.events: update')).toBeVisible()
    expect(screen.queryByText('effective_inherits:archive.read')).not.toBeInTheDocument()
    await user.click(screen.getByText('Фактический rolesInfo'))
    expect(screen.getByText('appdb.events')).toBeVisible()
    expect(screen.getAllByText('archive.read')).not.toHaveLength(0)
    expect(screen.getByText('effective privilege reaches a protected namespace')).toBeVisible()
    expect(screen.getByText('Direct resource shape вне managed contract.')).toBeVisible()
    expect(screen.queryByText('direct:unsupported_resource_shape')).not.toBeInTheDocument()
  })

  it('previews replacement of both direct arrays and posts pinned state', async () => {
    const requests: Array<{ path: string; body: unknown }> = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        requests.push({ path: String(input), body: JSON.parse(String(init?.body)) })
        return response({ operation_id: 'operation-mongo-repair' }, 202)
      }
      return response({ policies: [policy()] })
    }))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Исправить drift:/ }))
    const repairDialog = screen.getByRole('dialog', { name: 'Исправить MongoDB policy?' })
    await waitFor(() => expect(repairDialog).toBeVisible())
    expect(screen.getByText(/updateRole заменит обе direct-массива/)).toBeVisible()
    expect(screen.getByText('Добавится (1)')).toBeVisible()
    expect(screen.getByText('Будет удалено (1)')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Исправить' }))

    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0]).toEqual({
      path: '/api/v1/connections/connection-1/role-policies/etl-reader/repair',
      body: {
        request_id: expect.any(String),
        version: 7,
        observed_fingerprint: 'sha256:mongo-observed',
        confirm: true,
      },
    })
    expect(await screen.findByText(/operation-mongo-repair поставлена в очередь/)).toBeVisible()
  })

  it('fails closed with a specific recovery reason', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      policies: [policy({
        managed: false,
        exact: true,
        dangerous: false,
        apply_supported: false,
        repairable: false,
        blocked_reason: 'role_management_privileges_missing',
        status: 'blocked',
      })],
    })))
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    expect(await screen.findByText('Часть policies нельзя изменить')).toBeVisible()
    expect(screen.getAllByText(/не хватает privileges для rolesInfo/)).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /Принять под управление/ })).not.toBeInTheDocument()
  })

  it.each([
    ['read_only_target', 'MongoDB target доступен только для чтения; требуется writable primary.'],
    ['unsupported_role_resource_shape', 'У роли есть resource shape, который managed policy не поддерживает.'],
    ['inherited_policy_drift', 'Зависимая custom-role policy имеет drift; сначала исправьте её.'],
    ['role_is_connection_admin_dependency', 'Policy-роль даёт доступ admin credential подключения; её нельзя менять без риска self-revoke.'],
    ['admin_authority_observation_failed', 'Не удалось безопасно проверить effective privileges admin credential; мутации закрыты.'],
  ])('localizes blocked reason %s', async (blockedReason, label) => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      policies: [policy({
        apply_supported: false,
        repairable: false,
        blocked_reason: blockedReason,
        status: 'blocked',
      })],
    })))
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    expect(await screen.findAllByText(label)).toHaveLength(2)
  })

  it('uses the adapter preview limits in truncated rolesInfo copy', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      policies: [policy({
        observed_summary: {
          ...policy().observed_summary,
          direct_privileges_count: 80,
          truncated: true,
        },
      })],
    })))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin={false} connectionActive />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByText('Фактический rolesInfo'))
    expect(screen.getByText(/ограничен 20 privilege entries и общим бюджетом 100 actions/))
      .toBeVisible()
  })

  it('hides mutation actions while the connection is not active', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({ policies: [policy()] })))
    render(
      <MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive={false} />,
      { wrapper: Wrapper },
    )

    expect(await screen.findByText(/доступны только для active connection/)).toBeVisible()
    expect(screen.queryByRole('button', { name: /Исправить drift/ })).not.toBeInTheDocument()
  })

  it('keeps an inheritance dependency blocker visible until the parent policy is synced', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response({
      policies: [policy({
        managed: false,
        exact: false,
        dangerous: false,
        apply_supported: false,
        repairable: false,
        blocked_reason: 'inherited_policy_not_ready',
        status: 'blocked',
        observed_summary: {
          missing: [],
          extra: [],
          dependency_blockers: ['role:appdb.baseReader'],
        },
      })],
    })))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    expect(await screen.findAllByText('Зависимая custom-role policy ещё не managed/synced.'))
      .toHaveLength(2)
    await user.click(screen.getByText('Фактический rolesInfo'))
    expect(screen.getByText('Dependency blockers')).toBeVisible()
    expect(screen.getByText('role:appdb.baseReader')).toBeVisible()
    expect(screen.getByText(/Сначала примените или исправьте эти policies/)).toBeVisible()
  })

  it('allows exact Adopt and missing-role Apply only to admin', async () => {
    const posted: string[] = []
    const policies = [
      policy({
        id: 'mongo-adopt',
        managed: false,
        exact: true,
        dangerous: false,
        repairable: false,
        status: 'observed',
        observed_summary: { missing: [], extra: [] },
      }),
      policy({
        id: 'mongo-apply',
        template_key: 'writer',
        name: 'Writer',
        managed: false,
        exact: false,
        dangerous: false,
        repairable: false,
        status: 'missing',
        observed_fingerprint: 'sha256:missing-role-observation',
        observed_summary: { missing: [], extra: [] },
      }),
    ]
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        posted.push(String(input))
        return response({ operation_id: `operation-${posted.length}` }, 202)
      }
      return response({ policies })
    }))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Принять под управление:/ }))
    await user.click(screen.getByRole('button', { name: 'Принять' }))
    await waitFor(() => expect(posted).toContain(
      '/api/v1/connections/connection-1/role-policies/etl-reader/adopt',
    ))

    await user.click(await screen.findByRole('button', { name: /^Применить policy:/ }))
    const applyDialog = await screen.findByRole('dialog', { name: 'Применить MongoDB policy?' })
    await waitFor(() => expect(within(applyDialog).getByText(/выполнит createRole/)).toBeVisible())
    await user.click(screen.getByRole('button', { name: 'Применить' }))
    await waitFor(() => expect(posted).toContain(
      '/api/v1/connections/connection-1/role-policies/writer/apply',
    ))
  })

  it('reuses one request_id when a lost response is retried from the same intent', async () => {
    const postBodies: Array<{ request_id: string }> = []
    let postAttempts = 0
    vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        postAttempts += 1
        postBodies.push(JSON.parse(String(init?.body)) as { request_id: string })
        if (postAttempts === 1) throw new TypeError('response lost')
        return response({ operation_id: 'operation-recovered' }, 202)
      }
      return response({ policies: [policy()] })
    }))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Исправить drift:/ }))
    await user.click(screen.getByRole('button', { name: 'Исправить' }))
    expect(await screen.findByText('сеть недоступна или API не отвечает')).toBeVisible()
    const retry = screen.getByRole('button', { name: 'Исправить' })
    await waitFor(() => expect(retry).toBeEnabled())
    await user.click(retry)

    await waitFor(() => expect(postBodies).toHaveLength(2))
    expect(postBodies[0]?.request_id).toBe(postBodies[1]?.request_id)
    expect(await screen.findByText(/operation-recovered поставлена в очередь/)).toBeVisible()
  })

  it('reconciles a lost response through pending to terminal without another POST', async () => {
    let getAttempts = 0
    let postAttempts = 0
    vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      if ((init?.method ?? 'GET') === 'POST') {
        postAttempts += 1
        throw new TypeError('response lost after accept')
      }
      getAttempts += 1
      if (getAttempts === 1) return response({ policies: [policy()] })
      if (getAttempts === 2) {
        return response({ policies: [policy({
          version: 8,
          status: 'pending',
          transition_active: true,
          repairable: false,
          transition_operation_id: 'operation-accepted',
        })] })
      }
      return response({ policies: [policy({
        version: 9,
        status: 'synced',
        exact: true,
        dangerous: false,
        transition_active: false,
        repairable: false,
        transition_operation_id: null,
        observed_summary: { missing: [], extra: [], exists: true },
      })] })
    }))
    const user = userEvent.setup()
    render(<MongoDBRolePoliciesSection connectionId="connection-1" isAdmin connectionActive />, {
      wrapper: Wrapper,
    })

    await user.click(await screen.findByRole('button', { name: /^Исправить drift:/ }))
    await user.click(screen.getByRole('button', { name: 'Исправить' }))
    expect(await screen.findByText(/сервер принял операцию; выполнение продолжается/)).toBeVisible()
    expect(screen.queryByRole('dialog', { name: 'Исправить MongoDB policy?' })).not.toBeInTheDocument()
    expect(await screen.findByText('Синхронизировано', {}, { timeout: 3_500 })).toBeVisible()
    expect(postAttempts).toBe(1)
  })
})
