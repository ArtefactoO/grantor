import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Binding, Permission } from '../lib/types'
import { ManageRolesDrawer } from './connection-account-dialogs'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, ...props }: { children: ReactNode }) => <a {...props}>{children}</a>,
}))

vi.mock('../auth/AuthProvider', () => ({
  useAuth: () => ({ role: 'admin', email: 'admin@grantor.dev' }),
  roleAtLeast: (actual: string, required: string) =>
    ['viewer', 'operator', 'admin'].indexOf(actual) >=
    ['viewer', 'operator', 'admin'].indexOf(required),
}))

const account: Account = {
  id: 'account-1',
  principal_id: 'principal-1',
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'reports_bot',
  authentication_scope: '',
  credential_mode: 'existing_vault_ref',
  vault_path: 'principals/principal-1/environments/test/credential',
  status: 'active',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-23T00:00:00Z',
  updated_at: '2026-07-23T00:00:00Z',
}

function permission(id: string, name: string, overrides: Partial<Permission> = {}): Permission {
  return {
    id,
    connection_id: 'connection-1',
    engine: 'postgres',
    name,
    external_id: `role:${name}`,
    scope_resource_id: null,
    dangerous: false,
    assignable: true,
    status: 'observed',
    attributes: {},
    normalized: {
      category: 'role', action: '', resource: name, scope: '',
      dangerous: false, danger_reason: '', details: null, raw: name,
    },
    created_at: '2026-07-23T00:00:00Z',
    updated_at: '2026-07-23T00:00:00Z',
    ...overrides,
  }
}

function binding(id: string, permissionId: string): Binding {
  return {
    id,
    account_id: account.id,
    permission_definition_id: permissionId,
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
}

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 202,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

describe('ManageRolesDrawer', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('pins assigned and newly selected roles across search changes, including pending revokes', async () => {
    const user = userEvent.setup()
    const permissions = [permission('a', 'alpha'), permission('b', 'beta'), permission('z', 'zeta_assigned')]
    render(<Wrapper><ManageRolesDrawer open account={account} permissions={permissions}
      bindings={[binding('z-binding', 'z')]} onClose={vi.fn()} onStarted={vi.fn()} /></Wrapper>)
    expect(screen.getAllByRole('checkbox')[0]).toHaveAccessibleName(/zeta_assigned/)
    await user.click(screen.getByRole('checkbox', { name: /beta/ }))
    await user.type(screen.getByRole('textbox', { name: 'Поиск роли' }), 'alpha')
    expect(screen.getAllByRole('checkbox').map(input => input.closest('label')?.textContent)).toEqual([
      expect.stringContaining('zeta_assigned'), expect.stringContaining('beta'), expect.stringContaining('alpha'),
    ])
    await user.click(screen.getByRole('checkbox', { name: /zeta_assigned/ }))
    await user.clear(screen.getByRole('textbox', { name: 'Поиск роли' }))
    await user.type(screen.getByRole('textbox', { name: 'Поиск роли' }), 'no_match')
    expect(screen.getByRole('checkbox', { name: /zeta_assigned/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /beta/ })).toBeChecked()
    expect(screen.queryByRole('checkbox', { name: /alpha/ })).not.toBeInTheDocument()
  })

  it('preserves input and pending selection when equivalent bindings are recreated or refreshed', async () => {
    const user = userEvent.setup()
    const permissions = [permission('a', 'alpha'), permission('b', 'beta'), permission('z', 'zeta')]
    const props = { open: true, account, permissions, onClose: vi.fn(), onStarted: vi.fn() }
    const view = render(<Wrapper><ManageRolesDrawer {...props} bindings={[binding('a-binding', 'a')]} /></Wrapper>)
    await user.click(screen.getByRole('checkbox', { name: /alpha/ }))
    await user.click(screen.getByRole('checkbox', { name: /beta/ }))
    await user.type(screen.getByRole('textbox', { name: 'Поиск роли' }), 'beta')
    view.rerender(<Wrapper><ManageRolesDrawer {...props} permissions={permissions.map(p => ({ ...p }))}
      bindings={[{ ...binding('a-binding', 'a') }]} /></Wrapper>)
    expect(screen.getByRole('textbox', { name: 'Поиск роли' })).toHaveValue('beta')
    expect(screen.getByRole('checkbox', { name: /beta/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /alpha/ })).not.toBeChecked()
    view.rerender(<Wrapper><ManageRolesDrawer {...props}
      bindings={[binding('a-binding', 'a'), binding('z-binding', 'z')]} /></Wrapper>)
    expect(screen.getByRole('textbox', { name: 'Поиск роли' })).toHaveValue('beta')
    expect(screen.getByRole('checkbox', { name: /beta/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /alpha/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /zeta/ })).toBeChecked()
    view.rerender(<Wrapper><ManageRolesDrawer {...props} open={false} bindings={[binding('a-binding', 'a')]} /></Wrapper>)
    view.rerender(<Wrapper><ManageRolesDrawer {...props} bindings={[binding('a-binding', 'a')]} /></Wrapper>)
    expect(screen.getByRole('textbox', { name: 'Поиск роли' })).toHaveValue('')
    expect(screen.getByRole('checkbox', { name: /alpha/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /beta/ })).not.toBeChecked()
  })

  it('pins observed external roles without silently adopting them', async () => {
    const user = userEvent.setup()
    render(<Wrapper><ManageRolesDrawer open account={account}
      permissions={[permission('a', 'alpha'), permission('z', 'zeta_external')]}
      bindings={[{ ...binding('external-binding', 'z'), source: 'external', desired_state: null }]}
      onClose={vi.fn()} onStarted={vi.fn()} /></Wrapper>)
    expect(screen.getAllByRole('checkbox')[0]).toHaveAccessibleName(/zeta_external/)
    expect(screen.getByRole('checkbox', { name: /zeta_external/ })).not.toBeChecked()
    expect(screen.getByText('Выдана вне Grantor')).toBeInTheDocument()
    await user.type(screen.getByRole('textbox', { name: 'Поиск роли' }), 'no_match')
    expect(screen.getByRole('checkbox', { name: /zeta_external/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Применить изменения' })).toBeDisabled()
  })

  it('submits grants and revokes as one account-scoped role delta', async () => {
    const permissions = [
      permission('permission-read', 'report_read'),
      permission('permission-write', 'report_write'),
    ]
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = {
        path: String(input),
        body: JSON.parse(String(init?.body)),
      }
      return response({
        operation_id: 'parent-operation',
        children: [
          { operation_id: 'child-read', binding_id: 'binding-read', action: 'revoke' },
          { operation_id: 'child-write', binding_id: 'binding-write', action: 'grant' },
        ],
      })
    }))
    const onStarted = vi.fn()
    const user = userEvent.setup()

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={permissions}
          bindings={[binding('binding-read', 'permission-read')]}
          onClose={vi.fn()}
          onStarted={onStarted}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('checkbox', { name: /report_read/ })).toBeChecked()
    expect(screen.getByText('Назначена')).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /report_read/ }))
    await user.click(screen.getByRole('checkbox', { name: /report_write/ }))
    expect(screen.getByText('Будет снята')).toBeInTheDocument()
    expect(screen.getByText('Будет добавлена')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/accounts/account-1/roles',
      body: {
        add_permission_ids: ['permission-write'],
        remove_binding_ids: ['binding-read'],
      },
    }))
    expect(onStarted).toHaveBeenCalledWith(
      'parent-operation',
      { added: ['report_write'], removed: ['report_read'] },
    )
  })

  // Failed-binding не считается назначенным: раньше клик по такой роли уходил
  // в 409 access is already assigned, теперь это обычная повторная выдача.
  it('treats a failed role as unassigned and grantable again', async () => {
    const permissions = [permission('permission-read', 'report_read')]
    const failed: Binding = {
      ...binding('binding-read', 'permission-read'),
      observed_state: 'unknown',
      status: 'failed',
    }
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = { path: String(input), body: JSON.parse(String(init?.body)) }
      return response({
        operation_id: 'parent-operation',
        children: [{ operation_id: 'child-read', binding_id: 'binding-read', action: 'grant' }],
      })
    }))
    const user = userEvent.setup()

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={permissions}
          bindings={[failed]}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('checkbox', { name: /report_read/ })).not.toBeChecked()
    await user.click(screen.getByRole('checkbox', { name: /report_read/ }))
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/accounts/account-1/roles',
      body: { add_permission_ids: ['permission-read'], remove_binding_ids: [] },
    }))
  })

  it('renders one RabbitMQ vhost slot as a radio group and submits a replace delta', async () => {
    const assignmentKey = 'rabbitmq:vhost:sl-project'
    const legacy = permission('permission-full', 'vhost-access:sl-project', {
      engine: 'rabbitmq',
      assignment_key: assignmentKey,
      attributes: {
        kind: 'vhost', vhost: 'sl-project', configure: '.*', write: '.*', read: '.*',
        broad: true, description: 'Полный доступ для обратной совместимости',
      },
    })
    const narrow = permission('permission-etl', 'rabbitmq-template:service-etl', {
      engine: 'rabbitmq',
      assignment_key: assignmentKey,
      attributes: {
        kind: 'vhost', template_name: 'project ETL worker',
        description: 'Только очереди ETL', vhost: 'sl-project',
        configure: '^(status_changes|project_etl_match_state_updates)$',
        write: '^project_etl_match_state_updates$',
        read: '^(status_changes|project_etl_match_state_updates)$',
        broad: false,
      },
    })
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = { path: String(input), body: JSON.parse(String(init?.body)) }
      return response({
        operation_id: 'replace-operation',
        children: [{ operation_id: 'replace-child', binding_id: 'binding-vhost', action: 'replace' }],
      })
    }))
    const user = userEvent.setup()

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={[legacy, narrow]}
          bindings={[{ ...binding('binding-vhost', legacy.id), assignment_key: assignmentKey }]}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('group', { name: 'vhost sl-project' })).toBeInTheDocument()
    expect(screen.getByRole('radio', { name: /vhost-access:sl-project/ })).toBeChecked()
    expect(screen.getByText('broad')).toBeInTheDocument()
    expect(screen.getByText('Только очереди ETL')).toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: /project ETL worker/ }))
    expect(screen.getByRole('radio', { name: /vhost-access:sl-project/ })).not.toBeChecked()
    expect(screen.getByRole('radio', { name: /project ETL worker/ })).toBeChecked()
    expect(screen.getByText('Атомарно заменить')).toBeInTheDocument()
    expect(screen.getByText('vhost-access:sl-project → rabbitmq-template:service-etl')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))
    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/accounts/account-1/roles',
      body: {
        add_permission_ids: ['permission-etl'],
        remove_binding_ids: ['binding-vhost'],
      },
    }))
  })

  it('shows and locks an in-flight exclusive replacement', () => {
    const assignmentKey = 'rabbitmq:vhost:sl-project'
    const legacy = permission('permission-full', 'vhost-access:sl-project', {
      engine: 'rabbitmq', assignment_key: assignmentKey,
    })
    const narrow = permission('permission-etl', 'rabbitmq-template:service-etl', {
      engine: 'rabbitmq', assignment_key: assignmentKey,
    })
    const transitioning: Binding = {
      ...binding('binding-vhost', narrow.id),
      assignment_key: assignmentKey,
      observed_permission_definition_id: legacy.id,
      transition_operation_id: 'replace-operation',
      status: 'pending',
    }

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={[legacy, narrow]}
          bindings={[transitioning]}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('status')).toHaveTextContent(
      'Выполняется замена: vhost-access:sl-project → rabbitmq-template:service-etl',
    )
    expect(screen.getByRole('radio', { name: /rabbitmq-template:service-etl/ })).toBeDisabled()
  })

  it('allows an explicit reverse selection after a replacement fails', async () => {
    const assignmentKey = 'rabbitmq:vhost:sl-project'
    const original = permission('permission-full', 'vhost-access:sl-project', {
      engine: 'rabbitmq', assignment_key: assignmentKey,
    })
    const failedTarget = permission('permission-etl', 'rabbitmq-template:service-etl', {
      engine: 'rabbitmq', assignment_key: assignmentKey,
    })
    const failed: Binding = {
      ...binding('binding-vhost', failedTarget.id),
      assignment_key: assignmentKey,
      observed_permission_definition_id: original.id,
      transition_operation_id: 'replace-operation',
      status: 'failed',
    }
    let posted: { path: string; body: unknown } | null = null
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posted = { path: String(input), body: JSON.parse(String(init?.body)) }
      return response({
        operation_id: 'reverse-parent',
        children: [{ operation_id: 'reverse-child', binding_id: failed.id, action: 'replace' }],
      })
    }))
    const user = userEvent.setup()

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={[original, failedTarget]}
          bindings={[failed]}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    expect(screen.getByRole('alert')).toHaveTextContent('Замена не завершилась')
    const originalRadio = screen.getByRole('radio', { name: /vhost-access:sl-project/ })
    expect(originalRadio).not.toBeDisabled()
    await user.click(originalRadio)
    await user.click(screen.getByRole('button', { name: 'Применить изменения' }))

    await waitFor(() => expect(posted).toEqual({
      path: '/api/v1/accounts/account-1/roles',
      body: {
        add_permission_ids: [original.id],
        remove_binding_ids: [failed.id],
      },
    }))
  })

  it('shows expected and actual RabbitMQ regex when an exclusive slot drifts', () => {
    const assignmentKey = 'rabbitmq:vhost:sl-project'
    const legacy = permission('permission-full', 'vhost-access:sl-project', {
      engine: 'rabbitmq',
      assignment_key: assignmentKey,
      attributes: {
        kind: 'vhost', vhost: 'sl-project', configure: '.*', write: '.*', read: '.*',
      },
    })
    const drifted: Binding = {
      ...binding('binding-vhost', legacy.id),
      assignment_key: assignmentKey,
      observed_permission_definition_id: legacy.id,
      observed_attributes: {
        configure: '^status_changes$', write: '^updates$', read: '^status_changes$',
      },
      observed_effective: false,
      status: 'drift',
    }

    render(
      <Wrapper>
        <ManageRolesDrawer
          open
          account={account}
          permissions={[legacy]}
          bindings={[drifted]}
          onClose={vi.fn()}
          onStarted={vi.fn()}
        />
      </Wrapper>,
    )

    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent(
      'Drift: ожидалось vhost-access:sl-project, фактически vhost-access:sl-project.',
    )
    expect(alert).toHaveTextContent('^updates$')
    expect(screen.getByText('Drift', { selector: 'span' })).toBeInTheDocument()
  })
})
