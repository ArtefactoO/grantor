import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Account, Binding, Connection, Permission, Principal } from '../lib/types'
import { accountActions, restoreBindingEligibility } from '../lib/account-actions'
import { buildAccessEntries } from '../lib/access-entries'
import { AccountDirectoryFilter, accountsForDirectoryView } from './connection-accounts'
import { BindingsSection } from './connection-panels'
import { PrincipalDirectory } from './principals'

const basePrincipal = (id: string, status: string): Principal => ({
  id,
  type: 'human',
  display_name: id === 'deleted' ? 'Удалённый пользователь' : 'Текущий пользователь',
  external_provider: '',
  external_subject: '',
  status,
  attributes: {},
  accounts_count: 0,
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
})

const baseAccount = (id: string, status: string): Account => ({
  id,
  principal_id: null,
  connection_id: 'connection',
  kind: 'login',
  engine_identity: id,
  authentication_scope: '',
  credential_mode: null,
  vault_path: '',
  status,
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
})

const connection: Connection = {
  id: 'connection',
  display_name: 'postgres-prod',
  engine: 'postgres',
  environment: 'prod',
  tags: [],
  endpoints: [],
  execution_mode: 'direct',
  tls_config: {},
  admin_credential_mode: 'vault',
  vault_admin_path: '',
  capabilities: ['account.restore'],
  discovery_config: {},
  status: 'active',
  server_version: '16',
  topology: {},
  last_discovery_at: null,
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

describe('deleted directories', () => {
  it('shows current principals by default and deleted principals only after chip selection', async () => {
    const user = userEvent.setup()
    render(
      <PrincipalDirectory
        principals={[
          basePrincipal('current', 'active'),
          basePrincipal('deleted', 'deleted'),
        ]}
        onOpen={vi.fn()}
      />,
    )

    expect(screen.getByText('Текущий пользователь')).toBeInTheDocument()
    expect(screen.queryByText('Удалённый пользователь')).not.toBeInTheDocument()

    await user.click(screen.getByRole('radio', { name: 'Deleted 1' }))

    expect(screen.queryByText('Текущий пользователь')).not.toBeInTheDocument()
    expect(screen.getByText('Удалённый пользователь')).toBeInTheDocument()
    expect(screen.getByText(/Удаление пользователя необратимо/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /восстанов/i })).not.toBeInTheDocument()
  })

  it('uses the account deleted chip as an exclusive current/deleted filter', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const accounts = [baseAccount('current', 'active'), baseAccount('deleted', 'deleted')]

    const view = render(
      <AccountDirectoryFilter value="current" currentCount={1} deletedCount={1} onChange={onChange} />,
    )
    const current = screen.getByRole('radio', { name: 'Current 1' })
    expect(current).toHaveAttribute('aria-checked', 'true')
    await user.click(screen.getByRole('radio', { name: 'Deleted 1' }))
    expect(onChange).toHaveBeenCalledWith('deleted')
    expect(accountsForDirectoryView(accounts, 'current').map((item) => item.id)).toEqual([
      'current',
    ])
    expect(accountsForDirectoryView(accounts, 'deleted').map((item) => item.id)).toEqual([
      'deleted',
    ])

    view.rerender(
      <AccountDirectoryFilter value="deleted" currentCount={1} deletedCount={1} onChange={onChange} />,
    )
    expect(screen.getByRole('radio', { name: 'Deleted 1' })).toHaveAttribute(
      'aria-checked',
      'true',
    )
  })

  it('keeps explicit current and deleted account choices when there are no tombstones', () => {
    render(
      <AccountDirectoryFilter
        value="current"
        currentCount={2}
        deletedCount={0}
        onChange={vi.fn()}
      />,
    )

    expect(screen.getByRole('radio', { name: 'Current 2' })).toHaveAttribute(
      'aria-checked',
      'true',
    )
    expect(screen.getByRole('radio', { name: 'Deleted 0' })).toHaveAttribute(
      'aria-checked',
      'false',
    )
  })
})

function binding(id: string, desired: string | null, observed: string): Binding {
  return {
    id,
    account_id: 'account',
    permission_definition_id: `permission-${id}`,
    scope_resource_id: null,
    source: desired === null ? 'external' : 'service',
    desired_state: desired,
    observed_state: observed,
    observed_effective: true,
    status: desired === 'present' && observed === 'present' ? 'synced' : 'drift',
    expires_at: null,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  }
}

function permission(id: string): Permission {
  return {
    id: `permission-${id}`,
    connection_id: 'connection',
    engine: 'postgres',
    external_id: id,
    name: `role-${id}`,
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: false,
    attributes: {},
    normalized: {
      category: 'role', action: '', resource: `role-${id}`, scope: '',
      dangerous: false, danger_reason: '', details: null, raw: `role-${id}`,
    },
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  }
}

describe('active access surfaces', () => {
  it('keeps access collapsed by default and separates revoked bindings when opened', async () => {
    const values = [
      binding('active', 'present', 'present'),
      binding('revoked', 'absent', 'present'),
      binding('absent', 'present', 'absent'),
    ]
    const permissions = new Map(
      ['active', 'revoked', 'absent'].map((id) => [permission(id).id, permission(id)]),
    )
    const onRevoke = vi.fn()
    const user = userEvent.setup()

    render(
      <BindingsSection
        query={{ data: values, isPending: false, isError: false, error: null }}
        permissionsById={permissions}
        emptyText="Нет bindings"
        onRevoke={onRevoke}
      />,
    )

    const disclosure = screen.getByRole('button', { name: /Права доступа/ })
    expect(disclosure).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(/Действующие/)).not.toBeInTheDocument()
    await user.click(disclosure)

    expect(screen.getByText(/Действующие/)).toHaveTextContent('1')
    expect(screen.getByText(/Неактивные и история/)).toHaveTextContent('2')
    expect(screen.getByText('Revoked')).toBeInTheDocument()
    expect(screen.getByText('Absent')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Снять роль' })).toHaveLength(1)
  })

  it('excludes revoked and absent bindings from account access chips', () => {
    const values = [
      binding('active', 'present', 'present'),
      binding('revoked', 'absent', 'present'),
      binding('absent', 'present', 'absent'),
    ]
    const permissions = new Map(
      ['active', 'revoked', 'absent'].map((id) => [permission(id).id, permission(id)]),
    )

    expect(buildAccessEntries(values, permissions, new Map())).toEqual([
      expect.objectContaining({ label: 'role-active' }),
    ])
  })
})

describe('shared role actions', () => {
  // Бэкенд отвечает 409 на delete/adopt/rotate/disable/share для kind=group:
  // это носитель прав, а не учётная запись, и account.delete означал бы на
  // целевой системе DROP ROLE. Панель не должна предлагать таких кнопок.
  it('offers no account lifecycle or credential actions for a group kind', () => {
    const managedGroup: Account = { ...baseAccount('readers', 'active'), kind: 'group' }
    const managed = accountActions(managedGroup, 'admin', connection)
    expect(managed.delete).toBe(false)
    expect(managed.rotate).toBe(false)
    expect(managed.share).toBe(false)
    expect(managed.disable).toBe(false)
    expect(managed.link).toBe(false)
    expect(managed.restore).toBe(false)
    // Пояснение про общую роль переехало из предиката в саму панель,
    // поэтому проверяем итог: ни одного первичного действия не предлагается.
    expect(managed.anyPrimary).toBe(false)

    // Принятие под управление роли РАЗРЕШЕНО, но только как metadata: grantor
    // начинает отслеживать её bindings, целевая система не затрагивается.
    // Кредовые режимы диалог для неё не показывает, а бэкенд отвечает 409 —
    // у роли нет пароля, который можно подтвердить, задать или сгенерировать.
    const unmanagedGroup: Account = { ...managedGroup, ownership: 'unmanaged' }
    expect(accountActions(unmanagedGroup, 'admin', connection).adopt).toBe(true)
    expect(accountActions(unmanagedGroup, 'admin', connection).rotate).toBe(false)
    expect(accountActions(unmanagedGroup, 'admin', connection).share).toBe(false)

    // Login-аккаунт полный набор сохраняет.
    const login = accountActions(baseAccount('svc-a', 'active'), 'admin', connection)
    expect(login.delete).toBe(true)
    expect(login.rotate).toBe(true)
    expect(accountActions(
      { ...baseAccount('svc-b', 'active'), ownership: 'unmanaged' }, 'admin', connection,
    ).adopt).toBe(true)
  })
})

describe('restore eligibility', () => {
  it('requires admin, deleted managed login, active connection and capability', () => {
    const deleted = baseAccount('deleted', 'deleted')
    expect(accountActions(deleted, 'admin', connection).restore).toBe(true)
    expect(accountActions(deleted, 'operator', connection).restore).toBe(false)
    expect(
      accountActions(deleted, 'admin', { ...connection, status: 'disabled' }).restore,
    ).toBe(false)
    expect(
      accountActions(deleted, 'admin', { ...connection, capabilities: [] }).restore,
    ).toBe(false)
    expect(accountActions({ ...deleted, kind: 'group' }, 'admin', connection).restore).toBe(
      false,
    )
    expect(accountActions(deleted, 'admin', connection).purge).toBe(true)
    expect(accountActions(deleted, 'operator', connection).purge).toBe(false)
    expect(accountActions({ ...deleted, ownership: 'unmanaged' }, 'admin', connection).purge).toBe(false)
  })

  it.each([
    ['loading', { data: undefined, isPending: true, isError: false }, 'loading'],
    ['error', { data: undefined, isPending: false, isError: true }, 'error'],
    ['unknown', { data: undefined, isPending: false, isError: false }, 'error'],
    ['zero', { data: [], isPending: false, isError: false }, 'eligible'],
    ['nonzero', { data: [{}], isPending: false, isError: false }, 'blocked'],
  ] as const)('fails closed for %s bindings query', (_name, query, expected) => {
    expect(restoreBindingEligibility(true, query)).toBe(expected)
  })
})
