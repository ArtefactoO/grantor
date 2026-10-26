import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Account, Binding, Connection, Permission, Principal, Resource } from '../lib/types'
import { AccessLens, buildAccessLensModel } from './access-lens'

const timestamp = '2026-07-22T10:00:00.000Z'

const account: Account = {
  id: 'account-1', principal_id: 'principal-1', connection_id: 'connection-1',
  kind: 'login', engine_identity: 'test', authentication_scope: 'database',
  credential_mode: 'vault', vault_path: 'principals/test', status: 'active',
  ownership: 'managed', attributes: {}, created_at: timestamp, updated_at: timestamp,
}

const connection: Connection = {
  id: 'connection-1', display_name: 'local-ui-review', engine: 'postgres',
  environment: 'dev', tags: [], endpoints: [], execution_mode: 'direct',
  tls_config: {}, admin_credential_mode: 'vault', vault_admin_path: 'connections/admin',
  capabilities: [], discovery_config: {}, status: 'active', server_version: '17',
  topology: {}, last_discovery_at: timestamp, created_at: timestamp, updated_at: timestamp,
}

const principal: Principal = {
  id: 'principal-1', type: 'human', display_name: 'Тестовый пользователь',
  external_provider: '', external_subject: '', status: 'active', attributes: {},
  created_at: timestamp, updated_at: timestamp,
}

const permission: Permission = {
  id: 'permission-1', connection_id: 'connection-1', engine: 'postgres',
  external_id: 'role-1', name: 'developer', scope_resource_id: null,
  assignable: true, dangerous: true, attributes: {}, created_at: timestamp,
  status: 'observed',
  updated_at: timestamp,
    normalized: {
      category: 'role', action: '', resource: 'developer', scope: '',
      dangerous: true, danger_reason: 'широкие полномочия', details: null, raw: 'developer',
    },
}

const resource: Resource = {
  id: 'resource-1', connection_id: 'connection-1', parent_id: null,
  kind: 'database', external_id: 'app', name: 'app', canonical_path: 'db/app',
  attributes: {}, fingerprint: 'fingerprint', observed_at: timestamp, status: 'active',
  ownership: 'managed', created_at: timestamp, updated_at: timestamp,
}

function binding(overrides: Partial<Binding> = {}): Binding {
  return {
    id: 'binding-1', account_id: 'account-1',
    permission_definition_id: 'permission-1', scope_resource_id: 'resource-1',
    source: 'managed', desired_state: 'present', observed_state: 'present',
    observed_effective: true,
    status: 'active', expires_at: null, created_at: timestamp, updated_at: timestamp,
    ...overrides,
  }
}

describe('AccessLens', () => {
  it('aggregates active role scopes and excludes revoked bindings', () => {
    const model = buildAccessLensModel(
      [
        binding(),
        binding({ id: 'binding-2', scope_resource_id: null }),
        binding({ id: 'binding-3', desired_state: 'absent' }),
      ],
      new Map([[permission.id, permission]]),
      new Map([[resource.id, resource]]),
    )

    expect(model.roles).toEqual([
      expect.objectContaining({
        name: 'developer',
        dangerous: true,
        scopes: ['db/app', 'Всё подключение'],
      }),
    ])
    expect(model.scopes).toEqual([
      { id: 'resource-1', label: 'db/app' },
      { id: null, label: 'Всё подключение' },
    ])
  })

  it('keeps details collapsed until the operator asks for them', () => {
    render(
      <AccessLens
        account={account}
        connection={connection}
        principal={principal}
        bindings={[binding()]}
        permissionsById={new Map([[permission.id, permission]])}
        resourcesById={new Map([[resource.id, resource]])}
      />,
    )

    expect(screen.getByText('Тестовый пользователь')).toBeInTheDocument()
    expect(screen.getByText('1 роль')).toBeInTheDocument()
    expect(screen.queryByText('Пользователь')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button'))

    expect(screen.getByText('Пользователь')).toBeInTheDocument()
    expect(screen.getByText('developer')).toBeInTheDocument()
    expect(screen.getByText('db/app')).toBeInTheDocument()
  })
})
