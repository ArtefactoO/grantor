import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Account, AuditEvent, Operation, Permission } from '../lib/types'
import {
  AuditAccessContext,
  OperationContext,
  operationEffectiveConnectionId,
  isRetryableAdminCredentialOperation,
  shouldPollOperation,
} from './control'

function event(overrides: Partial<AuditEvent>): AuditEvent {
  return {
    id: 42,
    occurred_at: '2026-07-21T00:00:00Z',
    actor_type: 'user',
    actor_id: 'admin@example.test',
    action: 'operation.approved',
    connection_id: 'connection-1',
    resource_id: null,
    principal_id: null,
    account_id: 'account-1',
    operation_id: 'operation-1',
    result: 'success',
    metadata: {},
    ...overrides,
  }
}

describe('AuditAccessContext', () => {
  it('shows the recorded approval actors, self-approval, reason and change ref', () => {
    render(<AuditAccessContext event={event({
      metadata: {
        requester_actor_type: 'user',
        requester_actor_id: 'admin@example.test',
        operation_kind: 'access.grant',
        reason: 'Согласовано владельцем',
        self_approved: true,
      },
    })} />)

    expect(screen.getByText('account-1')).toBeInTheDocument()
    expect(screen.getByText('Подтвердил')).toBeInTheDocument()
    expect(screen.getAllByText('user: admin@example.test')).toHaveLength(2)
    expect(screen.getByText('Да')).toBeInTheDocument()
    expect(screen.getByText('Согласовано владельцем')).toBeInTheDocument()
    expect(screen.getByText('operation-1')).toBeInTheDocument()
  })

  it('shows access role and account only when the event actually records them', () => {
    render(<AuditAccessContext event={event({
      action: 'access.granted',
      account_id: null,
      metadata: {
        account: 'deploy_bot',
        permission: 'role:writer',
        binding_id: 'binding-1',
        ignored_field: 'must not be rendered',
      },
    })} />)

    expect(screen.getByText('deploy_bot')).toBeInTheDocument()
    expect(screen.getByText('role:writer')).toBeInTheDocument()
    expect(screen.getByText('binding-1')).toBeInTheDocument()
    expect(screen.queryByText('must not be rendered')).not.toBeInTheDocument()
    expect(screen.queryByText('Подтвердил')).not.toBeInTheDocument()
  })

  it('shows synchronous account adoption parameters recorded by audit', () => {
    render(<AuditAccessContext event={event({
      action: 'account.adopted',
      account_id: 'account-1',
      operation_id: null,
      metadata: {
        engine_identity: 'reports_bot',
        mode: 'metadata',
        adopted_bindings: 2,
      },
    })} />)

    expect(screen.getByText('reports_bot')).toBeInTheDocument()
    expect(screen.getByText('Без смены пароля')).toBeInTheDocument()
    expect(screen.getByText('Принято доступов')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
  })
})

describe('OperationContext', () => {
  it('joins an adopt operation with its audit parameters', () => {
    const operation = {
      id: 'operation-1',
      kind: 'credential.rotate',
      account_id: 'account-1',
      payload: { account_id: 'account-1', adopt: true },
      actor_type: 'user',
      actor_id: 'admin@example.test',
    } as Operation

    render(<OperationContext operation={operation} auditEvents={[event({
      action: 'account.adopt_requested',
      operation_id: 'operation-1',
      metadata: {
        engine_identity: 'reports_bot',
        mode: 'password',
        adopted_bindings: 1,
      },
    })]} />)

    expect(screen.getByText('reports_bot')).toBeInTheDocument()
    expect(screen.getByText('Задан новый пароль')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.queryByText('account-1')).not.toBeInTheDocument()
  })

  it('renders the global user login instead of the internal principal id', () => {
    const operation = {
      id: 'operation-2', kind: 'credential.rotate', account_id: 'account-2',
      principal_id: 'principal-2', payload: { managed_link_principal_id: 'principal-2' },
      actor_type: 'user', actor_id: 'admin@example.test',
    } as Operation

    render(<OperationContext operation={operation} auditEvents={[]} principalNames={new Map([['principal-2', 'test']])} />)

    expect(screen.getByText('test')).toBeInTheDocument()
    expect(screen.queryByText('principal-2')).not.toBeInTheDocument()
  })

  it('shows every child role and account for a bulk grant', () => {
    const child = (id: string, bindingID: string, status: string): Operation => ({
      id,
      parent_id: 'operation-bulk',
      kind: 'access.grant',
      status,
      connection_id: 'connection-1',
      account_id: 'account-1',
      binding_id: bindingID,
    } as Operation)
    const operation = {
      id: 'operation-bulk',
      kind: 'bulk.grant',
      status: 'running',
      aggregate_status: 'running',
      connection_id: null,
      actor_type: 'user',
      actor_id: 'admin@example.test',
      children: [
        child('operation-child-1', 'binding-1', 'success'),
        child('operation-child-2', 'binding-2', 'running'),
      ],
    } as Operation
    const account = {
      id: 'account-1',
      engine_identity: 'service_account_with_a_very_long_engine_identity',
      bindings: [
        { id: 'binding-1', permission_definition_id: 'permission-1' },
        { id: 'binding-2', permission_definition_id: 'permission-2' },
      ],
    } as Account
    const permissions = [
      { id: 'permission-1', name: 'ui_managed_role' },
      { id: 'permission-2', name: 'ui_unmanaged_role' },
    ] as Permission[]

    render(<OperationContext
      operation={operation}
      auditEvents={[]}
      accountsById={new Map([[account.id, account]])}
      permissionsById={new Map(permissions.map((permission) => [permission.id, permission]))}
    />)

    expect(screen.getByText('ui_managed_role')).toBeInTheDocument()
    expect(screen.getByText('ui_unmanaged_role')).toBeInTheDocument()
    expect(screen.getAllByText(/Аккаунт:/)).toHaveLength(2)
    const accountNames = screen.getAllByText('service_account_with_a_very_long_engine_identity')
    expect(accountNames).toHaveLength(2)
    for (const accountName of accountNames) {
      expect(accountName.parentElement).toHaveClass('whitespace-normal', '[overflow-wrap:anywhere]')
      expect(accountName.parentElement).not.toHaveClass('truncate')
    }
    expect(screen.getByText('Done')).toBeInTheDocument()
    expect(screen.getByText('Running')).toBeInTheDocument()
  })
})

describe('admin credential top-level retry', () => {
  it('offers retry only for failed top-level credential operations', () => {
    const operation = {
      id: 'operation-credential',
      kind: 'connection.admin_credential.rotate',
      status: 'failed',
      parent_id: null,
      retryable: true,
    } as Operation
    expect(isRetryableAdminCredentialOperation(operation)).toBe(true)
    expect(isRetryableAdminCredentialOperation({ ...operation, status: 'running' })).toBe(false)
    expect(isRetryableAdminCredentialOperation({ ...operation, parent_id: 'parent' })).toBe(false)
    expect(isRetryableAdminCredentialOperation({ ...operation, retryable: false })).toBe(false)
    expect(isRetryableAdminCredentialOperation({ ...operation, kind: 'credential.rotate' })).toBe(false)
  })
})

describe('bulk operation refresh and connection context', () => {
  it('inherits one connection from children and keeps polling until aggregate status is terminal', () => {
    const running = {
      status: 'running',
      connection_id: null,
      aggregate_status: 'running',
      children: [
        { connection_id: 'connection-1' },
        { connection_id: 'connection-1' },
      ],
    } as Operation

    expect(operationEffectiveConnectionId(running)).toBe('connection-1')
    expect(shouldPollOperation(running)).toBe(true)
    expect(shouldPollOperation({ ...running, aggregate_status: 'success' })).toBe(false)
  })

  it('does not claim one connection for a cross-connection operation', () => {
    expect(operationEffectiveConnectionId({
      connection_id: null,
      children: [
        { connection_id: 'connection-1' },
        { connection_id: 'connection-2' },
      ],
    } as Operation)).toBeNull()
  })
})
