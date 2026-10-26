import { describe, expect, it } from 'vitest'
import type { AuditEvent } from './types'
import { mergeUnknownKinds } from './operation-kinds'
import {
  accountAdoptContext,
  accountManagedLinkContext,
  isRecentActivityOperation,
  operationDisplayLabel,
  operationLabel,
  operationStatusLabel,
  RECENT_ACTIVITY_KINDS,
} from './operation-presentation'

describe('operation presentation', () => {
  it('presents protected statistics membership as ordinary access activity', () => {
    const grant = 'postgres.stats_membership.grant.v1'
    const revoke = 'postgres.stats_membership.revoke.v1'
    expect(operationLabel(grant)).toBe('Выдача доступа')
    expect(operationLabel(revoke)).toBe('Отзыв доступа')
    expect(isRecentActivityOperation({ actor_type: 'user', kind: grant, parent_id: null })).toBe(true)
    expect(isRecentActivityOperation({ actor_type: 'user', kind: revoke, parent_id: null })).toBe(true)
    const groups = mergeUnknownKinds([grant, revoke])
    expect(groups.find((group) => group.label === 'access')?.kinds).toEqual(expect.arrayContaining([grant, revoke]))
    expect(groups.find((group) => group.label === 'прочие')).toBeUndefined()
  })

  it('distinguishes read-only provisioning recovery from role creation', () => {
    expect(operationLabel('account.recover_provisioning')).toBe('Восстановление записи из кластера')
    expect(operationLabel('role.create')).toBe('Создание роли')
    expect(operationLabel('resource.create.database_with_roles')).toBe('Создание базы и ролей доступа')
    expect(operationLabel('postgres.resource.create.database_with_roles.v2')).toBe('Создание базы и ролей доступа')
    expect(operationLabel('postgres.account.create.v2')).toBe('Создание PostgreSQL-аккаунта')
    expect(operationLabel('resource.create.prepared_database')).toBe('Создание подготовленной базы')
    expect(operationLabel('role.policy.create_database')).toBe('Создание роли доступа')
  })

  it('keeps state changes and excludes discovery, automation, children and unknown kinds', () => {
    const operation = (overrides: Partial<{
      actor_type: string
      kind: string
      parent_id: string | null
    }> = {}) => ({
      actor_type: 'user',
      kind: 'access.grant',
      parent_id: null,
      ...overrides,
    })

    expect(isRecentActivityOperation(operation())).toBe(true)
    expect(isRecentActivityOperation(operation({ kind: 'connection.discover' }))).toBe(false)
    expect(isRecentActivityOperation(operation({ actor_type: 'service' }))).toBe(false)
    expect(isRecentActivityOperation(operation({ parent_id: 'bulk-parent' }))).toBe(false)
    expect(isRecentActivityOperation(operation({ kind: 'future.operation' }))).toBe(false)
    expect(RECENT_ACTIVITY_KINDS).toContain('account.restore')
    expect(RECENT_ACTIVITY_KINDS).toContain('connection.admin_credential.rotate')
    expect(RECENT_ACTIVITY_KINDS).not.toContain('connection.discover')
  })

  it('uses human labels while preserving unknown technical values', () => {
    expect(operationLabel('account.delete')).toBe('Удаление аккаунта')
    expect(operationLabel('role.policy.repair')).toBe('Исправление политики роли')
    expect(operationLabel('connection.admin_credential.switch')).toBe('Смена admin credential')
    // Незнакомый kind читается в списках; техническое значение остаётся
    // видимым в панели операции.
    expect(operationLabel('future.operation')).toBe('Future · operation')
    expect(operationStatusLabel('success')).toBe('Done')
  })

  it('presents account adoption as a distinct operation without exposing its internal guards', () => {
    const operation = {
      id: 'operation-1',
      kind: 'credential.rotate',
      account_id: 'account-1',
      payload: {
        account_id: 'account-1',
        adopt: true,
        adopt_generate: true,
        expected_lifecycle_version: 7,
      },
    }
    const context = accountAdoptContext(operation, [{
      id: 1,
      occurred_at: '2026-07-22T10:13:35Z',
      actor_type: 'user',
      actor_id: 'admin@example.test',
      action: 'account.adopt_requested',
      connection_id: 'connection-1',
      resource_id: null,
      principal_id: null,
      account_id: 'account-1',
      operation_id: 'operation-1',
      result: 'success',
      metadata: {
        engine_identity: 'reports_bot',
        mode: 'generate',
        adopted_bindings: 3,
      },
    } satisfies AuditEvent])

    expect(operationDisplayLabel(operation)).toBe('Принятие аккаунта под управление')
    expect(context).toEqual({
      account: 'reports_bot',
      mode: 'Новый пароль сгенерирован',
      adoptedBindings: 3,
    })
    expect(context).not.toHaveProperty('expected_lifecycle_version')
  })

  it('presents link-and-manage with safe account and principal context', () => {
    const operation = {
      id: 'operation-2',
      kind: 'credential.rotate',
      account_id: 'account-2',
      principal_id: 'principal-2',
      payload: {
        account_id: 'account-2',
        managed_link_principal_id: 'principal-2',
        shared_credential_path: 'principals/principal-2/environments/test/credential',
      },
    }
    const events = [{
      id: 2,
      occurred_at: '2026-07-22T10:13:35Z',
      actor_type: 'user',
      actor_id: 'admin@example.test',
      action: 'account.managed_link_requested',
      connection_id: 'connection-1',
      resource_id: null,
      principal_id: 'principal-2',
      account_id: 'account-2',
      operation_id: 'operation-2',
      result: 'success',
      metadata: {
        engine_identity: 'reports_bot',
        environment: 'test',
        credential_source: 'generated',
      },
    } satisfies AuditEvent]

    expect(operationDisplayLabel(operation)).toBe('Связать аккаунт и взять под управление')
    expect(accountManagedLinkContext(operation, events, new Map([['principal-2', 'deploy-user']]))).toEqual({
      account: 'reports_bot',
      principal: 'deploy-user',
      environment: 'test',
      credentialSource: 'generated',
    })
    expect(accountManagedLinkContext(operation, events)).not.toHaveProperty('shared_credential_path')
  })

  it('uses the audit display name and never leaks a missing principal UUID', () => {
    const operation = {
      id: 'operation-3', kind: 'credential.rotate', account_id: 'account-3',
      principal_id: 'principal-deleted',
      payload: { managed_link_principal_id: 'principal-deleted' },
    }
    const event = {
      id: 3, occurred_at: '2026-07-22T10:13:35Z', actor_type: 'user',
      actor_id: 'admin@example.test', action: 'account.managed_link_requested',
      connection_id: 'connection-1', resource_id: null,
      principal_id: 'principal-deleted', account_id: 'account-3',
      operation_id: 'operation-3', result: 'success',
      metadata: { principal_display_name: 'former-user' },
    } satisfies AuditEvent

    expect(accountManagedLinkContext(operation, [event])?.principal).toBe('former-user')
    expect(accountManagedLinkContext(operation, [])?.principal).toBe('Удалённый пользователь')
  })
})
