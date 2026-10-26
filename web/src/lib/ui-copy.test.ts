import { describe, expect, it } from 'vitest'
import {
  auditActionLabel,
  accountKindLabel,
  auditResultLabel,
  bindingStateLabel,
  bindingStatusLabel,
  connectionStatusLabel,
  connectionSyncLabel,
  driftKindLabel,
  inventoryStatusLabel,
  ownershipLabel,
  principalTypeLabel,
  resourceKindLabel,
  UI_COPY,
} from './ui-copy'

describe('canonical UI vocabulary', () => {
  it('keeps shared product terms in one place', () => {
    expect(UI_COPY).toEqual({
      all: 'All',
      active: 'Active',
      approval: 'Approval',
      current: 'Current',
      configured: 'Configured',
      configuredUnknown: 'Unknown',
      deleted: 'Deleted',
      disabled: 'Disabled',
      enabled: 'Enabled',
      error: 'Error',
      failed: 'Failed',
      healthy: 'Healthy',
      loading: 'Loading',
      managed: 'Managed',
      manual: 'Manual',
      notConfigured: 'Not configured',
      unmanaged: 'Unmanaged',
      unavailable: 'Unavailable',
      roles: 'Roles',
      accounts: 'Accounts',
      drift: 'Drift',
      sync: 'Sync',
      apiTokens: 'API-токены',
    })
    expect(ownershipLabel('managed')).toBe('Managed')
    expect(ownershipLabel('unmanaged')).toBe('Unmanaged')
    expect(connectionStatusLabel('active')).toBe('Active')
    expect(connectionStatusLabel('discovery_failed')).toBe('Sync error')
    expect(connectionStatusLabel('credential_updating')).toBe('Credential updating')
    expect(connectionSyncLabel(0)).toBe('Sync')
    expect(connectionSyncLabel(2)).toBe('Drift 2')
    expect(inventoryStatusLabel('observed')).toBe('Observed')
    expect(bindingStatusLabel('synced')).toBe('Sync')
    expect(bindingStateLabel('present')).toBe('Present')
    expect(principalTypeLabel('service')).toBe('Service')
    expect(resourceKindLabel('database')).toBe('Database')
    expect(accountKindLabel('login')).toBe('Login')
    expect(resourceKindLabel('future_kind')).toBe('Future kind')
  })

  it('keeps backend enums out of active control summaries', () => {
    expect(auditActionLabel('connection.updated')).toBe('Подключение изменено')
    expect(auditActionLabel('connection.disabled')).toBe('Подключение отключено')
    expect(auditActionLabel('principal.credential_created')).toBe('Credential пользователя создан')
    expect(auditActionLabel('principal.purged')).toBe('Пользователь удалён навсегда')
    expect(auditActionLabel('connection.admin_credential_rotate_requested'))
      .toBe('Запрошена ротация admin credential')
    expect(auditActionLabel('connection.admin_credential_change_failed'))
      .toBe('Ошибка изменения admin credential')
    // Незнакомое событие читается, а не показывается идентификатором — так
    // же, как resourceKindLabel выше.
    expect(auditActionLabel('future.action')).toBe('Future · action')
    expect(auditActionLabel('principal.external_identity_status_changed')).toBe('Статус в каталоге изменён')
    expect(auditActionLabel('security.offboarding_incomplete')).toBe('Offboarding не завершён')
    expect(auditResultLabel('success')).toBe('Success')
    expect(driftKindLabel('binding_drift')).toBe('Расхождение доступа')
  })
})
