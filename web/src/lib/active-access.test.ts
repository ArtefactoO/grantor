import { describe, expect, it } from 'vitest'
import type { Binding } from './types'
import {
  activeAccessBindings,
  bindingNeedsRepair,
  isActiveAccessBinding,
  isAssignedManagedBinding,
} from './active-access'

function binding(
  id: string,
  desiredState: string | null,
  observedState: string,
  overrides: Partial<Binding> = {},
): Binding {
  return {
    id,
    account_id: 'account',
    permission_definition_id: `permission-${id}`,
    scope_resource_id: null,
    source: desiredState === null ? 'external' : 'service',
    desired_state: desiredState,
    observed_state: observedState,
    observed_effective: true,
    status: 'synced',
    expires_at: null,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
    ...overrides,
  }
}

describe('active access predicate', () => {
  it.each([
    ['managed present', binding('managed', 'present', 'present'), true],
    ['unmanaged present', binding('unmanaged', null, 'present'), true],
    ['revoking but observed', binding('revoking', 'absent', 'present'), false],
    ['managed absent', binding('absent', 'present', 'absent'), false],
    ['unmanaged disappeared', binding('gone', null, 'absent'), false],
    ['unknown target state', binding('unknown', 'present', 'unknown'), false],
  ])('%s is active=%s', (_name, value, expected) => {
    expect(isActiveAccessBinding(value)).toBe(expected)
  })

  it('keeps only currently effective rights for chips and summaries', () => {
    const values = [
      binding('managed', 'present', 'present'),
      binding('revoked', 'absent', 'absent'),
      binding('missing', 'present', 'absent'),
    ]
    expect(activeAccessBindings(values).map((item) => item.id)).toEqual(['managed'])
  })
})

// Зеркало internal/core/inventory.BindingNeedsRepair — кейсы 1:1 с Go-тестом
// TestBindingNeedsRepair; менять синхронно.
describe('binding repair predicate', () => {
  it.each([
    ['снято снаружи', binding('a', 'present', 'absent', { status: 'drift' }), true],
    ['выдано, но не действует',
      binding('b', 'present', 'present', { observed_effective: false, status: 'drift' }), true],
    ['выдано и работает', binding('c', 'present', 'present'), false],
    ['свежий грант, ещё не наблюдалось',
      binding('d', 'present', 'unknown', { status: 'pending' }), false],
    ['применение упало', binding('e', 'present', 'unknown', { status: 'failed' }), true],
    ['применение упало поверх выданного',
      binding('f', 'present', 'present', { status: 'failed' }), true],
    ['провал отзыва', binding('g', 'absent', 'present', { status: 'failed' }), false],
    ['unmanaged', binding('h', null, 'absent', { status: 'observed' }), false],
  ])('%s → needsRepair=%s', (_name, value, expected) => {
    expect(bindingNeedsRepair(value)).toBe(expected)
  })

  // «Уже назначена» = предикат 409 API: сломанное право не считается
  // назначенным и остаётся доступным для повторной выдачи.
  it.each([
    ['здоровое право назначено', binding('a', 'present', 'present'), true],
    ['свежий грант назначен', binding('b', 'present', 'unknown', { status: 'pending' }), true],
    ['failed можно выдать повторно', binding('c', 'present', 'unknown', { status: 'failed' }), false],
    ['drift можно выдать повторно', binding('d', 'present', 'absent', { status: 'drift' }), false],
    ['unmanaged не назначено', binding('e', null, 'present', { status: 'observed' }), false],
  ])('%s → assigned=%s', (_name, value, expected) => {
    expect(isAssignedManagedBinding(value)).toBe(expected)
  })
})
