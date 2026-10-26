import { describe, expect, it } from 'vitest'
import {
  buildPermissionEntries,
  EMPTY_PERMISSION_FILTERS,
  filterPermissions,
  permissionLabel,
  summarizePermissions,
} from './permission-view'
import type { Binding, Permission, PermissionView, Resource } from './types'

function view(overrides: Partial<PermissionView> = {}): PermissionView {
  return {
    category: 'unknown',
    action: '',
    resource: '',
    scope: '',
    dangerous: false,
    danger_reason: '',
    details: null,
    raw: 'raw-value',
    ...overrides,
  }
}

function permission(id: string, overrides: Partial<Permission> = {}): Permission {
  return {
    id,
    connection_id: 'conn',
    engine: 'postgres',
    external_id: `role:${id}`,
    name: id,
    scope_resource_id: null,
    assignable: true,
    status: 'observed',
    dangerous: false,
    attributes: {},
    normalized: view({ category: 'role', resource: id, raw: id }),
    created_at: '',
    updated_at: '',
    ...overrides,
  }
}

function binding(overrides: Partial<Binding> = {}): Binding {
  return {
    id: `b-${Math.random()}`,
    account_id: 'acct',
    permission_definition_id: 'p1',
    scope_resource_id: null,
    source: 'service',
    desired_state: 'present',
    observed_state: 'present',
    observed_effective: true,
    status: 'synced',
    expires_at: null,
    created_at: '',
    updated_at: '',
    ...overrides,
  }
}

describe('permissionLabel', () => {
  it('сочетает действие и ресурс', () => {
    expect(permissionLabel(view({ action: 'read', resource: 'orders' }))).toBe('read: orders')
  })

  it('показывает роль с базой, когда база добавляет смысл', () => {
    expect(permissionLabel(view({ category: 'role', resource: 'readWrite', scope: 'ads' }))).toBe(
      'readWrite @ ads',
    )
  })

  it('не дублирует scope, совпадающий с ресурсом', () => {
    expect(permissionLabel(view({ category: 'vhost', resource: 'sl', scope: 'sl' }))).toBe('sl')
  })

  // Право без разобранных полей не должно исчезать из интерфейса.
  it('падает обратно на исходное выражение', () => {
    expect(permissionLabel(view({ raw: 'acl:weird:notation' }))).toBe('acl:weird:notation')
  })
})

describe('buildPermissionEntries', () => {
  const permissions = new Map([['p1', permission('p1')]])
  const resources = new Map<string, Resource>()

  it('переносит факты binding в запись', () => {
    const [entry] = buildPermissionEntries(
      [binding({ source: 'external', desired_state: null, observed_state: 'present' })],
      permissions,
      resources,
    )
    expect(entry.managed).toBe(false)
    expect(entry.present).toBe(true)
    expect(entry.inherited).toBe(false)
    expect(entry.label).toBe('p1')
  })

  // Одно право может прийти и от discovery, и от grantor: склейка обязана
  // показывать худший случай, иначе строка выглядит благополучнее реальности.
  it('склеивает дубликаты пессимистично', () => {
    const entries = buildPermissionEntries(
      [
        binding({ desired_state: 'present', observed_state: 'present' }),
        binding({ desired_state: 'present', observed_state: 'absent' }),
      ],
      permissions,
      resources,
    )
    expect(entries).toHaveLength(1)
    expect(entries[0].managed).toBe(true)
    expect(entries[0].present).toBe(false)
  })

  // Недостающее право — та самая строка, которая объясняет, почему доступ не
  // работает: grantor его требует, discovery не видит.
  it('оставляет недостающее право видимым', () => {
    const [entry] = buildPermissionEntries(
      [binding({ desired_state: 'present', observed_state: 'absent', status: 'drift' })],
      permissions,
      resources,
    )
    expect(entry.present).toBe(false)
    expect(entry.managed).toBe(true)
    expect(entry.status).toBe('drift')
  })

  // Завершённый отзыв показывать нечего.
  it('отбрасывает завершённый отзыв', () => {
    expect(
      buildPermissionEntries(
        [binding({ desired_state: 'absent', observed_state: 'absent' })],
        permissions,
        resources,
      ),
    ).toHaveLength(0)
  })

  // Гонка discovery и чтения: binding есть, определения ещё нет.
  it('показывает право без определения по короткому id', () => {
    const [entry] = buildPermissionEntries(
      [binding({ permission_definition_id: '00000000-1111-2222-3333-444444444444' })],
      new Map(),
      resources,
    )
    expect(entry.label).not.toBe('')
    expect(entry.raw).not.toBe('')
  })
})

describe('summarizePermissions', () => {
  it('считает признаки раздельно', () => {
    const entries = buildPermissionEntries(
      [
        binding({ permission_definition_id: 'p1' }),
        binding({ permission_definition_id: 'p2', desired_state: null, source: 'external' }),
      ],
      new Map([
        ['p1', permission('p1', { normalized: view({ category: 'role', resource: 'p1', dangerous: true, danger_reason: 'x', raw: 'p1' }) })],
        ['p2', permission('p2')],
      ]),
      new Map(),
    )
    const summary = summarizePermissions(entries)
    expect(summary.total).toBe(2)
    expect(summary.dangerous).toBe(1)
    expect(summary.unmanaged).toBe(1)
    expect(summary.direct).toBe(2)
  })
})

describe('filterPermissions', () => {
  const entries = buildPermissionEntries(
    [
      binding({ permission_definition_id: 'p1' }),
      binding({ permission_definition_id: 'p2', desired_state: null, source: 'external' }),
    ],
    new Map([
      ['p1', permission('p1', { normalized: view({ category: 'role', action: 'read', resource: 'orders', raw: 'topic-consume:orders' }) })],
      ['p2', permission('p2')],
    ]),
    new Map(),
  )

  it('ищет по подписи и по исходному выражению', () => {
    expect(filterPermissions(entries, { ...EMPTY_PERMISSION_FILTERS, query: 'orders' })).toHaveLength(1)
    expect(
      filterPermissions(entries, { ...EMPTY_PERMISSION_FILTERS, query: 'topic-consume' }),
    ).toHaveLength(1)
  })

  it('фильтрует по управляемости', () => {
    expect(filterPermissions(entries, { ...EMPTY_PERMISSION_FILTERS, managed: false })).toHaveLength(1)
    expect(filterPermissions(entries, { ...EMPTY_PERMISSION_FILTERS, managed: true })).toHaveLength(1)
  })

  it('пустой фильтр ничего не отсекает', () => {
    expect(filterPermissions(entries, EMPTY_PERMISSION_FILTERS)).toHaveLength(2)
  })
})

// Унаследованное право отозвать нельзя: прямого ребра в целевой системе нет,
// команда отзыва не находит что снимать и завершается no-op. Раньше кнопка
// показывалась, отзыв рапортовал успех, а доступ оставался.
describe('revocable для унаследованных прав', () => {
  const permissions = new Map([['p1', permission('p1')]])
  const resources = new Map<string, Resource>()

  it('не предлагает отзыв права, полученного через роль', () => {
    const [entry] = buildPermissionEntries(
      [binding({ source: 'inherited', desired_state: 'present', observed_state: 'present' })],
      permissions,
      resources,
    )
    expect(entry.inherited).toBe(true)
    expect(entry.revocable).toBeNull()
  })

  it('предлагает отзыв прямого управляемого права', () => {
    const [entry] = buildPermissionEntries(
      [binding({ id: 'b-direct', source: 'service', desired_state: 'present' })],
      permissions,
      resources,
    )
    expect(entry.revocable?.id).toBe('b-direct')
  })
})
