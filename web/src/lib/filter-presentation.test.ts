import { describe, expect, it } from 'vitest'
import {
  connectionListFilterOptions,
  controlTabFilterOptions,
  directoryFilterOptions,
  ownershipFilterOptions,
} from './filter-presentation'

describe('canonical filter presentation', () => {
  it('keeps shared state labels in one English vocabulary and stable order', () => {
    expect(connectionListFilterOptions({ all: 5, synced: 4, error: 1 })).toEqual([
      { value: 'all', label: 'All', count: 5 },
      { value: 'synced', label: 'Sync', count: 4 },
      { value: 'error', label: 'Error', count: 1 },
    ])
    expect(directoryFilterOptions(3, 1)).toEqual([
      { value: 'current', label: 'Current', count: 3 },
      { value: 'deleted', label: 'Deleted', count: 1 },
    ])
    expect(ownershipFilterOptions(2, 3)).toEqual([
      { value: 'all', label: 'All', count: 5 },
      { value: 'managed', label: 'Managed', count: 2 },
      { value: 'unmanaged', label: 'Unmanaged', count: 3 },
    ])
    const counts = {
      all: 6, active: 2, approval: 1, errors: 3, manual: 4, events: 4, drift: 2,
      access: 1, resources: 1, connections: 0, baselined: 0,
    }
    expect(controlTabFilterOptions('operations', counts)).toEqual([
      { value: 'all', label: 'All', count: 6 },
      { value: 'manual', label: 'Manual', count: 4 },
      { value: 'active', label: 'Active', count: 2 },
      { value: 'approval', label: 'Approval', count: 1 },
      { value: 'errors', label: 'Error', count: 3 },
      { value: 'events', label: 'События', count: 4 },
    ])
    // Пустой фильтр не показывается: он занимает место и обещает выборку,
    // которой нет.
    expect(controlTabFilterOptions('findings', counts)).toEqual([
      { value: 'all', label: 'All', count: 6 },
      { value: 'access', label: 'Access', count: 1 },
      { value: 'resources', label: 'Resources', count: 1 },
    ])
    // Выбранный остаётся даже пустым — иначе он исчез бы вместе со своим
    // результатом, и пользователь не понял бы, какой фильтр включён.
    expect(controlTabFilterOptions('findings', counts, 'connections')).toEqual([
      { value: 'all', label: 'All', count: 6 },
      { value: 'access', label: 'Access', count: 1 },
      { value: 'resources', label: 'Resources', count: 1 },
      { value: 'connections', label: 'Connections', count: 0 },
    ])
  })
})
