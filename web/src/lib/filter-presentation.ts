import type { SelectionOption } from '../components/ui/selection-chips'
import type { ConnectionListFilter } from './connection-presentation'
import type { ControlFilter, ControlTab } from './control-search'
import { UI_COPY } from './ui-copy'

/** Канонический каталог общих фильтров приложения. */
export function connectionListFilterOptions(
  counts: Record<ConnectionListFilter, number>,
): readonly SelectionOption<ConnectionListFilter>[] {
  return [
    { value: 'all', label: UI_COPY.all, count: counts.all },
    { value: 'synced', label: UI_COPY.sync, count: counts.synced },
    { value: 'error', label: UI_COPY.error, count: counts.error },
  ]
}

export type DirectoryFilterValue = 'current' | 'deleted'

export function directoryFilterOptions(
  current: number,
  deleted: number,
): readonly SelectionOption<DirectoryFilterValue>[] {
  return [
    { value: 'current', label: UI_COPY.current, count: current },
    { value: 'deleted', label: UI_COPY.deleted, count: deleted },
  ]
}

export type OwnershipFilterValue = 'all' | 'managed' | 'unmanaged'

export function ownershipFilterOptions(
  managed: number,
  unmanaged: number,
): readonly SelectionOption<OwnershipFilterValue>[] {
  return [
    { value: 'all', label: UI_COPY.all, count: managed + unmanaged },
    { value: 'managed', label: UI_COPY.managed, count: managed },
    { value: 'unmanaged', label: UI_COPY.unmanaged, count: unmanaged },
  ]
}

export type ControlFilterCounts = Record<ControlFilter, number>

/** Один каталог фильтров для всех вкладок Control. */
export function controlTabFilterOptions(
  tab: ControlTab,
  counts: ControlFilterCounts,
  active?: ControlFilter,
): readonly SelectionOption<ControlFilter>[] {
  const option = (value: ControlFilter, label: string): SelectionOption<ControlFilter> => ({
    value,
    label,
    count: counts[value],
  })
  // Пустой фильтр скрывается: «Error 0» занимает место и обещает выборку,
  // которой нет. Всё и выбранный остаются всегда — иначе активный фильтр
  // исчез бы вместе со своим результатом.
  const visible = (options: readonly SelectionOption<ControlFilter>[]) =>
    options.filter((item) => item.value === 'all' || item.value === active || (item.count ?? 0) > 0)
  if (tab === 'attention') {
    return visible([
      option('all', UI_COPY.all),
      option('approval', UI_COPY.approval),
      option('errors', UI_COPY.error),
    ])
  }
  if (tab === 'operations') {
    return visible([
      option('all', UI_COPY.all),
      option('manual', UI_COPY.manual),
      option('active', UI_COPY.active),
      option('approval', UI_COPY.approval),
      option('errors', UI_COPY.error),
      option('events', 'События'),
    ])
  }
  if (tab === 'findings') {
    return visible([
      option('all', UI_COPY.all),
      option('access', 'Access'),
      option('resources', 'Resources'),
      option('connections', 'Connections'),
      option('baselined', 'Baseline'),
    ])
  }
  return []
}
