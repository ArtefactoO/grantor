// Зоны данных grantor: managed («чем grantor управляет») и sync («что
// синкается из кластера discovery»). Единственный источник визуальной
// семантики разделения — все экраны переиспользуют эти константы и
// компоненты, не дублируя классы и подписи. Цвета — только семантические
// токены (ok — managed-акцент, muted/faint — sync), без хардкодов.
import { cn, Tooltip, DirectorySectionHeader, selectionTabClassName } from '@project/ui'
import { SegmentedFilter } from '../components/ui/selection-chips'
import { UI_COPY } from './ui-copy'
import { ownershipFilterOptions } from './filter-presentation'
import type { OwnershipFilterValue } from './filter-presentation'

/** Зона данных: managed — управляет grantor, sync — снимок кластера. */
export type Zone = 'managed' | 'sync'

/** Метаданные зоны: подписи группы вкладок и секций таблиц. */
export interface ZoneMeta {
  /** Заголовок секции таблицы/списка. */
  sectionLabel: string
}

export const ZONE_META: Record<Zone, ZoneMeta> = {
  managed: { sectionLabel: UI_COPY.managed },
  sync: { sectionLabel: UI_COPY.unmanaged },
}

// ---------------------------------------------------------------------------
// Группировка по ownership.

/** Разбивает элементы на managed и остальные (unmanaged/неизвестные). */
export function groupByOwnership<T>(
  items: readonly T[],
  getOwnership: (item: T) => string,
): { managed: T[]; unmanaged: T[] } {
  const managed: T[] = []
  const unmanaged: T[] = []
  for (const item of items) {
    if (getOwnership(item) === 'managed') {
      managed.push(item)
    } else {
      unmanaged.push(item)
    }
  }
  return { managed, unmanaged }
}

// ---------------------------------------------------------------------------
// Вкладки с зонами.

/** Вкладка с зоной: managed-вкладки рендерятся первыми, sync — приглушённо
 * после разделителя. */
export interface ZoneTabItem<K extends string> {
  key: K
  label: string
  zone: Zone
}

export interface ZoneTabsProps<K extends string> {
  tabs: ReadonlyArray<ZoneTabItem<K>>
  active: K
  onSelect: (key: K) => void
}

/**
 * Полоса вкладок, разделённая по зонам: сперва managed, затем вертикальный
 * разделитель и приглушённые read-only вкладки. Иконки намеренно не
 * дублируют зону: это навигация, а не действие Sync. Порядок групп фиксирован
 * независимо от порядка tabs.
 */
export function ZoneTabs<K extends string>({ tabs, active, onSelect }: ZoneTabsProps<K>) {
  const managedTabs = tabs.filter((t) => t.zone === 'managed')
  const syncTabs = tabs.filter((t) => t.zone === 'sync')

  const renderTab = (item: ZoneTabItem<K>) => (
    <button
      key={item.key}
      type="button"
      aria-pressed={active === item.key}
      onClick={() => onSelect(item.key)}
      className={cn(
        'grantor-touch-target inline-flex shrink-0 items-center gap-1.5 px-3 py-2 text-sm',
        selectionTabClassName(
          active === item.key,
          item.zone === 'sync' ? 'faint' : 'muted',
        ),
      )}
    >
      {item.label}
    </button>
  )

  return (
    <div role="group" aria-label="Разделы" className="flex max-w-full items-center gap-1 overflow-x-auto overscroll-x-contain border-b border-line">
      {managedTabs.map(renderTab)}
      {syncTabs.length > 0 && (
        <>
          {/* Только разделитель: текст и декоративные Sync-иконки читались
              как отдельные элементы навигации. */}
          <span className="mx-2 h-4 w-px shrink-0 bg-line" aria-hidden="true" />
          {syncTabs.map(renderTab)}
        </>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Заголовки секций таблиц/списков.

export interface ZoneSectionHeaderProps {
  zone: Zone
  /** Переопределение подписи; по умолчанию — sectionLabel зоны. */
  label?: string
  /** Счётчик элементов секции. */
  count?: number
  /** Короткая подсказка (например, что делать с пустой секцией). */
  hint?: string
  className?: string
}

/** Заголовок секции зоны: компактная uppercase-подпись без декоративных
 * иконок. Managed — спокойный зелёный маркер, sync — нейтральный. */
export function ZoneSectionHeader({
  zone,
  label,
  count,
  hint,
  className,
}: ZoneSectionHeaderProps) {
  const sectionLabel = label ?? ZONE_META[zone].sectionLabel
  const content = (
    <span
      className={cn(
        'inline-flex shrink-0 items-baseline gap-1.5 text-[10px] font-semibold uppercase tracking-[0.08em]',
        zone === 'managed' ? 'text-ok' : 'text-muted',
        hint !== undefined && 'cursor-help',
      )}
    >
      {sectionLabel}
      {count !== undefined && (
        <span className="font-normal tabular-nums text-faint">{count}</span>
      )}
    </span>
  )

  return (
    <div className={cn('flex min-h-4 items-center', className)}>
      {hint !== undefined ? (
        <Tooltip
          content={hint}
          disabledTarget
          targetLabel={`Подробнее о секции ${sectionLabel}`}
        >
          {content}
        </Tooltip>
      ) : (
        content
      )}
    </div>
  )
}

export interface ZoneSectionRowProps extends Omit<ZoneSectionHeaderProps, 'className'> {
  /** Число колонок таблицы — заголовок растягивается на всю ширину. */
  colSpan: number
}

/** Тот же заголовок секции, но строкой таблицы (для группировки внутри
 * <TableBody>). */
export function ZoneSectionRow({ colSpan, ...header }: ZoneSectionRowProps) {
  const sectionLabel = header.label ?? ZONE_META[header.zone].sectionLabel
  return (
    <tr>
      <td colSpan={colSpan} className="p-0">
        <DirectorySectionHeader
          label={sectionLabel}
          count={header.count}
          hint={header.hint}
          tone={header.zone === 'managed' ? 'managed' : 'neutral'}
          marker
        />
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// Фильтр по ownership.

export type { OwnershipFilterValue } from './filter-presentation'

export interface OwnershipCounts {
  managed: number
  unmanaged: number
}

export interface OwnershipFilterProps {
  value: OwnershipFilterValue
  onChange: (value: OwnershipFilterValue) => void
  counts: OwnershipCounts
  className?: string
}

/** Чипы «All (N) · Managed (N) · Unmanaged (N)»; controlled. */
export function OwnershipFilter({ value, onChange, counts, className }: OwnershipFilterProps) {
  return (
    <SegmentedFilter
      label="Управление аккаунтами"
      value={value}
      onChange={onChange}
      className={className}
      options={ownershipFilterOptions(counts.managed, counts.unmanaged)}
    />
  )
}
