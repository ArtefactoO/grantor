// Раздел «Права доступа» аккаунта: свёрнутая сводка, раскрытый список с
// поиском и фильтрами, панель подробностей по клику.
//
// Раздел свёрнут по умолчанию — список прав бывает в сотни строк и вытесняет
// со экрана всё остальное. Но свёрнутое состояние обязано отвечать на вопрос
// «стоит ли раскрывать»: сколько прав всего, есть ли опасные, есть ли
// недостающие. Поэтому сводка видна всегда.
//
// Наследование показывается только там, где оно есть: движки без иерархии
// ролей (rabbitmq, redis, kafka) унаследованных прав не порождают, и
// счётчик «0 унаследованных» у них был бы шумом.
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronDown, ChevronRight, Trash2 } from '@project/ui/icons'
import type { Binding, Permission, Resource } from '../lib/types'
import type { PermissionEntry, PermissionFilters } from '../lib/permission-view'
import {
  buildPermissionEntries,
  EMPTY_PERMISSION_FILTERS,
  filterPermissions,
  summarizePermissions,
} from '../lib/permission-view'
import { plural } from '../lib/plural'
import { cn, IconButton, SearchInput, Spinner } from '@project/ui'
import { PermissionChip } from './ui/permission-chip'
import { PermissionDetailsDrawer } from './permission-details-drawer'

const PLURAL_RIGHTS = ['право', 'права', 'прав'] as const

export interface AccountPermissionsSectionProps {
	additionalContent?: ReactNode
	summaryExtra?: ReactNode
	roleAssignmentsOnly?: boolean
	expandRequest?: number
  bindings: Binding[]
  permissionsById: Map<string, Permission>
  resourcesById: Map<string, Resource>
  engine: string
  accountLabel?: string
  /** Порог, после которого включается поиск: на коротком списке он лишний. */
  searchThreshold?: number
  /**
   * Отзыв права. Кнопка показывается только у управляемых прав: снять можно
   * лишь то, что выдал grantor. undefined — раздел только для чтения.
   */
  onRevoke?: (binding: Binding) => void
  /** id binding, отзыв которого выполняется — на его строке спиннер. */
  revokingId?: string | null
}

export function AccountPermissionsSection({
	additionalContent, summaryExtra, roleAssignmentsOnly = false, expandRequest = 0,
  bindings,
  permissionsById,
  resourcesById,
  engine,
  accountLabel,
  searchThreshold = 8,
  onRevoke,
  revokingId,
}: AccountPermissionsSectionProps) {
  const [expanded, setExpanded] = useState(false)
  const [filters, setFilters] = useState<PermissionFilters>(EMPTY_PERMISSION_FILTERS)
  const [selected, setSelected] = useState<PermissionEntry | null>(null)
  useEffect(() => { if (expandRequest > 0) setExpanded(true) }, [expandRequest])

  const entries = useMemo(
    () => buildPermissionEntries(bindings, permissionsById, resourcesById),
    [bindings, permissionsById, resourcesById],
  )
  const summary = useMemo(() => summarizePermissions(entries), [entries])
  const visible = useMemo(() => filterPermissions(entries, filters), [entries, filters])

  const showSearch = entries.length >= searchThreshold

  return (
    <section className="space-y-2">
      <button
        type="button"
        onClick={() => setExpanded((value) => !value)}
        aria-expanded={expanded}
        className="grantor-touch-target ui-control-feedback flex w-full items-center gap-2 rounded px-1 py-1 text-left hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
      >
        {expanded ? (
          <ChevronDown className="size-3.5 shrink-0 text-muted" aria-hidden />
        ) : (
          <ChevronRight className="size-3.5 shrink-0 text-muted" aria-hidden />
        )}
        <span className="text-xs font-medium text-fg">Права доступа</span>
        <SummaryChips summary={summary} roleAssignmentsOnly={roleAssignmentsOnly} />
        {summaryExtra}
      </button>

      {expanded && (
        <div className="space-y-2 pl-6">
          {showSearch && (
            <SearchInput
              value={filters.query}
              onChange={(query) => setFilters((current) => ({ ...current, query }))}
              placeholder="Действие, ресурс или исходное выражение"
              ariaLabel="Поиск по правам"
              density="compact"
            />
          )}

          <FilterRow filters={filters} onChange={setFilters} summary={summary} />

          {visible.length === 0 ? (
            <p className="text-xs text-muted">
              {entries.length === 0 ? roleAssignmentsOnly ? 'Назначенных ролей нет' : 'Прав не обнаружено' : 'Ничего не найдено по фильтрам'}
            </p>
          ) : (
            <ul className="flex flex-wrap gap-1.5">
              {visible.map((entry) => (
                <li key={entry.key} className="flex min-w-0 max-w-full items-start gap-1">
                  <PermissionChip entry={entry} onOpen={setSelected} />
                  {onRevoke !== undefined && entry.managed && entry.revocable !== null && (
                    <IconButton
                      compact
                      tone="danger"
                      onClick={(event) => {
                        event.stopPropagation()
                        onRevoke(entry.revocable!)
                      }}
                      busy={revokingId === entry.revocable.id}
                      label={`Снять право ${entry.raw}`}
                      icon={revokingId === entry.revocable.id ? (
                        <Spinner className="size-3.5" />
                      ) : (
                        <Trash2 className="size-3.5" aria-hidden="true" />
                      )}
                    />
                  )}
                </li>
              ))}
            </ul>
          )}
          {additionalContent}
        </div>
      )}

      <PermissionDetailsDrawer
        entry={selected}
        engine={engine}
        accountLabel={accountLabel}
        onClose={() => setSelected(null)}
      />
    </section>
  )
}

/** Сводка в свёрнутом состоянии: сколько прав и что требует внимания. */
function SummaryChips({ summary, roleAssignmentsOnly = false }: { summary: ReturnType<typeof summarizePermissions>; roleAssignmentsOnly?: boolean }) {
  return (
    <span className="flex min-w-0 flex-wrap items-center gap-1.5 text-[11px] text-muted">
      <span>
        {summary.total} {roleAssignmentsOnly ? plural(summary.total, ['назначение роли', 'назначения ролей', 'назначений ролей']) : plural(summary.total, PLURAL_RIGHTS)}
      </span>
      {summary.dangerous > 0 && (
        <span className="rounded border border-danger/40 px-1 text-danger">
          опасных: {summary.dangerous}
        </span>
      )}
      {summary.missing > 0 && (
        <span className="rounded border border-line px-1">
          отсутствует: {summary.missing}
        </span>
      )}
      {summary.inherited > 0 && (
        <span className="rounded border border-line px-1">
          унаследовано: {summary.inherited}
        </span>
      )}
      {summary.unmanaged > 0 && (
        <span className="rounded border border-line px-1">
          вне управления: {summary.unmanaged}
        </span>
      )}
    </span>
  )
}

interface FilterRowProps {
  filters: PermissionFilters
  onChange: (filters: PermissionFilters) => void
  summary: ReturnType<typeof summarizePermissions>
}

/**
 * Фильтры-переключатели. Показываются только те, которые что-то изменят:
 * фильтр «опасные» при нуле опасных прав бесполезен и только занимает место.
 */
function FilterRow({ filters, onChange, summary }: FilterRowProps) {
  const toggles: Array<{ key: keyof PermissionFilters; label: string; enabled: boolean }> = [
    { key: 'dangerous', label: 'опасные', enabled: summary.dangerous > 0 },
    { key: 'inherited', label: 'унаследованные', enabled: summary.inherited > 0 },
    { key: 'present', label: 'отсутствующие', enabled: summary.missing > 0 },
    { key: 'managed', label: 'вне управления', enabled: summary.unmanaged > 0 },
  ]
  const shown = toggles.filter((toggle) => toggle.enabled)
  if (shown.length === 0) {
    return null
  }

  // Фильтры «отсутствующие» и «вне управления» — отрицания полей present и
  // managed, поэтому включённому переключателю соответствует false; «опасные»
  // и «унаследованные» — прямые признаки.
  const valueWhenOn = (key: keyof PermissionFilters) =>
    key === 'dangerous' || key === 'inherited'

  return (
    <div className="flex flex-wrap gap-1.5">
      {shown.map((toggle) => {
        const active = filters[toggle.key] === valueWhenOn(toggle.key)
        return (
          <button
            key={toggle.key}
            type="button"
            aria-pressed={active}
            onClick={() =>
              onChange({
                ...filters,
                [toggle.key]: active ? null : valueWhenOn(toggle.key),
              })
            }
            className={cn(
              'grantor-touch-target ui-control-feedback rounded border px-1.5 py-0.5 text-[11px]',
              'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
              active
                ? 'border-accent/40 bg-accent-soft/55 text-accent'
                : 'border-line text-muted hover:border-accent/35 hover:text-accent',
            )}
          >
            {toggle.label}
          </button>
        )
      })}
    </div>
  )
}
