// Фильтры ленты «Контроля»: период и тип операции. Живут отдельным файлом от
// control.tsx — там ровно один SegmentedFilter, и guard-тест следит, чтобы
// route-local псевдочипы не расползались по экрану.
import { Combobox } from '@project/ui'
import type { ComboboxOption } from '@project/ui'
import { localDayRange } from '../lib/operation-time'
import { mergeUnknownKinds } from '../lib/operation-kinds'
import { operationLabel } from '../lib/operation-presentation'

export interface JournalWindow {
  created_from?: string
  created_before?: string
}

export type JournalRangePreset = 'today' | 'day' | 'week' | 'all'

const PRESET_LABELS: ReadonlyArray<readonly [JournalRangePreset, string]> = [
  ['all', 'Всё время'],
  ['today', 'Сегодня'],
  ['day', '24 часа'],
  ['week', '7 дней'],
]

/** Границы пресета; «всё время» снимает окно целиком. */
export function journalRangeWindow(preset: JournalRangePreset, now = new Date()): JournalWindow {
  if (preset === 'all') return {}
  if (preset === 'today') {
    const day = localDayRange(now)
    return { created_from: day.createdFrom, created_before: day.createdBefore }
  }
  const hours = preset === 'day' ? 24 : 24 * 7
  return { created_from: new Date(now.getTime() - hours * 3_600_000).toISOString() }
}

/**
 * Какой пресет соответствует текущему URL. Окно из чужой точки входа (плитка
 * «Операций сегодня» на обзоре) не подсвечивает ничего: подсветка обещала бы
 * «эти границы = этот пресет», а границы могут быть любыми.
 */
export function journalActivePreset(window: JournalWindow, now = new Date()): JournalRangePreset | null {
  if (window.created_from === undefined && window.created_before === undefined) return 'all'
  for (const [preset] of PRESET_LABELS) {
    if (preset === 'all') continue
    const candidate = journalRangeWindow(preset, now)
    if (candidate.created_from === window.created_from
      && candidate.created_before === window.created_before) {
      return preset
    }
  }
  return null
}

export function JournalRangeFilter({ window, onChange }: { window: JournalWindow; onChange: (next: JournalWindow) => void }) {
  const active = journalActivePreset(window)
  return <div className="flex items-center gap-1" role="group" aria-label="Период журнала">
    {PRESET_LABELS.map(([preset, label]) => (
      <button key={preset} type="button" aria-pressed={active === preset}
        onClick={() => onChange(journalRangeWindow(preset))}
        className={active === preset
          ? 'grantor-touch-target ui-control-feedback rounded-md bg-panel2 px-2 py-1 text-xs font-medium text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent'
          : 'grantor-touch-target ui-control-feedback rounded-md px-2 py-1 text-xs text-muted hover:bg-panel2/60 hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent'}>
        {label}
      </button>
    ))}
  </div>
}

export function JournalKindFilter({ value, observedKinds, onValueChange }: { value: string; observedKinds: Iterable<string>; onValueChange: (value: string) => void }) {
  const options: ComboboxOption[] = [{ value: '', label: 'Все типы' }]
  for (const group of mergeUnknownKinds(observedKinds)) {
    for (const kind of group.kinds) {
      options.push({ value: kind, label: operationLabel(kind), description: kind, keywords: [group.label] })
    }
  }
  return <Combobox value={value} options={options} onValueChange={onValueChange}
    label="Тип операции" placeholder="Все типы" searchPlaceholder="Тип операции…"
    emptyText="Тип не найден" className="w-56 max-w-full" />
}
