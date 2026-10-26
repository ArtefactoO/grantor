// Карточка-радиокнопка с подписью и подсказкой: выбранная подсвечена
// медью. Единый вид выбора режима credential, вида субъекта политики и
// типа принципала.
import { cn } from './cn'
import { Check, Info } from './icons'
import type { ReactNode } from 'react'
import { Tooltip } from './tooltip'
import { selectionSurfaceClassName } from './selection-state'

export interface RadioOptionCardProps {
  /** Имя группы радиокнопок (взаимоисключающий выбор). */
  name: string
  label: ReactNode
  hint: string
  icon?: ReactNode
  tooltip?: ReactNode
  checked: boolean
  onSelect: () => void
}

export function RadioOptionCard({
  name,
  label,
  hint,
  icon,
  tooltip,
  checked,
  onSelect,
}: RadioOptionCardProps) {
  return (
    <label
      className={cn(
        'ui-control-feedback group flex min-h-16 w-full cursor-pointer items-center gap-3 rounded-lg border border-line/80 px-3.5 py-3',
        selectionSurfaceClassName(
          checked,
          checked ? undefined : 'bg-panel2/25 hover:border-line-strong',
        ),
      )}
    >
      <input
        type="radio"
        name={name}
        checked={checked}
        onChange={onSelect}
        className="peer sr-only"
      />
      <span
        aria-hidden="true"
        className={cn(
          'ui-control-feedback grid size-5 shrink-0 place-items-center rounded-full border peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-accent',
          checked
            ? 'border-accent bg-accent text-accent-ink'
            : 'border-line-strong bg-panel group-hover:border-muted',
        )}
      >
        {checked && <Check className="size-3" strokeWidth={2.5} />}
      </span>
      {icon !== undefined && (
        <span className={cn('shrink-0', checked ? 'text-accent' : 'text-muted')} aria-hidden="true">
          {icon}
        </span>
      )}
      <span className="min-w-0 flex-1">
        <span className="block text-sm font-medium leading-5 text-text">{label}</span>
        <span className="mt-0.5 block text-xs leading-4 text-faint">{hint}</span>
      </span>
      {tooltip !== undefined && (
        <Tooltip content={tooltip} side="bottom">
          <span
            role="note"
            tabIndex={0}
            aria-label="Подробнее"
            className="grid size-6 shrink-0 place-items-center rounded-md text-faint hover:bg-panel hover:text-muted focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-accent"
            onClick={(event) => {
              event.preventDefault()
              event.stopPropagation()
            }}
          >
            <Info className="size-3.5" aria-hidden="true" />
          </span>
        </Tooltip>
      )}
    </label>
  )
}
