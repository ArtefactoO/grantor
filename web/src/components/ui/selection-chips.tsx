import * as Popover from '@radix-ui/react-popover'
import { Check, ChevronDown, Minus } from '@project/ui/icons'
import { useRef } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import { cn, usePopoverSurfaceMotion } from '@project/ui'
import { UI_COPY } from '../../lib/ui-copy'

export interface SelectionOption<T extends string> {
  value: T
  label: ReactNode
  /** Явное имя для сложной label с иконкой; count добавляется автоматически. */
  accessibleLabel?: string
  count?: number
  disabled?: boolean
}

interface SelectionChipProps {
  active: boolean
  children: ReactNode
  onClick: () => void
  accessibleLabel?: string
  disabled?: boolean
  role?: 'radio' | 'checkbox'
  checked?: boolean | 'mixed'
}

function SelectionIndicator({ active, children }: { active: boolean; children?: ReactNode }) {
  return (
    <span
      data-slot="selection-indicator"
      data-active={active ? 'true' : 'false'}
      className={cn(
        'grid h-3 shrink-0 place-items-center overflow-hidden',
        active ? 'mr-1.5 w-3 opacity-100' : 'mr-0 w-0 opacity-0',
      )}
      aria-hidden="true"
    >
      {children}
    </span>
  )
}

function SelectionChip({
  active,
  children,
  onClick,
  accessibleLabel,
  disabled = false,
  role,
  checked,
}: SelectionChipProps) {
  return (
    <button
      type="button"
      role={role}
      aria-label={accessibleLabel}
      aria-checked={checked}
      aria-pressed={role === undefined ? active : undefined}
      disabled={disabled}
      onClick={onClick}
      className={selectionChipClassName(active)}
    >
      {children}
    </button>
  )
}

export function selectionChipClassName(
  active: boolean,
  focus: 'visible' | 'within' = 'visible',
  className?: string,
): string {
  return cn(
    'grantor-touch-target ui-control-feedback ui-selection-chip inline-flex h-7 items-center rounded-full border px-2.5 text-xs disabled:cursor-not-allowed disabled:opacity-50',
    focus === 'within'
      ? 'focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-accent'
      : 'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
    active
      ? 'border-accent/25 bg-accent-soft/70 text-accent-text'
      : 'border-line/70 bg-transparent text-muted hover:text-text',
    className,
  )
}

export interface SelectionSelectOption {
  value: string
  label: string
  count?: number
}

export interface SelectionSelectProps {
  label: string
  value: string
  options: readonly SelectionSelectOption[]
  inactiveValue: string
  icon?: ReactNode
  onChange: (value: string) => void
  className?: string
}

/** Select with the same geometry and states as every other selection chip. */
export function SelectionSelect({
  label,
  value,
  options,
  inactiveValue,
  icon,
  onChange,
  className,
}: SelectionSelectProps) {
  const popoverMotion = usePopoverSurfaceMotion()
  const { open } = popoverMotion
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([])
  const selected = options.find((option) => option.value === value) ?? options[0]

  const selectOption = (nextValue: string) => {
    onChange(nextValue)
    popoverMotion.setOpen(false)
  }

  const moveOptionFocus = (
    event: KeyboardEvent<HTMLButtonElement>,
    currentIndex: number,
  ) => {
    let nextIndex: number | undefined
    if (event.key === 'ArrowDown') nextIndex = (currentIndex + 1) % options.length
    if (event.key === 'ArrowUp') nextIndex = (currentIndex - 1 + options.length) % options.length
    if (event.key === 'Home') nextIndex = 0
    if (event.key === 'End') nextIndex = options.length - 1
    if (nextIndex === undefined) return
    event.preventDefault()
    optionRefs.current[nextIndex]?.focus()
  }

  return (
    <Popover.Root open={open} onOpenChange={popoverMotion.setOpen}>
      <Popover.Trigger asChild>
        <button
          type="button"
          role="combobox"
          aria-label={label}
          aria-expanded={open}
          data-active={value !== inactiveValue ? 'true' : 'false'}
          className={cn(
            'grantor-touch-target ui-control-feedback ui-facet-select inline-flex h-8 max-w-60 items-center gap-2 rounded-md border border-line/65 bg-panel2/30 px-2.5 text-xs text-muted',
            'hover:border-line-strong hover:bg-panel2/60 hover:text-text',
            'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
            'data-[active=true]:border-accent/25 data-[active=true]:bg-accent-soft/45 data-[active=true]:text-text',
            className,
          )}
        >
          {icon !== undefined && (
            <span className="shrink-0 text-faint" aria-hidden="true">{icon}</span>
          )}
          <span className="min-w-0 truncate">{selected?.label}</span>
          {selected?.count !== undefined && (
            <span className="shrink-0 tabular-nums text-faint">{selected.count}</span>
          )}
          <ChevronDown
            className={cn(
              'size-3.5 shrink-0 text-faint',
              open && 'rotate-180',
            )}
            aria-hidden="true"
          />
        </button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="start"
          sideOffset={6}
          onOpenAutoFocus={(event) => {
            event.preventDefault()
            const selectedIndex = Math.max(
              0,
              options.findIndex((option) => option.value === value),
            )
            requestAnimationFrame(() => optionRefs.current[selectedIndex]?.focus())
          }}
          className={cn(
            popoverMotion.surfaceClassName,
            'z-50 min-w-[var(--radix-popover-trigger-width)] overflow-hidden rounded-md border border-line bg-panel p-1 shadow-[var(--shadow-floating)] focus:outline-none',
          )}
        >
          <div role="listbox" aria-label={label} className="space-y-0.5">
            {options.map((option, index) => {
              const active = option.value === value
              return (
                <button
                  key={option.value}
                  ref={(node) => {
                    optionRefs.current[index] = node
                  }}
                  type="button"
                  role="option"
                  aria-label={`${option.label}${option.count === undefined ? '' : ` ${option.count}`}`}
                  aria-selected={active}
                  onClick={() => selectOption(option.value)}
                  onKeyDown={(event) => moveOptionFocus(event, index)}
                  className={cn(
                    'grantor-touch-target ui-control-feedback flex min-h-8 w-full items-center gap-2 rounded-sm px-2.5 py-1.5 text-left text-sm text-muted',
                    'hover:bg-hover hover:text-text focus-visible:bg-hover focus-visible:text-text focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-accent',
                    active && 'bg-accent-soft/55 text-text',
                  )}
                >
                  <Check
                    className={cn(
                      'size-3.5 shrink-0 text-accent',
                      active ? 'opacity-100' : 'opacity-0',
                    )}
                    aria-hidden="true"
                  />
                  <span className="min-w-0 flex-1 truncate">{option.label}</span>
                  {option.count !== undefined && (
                    <span className="shrink-0 tabular-nums text-xs text-faint">
                      {option.count}
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}

export interface SegmentedFilterProps<T extends string> {
  label: string
  /** Current value. Undefined is allowed for shortcut groups with no active target. */
  value?: T
  options: readonly SelectionOption<T>[]
  onChange: (value: T) => void
  className?: string
}

/** Mutually exclusive chips: clicking the selected value keeps it selected. */
export function SegmentedFilter<T extends string>({
  label,
  value,
  options,
  onChange,
  className,
}: SegmentedFilterProps<T>) {
  return (
    <div role="radiogroup" aria-label={label} className={cn('flex flex-wrap gap-1.5', className)}>
      {options.map((option) => {
        const active = option.value === value
        return (
          <SelectionChip
            key={option.value}
            role="radio"
            checked={active}
            active={active}
            disabled={option.disabled}
            accessibleLabel={selectionOptionAccessibleLabel(option)}
            onClick={() => {
              if (!active) onChange(option.value)
            }}
          >
            {option.label}
            {option.count !== undefined && (
              <span
                className={cn(
                  'ml-1.5 inline-grid min-w-[1.5ch] justify-items-end tabular-nums',
                  !active && 'text-faint',
                )}
                aria-label={String(option.count)}
              >
                <span aria-hidden="true">{option.count}</span>
              </span>
            )}
          </SelectionChip>
        )
      })}
    </div>
  )
}

export interface CheckboxChipGroupProps<T extends string> {
  label: string
  options: readonly SelectionOption<T>[]
  selected: ReadonlySet<T>
  onChange: (selected: ReadonlySet<T>) => void
  allLabel?: ReactNode
  minSelected?: number
  /** Набор, в который master-chip переходит при повторном клике из состояния All. */
  allSelectedFallback?: ReadonlySet<T>
  className?: string
}

/** Multi-select chips with an explicit All / mixed state and visible checks. */
export function CheckboxChipGroup<T extends string>({
  label,
  options,
  selected,
  onChange,
  allLabel = UI_COPY.all,
  minSelected = 0,
  allSelectedFallback,
  className,
}: CheckboxChipGroupProps<T>) {
  const enabled = options.filter((option) => option.disabled !== true)
  const selectedEnabled = enabled.filter((option) => selected.has(option.value)).length
  const all = enabled.length > 0 && selectedEnabled === enabled.length
  const mixed = selectedEnabled > 0 && !all

  const toggleAll = () => {
    if (!all) {
      const next = new Set(selected)
      for (const option of enabled) next.add(option.value)
      onChange(next)
      return
    }
    if (allSelectedFallback !== undefined) {
      onChange(new Set(allSelectedFallback))
      return
    }
    if (minSelected === 0) {
      const next = new Set(selected)
      for (const option of enabled) next.delete(option.value)
      onChange(next)
    }
  }

  return (
    <div role="group" aria-label={label} className={cn('flex flex-wrap gap-1.5', className)}>
      <SelectionChip
        role="checkbox"
        checked={mixed ? 'mixed' : all}
        active={all || mixed}
        onClick={toggleAll}
      >
        <SelectionIndicator active={all || mixed}>
          {mixed ? <Minus className="size-3" /> : all ? <Check className="size-3" /> : null}
        </SelectionIndicator>
        {allLabel}
      </SelectionChip>
      {options.map((option) => {
        const active = selected.has(option.value)
        const locked = active && selected.size <= minSelected
        return (
          <SelectionChip
            key={option.value}
            role="checkbox"
            checked={active}
            active={active}
            disabled={option.disabled}
            accessibleLabel={selectionOptionAccessibleLabel(option)}
            onClick={() => {
              if (locked) return
              const next = new Set(selected)
              if (active) next.delete(option.value)
              else next.add(option.value)
              onChange(next)
            }}
          >
            <SelectionIndicator active={active}>
              {active ? <Check className="size-3" /> : null}
            </SelectionIndicator>
            {option.label}
            {option.count !== undefined && (
              <span className={cn('ml-1.5 tabular-nums', !active && 'text-faint')}>
                {option.count}
              </span>
            )}
          </SelectionChip>
        )
      })}
    </div>
  )
}

function selectionOptionAccessibleLabel<T extends string>(
  option: SelectionOption<T>,
): string | undefined {
  const label = option.accessibleLabel ?? (
    typeof option.label === 'string' ? option.label : undefined
  )
  return label === undefined
    ? undefined
    : `${label}${option.count === undefined ? '' : ` ${option.count}`}`
}
