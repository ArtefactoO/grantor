// Searchable multi-select with the same popover geometry as Combobox.
// The popover remains open while options are toggled so several roles can be
// selected without reopening the control for every assignment.
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import * as Popover from '@radix-ui/react-popover'
import { Command } from 'cmdk'
import { Check, ChevronsUpDown, Minus, Search } from './icons'
import { cn } from './cn'
import { Button } from './button'
import { usePopoverSurfaceMotion } from './popover-motion'

export interface MultiComboboxOption {
  value: string
  label: string
  keywords?: string[]
  disabled?: boolean
  icon?: ReactNode
  description?: ReactNode
}

export interface MultiComboboxProps {
  selected: ReadonlySet<string>
  options: readonly MultiComboboxOption[]
  onChange: (selected: ReadonlySet<string>) => void
  label: string
  placeholder?: string
  searchPlaceholder?: string
  emptyText?: string
  allLabel?: string
  disabled?: boolean
  className?: string
}

export function MultiCombobox({
  selected,
  options,
  onChange,
  label,
  placeholder = 'Выберите значения…',
  searchPlaceholder = 'Поиск…',
  emptyText = 'Ничего не найдено',
  allLabel = 'All',
  disabled = false,
  className,
}: MultiComboboxProps) {
  const popoverMotion = usePopoverSurfaceMotion()
  const { open } = popoverMotion
  const [query, setQuery] = useState('')
  const enabled = useMemo(
    () => options.filter((option) => option.disabled !== true),
    [options],
  )
  const selectedEnabled = enabled.filter((option) => selected.has(option.value))
  const all = enabled.length > 0 && selectedEnabled.length === enabled.length
  const mixed = selectedEnabled.length > 0 && !all

  const summary = all
    ? allLabel
    : selectedEnabled.length === 0
      ? placeholder
      : selectedEnabled.length === 1
        ? selectedEnabled[0]?.label
        : `${selectedEnabled[0]?.label} +${selectedEnabled.length - 1}`

  const setPopoverOpen = (nextOpen: boolean) => {
    popoverMotion.setOpen(nextOpen)
    if (!nextOpen) setQuery('')
  }

  const toggleAll = () => {
    const next = new Set(selected)
    for (const option of enabled) {
      if (all) next.delete(option.value)
      else next.add(option.value)
    }
    onChange(next)
  }

  const toggleOption = (option: MultiComboboxOption) => {
    const next = new Set(selected)
    if (next.has(option.value)) next.delete(option.value)
    else next.add(option.value)
    onChange(next)
  }

  return (
    <Popover.Root open={open} onOpenChange={setPopoverOpen}>
      <Popover.Trigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-label={label}
          aria-expanded={open}
          disabled={disabled}
          className={cn('w-full justify-between font-normal', className)}
        >
          <span className={cn('min-w-0 flex-1 truncate text-left', selectedEnabled.length === 0 && 'text-faint')}>
            {summary}
          </span>
          {selectedEnabled.length > 1 && !all && (
            <span className="shrink-0 rounded-full bg-accent-soft px-1.5 text-[10px] tabular-nums text-accent">
              {selectedEnabled.length}
            </span>
          )}
          <ChevronsUpDown aria-hidden="true" className="size-3.5 shrink-0 text-faint" />
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          data-slot="multi-combobox-content"
          align="start"
          sideOffset={4}
          className={cn(
            popoverMotion.surfaceClassName,
            'z-50 w-[var(--radix-popover-trigger-width)] min-w-56 overflow-hidden rounded-md border border-line bg-panel shadow-[var(--shadow-floating)] focus:outline-none',
          )}
        >
          <Command label={label} className="flex max-h-80 min-h-0 flex-col bg-panel text-text">
            <div className="flex h-9 shrink-0 items-center gap-2 border-b border-line px-3">
              <Search aria-hidden="true" className="size-3.5 shrink-0 text-faint" />
              <Command.Input
                value={query}
                onValueChange={setQuery}
                aria-label={`Поиск: ${label}`}
                placeholder={searchPlaceholder}
                className="h-full min-w-0 flex-1 bg-transparent text-sm text-text outline-none placeholder:text-faint"
              />
            </div>
            <Command.List label={label} className="min-h-0 overflow-y-auto p-1">
              <Command.Empty className="px-3 py-6 text-center text-sm text-muted">
                {emptyText}
              </Command.Empty>
              <Command.Item
                value="__all__"
                onSelect={toggleAll}
                className="flex min-h-8 cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-text outline-none data-[selected=true]:bg-accent-soft"
              >
                <span role="checkbox" aria-checked={mixed ? 'mixed' : all} className="contents">
                  <span className="grid size-4 shrink-0 place-items-center rounded border border-line text-accent">
                    {mixed ? <Minus className="size-3" /> : all ? <Check className="size-3" /> : null}
                  </span>
                  <span className="min-w-0 flex-1 truncate">{allLabel}</span>
                </span>
              </Command.Item>
              {options.map((option) => {
                const active = selected.has(option.value)
                return (
                  <Command.Item
                    key={option.value}
                    value={option.value}
                    keywords={[option.label, ...(option.keywords ?? [])]}
                    disabled={option.disabled}
                    onSelect={() => toggleOption(option)}
                    className="flex min-h-8 cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-text outline-none data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50 data-[selected=true]:bg-accent-soft"
                  >
                    <span role="checkbox" aria-checked={active} className="contents">
                      <span className={cn(
                        'grid size-4 shrink-0 place-items-center rounded border text-accent',
                        active ? 'border-accent/50 bg-accent-soft' : 'border-line',
                      )}>
                        {active && <Check className="size-3" />}
                      </span>
                      {option.icon !== undefined && (
                        <span aria-hidden="true" className="shrink-0">{option.icon}</span>
                      )}
                      <span className="min-w-0 flex-1">
                        <span className="block break-anywhere">{option.label}</span>
                        {option.description !== undefined && (
                          <span className="block text-xs text-faint">{option.description}</span>
                        )}
                      </span>
                    </span>
                  </Command.Item>
                )
              })}
            </Command.List>
          </Command>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
