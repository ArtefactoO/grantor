// Контролируемый searchable combobox для компактных селекторов control plane.
// Popover отвечает за portal/focus restore, cmdk - за фильтрацию и клавиатуру.
import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import * as Popover from '@radix-ui/react-popover'
import { Command } from 'cmdk'
import { Check, ChevronsUpDown, Search } from './icons'
import { cn } from './cn'
import { Button } from './button'
import { usePopoverSurfaceMotion } from './popover-motion'

export interface ComboboxOption {
  value: string
  label: string
  description?: string
  keywords?: string[]
  disabled?: boolean
  icon?: ReactNode
  meta?: ReactNode
  /** Компактное представление выбранного option внутри trigger. */
  trigger?: ReactNode
}

export interface ComboboxProps {
  value?: string
  options: ComboboxOption[]
  onValueChange: (value: string) => void
  label: string
  searchLabel?: string
  placeholder?: string
  searchPlaceholder?: string
  emptyText?: string
  disabled?: boolean
  className?: string
  contentClassName?: string
}

// Сентинел для option со значением '': cmdk выводит пустой value из текста
// пункта, и onSelect вернул бы текст вместо ''. Наружу сентинел не выходит.
const EMPTY_OPTION_VALUE = '__combobox-empty__'
const encodeValue = (value: string) => (value === '' ? EMPTY_OPTION_VALUE : value)
const decodeValue = (value: string) => (value === EMPTY_OPTION_VALUE ? '' : value)

export function Combobox({
  value,
  options,
  onValueChange,
  label,
  searchLabel = `Поиск: ${label}`,
  placeholder = 'Выберите значение…',
  searchPlaceholder = 'Поиск…',
  emptyText = 'Ничего не найдено',
  disabled = false,
  className,
  contentClassName,
}: ComboboxProps) {
  const popoverMotion = usePopoverSurfaceMotion()
  const { open } = popoverMotion
  const [query, setQuery] = useState('')
  const selected = useMemo(
    () => options.find((option) => option.value === value),
    [options, value],
  )

  const setPopoverOpen = (nextOpen: boolean) => {
    popoverMotion.setOpen(nextOpen)
    if (!nextOpen) {
      setQuery('')
    }
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
          <span className={cn('min-w-0 flex-1 truncate text-left', selected === undefined && 'text-faint')}>
            {selected?.trigger ?? selected?.label ?? placeholder}
          </span>
          <ChevronsUpDown aria-hidden="true" className="size-3.5 shrink-0 text-faint" />
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          data-slot="combobox-content"
          align="start"
          sideOffset={4}
          className={cn(
            popoverMotion.surfaceClassName,
            'z-50 w-[var(--radix-popover-trigger-width)] min-w-56 overflow-hidden rounded-md border border-line bg-panel shadow-[var(--shadow-floating)] focus:outline-none',
            contentClassName,
          )}
        >
          <Command
            label={searchLabel}
            className="flex max-h-80 min-h-0 flex-col bg-panel text-text"
          >
            <div className="flex h-9 shrink-0 items-center gap-2 border-b border-line px-3">
              <Search aria-hidden="true" className="size-3.5 shrink-0 text-faint" />
              <Command.Input
                value={query}
                onValueChange={setQuery}
                aria-label={searchLabel}
                placeholder={searchPlaceholder}
                className="h-full min-w-0 flex-1 bg-transparent text-sm text-text outline-none placeholder:text-faint"
              />
            </div>
            <Command.List
              label={label}
              className="min-h-0 overflow-y-auto p-1"
            >
              <Command.Empty className="px-3 py-6 text-center text-sm text-muted">
                {emptyText}
              </Command.Empty>
              {options.map((option) => (
                <Command.Item
                  key={option.value}
                  value={encodeValue(option.value)}
                  keywords={[option.label, option.description ?? '', ...(option.keywords ?? [])]}
                  disabled={option.disabled}
                  onSelect={(nextValue) => {
                    onValueChange(decodeValue(nextValue))
                    setPopoverOpen(false)
                  }}
                  className="flex min-h-8 cursor-default select-none items-center gap-2 rounded-sm px-2 py-1.5 text-sm text-text outline-none data-[disabled=true]:pointer-events-none data-[disabled=true]:opacity-50 data-[selected=true]:bg-accent-soft data-[selected=true]:text-text"
                >
                  {option.icon !== undefined && (
                    <span aria-hidden="true" className="shrink-0 text-muted">
                      {option.icon}
                    </span>
                  )}
                  <span className="min-w-0 flex-1">
                    <span className="block truncate">{option.label}</span>
                    {option.description !== undefined && (
                      <span className="block truncate text-xs text-muted">
                        {option.description}
                      </span>
                    )}
                  </span>
                  {option.meta !== undefined && (
                    <span className="shrink-0">{option.meta}</span>
                  )}
                  <Check
                    aria-hidden="true"
                    className={cn(
                      'size-3.5 shrink-0 text-accent',
                      option.value === value ? 'opacity-100' : 'opacity-0',
                    )}
                  />
                </Command.Item>
              ))}
            </Command.List>
          </Command>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  )
}
