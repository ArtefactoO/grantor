// Поле поиска: иконка лупы слева, единая очистка справа. Все списки получают
// одинаковую механику сброса без route-local кнопок.
import { useEffect, useRef, useState } from 'react'
import { Search, X } from './icons'
import { cn } from './cn'
import { Input } from './input'
import { IconButton } from './icon-button'

export interface SearchInputProps {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  disabled?: boolean
  ariaLabel?: string
  density?: 'default' | 'compact'
  className?: string
  /** Задержка перед onChange; 0 — сразу. Нужна там, где значение уходит в URL. */
  debounceMs?: number
}

export function SearchInput({
  value,
  onChange,
  placeholder,
  disabled,
  ariaLabel,
  density = 'default',
  className,
  debounceMs = 0,
}: SearchInputProps) {
  const compact = density === 'compact'
  const [draft, setDraft] = useState(value)
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null)
  // Внешнее изменение (сброс фильтров, переход по ссылке) должно быть видно
  // в поле, но не должно перебивать то, что человек печатает прямо сейчас.
  useEffect(() => {
    if (timer.current === null) setDraft(value)
  }, [value])
  useEffect(() => () => {
    if (timer.current !== null) clearTimeout(timer.current)
  }, [])

  const emit = (next: string) => {
    setDraft(next)
    if (debounceMs <= 0) {
      onChange(next)
      return
    }
    if (timer.current !== null) clearTimeout(timer.current)
    timer.current = setTimeout(() => {
      timer.current = null
      onChange(next)
    }, debounceMs)
  }
  const shown = debounceMs > 0 ? draft : value

  return (
    <div className={cn('relative', className)}>
      <Search
        className={cn(
          'pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-faint',
          compact ? 'size-3.5' : 'size-4',
        )}
      />
      <Input
        value={shown}
        onChange={(e) => emit(e.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        className={cn(
          'grantor-touch-target',
          compact && 'h-8 bg-panel2/35 text-xs',
          shown === '' ? 'pl-8' : 'pl-8 pr-14 sm:pr-9 [@media(pointer:coarse)]:pr-14',
        )}
        aria-label={ariaLabel}
      />
      {shown !== '' && (
        <span className="absolute right-1 top-1/2 inline-flex -translate-y-1/2">
          <IconButton
            compact
            onClick={() => { setDraft(''); onChange('') }}
            disabled={disabled}
            label="Очистить поиск"
            icon={<X className="size-3.5" aria-hidden="true" />}
          />
        </span>
      )}
    </div>
  )
}
