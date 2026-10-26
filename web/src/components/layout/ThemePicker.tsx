// Product palette picker. Each palette owns a complete Dark/Light token pair;
// the mode switch remains separate and applies to the whole application.
import { useEffect, useId, useRef, useState } from 'react'
import type { KeyboardEvent } from 'react'
import { Check, Monitor, Moon, Sun, Palette as PaletteIcon } from '@project/ui/icons'
import { cn, selectionSurfaceClassName, IconButton } from '@project/ui'
import { applyPalette, applyTheme, currentPalette, currentTheme, currentThemePreference, PALETTES } from '../../lib/themes'
import type { Palette, ThemePreference } from '../../lib/themes'

const PALETTE_LABELS = { signal: 'Mono', cobalt: 'Cobalt', orange: 'Orange' }
const OPTION_COUNT = PALETTES.length + 1

export function ThemePicker() {
  const [open, setOpen] = useState(false)
  const [palette, setPalette] = useState(() => currentPalette())
  const [preference, setPreference] = useState<ThemePreference>(currentThemePreference)
  const [theme, setTheme] = useState(currentTheme)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const modeRef = useRef<HTMLButtonElement>(null)
  const optionRefs = useRef<Array<HTMLButtonElement | null>>([])
  const initialIndex = useRef(0)
  const menuId = useId()

  useEffect(() => {
    const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: light)') : null
    const update = () => {
      applyTheme(preference)
      setTheme(currentTheme())
    }
    update()
    if (preference !== 'system' || media === null) return
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [preference])

  useEffect(() => {
    if (open) optionRefs.current[initialIndex.current]?.focus()
  }, [open])

  const close = () => {
    setOpen(false)
    triggerRef.current?.focus()
  }
  const show = (index = 0) => {
    initialIndex.current = index
    setOpen(true)
    if (open) optionRefs.current[index]?.focus()
  }
  const pick = (id: Palette['id']) => {
    applyPalette(id)
    setPalette(id)
    close()
  }
  const handleMenuKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const current = optionRefs.current.findIndex((item) => item === document.activeElement)
    let next: number | undefined
    if (event.key === 'ArrowDown') next = (current + 1) % OPTION_COUNT
    if (event.key === 'ArrowUp') next = (current - 1 + OPTION_COUNT) % OPTION_COUNT
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = OPTION_COUNT - 1
    if (next !== undefined) {
      event.preventDefault()
      optionRefs.current[next]?.focus()
    } else if (event.key === 'Escape') {
      event.preventDefault()
      event.stopPropagation()
      close()
    } else if (event.key === 'Tab') {
      event.preventDefault()
      setOpen(false)
      if (event.shiftKey) triggerRef.current?.focus()
      else modeRef.current?.focus()
    }
  }

  return (
    <div className="relative flex items-center gap-0.5">
      <IconButton
        ref={triggerRef}
        label="Выбрать цветовую систему"
        icon={<PaletteIcon className="size-4" aria-hidden="true" />}
        onClick={() => open ? close() : show()}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault()
            show(event.key === 'ArrowUp' ? OPTION_COUNT - 1 : 0)
          }
        }}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
      />

      <IconButton
        ref={modeRef}
        label={theme === 'dark' ? 'Включить светлую тему' : 'Включить тёмную тему'}
        icon={theme === 'dark' ? <Sun className="size-4" aria-hidden="true" /> : <Moon className="size-4" aria-hidden="true" />}
        onClick={() => setPreference(theme === 'dark' ? 'light' : 'dark')}
      />

      {open && (
        <>
          {/* Бэкдроп ловит клик мимо, закрывает меню. */}
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            className="fixed inset-0 z-40 cursor-default"
            onClick={close}
          />
          <div
            id={menuId}
            role="menu"
            aria-label="Цветовая система"
            onKeyDown={handleMenuKey}
            onBlur={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false)
            }}
            className="absolute right-0 top-full z-50 mt-1 w-44 rounded-md border border-line bg-panel2 p-1"
          >
            {PALETTES.map((p, index) => {
              const active = p.id === palette
              return (
                <button
                  key={p.id}
                  ref={(element) => { optionRefs.current[index] = element }}
                  type="button"
                  role="menuitemradio"
                  tabIndex={-1}
                  aria-checked={active}
                  onClick={() => pick(p.id)}
                  className={cn(
                    'ui-control-feedback flex min-h-11 w-full items-center gap-3 rounded px-2.5 py-1.5 text-sm focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent',
                    selectionSurfaceClassName(active, 'text-text'),
                  )}
                >
                  <span
                    className="size-3.5 shrink-0 rounded-full border border-line"
                    style={{ backgroundColor: p.swatch }}
                  />
                  <span className="flex-1 text-left">{PALETTE_LABELS[p.id]}</span>
                  {active && <Check className="size-3.5 shrink-0" aria-hidden="true" />}
                </button>
              )
            })}
            <div role="separator" className="my-1 border-t border-line" />
            <button
              ref={(element) => { optionRefs.current[PALETTES.length] = element }}
              type="button"
              role="menuitemcheckbox"
              tabIndex={-1}
              aria-checked={preference === 'system'}
              onClick={() => {
                setPreference(preference === 'system' ? theme : 'system')
                close()
              }}
              className={cn(
                'ui-control-feedback flex min-h-11 w-full items-center gap-3 rounded px-2.5 py-1.5 text-sm focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent',
                selectionSurfaceClassName(preference === 'system', 'text-text'),
              )}
            >
              <Monitor className="size-3.5 shrink-0" aria-hidden="true" />
              <span className="flex-1 text-left">System</span>
              {preference === 'system' && <Check className="size-3.5 shrink-0" aria-hidden="true" />}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
