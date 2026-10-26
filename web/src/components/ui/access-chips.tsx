// «Умные чипы» доступа: нейтральный чип с нормализованной подписью
// (lib/access-entries поверх нормализации адаптера), dangerous — маленькая
// красная точка внутри чипа, а
// не красный чип. AccessChipList держит одну строку фиксированной высоты
// (2–3 чипа + кнопка «+N»), полный сгруппированный список — в поповере.
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import type { AccessEntry } from '../../lib/access-entries'
import { cn, metadataChipClassName, CopyButton } from '@project/ui'

export interface ElevatedAccessDotProps {
  className?: string
}

/** Quiet marker for a role that grants broad or sensitive permissions. */
export function ElevatedAccessDot({ className }: ElevatedAccessDotProps) {
  return (
    <span
      className={cn('size-1.5 shrink-0 rounded-full bg-danger', className)}
      aria-label="Широкие полномочия"
      title="Роль предоставляет широкие полномочия"
    />
  )
}

export interface AccessChipProps {
  entry: AccessEntry
  className?: string
  wrapLabel?: boolean
}

/** Чип одного права: нейтральная подложка, точка dangerous, title=full. */
export function AccessChip({ entry, className, wrapLabel = false }: AccessChipProps) {
  return (
    <span
      title={entry.full}
      className={cn(
        'group/access',
        metadataChipClassName(),
        wrapLabel && 'h-auto max-w-full py-0.5',
        className,
      )}
    >
      {entry.dangerous && <ElevatedAccessDot />}
      <span className={cn(wrapLabel ? '[overflow-wrap:anywhere]' : 'truncate')}>
        {entry.label}
      </span>
      {/* Копируется полное выражение права, а не усечённая подпись — по тому
          же паттерну, что PermissionChip: кнопка проявляется на hover, чтобы
          не перегружать плотную строку доступов. */}
      <CopyButton
        value={entry.full}
        compact
        label={`Копировать право ${entry.label}`}
        className="opacity-0 transition-opacity group-hover/access:opacity-100 group-focus-within/access:opacity-100"
      />
    </span>
  )
}

export interface AccessChipListProps {
  entries: AccessEntry[]
  /** Сколько чипов видно в строке; остальные — в поповере «+N». */
  maxVisible?: number
  className?: string
  /** Allow long role names and the visible chip row to wrap inside its column. */
  wrapLabels?: boolean
}

// Ширина панели поповера (w-80) — нужна для прижатия к правому краю окна.
const POPOVER_WIDTH = 320

/**
 * Одна фиксированная строка чипов + «+N». Кнопка «+N» открывает поповер с
 * полным списком, сгруппированным по AccessEntry.group. Поповер рендерится
 * через портал с fixed-позицией от кнопки: таблицы обёрнуты в
 * overflow-x-auto (TableContainer), absolute-панель там была бы обрезана.
 * Закрытие — клик вне, Escape или скролл; клики не всплывают к строке.
 */
export function AccessChipList({
  entries,
  maxVisible = 3,
  className,
  wrapLabels = false,
}: AccessChipListProps) {
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null)
  const buttonRef = useRef<HTMLButtonElement | null>(null)
  const panelRef = useRef<HTMLDivElement | null>(null)
  const open = position !== null

  useEffect(() => {
    if (!open) {
      return
    }
    const onMouseDown = (event: MouseEvent) => {
      if (!(event.target instanceof Node)) {
        return
      }
      const insideButton = buttonRef.current?.contains(event.target) === true
      const insidePanel = panelRef.current?.contains(event.target) === true
      if (!insideButton && !insidePanel) {
        setPosition(null)
      }
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setPosition(null)
      }
    }
    // Прокрутка любого контейнера смещает якорь — проще закрыть поповер.
    const onScroll = (event: Event) => {
      if (event.target instanceof Node && panelRef.current?.contains(event.target) === true) {
        return
      }
      setPosition(null)
    }
    window.addEventListener('mousedown', onMouseDown)
    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('scroll', onScroll, true)
    return () => {
      window.removeEventListener('mousedown', onMouseDown)
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('scroll', onScroll, true)
    }
  }, [open])

  const toggle = () => {
    if (open) {
      setPosition(null)
      return
    }
    const rect = buttonRef.current?.getBoundingClientRect()
    if (rect === undefined) {
      return
    }
    setPosition({
      top: rect.bottom + 4,
      left: Math.max(8, Math.min(rect.left, window.innerWidth - POPOVER_WIDTH - 8)),
    })
  }

  const shown = entries.slice(0, maxVisible)
  const hidden = entries.length - shown.length

  // Группировка с сохранением порядка появления групп и записей.
  const groups: Array<{ name: string; items: AccessEntry[] }> = []
  for (const entry of entries) {
    const existing = groups.find((g) => g.name === entry.group)
    if (existing === undefined) {
      groups.push({ name: entry.group, items: [entry] })
    } else {
      existing.items.push(entry)
    }
  }

  return (
    <div
      className={cn(
        'flex h-[22px] min-w-0 items-center gap-1',
        wrapLabels && 'h-auto min-h-[22px] flex-wrap',
        className,
      )}
    >
      {shown.map((entry) => (
        <AccessChip
          key={`${entry.group}:${entry.full}`}
          entry={entry}
          wrapLabel={wrapLabels}
        />
      ))}
      {hidden > 0 && (
        <button
          ref={buttonRef}
          type="button"
          aria-expanded={open}
          aria-haspopup="true"
          aria-label={`Показать все права (${entries.length})`}
          onClick={(event) => {
            // Строки таблиц кликабельны — «+N» не должен выбирать строку.
            event.stopPropagation()
            toggle()
          }}
          className={cn(
            'inline-flex h-[22px] shrink-0 items-center rounded border px-1.5 text-[11px] transition-colors',
            open
              ? 'border-accent/40 bg-accent-soft text-accent'
              : 'border-line bg-panel2 text-faint hover:text-text',
          )}
        >
          +{hidden}
        </button>
      )}
      {position !== null &&
        createPortal(
          <div
            ref={panelRef}
            role="dialog"
            aria-label="Все права"
            onClick={(event) => event.stopPropagation()}
            style={{ top: position.top, left: position.left, width: POPOVER_WIDTH }}
            className="fixed z-50 max-h-64 overflow-y-auto rounded-md border border-line bg-panel p-2 shadow-[var(--shadow-floating)]"
          >
            <div className="space-y-2">
              {groups.map((group) => (
                <div key={group.name}>
                  <div className="px-1 pb-1 text-[10px] font-semibold uppercase tracking-wider text-faint">
                    {group.name}
                  </div>
                  <div className="space-y-0.5">
                    {group.items.map((entry) => (
                      <div
                        key={entry.full}
                        className="flex items-start gap-1.5 rounded px-1 py-0.5 font-mono text-[12px] text-text"
                      >
                        {entry.dangerous && <ElevatedAccessDot className="mt-1.5" />}
                        <span className="min-w-0 break-all">{entry.full}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>,
          document.body,
        )}
    </div>
  )
}
