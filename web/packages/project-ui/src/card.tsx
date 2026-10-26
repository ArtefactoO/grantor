// Shared panels and stat tiles keep geometry stable while values update.
import type { ReactNode } from 'react'
import { ArrowRight } from './icons'
import { cn } from './cn'

export interface CardProps {
  children: ReactNode
  className?: string
}

/** Базовая панель. */
export function Card({ children, className }: CardProps) {
  return (
    <div
      className={cn(
        'rounded-[14px] border border-line bg-panel',
        className,
      )}
    >
      {children}
    </div>
  )
}

export interface PageSurfaceHeaderProps {
  title: ReactNode
  icon: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
}

/**
 * Shared header for full-page product surfaces. The larger shell owns the
 * 14px radius; controls and marks keep the compact 8px interaction radius.
 */
export function PageSurfaceHeader({
  title,
  icon,
  description,
  actions,
  className,
}: PageSurfaceHeaderProps) {
  return (
    <header
      className={cn(
        'flex min-h-14 flex-wrap items-center justify-between gap-3 border-b border-line bg-panel2/45 px-4 py-3',
        className,
      )}
    >
      <div className="flex min-w-0 items-center gap-2.5">
        <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-accent text-accent-ink shadow-[var(--highlight-inset)]">
          {icon}
        </span>
        <span className="min-w-0">
          <h1 className="text-sm font-semibold text-text">{title}</h1>
          {description !== undefined && (
            <p className="mt-0.5 text-xs text-muted">{description}</p>
          )}
        </span>
      </div>
      {actions !== undefined && (
        <div className="flex min-w-0 flex-wrap items-center justify-end gap-2">
          {actions}
        </div>
      )}
    </header>
  )
}

export type StatTone = 'default' | 'ok' | 'warn' | 'danger' | 'accent'

const STAT_TONE_CLASSES: Record<StatTone, string> = {
  default: 'text-text',
  ok: 'text-ok',
  warn: 'text-warn',
  danger: 'text-danger',
  accent: 'text-accent-text',
}

export interface StatTileProps {
  label: string
  value: number | null
  /** Тон применяется только когда значение > 0 (нулевые метрики нейтральны). */
  tone?: StatTone
  hint?: string
  note?: ReactNode
  interactive?: boolean
}

/** Stat tile with a stable, immediately updated value. */
export function StatTile({
  label,
  value,
  tone = 'default',
  hint,
  note,
  interactive = false,
}: StatTileProps) {
  const applied = value !== null && value > 0 ? tone : 'default'
  return (
    <div
      className={cn(
        'relative h-full rounded-lg border border-line bg-panel px-4 py-3',
        interactive && 'ui-control-feedback hover:border-line-strong hover:bg-hover',
      )}
      title={hint}
    >
      <div className="pr-6 text-xs text-muted">{label}</div>
      <div
        className={cn(
          'mt-1 text-2xl font-semibold tabular-nums',
          STAT_TONE_CLASSES[applied],
        )}
      >
        {value === null
          ? <span className="text-sm font-normal text-muted" aria-label="Нет актуальных данных">Нет данных</span>
          : value.toLocaleString('ru-RU')}
      </div>
      {note !== undefined && <div className="mt-1 pr-6 text-[11px] text-muted">{note}</div>}
      {interactive && (
        <ArrowRight
          className="absolute right-3 top-1/2 size-4 -translate-y-1/2 text-faint"
          aria-hidden="true"
        />
      )}
    </div>
  )
}
