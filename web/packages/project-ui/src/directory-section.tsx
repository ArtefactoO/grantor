import { cn } from './cn'
import { Tooltip } from './tooltip'

export interface DirectorySectionHeaderProps {
  label: string
  count?: number
  tone?: 'neutral' | 'managed'
  /** Компактный маркер семантической зоны; обычным группам не нужен. */
  marker?: boolean
  hint?: string
  className?: string
}

/** Shared visual separator for grouped directories (environments, ownership). */
export function DirectorySectionHeader({
  label,
  count,
  tone = 'neutral',
  marker = false,
  hint,
  className,
}: DirectorySectionHeaderProps) {
  const content = (
    <span className="inline-flex items-center gap-2">
      {marker && (
        <span
          className={cn(
            'size-1.5 shrink-0 rounded-full',
            tone === 'managed' ? 'bg-ok/75' : 'bg-faint/70',
          )}
          aria-hidden="true"
        />
      )}
      <span
        className="text-[11px] font-semibold uppercase tracking-wider text-muted"
      >
        {label}
      </span>
      {count !== undefined && (
        <span className="text-[11px] tabular-nums text-faint">{count}</span>
      )}
    </span>
  )

  return (
    <div className={cn('flex h-8 items-center bg-panel2/25 px-3', className)}>
      {hint !== undefined ? (
        <Tooltip
          content={hint}
          disabledTarget
          targetLabel={`Подробнее о секции ${label}`}
        >
          {content}
        </Tooltip>
      ) : (
        content
      )}
    </div>
  )
}
