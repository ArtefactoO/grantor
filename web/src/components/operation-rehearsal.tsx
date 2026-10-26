import type { ReactNode } from 'react'
import { Eye, ShieldCheck } from '@project/ui/icons'
import { cn } from '@project/ui'

export interface OperationRehearsalProps {
  title: string
  detail: ReactNode
  impact?: ReactNode
  danger?: boolean
  className?: string
}

/**
 * Shared read-only preview for a mutating operation. It deliberately does not
 * own confirmation or a request: every surface gets the same future-state
 * semantics while its existing mutation remains the single source of truth.
 */
export function OperationRehearsal({
  title,
  detail,
  impact,
  danger = false,
  className,
}: OperationRehearsalProps) {
  return (
    <section
      className={cn(
        'space-y-3 rounded-md border px-3 py-2.5',
        danger ? 'border-danger/35 bg-danger-soft/55' : 'border-line/70 bg-panel2/45',
        className,
      )}
      aria-label="Репетиция изменения"
    >
      <div className="flex min-w-0 items-start gap-2.5">
        <span
          className={cn(
            'mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full',
            danger ? 'bg-danger/15 text-danger' : 'bg-accent-soft text-accent',
          )}
          aria-hidden="true"
        >
          <Eye className="size-3.5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="text-sm font-medium text-text">{title}</div>
          <div className="mt-0.5 text-xs leading-5 text-muted">{detail}</div>
        </div>
      </div>
      {impact !== undefined && (
        <div className="border-t border-line/50 pt-2.5">
          <div className="mb-1.5 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider text-faint">
            <ShieldCheck className="size-3.5" aria-hidden="true" />
            Затронуто
          </div>
          {impact}
        </div>
      )}
    </section>
  )
}
