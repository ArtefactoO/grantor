import { forwardRef } from 'react'
import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'
import { Tooltip } from './tooltip'

export type IconButtonTone = 'ghost' | 'outline' | 'danger'

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  label: string
  icon: ReactNode
  /** Дополнительная диагностика после канонического имени действия. */
  tooltipDetails?: string
  tone?: IconButtonTone
  busy?: boolean
  success?: boolean
  /** 24px action for dense inline/table contexts. */
  compact?: boolean
}

const TONES: Record<IconButtonTone, string> = {
  ghost: 'border-transparent text-muted hover:bg-panel2 hover:text-text',
  outline: 'border-line bg-transparent text-text hover:bg-panel2',
  danger: 'border-danger/40 bg-danger-soft text-danger hover:bg-danger/25',
}

/** Standard 32px icon-only action with tooltip and tactile feedback. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  {
    label,
    icon,
    tooltipDetails,
    tone = 'ghost',
    busy = false,
    success = false,
    compact = false,
    disabled,
    className,
    type,
    ...rest
  },
  ref,
) {
  const isDisabled = disabled === true || busy
  return (
    <Tooltip
      content={tooltipDetails === undefined ? label : `${label}: ${tooltipDetails}`}
      disabledTarget={isDisabled}
    >
      <button
        ref={ref}
        type={type ?? 'button'}
        aria-label={label}
        aria-busy={busy || undefined}
        disabled={isDisabled}
        data-success={success || undefined}
        className={cn(
          'grantor-touch-target ui-control-feedback ui-icon-button relative inline-grid shrink-0 place-items-center overflow-hidden border focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-not-allowed disabled:opacity-55',
          compact ? 'size-6 rounded' : 'size-8 rounded-md',
          TONES[tone],
          success && 'border-accent bg-accent text-accent-ink',
          className,
        )}
        {...rest}
      >
        {icon}
      </button>
    </Tooltip>
  )
})
