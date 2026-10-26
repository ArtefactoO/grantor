import { useEffect, useId, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { cn } from './cn'

export type TooltipSide = 'top' | 'right' | 'bottom' | 'left'

export interface TooltipProps {
  content: ReactNode
  children: ReactNode
  side?: TooltipSide
  delay?: number
  disabled?: boolean
  className?: string
  /** Makes a disabled control's wrapper keyboard reachable for its explanation. */
  disabledTarget?: boolean
  /** Accessible name for a focusable wrapper when the visible child is only a hint target. */
  targetLabel?: string
}

interface Position {
  left: number
  top: number
  transform: string
}

function tooltipPosition(rect: DOMRect, side: TooltipSide): Position {
  switch (side) {
    case 'right':
      return { left: rect.right + 8, top: rect.top + rect.height / 2, transform: 'translateY(-50%)' }
    case 'bottom':
      return { left: rect.left + rect.width / 2, top: rect.bottom + 8, transform: 'translateX(-50%)' }
    case 'left':
      return { left: rect.left - 8, top: rect.top + rect.height / 2, transform: 'translate(-100%, -50%)' }
    default:
      return { left: rect.left + rect.width / 2, top: rect.top - 8, transform: 'translate(-50%, -100%)' }
  }
}

/** Lightweight non-interactive tooltip for icon actions and short hints. */
export function Tooltip({
  content,
  children,
  side = 'top',
  delay = 350,
  disabled = false,
  className,
  disabledTarget = false,
  targetLabel,
}: TooltipProps) {
  const id = useId()
  const anchorRef = useRef<HTMLSpanElement>(null)
  const timerRef = useRef<number | null>(null)
  const [position, setPosition] = useState<Position | null>(null)

  const clearTimer = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current)
      timerRef.current = null
    }
  }
  const close = () => {
    clearTimer()
    setPosition(null)
  }
  const open = (wait: number) => {
    if (disabled) return
    clearTimer()
    const show = () => {
      const rect = anchorRef.current?.getBoundingClientRect()
      if (rect !== undefined) setPosition(tooltipPosition(rect, side))
    }
    if (wait === 0) show()
    else timerRef.current = window.setTimeout(show, wait)
  }

  useEffect(() => {
    if (position === null) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close()
    }
    const onViewportChange = () => close()
    window.addEventListener('keydown', onKeyDown)
    window.addEventListener('scroll', onViewportChange, true)
    window.addEventListener('resize', onViewportChange)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      window.removeEventListener('scroll', onViewportChange, true)
      window.removeEventListener('resize', onViewportChange)
    }
  }, [position])

  useEffect(() => () => clearTimer(), [])

  return (
    <>
      <span
        ref={anchorRef}
        className="inline-flex"
        tabIndex={disabledTarget ? 0 : undefined}
        aria-label={targetLabel}
        aria-describedby={position !== null ? id : undefined}
        onPointerEnter={() => open(delay)}
        onPointerLeave={close}
        onFocusCapture={() => open(0)}
        onBlurCapture={close}
      >
        {children}
      </span>
      {position !== null &&
        createPortal(
          <span
            id={id}
            role="tooltip"
            style={position}
            className={cn(
              'ui-tooltip fixed z-[80] max-w-64 rounded-md border border-line bg-panel px-2 py-1 text-xs leading-4 text-text',
              className,
            )}
          >
            {content}
          </span>,
          document.body,
        )}
    </>
  )
}
