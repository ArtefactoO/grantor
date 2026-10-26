import { useId, useState } from 'react'
import type { ReactNode } from 'react'
import { motion, useReducedMotion } from 'motion/react'
import { ChevronDown } from './icons'
import { cn } from './cn'
import { motionTransition, MOTION_VARIANTS } from './motion'

export interface DetailDisclosureProps {
  label: string
  icon: ReactNode
  summary: ReactNode
  children: ReactNode
  disabled?: boolean
  defaultExpanded?: boolean
  className?: string
  contentClassName?: string
}

/**
 * Единый компактный disclosure для технических деталей в инспекторах.
 * Сохраняет одинаковые геометрию, focus-state и motion у lens, attributes
 * и следующих on-demand блоков.
 */
export function DetailDisclosure({
  label,
  icon,
  summary,
  children,
  disabled = false,
  defaultExpanded = false,
  className,
  contentClassName,
}: DetailDisclosureProps) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const contentId = useId()
  const reducedMotion = useReducedMotion()

  return (
    <section aria-label={label} className={className}>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={contentId}
        onClick={() => setExpanded((value) => !value)}
        disabled={disabled}
        className={cn(
          'ui-control-feedback group flex w-full items-center gap-2 rounded-md border border-line bg-panel2/35 px-2.5 py-2 text-left hover:border-line-strong hover:bg-panel2/65 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-60',
          expanded && 'border-accent/35 bg-accent-soft/35',
        )}
      >
        <span className="grid size-4 shrink-0 place-items-center text-muted" aria-hidden="true">
          {icon}
        </span>
        <span className="min-w-0 flex-1">{summary}</span>
        <ChevronDown
          className={cn(
            'size-4 shrink-0 text-faint',
            expanded && 'rotate-180',
          )}
          aria-hidden="true"
        />
      </button>

      {expanded && !disabled && (
        <motion.div
          id={contentId}
          key="details"
          initial={reducedMotion || defaultExpanded ? false : 'hidden'}
          animate="visible"
          variants={MOTION_VARIANTS.overlay}
          transition={motionTransition('feedback', reducedMotion)}
        >
          <div
            className={cn(
              'mt-2 rounded-md border border-line/70 bg-panel2/20 px-3 py-3',
              contentClassName,
            )}
          >
            {children}
          </div>
        </motion.div>
      )}
    </section>
  )
}
