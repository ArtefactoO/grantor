import { useState } from 'react'

/**
 * Radix data-state drives a short opacity change on open/close. The stable
 * class cannot replay the reveal when focus moves between list options.
 */
export function usePopoverSurfaceMotion() {
  const [open, setOpen] = useState(false)

  return {
    open,
    setOpen,
    surfaceClassName: 'ui-popover-surface',
  }
}
