import type { HTMLAttributes } from 'react'
import { cn } from './cn'

export function metadataChipClassName(interactive = false, className?: string): string {
  return cn(
    'inline-flex h-[22px] min-w-0 max-w-[220px] items-center gap-1.5 rounded border border-line bg-panel2 px-1.5 font-mono text-[11px] text-muted',
    interactive &&
      'ui-metadata-chip cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent hover:border-accent/35 hover:bg-accent-soft/55 hover:text-accent',
    className,
  )
}

export function MetadataChip({
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement>) {
  return <span className={metadataChipClassName(false, className)} {...props} />
}
