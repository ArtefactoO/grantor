// Плотная операторская таблица: строки ~36px, tabular-nums, разделители
// токеном --line. Обёртка даёт горизонтальный скролл на узких экранах.
import { forwardRef } from 'react'
import type {
  HTMLAttributes,
  KeyboardEvent,
  MouseEvent,
  TdHTMLAttributes,
  ThHTMLAttributes,
} from 'react'
import { cn } from './cn'
import { selectionSurfaceClassName } from './selection-state'

export function TableContainer({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        'max-w-full overflow-x-auto overscroll-x-contain rounded-lg border border-line bg-panel',
        className,
      )}
      {...rest}
    />
  )
}

export function Table({ className, ...rest }: HTMLAttributes<HTMLTableElement>) {
  return (
    <table
      className={cn('min-w-full border-collapse text-sm tabular-nums', className)}
      {...rest}
    />
  )
}

export function TableHeader({ className, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return <thead className={cn('bg-panel2/60', className)} {...rest} />
}

// Keep ref forwarding available for directory callers.
export const TableBody = forwardRef<
  HTMLTableSectionElement,
  HTMLAttributes<HTMLTableSectionElement>
>(function TableBody({ className, ...rest }, ref) {
  return <tbody ref={ref} className={className} {...rest} />
})

export type TableRowInteraction = 'static' | 'selectable'
export type TableRowDivider = 'default' | 'subtle' | 'none'

export interface TableRowProps extends HTMLAttributes<HTMLTableRowElement> {
  interaction?: TableRowInteraction
  divider?: TableRowDivider
  selected?: boolean
}

const NESTED_INTERACTIVE_SELECTOR =
  'a,button,input,select,textarea,[role="button"],[role="link"],[tabindex]'

function hasNestedInteractiveTarget(
  event: MouseEvent<HTMLTableRowElement>,
): boolean {
  const target = event.target
  if (!(target instanceof Element) || target === event.currentTarget) {
    return false
  }
  // closest() поднимается и до самой строки: она получает tabIndex для
  // клавиатурной активации и потому тоже совпадает с selector. Блокируем
  // только настоящий вложенный control, но не обычную ячейку/текст строки.
  const nested = target.closest(NESTED_INTERACTIVE_SELECTOR)
  return nested !== null && nested !== event.currentTarget
}

export function TableRow({
  className,
  interaction = 'static',
  divider = 'default',
  selected,
  onClick,
  onKeyDown,
  tabIndex,
  ...rest
}: TableRowProps) {
  const interactive = interaction === 'selectable' && onClick !== undefined

  const handleClick = (event: MouseEvent<HTMLTableRowElement>) => {
    if (interactive && hasNestedInteractiveTarget(event)) {
      return
    }
    onClick?.(event)
  }

  const handleKeyDown = (event: KeyboardEvent<HTMLTableRowElement>) => {
    onKeyDown?.(event)
    if (
      event.defaultPrevented ||
      !interactive ||
      event.target !== event.currentTarget ||
      (event.key !== 'Enter' && event.key !== ' ')
    ) {
      return
    }
    event.preventDefault()
    event.currentTarget.click()
  }

  return (
    <tr
      className={cn(
        'ui-table-row',
        divider !== 'none' && 'border-b last:border-b-0',
        divider === 'default' && 'border-line',
        divider === 'subtle' && 'border-line/35',
        interactive &&
          'ui-interactive-row cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
        selected !== undefined && selectionSurfaceClassName(selected),
        className,
      )}
      aria-selected={selected === undefined ? undefined : selected}
      tabIndex={interactive ? 0 : tabIndex}
      onClick={interactive ? handleClick : undefined}
      onKeyDown={interactive ? handleKeyDown : onKeyDown}
      {...rest}
    />
  )
}

export type TableContentOverflow = 'nowrap' | 'wrap' | 'anywhere'

export interface TableHeadProps extends ThHTMLAttributes<HTMLTableCellElement> {
  overflow?: TableContentOverflow
}

function overflowClass(overflow: TableContentOverflow): string {
  switch (overflow) {
    case 'wrap':
      return 'whitespace-normal'
    case 'anywhere':
      return 'whitespace-normal [overflow-wrap:anywhere]'
    default:
      return 'whitespace-nowrap'
  }
}

export function TableHead({ className, overflow = 'nowrap', ...rest }: TableHeadProps) {
  return (
    <th
      className={cn(
        'h-8 border-b border-line px-3 text-left text-[11px] font-semibold uppercase tracking-wider text-faint',
        overflowClass(overflow),
        className,
      )}
      {...rest}
    />
  )
}

export interface TableCellProps extends TdHTMLAttributes<HTMLTableCellElement> {
  overflow?: TableContentOverflow
}

export function TableCell({ className, overflow = 'nowrap', ...rest }: TableCellProps) {
  return (
    <td
      className={cn(
        'h-9 px-3 align-middle',
        overflowClass(overflow),
        className,
      )}
      {...rest}
    />
  )
}
