import { Fragment } from 'react'
import type { ReactNode } from 'react'
import { cn } from './cn'
import { CopyButton } from './copy-button'

const IDENTIFIER_BREAK_SEPARATORS = new Set(['_', '-', '.', '@', ':', '/'])
const IDENTIFIER_MIN_FRAGMENT = 3
const IDENTIFIER_MAX_FRAGMENT = 16

/**
 * Даёт браузеру явные точки переноса технического идентификатора и не
 * оставляет на новой строке хвост короче трёх символов.
 */
export function identifierWrapSegments(
  value: string,
  minFragment = IDENTIFIER_MIN_FRAGMENT,
  maxFragment = IDENTIFIER_MAX_FRAGMENT,
): string[] {
  if (value.length <= maxFragment) {
    return [value]
  }

  const safeSegments: string[] = []
  let start = 0
  for (let index = 0; index < value.length; index += 1) {
    if (!IDENTIFIER_BREAK_SEPARATORS.has(value[index])) {
      continue
    }
    const end = index + 1
    if (end - start >= minFragment && value.length - end >= minFragment) {
      safeSegments.push(value.slice(start, end))
      start = end
    }
  }
  safeSegments.push(value.slice(start))

  return safeSegments.flatMap((segment) => {
    if (segment.length <= maxFragment) {
      return [segment]
    }
    const chunks: string[] = []
    let offset = 0
    while (segment.length - offset > maxFragment) {
      const remaining = segment.length - offset
      const chunkLength = remaining - maxFragment < minFragment
        ? remaining - minFragment
        : maxFragment
      chunks.push(segment.slice(offset, offset + chunkLength))
      offset += chunkLength
    }
    chunks.push(segment.slice(offset))
    return chunks
  })
}

function IdentifierValue({ value }: { value: string }) {
  const segments = identifierWrapSegments(value)
  return (
    <>
      {segments.map((segment, index) => (
        <Fragment key={`${index}-${segment}`}>
          {segment}
          {index < segments.length - 1 && <wbr />}
        </Fragment>
      ))}
    </>
  )
}

export interface CopyableValueProps {
  value: string
  children?: ReactNode
  label?: string
  className?: string
  valueClassName?: string
  /** Constrain the value to its container so long identifiers wrap instead of overflowing. */
  fill?: boolean
  /** Use the denser shared action intended for table cells. */
  compactAction?: boolean
  /** Technical identifiers wrap only at safe boundaries with a 3-char tail. */
  identifierWrap?: boolean
}

/**
 * A visible value with its copy action revealed on hover or keyboard focus
 * when hover is available. Touch-first pointers keep the action visible.
 */
export function CopyableValue({
  value,
  children,
  label = 'Копировать значение',
  className,
  valueClassName,
  fill = false,
  compactAction = false,
  identifierWrap = false,
}: CopyableValueProps) {
  const content = identifierWrap && children === undefined
    ? <IdentifierValue value={value} />
    : (children ?? value)
  return (
    <span
      className={cn(
        'group/copyable min-w-0 max-w-full items-start gap-0.5',
        fill ? 'flex w-full' : 'inline-flex',
        className,
      )}
    >
      <span
        className={cn(
          'min-w-0 max-w-full',
          identifierWrap
            ? 'whitespace-normal [overflow-wrap:normal] [word-break:normal]'
            : '[overflow-wrap:anywhere]',
          fill && 'flex-1',
          valueClassName,
        )}
      >
        {content}
      </span>
      <CopyButton
        value={value}
        label={label}
        compact={compactAction}
        className="shrink-0 transition-opacity [@media(hover:hover)]:pointer-events-none [@media(hover:hover)]:opacity-0 [@media(hover:hover)]:group-hover/copyable:pointer-events-auto [@media(hover:hover)]:group-hover/copyable:opacity-100 [@media(hover:hover)]:group-focus-within/copyable:pointer-events-auto [@media(hover:hover)]:group-focus-within/copyable:opacity-100"
      />
    </span>
  )
}

export type TableCopyableValueProps = Omit<
  CopyableValueProps,
  'fill' | 'compactAction'
>

/** Canonical name/identity presentation for every dense table. */
export function TableCopyableValue({
  className,
  ...props
}: TableCopyableValueProps) {
  return (
    <CopyableValue
      {...props}
      compactAction
      identifierWrap
      className={cn('gap-1 align-middle', className)}
    />
  )
}
