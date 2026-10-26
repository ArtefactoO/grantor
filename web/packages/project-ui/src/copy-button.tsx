import { useEffect, useRef, useState } from 'react'
import { Check, Copy } from './icons'
import { copyText } from './clipboard'
import { cn } from './cn'
import { IconButton } from './icon-button'

export interface CopyButtonProps {
  value: string
  label?: string
  successLabel?: string
  errorLabel?: string
  resetDelay?: number
  className?: string
  disabled?: boolean
  tabIndex?: number
  onCopied?: () => void
  onCopyError?: (error: unknown) => void
  /** 24px action for dense table cells; regular copy surfaces stay 32px. */
  compact?: boolean
}

type CopyState = 'idle' | 'copied' | 'error'

/** Icon-only Copy -> Check action shared by every real copy surface. */
export function CopyButton({
  value,
  label = 'Копировать',
  successLabel = 'Скопировано',
  errorLabel = 'Не удалось скопировать',
  resetDelay = 1_500,
  className,
  disabled = false,
  tabIndex,
  onCopied,
  onCopyError,
  compact = false,
}: CopyButtonProps) {
  const [state, setState] = useState<CopyState>('idle')
  const timerRef = useRef<number | null>(null)

  const resetLater = () => {
    if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    timerRef.current = window.setTimeout(() => setState('idle'), resetDelay)
  }

  useEffect(
    () => () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    },
    [],
  )

  const copy = async () => {
    try {
      await copyText(value)
      setState('copied')
      onCopied?.()
    } catch (error: unknown) {
      setState('error')
      onCopyError?.(error)
    } finally {
      resetLater()
    }
  }

  const copied = state === 'copied'
  const currentLabel = copied ? successLabel : state === 'error' ? errorLabel : label
  return (
    <span className={cn('inline-flex', className)}>
      <IconButton
        label={currentLabel}
        success={copied}
        disabled={disabled}
        tabIndex={tabIndex}
        compact={compact}
        // Копирование не должно активировать контейнер: кнопка живёт внутри
        // кликабельных строк таблиц и узлов дерева, и клик по ней выбирал бы
        // строку заодно. Тот же приём, что у «+N» в AccessChipList.
        onClick={(event) => {
          event.stopPropagation()
          void copy()
        }}
        className="ui-copy-button"
        icon={
          <span className="ui-copy-glyph" data-copied={copied || undefined}>
            <Copy className={cn('ui-copy-idle', compact ? 'size-3.5' : 'size-4')} aria-hidden="true" />
            <Check className={cn('ui-copy-success', compact ? 'size-3.5' : 'size-4')} aria-hidden="true" />
          </span>
        }
      />
      <span className="sr-only" role="status" aria-live="polite">
        {state === 'idle' ? '' : currentLabel}
      </span>
    </span>
  )
}
