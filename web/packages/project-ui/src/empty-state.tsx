// Пустые состояния и ошибки: иконка + текст + необязательное действие.
import type { ComponentType, ReactNode } from 'react'
import { CircleAlert, Inbox } from './icons'
import { Button } from './button'
import { cn } from './cn'

interface IconProps {
  className?: string
  'aria-hidden'?: boolean
}

export interface EmptyStateProps {
  icon?: ComponentType<IconProps>
  title: string
  description?: string
  action?: ReactNode
  className?: string
}

/** Аккуратное пустое состояние в стиле концепции. */
export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line px-6 py-12 text-center',
        className,
      )}
    >
      <Icon aria-hidden={true} className="size-8 text-faint" />
      <div className="text-sm font-medium text-text">{title}</div>
      {description !== undefined && (
        <div className="max-w-md text-sm text-muted">{description}</div>
      )}
      {action !== undefined && <div className="mt-2">{action}</div>}
    </div>
  )
}

export interface ErrorStateProps {
  title?: string
  message: string
  onRetry?: () => void
  className?: string
}

/** Состояние ошибки запроса с кнопкой повтора. */
export function ErrorState({
  title = 'Не удалось загрузить данные',
  message,
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-danger/40 bg-danger-soft px-6 py-10 text-center',
        className,
      )}
    >
      <CircleAlert aria-hidden="true" className="size-8 text-danger" />
      <div className="text-sm font-medium text-text">{title}</div>
      <div className="max-w-md text-sm text-muted">{message}</div>
      {onRetry !== undefined && (
        <Button variant="outline" size="sm" className="mt-2" onClick={onRetry}>
          Повторить
        </Button>
      )}
    </div>
  )
}
