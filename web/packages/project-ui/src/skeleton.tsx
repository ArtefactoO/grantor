// Заглушки загрузки, повторяющие форму будущего содержимого.
import { cn } from './cn'
import { Card } from './card'

export interface SkeletonProps {
  className?: string
}

/** Прямоугольник-заглушка. Пульсация уважает prefers-reduced-motion. */
export function Skeleton({ className }: SkeletonProps) {
  return <span className={cn('block animate-pulse rounded bg-panel2 motion-reduce:animate-none', className)} />
}

export interface RowSkeletonProps {
  /** Сколько строк рисовать; по умолчанию столько же, сколько влезает на экран. */
  rows?: number
  /** Место под иконку слева — для лент, где строки с иконкой домена. */
  leading?: boolean
  className?: string
}

/**
 * Список строк в карточке.
 *
 * Форма повторяет ControlRow: заголовок и подзаголовок разной ширины плюс
 * чип статуса справа. Ширины чередуются — одинаковые полосы читаются как
 * дефект отрисовки, а не как загрузка.
 */
export function RowSkeleton({ rows = 5, leading = false, className }: RowSkeletonProps) {
  const widths = ['w-48', 'w-64', 'w-40', 'w-56', 'w-44']
  return (
    <Card className={cn('divide-y divide-line overflow-hidden', className)}>
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="flex items-center gap-3 px-4 py-3">
          {leading && <Skeleton className="size-7 shrink-0 rounded-md" />}
          <span className="min-w-0 flex-1 space-y-1.5">
            <Skeleton className={cn('h-3.5', widths[index % widths.length])} />
            <Skeleton className="h-3 w-32" />
          </span>
          <Skeleton className="h-5 w-16 rounded-full" />
        </div>
      ))}
    </Card>
  )
}

/**
 * Полностраничная деталь (пользователь, подключение): шапка с заголовком и
 * рядом действий плюс список строк. Повторяет геометрию загруженной
 * страницы, чтобы контент не прыгал при появлении данных.
 */
export function DetailPageSkeleton() {
  return (
    <LoadingSkeleton>
      <div className="mx-auto max-w-6xl space-y-3">
        <Card className="space-y-4 p-4">
          <div className="flex items-start gap-3">
            <Skeleton className="size-9 shrink-0 rounded-md" />
            <span className="min-w-0 flex-1 space-y-2">
              <Skeleton className="h-5 w-56" />
              <Skeleton className="h-3.5 w-40" />
            </span>
            <Skeleton className="h-4 w-28" />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {Array.from({ length: 4 }, (_, index) => (
              <Skeleton key={index} className="h-8 w-36 rounded-md" />
            ))}
          </div>
        </Card>
        <RowSkeleton rows={6} leading />
      </div>
    </LoadingSkeleton>
  )
}

/** Обёртка со статусом для screen reader: пульсация им не видна. */
export function LoadingSkeleton({ children, label = 'Загрузка данных…' }: { children: React.ReactNode; label?: string }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">{label}</span>
      {/* Полосы-заглушки декоративны: диктор читает статус, а не их. */}
      <div aria-hidden="true">{children}</div>
    </div>
  )
}
