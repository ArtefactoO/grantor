// Индикаторы загрузки: инлайновый спиннер и полноэкранный лоадер.
import { LoaderCircle } from './icons'
import { cn } from './cn'

export interface SpinnerProps {
  className?: string
}

export function Spinner({ className }: SpinnerProps) {
  return (
    <LoaderCircle
      className={cn('size-4 animate-spin motion-reduce:animate-none text-muted', className)}
      aria-hidden="true"
    />
  )
}

export interface ScreenLoaderProps {
  label?: string
}

/** Полноэкранный лоадер (старт приложения, загрузка /auth/me). */
export function ScreenLoader({ label = 'Загрузка…' }: ScreenLoaderProps) {
  return (
    <div className="flex h-screen flex-col items-center justify-center gap-3 bg-bg text-muted">
      <Spinner className="size-6" />
      <div className="text-sm">{label}</div>
    </div>
  )
}
