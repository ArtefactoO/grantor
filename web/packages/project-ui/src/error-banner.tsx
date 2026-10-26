// Инлайновая полоса ошибки/опасного уведомления: красная рамка на
// полупрозрачной danger-подложке. Текст (в т.ч. с префиксом «Не удалось …»)
// передаётся детьми. Заменяет повтор одинакового div по экранам.
import type { ReactNode } from 'react'

export interface ErrorBannerProps {
  children: ReactNode
}

export function ErrorBanner({ children }: ErrorBannerProps) {
  return (
    <div className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">
      {children}
    </div>
  )
}
