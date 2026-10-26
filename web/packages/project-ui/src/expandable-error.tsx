// Разворачиваемый текст ошибки для табличных ячеек: свёрнуто — одна
// усечённая строка-кнопка, по клику — блок с полным текстом (font-mono,
// переносы) и кнопкой копирования (паттерн копирования — как в
// OneTimeSecretDialog, плюс fallback для окружений без Clipboard API).
import { useState } from 'react'
import { ChevronDown, ChevronRight } from './icons'
import { CopyButton } from './copy-button'

export interface ExpandableErrorProps {
  /** Полный текст ошибки; пустая строка рендерит прочерк. */
  text: string
}

export function ExpandableError({ text }: ExpandableErrorProps) {
  const [expanded, setExpanded] = useState(false)

  if (text === '') {
    return <span className="text-faint">—</span>
  }

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={() => setExpanded(true)}
        title="Показать полный текст ошибки"
        className="flex w-full min-w-0 items-center gap-1 text-left"
      >
        <ChevronRight className="size-3 shrink-0 text-faint" aria-hidden="true" />
        <span className="min-w-0 flex-1 truncate text-[13px] text-danger">{text}</span>
      </button>
    )
  }

  return (
    <div className="space-y-1.5 py-1">
      <div className="flex items-center gap-1.5">
        <button
          type="button"
          onClick={() => setExpanded(false)}
          title="Свернуть текст ошибки"
          className="flex items-center gap-1 text-xs text-faint transition-colors hover:text-text"
        >
          <ChevronDown className="size-3" aria-hidden="true" />
          свернуть
        </button>
        <CopyButton value={text} label="Копировать текст ошибки" className="ml-0.5" />
      </div>
      <div className="whitespace-pre-wrap break-words rounded-md border border-danger/30 bg-danger-soft/40 px-2 py-1.5 font-mono text-[12px] leading-relaxed text-danger">
        {text}
      </div>
    </div>
  )
}
