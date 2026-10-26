// Инлайн-уведомление об успешном действии (запущенная операция,
// привязка и т.п.): зелёная полоса с текстом и кнопкой закрытия.
import { X } from './icons'
import { IconButton } from './icon-button'

export interface InlineNoticeProps {
  text: string
  onClose: () => void
}

export function InlineNotice({ text, onClose }: InlineNoticeProps) {
  return (
    <div className="flex min-w-0 items-center gap-2 rounded-md border border-ok/40 bg-ok-soft px-3 py-1.5 text-sm text-ok">
      <span className="min-w-0 truncate" title={text}>
        {text}
      </span>
      <IconButton
        compact
        onClick={onClose}
        label="Скрыть уведомление"
        icon={<X className="size-4" aria-hidden="true" />}
      />
    </div>
  )
}
