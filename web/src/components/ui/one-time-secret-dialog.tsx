// Общий диалог показа одноразового секрета: моно-блок со значением, кнопка
// «Копировать» и предупреждение о единственном показе. Секрет живёт только в
// состоянии вызывающей панели — после закрытия снова не показывается, новый
// показ = новый секрет с сервера. База для ShareLinkDialog (одноразовая ссылка
// на креды) и выпуска service token (grt_…).
import type { ReactNode } from 'react'
import { Dialog, Button, CopyButton } from '@project/ui'

export interface OneTimeSecretDialogProps {
  open: boolean
  title: string
  /** Показываемый секрет; null скрывает тело (диалог закрыт или сброшен). */
  secret: string | null
  /** Чипы над секретом (одноразовость, срок и т.п.); необязательно. */
  chips?: ReactNode
  /** Предупреждение под секретом. */
  warning: ReactNode
  onClose: () => void
}

export function OneTimeSecretDialog({
  open,
  title,
  secret,
  chips,
  warning,
  onClose,
}: OneTimeSecretDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} title={title}>
      {secret !== null && (
        <div className="space-y-4">
          {chips !== undefined && (
            <div className="flex flex-wrap items-center gap-2">{chips}</div>
          )}
          <div className="flex items-center gap-2">
            <div className="min-w-0 flex-1 break-all rounded-md border border-line bg-panel2 px-3 py-2 font-mono text-[12px] text-text">
              {secret}
            </div>
            <CopyButton value={secret} label="Копировать секрет" className="shrink-0" />
          </div>
          <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
            {warning}
          </div>
          <div className="flex justify-end">
            <Button variant="outline" onClick={onClose}>
              Закрыть
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  )
}
