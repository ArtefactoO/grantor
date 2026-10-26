// Одноразовая ссылка на креды: общий диалог для аккаунта (share по аккаунту) и
// принципала (share общего пароля окружения). Тонкая обёртка над
// OneTimeSecretDialog — добавляет чипы одноразовости и срока и текст про
// ссылку; общий показ секрета и копирование живут в OneTimeSecretDialog.
import { OneTimeSecretDialog } from './one-time-secret-dialog'
import { StatusChip } from './badge'

/**
 * Данные одноразовой ссылки — зеркало link/expires_in_hours/one_time ответов
 * POST /accounts/{id}/share и POST /principals/{id}/share.
 */
export interface ShareLinkData {
  link: string
  expires_in_hours: number
  one_time: boolean
}

export interface ShareLinkDialogProps {
  open: boolean
  share: ShareLinkData | null
  /** Заголовок диалога; по умолчанию общий для аккаунтов и принципалов. */
  title?: string
  onClose: () => void
}

export function ShareLinkDialog({
  open,
  share,
  title = 'Одноразовая ссылка на креды',
  onClose,
}: ShareLinkDialogProps) {
  return (
    <OneTimeSecretDialog
      open={open}
      title={title}
      secret={share?.link ?? null}
      chips={
        share !== null ? (
          <>
            {share.one_time && <StatusChip tone="ok">One-time</StatusChip>}
            <StatusChip tone="warn">Expires in {share.expires_in_hours} h</StatusChip>
          </>
        ) : undefined
      }
      warning="Ссылка показана один раз и не сохраняется. Скопируйте её сейчас и передайте получателю напрямую."
      onClose={onClose}
    />
  )
}
