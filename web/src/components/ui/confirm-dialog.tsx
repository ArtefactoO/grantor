// Маленький confirm-диалог действий (отзыв, отключение, отвязка):
// текст-описание и пара кнопок; danger переводит подтверждение в красную
// зону. Используется панелью аккаунта, деталью пользователя и «Дрифтом».
import type { ReactNode } from 'react'
import { Dialog, Button, Spinner } from '@project/ui'
import { OperationRehearsal } from '../operation-rehearsal'

export interface ConfirmActionDialogProps {
  open: boolean
  title: string
  description: ReactNode
  confirmLabel: string
  danger?: boolean
  pending: boolean
  rehearsal?: {
    title: string
    detail: ReactNode
    impact?: ReactNode
  }
  onConfirm: () => void
  onClose: () => void
}

export function ConfirmActionDialog({
  open,
  title,
  description,
  confirmLabel,
  danger = false,
  pending,
  rehearsal,
  onConfirm,
  onClose,
}: ConfirmActionDialogProps) {
  return (
    <Dialog open={open} onClose={onClose} title={title}>
      <div className="space-y-4">
        {rehearsal === undefined ? (
          <div className="text-sm text-muted">{description}</div>
        ) : (
          <OperationRehearsal
            title={rehearsal.title}
            detail={rehearsal.detail}
            impact={rehearsal.impact ?? description}
            danger={danger}
          />
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={pending}>
            Отмена
          </Button>
          <Button
            variant={danger ? 'danger' : 'primary'}
            onClick={onConfirm}
            disabled={pending}
          >
            {pending && <Spinner className="size-3.5" />}
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
