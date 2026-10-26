import { Unlink } from '@project/ui/icons'
import type { MouseEventHandler } from 'react'
import { IconButton } from '@project/ui'

export interface UnlinkAccountButtonProps {
  onClick: MouseEventHandler<HTMLButtonElement>
  disabled?: boolean
}

/** Единое компактное действие отвязки аккаунта от глобального пользователя. */
export function UnlinkAccountButton({ onClick, disabled }: UnlinkAccountButtonProps) {
  return (
    <IconButton
      compact
      label="Отвязать от пользователя"
      icon={<Unlink className="size-3.5" />}
      disabled={disabled}
      onClick={onClick}
      className="text-faint hover:bg-danger-soft hover:text-danger"
    />
  )
}
