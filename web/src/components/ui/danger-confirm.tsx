// Подтверждение необратимого по последствиям решения: красная зона с
// заголовком, чекбоксом подтверждения и admin-only предупреждением. Сам
// чекбокс доступен только admin (disabled иначе). Используется дроверами
// выдачи опасной роли и диалогом offboard (принятие чужих паролей).
import type { ReactNode } from 'react'

const ADMIN_ONLY = 'Это решение доступно только администратору.'

export interface DangerConfirmProps {
  title: string
  /** Текст у чекбокса; ReactNode — часть подтверждений перечисляет
   * затронутые объекты списком. */
  label: ReactNode
  checked: boolean
  onChange: (checked: boolean) => void
  isAdmin: boolean
}

export function DangerConfirm({
  title,
  label,
  checked,
  onChange,
  isAdmin,
}: DangerConfirmProps) {
  return (
    <div className="space-y-2 rounded-md border border-danger/40 bg-danger-soft p-3">
      <div className="text-sm font-medium text-danger">{title}</div>
      <label className="flex cursor-pointer items-start gap-2 text-sm text-text">
        <input
          type="checkbox"
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          disabled={!isAdmin}
          className="mt-0.5 accent-danger"
        />
        {label}
      </label>
      {!isAdmin && <div className="text-xs text-danger">{ADMIN_ONLY}</div>}
    </div>
  )
}
