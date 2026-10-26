// Диалог выбора окружения для ротации пароля и выдачи кредов. Список
// окружений — те, где у принципала есть managed-аккаунты на общем секрете.
// Селектор — общий Combobox (как выбор движка в форме подключения), а не
// нативный select: тот рендерится системным виджетом и выглядит чужим.
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { Dialog, Field, Combobox, Button, Spinner } from '@project/ui'

interface EnvironmentPickerDialogProps {
  open: boolean
  title: string
  description: ReactNode
  confirmLabel: string
  environments: string[]
  pending: boolean
  onConfirm: (environment: string) => void
  onClose: () => void
}

export function EnvironmentPickerDialog({
  open,
  title,
  description,
  confirmLabel,
  environments,
  pending,
  onConfirm,
  onClose,
}: EnvironmentPickerDialogProps) {
  const [environment, setEnvironment] = useState('')

  // При открытии единственное окружение выбирается сразу, иначе — пусто.
  useEffect(() => {
    if (open) {
      setEnvironment(environments.length === 1 ? environments[0] : '')
    }
  }, [open, environments])

  return (
    <Dialog open={open} onClose={onClose} title={title}>
      <div className="space-y-4">
        <p className="text-sm text-muted">{description}</p>
        <Field label="Окружение">
          <Combobox
            value={environment === '' ? undefined : environment}
            onValueChange={setEnvironment}
            label="Окружение"
            placeholder="Выберите окружение…"
            // Имя окружения показывается ровно так, как его завели: список
            // выбора и реестр окружений должны читаться одинаково, иначе
            // «PROD» здесь и «prod» там выглядят разными сущностями.
            options={environments.map((env) => ({ value: env, label: env }))}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={pending}>
            Отмена
          </Button>
          <Button
            disabled={environment === '' || pending}
            onClick={() => onConfirm(environment)}
          >
            {pending && <Spinner className="size-3.5 text-accent-ink" />}
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
