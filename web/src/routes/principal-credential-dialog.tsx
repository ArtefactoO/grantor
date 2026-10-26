import { useEffect, useState } from 'react'
import { Dialog, Button, Input, Spinner, RadioOptionCard } from '@project/ui'
import type { CreatePrincipalCredentialInput } from './principal-detail-actions'

interface PrincipalCredentialDialogProps {
  open: boolean
  environment: string | null
  pending: boolean
  onClose: () => void
  onConfirm: (input: CreatePrincipalCredentialInput) => void
}

export function PrincipalCredentialDialog({
  open,
  environment,
  pending,
  onClose,
  onConfirm,
}: PrincipalCredentialDialogProps) {
  const [mode, setMode] = useState<'generated' | 'provided'>('generated')
  const [password, setPassword] = useState('')

  useEffect(() => {
    if (!open) {
      setMode('generated')
      setPassword('')
    }
  }, [open])

  const providedInvalid = mode === 'provided' && (password.length < 12 || password.length > 256)

  return (
    <Dialog open={open} onClose={onClose} title="Создать credential">
      <div className="space-y-4">
        <p className="text-sm text-muted">
          Пароль для окружения <span className="font-mono text-text">{environment}</span>{' '}
          будет сохранён в Vault. Он автоматически переиспользуется при создании
          или переводе аккаунтов пользователя под управление.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <RadioOptionCard
            name="principal-credential-mode"
            label="Сгенерировать"
            hint="Криптографически случайный пароль"
            checked={mode === 'generated'}
            onSelect={() => setMode('generated')}
          />
          <RadioOptionCard
            name="principal-credential-mode"
            label="Задать вручную"
            hint="От 12 до 256 символов"
            checked={mode === 'provided'}
            onSelect={() => setMode('provided')}
          />
        </div>
        {mode === 'provided' && (
          <label className="block space-y-1.5 text-sm text-muted">
            <span>Пароль</span>
            <Input
              type="password"
              value={password}
              autoComplete="new-password"
              onChange={(event) => setPassword(event.target.value)}
            />
          </label>
        )}
        <div className="flex justify-end gap-2">
          <Button variant="outline" disabled={pending} onClick={onClose}>Отмена</Button>
          <Button
            disabled={pending || environment === null || providedInvalid}
            onClick={() => {
              if (environment === null) return
              onConfirm({
                environment,
                mode,
                ...(mode === 'provided' ? { password } : {}),
              })
            }}
          >
            {pending && <Spinner className="size-3.5" />}
            Создать
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
