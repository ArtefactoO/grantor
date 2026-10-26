// Создание окружения в реестре: раньше окружение появлялось только вместе с
// первым подключением, и подготовить пользователю env-credential заранее
// было невозможно.
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, apiList, ApiError } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type { EnvironmentEntry } from '../lib/types'
import { Dialog, Button, ErrorBanner, Field, Input, Spinner } from '@project/ui'

interface EnvironmentCreateDialogProps {
  open: boolean
  onClose: () => void
}

export function EnvironmentCreateDialog({ open, onClose }: EnvironmentCreateDialogProps) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) {
      setName('')
      setFormError(null)
    }
  }, [open])

  const createMutation = useMutation({
    mutationFn: (environment: string) =>
      api<EnvironmentEntry>('/api/v1/environments', {
        method: 'POST',
        body: { name: environment },
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.environments() })
      onClose()
    },
    onError: (err: unknown) => {
      setFormError(err instanceof ApiError ? err.message : errorMessage(err))
    },
  })

  // Существующие окружения показываются в диалоге: без списка легко завести
  // дубль по памяти и получить 409 вместо подсказки.
  const existingQuery = useQuery({
    queryKey: qk.environments(),
    queryFn: ({ signal }) =>
      apiList<EnvironmentEntry>('/api/v1/environments', 'environments', signal),
    enabled: open,
  })
  const existing = (existingQuery.data ?? []).map((entry) => entry.name)

  const trimmed = name.trim()
  const duplicate = existing.some(
    (entry) => entry.toLocaleLowerCase() === trimmed.toLocaleLowerCase(),
  )
  // Имя — сегмент Vault-пути env-credential, '/' сломал бы его.
  const invalid = trimmed === '' || trimmed.includes('/') || duplicate

  return (
    <Dialog open={open} onClose={onClose} title="Новое окружение">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          if (!invalid) createMutation.mutate(trimmed)
        }}
      >
        <p className="text-sm text-muted">
          Окружение появится в форме подключения, матрице окружений и на
          карточках пользователей. Пароли можно готовить до первого
          подключения.
        </p>
        <Field
          label="Название"
          hint={duplicate ? 'Такое окружение уже существует' : 'Без «/»; например dev, stage, prod'}
        >
          <Input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="stage"
            className="font-mono text-[13px]"
            aria-invalid={duplicate || undefined}
            autoFocus
            required
          />
        </Field>
        {existing.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted">
            <span>Уже есть:</span>
            {existing.map((entry) => (
              <span
                key={entry}
                className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[11px] text-text"
              >
                {entry}
              </span>
            ))}
          </div>
        )}
        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}
        <div className="flex justify-end gap-2">
          <Button variant="outline" disabled={createMutation.isPending} onClick={onClose}>
            Отмена
          </Button>
          <Button type="submit" disabled={createMutation.isPending || invalid}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Создать
          </Button>
        </div>
      </form>
    </Dialog>
  )
}
