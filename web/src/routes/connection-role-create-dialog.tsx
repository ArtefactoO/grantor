// Создание роли-контейнера подключения: POST /connections/{id}/roles.
//
// Роль без логина не аутентифицируется и пароля не имеет, поэтому в форме
// только имя. В целевой системе она появляется сразу, а назначаемым правом
// становится после ближайшего discovery — об этом диалог говорит прямо, иначе
// оператор ищет только что созданную роль в списке выдачи и не находит.
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type { AccountOperationResponse, Connection } from '../lib/types'
import { Dialog, Button, Field, Input, Spinner, ErrorBanner } from '@project/ui'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'

export interface CreateRoleDialogProps {
  connectionId: string
  connection?: Connection
  open: boolean
  onClose: () => void
  onStarted: (operationId: string, roleName: string) => void
}

export function CreateRoleDialog({
  connectionId,
  connection,
  open,
  onClose,
  onStarted,
}: CreateRoleDialogProps) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const provisioningIssue = connection === undefined ? null : postgresProvisioningIssue(connection)
  const provisioningBlockerId = connection === undefined ? undefined : `postgres-role-create-${connection.id}-blocker`

  useEffect(() => {
    if (open) {
      setName('')
      setFormError(null)
    }
  }, [open])

  const createMutation = useMutation({
    mutationFn: (roleName: string) =>
      apiPost<AccountOperationResponse>(
        `/api/v1/connections/${connectionId}/roles`,
        { name: roleName },
      ),
    onSuccess: (data, roleName) => {
      // Роль — это и учётка kind=group, и будущее право: обновляем оба списка.
      void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      onStarted(data.operation_id, roleName)
      onClose()
    },
    onError: (err: unknown) => setFormError(errorMessage(err)),
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (provisioningIssue !== null) {
      setFormError(provisioningIssue)
      return
    }
    const roleName = name.trim()
    if (roleName === '') {
      setFormError('Укажите имя роли')
      return
    }
    if (/\s/.test(roleName)) {
      setFormError('Имя роли не должно содержать пробельных символов')
      return
    }
    createMutation.mutate(roleName)
  }

  return (
    <Dialog open={open} onClose={onClose} title="Создать пустую роль">
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {connection?.engine === 'postgres' && <PostgresProvisioningNotice connection={connection} id={provisioningBlockerId} />}
        <Field
          label="Имя роли"
          hint="Роль без логина: пароля у неё нет, она выдаётся пользователям как право"
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="r_appdb"
            className="font-mono text-[13px]"
            autoComplete="off"
            required
          />
        </Field>

        {/* Соглашение об именах из docs/postgresql-access-operations.md:
            по префиксу видно объём прав, и это единственное, что отличает
            роли друг от друга в списке выдачи. */}
        <p className="rounded-md border border-line bg-panel2/40 px-3 py-2 text-xs text-muted">
          Принятые префиксы: <span className="font-mono text-text">r_</span> (чтение),{' '}
          <span className="font-mono text-text">rw_</span> (чтение и запись),{' '}
          <span className="font-mono text-text">ddl_</span> (изменение схемы).
          Роль появится в списке ролей после ближайшей синхронизации.
        </p>

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose} disabled={createMutation.isPending}>
            Отмена
          </Button>
          <Button type="submit" aria-describedby={provisioningIssue === null ? undefined : provisioningBlockerId}
            disabled={createMutation.isPending || provisioningIssue !== null}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Создать
          </Button>
        </div>
      </form>
    </Dialog>
  )
}
