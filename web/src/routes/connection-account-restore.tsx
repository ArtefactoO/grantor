import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  Account,
  Connection,
  Operation,
  RestoreAccountRequest,
  RestoreAccountResponse,
  ShareCredentialResponse,
} from '../lib/types'
import { operationInProgress, shortId } from '../lib/status'
import { operationStatusLabel } from '../lib/operation-presentation'
import { POLL_OPERATION_MS } from '../lib/intervals'
import { Dialog, Button, Field, Input, RadioOptionCard, ErrorBanner, Spinner } from '@project/ui'
import { ShareLinkDialog } from '../components/ui/share-link-dialog'
import { OperationRehearsal } from '../components/operation-rehearsal'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'

export type RestoreCredentialMode = 'principal' | 'generated' | 'provided'

export function restorePasswordError(password: string): string | null {
  const length = Array.from(password).length
  if (length < 12) return 'Пароль должен содержать не меньше 12 символов'
  if (length > 256) return 'Пароль должен содержать не больше 256 символов'
  if (password.includes('\u0000')) return 'Пароль не должен содержать нулевой символ'
  return null
}

export interface RestoreAccountDialogProps {
  open: boolean
  account: Account
  connectionId: string
  connection?: Connection
  onClose: () => void
  onRestored: (operationId: string) => void
}

type RestoreStage =
  | 'form'
  | 'starting'
  | 'waiting'
  | 'failed'
  | 'sharing'
  | 'share_failed'
  | 'complete'

export function RestoreAccountDialog({
  open,
  account,
  connectionId,
  connection,
  onClose,
  onRestored,
}: RestoreAccountDialogProps) {
  const queryClient = useQueryClient()
  const defaultMode: RestoreCredentialMode = account.principal_id !== null ? 'principal' : 'generated'
  const [mode, setMode] = useState<RestoreCredentialMode>(defaultMode)
  const [submittedMode, setSubmittedMode] = useState<RestoreCredentialMode | null>(null)
  const [password, setPassword] = useState('')
  const [stage, setStage] = useState<RestoreStage>('form')
  const [operationId, setOperationId] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [share, setShare] = useState<ShareCredentialResponse | null>(null)
  const [shareOpen, setShareOpen] = useState(false)
  const handledOperation = useRef<string | null>(null)
  const provisioningIssue = connection === undefined ? null : postgresProvisioningIssue(connection)
  const provisioningBlockerId = connection === undefined ? undefined : `postgres-restore-${connection.id}-blocker`

  useEffect(() => {
    if (!open) return
    setMode(account.principal_id !== null ? 'principal' : 'generated')
    setSubmittedMode(null)
    setPassword('')
    setStage('form')
    setOperationId(null)
    setFormError(null)
    setShare(null)
    setShareOpen(false)
    handledOperation.current = null
  }, [open, account.id])

  const operationQuery = useQuery({
    queryKey: qk.operation(operationId ?? ''),
    queryFn: ({ signal }) =>
      api<Operation>(`/api/v1/operations/${operationId}`, { signal }),
    enabled: operationId !== null && stage === 'waiting',
    refetchInterval: (query) => {
      const operation = query.state.data
      return operation === undefined || operationInProgress(operation.status)
        ? POLL_OPERATION_MS
        : false
    },
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) })
    void queryClient.invalidateQueries({ queryKey: qk.accountBindings(account.id) })
    // Списки операций должны обновиться, но повторно дёргать уже известную
    // terminal detail текущей операции не нужно.
    void queryClient.invalidateQueries({
      queryKey: qk.operations(),
      predicate: (query) => query.queryKey[1] !== 'detail',
    })
  }

  const finish = (finishedOperationId: string) => {
    setStage('complete')
    invalidate()
    onRestored(finishedOperationId)
    onClose()
  }

  const shareGeneratedCredential = async (finishedOperationId: string) => {
    setStage('sharing')
    setFormError(null)
    try {
      const result = await apiPost<ShareCredentialResponse>(
        `/api/v1/accounts/${account.id}/share`,
      )
      setShare(result)
      setShareOpen(true)
      finish(finishedOperationId)
    } catch (error: unknown) {
      setStage('share_failed')
      setFormError(
        `Аккаунт восстановлен, но одноразовую ссылку получить не удалось: ${errorMessage(error)}`,
      )
      invalidate()
    }
  }

  useEffect(() => {
    const operation = operationQuery.data
    if (
      operation === undefined ||
      operationId === null ||
      operationInProgress(operation.status) ||
      handledOperation.current === operation.id
    ) {
      return
    }
    handledOperation.current = operation.id
    if (operation.status !== 'success') {
      setStage('failed')
      setFormError(
        operation.error !== ''
          ? operation.error
          : `Восстановление завершилось со статусом ${operationStatusLabel(operation.status)}`,
      )
      return
    }
    if (submittedMode === 'generated') {
      void shareGeneratedCredential(operation.id)
    } else {
      finish(operation.id)
    }
  }, [operationQuery.data, operationId, submittedMode])

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (provisioningIssue !== null) {
      setFormError(provisioningIssue)
      return
    }
    const selectedMode = mode
    if (selectedMode === 'provided') {
      const validation = restorePasswordError(password)
      if (validation !== null) {
        setFormError(validation)
        return
      }
    }

    const request: RestoreAccountRequest = {
      credential:
        selectedMode === 'principal'
          ? { mode: 'existing_vault_ref' }
          : selectedMode === 'generated'
            ? { mode: 'generated' }
            : { mode: 'provided', password },
    }

    // Не держим provided password в React state или react-query mutation
    // variables после submit. Он остаётся только в локальном теле запроса.
    setPassword('')
    setSubmittedMode(selectedMode)
    setStage('starting')
    setFormError(null)
    void apiPost<RestoreAccountResponse>(
      `/api/v1/accounts/${account.id}/restore`,
      request,
    )
      .then((response) => {
        setOperationId(response.operation_id)
        setStage('waiting')
      })
      .catch((_error: unknown) => {
        setSubmittedMode(null)
        setStage('form')
        setFormError(
          'Восстановление не запущено. Проверьте, что подключение активно, поддерживает восстановление и у удалённого аккаунта не осталось действующих прав.',
        )
      })
  }

  const locked = stage === 'starting' || stage === 'waiting' || stage === 'sharing'
  const retryAfterFailure = () => {
    handledOperation.current = null
    setOperationId(null)
    setSubmittedMode(null)
    setStage('form')
    setFormError(null)
  }

  return (
    <>
      <Dialog
        open={open}
        onClose={() => {
          if (!locked) onClose()
        }}
        title={`Восстановить аккаунт - ${account.engine_identity}`}
      >
        <form onSubmit={submit} className="space-y-4" autoComplete="off">
          {connection?.engine === 'postgres' && <PostgresProvisioningNotice connection={connection} id={provisioningBlockerId} />}
          <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
            {account.principal_id !== null
              ? 'Будет создан чистый аккаунт с тем же identity и актуальным паролем глобального пользователя. Прежние роли и права не восстанавливаются.'
              : 'Будет создан чистый локальный аккаунт с тем же identity и новым паролем. Прежние роли и права не восстанавливаются.'}
          </div>

          {stage === 'form' && (
            <>
              <div className="space-y-1.5">
                {account.principal_id !== null && (
                  <RadioOptionCard
                    name="restore-credential-mode"
                    label="Использовать пароль пользователя"
                    hint="Будет применён текущий credential глобального пользователя для окружения подключения; связь сохранится."
                    checked={mode === 'principal'}
                    onSelect={() => {
                      setMode('principal')
                      setPassword('')
                      setFormError(null)
                    }}
                  />
                )}
                <RadioOptionCard
                  name="restore-credential-mode"
                  label="Сгенерировать пароль"
                  hint={account.principal_id !== null
                    ? 'Создаст отдельный пароль и отвяжет аккаунт от глобального пользователя.'
                    : 'После успешной операции Grantor создаст одноразовую ссылку на новые креды.'}
                  checked={mode === 'generated'}
                  onSelect={() => {
                    setMode('generated')
                    setPassword('')
                    setFormError(null)
                  }}
                />
                <RadioOptionCard
                  name="restore-credential-mode"
                  label="Задать пароль"
                  hint={account.principal_id !== null
                    ? 'Задаст отдельный пароль и отвяжет аккаунт от глобального пользователя.'
                    : 'Пароль уйдёт в Vault и target, но не будет показан или сохранён в UI.'}
                  checked={mode === 'provided'}
                  onSelect={() => {
                    setMode('provided')
                    setFormError(null)
                  }}
                />
              </div>

              {mode === 'provided' && (
                <Field
                  label="Новый пароль"
                  hint="От 12 до 256 символов"
                  htmlFor="restore-account-password"
                >
                  <Input
                    id="restore-account-password"
                    aria-label="Новый пароль"
                    type="password"
                    value={password}
                    minLength={12}
                    maxLength={256}
                    onChange={(event) => setPassword(event.target.value)}
                    autoComplete="new-password"
                    required
                  />
                </Field>
              )}

              <OperationRehearsal
                title={`Восстановление аккаунта ${account.engine_identity}`}
                detail={
                  mode === 'principal'
                    ? 'Будет применён актуальный пароль глобального пользователя для окружения подключения.'
                    : mode === 'generated'
                      ? 'Будет создан новый пароль для восстановленного аккаунта.'
                      : 'Будет применён указанный пароль.'
                }
                impact={(
                  <div className="grid gap-1 text-xs text-muted sm:grid-cols-2">
                    <span>Роли и права</span>
                    <span className="text-text">Не восстанавливаются</span>
                    <span>Связь с пользователем</span>
                    <span className="text-text">
                      {mode === 'principal' ? 'Сохранится' : 'Будет удалена'}
                    </span>
                  </div>
                )}
              />
            </>
          )}

          {stage === 'starting' && (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Spinner className="size-3.5" />
              Ставим восстановление в очередь…
            </div>
          )}
          {stage === 'waiting' && (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Spinner className="size-3.5" />
              Ждём результат операции {shortId(operationId ?? '')}…
            </div>
          )}
          {stage === 'sharing' && (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Spinner className="size-3.5" />
              Аккаунт восстановлен. Создаём одноразовую ссылку…
            </div>
          )}

          {operationQuery.isError && stage === 'waiting' && (
            <ErrorBanner>
              Не удалось проверить операцию: {errorMessage(operationQuery.error)}
              <Button
                variant="outline"
                size="sm"
                className="ml-2"
                onClick={() => void operationQuery.refetch()}
              >
                Повторить
              </Button>
            </ErrorBanner>
          )}
          {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="outline" onClick={onClose} disabled={locked}>
              Закрыть
            </Button>
            {stage === 'form' && (
              <Button type="submit" aria-describedby={provisioningIssue === null ? undefined : provisioningBlockerId}
                disabled={provisioningIssue !== null}>Восстановить</Button>
            )}
            {stage === 'failed' && (
              <Button type="button" onClick={retryAfterFailure}>
                Повторить восстановление
              </Button>
            )}
            {stage === 'share_failed' && operationId !== null && (
              <Button
                type="button"
                onClick={() => void shareGeneratedCredential(operationId)}
              >
                Повторить получение ссылки
              </Button>
            )}
          </div>
        </form>
      </Dialog>

      <ShareLinkDialog
        open={shareOpen}
        share={share}
        title="Новые креды восстановленного аккаунта"
        onClose={() => {
          setShareOpen(false)
          setShare(null)
        }}
      />
    </>
  )
}
