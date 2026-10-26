import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { RefreshCw } from '@project/ui/icons'
import { api, apiPost, ApiError } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { POLL_OPERATION_MS } from '../lib/intervals'
import { qk } from '../lib/queryKeys'
import type { Account, Operation, RetryOperationResponse } from '../lib/types'
import { operationInProgress } from '../lib/status'
import type { ChipTone } from '../components/ui/badge'
import type { OperationAnchor } from '../components/operation-progress-notice'
import { Button, Dialog, ErrorBanner, Spinner } from '@project/ui'

export interface AccountProvisioning {
  account_id: string
  updated_at: string
  state: 'running' | 'failed' | 'unavailable'
  operation_id?: string
  operation_kind?: string
  operation_status?: string
  operation_error?: string
  recoverable: boolean
  retryable: boolean
  verification_ready?: boolean
  creation_phase?: 'planned' | 'creating' | 'created' | 'verified'
  blocked_reason?: string
}

interface RecoveryRequest {
  request_id: string
  updated_at: string
  operation_id: string
}

interface RecoveryResponse {
  account_id: string
  operation_id: string
  status: string
  deduplicated?: boolean
}

interface VerificationSubmission {
  accountId: string
  request: RecoveryRequest
}

interface VerificationResponse extends RecoveryResponse {
  verification_only: true
}

function creationAlreadyStarted(data: AccountProvisioning | undefined): boolean {
  return data?.verification_ready === true ||
    ['creating', 'created', 'verified'].includes(data?.creation_phase ?? '')
}

function readyToVerify(data: AccountProvisioning | undefined, account: Account): boolean {
  return account.status === 'provisioning' && account.ownership === 'managed' &&
    data?.account_id === account.id && data.state === 'failed' &&
    data.operation_status === 'failed' && data.verification_ready === true &&
    data.creation_phase === 'created' && data.operation_kind === 'postgres.account.provision.v1' &&
    typeof data.operation_id === 'string' && data.operation_id !== '' &&
    typeof data.updated_at === 'string' && data.updated_at !== ''
}

export function accountProvisioningPollInterval(
  data: AccountProvisioning | undefined,
  failed: boolean,
): number | false {
  return !failed && data?.state === 'running' ? POLL_OPERATION_MS : false
}

export function useAccountProvisioning(account: Account) {
  return useQuery({
    queryKey: qk.accountProvisioning(account.id),
    queryFn: ({ signal }) =>
      api<AccountProvisioning>(`/api/v1/accounts/${account.id}/provisioning`, { signal }),
    enabled: account.status === 'provisioning',
    retry: false,
    refetchInterval: (query) => accountProvisioningPollInterval(
      query.state.data,
      query.state.status === 'error',
    ),
    refetchIntervalInBackground: false,
  })
}

type ProvisioningQuery = ReturnType<typeof useAccountProvisioning>

export function accountProvisioningPresentation(
  query: Pick<ProvisioningQuery, 'data' | 'isPending' | 'isError'>,
): { label: string; tone: ChipTone } {
  if (query.isPending) return { label: 'Проверяем создание', tone: 'unmg' }
  if (query.isError) return { label: 'Статус создания недоступен', tone: 'danger' }
  switch (query.data?.state) {
    case 'running':
      return { label: 'Создание выполняется', tone: 'warn' }
    case 'failed':
      if (query.data.creation_phase === 'created') {
        return { label: 'Учётка создана, проверка не завершена', tone: 'warn' }
      }
      if (query.data.blocked_reason === 'creation_outcome_unknown') {
        return { label: 'Результат создания не подтверждён', tone: 'danger' }
      }
      return { label: 'Создание не удалось', tone: 'danger' }
    default:
      return { label: 'Статус создания недоступен', tone: 'danger' }
  }
}

export function provisioningBlockedReason(reason: string | undefined): string {
  switch (reason) {
    case 'not_provisioning':
      return 'Состояние записи уже изменилось. Обновите данные аккаунта.'
    case 'no_failed_creation':
      return 'Не найдена завершившаяся с ошибкой операция создания. Автоматическое восстановление недоступно.'
    case 'busy':
      return 'Есть незавершённая операция. Дождитесь её завершения и проверьте состояние снова.'
    case 'managed_bindings':
      return 'У записи есть управляемые права. Сначала нужно проверить связанные операции доступа.'
    case 'role_policy':
      return 'Эта роль связана с шаблоном доступа. Проверьте его состояние во вкладке «Роли».'
    case 'connection_unavailable':
      return 'Подключение сейчас недоступно для восстановления. Восстановите его работу и повторите проверку.'
    case 'connection_admin':
      return 'Это учётная запись подключения. Её восстановление выполняется через настройки подключения.'
    case 'creation_outcome_unknown':
      return 'Результат создания не подтверждён. Сначала проверьте, появилась ли учётка в базе; повторное создание не запускается.'
    case 'creation_intent_changed':
      return 'Параметры учётки или подключения изменились. Администратору нужно проверить их перед продолжением.'
    default:
      return 'Безопасное восстановление сейчас недоступно. Проверьте состояние операции или обратитесь к администратору.'
  }
}

interface AccountProvisioningNoticeProps {
  account: Account
  provisioning: ProvisioningQuery
  isAdmin: boolean
  canOperate: boolean
  onOperationStarted: (operationId: string, label: string, anchor?: OperationAnchor) => void
}

export function AccountProvisioningNotice(props: AccountProvisioningNoticeProps) {
  return <AccountProvisioningSession key={props.account.id} {...props} />
}

function AccountProvisioningSession({
  account,
  provisioning,
  isAdmin,
  canOperate,
  onOperationStarted,
}: AccountProvisioningNoticeProps) {
  const queryClient = useQueryClient()
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [retryOpen, setRetryOpen] = useState(false)
  const [retrySourceId, setRetrySourceId] = useState<string | null>(null)
  const [uncertain, setUncertain] = useState(false)
  const [discoveryId, setDiscoveryId] = useState<string | null>(null)
  const [discoveryFailure, setDiscoveryFailure] = useState<string | null>(null)
  const submission = useRef<RecoveryRequest | null>(null)
  const inFlight = useRef(false)
  const retryInFlight = useRef(false)
  const handledDiscovery = useRef<string | null>(null)
  const verificationSubmission = useRef<VerificationSubmission | null>(null)
  const verificationInFlight = useRef(false)
  const mounted = useRef(true)
  const [verificationChecking, setVerificationChecking] = useState(false)
  const [verificationUncertain, setVerificationUncertain] = useState(false)
  const [verificationGuardError, setVerificationGuardError] = useState<string | null>(null)
  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])
  const data = provisioning.data
  // Never use cached eligibility after a failed read. The server remains the
  // final guard; updated_at and the source operation pin the approved intent.
  const eligible = !verificationUncertain && !creationAlreadyStarted(data) &&
    !provisioning.isError && !provisioning.isFetching &&
    data?.account_id === account.id && data.state === 'failed' &&
    data.recoverable === true && typeof data.operation_id === 'string' &&
    data.operation_id !== '' && typeof data.updated_at === 'string' && data.updated_at !== ''
  const canRetryCreation = canOperate && !uncertain && !verificationUncertain && !creationAlreadyStarted(data) &&
    !provisioning.isError && !provisioning.isFetching &&
    data?.account_id === account.id && data.state === 'failed' && data.retryable === true &&
    ['account.create', 'role.create', 'postgres.account.create.v2', 'postgres.account.provision.v1', 'postgres.role.create.v2']
      .includes(data.operation_kind ?? '') &&
    typeof data.operation_id === 'string' && data.operation_id !== ''
  const canVerify = canOperate && !uncertain && discoveryId === null &&
    !provisioning.isPending && !provisioning.isError && !provisioning.isFetching && readyToVerify(data, account)

  const discovery = useQuery({
    queryKey: qk.operation(discoveryId ?? ''),
    queryFn: async ({ signal }) => {
      const result = await api<Operation>(`/api/v1/operations/${discoveryId}`, { signal })
      if (result?.id !== discoveryId || typeof result.status !== 'string') {
        throw new Error('server response did not confirm recovery operation status')
      }
      return result
    },
    enabled: discoveryId !== null,
    retry: false,
    refetchInterval: (query) => query.state.status !== 'error' &&
      (query.state.data === undefined || operationInProgress(query.state.data.status))
      ? POLL_OPERATION_MS
      : false,
    refetchIntervalInBackground: false,
  })

  const invalidateInventory = () => {
    void queryClient.invalidateQueries({ queryKey: qk.connection(account.connection_id) })
    void queryClient.invalidateQueries({ queryKey: qk.accounts() })
    void queryClient.invalidateQueries({ queryKey: qk.resources() })
    void queryClient.invalidateQueries({ queryKey: qk.operations() })
    void queryClient.invalidateQueries({ queryKey: qk.principals() })
    void queryClient.invalidateQueries({ queryKey: qk.drift() })
  }

  useEffect(() => {
    const operation = discovery.data
    if (discoveryId === null || discovery.isError || operation === undefined ||
      operationInProgress(operation.status) || handledDiscovery.current === operation.id) return
    handledDiscovery.current = operation.id
    submission.current = null
    setDiscoveryId(null)
    setDiscoveryFailure(operation.status === 'success' ? null : (
      operation.error || 'Синхронизация не смогла подтвердить существующую учётную запись.'
    ))
    invalidateInventory()
  }, [discovery.data, discovery.isError, discoveryId])

  const recovery = useMutation({
    mutationFn: async (request: RecoveryRequest) => {
      const result = await apiPost<RecoveryResponse>(
        `/api/v1/accounts/${account.id}/recover-provisioning`, request,
      )
      if (result?.account_id !== account.id ||
        !['pending', 'running', 'success', 'failed', 'cancelled'].includes(result.status) ||
        typeof result.operation_id !== 'string' || result.operation_id === '') {
        throw new Error('server response did not confirm provisioning recovery')
      }
      return result
    },
    retry: false,
    onSuccess: (result) => {
      setDiscoveryId(result.operation_id)
      setDiscoveryFailure(null)
      handledDiscovery.current = null
      setUncertain(false)
      setConfirmOpen(false)
      onOperationStarted(result.operation_id, `Восстановление из кластера · ${account.engine_identity}`, 'account')
      invalidateInventory()
    },
    onError: (error: unknown) => {
      // A lost response may follow a committed recovery. Retrying must retain
      // the entire original request, even if the next GET no longer shows a
      // provisioning record. Server deduplication precedes the CAS guards.
      const rejected = error instanceof ApiError && error.status >= 400 && error.status < 500
      setUncertain(!rejected)
      if (rejected) {
        submission.current = null
        void provisioning.refetch()
      }
    },
    onSettled: () => { inFlight.current = false },
  })

  const submit = () => {
    if (!isAdmin || inFlight.current || discoveryId !== null || retryInFlight.current || verificationInFlight.current || verificationUncertain) return
    if (submission.current === null) {
      if (!eligible || data?.operation_id === undefined) return
      submission.current = {
        request_id: globalThis.crypto.randomUUID(),
        updated_at: data.updated_at,
        operation_id: data.operation_id,
      }
    }
    inFlight.current = true
    recovery.mutate(submission.current)
  }

  const retryCreation = useMutation({
    mutationFn: async (operationId: string) => {
      const result = await apiPost<RetryOperationResponse>(`/api/v1/operations/${operationId}/retry`)
      if (result?.operation_id !== operationId) {
        throw new Error('server response did not confirm creation retry')
      }
      return result
    },
    retry: false,
    onSuccess: (result) => {
      setRetryOpen(false)
      setDiscoveryFailure(null)
      onOperationStarted(result.operation_id, `Повтор создания · ${account.engine_identity}`, 'account')
      invalidateInventory()
    },
    onError: () => { void provisioning.refetch() },
    onSettled: () => { retryInFlight.current = false },
  })

  const submitRetry = () => {
    if (!canRetryCreation || retryInFlight.current || inFlight.current ||
      verificationInFlight.current || verificationUncertain ||
      discoveryId !== null || retrySourceId === null || data?.operation_id !== retrySourceId) return
    retryInFlight.current = true
    retryCreation.mutate(retrySourceId)
  }

  const verification = useMutation({
    retry: false,
    mutationFn: async (intent: VerificationSubmission) => {
      const result = await apiPost<VerificationResponse>(
        `/api/v1/accounts/${intent.accountId}/verify-creation`, intent.request,
      )
      if (result?.account_id !== intent.accountId || result.verification_only !== true ||
        typeof result.operation_id !== 'string' || result.operation_id === '' ||
        !['pending', 'pending_approval', 'running', 'success', 'partial', 'failed', 'cancelled'].includes(result.status)) {
        throw new Error('server response did not confirm verification-only continuation')
      }
      return result
    },
    onSuccess: (result, intent) => {
      if (!mounted.current || intent.accountId !== account.id) return
      verificationSubmission.current = null
      setVerificationUncertain(false)
      setVerificationGuardError(null)
      onOperationStarted(result.operation_id, `Проверка учётки · ${account.engine_identity}`, 'account')
      void provisioning.refetch()
      invalidateInventory()
    },
    onError: (error: unknown, intent) => {
      if (!mounted.current || intent.accountId !== account.id) return
      // Only a definite rejection releases the pinned request. An unknown
      // acknowledgement is retried with the same ID before the server CAS.
      const rejected = error instanceof ApiError && error.status >= 400 && error.status < 500 &&
        error.status !== 408 && error.status !== 429
      setVerificationUncertain(!rejected)
      if (rejected) {
        verificationSubmission.current = null
        void provisioning.refetch()
      }
    },
    onSettled: () => { verificationInFlight.current = false },
  })

  const submitVerification = async () => {
    if (!canOperate || verificationInFlight.current || inFlight.current || retryInFlight.current ||
      discoveryId !== null || uncertain) return
    const pinned = verificationSubmission.current
    if (pinned !== null) {
      if (!verificationUncertain || pinned.accountId !== account.id) return
      verificationInFlight.current = true
      verification.mutate(pinned)
      return
    }
    if (!canVerify || data?.operation_id === undefined) return
    const sourceOperationId = data.operation_id
    verificationInFlight.current = true
    setVerificationChecking(true)
    setVerificationGuardError(null)
    verification.reset()
    const fresh = await provisioning.refetch()
    if (!mounted.current) return
    setVerificationChecking(false)
    if (!fresh.isSuccess || !readyToVerify(fresh.data, account) || fresh.data?.operation_id !== sourceOperationId) {
      verificationInFlight.current = false
      setVerificationGuardError('Состояние создания изменилось или недоступно. Проверьте состояние и повторите продолжение.')
      return
    }
    const intent: VerificationSubmission = {
      accountId: account.id,
      request: {
        request_id: globalThis.crypto.randomUUID(),
        updated_at: fresh.data.updated_at,
        operation_id: sourceOperationId,
      },
    }
    verificationSubmission.current = intent
    verification.mutate(intent)
  }
  const verificationBusy = verificationChecking || verification.isPending

  const retryRead = () => {
    setVerificationGuardError(null)
    void provisioning.refetch()
    void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(account.connection_id) })
  }
  const retryButton = (
    <Button variant="outline" size="sm" disabled={provisioning.isFetching} onClick={retryRead}>
      {provisioning.isFetching ? <Spinner className="size-3.5" /> : <RefreshCw className="size-3.5" aria-hidden="true" />}
      Проверить состояние
    </Button>
  )

  if (discoveryId !== null) {
    return (
      <section aria-label="Состояние восстановления" className="space-y-2 text-sm text-muted">
        {discovery.isError ? (
          <>
            <p role="alert">Не удалось проверить синхронизацию. Повтор создания автоматически не запускается.</p>
            <Button variant="outline" size="sm" disabled={discovery.isFetching} onClick={() => void discovery.refetch()}>
              Проверить синхронизацию
            </Button>
          </>
        ) : (
          <p role="status">Синхронизация запущена. Запись будет восстановлена только после обнаружения учётной записи в кластере.</p>
        )}
        <Link to="/control" search={{ tab: 'operations', operation: discoveryId }} className="text-accent underline underline-offset-4">
          Открыть синхронизацию
        </Link>
      </section>
    )
  }

  return (
    <>
      <section aria-label="Состояние создания" className="min-w-0 space-y-2 text-sm text-muted">
        {discoveryFailure !== null && (
          <div role="alert">
            <ErrorBanner>
              <p>Восстановление не завершено. Запись создания сохранена; повтор автоматически не запускается.</p>
              <p className="mt-1 [overflow-wrap:anywhere]">{discoveryFailure}</p>
            </ErrorBanner>
          </div>
        )}
        {provisioning.isPending ? (
          <p role="status" className="flex items-center gap-2">
            <Spinner className="size-3.5 shrink-0" />
            Проверяем операцию создания…
          </p>
        ) : provisioning.isError ? (
          <div role="alert">
            <ErrorBanner>
              <p>Не удалось проверить создание: {errorMessage(provisioning.error)}.</p>
              <p className="mt-1">{creationAlreadyStarted(data)
                ? 'Продолжение недоступно до успешной проверки состояния.'
                : 'Восстановление недоступно до успешной проверки.'}</p>
            </ErrorBanner>
          </div>
        ) : data?.state === 'running' ? (
          <p role="status">Операция ещё выполняется. Действия с аккаунтом доступны после завершения создания.</p>
        ) : data?.state === 'failed' ? (
          <>
            {data.creation_phase === 'created' && data.account_id === account.id ? (
              <p>Учётка уже создана. Не завершена только проверка входа: после исправления доступа продолжите создание. Пароль не меняется, учётка повторно не создаётся.</p>
            ) : data.blocked_reason === 'creation_outcome_unknown' ? null : (
              <p>Операция создания завершилась с ошибкой. Ожидание не завершит создание аккаунта.</p>
            )}
            {data.operation_error && (
              <details>
                <summary className="cursor-pointer text-danger">Причина ошибки</summary>
                <p className="mt-1 whitespace-pre-wrap [overflow-wrap:anywhere]">{data.operation_error}</p>
              </details>
            )}
            {creationAlreadyStarted(data) ? (
              !data.verification_ready && <p>{provisioningBlockedReason(data.blocked_reason)}</p>
            ) : data.recoverable ? (
              <p>
                {isAdmin
                  ? 'Можно перечитать существующую учётную запись из кластера. Её пароль, права и владение базами не изменятся.'
                  : 'Восстановить запись из кластера может администратор Grantor. Пароль, права и владение базами при этом не меняются.'}
              </p>
            ) : (
              <p>{provisioningBlockedReason(data.blocked_reason)}</p>
            )}
          </>
        ) : (
          <p role="alert">{provisioningBlockedReason(data?.blocked_reason)}</p>
        )}
        {verificationGuardError !== null && <p role="alert">{verificationGuardError}</p>}
        {verification.isError && <div role="alert"><ErrorBanner>
          {verificationUncertain
            ? 'Результат запроса не подтверждён. Повторите тот же запрос: это только проверка уже созданной учётки.'
            : `Проверка не запущена: ${errorMessage(verification.error)}. Проверьте состояние перед продолжением.`}
        </ErrorBanner></div>}
        <div className="flex flex-wrap items-center gap-2">
          {canOperate && (canVerify || verificationBusy || verificationUncertain) && (
            <Button size="sm" className="grantor-touch-target" disabled={verificationBusy || recovery.isPending || retryCreation.isPending}
              onClick={() => void submitVerification()}>
              {verificationBusy && <Spinner className="size-3.5" />}
              {verificationBusy ? 'Проверяем…' : verificationUncertain ? 'Повторить запрос проверки' : 'Продолжить создание'}
            </Button>
          )}
          {isAdmin && (eligible || uncertain) && (
            <Button
              size="sm"
              onClick={() => setConfirmOpen(true)}
              disabled={recovery.isPending || retryCreation.isPending || verificationBusy}
            >
              <RefreshCw className="size-3.5" aria-hidden="true" />
              {uncertain ? 'Повторить запрос восстановления' : 'Восстановить из кластера'}
            </Button>
          )}
          {canRetryCreation && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                retryCreation.reset()
                setRetrySourceId(data?.operation_id ?? null)
                setRetryOpen(true)
              }}
              disabled={recovery.isPending || retryCreation.isPending || verificationBusy}
            >
              Повторить создание
            </Button>
          )}
          {!provisioning.isPending && retryButton}
          {data?.operation_id && (
            <Link
              to="/control"
              search={{ tab: 'operations', operation: data.operation_id }}
              className="text-sm text-accent underline underline-offset-4 [overflow-wrap:anywhere]"
            >
              Открыть операцию
            </Link>
          )}
        </div>
      </section>
      <Dialog
        open={confirmOpen}
        title="Восстановить из кластера"
        onClose={() => { if (!recovery.isPending) setConfirmOpen(false) }}
        footer={
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" disabled={recovery.isPending} onClick={() => setConfirmOpen(false)}>
              Отмена
            </Button>
            <Button
              disabled={recovery.isPending || (!eligible && !uncertain) || !isAdmin}
              onClick={submit}
            >
              {recovery.isPending && <Spinner className="size-3.5" />}
              {uncertain ? 'Повторить запрос' : 'Восстановить из кластера'}
            </Button>
          </div>
        }
      >
        <div className="space-y-3 text-sm text-muted">
          <p>
            Grantor сначала проверит, есть ли в кластере запись{' '}
            <span className="font-mono text-text [overflow-wrap:anywhere]">{account.engine_identity}</span>{' '}
            и прочитает её фактическое состояние.
          </p>
          <p>Роль в кластере, её пароль, права и владение базами не изменятся. В целевой системе ничего не удаляется и не создаётся.</p>
          <p>
            Только после подтверждения Grantor снимет незавершённое создание и перестанет использовать
            непроверенный пароль. Найденную запись можно будет принять под управление отдельно.
          </p>
          <p>
            Если запись не найдена или кластер недоступен, незавершённое создание и сохранённые параметры останутся без изменений.
          </p>
          {recovery.isError && (
            <div role="alert">
              <ErrorBanner>
                {uncertain
                  ? 'Результат запроса не подтверждён. Повторите запрос: Grantor проверит то же восстановление, не запуская повторное.'
                  : `Восстановление не запущено: ${errorMessage(recovery.error)}`}
              </ErrorBanner>
            </div>
          )}
          {!uncertain && !eligible && !recovery.isPending && (
            <div className="space-y-2">
              <p>{provisioningBlockedReason(data?.blocked_reason)}</p>
              {retryButton}
            </div>
          )}
        </div>
      </Dialog>
      <Dialog
        open={retryOpen}
        title="Повторить создание"
        onClose={() => { if (!retryCreation.isPending) setRetryOpen(false) }}
        footer={
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" disabled={retryCreation.isPending} onClick={() => setRetryOpen(false)}>Отмена</Button>
            <Button disabled={!canRetryCreation || data?.operation_id !== retrySourceId || retryCreation.isPending} onClick={submitRetry}>
              {retryCreation.isPending && <Spinner className="size-3.5" />}
              Повторить создание
            </Button>
          </div>
        }
      >
        <div className="space-y-3 text-sm text-muted">
          <p>
            Grantor повторит операцию создания{' '}
            <span className="font-mono text-text [overflow-wrap:anywhere]">{account.engine_identity}</span>{' '}
            с ранее заданными параметрами. При успехе учётная запись будет создана в целевой системе.
          </p>
          <p>
            Это изменение кластера, а не проверка существующей записи. Если учётная запись уже есть,
            создание будет отклонено: для неё используйте «Восстановить из кластера».
          </p>
          {retryCreation.isError && (
            <div role="alert">
              <ErrorBanner>Не удалось подтвердить повтор создания: {errorMessage(retryCreation.error)}. Проверьте состояние операции.</ErrorBanner>
            </div>
          )}
          {(!canRetryCreation || data?.operation_id !== retrySourceId) && !retryCreation.isPending && (
            <div className="space-y-2">
              <p>{data?.state === 'running' ? 'Операция уже выполняется.' : provisioningBlockedReason(data?.blocked_reason)}</p>
              {retryButton}
            </div>
          )}
          {data?.operation_id && (
            <Link to="/control" search={{ tab: 'operations', operation: data.operation_id }} className="text-accent underline underline-offset-4">
              Открыть операцию
            </Link>
          )}
        </div>
      </Dialog>
    </>
  )
}
