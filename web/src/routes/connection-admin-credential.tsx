import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import type { QueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { KeyRound, RotateCw, ShieldAlert, UserRoundCog } from '@project/ui/icons'
import { api } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { qk } from '../lib/queryKeys'
import { operationStatusLabel } from '../lib/operation-presentation'
import { operationStatusTone, shortId } from '../lib/status'
import { formatDateTime } from '../lib/time'
import type {
  Connection,
  ConnectionAdminCredentialChangeMode,
  ConnectionAuthMode,
} from '../lib/types'
import { Button } from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { Dialog } from '@project/ui'
import { ErrorBanner } from '@project/ui'
import { Field, Input } from '@project/ui'
import { IconButton } from '@project/ui'
import { RadioOptionCard } from '@project/ui'
import { Spinner } from '@project/ui'
import { ConnectionAuthModeField, RedisNoAuthNotice } from './connection-auth-mode-field'

export const ADMIN_CREDENTIAL_SWITCH_CAPABILITY = 'connection.admin_credential.switch'
export const ADMIN_CREDENTIAL_ROTATE_CAPABILITY = 'connection.admin_credential.rotate'

const ACTIVE_OPERATION_STATUSES = new Set(['pending', 'pending_approval', 'running'])
const TERMINAL_PHASES = new Set(['completed', 'failed', 'cancelled'])

async function invalidateAdminCredentialQueries(
  queryClient: QueryClient,
  connectionId: string,
) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: qk.connection(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.connections() }),
    queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.connectionResources(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.connectionResourceTree(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.drift(connectionId) }),
    queryClient.invalidateQueries({ queryKey: qk.operations() }),
  ])
}

export function canSwitchAdminCredential(connection: Connection): boolean {
  return connection.capabilities.includes(ADMIN_CREDENTIAL_SWITCH_CAPABILITY) ||
    (connection.engine === 'redis' && connection.auth_mode === 'none') ||
    connection.vault_admin_path !== ''
}

export function canRotateAdminCredential(connection: Connection): boolean {
  return connection.auth_mode !== 'none' && connection.capabilities.includes(ADMIN_CREDENTIAL_ROTATE_CAPABILITY)
}

export function canManageAdminCredential(isAdmin: boolean, connection: Connection): boolean {
  return isAdmin && (canSwitchAdminCredential(connection) || canRotateAdminCredential(connection))
}

export function isTerminalAdminCredentialChange(
  change: Connection['admin_credential_change'],
): boolean {
  if (change === null || change === undefined) return false
  return !ACTIVE_OPERATION_STATUSES.has(change.status) &&
    (TERMINAL_PHASES.has(change.phase) ||
      change.status === 'success' || change.status === 'failed' ||
      change.status === 'cancelled' || change.status === 'partial')
}

export function shouldPollAdminCredentialChange(connection: Connection | undefined): boolean {
  if (connection === undefined) return false
  if (connection.status === 'credential_updating') return true
  const change = connection.admin_credential_change
  return change !== null && change !== undefined && ACTIVE_OPERATION_STATUSES.has(change.status)
}

const MODE_LABELS: Record<ConnectionAdminCredentialChangeMode, string> = {
  switch: 'Смена учётки',
  rotate: 'Ротация пароля',
}

const PHASE_LABELS: Record<string, string> = {
  preparing: 'Подготовка candidate',
  staged: 'Candidate сохранён',
  candidate_proving: 'Проверка candidate',
  target_applying: 'Изменение target',
  target_applied: 'Target изменён',
  promoting: 'Продвижение в Vault',
  promoted: 'Credential продвинут',
  metadata_committing: 'Фиксация metadata',
  completed: 'Завершено',
  failed: 'Ошибка',
  cancelled: 'Отменено',
}

const ERROR_CODE_LABELS: Record<string, string> = {
  invalid_candidate: 'Candidate credential не прошёл проверку; действующий credential сохранён.',
  rotation_unsupported: 'Self-rotation недоступна для обнаруженной конфигурации.',
  admin_authority_changed: 'Admin privileges изменились во время операции.',
  old_credential_still_valid: 'Старый credential всё ещё принимается target; ротация не подтверждена.',
  target_identity_changed: 'Endpoint больше не доказывает исходную identity target.',
  canonical_version_changed: 'Canonical credential изменился до начала target mutation; создайте новый запрос после проверки Vault.',
  vault_unavailable: 'Vault временно недоступен.',
  connector_unavailable: 'Connector временно недоступен.',
  metadata_commit_failed: 'Target/Vault могли измениться, но metadata commit не подтверждён.',
  internal_error: 'Внутренняя ошибка без раскрытия credential.',
}

function fallbackToken(value: string): string {
  const normalized = value.replaceAll('_', ' ').trim()
  return normalized === '' ? value : normalized.charAt(0).toLocaleUpperCase() + normalized.slice(1)
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length
}

function passwordIsValid(password: string): boolean {
  return password !== '' && utf8Bytes(password) <= 8_192 && !password.includes('\0')
}

export function adminCredentialPhaseLabel(phase: string): string {
  return PHASE_LABELS[phase] ?? fallbackToken(phase)
}

export function adminCredentialErrorLabel(code: string | null): string {
  if (code === null || code === '') return ''
  return ERROR_CODE_LABELS[code] ?? `Операция завершилась с безопасным кодом ошибки: ${code}.`
}

interface CredentialOperationResponse {
  operation_id: string
}

type DialogAction = ConnectionAdminCredentialChangeMode
type RotatePasswordMode = 'generated' | 'provided'

interface SubmissionIntent {
  path: string
  body: Record<string, unknown>
}

export interface ConnectionAdminCredentialDialogProps {
  connection: Connection
  open: boolean
  onClose: () => void
  onStarted: (operationId: string, mode: DialogAction, reconciled: boolean) => void
}

export function ConnectionAdminCredentialDialog({
  connection,
  open,
  onClose,
  onStarted,
}: ConnectionAdminCredentialDialogProps) {
  const queryClient = useQueryClient()
  const switchAvailable = canSwitchAdminCredential(connection)
  const rotateAvailable = canRotateAdminCredential(connection)
  const [action, setAction] = useState<DialogAction>(switchAvailable ? 'switch' : 'rotate')
  const [rotateMode, setRotateMode] = useState<RotatePasswordMode>('generated')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [authMode, setAuthMode] = useState<ConnectionAuthMode>(connection.auth_mode ?? 'password')
  const [requestId, setRequestId] = useState('')
  const [updatedAt, setUpdatedAt] = useState('')
  const [formError, setFormError] = useState<string | null>(null)
  const [submittedOnce, setSubmittedOnce] = useState(false)
  const submissionRef = useRef<SubmissionIntent | null>(null)
  const usernameRef = useRef<HTMLInputElement>(null)
  const wasOpenRef = useRef(false)

  const reset = (nextAction: DialogAction = switchAvailable ? 'switch' : 'rotate') => {
    setAction(nextAction)
    setRotateMode('generated')
    setUsername('')
    setPassword('')
    setAuthMode(connection.auth_mode ?? 'password')
    setRequestId(globalThis.crypto.randomUUID())
    setUpdatedAt(connection.updated_at)
    setFormError(null)
    setSubmittedOnce(false)
    submissionRef.current = null
  }

  useEffect(() => {
    if (open && !wasOpenRef.current) reset()
    wasOpenRef.current = open
  // reset is intentionally tied to the opening edge, not every phase refetch.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open])

  const invalidate = async () => {
    await invalidateAdminCredentialQueries(queryClient, connection.id)
  }

  const mutation = useMutation({
    mutationFn: () => {
      const submission = submissionRef.current
      submissionRef.current = null
      if (submission === null) throw new Error('admin credential submission is unavailable')
      return api<CredentialOperationResponse>(submission.path, {
        method: 'POST',
        body: submission.body,
      })
    },
    onSuccess: async (response) => {
      setPassword('')
      setFormError(null)
      await invalidate()
      onStarted(response.operation_id, action, false)
      onClose()
    },
    onError: async (error: unknown) => {
      setPassword('')
      setSubmittedOnce(true)
      setFormError(errorMessage(error))
      await invalidate()
    },
  })

  useEffect(() => {
    if (!open || formError === null) return
    const change = connection.admin_credential_change
    if (change === null || change === undefined || change.operation_id !== requestId) return
    setPassword('')
    setFormError(null)
    void invalidateAdminCredentialQueries(queryClient, connection.id)
    onStarted(change.operation_id, change.mode, true)
    onClose()
  }, [connection.admin_credential_change, connection.id, formError, onClose, onStarted, open, queryClient, requestId])

  const chooseAction = (next: DialogAction) => {
    if (mutation.isPending || next === action) return
    reset(next)
    mutation.reset()
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setFormError(null)
    const id = requestId || globalThis.crypto.randomUUID()
    if (requestId === '') setRequestId(id)
    const common = { request_id: id, updated_at: updatedAt }
    if (action === 'switch') {
      const candidateUsername = username.trim()
      const noAuth = connection.engine === 'redis' && authMode === 'none'
      if (!noAuth && (candidateUsername === '' || utf8Bytes(candidateUsername) > 512 ||
        /[\u0000-\u001f\u007f]/.test(candidateUsername) || !passwordIsValid(password))) {
        setFormError('Укажите username и password готового admin credential.')
        return
      }
      submissionRef.current = {
        path: `/api/v1/connections/${connection.id}/admin-credential/switch`,
        body: noAuth ? { ...common, auth_mode: 'none' } : { ...common, ...(connection.engine === 'redis' ? { auth_mode: 'password' } : {}), username: candidateUsername, password },
      }
    } else if (rotateMode === 'provided') {
      if (!passwordIsValid(password)) {
        setFormError('Укажите новый password либо выберите генерацию.')
        return
      }
      submissionRef.current = {
        path: `/api/v1/connections/${connection.id}/admin-credential/rotate`,
        body: { ...common, mode: 'provided', password },
      }
    } else {
      submissionRef.current = {
        path: `/api/v1/connections/${connection.id}/admin-credential/rotate`,
        body: { ...common, mode: 'generated' },
      }
    }
    // Secret leaves controlled state before React Query observes the mutation.
    setPassword('')
    setSubmittedOnce(true)
    mutation.mutate()
  }

  const close = () => {
    if (mutation.isPending) return
    setPassword('')
    setFormError(null)
    submissionRef.current = null
    onClose()
  }
  const formId = 'connection-admin-credential-form'
  const needsPassword = action === 'switch' ? authMode !== 'none' : rotateMode === 'provided'

  return (
    <Dialog
      open={open}
      onClose={close}
      title="Admin credential подключения"
      description="Смена учётки либо безопасная self-rotation admin credential"
      closeOnOverlayClick={false}
      initialFocusRef={action === 'switch' && authMode !== 'none' ? usernameRef : undefined}
      footer={(
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={close} disabled={mutation.isPending}>
            Отмена
          </Button>
          <Button type="submit" form={formId} disabled={mutation.isPending || (needsPassword && password === '')}>
            {mutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            {submittedOnce ? 'Повторить запрос' : action === 'switch' ? 'Проверить и сменить' : 'Запустить ротацию'}
          </Button>
        </div>
      )}
    >
      <form id={formId} onSubmit={submit} className="space-y-4" autoComplete="off">
        <div className="space-y-1.5" role="radiogroup" aria-label="Операция с admin credential">
          {switchAvailable && (
            <RadioOptionCard
              name="admin-credential-action"
              label="Сменить учётку"
              hint={connection.engine === 'redis' ? 'Проверить готовую учетку или явно выбрать подключение без пароля' : 'Проверить готовые username/password и атомарно продвинуть их в canonical Vault path'}
              checked={action === 'switch'}
              onSelect={() => chooseAction('switch')}
            />
          )}
          {rotateAvailable && (
            <RadioOptionCard
              name="admin-credential-action"
              label="Ротировать password"
              hint="Candidate-first self-rotation доступна только после capability discovery"
              checked={action === 'rotate'}
              onSelect={() => chooseAction('rotate')}
            />
          )}
        </div>

        {action === 'switch' ? (
          <div className="space-y-3">
            {connection.engine === 'redis' && <ConnectionAuthModeField value={authMode} disabled={mutation.isPending} onChange={next => { setAuthMode(next); setUsername(''); setPassword('') }} />}
            {connection.engine === 'redis' && authMode === 'none' ? <RedisNoAuthNotice /> : <>
            <Field label="Username" hint="Identity готовой учётки на том же target">
              <Input
                ref={usernameRef}
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                className="font-mono text-[13px]"
                autoComplete="off"
                maxLength={512}
                required
              />
            </Field>
            <Field label="Password">
              <Input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="off"
                maxLength={8192}
                required
              />
            </Field>
            </>}
          </div>
        ) : (
          <div className="space-y-3">
            <div className="space-y-1.5" role="radiogroup" aria-label="Источник нового password">
              <RadioOptionCard
                name="admin-credential-rotate-mode"
                label="Сгенерировать"
                hint="Grantor создаст candidate; значение не возвращается в UI"
                checked={rotateMode === 'generated'}
                onSelect={() => {
                  setRotateMode('generated')
                  setPassword('')
                }}
              />
              <RadioOptionCard
                name="admin-credential-rotate-mode"
                label="Задать password"
                hint="Значение используется только для candidate и не сохраняется в форме"
                checked={rotateMode === 'provided'}
                onSelect={() => setRotateMode('provided')}
              />
            </div>
            {rotateMode === 'provided' && (
              <Field label="Новый password">
                <Input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="off"
                  maxLength={8192}
                  required
                />
              </Field>
            )}
          </div>
        )}

        <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-xs leading-relaxed text-warn">
          <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <p>
            Candidate сначала доказывается на target. После первого возможного target/Vault side effect
            операция становится forward-only: её можно только повторять либо запустить явное обратное изменение.
          </p>
        </div>

        {formError !== null && (
          <div role="alert">
            <ErrorBanner>
              <p>{formError}</p>
              {submittedOnce && !mutation.isPending && needsPassword && (
                <p className="mt-1 text-xs">
                  Password очищен. При повторе с тем же request_id введите тот же candidate password заново.
                </p>
              )}
            </ErrorBanner>
          </div>
        )}
      </form>
    </Dialog>
  )
}

const ROTATE_PHASE_ORDER = [
  'preparing',
  'staged',
  'candidate_proving',
  'target_applying',
  'target_applied',
  'promoting',
  'promoted',
  'metadata_committing',
  'completed',
] as const

const SWITCH_PHASE_ORDER = [
  'preparing',
  'staged',
  'candidate_proving',
  'promoting',
  'promoted',
  'metadata_committing',
  'completed',
] as const

export interface AdminCredentialChangePanelProps {
  connection: Connection
  isAdmin: boolean
  onNotice: (message: string) => void
  onRefresh: () => void
}

export function AdminCredentialChangePanel({
  connection,
  isAdmin,
  onNotice,
  onRefresh,
}: AdminCredentialChangePanelProps) {
  const queryClient = useQueryClient()
  const change = connection.admin_credential_change
  const [cancelIntent, setCancelIntent] = useState<{
    request_id: string
    updated_at: string
  } | null>(null)
  const [cancelError, setCancelError] = useState<string | null>(null)
  const cancelSubmissionRef = useRef<{ request_id: string; updated_at: string } | null>(null)

  useEffect(() => {
    setCancelIntent(null)
    setCancelError(null)
    cancelSubmissionRef.current = null
  }, [change?.operation_id])

  useEffect(() => {
    if (change === null || change === undefined ||
      !change.cancel_allowed || change.target_side_effect_possible || TERMINAL_PHASES.has(change.phase)) {
      setCancelIntent(null)
      cancelSubmissionRef.current = null
    }
  }, [change])

  const cancelMutation = useMutation({
    mutationFn: () => {
      const body = cancelSubmissionRef.current
      cancelSubmissionRef.current = null
      if (body === null) throw new Error('admin credential cancel intent is unavailable')
      return api<CredentialOperationResponse>(
        `/api/v1/connections/${connection.id}/admin-credential/cancel`,
        { method: 'POST', body },
      )
    },
    onSuccess: async (response) => {
      setCancelIntent(null)
      setCancelError(null)
      await invalidateAdminCredentialQueries(queryClient, connection.id)
      onNotice(`Операция ${shortId(response.operation_id)} отменяется до внешнего side effect.`)
    },
    onError: async (error: unknown) => {
      setCancelError(errorMessage(error))
      await invalidateAdminCredentialQueries(queryClient, connection.id)
    },
  })

  if ((change === null || change === undefined) && connection.status !== 'credential_updating') {
    return null
  }
  if (change === null || change === undefined) {
    return (
      <section className="rounded-md border border-warn/40 bg-warn-soft p-3" aria-label="Admin credential progress" aria-live="polite">
        <div className="flex items-center gap-2 text-sm text-warn">
          <Spinner className="size-4" />
          Состояние credential operation ещё не загрузилось.
        </div>
        <Button variant="outline" size="sm" className="mt-2" onClick={onRefresh}>
          Повторить загрузку
        </Button>
      </section>
    )
  }

  const phaseOrder: readonly string[] = change.mode === 'switch'
    ? SWITCH_PHASE_ORDER
    : ROTATE_PHASE_ORDER
  const phaseIndex = phaseOrder.indexOf(change.phase)
  const cancelVisible = isAdmin && change.cancel_allowed &&
    !change.target_side_effect_possible
  const retryAvailable = change.retryable &&
    (change.status === 'failed' || change.status === 'partial')
  const startCancel = () => {
    const intent = cancelIntent ?? {
      request_id: globalThis.crypto.randomUUID(),
      updated_at: connection.updated_at,
    }
    if (cancelIntent === null) setCancelIntent(intent)
    cancelSubmissionRef.current = intent
    cancelMutation.mutate()
  }

  return (
    <section className="space-y-3 rounded-md border border-line bg-panel p-3" aria-labelledby="admin-credential-progress-title">
      <p className="sr-only" aria-live="polite">
        Admin credential: {MODE_LABELS[change.mode]}; {operationStatusLabel(change.status)};
        {adminCredentialPhaseLabel(change.phase)}.
      </p>
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <KeyRound className="size-4 text-muted" aria-hidden="true" />
            <h2 id="admin-credential-progress-title" className="text-sm font-semibold text-text">
              Admin credential · {MODE_LABELS[change.mode]}
            </h2>
            <StatusChip tone={operationStatusTone(change.status)}>
              {operationStatusLabel(change.status)}
            </StatusChip>
          </div>
          <p className="mt-1 text-xs text-muted">
            Phase: <span className="text-text">{adminCredentialPhaseLabel(change.phase)}</span>
            {change.started_at !== null && <>{' · '}запущено {formatDateTime(change.started_at)}</>}
            {' · '}обновлено {formatDateTime(change.updated_at)}
          </p>
        </div>
        <Link
          to="/control"
          search={{
            tab: 'operations',
            status: 'all',
            connection: connection.id,
            operation: change.operation_id,
            query: change.operation_id,
          }}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line px-3 text-xs text-text hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          Операция {shortId(change.operation_id)}
        </Link>
      </div>

      {phaseIndex >= 0 && !TERMINAL_PHASES.has(change.phase) && (
        <ol className="grid gap-1.5 sm:grid-cols-4" aria-label="Этапы credential operation">
          {phaseOrder.map((phase, index) => {
            const active = index === phaseIndex
            const done = index < phaseIndex
            return (
              <li
                key={phase}
                aria-current={active ? 'step' : undefined}
                className={`flex min-w-0 items-center gap-1.5 rounded px-2 py-1 text-[11px] ${active ? 'bg-warn-soft text-warn' : done ? 'text-ok' : 'text-faint'}`}
              >
                <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
                <span className="truncate">{adminCredentialPhaseLabel(phase)}</span>
              </li>
            )
          })}
        </ol>
      )}

      {change.target_side_effect_possible && change.status !== 'success' && (
        <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
          Учётные данные в целевой системе или Vault уже могли измениться. Отмена недоступна.
          Повторите исходную операцию в «Контроле» либо выполните обратное изменение после её завершения.
        </p>
      )}
      {change.error_code !== null && (
        <div className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-xs text-danger">
          <p>{adminCredentialErrorLabel(change.error_code)}</p>
          <p className="mt-1 font-mono text-[11px]">{change.error_code}</p>
        </div>
      )}
      {retryAvailable && (
        <p className="text-xs text-muted">
          Операция допускает top-level retry. Откройте её карточку в «Контроле» и повторите там.
        </p>
      )}
      {cancelError !== null && <div role="alert"><ErrorBanner>{cancelError}</ErrorBanner></div>}
      {cancelVisible && (
        <div className="flex justify-end">
          <Button variant="outline" size="sm" onClick={startCancel} disabled={cancelMutation.isPending}>
            {cancelMutation.isPending && <Spinner className="size-3.5" />}
            Отменить до side effect
          </Button>
        </div>
      )}
    </section>
  )
}

export function AdminCredentialControlButton({
  connection,
  isAdmin,
  busy,
  onOpen,
}: {
  connection: Connection
  isAdmin: boolean
  busy: boolean
  onOpen: () => void
}) {
  if (!canManageAdminCredential(isAdmin, connection)) return null
  return (
    <IconButton
      label="Управление admin credential"
      tone="outline"
      disabled={busy}
      icon={busy
        ? <RotateCw className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />
        : <UserRoundCog className="size-4" aria-hidden="true" />}
      onClick={onOpen}
    />
  )
}
