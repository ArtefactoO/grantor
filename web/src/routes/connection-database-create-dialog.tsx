// Создание базы: POST /connections/{id}/resources (admin, architecture §11.2).
//
// Отката у создания базы нет: DROP DATABASE grantor не выполняет никогда.
// Поэтому форма показывает ровно то, что уйдёт в CREATE DATABASE, и говорит об
// отсутствии отката прямо — цена ошибки здесь выше, чем у обычной мутации.
import { useEffect, useId, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { apiPost, ApiError } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type { Connection, Operation } from '../lib/types'
import { Dialog, Button, Field, Input, Spinner, ErrorBanner } from '@project/ui'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { OperationProgressNotice } from '../components/operation-progress-notice'
import { DatabaseOwnerField, useDatabaseOwnerInventory } from './connection-database-owner-field'
import type { DatabaseOwnerCandidate } from './connection-database-owner-field'

/** Ответ POST /connections/{id}/resources. */
interface CreateResourceResponse {
  resource_id: string
  operation_id: string
  create_default_roles?: boolean
}

interface CreateDatabaseRequest {
  name: string
  owner?: string
}

interface CreateDatabaseWithRolesRequest extends CreateDatabaseRequest {
  create_default_roles: true
  request_id: string
  updated_at: string
  expected_target_identity: string
}

function postgresTargetIdentity(connection: Connection): string | null {
  const topology = connection.topology
  if (typeof topology !== 'object' || topology === null || Array.isArray(topology)) return null
  const identifier = (topology as Record<string, unknown>).system_identifier
  return typeof identifier === 'string' && /^[0-9]{1,20}$/.test(identifier)
    ? `postgres:system:${identifier}` : null
}

function operationalPreview(connection: Connection): string {
  return JSON.stringify({
    engine: connection.engine,
    environment: connection.environment,
    execution_mode: connection.execution_mode,
    endpoints: connection.endpoints,
    tls_config: connection.tls_config,
    discovery_config: connection.discovery_config,
    admin_credential_mode: connection.admin_credential_mode,
    vault_admin_path: connection.vault_admin_path,
    admin_credential_operation: connection.admin_credential_change?.operation_id,
  }, (_key, value: unknown) => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return value
    const record = value as Record<string, unknown>
    return Object.fromEntries(Object.keys(record).sort().map((key) => [key, record[key]]))
  })
}

const PREVIEW_CHANGED = 'Подключение изменилось после открытия формы. Проверьте подключение и обновите контекст; введённые данные сохранятся.'
const IDENTITY_MISSING = 'Сначала синхронизируйте подключение, затем обновите контекст: идентификатор PostgreSQL-кластера не был подтверждён.'

export interface CreateDatabaseDialogProps {
  connection: Connection
  open: boolean
  onClose: () => void
  onStarted: (operationId: string, databaseName: string, createDefaultRoles?: boolean) => void
}

export function CreateDatabaseDialog(props: CreateDatabaseDialogProps) {
  return <CreateDatabaseSession key={props.connection.id} {...props} />
}

function CreateDatabaseSession({
  connection,
  open,
  onClose,
  onStarted,
}: CreateDatabaseDialogProps) {
  const queryClient = useQueryClient()
  const connectionId = connection.id
  const formId = useId()
  const [previewConnection, setPreviewConnection] = useState(() => structuredClone(connection))
  const [name, setName] = useState('')
  const [owner, setOwner] = useState('')
  const [ownerSelection, setOwnerSelection] = useState<DatabaseOwnerCandidate | null>(null)
  const [createDefaultRoles, setCreateDefaultRoles] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [pinnedIntent, setPinnedIntent] = useState<CreateDatabaseWithRolesRequest | null>(null)
  const intentRef = useRef<CreateDatabaseWithRolesRequest | null>(null)
  const pendingRef = useRef(false)
  const uncertainRef = useRef(false)
  const wasOpenRef = useRef(false)
  const isPostgres = previewConnection.engine === 'postgres'
  const { query: ownersQuery, candidates: ownerCandidates } = useDatabaseOwnerInventory(connection, open && isPostgres)
  const targetIdentity = postgresTargetIdentity(previewConnection)
  const authorityIssue = isPostgres ? postgresProvisioningIssue(previewConnection) : null
  const authorityBlockerId = `postgres-database-create-${previewConnection.id}-blocker`
  const previewChanged = operationalPreview(previewConnection) !== operationalPreview(connection) ||
    targetIdentity !== postgresTargetIdentity(connection) ||
    connection.status !== 'active' || !connection.capabilities.includes('resource.create.database') ||
    ['pending', 'pending_approval', 'running'].includes(connection.admin_credential_change?.status ?? '')

  useEffect(() => {
    // Closing/reopening after an unknown response must not create a new intent.
    if (open && !wasOpenRef.current && intentRef.current === null && !pendingRef.current &&
      name === '' && owner === '' && !createDefaultRoles) {
      setPreviewConnection(structuredClone(connection))
      setFormError(null)
    }
    wasOpenRef.current = open
  }, [open, connection, name, owner, createDefaultRoles])

  const selectedOwnerIssue = ownerSelection === null ? null
    : ownersQuery.isFetching ? 'Обновляем выбранную роль. Дождитесь проверки списка.'
    : ownersQuery.isError ? 'Выбранная роль не подтверждена: список недоступен. Обновите список или введите точное имя вручную.'
    : !ownerCandidates.some((candidate) => candidate.id === ownerSelection.id &&
      candidate.identity === ownerSelection.identity && candidate.roleOid === ownerSelection.roleOid)
      ? 'Выбранная роль больше не подтверждена снимком подключения. Выберите владельца заново или синхронизируйте подключение.'
      : null

  const createMutation = useMutation({
    retry: false,
    mutationFn: async (payload: CreateDatabaseRequest | CreateDatabaseWithRolesRequest) => {
      const withRoles = 'create_default_roles' in payload
      // The distinct route fails closed against older APIs that ignore unknown
      // fields on /resources. Never fall back to creating only the database.
      const response = await apiPost<CreateResourceResponse>(
        `/api/v1/connections/${connectionId}/resources${withRoles ? '/database-with-roles' : ''}`,
        payload,
      )
      if (typeof response?.operation_id !== 'string' || response.operation_id === '' ||
        (withRoles && response.create_default_roles !== true)) {
        throw new Error('API не подтвердил постановку запроса. Повторите отправку того же запроса.')
      }
      return response
    },
    onSuccess: (data, payload) => {
      intentRef.current = null
      setPinnedIntent(null)
      uncertainRef.current = false
      setFormError(null)
      setName('')
      setOwner('')
      setOwnerSelection(null)
      setCreateDefaultRoles(false)
      void queryClient.invalidateQueries({ queryKey: qk.connectionResources(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.connectionResourceTree(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      if ('create_default_roles' in payload) onStarted(data.operation_id, payload.name, true)
      else onStarted(data.operation_id, payload.name)
      onClose()
    },
    onError: (err: unknown) => {
      const rejected = err instanceof ApiError && err.status >= 400 && err.status < 500 &&
        err.status !== 408 && err.status !== 429
      if (rejected && !uncertainRef.current) {
        // A definite validation/permission rejection can be corrected without
        // erasing the draft. An uncertain accepted request stays fully pinned.
        intentRef.current = null
        setPinnedIntent(null)
      } else if (intentRef.current !== null) {
        uncertainRef.current = true
      }
      setFormError(errorMessage(err))
    },
    onSettled: () => { pendingRef.current = false },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (pendingRef.current) return
    setFormError(null)
    if (intentRef.current !== null) {
      pendingRef.current = true
      createMutation.mutate(intentRef.current)
      return
    }
    const databaseName = name.trim()
    if (databaseName === '') {
      setFormError('Укажите имя базы')
      return
    }
    if (/\s/.test(databaseName)) {
      setFormError('Имя базы не должно содержать пробельных символов')
      return
    }
    if (previewChanged) {
      setFormError(PREVIEW_CHANGED)
      return
    }
    if (isPostgres && authorityIssue !== null) {
      setFormError(authorityIssue)
      return
    }
    if (createDefaultRoles && isPostgres) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(databaseName)) {
        setFormError('Для пары r_/rw_ нужны латинские буквы, цифры и подчёркивания, без цифры в начале.')
        return
      }
      if (databaseName.length > 60) {
        setFormError('Для пары r_/rw_ имя базы должно быть не длиннее 60 символов. Имена ролей не сокращаются.')
        return
      }
      if (targetIdentity === null) {
        setFormError(IDENTITY_MISSING)
        return
      }
    }
    if (selectedOwnerIssue !== null) {
      setFormError(selectedOwnerIssue)
      return
    }
    const ownerName = isPostgres ? owner : owner.trim()
    if (isPostgres && !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(ownerName)) {
      setFormError('Укажите существующего владельца базы: до 63 латинских букв, цифр и подчёркиваний, без цифры в начале.')
      return
    }
    const database = ownerName === '' ? { name: databaseName } : { name: databaseName, owner: ownerName }
    let payload: CreateDatabaseRequest | CreateDatabaseWithRolesRequest = database
    if (createDefaultRoles && isPostgres && targetIdentity !== null) {
      const intent: CreateDatabaseWithRolesRequest = {
        ...database,
        create_default_roles: true,
        request_id: globalThis.crypto.randomUUID(),
        updated_at: previewConnection.updated_at,
        expected_target_identity: targetIdentity,
      }
      intentRef.current = intent
      setPinnedIntent(intent)
      payload = intent
    }
    pendingRef.current = true
    createMutation.mutate(payload)
  }
  const fieldsLocked = createMutation.isPending || pinnedIntent !== null
  const missingIdentity = createDefaultRoles && pinnedIntent === null && targetIdentity === null
  const stalePreview = pinnedIntent === null && previewChanged
	const authorityBlocked = pinnedIntent === null && authorityIssue !== null
  const previewName = pinnedIntent?.name ?? (name.trim() || '<имя базы>')

  return (
    <Dialog open={open} onClose={onClose} title="Новая база" footer={(
      <div className="space-y-3">
        {formError !== null && <div role="alert"><ErrorBanner>{formError}</ErrorBanner></div>}
        {pinnedIntent !== null && !createMutation.isPending && (
          <p role="status" className="text-xs text-muted">
            Результат запроса неизвестен. Повтор отправит тот же запрос с теми же именами и снимком подключения.
          </p>
        )}
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={onClose}>
            {fieldsLocked ? 'Закрыть' : 'Отмена'}
          </Button>
          <Button type="submit" form={formId}
            aria-describedby={authorityBlocked ? authorityBlockerId : undefined}
            disabled={createMutation.isPending || missingIdentity || stalePreview || authorityBlocked ||
              (pinnedIntent === null && selectedOwnerIssue !== null)}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            {createMutation.isPending ? 'Отправляем…' : pinnedIntent !== null ? 'Повторить запрос' : 'Создать базу'}
          </Button>
        </div>
      </div>
    )}>
      <form id={formId} onSubmit={submit} className="space-y-4" autoComplete="off">

        <dl className="flex flex-wrap gap-x-6 gap-y-2 border-b border-line pb-3 text-sm">
          <div className="min-w-0"><dt className="text-xs text-muted">Подключение</dt><dd className="break-all font-medium text-text">{previewConnection.display_name}</dd></div>
          <div className="min-w-0"><dt className="text-xs text-muted">Окружение</dt><dd className="break-all text-text">{previewConnection.environment}</dd></div>
        </dl>
        {stalePreview && <div className="space-y-2">
          <p role="status" className="text-xs leading-relaxed text-warn">{PREVIEW_CHANGED}</p>
          <p className="text-xs text-muted">Текущее подключение: {connection.display_name} · {connection.environment}</p>
          <Button variant="outline" size="sm" disabled={fieldsLocked} onClick={() => {
            setPreviewConnection(structuredClone(connection))
            setFormError(null)
            void ownersQuery.refetch()
          }}>Обновить контекст подключения</Button>
        </div>}
		{isPostgres && <PostgresProvisioningNotice connection={previewConnection} id={authorityBlockerId} />}
        <Field label="Имя базы">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="appdb"
            className="font-mono text-[13px]"
            autoComplete="off"
            disabled={fieldsLocked}
            required
          />
        </Field>
        {isPostgres ? <>
          <DatabaseOwnerField value={owner} selection={ownerSelection} candidates={ownerCandidates}
            loading={ownersQuery.isFetching} failed={ownersQuery.isError} disabled={fieldsLocked}
            createDefaultRoles={createDefaultRoles}
            onChange={(value, selection) => { setOwner(value); setOwnerSelection(selection); setFormError(null) }} />
          {pinnedIntent === null && selectedOwnerIssue !== null && <p role="status" className="text-xs text-warn">{selectedOwnerIssue}</p>}
          {ownersQuery.isError && !fieldsLocked && <Button variant="ghost" size="sm" onClick={() => { void ownersQuery.refetch() }}>Обновить список ролей</Button>}
        </> : <Field
          label="Владелец"
          hint="Необязательно; роль должна существовать и не быть суперпользователем"
        >
          <Input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder="app_owner"
            className="font-mono text-[13px]"
            autoComplete="off"
            disabled={fieldsLocked}
            required={isPostgres}
          />
        </Field>}

        {isPostgres && (
          <div className="space-y-3">
            <label className="flex items-start gap-2 text-sm text-text">
              <input
                type="checkbox" checked={createDefaultRoles} disabled={fieldsLocked}
                onChange={(event) => { setCreateDefaultRoles(event.target.checked); setFormError(null) }}
                className="mt-0.5 size-4 shrink-0 accent-[var(--accent)]"
              />
              Создать роли чтения и записи вместе с базой
            </label>
            {createDefaultRoles && <>
              <ul aria-label="Создаваемые роли" className="divide-y divide-line border-y border-line text-sm">
                <li className="flex flex-wrap justify-between gap-2 py-2">
                  <span className="break-all font-mono text-text">r_{previewName}</span>
                  <span className="text-xs text-muted">Чтение</span>
                </li>
                <li className="flex flex-wrap justify-between gap-2 py-2">
                  <span className="break-all font-mono text-text">rw_{previewName}</span>
                  <span className="text-xs text-muted">Чтение и запись</span>
                </li>
              </ul>
              <p className="text-xs leading-relaxed text-muted">
                Для пары имя базы ограничено 60 символами: латинские буквы, цифры и подчёркивания, без цифры в начале.
                Роли создаются на сервере после базы. Назначение пользователям выполняется отдельно.
              </p>
              {missingIdentity && (
                <p role="status" className="text-xs text-warn">
                  {IDENTITY_MISSING}
                </p>
              )}
              {!fieldsLocked && missingIdentity && !stalePreview && (
                <Button variant="outline" size="sm" onClick={() => {
                  setPreviewConnection(structuredClone(connection))
                  setFormError(null)
                  void ownersQuery.refetch()
                }}>Обновить контекст подключения</Button>
              )}
            </>}
          </div>
        )}

        {/* Шаблон и tablespace задаются только через allowlists подключения:
            в форме их нет, чтобы не предлагать то, что почти всегда отклонят. */}
        <p className="rounded-md border border-line bg-panel2/40 px-3 py-2 text-xs text-muted">
          База создаётся без автоматического отката: если что-то пойдёт
          не так, удалять её придётся отдельно и вручную. Запущенная операция продолжится после закрытия страницы.
        </p>
      </form>
    </Dialog>
  )
}

export function DatabaseCreationNotice({
  operationId, databaseName, createDefaultRoles, onSettled, onClose,
}: {
  operationId: string
  databaseName: string
  createDefaultRoles?: boolean
  onSettled: (operation: Operation) => void
  onClose: () => void
}) {
  return (
    <OperationProgressNotice
      key={operationId}
      operationId={operationId}
      label={`Создание базы ${databaseName}${createDefaultRoles ? ' и пары ролей r_/rw_' : ''}`}
      onSettled={onSettled}
      onClose={onClose}
      className="mb-3"
      pollFailures={false}
      autoCloseSuccess={false}
      closeWhileRunning
      statusLabel={databaseCreationStatusLabel}
      failureMessage={databaseCreationFailureMessage}
      details={(
        <Link to="/control" search={{ tab: 'operations', operation: operationId }} className="text-text underline underline-offset-4">
          Открыть операцию
        </Link>
      )}
    />
  )
}

function databaseCreationStatusLabel(status: string): string {
  switch (status) {
    case 'retry_pending': return 'Ожидает повторной попытки'
    case 'retry_unknown': return 'Проверяем состояние повтора'
    case 'pending': return 'В очереди'
    case 'pending_approval': return 'Ожидает подтверждения'
    case 'running': return 'Выполняется'
    case 'success': return 'Создано'
    case 'partial': return 'Частичный результат'
    case 'failed': return 'Ошибка выполнения'
    case 'cancelled': return 'Отменено'
    default: return 'Статус уточняется'
  }
}

function databaseCreationFailureMessage(operation: Operation): string {
  const progress = operation.database_provisioning
  const nextStep = 'Откройте операцию, чтобы проверить причину и дальнейшие действия.'
  if (progress?.database_created) {
    if (progress.read_created && progress.read_write_created) {
      return `База и обе роли созданы, но операция завершилась с ошибкой. ${nextStep}`
    }
    if (progress.read_created && !progress.read_write_created) {
      return `База и роль чтения созданы. Создание роли записи не завершено. ${nextStep}`
    }
    return `База создана, создание ролей не завершено. ${nextStep}`
  }
  return `Создание не завершено. ${nextStep}`
}
