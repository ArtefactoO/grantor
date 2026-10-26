import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { Button, Combobox, Dialog, ErrorBanner, Spinner } from '@project/ui'
import { api, apiList } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { basicRoleIntent, createBasicPostgresRoles } from '../lib/postgres-basic-access-flow'
import type { BasicRolesIntent, BasicRolesStage } from '../lib/postgres-basic-access-flow'
import { qk } from '../lib/queryKeys'
import type { Connection, Resource, ResourceTreeItem } from '../lib/types'
import { canEditAccessTemplates } from './connection-access-templates-dialog'
import { postgresProvisioningReady } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'

export interface PostgresBasicRolesDialogProps {
  connection: Connection
  open: boolean
  isAdmin: boolean
  onClose: () => void
  onStarted: (roles: string[], operationIds: string[], alreadyReady: boolean) => void
}

const STAGE_LABELS: Record<BasicRolesStage, string> = {
  checking: 'Проверяю базу и существующие роли…',
  saving: 'Сохраняю настройки пары…',
  discovering: 'Проверяю доступ и готовность базы…',
  creating: 'Запускаю создание ролей…',
}

export function PostgresBasicRolesDialog(props: PostgresBasicRolesDialogProps) {
  if (!props.open) return null
  return <BasicRolesSession key={props.connection.id} {...props} />
}

function BasicRolesSession({ connection, isAdmin, onClose, onStarted }: PostgresBasicRolesDialogProps) {
  const queryClient = useQueryClient()
  const databaseLabel = useId()
  const [baseline, setBaseline] = useState(() => structuredClone(connection))
  const [confirmationRequired, setConfirmationRequired] = useState(false)
  const [databaseId, setDatabaseId] = useState('')
  const [stage, setStage] = useState<BasicRolesStage>('checking')
  const [operations, setOperations] = useState<Record<string, string>>({})
  const [formError, setFormError] = useState<string | null>(null)
  const intentRef = useRef<BasicRolesIntent | null>(null)
  const controllerRef = useRef<AbortController | null>(null)
  const pendingRef = useRef(false)
  const activeRef = useRef(true)
  useEffect(() => {
    activeRef.current = true
    return () => {
      activeRef.current = false
      controllerRef.current?.abort()
    }
  }, [])
  const allowed = connection.engine === 'postgres' && connection.status === 'active' &&
    canEditAccessTemplates(connection, isAdmin) && postgresProvisioningReady(connection)
  const authorityBlockerId = `postgres-basic-roles-${connection.id}-blocker`
  const treeQuery = useQuery({
    queryKey: qk.connectionResourceTree(baseline.id),
    queryFn: ({ signal }) => apiList<ResourceTreeItem>(
      `/api/v1/connections/${baseline.id}/resources?view=tree`, 'resources', signal,
    ),
    enabled: isAdmin && baseline.engine === 'postgres',
  })
  const databases = useMemo(() => (treeQuery.data ?? []).filter((resource) =>
    resource.connection_id === baseline.id && resource.kind === 'database' && resource.status === 'observed',
  ).sort((left, right) => left.name.localeCompare(right.name)), [treeQuery.data, baseline.id])
  const databaseQuery = useQuery({
    queryKey: qk.resource(databaseId),
    queryFn: ({ signal }) => api<Resource>(`/api/v1/resources/${databaseId}`, { signal }),
    enabled: isAdmin && databaseId !== '' && databases.some((database) => database.id === databaseId),
  })
  const preview = useMemo(() => {
    if (databaseQuery.data === undefined || treeQuery.data === undefined) return { intent: null, error: null }
    try {
      return { intent: basicRoleIntent(baseline, databaseQuery.data, treeQuery.data), error: null }
    } catch (error) {
      return { intent: null, error: errorMessage(error) }
    }
  }, [baseline, databaseQuery.data, treeQuery.data])
  const refresh = () => Promise.all([
    queryClient.invalidateQueries({ queryKey: qk.connection(baseline.id), exact: true }),
    queryClient.invalidateQueries({ queryKey: qk.connectionRolePolicies(baseline.id) }),
    queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(baseline.id) }),
    queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(baseline.id) }),
    queryClient.invalidateQueries({ queryKey: qk.operations() }),
  ])
  const mutation = useMutation({
    retry: false,
    mutationFn: (intent: BasicRolesIntent) => {
      controllerRef.current = new AbortController()
      return createBasicPostgresRoles(intent, {
        signal: controllerRef.current.signal,
        onStage: setStage,
        onOperation: (label, id) => setOperations((previous) => ({ ...previous, [label]: id })),
      })
    },
    onSuccess: async (result, intent) => {
      await refresh()
      if (!activeRef.current) return
      if (result.confirmationRequired !== undefined) {
        setBaseline(structuredClone(result.confirmationRequired))
        intentRef.current = null
        setConfirmationRequired(true)
        return
      }
      onStarted(intent.selected.map((template) => template.role_name), result.operationIds, result.ready === 2)
      onClose()
    },
    onError: async (error: unknown) => {
      if (activeRef.current) setFormError(errorMessage(error))
      await refresh()
    },
    onSettled: () => { pendingRef.current = false },
  })
  const close = () => {
    controllerRef.current?.abort()
    onClose()
  }
  const submit = () => {
    if (!allowed || pendingRef.current || preview.intent === null) return
    // Preserve request IDs and the exact intended catalog on a failed/lost response.
    intentRef.current ??= preview.intent
    pendingRef.current = true
    setFormError(null)
    mutation.mutate(intentRef.current)
  }
  const shownIntent = intentRef.current ?? preview.intent
  const error = formError ?? preview.error ?? (treeQuery.isError ? errorMessage(treeQuery.error)
    : databaseQuery.isError ? errorMessage(databaseQuery.error) : null)

  return (
    <Dialog
      open title="Роли доступа к базе" onClose={close} closeOnOverlayClick={false}
      description="Выберите базу. Grantor создаст роли чтения и чтения с записью; аккаунтам они назначаются отдельно."
      footer={(
        <div className="space-y-3">
          {error !== null && <div role="alert"><ErrorBanner>{error}</ErrorBanner></div>}
          {mutation.isPending && (
            <p role="status" className="flex items-center gap-2 text-xs text-muted">
              <Spinner className="size-3.5" />{STAGE_LABELS[stage]}
            </p>
          )}
          {confirmationRequired && !mutation.isPending && (
            <p role="status" className="text-xs text-muted">База проверена. Подтвердите создание показанной пары ролей.</p>
          )}
          {Object.keys(operations).length > 0 && (
            <ul className="space-y-1 text-xs text-muted" aria-label="Запущенные операции">
              {Object.entries(operations).map(([label, id]) => (
                <li key={id}>
                  <Link to="/control" search={{ tab: 'operations', operation: id }} className="underline underline-offset-4">
                    {label}: открыть операцию
                  </Link>
                </li>
              ))}
            </ul>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={close}>{mutation.isPending ? 'Продолжить позже' : 'Отмена'}</Button>
            <Button onClick={submit}
              aria-describedby={!postgresProvisioningReady(connection) ? authorityBlockerId : undefined}
              disabled={!allowed || mutation.isPending || preview.intent === null}>
              {mutation.isPending ? 'Создание…' : confirmationRequired ? 'Подтвердить создание' : intentRef.current === null ? 'Создать r_ / rw_' : 'Продолжить создание'}
            </Button>
          </div>
        </div>
      )}
    >
      <div className="space-y-4">
        <p className="text-sm text-muted">
          Две роли для выбранной базы. Владельца и схемы Grantor возьмёт из инвентаря.
          Назначение ролей аккаунтам выполняется отдельно.
        </p>
        {!isAdmin && <p role="status" className="text-sm text-warn">Создавать роли доступа может только администратор.</p>}
        {isAdmin && !postgresProvisioningReady(connection) && (
          <PostgresProvisioningNotice connection={connection} id={authorityBlockerId} />
        )}
        {isAdmin && !allowed && !mutation.isPending && (
          postgresProvisioningReady(connection) && (
            <p role="status" className="text-sm text-warn">Дождитесь активного состояния подключения и откройте окно заново.</p>
          )
        )}
        <div className="space-y-1.5">
          <span id={databaseLabel} className="text-xs font-medium text-muted">База данных</span>
          <Combobox
            label="База данных" value={databaseId}
            options={databases.map((database) => ({ value: database.id, label: database.name }))}
            placeholder={treeQuery.isPending ? 'Загрузка баз…' : 'Выберите базу'}
            disabled={!allowed || mutation.isPending || intentRef.current !== null || treeQuery.isPending}
            onValueChange={(id) => { setDatabaseId(id); setFormError(null); setConfirmationRequired(false) }}
          />
        </div>
        {treeQuery.isSuccess && databases.length === 0 && (
          <p className="text-xs text-muted">Базы ещё не обнаружены. Создайте базу и синхронизируйте подключение.</p>
        )}
        {databaseId !== '' && databaseQuery.isPending && (
          <p role="status" className="text-xs text-muted">Загрузка владельца базы…</p>
        )}
        {shownIntent !== null && (
          <>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
              <dt className="text-muted">Владелец</dt>
              <dd className="break-all font-mono text-text">{shownIntent.selected[0].owner_roles.join(', ')}</dd>
              <dt className="text-muted">Схемы</dt>
              <dd className="break-words font-mono text-text">{shownIntent.selected[0].schemas.join(', ')}</dd>
            </dl>
            <ul className="divide-y divide-line border-y border-line" aria-label="Создаваемые роли">
              {shownIntent.selected.map((template) => (
                <li key={template.key} className="flex flex-wrap items-baseline justify-between gap-2 py-3">
                  <span className="break-all font-mono text-sm text-text">{template.role_name}</span>
                  <span className="text-xs text-muted">{template.profile === 'read' ? 'Чтение' : 'Чтение и запись'}</span>
                </li>
              ))}
            </ul>
            <p className="text-xs leading-relaxed text-muted">
              Права распространяются на текущие и будущие объекты, создаваемые владельцем базы в этих схемах.
              Создание таблиц и изменение структуры не разрешаются.
            </p>
          </>
        )}
        {mutation.isPending && (
          <p className="text-xs text-muted">Запущенные операции продолжатся после закрытия. Прерванное создание пары можно повторить.</p>
        )}
      </div>
    </Dialog>
  )
}
