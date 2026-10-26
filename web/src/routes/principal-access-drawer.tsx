// Выдача доступа от пользователя: POST /api/v1/principals/{id}/access
// (operator; dangerous среди ролей — admin с confirm). Оператор выбирает
// подключения, для каждого — доступная для выдачи роль; сервис
// создаёт где надо локальный managed-аккаунт с общим паролем принципала.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { apiList, apiPost } from '../lib/api'
import { isPostgresObjectPrivilege } from '../lib/postgres-object-acl'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  Account,
  Binding,
  Connection,
  Operation,
  Permission,
  Principal,
  PrincipalAccessRequest,
  PrincipalAccessResponse,
} from '../lib/types'
import { useToggleSet } from '../lib/useToggleSet'
import { MAX_BULK_ITEMS } from '../lib/limits'
import { permissionNameLabel } from '../lib/access-entries'
import { isAssignedManagedBinding } from '../lib/active-access'
import { isConnectionAdminAccount, isSharedRoleKind } from '../lib/account-actions'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  cn,
  selectionSurfaceClassName,
  Button,
  Drawer,
  Combobox,
  MultiCombobox,
  Field,
  Input,
  Spinner,
  ErrorBanner,
  SearchInput,
} from '@project/ui'
import { EngineBadge, PrincipalTypeIcon, StatusChip, TagBadge } from '../components/ui/badge'
import { ElevatedAccessDot } from '../components/ui/access-chips'
import { DangerConfirm } from '../components/ui/danger-confirm'
import { connectionSearchKeywords } from '../components/ConnectionPicker'
import { environmentLabel } from './principal-detail-shared'
import { connectionStatusTone, operationInProgress } from '../lib/status'
import { connectionStatusLabel } from '../lib/ui-copy'
import { RestoreAccountDialog } from './connection-account-restore'
import { buildConnectionAccountPickerProjection } from '../lib/connection-account-picker'
import { ManageRolesDrawer } from './connection-account-dialogs'
import { POLL_OPERATIONS_MS } from '../lib/intervals'

const RESTORE_ACCOUNT_PREFIX = '__restore_account__:'
const EXISTING_LOCAL_ACCOUNT_PREFIX = '__existing_local_account__:'
const ACTIVE_OPERATION_STATUSES = 'pending,pending_approval,running'

function localAccountGrantBlockedReason(account: Account, connection: Connection | undefined, role: string): string | undefined {
  if (!roleAtLeast(role, 'operator')) return 'Выдавать доступ может оператор или администратор.'
  if (account.status === 'provisioning') return 'Создание учётки ещё не подтверждено.'
  if (account.status === 'missing') return 'Учётка отсутствует в кластере. Сначала проверьте её состояние.'
  if (account.status !== 'active' && account.status !== 'disabled') return 'Учётка недоступна для изменения доступа.'
  if (isSharedRoleKind(account.kind)) return 'Выберите учётку, которой нужно назначить роль.'
  if (isConnectionAdminAccount(account)) return 'Права учётки подключения нельзя менять здесь.'
  if (connection === undefined) return 'Проверяем подключение…'
  if (connection.status !== 'active') return 'Подключение сейчас недоступно для изменения доступа.'
  if (!connection.capabilities.includes('access.grant')) return 'Подключение не поддерживает выдачу доступа.'
  return undefined
}

// Пресеты срока действия доступа. Значение — часы; спец-значения: без
// срока и произвольная дата.
const EXPIRY_NONE = 'none'
const EXPIRY_CUSTOM = 'custom'
const EXPIRY_OPTIONS = [
  { value: EXPIRY_NONE, label: 'Бессрочно' },
  { value: '24', label: '1 день' },
  { value: '168', label: '1 неделя' },
  { value: '720', label: '30 дней' },
  { value: EXPIRY_CUSTOM, label: 'До даты…' },
] as const

/**
 * Превращает выбор срока в RFC 3339 timestamp; null — бессрочно. Пресеты
 * считаются от момента отправки, произвольная дата берётся из
 * datetime-local как локальное время оператора.
 */
export function expiryToTimestamp(choice: string, custom: string, now: Date = new Date()): string | null {
  if (choice === EXPIRY_NONE) return null
  if (choice === EXPIRY_CUSTOM) {
    if (custom === '') return null
    const parsed = new Date(custom)
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString()
  }
  const hours = Number(choice)
  return new Date(now.getTime() + hours * 3_600_000).toISOString()
}

interface GrantAccessDrawerProps {
  open: boolean
  /** Зафиксированный пользователь (вход из профиля пользователя). */
  principalId?: string
  principalName?: string
  /** Зафиксированное подключение (быстрый вход из подключения). */
  fixedConnectionId?: string
  onClose: () => void
  onStarted: (operationId: string, principalName: string) => void
}

export function GrantAccessDrawer({
  open,
  principalId,
  principalName,
  fixedConnectionId,
  onClose,
  onStarted,
}: GrantAccessDrawerProps) {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const queryClient = useQueryClient()

  const [search, setSearch] = useState('')
  const [selectedPrincipalId, setSelectedPrincipalId] = useState<string | undefined>(
    principalId,
  )
  const [selectedLocalAccountId, setSelectedLocalAccountId] = useState<string | null>(null)
  const [submissionPending, setSubmissionPending] = useState(false)
  const submissionPendingRef = useRef(false)
  const changeSubmissionPending = useCallback((pending: boolean) => {
    submissionPendingRef.current = pending
    setSubmissionPending(pending)
  }, [])
  const {
    set: selected,
    toggle: toggleSelected,
    replace: replaceSelected,
  } = useToggleSet()
  // Выбранные роли по подключению. Модель совпадает с API: каждая роль
  // превращается в отдельный item, а backend переиспользует один аккаунт.
  const [rolesByConn, setRolesByConn] = useState<ReadonlyMap<string, Permission[]>>(
    new Map(),
  )
  const [engineIdentity, setEngineIdentity] = useState('')
  // Срок действия: пресет или произвольная дата. По умолчанию бессрочно —
  // прежнее поведение выдачи не меняется, срок остаётся явным решением.
  const [expiryChoice, setExpiryChoice] = useState(EXPIRY_NONE)
  const [expiryCustom, setExpiryCustom] = useState('')
  const [dangerConfirmed, setDangerConfirmed] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [restoreAccount, setRestoreAccount] = useState<Account | null>(null)

  // Полный сброс формы при каждом открытии drawer.
  useEffect(() => {
    if (open) {
      setSearch('')
      setSelectedPrincipalId(principalId)
      setSelectedLocalAccountId(null)
      replaceSelected(fixedConnectionId === undefined ? [] : [fixedConnectionId])
      setRolesByConn(new Map())
      setEngineIdentity('')
      setDangerConfirmed(false)
      setFormError(null)
      setRestoreAccount(null)
    }
  }, [fixedConnectionId, open, principalId, replaceSelected])

  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
    enabled: open && principalId === undefined,
  })

  const principals = principalsQuery.data ?? []

  // Для входа из конкретного подключения заранее знаем, какие глобальные
  // пользователи уже имеют account или deleted tombstone. Это не даёт форме
  // предлагать заведомо конфликтующий implicit create и показывать сырой 409.
  const connectionAccountsQuery = useQuery({
    queryKey: qk.connectionAccounts(fixedConnectionId ?? '', 'summary'),
    queryFn: ({ signal }) =>
      apiList<Account>(
        `/api/v1/connections/${fixedConnectionId}/accounts?view=summary&include=bindings,provisioning`,
        'accounts',
        signal,
      ),
    enabled: open && fixedConnectionId !== undefined,
  })
  const picker = useMemo(
    () => buildConnectionAccountPickerProjection(
      principals,
      connectionAccountsQuery.data ?? [],
    ),
    [connectionAccountsQuery.data, principals],
  )
  const selectablePrincipals = picker.principals
  const accountByPrincipalId = picker.accountByPrincipalId
  const localDeletedAccounts = picker.localDeletedAccounts
  const localAccounts = (connectionAccountsQuery.data ?? []).filter(
    (account) => account.principal_id === null && account.status !== 'deleted' && !isSharedRoleKind(account.kind),
  )
  const selectedLocalAccount = (connectionAccountsQuery.data ?? []).find((account) => account.id === selectedLocalAccountId)

  const selectedPrincipal = selectablePrincipals.find(
    (principal) => principal.id === selectedPrincipalId,
  )
  const effectivePrincipalId = principalId ?? selectedPrincipalId
  const effectivePrincipalName =
    principalName ?? selectedPrincipal?.display_name ?? ''

  const connectionsQuery = useQuery({
    queryKey: qk.connections(),
    queryFn: ({ signal }) =>
      apiList<Connection>('/api/v1/connections', 'connections', signal),
    enabled: open,
  })

  const connections = connectionsQuery.data ?? []
  const fixedConnection = fixedConnectionId === undefined
    ? undefined : connections.find((connection) => connection.id === fixedConnectionId)
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (q === '') {
      return connections
    }
    return connections.filter((connection) =>
      connectionSearchKeywords(connection).some((keyword) =>
        keyword.toLocaleLowerCase().includes(q),
      ),
    )
  }, [connections, search])

  // Выбранные подключения в порядке общего списка — для секции ролей.
  const selectedConnections = useMemo(
    () => connections.filter((c) => selected.has(c.id)),
    [connections, selected],
  )

  const toggleConnection = (id: string) => {
    toggleSelected(id)
    // Снятие подключения убирает и выбранную для него роль.
    setRolesByConn((prev) => {
      if (!prev.has(id)) {
        return prev
      }
      const next = new Map(prev)
      next.delete(id)
      return next
    })
  }

  const setRoles = (connectionId: string, permissions: Permission[]) => {
    setRolesByConn((prev) => {
      const next = new Map(prev)
      if (permissions.length === 0) {
        next.delete(connectionId)
      } else {
        next.set(connectionId, permissions)
      }
      return next
    })
    setDangerConfirmed(false)
  }

  const allChosen =
    selectedConnections.length > 0 &&
    selectedConnections.every((c) => (rolesByConn.get(c.id)?.length ?? 0) > 0)
  const anyDangerous = selectedConnections.some(
    (c) => rolesByConn.get(c.id)?.some((permission) => permission.dangerous) === true,
  )
  const selectedRoleCount = selectedConnections.reduce(
    (total, connection) => total + (rolesByConn.get(connection.id)?.length ?? 0),
    0,
  )
  const overLimit = selectedRoleCount > MAX_BULK_ITEMS

  const grantMutation = useMutation({
    mutationFn: (payload: PrincipalAccessRequest) =>
      apiPost<PrincipalAccessResponse>(
        `/api/v1/principals/${effectivePrincipalId}/access`,
        payload,
      ),
    onSuccess: async (data) => {
      setFormError(null)
      // Account создаётся в metadata синхронно с parent-операцией. До закрытия
      // drawer обновляем обе проекции: профиль пользователя и каждый список
      // аккаунтов подключения. Иначе активная таблица продолжает показывать
      // старый cache до ручного refresh.
      const connectionIds = [...new Set(data.children.map((child) => child.connection_id))]
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.principals() }),
        queryClient.invalidateQueries({ queryKey: qk.accounts() }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
        ...connectionIds.flatMap((connectionId) => [
          queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) }),
          queryClient.invalidateQueries({ queryKey: qk.connectionAccess(connectionId) }),
        ]),
      ])
      onStarted(data.operation_id, effectivePrincipalName)
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err))
    },
    onSettled: () => changeSubmissionPending(false),
  })

  const close = () => {
    if (!submissionPendingRef.current && !grantMutation.isPending) onClose()
  }

  // Произвольный срок обязан быть валидной будущей датой до отправки:
  // сервер ответит 400, но подсветить проблему честнее до запроса.
  const expiryInvalid =
    expiryChoice === EXPIRY_CUSTOM &&
    (expiryCustom === '' || new Date(expiryCustom).getTime() <= Date.now())
  const canSubmit =
    roleAtLeast(auth.role, 'operator') &&
    effectivePrincipalId !== undefined &&
    allChosen &&
    !overLimit &&
    !expiryInvalid &&
    !submissionPending &&
    !grantMutation.isPending &&
    (!anyDangerous || (isAdmin && dangerConfirmed))

  const submit = () => {
    if (!canSubmit || submissionPendingRef.current || effectivePrincipalId === undefined) {
      return
    }
    const items = selectedConnections.flatMap((connection) =>
      (rolesByConn.get(connection.id) ?? []).map((permission) => ({
        connection_id: connection.id,
        permission_id: permission.id,
      })),
    )
    const identity = engineIdentity.trim()
    const payload: PrincipalAccessRequest = { items }
    if (identity !== '') {
      payload.engine_identity = identity
    }
    if (anyDangerous) {
      payload.confirm = true
    }
    const expiresAt = expiryToTimestamp(expiryChoice, expiryCustom)
    if (expiresAt !== null) {
      payload.expires_at = expiresAt
    }
    changeSubmissionPending(true)
    grantMutation.mutate(payload)
  }

  return (
    <>
    <Drawer
      open={open}
      onClose={close}
      closeOnOverlayClick={!submissionPending && !grantMutation.isPending}
      title={
        principalId === undefined
          ? 'Выдать доступ'
          : `Выдать доступ: ${principalName}`
      }
    >
      <div className="space-y-4">
        {principalId === undefined && (
          <div>
            <span className="mb-1.5 block text-xs font-medium text-muted">
              Учётка или глобальный пользователь
            </span>
            <Combobox
              value={selectedLocalAccountId === null ? selectedPrincipalId : `${EXISTING_LOCAL_ACCOUNT_PREFIX}${selectedLocalAccountId}`}
              label="Учётка или пользователь для выдачи доступа"
              searchLabel="Поиск учётки или пользователя"
              placeholder="Выберите учётку или пользователя…"
              searchPlaceholder="Имя, логин или внешний идентификатор…"
              options={[
                ...localAccounts.map((account) => {
                  const blockedReason = localAccountGrantBlockedReason(account, fixedConnection, auth.role)
                  return {
                    value: `${EXISTING_LOCAL_ACCOUNT_PREFIX}${account.id}`,
                    label: account.engine_identity,
                    description: blockedReason ?? 'Существующая локальная учётка',
                    keywords: [account.engine_identity, account.kind, 'local', 'локальная'],
                    icon: <PrincipalTypeIcon type="service" />,
                    disabled: blockedReason !== undefined,
                  }
                }),
                ...selectablePrincipals.map((principal) => {
                  const account = accountByPrincipalId.get(principal.id)
                  const deleted = account?.status === 'deleted'
                  return {
                    value: principal.id,
                    label: principal.display_name,
                    description: deleted
                      ? `Удалённый аккаунт: ${account.engine_identity}`
                      : account !== undefined
                        ? `Уже в подключении: ${account.engine_identity}`
                        : principal.external_subject || undefined,
                    keywords: [
                      principal.display_name,
                      principal.external_subject,
                      principal.external_provider,
                      account?.engine_identity ?? '',
                    ],
                    icon: <PrincipalTypeIcon type={principal.type} />,
                    // Tombstone остаётся действием восстановления даже если
                    // сам global principal уже неактивен: оператор может
                    // восстановить его с отдельным credential и снять link.
                    disabled: !deleted && principal.status !== 'active',
                    meta: deleted ? (
                      <StatusChip tone="unmg">Deleted</StatusChip>
                    ) : account !== undefined ? (
                      <StatusChip tone="ok">Added</StatusChip>
                    ) : undefined,
                  }
                }),
                ...localDeletedAccounts.map((account) => ({
                  value: `${RESTORE_ACCOUNT_PREFIX}${account.id}`,
                  label: account.engine_identity,
                  description: 'Удалённый локальный аккаунт',
                  keywords: [account.engine_identity, 'deleted', 'локальный'],
                  meta: <StatusChip tone="unmg">Deleted</StatusChip>,
                })),
              ]}
              disabled={
                submissionPending ||
                grantMutation.isPending ||
                principalsQuery.isPending ||
                principalsQuery.isError ||
                (fixedConnectionId !== undefined && (connectionAccountsQuery.isPending || connectionAccountsQuery.isError))
              }
              onValueChange={(value) => {
                if (submissionPendingRef.current || grantMutation.isPending) return
                setFormError(null)
                setSelectedLocalAccountId(null)
                if (value.startsWith(EXISTING_LOCAL_ACCOUNT_PREFIX)) {
                  setSelectedPrincipalId(undefined)
                  setSelectedLocalAccountId(value.slice(EXISTING_LOCAL_ACCOUNT_PREFIX.length))
                  return
                }
                if (value.startsWith(RESTORE_ACCOUNT_PREFIX)) {
                  setSelectedPrincipalId(undefined)
                  const accountId = value.slice(RESTORE_ACCOUNT_PREFIX.length)
                  const account = localDeletedAccounts.find((item) => item.id === accountId)
                  if (account !== undefined) setRestoreAccount(account)
                  return
                }
                const account = accountByPrincipalId.get(value)
                if (account?.status === 'deleted') {
                  setSelectedPrincipalId(undefined)
                  setRestoreAccount(account)
                  return
                }
                setSelectedPrincipalId(value)
              }}
            />
            {principalsQuery.isError && (
              <div className="mt-1.5 text-xs text-danger">
                {errorMessage(principalsQuery.error)}
              </div>
            )}
            {connectionAccountsQuery.isError && fixedConnectionId !== undefined && (
              <div className="mt-1.5 text-xs text-danger">{errorMessage(connectionAccountsQuery.error)}</div>
            )}
          </div>
        )}

        {selectedLocalAccountId !== null ? (
          selectedLocalAccount === undefined ? (
            <ErrorBanner>Учётка больше недоступна. Выберите другую учётку или обновите список.</ErrorBanner>
          ) : (
            <LocalAccountRolesEditor
              key={selectedLocalAccount.id}
              open={open}
              account={selectedLocalAccount}
              connection={fixedConnection}
              onClose={close}
              onPendingChange={changeSubmissionPending}
              onStarted={onStarted}
            />
          )
        ) : (
        <>
        {fixedConnectionId === undefined && (
          <div>
            <span className="mb-1.5 block text-xs font-medium text-muted">
              Подключения
            </span>
            <SearchInput
              value={search}
              onChange={setSearch}
              placeholder="Имя, движок, окружение, тег или endpoint…"
              ariaLabel="Поиск подключения"
            />
          </div>
        )}

        {connectionsQuery.isError ? (
          <div className="text-sm text-danger">
            {errorMessage(connectionsQuery.error)}
          </div>
        ) : connectionsQuery.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner />
          </div>
        ) : connections.length === 0 ? (
          <div className="text-sm text-faint">Подключений пока нет.</div>
        ) : fixedConnectionId !== undefined ? null : filtered.length === 0 ? (
          <div className="text-sm text-faint">
            Ничего не найдено по «{search.trim()}».
          </div>
        ) : (
          <div className="max-h-[32vh] space-y-1 overflow-y-auto rounded-md border border-line p-1.5">
            {filtered.map((connection) => {
              const checked = selected.has(connection.id)
              return (
                <label
                  key={connection.id}
                  className={cn(
                    'flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 transition-colors',
                    selectionSurfaceClassName(checked),
                  )}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggleConnection(connection.id)}
                    className="accent-accent"
                    aria-label={`Выбрать ${connection.display_name}`}
                  />
                  <EngineBadge engine={connection.engine} />
                  <span className="min-w-0 flex-1 truncate text-sm text-text">
                    {connection.display_name}
                  </span>
                  <TagBadge>{environmentLabel(connection)}</TagBadge>
                  <StatusChip tone={connectionStatusTone(connection.status)}>
                    {connectionStatusLabel(connection.status)}
                  </StatusChip>
                </label>
              )
            })}
          </div>
        )}

        <div>
          <span className="mb-1.5 block text-xs font-medium text-muted">
            Роли по подключениям
          </span>
          {selectedConnections.length === 0 ? (
            <div className="text-sm text-faint">
              Выберите подключения выше, чтобы назначить роли.
            </div>
          ) : (
            <div className="space-y-2">
              {selectedConnections.map((connection) => (
                <ConnectionRoleRow
                  key={connection.id}
                  connection={connection}
                  principalId={effectivePrincipalId}
                  value={rolesByConn.get(connection.id) ?? []}
                  onChange={(permissions) => setRoles(connection.id, permissions)}
                />
              ))}
            </div>
          )}
        </div>

        <Field
          label="Логин в подключении"
          tooltip="Имя аккаунта непосредственно в выбранной базе или кластере. Оставьте поле пустым, чтобы использовать имя глобального пользователя."
        >
          <Input
            value={engineIdentity}
            onChange={(e) => setEngineIdentity(e.target.value)}
            placeholder="Как у пользователя"
            className="font-mono text-[13px]"
            autoComplete="off"
          />
        </Field>

        <Field
          label="Срок действия"
          hint="по истечении доступ отзывается автоматически"
        >
          <Combobox
            value={expiryChoice}
            label="Срок действия"
            options={EXPIRY_OPTIONS.map((option) => ({ value: option.value, label: option.label }))}
            onValueChange={setExpiryChoice}
          />
          {expiryChoice === EXPIRY_CUSTOM && (
            <Input
              type="datetime-local"
              value={expiryCustom}
              onChange={(e) => setExpiryCustom(e.target.value)}
              className="mt-2"
              aria-label="Дата и время окончания доступа"
              required
            />
          )}
        </Field>

        {anyDangerous && (
          <DangerConfirm
            title="Среди выбранных ролей есть опасные"
            label="Я понимаю, что выдаю опасные права"
            checked={dangerConfirmed}
            onChange={setDangerConfirmed}
            isAdmin={isAdmin}
          />
        )}

        {selectedConnections.length > 0 && !allChosen && (
          <div className="text-xs text-faint">
            Выберите роль для каждого выбранного подключения.
          </div>
        )}

        {overLimit && (
          <div className="text-sm text-danger">
            Не больше {MAX_BULK_ITEMS} назначений ролей за один запуск.
          </div>
        )}

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={close} disabled={submissionPending || grantMutation.isPending}>
            Отмена
          </Button>
          <Button disabled={!canSubmit} onClick={submit}>
            {grantMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Выдать доступ
          </Button>
        </div>
        </>
        )}
      </div>
    </Drawer>
    {restoreAccount !== null && fixedConnectionId !== undefined && (
      <RestoreAccountDialog
        open
        account={restoreAccount}
        connectionId={fixedConnectionId}
        connection={fixedConnection}
        onClose={() => setRestoreAccount(null)}
        onRestored={() => {
          setRestoreAccount(null)
          void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(fixedConnectionId) })
          void queryClient.invalidateQueries({ queryKey: qk.principals() })
        }}
      />
    )}
    </>
  )
}

function LocalAccountRolesEditor({ open, account, connection, onClose, onStarted, onPendingChange }: {
  open: boolean
  account: Account
  connection: Connection | undefined
  onClose: () => void
  onStarted: GrantAccessDrawerProps['onStarted']
  onPendingChange: (pending: boolean) => void
}) {
  const auth = useAuth()
  const queryClient = useQueryClient()
  const eligibilityBlocker = localAccountGrantBlockedReason(account, connection, auth.role)
  const enabled = open && eligibilityBlocker === undefined
  const permissionsQuery = useQuery({
    queryKey: qk.connectionPermissions(account.connection_id, 'roles'),
    queryFn: ({ signal }) => apiList<Permission>(`/api/v1/connections/${account.connection_id}/permissions?category=roles`, 'permissions', signal),
    enabled,
  })
  const bindingsQuery = useQuery({
    queryKey: qk.accountBindings(account.id, 'roles'),
    queryFn: ({ signal }) => apiList<Binding>(`/api/v1/accounts/${account.id}/bindings?category=roles`, 'bindings', signal),
    enabled,
    retry: false,
  })
  const operationsQuery = useQuery({
    queryKey: qk.operationsList(account.connection_id, ACTIVE_OPERATION_STATUSES),
    queryFn: ({ signal }) => apiList<Operation>(
      `/api/v1/operations?connection_id=${account.connection_id}&status=${ACTIVE_OPERATION_STATUSES}`, 'operations', signal,
    ),
    enabled,
    retry: false,
    refetchInterval: enabled ? POLL_OPERATIONS_MS : false,
    refetchIntervalInBackground: false,
  })
  const readError = permissionsQuery.isError || bindingsQuery.isError || operationsQuery.isError
  const busy = (operationsQuery.data ?? []).some((operation) =>
    operation.account_id === account.id && operationInProgress(operation.status) &&
    (operation.kind.startsWith('account.') || operation.kind === 'role.create' || operation.kind === 'credential.rotate'),
  )
  const blockedReason = eligibilityBlocker ?? (readError
    ? 'Не удалось проверить состояние учётки. Закройте форму и повторите попытку.'
    : busy ? 'Есть незавершённая операция. Дождитесь её завершения перед изменением доступа.' : undefined)
  if (permissionsQuery.data === undefined || bindingsQuery.data === undefined || operationsQuery.data === undefined) {
    return (
      <div className="space-y-3">
        {blockedReason !== undefined ? <ErrorBanner>{blockedReason}</ErrorBanner> : <div className="flex items-center gap-2 text-sm text-muted"><Spinner />Проверяем права и операции учётки…</div>}
        <div className="flex justify-end"><Button variant="outline" onClick={onClose}>Отмена</Button></div>
      </div>
    )
  }
  return (
    <ManageRolesDrawer
      embedded
      open={open}
      account={account}
      permissions={permissionsQuery.data}
      bindings={bindingsQuery.data}
      blockedReason={blockedReason}
      onClose={onClose}
      onPendingChange={onPendingChange}
      onStarted={async (operationId) => {
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: qk.accountBindings(account.id) }),
          queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(account.connection_id) }),
          queryClient.invalidateQueries({ queryKey: qk.connectionAccess(account.connection_id) }),
          queryClient.invalidateQueries({ queryKey: qk.operations() }),
        ])
        onStarted(operationId, account.engine_identity)
      }}
    />
  )
}

// ---------------------------------------------------------------------------
// Строка выбора роли для одного подключения отдаёт выбранную роль наверх
// целиком, чтобы родитель сохранил security-флаг подтверждения.

interface ConnectionRoleRowProps {
  connection: Connection
  principalId?: string
  value: Permission[]
  onChange: (permissions: Permission[]) => void
}

function ConnectionRoleRow({ connection, principalId, value, onChange }: ConnectionRoleRowProps) {
  const permissionsQuery = useQuery({
    queryKey: qk.connectionPermissions(connection.id, 'roles'),
    queryFn: ({ signal }) =>
      apiList<Permission>(
        `/api/v1/connections/${connection.id}/permissions?category=roles`,
        'permissions',
        signal,
      ),
  })

  // Права, исчезнувшего из целевой системы, в выдаче нет: операция упала бы
  // на target, а API отвечает на неё 409.
  const assignable = useMemo(
    () => (permissionsQuery.data ?? []).filter((p) => p.assignable && p.status !== 'missing' && !isPostgresObjectPrivilege(p)),
    [permissionsQuery.data],
  )
  const accountsQuery = useQuery({
    queryKey: qk.connectionAccounts(connection.id, 'summary'),
    queryFn: ({ signal }) =>
      apiList<Account>(
        `/api/v1/connections/${connection.id}/accounts?view=summary&include=bindings,provisioning`,
        'accounts',
        signal,
      ),
    enabled: principalId !== undefined,
  })
  const assignedPermissionIds = useMemo(() => {
    const account = (accountsQuery.data ?? []).find(
      (candidate) => candidate.principal_id === principalId && candidate.status !== 'deleted',
    )
    return new Set(
      // Тот же предикат, что у 409 API на повторную выдачу: фильтр по
      // одному desired_state блокировал «Уже назначена» навсегда, даже
      // когда право сломано (failed/drift) и повторная выдача его чинит.
      (account?.bindings ?? [])
        .filter(isAssignedManagedBinding)
        .map((binding) => binding.permission_definition_id),
    )
  }, [accountsQuery.data, principalId])
  const existingAccount = (accountsQuery.data ?? []).find(
    (candidate) => candidate.principal_id === principalId && candidate.status !== 'deleted',
  )
  const provisioningIssue = principalId !== undefined && existingAccount === undefined
    ? postgresProvisioningIssue(connection) : null

  return (
    <div className="space-y-2 rounded-md border border-line p-2.5">
      <div className="flex items-center gap-2">
        <EngineBadge engine={connection.engine} />
        <span className="min-w-0 flex-1 truncate text-sm text-text">
          {connection.display_name}
        </span>
        <TagBadge>{environmentLabel(connection)}</TagBadge>
      </div>
      {permissionsQuery.isError ? (
        <div className="text-xs text-danger">
          {errorMessage(permissionsQuery.error)}
        </div>
      ) : permissionsQuery.isPending || (principalId !== undefined && accountsQuery.isPending) ? (
        <div className="flex items-center gap-2 text-xs text-faint">
          <Spinner className="size-3.5" />
          Загрузка ролей…
        </div>
      ) : accountsQuery.isError ? (
        <div className="text-xs text-danger">Не удалось проверить существующий аккаунт: {errorMessage(accountsQuery.error)}</div>
      ) : provisioningIssue !== null ? (
        <PostgresProvisioningNotice connection={connection} />
      ) : assignable.length === 0 ? (
        <div className="text-xs text-faint">У подключения нет ролей, доступных для выдачи.</div>
      ) : (
        <MultiCombobox
          label={`Роли для ${connection.display_name}`}
          allLabel="All"
          selected={new Set(value.map((permission) => permission.id))}
          placeholder="Выберите роли…"
          searchPlaceholder="Поиск роли…"
          options={assignable.map((permission) => ({
            value: permission.id,
            label: permissionNameLabel(permission, permission.name),
            icon: permission.dangerous ? <ElevatedAccessDot /> : undefined,
            disabled: assignedPermissionIds.has(permission.id),
            description: assignedPermissionIds.has(permission.id)
              ? 'Уже назначена'
              : undefined,
          }))}
          onChange={(selectedIds) => {
            onChange(assignable.filter((permission) => selectedIds.has(permission.id)))
          }}
        />
      )}
    </div>
  )
}
