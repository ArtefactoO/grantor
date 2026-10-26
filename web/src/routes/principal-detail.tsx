// Экран «Пользователь»: шапка принципала с каскадным включением/
// отключением (operator+; managed-аккаунты во всех кластерах получают
// account.disable/enable — обратимо), необратимым offboard (admin; revoke
// + delete всех managed-аккаунтов, зачистка общих паролей, tombstone
// deleted) и principal-centric действия «работы от пользователя»
// (operator+):
//   • «Выдать доступ» — bulk-выдача ролей по выбранным подключениям
//     (POST /api/v1/principals/{id}/access): сервис создаёт где надо
//     локальный managed-аккаунт с общим паролем принципала и выдаёт роль;
//   • «Ротация пароля» — замена общего пароля окружения
//     (POST /api/v1/principals/{id}/rotate?environment=);
//   • «Получить креды» — одноразовая ссылка на общий пароль окружения
//     (POST /api/v1/principals/{id}/share?environment=).
// Плюс таблица учётных записей по всем подключениям с отвязкой
// (POST /api/v1/accounts/{id}/unlink) через confirm-диалог.
import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useQueries, useQuery, useQueryClient } from '@tanstack/react-query'
import { getRouteApi, Link, useNavigate } from '@tanstack/react-router'
import {
  ArrowLeft,
  Cable,
  Globe2,
  KeyRound,
  Link2,
  Power,
  PowerOff,
  RotateCw,
  ShieldCheck,
  Trash2,
  Unlink,
  UserX,
} from '@project/ui/icons'
import { api, apiList } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type { Account, Binding, Connection, Permission, PrincipalCredentialEnvironment, PrincipalDetail, Resource } from '../lib/types'
import {
  inventoryStatusTone,
  ownershipTone,
  shortId,
} from '../lib/status'
import { externalIdentity } from '../lib/externalIdentity'
import { indexById } from '../lib/indexById'
import { formatDateTime, formatRelative } from '../lib/time'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  Button,
  InlineNotice,
  Spinner,
  DetailPageSkeleton,
  ErrorState,
  ErrorBanner,
  cn,
  CopyableValue,
  TableCopyableValue,
  MetadataChip,
  metadataChipClassName,
} from '@project/ui'
import { EngineBadge, KindBadge, PrincipalTypeChip, StatusChip } from '../components/ui/badge'
import { AccessChipList } from '../components/ui/access-chips'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { DangerConfirm } from '../components/ui/danger-confirm'
import { ShareLinkDialog } from '../components/ui/share-link-dialog'
import { BulkOperationPanel } from '../components/BulkOperationPanel'
import { SHARED_CREDENTIAL_MODE, environmentLabel } from './principal-detail-shared'
import { principalCredentialVaultPath } from '../lib/vault-paths'
import { usePrincipalActions } from './principal-detail-actions'
import { GrantAccessDrawer } from './principal-access-drawer'
import { EnvironmentPickerDialog } from './environment-picker-dialog'
import { ServiceTokensSection } from './principal-tokens-section'
import { PrincipalCredentialDialog } from './principal-credential-dialog'
import { activeAccessBindings } from '../lib/active-access'
import { PrincipalIdentityChips } from '../components/principal-identity-chips'
import {
  accountActions,
  accountHasCredential,
  accountOnOwnCredential,
  isSharedRoleKind,
} from '../lib/account-actions'
import { buildAccessEntries } from '../lib/access-entries'
import { LinkPrincipalDialog } from './connection-account-dialogs'
import {
  accountKindLabel,
  inventoryStatusLabel,
  ownershipLabel,
  UI_COPY,
} from '../lib/ui-copy'
import { UnlinkAccountButton } from '../components/ui/unlink-account-button'
import { SelectionSelect } from '../components/ui/selection-chips'
import { connectionEnvironmentLabel } from '../lib/connection-presentation'
import { directlyOwnedPostgresDatabases } from '../lib/postgres-database-ownership'
import { AccountDatabaseOwnership } from '../components/account-database-ownership'

const routeApi = getRouteApi('/principals/$principalId')
const ALL_ACCOUNT_ENVIRONMENTS = '__all_account_environments__'
const ALL_ACCOUNT_CONNECTIONS = '__all_account_connections__'

export function PrincipalDetailPage() {
  const { principalId } = routeApi.useParams()
  const navigate = useNavigate()
  return (
    <PrincipalProfileContent
      principalId={principalId}
      onPurged={() => void navigate({ to: '/principals' })}
    />
  )
}

export interface PrincipalProfileContentProps {
  principalId: string
  /** Drawer/inspector omits page-level back navigation and outer max width. */
  embedded?: boolean
  /** Lets a containing drawer reserve the first Escape for nested account details. */
  onNestedViewChange?: (open: boolean) => void
  /** Закрывает drawer или возвращает страницу к каталогу после hard delete. */
  onPurged?: () => void
}

interface CredentialEnvironmentSummary {
  environment: string
  connections: number
  accounts: number
  /** null — состояние credential неизвестно (метаданные не прочитались). */
  configured: boolean | null
  actionable: boolean
}

/** Shared profile content for both the list drawer and the stable deep link. */
export function PrincipalProfileContent({
  principalId,
  embedded = false,
  onNestedViewChange,
  onPurged,
}: PrincipalProfileContentProps) {
  const auth = useAuth()
  const queryClient = useQueryClient()
  const canOperate = roleAtLeast(auth.role, 'operator')
  const isAdmin = roleAtLeast(auth.role, 'admin')

  // Principal-centric действия: drawer выдачи и панель запущенной
  // bulk-операции. Мутации и состояние их диалогов — в usePrincipalActions.
  const [grantOpen, setGrantOpen] = useState(false)
  const [accessOperationId, setAccessOperationId] = useState<string | null>(null)
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null)
  const [createCredentialEnvironment, setCreateCredentialEnvironment] = useState<string | null>(null)
  const [accountEnvironmentFilter, setAccountEnvironmentFilter] = useState(
    ALL_ACCOUNT_ENVIRONMENTS,
  )
  const [accountConnectionFilter, setAccountConnectionFilter] = useState(
    ALL_ACCOUNT_CONNECTIONS,
  )

  useEffect(() => {
    onNestedViewChange?.(selectedAccountId !== null)
  }, [onNestedViewChange, selectedAccountId])

  useEffect(() => {
    if (selectedAccountId === null) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault()
      event.stopPropagation()
      event.stopImmediatePropagation()
      setSelectedAccountId(null)
    }
    document.addEventListener('keydown', onKeyDown, true)
    return () => document.removeEventListener('keydown', onKeyDown, true)
  }, [selectedAccountId])

  const {
    unlinkAccount,
    setUnlinkAccount,
    unlinkOpen,
    setUnlinkOpen,
    actionError,
    setActionError,
    notice,
    setNotice,
    statusConfirm,
    setStatusConfirm,
    offboardOpen,
    setOffboardOpen,
    offboardTakeover,
    setOffboardTakeover,
    offboardCountdown,
    armOffboard,
    cancelOffboard,
    restoreOpen,
    setRestoreOpen,
    restoreMutation,
    purgeOpen,
    setPurgeOpen,
    cascadeOperationId,
    setCascadeOperationId,
    rotateOpen,
    setRotateOpen,
    shareOpen,
    setShareOpen,
    shareLink,
    shareLinkOpen,
    setShareLinkOpen,
    statusMutation,
    offboardMutation,
    purgeMutation,
    unlinkMutation,
    rotateMutation,
    shareMutation,
    createCredentialOpen,
    setCreateCredentialOpen,
    createCredentialMutation,
  } = usePrincipalActions(principalId)

  const principalQuery = useQuery({
    queryKey: qk.principal(principalId),
    queryFn: ({ signal }) =>
      api<PrincipalDetail>(`/api/v1/principals/${principalId}`, { signal }),
  })

  // Имена подключений для колонки «Подключение» — ключ общий с другими
  // экранами, кэш переиспользуется.
  const connectionsQuery = useQuery({
    queryKey: qk.connections(),
    queryFn: ({ signal }) =>
      apiList<Connection>('/api/v1/connections', 'connections', signal),
  })

  const connectionsById = useMemo(
    () => indexById(connectionsQuery.data ?? []),
    [connectionsQuery.data],
  )

  // Профиль показывает не только факт привязки аккаунта, но и его текущие
  // роли. Ключи совпадают с экраном подключения, поэтому уже загруженный
  // инвентарь переиспользуется, а подписи прав собирает общий helper.
  const profileAccounts = principalQuery.data?.accounts ?? []
  const profileConnectionIds = useMemo(
    () => [...new Set(profileAccounts.map((account) => account.connection_id))],
    [profileAccounts],
  )
  const accountBindingQueries = useQueries({
    queries: profileAccounts.map((account) => ({
      queryKey: qk.accountBindings(account.id),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        apiList<Binding>(`/api/v1/accounts/${account.id}/bindings`, 'bindings', signal),
    })),
  })
  const profilePermissionQueries = useQueries({
    queries: profileConnectionIds.map((connectionId) => ({
      queryKey: qk.connectionPermissions(connectionId),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        apiList<Permission>(
          `/api/v1/connections/${connectionId}/permissions`,
          'permissions',
          signal,
        ),
    })),
  })
  const profileResourceQueries = useQueries({
    queries: profileConnectionIds.map((connectionId) => ({
      queryKey: qk.connectionResources(connectionId),
      queryFn: ({ signal }: { signal: AbortSignal }) =>
        apiList<Resource>(
          `/api/v1/connections/${connectionId}/resources`,
          'resources',
          signal,
        ),
    })),
  })
  const profileConnectionIndex = useMemo(
    () => new Map(profileConnectionIds.map((connectionId, index) => [connectionId, index])),
    [profileConnectionIds],
  )

  const credentialsQuery = useQuery({
    queryKey: qk.principalCredentials(principalId),
    queryFn: ({ signal }) =>
      apiList<PrincipalCredentialEnvironment>(
        `/api/v1/principals/${principalId}/credentials`,
        'credentials',
        signal,
      ),
  })

  // Credential принципала скоупится окружением, а не существует глобально.
  const credentialEnvironments = useMemo<CredentialEnvironmentSummary[]>(() => {
    const byEnvironment = new Map<string, CredentialEnvironmentSummary>()
    for (const credential of credentialsQuery.data ?? []) {
      byEnvironment.set(credential.environment, {
        environment: credential.environment,
        connections: credential.connections,
        accounts: 0,
        configured: credential.configured,
        actionable: false,
      })
    }
    for (const account of principalQuery.data?.accounts ?? []) {
      const connection = connectionsById.get(account.connection_id)
      if (connection === undefined || account.status === 'deleted') continue
      const environment = environmentLabel(connection)
      const current = byEnvironment.get(environment) ?? {
        environment,
        connections: 0,
        accounts: 0,
        configured: false,
        actionable: false,
      }
      current.accounts += 1
      current.actionable ||=
        account.status === 'active' &&
        account.ownership === 'managed' &&
        account.credential_mode === SHARED_CREDENTIAL_MODE
      byEnvironment.set(environment, current)
    }
    return [...byEnvironment.values()].sort((a, b) =>
      a.environment.localeCompare(b.environment),
    )
  }, [principalQuery.data, connectionsById, credentialsQuery.data])
  const rotatableEnvironments = credentialEnvironments
    .filter((item) => item.actionable)
    .map((item) => item.environment)
  const sharedEnvironments = credentialEnvironments
    .filter((item) => item.configured)
    .map((item) => item.environment)

  const offboardTargets = useMemo(
    () =>
      (principalQuery.data?.accounts ?? []).filter(
        (account) => account.ownership === 'managed' && account.status !== 'deleted',
      ),
    [principalQuery.data],
  )
  if (principalQuery.isError) {
    return (
      <div className="mx-auto max-w-6xl">
        <ErrorState
          message={errorMessage(principalQuery.error)}
          onRetry={() => {
            void principalQuery.refetch()
          }}
        />
      </div>
    )
  }
  if (principalQuery.isPending) {
    return <DetailPageSkeleton />
  }

  const principal = principalQuery.data
  const principalName = principal.display_name
  const disabled = principal.status === 'disabled'
  // Tombstone после offboard: действия скрыты, страница только показывает
  // прежние аккаунты (deleted) и статус.
  const isDeleted = principal.status === 'deleted'
  // Вывод из системы запущен, но срок хранения не истёк: доступ закрыт,
  // данные целы, операция отменяется одной кнопкой.
  const pendingPurge = principal.status === 'pending_purge'
  const externalIdentityNeedsOffboard =
    principal.external_identity_status === 'disabled' ||
    principal.external_identity_status === 'deleted'
  const accounts = principal.accounts
  const identity = externalIdentity(principal)
  const noSharedHint =
    sharedEnvironments.length === 0
      ? 'У пользователя пока нет настроенных credential окружений'
      : undefined
  const noRotatableHint =
    rotatableEnvironments.length === 0
      ? 'Нет активных managed-аккаунтов, к которым нужно применить новый пароль'
      : undefined

  // Managed-аккаунты — цели каскада disable/enable и offboard; unmanaged
  // привязанные offboard не трогает и перечисляет для ручного внимания.
  const managedAccounts = accounts.filter(
    (account) => account.ownership === 'managed' && account.status !== 'deleted',
  )
  const unmanagedLinked = accounts.filter(
    (account) => account.ownership !== 'managed' && account.status !== 'deleted',
  )
  // Аккаунты на личных паролях: ротация общего секрета их не касается, а
  // offboard делит их по тому, владеет ли grantor паролем. Аккаунт без
  // credential приняли под управление без пароля — сменить его значит
  // присвоить чужой, поэтому нужен явный takeover.
  const ownCredentialAccounts = managedAccounts.filter((account) =>
    accountOnOwnCredential(account, principal.id),
  )
  const takeoverAccounts = ownCredentialAccounts.filter(
    (account) => !accountHasCredential(account),
  )
  const connectionName = (connectionId: string) =>
    connectionsById.get(connectionId)?.display_name ?? shortId(connectionId)
  const accountConnections = [...new Map(
    accounts
      .map((account) => connectionsById.get(account.connection_id))
      .filter((connection): connection is Connection => connection !== undefined)
      .map((connection) => [connection.id, connection]),
  ).values()]
  const accountEnvironments = [...new Set(
    accountConnections.map((connection) => environmentLabel(connection)),
  )].sort((left, right) => left.localeCompare(right, 'ru'))
  const connectionFilterCandidates = accountConnections
    .filter(
      (connection) =>
        accountEnvironmentFilter === ALL_ACCOUNT_ENVIRONMENTS ||
        environmentLabel(connection) === accountEnvironmentFilter,
    )
    .sort((left, right) =>
      left.display_name.localeCompare(right.display_name, 'ru', { sensitivity: 'base' }),
    )
  const environmentFilteredAccounts = accounts.filter((account) => {
    const connection = connectionsById.get(account.connection_id)
    return !(
      accountEnvironmentFilter !== ALL_ACCOUNT_ENVIRONMENTS &&
      (connection === undefined || environmentLabel(connection) !== accountEnvironmentFilter)
    )
  })
  const filteredAccounts = environmentFilteredAccounts.filter((account) => {
    return (
      accountConnectionFilter === ALL_ACCOUNT_CONNECTIONS ||
      account.connection_id === accountConnectionFilter
    )
  })
  const environmentFilterOptions = [
    {
      value: ALL_ACCOUNT_ENVIRONMENTS,
      label: 'Все окружения',
      count: accounts.length,
    },
    ...accountEnvironments.map((environment) => ({
      value: environment,
      label: connectionEnvironmentLabel(environment),
      count: accounts.filter((account) => {
        const connection = connectionsById.get(account.connection_id)
        return connection !== undefined && environmentLabel(connection) === environment
      }).length,
    })),
  ]
  const connectionFilterOptions = [
    {
      value: ALL_ACCOUNT_CONNECTIONS,
      label: 'Все подключения',
      count: environmentFilteredAccounts.length,
    },
    ...connectionFilterCandidates.map((connection) => ({
      value: connection.id,
      label: connection.display_name,
      count: accounts.filter((account) => account.connection_id === connection.id).length,
    })),
  ]
  const bindingQueryByAccount = new Map(
    profileAccounts.map((account, index) => [account.id, accountBindingQueries[index]]),
  )
  const offboardAccessByAccount = new Map(
    offboardTargets.map((account) => {
      const bindings = bindingQueryByAccount.get(account.id)?.data
      return [account.id, bindings === undefined ? null : activeAccessBindings(bindings).length]
    }),
  )
  const offboardScopePending = offboardTargets.some(
    (account) => bindingQueryByAccount.get(account.id)?.isPending === true,
  )
  const offboardScopeError = offboardTargets.some(
    (account) => bindingQueryByAccount.get(account.id)?.isError === true,
  )
  const offboardAccessTotal = [...offboardAccessByAccount.values()].reduce<number | null>(
    (total, count) => (total === null || count === null ? null : total + count),
    0,
  )
  const accountLines = (list: typeof accounts, showAccess = false) =>
    list.map((account) => (
      <span key={account.id} className="block font-mono text-[12px] text-text">
        {account.engine_identity}
        <span className="font-sans text-muted"> · {connectionName(account.connection_id)}</span>
        {showAccess && (
          <span className="font-sans text-muted">
            {' '}· {offboardAccessByAccount.get(account.id) ?? '—'} активных доступов
          </span>
        )}
      </span>
    ))
  const accessForAccount = (account: Account) => {
    const accountIndex = profileAccounts.findIndex((item) => item.id === account.id)
    const connectionIndex = profileConnectionIndex.get(account.connection_id)
    if (accountIndex < 0 || connectionIndex === undefined) {
      return { state: 'loading' as const, entries: [] }
    }
    const bindingsQuery = accountBindingQueries[accountIndex]
    const permissionsQuery = profilePermissionQueries[connectionIndex]
    const resourcesQuery = profileResourceQueries[connectionIndex]
    if (bindingsQuery?.isError || permissionsQuery?.isError || resourcesQuery?.isError) {
      return { state: 'error' as const, entries: [] }
    }
    if (
      bindingsQuery?.data === undefined ||
      permissionsQuery?.data === undefined ||
      resourcesQuery?.data === undefined
    ) {
      return { state: 'loading' as const, entries: [] }
    }
    return {
      state: 'ready' as const,
      entries: buildAccessEntries(
        bindingsQuery.data,
        indexById(permissionsQuery.data),
        indexById(resourcesQuery.data),
      ),
    }
  }
  const ownedDatabasesForAccount = (account: Account) => {
    const connectionIndex = profileConnectionIndex.get(account.connection_id)
    if (connectionIndex === undefined) return []
    return directlyOwnedPostgresDatabases(
      account,
      connectionsById.get(account.connection_id),
      profileResourceQueries[connectionIndex]?.data ?? [],
    )
  }
  const panelOperationId = accessOperationId ?? cascadeOperationId
  const selectedAccount =
    selectedAccountId === null
      ? null
      : (accounts.find((account) => account.id === selectedAccountId) ?? null)

  if (selectedAccount !== null) {
    const connection = connectionsById.get(selectedAccount.connection_id)
    const selectedActions = accountActions(selectedAccount, auth.role, connection)
    return (
      <PrincipalAccountProfile
        account={selectedAccount}
        connection={connection}
        principal={principal}
        ownedDatabases={ownedDatabasesForAccount(selectedAccount)}
        canUnlink={canOperate && !isDeleted && selectedAccount.status !== 'deleted'}
        canManageLinked={
          !isDeleted && principal.status === 'active' && selectedActions.manageLinked
        }
        unlinkPending={unlinkMutation.isPending}
        actionError={actionError}
        onBack={() => setSelectedAccountId(null)}
        onUnlink={() => {
          setUnlinkAccount(selectedAccount)
          setUnlinkOpen(true)
        }}
        onManaged={(operationId) => {
          setActionError(null)
          setNotice(
            `Операция ${shortId(operationId)} запущена: аккаунт ${selectedAccount.engine_identity} переводится на общий credential пользователя`,
          )
          setSelectedAccountId(null)
        }}
        unlinkDialog={
          <ConfirmActionDialog
            open={unlinkOpen && unlinkAccount !== null}
            title="Отвязать аккаунт"
            description={
              <>
                Аккаунт{' '}
                <span className="font-mono text-text">{selectedAccount.engine_identity}</span>{' '}
                будет отвязан от пользователя{' '}
                <span className="text-text">{principalName}</span>. Привязка хранится в
                метаданных control plane: учётная запись в целевой системе не изменится.
              </>
            }
            confirmLabel="Отвязать"
            pending={unlinkMutation.isPending}
            onConfirm={() => unlinkMutation.mutate(selectedAccount)}
            onClose={() => setUnlinkOpen(false)}
          />
        }
      />
    )
  }

  return (
    <div className={cn('space-y-4', !embedded && 'mx-auto max-w-6xl')}>
      {!embedded && <div>
        <Link
          to="/principals"
          className="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-text"
        >
          <ArrowLeft className="size-4" />
          Пользователи
        </Link>
      </div>}

      <div className="flex min-w-0 items-start gap-3">
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
          {!embedded && (
            <div className="min-w-0">
              <h1 className="break-words font-mono text-lg font-semibold">{principalName}</h1>
            </div>
          )}
          <PrincipalTypeChip type={principal.type} />
          <PrincipalIdentityChips principal={principal} />
          {identity !== '—' && (
            <span className="font-mono text-[12px] text-muted">{identity}</span>
          )}
        </div>
        <span
          className="ml-auto shrink-0 pt-1 text-[11px] text-faint"
          title={formatDateTime(principal.created_at)}
        >
          создан: {formatRelative(principal.created_at)}
        </span>
      </div>
      {/* UUID пользователя — ключ путей его секретов в Vault
          (principals/<id>/environments/<env>/credential). Полностью он не
          показывался нигде, а по shortId в Vault не найти. */}
      <div className="flex items-center gap-1 text-[11px] text-faint">
        <span>ID</span>
        <CopyableValue
          value={principal.id}
          label="Копировать идентификатор пользователя"
          compactAction
          valueClassName="font-mono"
        >
          {principal.id}
        </CopyableValue>
      </div>
      {canOperate && !isDeleted && (
        <div className="flex flex-wrap items-center gap-1.5">
            <Button size="sm" onClick={() => setGrantOpen(true)}>
              <KeyRound className="size-3.5" />
              Выдать доступ
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={rotatableEnvironments.length === 0 || rotateMutation.isPending}
              title={noRotatableHint}
              onClick={() => setRotateOpen(true)}
            >
              <RotateCw className="size-3.5" />
              Ротировать пароль
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={sharedEnvironments.length === 0 || shareMutation.isPending}
              title={noSharedHint}
              onClick={() => setShareOpen(true)}
            >
              {shareMutation.isPending ? (
                <Spinner className="size-3.5" />
              ) : (
                <Link2 className="size-3.5" />
              )}
              Получить учётные данные
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={statusMutation.isPending}
              onClick={() => setStatusConfirm(disabled ? 'enable' : 'disable')}
            >
              {statusMutation.isPending ? (
                <Spinner className="size-3.5" />
              ) : disabled ? (
                <Power className="size-3.5" />
              ) : (
                <PowerOff className="size-3.5" />
              )}
              {disabled ? 'Включить' : 'Отключить'}
            </Button>
            {isAdmin && (
              <Button
                variant="danger"
                size="sm"
                disabled={offboardMutation.isPending || offboardCountdown !== null}
                onClick={() => {
                  // Согласие на чужие пароли не переносится между открытиями:
                  // прошлый выбор здесь означал бы молчаливую ротацию.
                  setOffboardTakeover(false)
                  setOffboardOpen(true)
                }}
              >
                {offboardMutation.isPending ? (
                  <Spinner className="size-3.5" />
                ) : (
                  <UserX className="size-3.5" />
                )}
                Вывести из системы
              </Button>
            )}
        </div>
      )}
      {pendingPurge && (
        <div className="flex flex-wrap items-center gap-3 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">
          <div className="min-w-0 flex-1">
            <p className="font-medium text-text">Пользователь выводится из системы</p>
            <p className="mt-0.5 text-xs text-muted">
              Права отозваны и пароль сменён, но ничего не удалено
              {principal.purge_after !== null && principal.purge_after !== undefined
                ? `: восстановить можно до ${formatDateTime(principal.purge_after)}`
                : ''}
              . После этого срока аккаунты и пароли удаляются безвозвратно.
            </p>
          </div>
          {isAdmin && (
            <Button
              size="sm"
              disabled={restoreMutation.isPending}
              onClick={() => setRestoreOpen(true)}
            >
              {restoreMutation.isPending ? (
                <Spinner className="size-3.5" />
              ) : (
                <Power className="size-3.5" />
              )}
              Отменить вывод
            </Button>
          )}
        </div>
      )}

      {isAdmin && isDeleted && (
          <Button
            variant="danger"
            size="sm"
            disabled={purgeMutation.isPending || accounts.length > 0}
            title={accounts.length > 0 ? 'Сначала удалите все аккаунты пользователя' : undefined}
            onClick={() => setPurgeOpen(true)}
          >
            {purgeMutation.isPending ? (
              <Spinner className="size-3.5" />
            ) : (
              <Trash2 className="size-3.5" />
            )}
            Удалить навсегда
          </Button>
      )}

      {externalIdentityNeedsOffboard && !isDeleted && (
        <p className="flex min-h-9 items-center rounded-md border border-warn/40 bg-warn-soft px-3 py-1.5 text-sm text-warn">
          Внешняя identity неактивна. Проверьте scope и выполните Offboard managed-аккаунтов.
        </p>
      )}

      {offboardCountdown !== null && (
        <div
          role="status"
          className="flex min-h-9 items-center gap-3 rounded-md border border-danger/40 bg-danger-soft px-3 py-1.5 text-sm text-danger"
        >
          <span>
            Вывод пользователя <span className="font-medium">{principalName}</span> начнётся
            через {offboardCountdown} с: права будут отозваны, пароли заменены.
          </span>
          <Button size="sm" variant="outline" className="ml-auto shrink-0" onClick={cancelOffboard}>
            Отменить
          </Button>
        </div>
      )}

      {notice !== null && <InlineNotice text={notice} onClose={() => setNotice(null)} />}

      {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}

      {panelOperationId !== null && (
        <BulkOperationPanel
          operationId={panelOperationId}
          accounts={accounts}
          onClose={() => {
            setAccessOperationId(null)
            setCascadeOperationId(null)
          }}
          onSettled={() => {
            // Ротация/каскад меняют аккаунты и credentials — карточка
            // обновляется сразу по завершении, а не по закрытию панели.
            void queryClient.invalidateQueries({ queryKey: qk.principals() })
            void queryClient.invalidateQueries({
              queryKey: qk.principalCredentials(principalId),
            })
          }}
        />
      )}

      <section className="space-y-2">
        <div>
          <h2 className="text-sm font-semibold text-text">Credential по окружениям</h2>
          <p className="mt-0.5 text-xs text-muted">
            Отдельный credential для каждого окружения можно подготовить заранее;
            аккаунты пользователя затем переиспользуют его автоматически.
          </p>
        </div>
        {credentialsQuery.isError ? (
          <ErrorBanner>{errorMessage(credentialsQuery.error)}</ErrorBanner>
        ) : credentialEnvironments.length === 0 ? (
          <p className="rounded-md border border-line bg-panel2/40 px-3 py-2 text-sm text-muted">
            Окружений пока нет: создайте окружение на Обзоре или добавьте первое
            подключение.
          </p>
        ) : (
          <div className="divide-y divide-line rounded-md border border-line">
            {credentialEnvironments.map((item) => (
              <div key={item.environment} className="flex items-center gap-3 px-3 py-2">
                <span className="min-w-0 flex-1">
                  <span className="block font-mono text-[12px] text-text">
                    {item.environment}
                  </span>
                  {/* Готовый путь секрета: собирается по той же схеме, что
                      internal/providers/vault/paths.go, чтобы не искать его
                      вручную по UUID и имени окружения. */}
                  <CopyableValue
                    value={principalCredentialVaultPath(principal.id, item.environment)}
                    label={`Копировать путь credential в Vault для окружения ${item.environment}`}
                    compactAction
                    valueClassName="font-mono text-[11px] text-faint"
                  >
                    {principalCredentialVaultPath(principal.id, item.environment)}
                  </CopyableValue>
                </span>
                <span className="text-xs tabular-nums text-muted">
                  подключений: {item.connections} · аккаунтов: {item.accounts}
                </span>
                {item.configured === null ? (
                  <StatusChip
                    tone="warn"
                    title="Vault не ответил про это окружение; статус появится после обновления"
                  >
                    {UI_COPY.configuredUnknown}
                  </StatusChip>
                ) : (
                  <StatusChip
                    tone={item.configured ? 'ok' : 'unmg'}
                    title={
                      item.configured && !item.actionable
                        ? 'Credential хранится в Vault; ротация станет доступна после появления активного managed-аккаунта'
                        : undefined
                    }
                  >
                    {item.configured ? UI_COPY.configured : UI_COPY.notConfigured}
                  </StatusChip>
                )}
                {canOperate && !isDeleted && item.configured === false && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      setCreateCredentialEnvironment(item.environment)
                      setCreateCredentialOpen(true)
                    }}
                  >
                    <KeyRound className="size-3.5" />
                    Создать
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </section>

      <div className="space-y-2">
        <h2 className="text-sm font-semibold text-text">Аккаунты и доступы</h2>
        {accounts.length === 0 ? (
          <p className="rounded-md border border-line bg-panel2/30 px-3 py-2 text-sm text-muted">
            <span className="font-medium text-text">Нет привязанных аккаунтов.</span>{' '}
            Выдайте доступ или свяжите существующий аккаунт в подключении.
          </p>
        ) : (
          <>
            <div
              aria-label="Фильтры аккаунтов пользователя"
              className="flex flex-wrap items-center gap-1.5"
            >
              <SelectionSelect
                label="Фильтр по окружению"
                value={accountEnvironmentFilter}
                inactiveValue={ALL_ACCOUNT_ENVIRONMENTS}
                options={environmentFilterOptions}
                icon={<Globe2 className="size-3.5" aria-hidden="true" />}
                onChange={(value) => {
                  setAccountEnvironmentFilter(value)
                  if (
                    value !== ALL_ACCOUNT_ENVIRONMENTS &&
                    accountConnectionFilter !== ALL_ACCOUNT_CONNECTIONS
                  ) {
                    const selectedConnection = connectionsById.get(accountConnectionFilter)
                    if (
                      selectedConnection === undefined ||
                      environmentLabel(selectedConnection) !== value
                    ) {
                      setAccountConnectionFilter(ALL_ACCOUNT_CONNECTIONS)
                    }
                  }
                }}
              />
              <SelectionSelect
                label="Фильтр по подключению"
                value={accountConnectionFilter}
                inactiveValue={ALL_ACCOUNT_CONNECTIONS}
                options={connectionFilterOptions}
                icon={<Cable className="size-3.5" aria-hidden="true" />}
                onChange={setAccountConnectionFilter}
              />
            </div>
            <div
              role="table"
              aria-label="Аккаунты и доступы пользователя"
              className="divide-y divide-line/35 overflow-hidden rounded-lg border border-line bg-panel"
            >
            {filteredAccounts.map((account) => {
              const connection = connectionsById.get(account.connection_id)
              const access = accessForAccount(account)
              const ownedDatabases = ownedDatabasesForAccount(account)
              const openAccount = () => setSelectedAccountId(account.id)
              return (
                <div
                  key={account.id}
                  role="row"
                  tabIndex={0}
                  aria-label={`Открыть аккаунт ${account.engine_identity}`}
                  className="ui-interactive-row cursor-pointer space-y-2 px-3 py-3 transition-colors hover:bg-panel2/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
                  onClick={(event) => {
                    const target = event.target
                    if (target instanceof Element && target.closest('button,a,[role="button"]') !== null) return
                    openAccount()
                  }}
                  onKeyDown={(event) => {
                    if (
                      event.target === event.currentTarget &&
                      (event.key === 'Enter' || event.key === ' ')
                    ) {
                      event.preventDefault()
                      openAccount()
                    }
                  }}
                >
                  <div role="cell" className="flex min-w-0 flex-wrap items-start gap-2">
                    <div className="min-w-0 flex-1 space-y-1">
                      <TableCopyableValue
                        value={account.engine_identity}
                        label={`Копировать имя аккаунта ${account.engine_identity}`}
                        className="min-w-0 font-mono text-[13px] font-medium text-text"
                      />
                      <div className="flex flex-wrap items-center gap-1.5">
                        <KindBadge
                          kind={account.kind}
                          principalType={principal.type}
                          className="w-fit text-[11px]"
                        />
                        <MetadataChip className="font-sans uppercase tracking-wide text-faint">
                          {connection === undefined
                            ? '—'
                            : connectionEnvironmentLabel(connection.environment)}
                        </MetadataChip>
                      </div>
                      <AccountDatabaseOwnership databases={ownedDatabases} />
                    </div>
                    <div className="flex flex-wrap items-center justify-end gap-1.5">
                      {!isSharedRoleKind(account.kind) && (
                        <StatusChip tone={ownershipTone(account.ownership)}>
                          {ownershipLabel(account.ownership)}
                        </StatusChip>
                      )}
                      <StatusChip tone={inventoryStatusTone(account.status)}>
                        {inventoryStatusLabel(account.status)}
                      </StatusChip>
                      {canOperate && !isDeleted && (
                        <UnlinkAccountButton
                          onClick={(event) => {
                            event.stopPropagation()
                            setUnlinkAccount(account)
                            setUnlinkOpen(true)
                          }}
                        />
                      )}
                    </div>
                  </div>

                  <div role="cell" className="flex min-w-0 flex-wrap items-center gap-2 text-xs">
                    <span className="shrink-0 text-faint">Подключение</span>
                    <a
                      href={`/connections/${account.connection_id}`}
                      title={`Открыть подключение ${connection?.display_name ?? shortId(account.connection_id)}`}
                      className={metadataChipClassName(true)}
                    >
                      {connection !== undefined && (
                        <EngineBadge
                          engine={connection.engine}
                          className="size-4 border-0 bg-transparent"
                        />
                      )}
                      <span className="truncate">
                        {connection?.display_name ?? shortId(account.connection_id)}
                      </span>
                    </a>
                  </div>

                  <div role="cell" className="flex min-w-0 flex-wrap items-center gap-2">
                    <span className="shrink-0 text-xs text-faint">Доступ</span>
                    <div className="min-w-0 flex-1">
                      {access.state === 'loading' ? (
                        <Spinner className="size-3.5" />
                      ) : access.state === 'error' ? (
                        <span className="text-xs text-danger">Не удалось загрузить</span>
                      ) : access.entries.length === 0 ? (
                        <span className="text-faint" title="У аккаунта нет активных назначений">—</span>
                      ) : (
                        <AccessChipList entries={access.entries} maxVisible={3} wrapLabels />
                      )}
                    </div>
                  </div>
                </div>
              )
            })}
            {filteredAccounts.length === 0 && (
              <p className="px-3 py-6 text-center text-sm text-muted">
                Аккаунты по выбранным фильтрам не найдены
              </p>
            )}
            </div>
          </>
        )}
      </div>

      {isAdmin && !isDeleted && principal.type === 'service' && (
        <ServiceTokensSection
          principalId={principal.id}
          principalName={principalName}
        />
      )}

      <GrantAccessDrawer
        open={grantOpen}
        principalId={principal.id}
        principalName={principalName}
        onClose={() => setGrantOpen(false)}
        onStarted={(operationId) => {
          setGrantOpen(false)
          setActionError(null)
          setAccessOperationId(operationId)
          setNotice(`Операция ${shortId(operationId)} запущена: выдача доступа`)
        }}
      />

      <EnvironmentPickerDialog
        open={rotateOpen}
        title="Ротация пароля"
        description={
          <>
            Общий пароль пользователя{' '}
            <span className="text-text">{principalName}</span> в выбранном
            окружении будет заменён: новая версия сохранится в Vault и применится
            во всех его аккаунтах этого окружения. Старый пароль перестанет
            действовать.
            {ownCredentialAccounts.length > 0 && (
              <span className="mt-2 block text-warn">
                Аккаунты на личных паролях ({ownCredentialAccounts.length}) сюда не
                входят: у каждого свой пароль, и новый пришлось бы выдавать по
                отдельности. Ротируйте их на карточке аккаунта.
                <span className="mt-1 block">{accountLines(ownCredentialAccounts)}</span>
              </span>
            )}
          </>
        }
        confirmLabel="Ротировать"
        environments={rotatableEnvironments}
        pending={rotateMutation.isPending}
        onConfirm={(environment) => rotateMutation.mutate(environment)}
        onClose={() => setRotateOpen(false)}
      />

      <EnvironmentPickerDialog
        open={shareOpen}
        title="Получить учётные данные"
        description={
          <>
            Будет создана одноразовая ссылка на общий пароль пользователя{' '}
            <span className="text-text">{principalName}</span> в выбранном
            окружении. Ссылка показывается один раз и не сохраняется.
          </>
        }
        confirmLabel="Создать ссылку"
        environments={sharedEnvironments}
        pending={shareMutation.isPending}
        onConfirm={(environment) => shareMutation.mutate(environment)}
        onClose={() => setShareOpen(false)}
      />

      <ShareLinkDialog
        open={shareLinkOpen}
        share={shareLink}
        onClose={() => setShareLinkOpen(false)}
      />

      <PrincipalCredentialDialog
        open={createCredentialOpen}
        environment={createCredentialEnvironment}
        pending={createCredentialMutation.isPending}
        onConfirm={(input) => createCredentialMutation.mutate(input)}
        onClose={() => {
          setCreateCredentialOpen(false)
          setCreateCredentialEnvironment(null)
        }}
      />

      <ConfirmActionDialog
        open={statusConfirm !== null}
        title={statusConfirm === 'enable' ? 'Включить пользователя' : 'Отключить пользователя'}
        description={
          statusConfirm === 'enable' ? (
            <>
              Пользователь <span className="text-text">{principalName}</span>{' '}
              будет включён: доступ будет включён во всех кластерах, его
              managed-аккаунты ({managedAccounts.length}) снова смогут логиниться.
              Действие обратимо.
              {managedAccounts.length > 0 && (
                <span className="mt-2 block">{accountLines(managedAccounts)}</span>
              )}
            </>
          ) : (
            <>
              Пользователь <span className="text-text">{principalName}</span>{' '}
              будет отключён: доступ будет отключён во всех кластерах, его
              managed-аккаунты ({managedAccounts.length}) перестанут логиниться.
              Пароли и гранты не удаляются, действие обратимо кнопкой «Включить».
              {managedAccounts.length > 0 && (
                <span className="mt-2 block">{accountLines(managedAccounts)}</span>
              )}
            </>
          )
        }
        confirmLabel={statusConfirm === 'enable' ? 'Включить' : 'Отключить'}
        pending={statusMutation.isPending}
        onConfirm={() => {
          if (statusConfirm !== null) {
            statusMutation.mutate(statusConfirm)
          }
        }}
        onClose={() => setStatusConfirm(null)}
      />

      <ConfirmActionDialog
        open={restoreOpen}
        title="Отменить вывод из системы"
        description={
          <div className="space-y-2">
            <p>
              Пользователь <span className="font-medium text-text">{principalName}</span> вернётся в
              работу: его managed-аккаунты включатся обратно, а общие пароли окружений снова станут
              доступны.
            </p>
            <p className="text-xs text-muted">
              Права будут выданы заново, ровно те, которые снял вывод из системы.
              Пароль остался новым: передайте его через «Получить учётные данные».
            </p>
          </div>
        }
        confirmLabel="Отменить вывод"
        pending={restoreMutation.isPending}
        onConfirm={() => restoreMutation.mutate()}
        onClose={() => setRestoreOpen(false)}
      />

      <ConfirmActionDialog
        open={offboardOpen}
        title="Вывести пользователя из системы"
        danger
        description={
          <>
            Offboard пользователя <span className="text-text">{principalName}</span>{' '}
            закроет доступ по managed-аккаунтам ({managedAccounts.length}) и их
            активным доступам ({offboardAccessTotal ?? '—'}): права отзываются,
            а пароли (и общий пароль окружения, и личные пароли аккаунтов)
            меняются на новые, которые никому не выдаются, так что вход тоже
            закрывается.
            {offboardScopePending && (
              <span className="mt-2 block text-muted">Считаем активные доступы…</span>
            )}
            {offboardScopeError && (
              <span className="mt-2 block text-warn">
                Часть scope не удалось загрузить; проверьте аккаунты вручную перед подтверждением.
              </span>
            )}
            {managedAccounts.length > 0 && (
              <span className="mt-2 block">{accountLines(managedAccounts, true)}</span>
            )}
            {unmanagedLinked.length > 0 && (
              <span className="mt-2 block text-warn">
                Исключения: metadata-only/unmanaged-аккаунты ({unmanagedLinked.length})
                и их доступы не изменятся. Сначала используйте «Связать и управлять»
                либо разберите их вручную:
                <span className="mt-1 block">{accountLines(unmanagedLinked)}</span>
              </span>
            )}
            {takeoverAccounts.length > 0 && (
              <div className="mt-3">
                <DangerConfirm
                  title={`Пароли ${takeoverAccounts.length} аккаунтов grantor не принадлежат`}
                  label={
                    <>
                      Эти учётки приняли под управление без пароля. Настоящий знает
                      владелец системы, и по умолчанию он останется рабочим. Отметьте,
                      чтобы принять пароли под управление и сменить их вместе с
                      остальными.
                      <span className="mt-1 block">{accountLines(takeoverAccounts)}</span>
                    </>
                  }
                  checked={offboardTakeover}
                  onChange={setOffboardTakeover}
                  isAdmin={isAdmin}
                />
              </div>
            )}
            <span className="mt-2 block">
              Ничего не удаляется сразу: вывод можно отменить одной кнопкой в течение
              срока хранения. По его истечении аккаунты и пароли удаляются безвозвратно.
            </span>
          </>
        }
        confirmLabel="Вывести из системы"
        pending={offboardMutation.isPending || offboardScopePending}
        onConfirm={() => armOffboard(offboardTakeover)}
        onClose={() => setOffboardOpen(false)}
      />

      <ConfirmActionDialog
        open={purgeOpen}
        title="Удалить пользователя навсегда"
        danger
        description={
          <>
            Пользователь <span className="text-text">{principalName}</span>{' '}
            будет полностью удалён из Grantor. Действие доступно только после
            удаления всех его аккаунтов и необратимо. Исторический audit сохранится.
          </>
        }
        confirmLabel="Удалить навсегда"
        pending={purgeMutation.isPending}
        onConfirm={() => purgeMutation.mutate(undefined, { onSuccess: onPurged })}
        onClose={() => setPurgeOpen(false)}
      />

      <ConfirmActionDialog
        open={unlinkOpen && unlinkAccount !== null}
        title="Отвязать аккаунт"
        description={
          unlinkAccount !== null ? (
            <>
              Аккаунт{' '}
              <span className="font-mono text-text">
                {unlinkAccount.engine_identity}
              </span>{' '}
              будет отвязан от пользователя{' '}
              <span className="text-text">{principalName}</span>. Привязка хранится в
              метаданных control plane: учётная запись в целевой системе не
              изменится.
            </>
          ) : (
            ''
          )
        }
        confirmLabel="Отвязать"
        pending={unlinkMutation.isPending}
        onConfirm={() => {
          if (unlinkAccount !== null) {
            unlinkMutation.mutate(unlinkAccount)
          }
        }}
        onClose={() => setUnlinkOpen(false)}
      />
    </div>
  )
}

interface PrincipalAccountProfileProps {
  account: Account
  connection?: Connection
  principal: PrincipalDetail
  ownedDatabases: readonly Resource[]
  canUnlink: boolean
  canManageLinked: boolean
  unlinkPending: boolean
  actionError: string | null
  onBack: () => void
  onUnlink: () => void
  onManaged: (operationId: string) => void
  unlinkDialog: ReactNode
}

/** Nested factual account view. Only the already implemented unlink action is exposed. */
function PrincipalAccountProfile({
  account,
  connection,
  principal,
  ownedDatabases,
  canUnlink,
  canManageLinked,
  unlinkPending,
  actionError,
  onBack,
  onUnlink,
  onManaged,
  unlinkDialog,
}: PrincipalAccountProfileProps) {
  const [manageOpen, setManageOpen] = useState(false)
  return (
    <div className="space-y-4">
      <Button variant="ghost" size="sm" onClick={onBack}>
        <ArrowLeft className="size-3.5" />
        Вернуться к пользователю
      </Button>

      <div className="flex flex-wrap items-center gap-2">
        <h2 className="mr-auto min-w-0 truncate font-mono text-base font-semibold text-text">
          {account.engine_identity}
        </h2>
        {!isSharedRoleKind(account.kind) && (
          <StatusChip tone={ownershipTone(account.ownership)}>{ownershipLabel(account.ownership)}</StatusChip>
        )}
        <StatusChip tone={inventoryStatusTone(account.status)}>{inventoryStatusLabel(account.status)}</StatusChip>
      </div>

      {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}

      <dl className="divide-y divide-line border-y border-line text-sm">
        <ProfileFact label="Пользователь" value={principal.display_name} />
        <ProfileFact
          label="Подключение"
          value={connection?.display_name ?? shortId(account.connection_id)}
        />
        <ProfileFact label="Kind" value={accountKindLabel(account.kind)} mono />
        <ProfileFact
          label="Auth scope"
          value={account.authentication_scope === '' ? 'нет' : account.authentication_scope}
          mono
        />
        <ProfileFact
          label="Credential mode"
          value={account.credential_mode === null || account.credential_mode === '' ? 'нет' : account.credential_mode}
          mono
        />
        <ProfileFact label="Vault path" value={account.vault_path === '' ? 'нет' : account.vault_path} mono />
        <ProfileFact label="Создан" value={formatDateTime(account.created_at)} />
        <ProfileFact label="Обновлён" value={formatDateTime(account.updated_at)} />
      </dl>

      <AccountDatabaseOwnership databases={ownedDatabases} detail />

      <div className="flex flex-wrap gap-2">
        {canManageLinked && connection !== undefined && (
          <Button variant="outline" size="sm" onClick={() => setManageOpen(true)}>
            <ShieldCheck className="size-3.5" />
            Перевести под управление
          </Button>
        )}
        {canUnlink && (
          <Button variant="outline" size="sm" disabled={unlinkPending} onClick={onUnlink}>
            {unlinkPending ? <Spinner className="size-3.5" /> : <Unlink className="size-3.5" />}
            Отвязать
          </Button>
        )}
      </div>

      {account.status === 'deleted' && (
        <p className="rounded-md border border-line bg-panel2/50 px-3 py-2 text-sm text-muted">
          Удалённый аккаунт сохранён для аудита и доступен только для просмотра.
        </p>
      )}
      {connection !== undefined && (
        <LinkPrincipalDialog
          open={manageOpen}
          account={account}
          connection={connection}
          lockedPrincipalId={principal.id}
          initialMode="managed"
          onClose={() => setManageOpen(false)}
          onLinked={(_principalName, mode, operationId) => {
            if (mode === 'managed' && operationId !== undefined) {
              setManageOpen(false)
              onManaged(operationId)
            }
          }}
        />
      )}
      {unlinkDialog}
    </div>
  )
}

function ProfileFact({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
  mono?: boolean
}) {
  return (
    <div className="grid gap-1 py-2.5 sm:grid-cols-[130px_minmax(0,1fr)] sm:gap-3">
      <dt className="text-xs text-faint">{label}</dt>
      <dd className={cn('min-w-0 break-all text-text', mono && 'font-mono text-[12px]')}>
        {value}
      </dd>
    </div>
  )
}
