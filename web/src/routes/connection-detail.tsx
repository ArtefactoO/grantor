// Экран «Подключение»: заголовок со статусом, сводные карточки зон и
// вкладки, разнесённые по зонам (lib/zones): managed — Аккаунты,
// sync — Ресурсы, Роли и настроенный pg_hba (read-only снимок кластера).
// Дерево ресурсов и панель деталей ресурса живут в resource-tree.tsx.
// Вкладка «Аккаунты» с мутациями живёт в connection-accounts.tsx, общие
// блоки панелей — в connection-panels.tsx.
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getRouteApi, Link, useNavigate } from '@tanstack/react-router'
import {
  ArrowLeft,
  Clock3,
  Download,
  FileCode2,
  FolderTree,
  KeyRound,
  Pencil,
  Plus,
  Power,
  PowerOff,
  ShieldCheck,
  Trash2,
} from '@project/ui/icons'
import { api, ApiError, apiList, downloadBlob } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  AccessExportSection,
  AccessManifest,
  AccessSnapshot,
  Connection,
  ManifestEntry,
  Permission,
  Resource,
  ResourceTreeItem,
} from '../lib/types'
import {
  connectionStatusTone,
  driftTotal,
  inventoryStatusTone,
  ownershipTone,
  shortId,
} from '../lib/status'
import { indexById } from '../lib/indexById'
import { permissionNameLabel } from '../lib/access-entries'
import { isPostgresObjectPrivilege } from '../lib/postgres-object-acl'
import { rawExpression } from '../lib/permission-view'
import { isSharedRoleKind } from '../lib/account-actions'
import { formatDateTime } from '../lib/time'
import {
  ZoneSectionHeader,
  ZoneTabs,
} from '../lib/zones'
import type { Zone, ZoneTabItem } from '../lib/zones'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  Button,
  CopyableValue,
  TableCopyableValue,
  IconButton,
  Tooltip,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Spinner,
  DetailPageSkeleton,
  EmptyState,
  ErrorState,
  ErrorBanner,
  InlineNotice,
} from '@project/ui'
import { ConnectionSyncButton } from '../components/connection-sync-button'
import { EngineBadge, StatusChip, TagBadge } from '../components/ui/badge'
import { QueryStates } from '../components/ui/query-states'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { CheckboxChipGroup } from '../components/ui/selection-chips'
import { ElevatedAccessDot } from '../components/ui/access-chips'
import { AccountsTab, useConnectionAccountsQuery } from './connection-accounts'
import { kafkaPlainInventoryOnly } from '../lib/kafka-inventory'
import { RedisNoAuthNotice } from './connection-auth-mode-field'
import { CreateAccountDrawer } from './connection-account-dialogs'
import { GrantAccessDrawer } from './principal-access-drawer'
import { OperationProgressNotice } from '../components/operation-progress-notice'
import type { TrackedOperation } from '../components/operation-progress-notice'
import { EditConnectionDialog } from './connection-edit-dialog'
import { buildResourceTree, ResourceDetailPanel, ResourceTree } from './resource-tree'
import { InspectorSplitLayout } from './connection-panels'
import { CreateRoleDialog } from './connection-role-create-dialog'
import { ConnectionRoleDefinitionDialog } from './connection-role-definition-dialog'
import { PostgresBasicRolesDialog } from './connection-postgres-basic-roles-dialog'
import type { RoleTemplateCatalog } from '../lib/role-template-document'
import { PostgresRolePoliciesSection } from './connection-role-policies'
import { MongoDBRolePoliciesSection } from './connection-mongodb-role-policies'
import {
  canEditAccessTemplates,
  ConnectionAccessTemplatesDialog,
  supportsAccessTemplates,
} from './connection-access-templates-dialog'
import type { AccessTemplateEditorIntent } from './connection-access-templates-dialog'
import { readRabbitMQPermissionTemplates } from '../lib/rabbitmq-permission-templates'
import { CreateDatabaseDialog, DatabaseCreationNotice } from './connection-database-create-dialog'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'
import { postgresProvisioningReady } from '../lib/postgres-provisioning-authority'
import { ConnectionHBASection, useConnectionHBA } from './connection-hba-section'
import {
  AdminCredentialChangePanel,
  ConnectionAdminCredentialDialog,
  isTerminalAdminCredentialChange,
  shouldPollAdminCredentialChange,
} from './connection-admin-credential'
import {
  connectionEnvironmentLabel,
  formatCompactRelative,
  shortServerVersion,
} from '../lib/connection-presentation'
import {
  accountKindLabel,
  connectionStatusLabel,
  connectionSyncLabel,
  bindingStateLabel,
  inventoryStatusLabel,
  ownershipLabel,
  UI_COPY,
} from '../lib/ui-copy'

const routeApi = getRouteApi('/connections/$connectionId')

type TabKey = 'resources' | 'accounts' | 'roles' | 'hba'

// Вкладки разнесены по зонам (lib/zones): сначала то, чем grantor
// управляет, затем read-only снимок кластера. Порядок групп рисует ZoneTabs.
const TABS: Array<ZoneTabItem<TabKey>> = [
  { key: 'accounts', label: 'Аккаунты', zone: 'managed' },
  { key: 'resources', label: 'Ресурсы', zone: 'sync' },
  { key: 'roles', label: 'Роли', zone: 'sync' },
]
const TABS_WITH_HBA: Array<ZoneTabItem<TabKey>> = [
  ...TABS,
  { key: 'hba', label: 'pg_hba', zone: 'sync' },
]

export function ConnectionDetailPage() {
  const { connectionId } = routeApi.useParams()
  return <ConnectionDetailSession key={connectionId} connectionId={connectionId} />
}

function ConnectionDetailSession({ connectionId }: { connectionId: string }) {
  // Deep-link из «Контроля»: search задаёт вкладку и предвыбранную сущность.
  const deepLink = routeApi.useSearch()
  const auth = useAuth()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [tab, setTab] = useState<TabKey>(deepLink.tab ?? 'accounts')

  // Повторный переход по находке на уже открытой странице обязан
  // переключить вкладку так же, как первый.
  useEffect(() => {
    if (deepLink.tab !== undefined) setTab(deepLink.tab)
  }, [deepLink.tab])
  const [editOpen, setEditOpen] = useState(false)
  const [createDatabaseOpen, setCreateDatabaseOpen] = useState(false)
  const [createAccountOpen, setCreateAccountOpen] = useState(false)
  const [grantAccessOpen, setGrantAccessOpen] = useState(false)
  const [accountOperation, setAccountOperation] = useState<TrackedOperation | null>(null)
  const [adminCredentialOpen, setAdminCredentialOpen] = useState(false)
  const [editNotice, setEditNotice] = useState<string | null>(null)
  const [databaseCreation, setDatabaseCreation] = useState<{
    operationId: string
    databaseName: string
    createDefaultRoles?: boolean
  } | null>(null)
  const [statusConfirm, setStatusConfirm] = useState<'disable' | 'enable' | null>(null)
  const [statusFailure, setStatusFailure] = useState<string | null>(null)
  const [deleteOpen, setDeleteOpen] = useState(false)
  // 409-guard от managed-аккаунтов: сообщение бэкенда и переход в режим force.
  const [deleteGuard, setDeleteGuard] = useState<string | null>(null)
  const [deleteFailure, setDeleteFailure] = useState<string | null>(null)
  const invalidatedAdminCredentialOperation = useRef<string | null>(null)

  const connectionQuery = useQuery({
    queryKey: qk.connection(connectionId),
    queryFn: ({ signal }) =>
      api<Connection>(`/api/v1/connections/${connectionId}?view=summary`, { signal }),
    refetchInterval: (query) =>
      shouldPollAdminCredentialChange(query.state.data) ? 1_500 : false,
  })
  const accountsQuery = useConnectionAccountsQuery(connectionId, { enabled: tab === 'accounts' && !connectionQuery.isError })
  const hbaQuery = useConnectionHBA(connectionId)

  useEffect(() => {
    const change = connectionQuery.data?.admin_credential_change
    if (isTerminalAdminCredentialChange(change) &&
      change !== null && change !== undefined &&
      invalidatedAdminCredentialOperation.current !== change.operation_id) {
      invalidatedAdminCredentialOperation.current = change.operation_id
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.connectionResources(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.connectionResourceTree(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.drift(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
      ])
    }
  }, [connectionId, connectionQuery.data, queryClient])

  // Deep-link на скрытую HBA-вкладку не должен оставлять пустой экран:
  // после ответа API возвращаемся в основной каталог аккаунтов.
  useEffect(() => {
    if (tab === 'hba' && hbaQuery.isSuccess && !hbaQuery.data.customized) {
      setTab('accounts')
    }
  }, [hbaQuery.data, hbaQuery.isSuccess, tab])

  // Permissions нужны и вкладке «Роли», и панелям bindings (маппинг
  // permission_definition_id -> имя), поэтому запрашиваются на уровне
  // страницы один раз.
  const permissionsQuery = useQuery({
    queryKey: qk.connectionPermissions(connectionId, 'roles'),
    queryFn: ({ signal }) =>
      apiList<Permission>(
        `/api/v1/connections/${connectionId}/permissions?category=roles`,
        'permissions',
        signal,
      ),
  })

  const permissionsById = useMemo(
    () => indexById(permissionsQuery.data ?? []),
    [permissionsQuery.data],
  )

  // Удаление подключения — метаданные grantor, кластер не трогаем. Первый
  // заход без force; 409 от managed-аккаунтов переводит диалог в режим
  // «Всё равно удалить» (?force=true, аккаунты осиротеют в кластере).
  const deleteMutation = useMutation({
    mutationFn: (force: boolean) =>
      api<unknown>(
        `/api/v1/connections/${connectionId}${force ? '?force=true' : ''}`,
        { method: 'DELETE' },
      ),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.connections() })
      void navigate({ to: '/overview' })
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 409) {
        setDeleteGuard(err.message)
        setDeleteFailure(null)
      } else {
        setDeleteFailure(errorMessage(err))
      }
    },
  })

  const statusMutation = useMutation({
    mutationFn: (action: 'disable' | 'enable') =>
      api<Connection>(`/api/v1/connections/${connectionId}/${action}`, {
        method: 'POST',
      }),
    onSuccess: (updated) => {
      setStatusConfirm(null)
      setStatusFailure(null)
      setEditNotice(
        updated.status === 'disabled'
          ? 'Подключение отключено. Снимок и настройки сохранены.'
          : 'Подключение включено. При необходимости запустите Sync.',
      )
      void queryClient.invalidateQueries({ queryKey: qk.connection(connectionId) })
      void queryClient.invalidateQueries({ queryKey: qk.connections() })
    },
    onError: (err: unknown) => {
      setStatusConfirm(null)
      setStatusFailure(errorMessage(err))
    },
  })

  const closeDelete = () => {
    setDeleteOpen(false)
    setDeleteGuard(null)
    setDeleteFailure(null)
    deleteMutation.reset()
  }

  if (connectionQuery.isError) {
    return (
      <div className="mx-auto max-w-6xl">
        <ErrorState
          message={errorMessage(connectionQuery.error)}
          onRetry={() => {
            void connectionQuery.refetch()
          }}
        />
      </div>
    )
  }
  if (connectionQuery.isPending) {
    return <DetailPageSkeleton />
  }

  const connection = connectionQuery.data
  const drift = driftTotal(connection.drift)
  const canRefresh = roleAtLeast(auth.role, 'operator')
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const canChangeStatus =
    isAdmin && (connection.status === 'active' || connection.status === 'disabled')
  const adminCredentialBusy = shouldPollAdminCredentialChange(connection)
  const canCreateDatabase = isAdmin && connection.capabilities.includes('resource.create.database')
  const supportsAccountCreation = connection.capabilities.includes('account.create')
  const supportsAccessGrant = connection.capabilities.includes('access.grant')
  const plainInventoryOnly = kafkaPlainInventoryOnly(connection)
  const refreshAccountOperation = () => {
    void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) })
    void queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) })
    void queryClient.invalidateQueries({ queryKey: qk.connectionAccess(connectionId) })
    void queryClient.invalidateQueries({ queryKey: qk.operations() })
  }
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div>
        <Link
          to="/overview"
          className="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-text"
        >
          <ArrowLeft className="size-4" />
          Обзор
        </Link>
      </div>

      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line pb-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <EngineBadge engine={connection.engine} />
          <CopyableValue
            value={connection.display_name}
            label="Копировать название подключения"
            valueClassName="font-mono text-lg font-semibold leading-tight"
          >
            {connection.display_name}
          </CopyableValue>
          <TagBadge>{connectionEnvironmentLabel(connection.environment)}</TagBadge>
          {connection.execution_mode === 'connector' && (
            <TagBadge title="Операции выполняются через execution connector (изолированный сегмент)">
              Connector
            </TagBadge>
          )}
          <StatusChip tone={connectionStatusTone(connection.status)}>
            {connectionStatusLabel(connection.status)}
          </StatusChip>
          <StatusChip tone={drift > 0 ? 'warn' : 'ok'}>
            {connectionSyncLabel(drift)}
          </StatusChip>
          {/* Версию собирает discovery; до первого снимка строка пуста.
              В подписи только номер, полная строка сборки — в title. */}
          {connection.server_version !== '' && (
            <span className="font-mono text-xs text-muted" title={connection.server_version}>
              {shortServerVersion(connection.server_version)}
            </span>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="flex items-center gap-0.5">
            <Tooltip
              content={`Последний успешный снимок кластера: ${formatDateTime(connection.last_discovery_at)}`}
            >
              {/* Ширина фиксирована по той же причине, что и в списке:
                  подпись времени меняет длину и двигала бы соседние кнопки. */}
              <span className="inline-flex h-8 w-[5.25rem] items-center justify-end gap-1.5 px-1 text-sm tabular-nums text-muted">
                <Clock3 className="size-3.5 shrink-0" aria-hidden="true" />
                {formatCompactRelative(connection.last_discovery_at)}
              </span>
            </Tooltip>
            {canRefresh && (
              <ConnectionSyncButton
                connectionId={connectionId}
                connectionName={connection.display_name}
                disabled={connection.status !== 'active'}
              />
            )}
          </span>
          {canChangeStatus && (
            <IconButton
              label={connection.status === 'disabled' ? 'Включить подключение' : 'Отключить подключение'}
              tone="outline"
              disabled={statusMutation.isPending}
              icon={
                statusMutation.isPending ? (
                  <Spinner className="size-4" />
                ) : connection.status === 'disabled' ? (
                  <Power className="size-4" aria-hidden="true" />
                ) : (
                  <PowerOff className="size-4" aria-hidden="true" />
                )
              }
              onClick={() => {
                setStatusFailure(null)
                setStatusConfirm(connection.status === 'disabled' ? 'enable' : 'disable')
              }}
            />
          )}
          <IconButton
            label="Состояние подключения"
            tone="outline"
            icon={<FileCode2 className="size-4" aria-hidden="true" />}
            onClick={() => {
              void navigate({
                to: '/connections/$connectionId/state',
                params: { connectionId },
              })
            }}
          />
          {isAdmin && (
            <IconButton
              label="Редактировать подключение"
              tone="outline"
              disabled={adminCredentialBusy}
              icon={<Pencil className="size-4" aria-hidden="true" />}
              onClick={() => setEditOpen(true)}
            />
          )}
          {isAdmin && (
            <IconButton
              label="Удалить подключение"
              tone="danger"
              disabled={adminCredentialBusy}
              icon={<Trash2 className="size-4" aria-hidden="true" />}
              onClick={() => setDeleteOpen(true)}
            />
          )}
        </div>
      </div>

      {/* Идентификаторы для поиска в Vault и в логах: UUID подключения — ключ
          путей секретов, admin-путь показываем как есть (это путь, не
          значение). Полный uuid нигде больше не виден, а shortId для поиска
          не годится. */}
      <div className="grid min-w-0 gap-x-6 gap-y-1 text-[11px] text-faint lg:grid-cols-[minmax(0,0.8fr)_minmax(0,1.4fr)]">
        <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-start gap-1">
          <span className="shrink-0 leading-5">ID</span>
          <CopyableValue
            value={connection.id}
            label="Копировать идентификатор подключения"
            compactAction
            className="w-fit"
            identifierWrap
            valueClassName="font-mono leading-5"
          />
        </div>
        {connection.vault_admin_path !== '' && (
          <div className="grid min-w-0 grid-cols-[auto_minmax(0,1fr)] items-start gap-1">
            <span className="shrink-0 leading-5">Vault</span>
            <CopyableValue
              value={connection.vault_admin_path}
              label="Копировать путь admin credential в Vault"
              compactAction
              className="w-fit"
              identifierWrap
              valueClassName="font-mono leading-5"
            />
          </div>
        )}
      </div>

      {editNotice !== null && (
        <InlineNotice text={editNotice} onClose={() => setEditNotice(null)} />
      )}
      {statusFailure !== null && <ErrorBanner>{statusFailure}</ErrorBanner>}

      <AdminCredentialChangePanel
        connection={connection}
        isAdmin={isAdmin}
        onNotice={setEditNotice}
        onRefresh={() => void connectionQuery.refetch()}
      />

      {plainInventoryOnly && (
        <p className="text-sm text-muted">
          Kafka подключён для просмотра топиков. ACL отключены; Grantor не может выдавать доступ или менять учётки PLAIN.
        </p>
      )}
      {connection.engine === 'redis' && connection.auth_mode === 'none' && <RedisNoAuthNotice />}

      {canRefresh && (canCreateDatabase || supportsAccountCreation || supportsAccessGrant) && (
        <div aria-label="Действия подключения" className="flex flex-wrap gap-2">
          {canCreateDatabase && (
            <Button className="grantor-touch-target" variant="outline"
              disabled={connection.status !== 'active' || adminCredentialBusy}
              onClick={() => setCreateDatabaseOpen(true)}>
              <Plus className="size-4" aria-hidden="true" />
              Создать базу
            </Button>
          )}
          {supportsAccountCreation && (
            <Button className="grantor-touch-target" variant="outline"
              disabled={connection.status !== 'active' || adminCredentialBusy}
              onClick={() => setCreateAccountOpen(true)}>
              <Plus className="size-4" aria-hidden="true" />
              Создать учётку
            </Button>
          )}
          {supportsAccessGrant && (
            <Button className="grantor-touch-target"
              disabled={connection.status !== 'active' || adminCredentialBusy}
              onClick={() => setGrantAccessOpen(true)}>
              <KeyRound className="size-4" aria-hidden="true" />
              Выдать доступ
            </Button>
          )}
        </div>
      )}

      <ZoneTabs
        tabs={hbaQuery.data?.customized ? TABS_WITH_HBA : TABS}
        active={tab}
        onSelect={setTab}
      />

      {accountOperation !== null && (
        <OperationProgressNotice
          operationId={accountOperation.id}
          label={accountOperation.label}
          autoCloseSuccess={false}
          closeWhileRunning
          onSettled={refreshAccountOperation}
          onClose={() => setAccountOperation(null)}
          onOpenDetails={(operation) => void navigate({
            to: '/control', search: { tab: 'operations', status: 'all', operation: operation.id },
          })}
        />
      )}

      {databaseCreation !== null && <DatabaseCreationNotice {...databaseCreation}
        onSettled={() => {
          // A partial result can already include a database and one role.
          // This tracker belongs to the connection, independently of its tab.
          void queryClient.invalidateQueries({ queryKey: qk.connectionResources(connectionId) })
          void queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) })
          void queryClient.invalidateQueries({ queryKey: qk.connectionRolePolicies(connectionId) })
          void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) })
          void queryClient.invalidateQueries({ queryKey: qk.connectionAccess(connectionId) })
        }}
        onClose={() => setDatabaseCreation(null)} />}

      {tab === 'resources' && (
        <ResourcesTab
          key={connection.id}
          connection={connection}
          permissionsById={permissionsById}
          initialSelectedId={deepLink.resource ?? null}
        />
      )}
      {tab === 'accounts' && (
        <AccountsTab
          connection={connection}
          accountsQuery={accountsQuery}
          permissions={permissionsQuery.data ?? []}
          permissionsById={permissionsById}
          hbaQuery={hbaQuery}
          initialSelectedId={deepLink.account ?? null}
          externalActions={{
            onCreateAccount: () => setCreateAccountOpen(true),
            onGrantAccess: () => setGrantAccessOpen(true),
          }}
        />
      )}
      {tab === 'roles' && <RolesTab connection={connection} permissionsQuery={permissionsQuery} />}
      {tab === 'hba' && hbaQuery.data?.customized && (
        <ConnectionHBASection data={hbaQuery.data} />
      )}
      <CreateDatabaseDialog
        connection={connection}
        open={createDatabaseOpen}
        onClose={() => setCreateDatabaseOpen(false)}
        onStarted={(operationId, databaseName, createDefaultRoles) =>
          setDatabaseCreation({ operationId, databaseName, createDefaultRoles })}
      />
      <CreateAccountDrawer
        connectionId={connectionId}
        connection={connection}
        open={createAccountOpen}
        onClose={() => setCreateAccountOpen(false)}
        onStarted={(id, identity) => {
          setCreateAccountOpen(false)
          setAccountOperation({ id, label: `Создание учётки ${identity}`, accountId: null, anchor: 'account' })
        }}
      />
      <GrantAccessDrawer
        fixedConnectionId={connectionId}
        open={grantAccessOpen}
        onClose={() => setGrantAccessOpen(false)}
        onStarted={(id, principalName) => {
          setGrantAccessOpen(false)
          setAccountOperation({ id, label: `Выдача доступа: ${principalName}`, accountId: null, anchor: 'access' })
        }}
      />
      <ConfirmActionDialog
        open={statusConfirm !== null}
        title={statusConfirm === 'enable' ? 'Включить подключение?' : 'Отключить подключение?'}
        confirmLabel={statusConfirm === 'enable' ? 'Включить' : 'Отключить'}
        pending={statusMutation.isPending}
        onConfirm={() => {
          if (statusConfirm !== null) statusMutation.mutate(statusConfirm)
        }}
        onClose={() => setStatusConfirm(null)}
        description={
          statusConfirm === 'enable' ? (
            <>
              Подключение <span className="font-mono text-text">{connection.display_name}</span>{' '}
              снова станет доступно для Sync и операций. Сохранённый снимок не изменится.
            </>
          ) : (
            <>
              Подключение <span className="font-mono text-text">{connection.display_name}</span>{' '}
              перестанет принимать Sync и операции. Снимок, настройки, аккаунты и права сохранятся.
            </>
          )
        }
      />

      <ConfirmActionDialog
        open={deleteOpen}
        title="Удалить подключение?"
        danger
        confirmLabel={deleteGuard !== null ? 'Всё равно удалить' : 'Удалить'}
        pending={deleteMutation.isPending}
        onConfirm={() => deleteMutation.mutate(deleteGuard !== null)}
        onClose={closeDelete}
        description={
          <span className="space-y-2 block">
            <span className="block">
              Подключение{' '}
              <span className="font-mono text-text">{connection.display_name}</span>{' '}
              будет удалено только из Grantor: сохранённые сведения, аккаунты, роли
              и выданные права. Реальный кластер и его пользователи не
              затрагиваются. Ничего не отзывается и не удаляется на стороне БД.
            </span>
            {deleteGuard !== null && (
              <span className="block rounded-md border border-danger/40 bg-danger-soft p-2 text-danger">
                {deleteGuard} Managed-аккаунты останутся в кластере (осиротеют).
                Подтвердите, чтобы удалить подключение и принять это.
              </span>
            )}
            {deleteFailure !== null && (
              <span className="block text-danger">Не удалось удалить: {deleteFailure}</span>
            )}
          </span>
        }
      />
      <EditConnectionDialog
        connection={connection}
        open={editOpen}
        isAdmin={isAdmin}
        adminCredentialOpen={adminCredentialOpen}
        onManageAdminCredential={() => setAdminCredentialOpen(true)}
        onClose={() => setEditOpen(false)}
        onSaved={(updated) => {
          setEditNotice(
            updated.operation_id !== undefined
              ? 'Параметры сохранены. Новый discovery уже поставлен в очередь.'
              : 'Метаданные подключения сохранены.',
          )
        }}
      />
      <ConnectionAdminCredentialDialog
        connection={connection}
        open={adminCredentialOpen}
        onClose={() => setAdminCredentialOpen(false)}
        onStarted={(operationId, mode, reconciled) => {
          setEditNotice(
            `${mode === 'switch' ? 'Смена admin credential' : 'Ротация admin credential'}: операция ${shortId(operationId)} ${reconciled ? 'уже принята сервером' : 'поставлена в очередь'}.`,
          )
        }}
      />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Вкладка «Ресурсы»: дерево + правая панель деталей (общие блоки из
// resource-tree.tsx).

interface ResourcesTabProps {
  connection: Connection
  permissionsById: Map<string, Permission>
  /** Ресурс, предвыбранный deep-link'ом из «Контроля». */
  initialSelectedId?: string | null
}

function ResourcesTab({ connection, permissionsById, initialSelectedId = null }: ResourcesTabProps) {
  const connectionId = connection.id
  const auth = useAuth()
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId)
  // Создание баз — admin-only (architecture §11.2) и только там, где движок
  // это умеет.
	const postgresCreationBlocked = roleAtLeast(auth.role, 'admin') && connection.engine === 'postgres' &&
		!postgresProvisioningReady(connection)

  // Повторный deep-link на смонтированной вкладке тоже выбирает ресурс.
  useEffect(() => {
    if (initialSelectedId !== null) setSelectedId(initialSelectedId)
  }, [initialSelectedId])

  const resourcesQuery = useQuery({
    queryKey: qk.connectionResourceTree(connectionId),
    queryFn: ({ signal }) =>
      apiList<ResourceTreeItem>(
        `/api/v1/connections/${connectionId}/resources?view=tree`,
        'resources',
        signal,
      ),
  })

  const tree = useMemo(
    () => buildResourceTree(resourcesQuery.data ?? []),
    [resourcesQuery.data],
  )
  const selectedExists = useMemo(
    () => selectedId !== null && (resourcesQuery.data ?? []).some((r) => r.id === selectedId),
    [resourcesQuery.data, selectedId],
  )
  const selectedQuery = useQuery({
    queryKey: qk.resource(selectedId ?? ''),
    queryFn: ({ signal }) => api<Resource>(`/api/v1/resources/${selectedId}`, { signal }),
    enabled: selectedId !== null && selectedExists,
  })

  return (
    <>
		{postgresCreationBlocked && <div className="mb-3"><PostgresProvisioningNotice connection={connection} /></div>}
      <QueryStates
        query={resourcesQuery}
        empty={
          <EmptyState
            icon={FolderTree}
            title="Ресурсы не обнаружены"
            description="Нажмите «Синхронизировать», чтобы discovery собрал инвентарь подключения."
          />
        }
        isEmpty={() => tree.length === 0}
      >
        {() => (
          <div className="space-y-2">
            <InspectorSplitLayout
              content={(
                <ResourceTree
                  className="min-w-0 flex-1"
                  nodes={tree}
                  selectedId={selectedId}
                  onSelect={setSelectedId}
                />
              )}
              inspector={
                selectedId !== null && selectedQuery.data !== undefined ? (
                  <ResourceDetailPanel
                    key="resource-panel"
                    resource={selectedQuery.data}
                    permissionsById={permissionsById}
                    onClose={() => setSelectedId(null)}
                  />
                ) : selectedId !== null && selectedQuery.isPending ? (
                  <div className="flex min-h-40 items-center justify-center rounded-lg border border-line bg-panel">
                    <Spinner />
                  </div>
                ) : selectedId !== null && selectedQuery.isError ? (
                  <ErrorState
                    title="Не удалось загрузить ресурс"
                    message={errorMessage(selectedQuery.error)}
                    onRetry={() => void selectedQuery.refetch()}
                  />
                ) : null
              }
            />
          </div>
        )}
      </QueryStates>
    </>
  )
}

// ---------------------------------------------------------------------------
// Вкладка «Роли» (permissions).

interface RolesTabProps {
  connection: Connection
  permissionsQuery: {
    data: Permission[] | undefined
    isPending: boolean
    isError: boolean
    error: unknown
    refetch: () => Promise<unknown>
  }
}

function RolesTab({ connection, permissionsQuery }: RolesTabProps) {
  const auth = useAuth()
  const permissions = (permissionsQuery.data ?? []).filter(p => !isPostgresObjectPrivilege(p))
  const [createOpen, setCreateOpen] = useState(false)
  const [templatesIntent, setTemplatesIntent] = useState<AccessTemplateEditorIntent | null>(null)
  const [basicRolesOpen, setBasicRolesOpen] = useState(false)
  const [templateSeed, setTemplateSeed] = useState<RoleTemplateCatalog | undefined>()
  const [definition, setDefinition] = useState<{
    connectionId: string
    templateKey?: string
    permission?: Permission
  } | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const catalogKey = connection.engine === 'postgres'
    ? 'postgres_role_policy_templates'
    : connection.engine === 'mongodb' ? 'mongodb_role_policy_templates' : 'rabbitmq_permission_templates'
  const config = connection.discovery_config !== null &&
    typeof connection.discovery_config === 'object' && !Array.isArray(connection.discovery_config)
    ? connection.discovery_config as Record<string, unknown> : {}
  const templates = config[catalogKey]
  const templateCount = Array.isArray(templates) ? templates.length : 0
  const rabbitTemplates = useMemo(
    () => connection.engine === 'rabbitmq'
      ? readRabbitMQPermissionTemplates(connection.discovery_config) : [],
    [connection.engine, connection.discovery_config],
  )
  const templatesEditable = canEditAccessTemplates(connection, isAdmin)
  const openTemplates = (intent: AccessTemplateEditorIntent) => {
    setTemplateSeed(undefined)
    setTemplatesIntent(intent)
  }
  const openTemplate = (key: string) => setDefinition({ connectionId: connection.id, templateKey: key })
  const templateActions = isAdmin && supportsAccessTemplates(connection.engine) ? (
    <div className="flex flex-wrap items-center gap-2">
      {connection.engine === 'postgres' ? (
        <Button size="sm" disabled={!templatesEditable || !postgresProvisioningReady(connection)} onClick={() => setBasicRolesOpen(true)}>
          <Plus className="size-3.5" aria-hidden="true" />
          Создать роли для базы
        </Button>
      ) : (
        <Button size="sm" disabled={!templatesEditable} onClick={() => openTemplates('create')}>
          <Plus className="size-3.5" aria-hidden="true" />
          Создать шаблон
        </Button>
      )}
      {(templateCount > 0 || connection.engine === 'postgres') && (
        <Button size="sm" variant="outline" disabled={!templatesEditable} onClick={() => openTemplates('catalog')}>
          {connection.engine === 'postgres' ? 'Расширенные шаблоны' : 'Редактировать шаблоны'}
        </Button>
      )}
    </div>
  ) : undefined
  // Создавать роли может тот же, кто заводит аккаунты; движок должен уметь
  // это делать, а подключение — быть активным.
  const canCreateRole =
    (connection.engine === 'postgres' || connection.engine === 'mongodb'
      ? isAdmin
      : roleAtLeast(auth.role, 'operator')) &&
    connection.status === 'active' &&
    connection.capabilities.includes('role.create')

  return (
    <>
      <div className="space-y-5">
        {connection.engine === 'postgres' && (
          <PostgresRolePoliciesSection
            connectionId={connection.id}
            connection={connection}
            isAdmin={isAdmin}
            templateActions={templateActions}
            onOpenTemplate={openTemplate}
          />
        )}
        {connection.engine === 'mongodb' && (
          <MongoDBRolePoliciesSection
            connectionId={connection.id}
            isAdmin={isAdmin}
            connectionActive={connection.status === 'active'}
            templateActions={templateActions}
            onOpenTemplate={openTemplate}
          />
        )}
        {connection.engine === 'rabbitmq' && (
          <section className="space-y-3" aria-labelledby="rabbitmq-access-templates-title">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <h2 id="rabbitmq-access-templates-title" className="text-sm font-semibold text-text">
                  Шаблоны доступа RabbitMQ
                </h2>
                <p className="mt-1 max-w-3xl text-xs text-muted">
                  Шаблон задаёт configure/write/read для vhost. Чтобы выдать права,
                  назначьте его аккаунту через управление ролями.
                </p>
              </div>
              {templateActions}
            </div>
            {rabbitTemplates.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                title="Шаблоны доступа не настроены"
                description={isAdmin
                  ? 'Создайте шаблон здесь. Сохранение шаблона не меняет права аккаунтов.'
                  : 'Администратор ещё не опубликовал шаблоны для этого подключения.'}
                className="py-7"
              />
            ) : (
              <ul className="divide-y divide-line" aria-label="Шаблоны RabbitMQ">
                {rabbitTemplates.map((template) => (
                  <li key={template.key} className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1 py-2 text-sm">
                    <button
                      type="button"
                      className="grantor-touch-target ui-control-feedback break-words text-left font-medium text-text underline decoration-line underline-offset-4 hover:decoration-current focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                      aria-label={`Открыть шаблон ${template.name}`}
                      onClick={() => openTemplate(template.key)}
                    >
                      {template.name}
                    </button>
                    <span className="break-all font-mono text-xs text-muted">{template.vhost}</span>
                    {template.description !== '' && <span className="text-xs text-muted">{template.description}</span>}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        <section className="space-y-2" aria-labelledby="connection-roles-title">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 id="connection-roles-title" className="text-sm font-semibold text-text">
                Роли подключения
              </h2>
              <p className="mt-0.5 text-xs text-muted">
                Роли из последнего discovery. Создание пустой роли не настраивает её права;
                роль управляемого шаблона доступна для назначения только в synced.
              </p>
            </div>
            {canCreateRole && (
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus className="size-3.5" aria-hidden="true" />
                Создать пустую роль
              </Button>
            )}
          </div>

          {notice !== null && <InlineNotice text={notice} onClose={() => setNotice(null)} />}

          <QueryStates
            query={permissionsQuery}
            empty={
              <EmptyState
                icon={KeyRound}
                title="Роли не обнаружены"
                description="Discovery ещё не собрал permission definitions этого подключения."
                action={canCreateRole ? (
                  <Button size="sm" onClick={() => setCreateOpen(true)}>
                    <Plus className="size-3.5" aria-hidden="true" />
                    Создать пустую роль
                  </Button>
                ) : undefined}
              />
            }
          >
            {() => (
              <TableContainer>
                <Table>
                  <TableHeader>
                    <tr>
                      <TableHead>Имя</TableHead>
                      <TableHead>External ID</TableHead>
                    </tr>
                  </TableHeader>
                  <TableBody>
                    {permissions.map((permission) => {
                      // Роль, исчезнувшая из целевой системы: строка остаётся —
                      // на неё могут ссылаться выданные bindings, — но приглушена
                      // и помечена, а из диалогов выдачи она уже убрана.
                      const missing = permission.status === 'missing'
                      const attributes = permission.attributes !== null &&
                        typeof permission.attributes === 'object' && !Array.isArray(permission.attributes)
                        ? permission.attributes as Record<string, unknown>
                        : {}
                      const policyAssignmentBlocked =
                        !permission.assignable && typeof attributes.role_policy_key === 'string'
                      return (
                        <TableRow key={permission.id} className={missing ? 'opacity-60' : undefined}>
                          {/* Нормализованная подпись; сырое имя — в title, external
                              id — в соседней колонке (это reference-список). */}
                          <TableCell className="font-mono text-[13px]" title={permission.name}>
                            <TableCopyableValue
                              value={permission.name}
                              label={`Копировать имя роли ${permission.name}`}
                              valueClassName="inline-flex items-center gap-1.5"
                            >
                              {permission.dangerous && <ElevatedAccessDot />}
                              <button
                                type="button"
                                className="grantor-touch-target ui-control-feedback text-left underline decoration-line underline-offset-4 hover:decoration-current focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                                aria-label={`Открыть роль ${permission.name}`}
                                onClick={() => setDefinition({ connectionId: connection.id, permission })}
                              >
                                {permissionNameLabel(permission, permission.name)}
                              </button>
                              {missing && (
                                <StatusChip tone={inventoryStatusTone('missing')}>
                                  {inventoryStatusLabel('missing')}
                                </StatusChip>
                              )}
                              {!missing && attributes.login_role === true && <StatusChip tone="unmg">LOGIN · не назначается</StatusChip>}
                              {policyAssignmentBlocked && !missing && (
                                <StatusChip tone="warn">Назначение заблокировано</StatusChip>
                              )}
                            </TableCopyableValue>
                          </TableCell>
                          <TableCell className="font-mono text-[12px] text-muted">
                            {permission.external_id}
                          </TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </QueryStates>
        </section>
      </div>
      <ConnectionAccessTemplatesDialog
        connection={connection}
        isAdmin={isAdmin}
        open={templatesIntent !== null}
        intent={templatesIntent ?? 'catalog'}
        initialTemplates={templateSeed}
        initialMode={templateSeed === undefined ? 'form' : 'json'}
        onClose={() => setTemplatesIntent(null)}
        onSaved={() => setNotice('Шаблоны сохранены. Права в целевой системе не изменены.')}
      />
      <PostgresBasicRolesDialog
        connection={connection} isAdmin={isAdmin} open={basicRolesOpen}
        onClose={() => setBasicRolesOpen(false)}
        onStarted={(roles, _operationIds, alreadyReady) => setNotice(alreadyReady
          ? `Роли ${roles.join(' и ')} уже настроены. Их можно назначить аккаунтам.`
          : `Создание ${roles.join(' и ')} запущено. После завершения операции роли можно назначить аккаунтам.`)}
      />
      {definition?.connectionId === connection.id && (
        <ConnectionRoleDefinitionDialog
          connection={connection}
          templateKey={definition.templateKey}
          permission={definition.permission}
          onClose={() => setDefinition(null)}
          onCreate={templatesEditable ? (catalog) => {
            setDefinition(null)
            setTemplateSeed(catalog)
            setTemplatesIntent('create')
          } : undefined}
        />
      )}
      <CreateRoleDialog
        connectionId={connection.id}
        connection={connection}
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onStarted={(_operationId, roleName) =>
          setNotice(
            `Пустая роль ${roleName} создаётся. В списке ролей она появится после синхронизации подключения.`,
          )
        }
      />
    </>
  )
}

// ---------------------------------------------------------------------------
// Вкладка «Выданные права»: доступы этого подключения с переключаемыми
// секциями (GET /api/v1/access/export?connection=id&sections=). Managed-only
// (по умолчанию) — прежний манифест: его можно хранить в git и применять
// повторно. Любая иная комбинация секций — фактический аудит-снимок
// (kind=access_snapshot), НЕ манифест. Выгрузка JSON/YAML идёт тем же
// эндпоинтом с текущим выбором секций; для managed-only параметр sections
// опускается, чтобы работал чистый manifest-путь. Экспорт доступен роли
// viewer — зеркалирует RBAC бэкенда; секретов выгрузка не несёт (только
// имена и идентификаторы).

// ExportFormat — формат выгрузки выданных прав (Content-Type определяет бэкенд).
type ExportFormat = 'json' | 'yaml'

// Секции экспорта в фиксированном порядке: он же уходит в query-параметр
// sections и определяет порядок таблиц.
const ACCESS_SECTIONS: Array<{ key: AccessExportSection; label: string }> = [
  { key: 'managed', label: UI_COPY.managed },
  { key: 'unmanaged', label: UI_COPY.unmanaged },
  { key: 'roles', label: UI_COPY.roles },
  { key: 'accounts', label: UI_COPY.accounts },
]

// safeFileName приводит display_name подключения к безопасному имени файла:
// небуквенно-цифровые группы — в один дефис, обрезка ведущих/хвостовых дефисов.
function safeFileName(name: string): string {
  const cleaned = name.replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '')
  return cleaned === '' ? 'connection' : cleaned
}

interface GrantedAccessTabProps {
  connectionId: string
  connectionName: string
}

export function GrantedAccessTab({ connectionId, connectionName }: GrantedAccessTabProps) {
  const [exporting, setExporting] = useState<ExportFormat | null>(null)
  const [exportError, setExportError] = useState<string | null>(null)
  const [selected, setSelected] = useState<ReadonlySet<AccessExportSection>>(
    () => new Set<AccessExportSection>(['managed']),
  )

  const sectionsParam = ACCESS_SECTIONS.filter((section) => selected.has(section.key))
    .map((section) => section.key)
    .join(',')
  const hasSelection = selected.size > 0
  // Managed-only идёт прежним manifest-путём (без параметра sections):
  // ответ байт-в-байт совместим с прежним export и пригоден для apply.
  const managedOnly = hasSelection && sectionsParam === 'managed'

  const manifestQuery = useQuery({
    queryKey: qk.connectionAccess(connectionId),
    queryFn: ({ signal }) =>
      api<AccessManifest>(`/api/v1/access/export?connection=${connectionId}`, { signal }),
    enabled: managedOnly,
  })
  const snapshotQuery = useQuery({
    queryKey: qk.connectionAccessSnapshot(connectionId, sectionsParam),
    queryFn: ({ signal }) =>
      api<AccessSnapshot>(
        `/api/v1/access/export?connection=${connectionId}&sections=${sectionsParam}`,
        { signal },
      ),
    enabled: hasSelection && !managedOnly,
  })
  const showSnapshotAccountOwnership = (snapshotQuery.data?.accounts ?? [])
    .some((account) => !isSharedRoleKind(account.kind))

  const downloadExport = async (format: ExportFormat) => {
    if (!hasSelection) return
    setExporting(format)
    setExportError(null)
    try {
      const sectionsQuery = managedOnly ? '' : `&sections=${sectionsParam}`
      const suffix = managedOnly ? '' : '-snapshot'
      await downloadBlob(
        `/api/v1/access/export?connection=${connectionId}${sectionsQuery}&format=${format}`,
        `grantor-access-${safeFileName(connectionName)}${suffix}.${format}`,
      )
    } catch (err: unknown) {
      setExportError(errorMessage(err))
    } finally {
      setExporting(null)
    }
  }

  const entries = manifestQuery.data?.entries ?? []

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start gap-3">
        <p className="min-w-0 flex-1 text-sm text-muted">
          {!hasSelection ? (
            <>Выберите секции, которые нужно включить в документ.</>
          ) : managedOnly ? (
            <>
              Применяемый манифест. Включает только права, связанные с пользователями.
            </>
          ) : (
            <>
              Read-only снимок выбранных секций. Его нельзя применить.
            </>
          )}
        </p>
        <div className="flex shrink-0 gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={!hasSelection || exporting !== null}
            onClick={() => void downloadExport('json')}
          >
            {exporting === 'json' ? (
              <Spinner className="size-3.5" />
            ) : (
              <Download className="size-3.5" />
            )}
            Скачать JSON
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasSelection || exporting !== null}
            onClick={() => void downloadExport('yaml')}
          >
            {exporting === 'yaml' ? (
              <Spinner className="size-3.5" />
            ) : (
              <Download className="size-3.5" />
            )}
            Скачать YAML
          </Button>
        </div>
      </div>

      <CheckboxChipGroup
        label="Секции выданных прав"
        options={ACCESS_SECTIONS.map((section) => ({
          value: section.key,
          label: section.label,
        }))}
        selected={selected}
        onChange={setSelected}
      />

      {exportError !== null && (
        <ErrorBanner>Не удалось выгрузить права: {exportError}</ErrorBanner>
      )}

      {!hasSelection ? (
        <EmptyState
          icon={ShieldCheck}
          title="Секции не выбраны"
          description="Выберите одну или несколько секций, чтобы сформировать документ состояния подключения."
        />
      ) : managedOnly ? (
        <QueryStates
          query={manifestQuery}
          empty={
            <EmptyState
              icon={ShieldCheck}
              title="Grantor пока не управляет доступами"
              description="В манифесте пока нет прав, связанных с пользователями."
            />
          }
          isEmpty={() => entries.length === 0}
        >
          {() => <ManagedEntriesTable entries={entries} />}
        </QueryStates>
      ) : (
        <QueryStates query={snapshotQuery}>
          {(snapshot) => (
            <div className="space-y-6">
              {snapshot.managed !== undefined && (
                <AccessSection zone="managed" title={UI_COPY.managed}>
                  {snapshot.managed.length === 0 ? (
                    <SectionEmpty text="Управляемых прав нет: Grantor пока не выдавал права в этом подключении." />
                  ) : (
                    <ManagedEntriesTable entries={snapshot.managed} showAccount />
                  )}
                </AccessSection>
              )}
              {snapshot.unmanaged !== undefined && (
                <AccessSection zone="sync" title={UI_COPY.unmanaged}>
                  {snapshot.unmanaged.length === 0 ? (
                    <SectionEmpty text="Неуправляемые права не обнаружены." />
                  ) : (
                    <TableContainer>
                      <Table>
                        <TableHeader>
                          <tr>
                            <TableHead>Аккаунт</TableHead>
                            <TableHead>Роль</TableHead>
                            <TableHead>Scope</TableHead>
                            <TableHead>Наблюдаемое состояние</TableHead>
                          </tr>
                        </TableHeader>
                        <TableBody>
                          {snapshot.unmanaged.map((binding, index) => (
                            <TableRow key={`${binding.account}-${binding.role}-${binding.scope ?? ''}-${index}`}>
                              <TableCell className="font-mono text-[13px]">
                                <TableCopyableValue
                                  value={binding.account}
                                  label={`Копировать имя аккаунта ${binding.account}`}
                                />
                              </TableCell>
                              {/* Scope здесь не подмешивается в подпись — у
                                  него своя колонка; сырое имя роли — в title. */}
                              <TableCell className="font-mono text-[13px]" title={binding.role}>
                                {binding.role}
                              </TableCell>
                              <TableCell className="font-mono text-[12px] text-muted">
                                {binding.scope !== undefined && binding.scope !== '' ? (
                                  binding.scope
                                ) : (
                                  <span className="text-faint">всё подключение</span>
                                )}
                              </TableCell>
                              <TableCell>
                                <StatusChip
                                  tone={binding.observed_state === 'present' ? 'unmg' : 'warn'}
                                >
                                  {bindingStateLabel(binding.observed_state)}
                                </StatusChip>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </AccessSection>
              )}
              {snapshot.roles !== undefined && (
                <AccessSection zone="sync" title={UI_COPY.roles}>
                  {snapshot.roles.length === 0 ? (
                    <SectionEmpty text="Ролей нет: discovery ещё не собрал permission definitions подключения." />
                  ) : (
                    <TableContainer>
                      <Table>
                        <TableHeader>
                          <tr>
                            <TableHead>Имя</TableHead>
                            <TableHead>External ID</TableHead>
                            <TableHead>Scope</TableHead>
                          </tr>
                        </TableHeader>
                        <TableBody>
                          {snapshot.roles.map((role) => (
                            <TableRow key={role.external_id}>
                              {/* Reference-список: подпись нормализована,
                                  сырое имя — в title, external id — рядом. */}
                              <TableCell className="font-mono text-[13px]" title={role.name}>
                                <TableCopyableValue
                                  value={role.name}
                                  label={`Копировать имя роли ${role.name}`}
                                  valueClassName="inline-flex items-center gap-1.5"
                                >
                                  {role.dangerous && <ElevatedAccessDot />}
                                  <span>
                                    {role.name}
                                  </span>
                                </TableCopyableValue>
                              </TableCell>
                              <TableCell className="font-mono text-[12px] text-muted">
                                {role.external_id}
                              </TableCell>
                              <TableCell className="font-mono text-[12px] text-muted">
                                {role.scope !== undefined && role.scope !== '' ? (
                                  role.scope
                                ) : (
                                  <span className="text-faint">—</span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </AccessSection>
              )}
              {snapshot.accounts !== undefined && (
                <AccessSection zone="sync" title={UI_COPY.accounts}>
                  {snapshot.accounts.length === 0 ? (
                    <SectionEmpty text="Аккаунтов нет: discovery не обнаружил учётных записей в подключении." />
                  ) : (
                    <TableContainer>
                      <Table>
                        <TableHeader>
                          <tr>
                            <TableHead>Identity</TableHead>
                            <TableHead>Kind</TableHead>
                            {showSnapshotAccountOwnership && <TableHead>Ownership</TableHead>}
                            <TableHead>Статус</TableHead>
                            <TableHead>Принципал</TableHead>
                          </tr>
                        </TableHeader>
                        <TableBody>
                          {snapshot.accounts.map((account, index) => (
                            <TableRow key={`${account.engine_identity}-${index}`}>
                              <TableCell className="font-mono text-[13px]">
                                <TableCopyableValue
                                  value={account.engine_identity}
                                  label={`Копировать имя аккаунта ${account.engine_identity}`}
                                />
                              </TableCell>
                              <TableCell className="text-muted">{accountKindLabel(account.kind)}</TableCell>
                              {showSnapshotAccountOwnership && (
                                <TableCell>
                                  {!isSharedRoleKind(account.kind) && (
                                    <StatusChip tone={ownershipTone(account.ownership)}>
                                      {ownershipLabel(account.ownership)}
                                    </StatusChip>
                                  )}
                                </TableCell>
                              )}
                              <TableCell>
                                <StatusChip tone={inventoryStatusTone(account.status)}>
                                  {inventoryStatusLabel(account.status)}
                                </StatusChip>
                              </TableCell>
                              <TableCell className="font-mono text-[12px] text-muted">
                                {account.principal !== undefined && account.principal !== '' ? (
                                  account.principal
                                ) : (
                                  <span className="text-faint">—</span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                  )}
                </AccessSection>
              )}
            </div>
          )}
        </QueryStates>
      )}
    </div>
  )
}

// ManagedEntriesTable — таблица managed-прав. Managed-only режим рендерит
// записи манифеста (principal → роль, без аккаунта); снапшот — свою секцию
// managed, где есть и аккаунт, и права без привязанного принципала (в
// манифест они не входят — подсказка в ячейке).
//
// Имя роли показывается сырым: снимок манифеста несёт только его, без
// определения права, а значит и без нормализованного представления. Scope
// дописывается к имени — отдельной колонки под него в этой таблице нет.
function ManagedEntriesTable({
  entries,
  showAccount = false,
}: {
  entries: Array<
    Pick<ManifestEntry, 'role' | 'state'> & {
      principal?: string
      account?: string
      scope?: string
    }
  >
  showAccount?: boolean
}) {
  return (
    <TableContainer>
      <Table>
        <TableHeader>
          <tr>
            {showAccount && <TableHead>Аккаунт</TableHead>}
            <TableHead>Принципал</TableHead>
            <TableHead>Роль</TableHead>
            <TableHead>Состояние</TableHead>
          </tr>
        </TableHeader>
        <TableBody>
          {entries.map((entry, index) => (
            <TableRow key={`${entry.account ?? ''}-${entry.principal ?? ''}-${entry.role}-${index}`}>
              {showAccount && (
                <TableCell className="font-mono text-[13px]">
                  {entry.account !== undefined && entry.account !== '' ? (
                    <TableCopyableValue
                      value={entry.account}
                      label={`Копировать имя аккаунта ${entry.account}`}
                    />
                  ) : null}
                </TableCell>
              )}
              <TableCell className="font-mono text-[13px]">
                {entry.principal !== undefined && entry.principal !== '' ? (
                  <TableCopyableValue
                    value={entry.principal}
                    label={`Копировать имя принципала ${entry.principal}`}
                  />
                ) : (
                  <span
                    className="text-faint"
                    title="Аккаунт не привязан к пользователю: право управляется Grantor, но в переприменяемый манифест не входит. Привяжите аккаунт («Связать с пользователем»), чтобы оно попало в выгрузку."
                  >
                    Не привязан
                  </span>
                )}
              </TableCell>
              <TableCell className="font-mono text-[13px]" title={entry.role}>
                {rawExpression(entry.role, entry.scope)}
              </TableCell>
              <TableCell>
                <StatusChip tone="ok">{bindingStateLabel(entry.state)}</StatusChip>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

// AccessSection — секция снапшота: заголовок зоны (lib/zones) + содержимое.
// managed-секция отмечена спокойным цветом, остальные нейтральны.
function AccessSection({
  zone,
  title,
  children,
}: {
  zone: Zone
  title: string
  children: ReactNode
}) {
  return (
    <section className="space-y-2">
      <ZoneSectionHeader zone={zone} label={title} />
      {children}
    </section>
  )
}

// SectionEmpty — компактное пустое состояние одной секции снапшота (общий
// EmptyState был бы слишком крупным для секции в списке).
function SectionEmpty({ text }: { text: string }) {
  return (
    <p className="rounded-md border border-line bg-panel2 px-3 py-2 text-sm text-muted">
      {text}
    </p>
  )
}
