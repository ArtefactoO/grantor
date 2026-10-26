// Вкладка «Аккаунты» экрана подключения: таблица учётных записей,
// создание managed-аккаунта (operator+) и действия над выбранным
// аккаунтом — выдача/отзыв прав, одноразовая выдача credential, ротация,
// включение/отключение (operator+), удаление (admin) и привязка к
// пользователю (operator+; метаданные control plane, ответ 200 сразу).
// Остальные мутации отвечают 202: работу выполняет worker, прогресс — на
// экране «Операции».
import { Fragment, useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { KeyRound, Plus, Users } from '@project/ui/icons'
import { apiList } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type { Account, Connection, Operation, Permission, Principal, Resource } from '../lib/types'
import { ownershipTone } from '../lib/status'
import { formatDateTime } from '../lib/time'
import { indexById } from '../lib/indexById'
import { buildAccessEntries } from '../lib/access-entries'
import { accountDirectObjectCount, directObjectSummary, objectRecord, withoutObjectPrivileges } from '../lib/postgres-object-acl'
import { activeAccessBindings } from '../lib/active-access'
import { isConnectionAdminAccount, isSharedRoleKind } from '../lib/account-actions'
import {
  groupByOwnership,
  ZoneSectionRow,
} from '../lib/zones'
import type { OwnershipFilterValue } from '../lib/zones'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  Button,
  TableCopyableValue,
  Table,
  TableContainer,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  InlineNotice,
  EmptyState,
  SearchInput,
  cn,
} from '@project/ui'
import { KindBadge, StatusChip } from '../components/ui/badge'
import { AccessChipList } from '../components/ui/access-chips'
import { OperationProgressNotice } from '../components/operation-progress-notice'
import type { OperationAnchor, TrackedOperation } from '../components/operation-progress-notice'
import { QueryStates } from '../components/ui/query-states'
import { SegmentedFilter } from '../components/ui/selection-chips'
import { ownershipLabel } from '../lib/ui-copy'
import { accountProvisioningSummaryPresentation } from '../lib/account-provisioning-summary'
import { directoryFilterOptions, ownershipFilterOptions } from '../lib/filter-presentation'
import { POLL_LIST_MS } from '../lib/intervals'
import type { DirectoryFilterValue } from '../lib/filter-presentation'
import { AccountDetailPanel } from './connection-account-panel'
import type { ConnectionHBAQuery } from './connection-hba-section'
import { GrantAccessDrawer } from './principal-access-drawer'
import { CreateAccountDrawer } from './connection-account-dialogs'
import { InspectorSplitLayout } from './connection-panels'
import { directlyOwnedPostgresDatabases } from '../lib/postgres-database-ownership'
import { AccountDatabaseOwnership } from '../components/account-database-ownership'
import { kafkaPlainInventoryOnly } from '../lib/kafka-inventory'

/**
 * Аккаунты подключения с bindings — общий запрос вкладки «Аккаунты» и
 * сводных карточек шапки (connection-detail): один queryKey, один fetcher,
 * react-query переиспользует кэш без лишнего трафика.
 */
export function useConnectionAccountsQuery(connectionId: string, options: { enabled?: boolean } = {}) {
  return useQuery({
    queryKey: qk.connectionAccounts(connectionId, 'summary'),
    queryFn: ({ signal }) =>
      apiList<Account>(
        `/api/v1/connections/${connectionId}/accounts?view=summary&include=bindings,provisioning`,
        'accounts',
        signal,
      ),
    enabled: options.enabled ?? true,
    // Инвентарь меняет worker и discovery вне текущего React-дерева.
    // Фоновый поллинг не оставляет таблицу устаревшей, даже если операция
    // была запущена из другого экрана или другим оператором.
    refetchInterval: POLL_LIST_MS,
    refetchIntervalInBackground: false,
  })
}

export type AccountDirectoryView = DirectoryFilterValue

export interface AccountDirectoryFilterProps {
  value: AccountDirectoryView
  currentCount: number
  deletedCount: number
  onChange: (value: AccountDirectoryView) => void
}

export function AccountDirectoryFilter({
  value,
  currentCount,
  deletedCount,
  onChange,
}: AccountDirectoryFilterProps) {
  return (
    <SegmentedFilter
      label="Состояние аккаунтов"
      value={value}
      onChange={onChange}
      options={directoryFilterOptions(currentCount, deletedCount)}
    />
  )
}

export function accountsForDirectoryView(
  accounts: readonly Account[],
  view: AccountDirectoryView,
): Account[] {
  return accounts.filter((account) =>
    view === 'deleted' ? account.status === 'deleted' : account.status !== 'deleted',
  )
}

export type AccountDisplayCategory = 'login' | 'service' | 'group'

/**
 * Visual category is resolved from both the engine account kind and the linked
 * global principal. Some engines expose service accounts as ordinary logins,
 * so account.kind alone is not sufficient after linking.
 */
export function accountDisplayCategory(
  account: Pick<Account, 'kind' | 'principal_id'>,
  principalTypeById: ReadonlyMap<string, string>,
): AccountDisplayCategory {
  const principalType = account.principal_id === null
    ? undefined
    : principalTypeById.get(account.principal_id)

  if (account.kind === 'group' || account.kind === 'role' || principalType === 'group') {
    return 'group'
  }
  if (account.kind === 'service' || principalType === 'service') {
    return 'service'
  }
  return 'login'
}

const ACCOUNT_CATEGORY_ORDER: Record<AccountDisplayCategory, number> = {
  login: 0,
  service: 1,
  group: 2,
}

export function sortAccountsForDisplay<
  T extends Pick<Account, 'kind' | 'principal_id' | 'engine_identity'>,
>(
  accounts: readonly T[],
  principalTypeById: ReadonlyMap<string, string>,
): T[] {
  return [...accounts].sort((a, b) => {
    const categoryDifference =
      ACCOUNT_CATEGORY_ORDER[accountDisplayCategory(a, principalTypeById)] -
      ACCOUNT_CATEGORY_ORDER[accountDisplayCategory(b, principalTypeById)]
    return categoryDifference || a.engine_identity.localeCompare(b.engine_identity)
  })
}

export function isAccountCategoryBoundary(
  previous: Pick<Account, 'kind' | 'principal_id'>,
  current: Pick<Account, 'kind' | 'principal_id'>,
  principalTypeById: ReadonlyMap<string, string>,
): boolean {
  return accountDisplayCategory(previous, principalTypeById) !==
    accountDisplayCategory(current, principalTypeById)
}

export function accountMatchesDirectorySearch(
  account: Pick<Account, 'engine_identity' | 'kind' | 'principal_id' | 'bindings'>,
  query: string,
  principalTypeById: ReadonlyMap<string, string>,
  permissionsById: ReadonlyMap<string, Permission>,
): boolean {
  const normalizedQuery = query.trim().toLocaleLowerCase('ru-RU')
  if (normalizedQuery === '') return true

  const category = accountDisplayCategory(account, principalTypeById)
  const categoryAliases: Record<AccountDisplayCategory, string[]> = {
    login: ['login', 'логин'],
    service: ['service', 'сервис'],
    group: ['group', 'группа'],
  }
  const roleNames = activeAccessBindings(account.bindings ?? []).flatMap((binding) => {
    const permission = permissionsById.get(binding.permission_definition_id)
    return permission === undefined ? [] : [permission.name, permission.external_id]
  })

  return [
    account.engine_identity,
    account.kind,
    ...categoryAliases[category],
    ...roleNames,
  ].some((value) => value.toLocaleLowerCase('ru-RU').includes(normalizedQuery))
}

export interface AccountsTabProps {
  hbaQuery?: ConnectionHBAQuery
  connection: Connection
  permissions: Permission[]
  permissionsById: Map<string, Permission>
  /** The route owns the early query and its poller while the header loads. */
  accountsQuery?: ReturnType<typeof useConnectionAccountsQuery>
  /** Аккаунт, предвыбранный deep-link'ом из «Контроля». */
  initialSelectedId?: string | null
  /** Общая шапка подключения уже содержит постоянные входы в эти действия. */
  externalActions?: {
    onCreateAccount: () => void
    onGrantAccess: () => void
  }
}

// Inspector width is added back to the table below so opening it cannot
// rewrap every row. Narrow desktop panes scroll within the directory.
const ACCOUNT_CELL_LAYOUT = 'min-w-0 h-auto [padding-inline:0] py-0 align-top lg:h-9 lg:[padding-inline:0.75rem] lg:py-1.5'

export function AccountsTab({
  hbaQuery,
  connection,
  permissions,
  permissionsById,
  accountsQuery: sharedAccountsQuery,
  initialSelectedId = null,
  externalActions,
}: AccountsTabProps) {
  const connectionId = connection.id
  const auth = useAuth()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const canOperate = roleAtLeast(auth.role, 'operator')
  const canCreateAccount = canOperate && connection.status === 'active' && connection.capabilities.includes('account.create')
  const canGrantAccess = canOperate && connection.status === 'active' && connection.capabilities.includes('access.grant')
  const plainInventoryOnly = kafkaPlainInventoryOnly(connection)
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId)
  const [directAccessRequest, setDirectAccessRequest] = useState(0)

  // Повторный deep-link на смонтированной вкладке тоже выбирает аккаунт.
  useEffect(() => {
    if (initialSelectedId !== null) setSelectedId(initialSelectedId)
  }, [initialSelectedId])
  const [grantUserOpen, setGrantUserOpen] = useState(false)
  const [createAccountOpen, setCreateAccountOpen] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [trackedOperation, setTrackedOperation] = useState<TrackedOperation | null>(null)
  const [ownership, setOwnership] = useState<OwnershipFilterValue>('all')
  const [searchQuery, setSearchQuery] = useState('')
  // Deleted-аккаунты — tombstone'ы soft delete: по умолчанию скрыты, чтобы
  // не засорять список; тумблер показывает их приглушёнными строками.
  const [directoryView, setDirectoryView] = useState<AccountDirectoryView>('current')

  const fallbackAccountsQuery = useConnectionAccountsQuery(connectionId, { enabled: sharedAccountsQuery === undefined })
  const accountsQuery = sharedAccountsQuery ?? fallbackAccountsQuery
  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
  })
  const principalTypeById = useMemo(
    () => new Map((principalsQuery.data ?? []).map((principal) => [principal.id, principal.type])),
    [principalsQuery.data],
  )

  const trackOperation = (
    id: string,
    label: string,
    accountId: string | null = null,
    anchor: OperationAnchor = 'account',
  ) => {
    setNotice(null)
    setTrackedOperation({ id, label, accountId, anchor })
  }

  const refreshAfterOperation = (_operation: Operation) => {
    void Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(connectionId) }),
      queryClient.invalidateQueries({ queryKey: qk.connectionAccess(connectionId) }),
      queryClient.invalidateQueries({ queryKey: qk.accounts() }),
      queryClient.invalidateQueries({ queryKey: qk.principals() }),
      queryClient.invalidateQueries({ queryKey: qk.operations() }),
    ])
    // Terminal state остаётся у исходного объекта, пока оператор сам его не
    // закроет. Автоматическое закрытие панели ломало непрерывность сценария.
  }

  // Ресурсы нужны только для резолва scope binding'а («куда») в колонке
  // «Доступ». Ключ общий со вкладкой «Ресурсы» — react-query переиспользует
  // кэш, лишнего запроса нет.
  const resourcesQuery = useQuery({
    queryKey: connection.engine === 'postgres' ? [...qk.connectionResources(connectionId), 'database'] : qk.connectionResources(connectionId),
    queryFn: ({ signal }) =>
      apiList<Resource>(
        `/api/v1/connections/${connectionId}/resources${connection.engine === 'postgres' ? '?kind=database' : ''}`,
        'resources',
        signal,
      ),
  })

  const resourcesById = useMemo(
    () => indexById(resourcesQuery.data ?? []),
    [resourcesQuery.data],
  )

  const allAccounts = accountsQuery.data ?? []
  const selected = allAccounts.find((a) => a.id === selectedId) ?? null
  const filteredAccounts = allAccounts.filter((account) =>
    accountMatchesDirectorySearch(
      account,
      searchQuery,
      principalTypeById,
      permissionsById,
    ),
  )

  // Deleted — soft-delete tombstone'ы (пользователь в кластере уже удалён,
  // строка остаётся для аудита). Они НЕ входят в managed/cluster-зоны и их
  // счётчики: удалённый аккаунт больше не управляется. Показываются отдельной
  // приглушённой секцией внизу по тумблеру.
  const liveAccounts = accountsForDirectoryView(filteredAccounts, 'current')
  const deletedAccounts = sortAccountsForDisplay(
    accountsForDirectoryView(filteredAccounts, 'deleted'),
    principalTypeById,
  )
  // Group roles have no credential lifecycle. Keep them outside account
  // ownership zones even when their inventory metadata is marked managed.
  const roleAccounts = sortAccountsForDisplay(
    liveAccounts.filter((account) => isSharedRoleKind(account.kind)),
    principalTypeById,
  )
  const groups = groupByOwnership(
    liveAccounts.filter((account) => !isSharedRoleKind(account.kind)),
    (account) => account.ownership,
  )
  groups.managed = sortAccountsForDisplay(groups.managed, principalTypeById)
  groups.unmanaged = sortAccountsForDisplay(groups.unmanaged, principalTypeById)
  const hasLiveIdentities = groups.managed.length + groups.unmanaged.length > 0
  const showOwnershipFilter = directoryView === 'current' &&
    (hasLiveIdentities || ownership !== 'all')
  const showOwnershipColumn = directoryView === 'current'
    ? hasLiveIdentities
    : deletedAccounts.some((account) => !isSharedRoleKind(account.kind))
  const hasDirectColumn = connection.engine === 'postgres'
  const columnCount = (showOwnershipColumn ? 5 : 4) + (hasDirectColumn ? 1 : 0)
  const showManaged = ownership !== 'unmanaged'
  const showUnmanaged = ownership !== 'managed'

  const accountActions = (canCreateAccount || canGrantAccess) && externalActions === undefined ? (
    <div className="flex flex-wrap items-center gap-2">
      {canCreateAccount && (
        <Button variant="outline" size="sm" onClick={() => setCreateAccountOpen(true)}>
          <Plus className="size-4" />
          Создать учётку
        </Button>
      )}
      {canGrantAccess && (
        <Button variant="outline" size="sm" onClick={() => setGrantUserOpen(true)}>
          <KeyRound className="size-4" />
          Выдать доступ
        </Button>
      )}
    </div>
  ) : undefined

  return (
    <div className="space-y-3">
      {(notice !== null || trackedOperation !== null) && (
        <div className="flex min-h-11 items-center gap-3">
          {trackedOperation !== null ? (
            <OperationProgressNotice
              operationId={trackedOperation.id}
              label={trackedOperation.label}
              onSettled={refreshAfterOperation}
              onOpenDetails={(operation) => void navigate({
                to: '/control',
                search: {
                  tab: 'operations', status: 'all',
                  connection: operation.connection_id ?? connectionId,
                  query: operation.id,
                  operation: operation.id,
                },
              })}
              onClose={() => setTrackedOperation(null)}
            />
          ) : notice !== null ? (
            <InlineNotice text={notice} onClose={() => setNotice(null)} />
          ) : null}
        </div>
      )}

      <QueryStates
        query={accountsQuery}
        empty={
          <EmptyState
            icon={Users}
            title={plainInventoryOnly ? 'Каталог учёток недоступен' : 'Аккаунтов нет'}
            description={plainInventoryOnly
              ? 'Kafka не публикует список учёток PLAIN. Подключение использует существующий логин; Grantor не создаёт и не меняет такие учётки.'
              : externalActions !== undefined && canCreateAccount && canGrantAccess
                ? 'Создайте учётку или выдайте доступ с помощью кнопок наверху.'
                : externalActions !== undefined && canCreateAccount
                  ? 'Создайте учётку с помощью кнопки наверху.'
                  : externalActions !== undefined && canGrantAccess
                    ? 'Выдайте доступ с помощью кнопки наверху.'
                    : 'Discovery ещё не нашёл учётных записей, а managed-аккаунты не создавались.'}
            action={accountActions}
          />
        }
      >
        {() => {
          // Ownership задаётся заголовком секции и чипом строки.
          // Фон и рамка остаются семантикой hover/selection.
          const renderRow = (account: Account) => {
            const isDeleted = account.status === 'deleted'
            const sharedRole = isSharedRoleKind(account.kind)
            const isManaged = account.ownership === 'managed' && !isDeleted
            const isSelected = account.id === selectedId
            const status = accountProvisioningSummaryPresentation(account)
            const ownedDatabases = directlyOwnedPostgresDatabases(
              account,
              connection,
              resourcesQuery.data ?? [],
            )
            return (
              <TableRow
                key={account.id}
                interaction="selectable"
                divider="subtle"
                selected={isSelected}
                data-account-row={account.id}
                role="row"
                className={cn(
                  'grid grid-cols-[minmax(0,1fr)_auto] items-start gap-x-2 gap-y-1.5 px-3 py-3 lg:table-row lg:p-0',
                  isDeleted && 'opacity-60',
                )}
                onClick={() => { setDirectAccessRequest(0); setSelectedId(isSelected ? null : account.id) }}
              >
                <TableCell
                  overflow="wrap"
                  role="cell"
                  className={cn(
                    ACCOUNT_CELL_LAYOUT,
                    'order-1 col-span-2 font-mono text-[13px]',
                    ((!sharedRole && !isManaged) || isDeleted) && 'text-muted',
                    isDeleted && 'line-through',
                  )}
                >
                  <TableCopyableValue
                    value={account.engine_identity}
                    label={`Копировать имя аккаунта ${account.engine_identity}`}
                    className="w-full"
                  />
                  <AccountDatabaseOwnership databases={ownedDatabases} />
                </TableCell>
                <TableCell role="cell" className={cn(ACCOUNT_CELL_LAYOUT, 'order-2')}>
                  <KindBadge
                    kind={account.kind}
                    principalType={
                      account.principal_id === null
                        ? undefined
                        : principalTypeById.get(account.principal_id)
                    }
                  />
                </TableCell>
                <TableCell role="cell" overflow="anywhere" className={cn(ACCOUNT_CELL_LAYOUT, 'order-5 col-span-2')}>
                  <span className="mb-1 block text-[11px] font-medium text-muted lg:hidden">
                    {isDeleted ? 'Удаление' : hasDirectColumn ? 'Роли' : 'Доступ'}
                  </span>
                  {/* У tombstone bindings уже удалены — вместо прочерка в
                      колонке «Доступ» компактно показываем когда/кем удалён;
                      причина (если есть) — в title строки. */}
                  {isDeleted ? (
                    <DeletedSummary account={account} />
                  ) : (
                    <AccessSummary
                      bindings={account.bindings === undefined ? undefined : hasDirectColumn ? withoutObjectPrivileges(account.bindings, permissionsById) : account.bindings}
                      rolesOnly={hasDirectColumn}
                      permissionsById={permissionsById}
                      resourcesById={resourcesById}
                    />
                  )}
                </TableCell>
                {hasDirectColumn && <TableCell role="cell" className={cn(ACCOUNT_CELL_LAYOUT, 'order-6 col-span-2')}>
                  <span className="mb-1 block text-[11px] font-medium text-muted lg:hidden">Прямые права</span>
                  {account.bindings === undefined ? <span className="text-xs text-muted">Загрузка</span> : objectRecord(connection.topology).postgres_object_acl_version !== 1 ? <span className="text-xs text-muted">Нет снимка</span> :
                    <button type="button" className="grantor-touch-target ui-control-feedback inline-flex max-w-full items-center rounded border border-line bg-panel2 px-2 py-1 text-xs tabular-nums text-text hover:bg-hover focus-visible:outline-2 focus-visible:outline-accent"
                      aria-label={`Прямые права ${account.engine_identity}`}
                      onClick={event => { event.stopPropagation(); setSelectedId(account.id); setDirectAccessRequest(value => value + 1) }}>
                      {directObjectSummary(accountDirectObjectCount(account, account.bindings, permissionsById), connection.topology)}
                    </button>}
                </TableCell>}
                {showOwnershipColumn && (
                  <TableCell role="cell" overflow="anywhere" className={cn(ACCOUNT_CELL_LAYOUT, 'order-4 col-span-2')}>
                    {!sharedRole && (
                      <span className="inline-flex flex-wrap items-center gap-1">
                        <StatusChip tone={ownershipTone(account.ownership)}>
                          {ownershipLabel(account.ownership)}
                        </StatusChip>
                        {/* Служебная учётка подключения выглядела обычной
                            unmanaged-строкой, и «Принять под управление»
                            отвечало 409 уже после клика. */}
                        {isConnectionAdminAccount(account) && (
                          <StatusChip tone="accent">Учётка подключения</StatusChip>
                        )}
                      </span>
                    )}
                  </TableCell>
                )}
                <TableCell role="cell" overflow="anywhere" className={cn(ACCOUNT_CELL_LAYOUT, 'order-3 max-w-[12rem] justify-self-end lg:max-w-none')}>
                  <StatusChip tone={status.tone} className="min-h-[22px] max-w-full flex-wrap py-0.5 [height:auto] [white-space:normal]">
                    <span className="min-w-0 [overflow-wrap:anywhere]">{status.label}</span>
                  </StatusChip>
                </TableCell>
              </TableRow>
            )
          }
          // Category boundaries are deliberately quieter than ownership zone
          // headers: a narrow tonal gap keeps Login / Service / Group readable
          // without introducing another level of section headings.
          const renderAccountRows = (accounts: Account[]) => accounts.map((account, index) => {
            const category = accountDisplayCategory(account, principalTypeById)
            const showDivider = index > 0 && isAccountCategoryBoundary(
              accounts[index - 1],
              account,
              principalTypeById,
            )

            return (
              <Fragment key={account.id}>
                {showDivider && (
                  <tr
                    aria-hidden="true"
                    data-account-category-divider={category}
                    className="h-2 bg-panel2/25"
                  >
                    <td className="border-y border-line/20 p-0" colSpan={columnCount} />
                  </tr>
                )}
                {renderRow(account)}
              </Fragment>
            )
          })
          return (
            <div className="space-y-3">
              <div
                className="flex flex-wrap items-center gap-2"
                role="group"
                aria-label="Поиск и фильтры аккаунтов"
              >
                <SearchInput
                  value={searchQuery}
                  onChange={setSearchQuery}
                  placeholder="Login, группа или роль..."
                  ariaLabel="Поиск по login, группе или роли доступа"
                  density="compact"
                  className="w-72 max-w-full shrink-0"
                />
                {showOwnershipFilter && (
                  <SegmentedFilter
                    label="Управление аккаунтами"
                    value={ownership}
                    onChange={setOwnership}
                    options={ownershipFilterOptions(
                      groups.managed.length,
                      groups.unmanaged.length,
                    ).map((option) => option.value === 'all'
                      ? { ...option, count: liveAccounts.length }
                      : option)}
                  />
                )}
                {showOwnershipFilter && (
                  <span className="h-4 w-px shrink-0 bg-line" aria-hidden="true" />
                )}
                <AccountDirectoryFilter
                  value={directoryView}
                  currentCount={liveAccounts.length}
                  deletedCount={deletedAccounts.length}
                  onChange={setDirectoryView}
                />
                {accountActions !== undefined && (
                  <div className="ml-auto shrink-0">{accountActions}</div>
                )}
              </div>
              <InspectorSplitLayout
                content={(
                  <TableContainer role="region" aria-label="Список аккаунтов" tabIndex={0} className="min-w-0 flex-1 focus-visible:outline-2 focus-visible:outline-accent">
                    <Table role="table" aria-label="Аккаунты подключения" className="block w-full lg:table lg:min-w-[56rem] lg:w-[calc(100%_+_var(--inspector-inline-size,0px))] lg:table-fixed">
                      <colgroup className="hidden lg:table-column-group">
                        <col className={hasDirectColumn ? 'w-[24%]' : 'w-[28%]'} />
                        <col className={hasDirectColumn ? 'w-[9%]' : 'w-[11%]'} />
                        <col className={hasDirectColumn ? showOwnershipColumn ? 'w-[21%]' : 'w-[34%]' : showOwnershipColumn ? 'w-[23%]' : 'w-[37%]'} />
                        {hasDirectColumn && <col className="w-[14%]" />}
                        {showOwnershipColumn && <col className={hasDirectColumn ? 'w-[13%]' : 'w-[14%]'} />}
                        <col className={hasDirectColumn ? 'w-[19%]' : 'w-[24%]'} />
                      </colgroup>
                      <TableHeader className="sr-only lg:not-sr-only lg:table-header-group">
                        <tr>
                          <TableHead overflow="wrap">Identity</TableHead>
                          <TableHead>Kind</TableHead>
                          <TableHead overflow="anywhere">{hasDirectColumn ? 'Роли' : 'Доступ'}</TableHead>
                          {hasDirectColumn && <TableHead overflow="anywhere">Прямые права</TableHead>}
                          {showOwnershipColumn && <TableHead overflow="anywhere">Ownership</TableHead>}
                          <TableHead overflow="anywhere">Статус</TableHead>
                        </tr>
                      </TableHeader>
                      <TableBody
                        role="rowgroup"
                        className="block lg:table-row-group [&>tr:not([data-account-row])]:block [&>tr:not([data-account-row])>td]:block lg:[&>tr:not([data-account-row])]:table-row lg:[&>tr:not([data-account-row])>td]:table-cell"
                      >
                        {directoryView === 'current' && hasLiveIdentities && showManaged && (
                          <>
                            <ZoneSectionRow
                              zone="managed"
                              colSpan={columnCount}
                              count={groups.managed.length}
                              hint={
                                groups.managed.length === 0
                                  ? 'создайте аккаунт или выдайте право'
                                  : undefined
                              }
                            />
                            {renderAccountRows(groups.managed)}
                          </>
                        )}
                        {directoryView === 'current' && showUnmanaged && groups.unmanaged.length > 0 && (
                          <>
                            <ZoneSectionRow
                              zone="sync"
                              colSpan={columnCount}
                              count={groups.unmanaged.length}
                            />
                            {renderAccountRows(groups.unmanaged)}
                          </>
                        )}
                        {directoryView === 'current' && ownership === 'all' && roleAccounts.length > 0 && (
                          <>
                            <ZoneSectionRow
                              zone="sync"
                              label="Роли"
                              colSpan={columnCount}
                              count={roleAccounts.length}
                            />
                            {renderAccountRows(roleAccounts)}
                          </>
                        )}
                        {directoryView === 'deleted' && deletedAccounts.length > 0 && (
                          <>
                            <ZoneSectionRow
                              zone="sync"
                              label="Deleted"
                              colSpan={columnCount}
                              count={deletedAccounts.length}
                              hint="Прежние права и связи не восстанавливаются"
                            />
                            {renderAccountRows(deletedAccounts)}
                          </>
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
                inspector={
                  selected !== null ? (
                    <AccountDetailPanel
                      directAccessRequest={directAccessRequest}
                      key="account-panel"
                      account={selected}
                      hbaQuery={hbaQuery}
                      connection={connection}
                      permissions={permissions}
                      permissionsById={permissionsById}
                      resourcesById={resourcesById}
                      onClose={() => setSelectedId(null)}
                      onNotice={setNotice}
                      onOperationStarted={(operationId, label, anchor = 'account') =>
                        trackOperation(operationId, label, selected.id, anchor)
                      }
                    />
                  ) : null
                }
              />
            </div>
          )
        }}
      </QueryStates>

      <CreateAccountDrawer
        connectionId={connectionId}
        connection={connection}
        open={createAccountOpen}
        onClose={() => setCreateAccountOpen(false)}
        onStarted={(operationId, identity) => {
          setCreateAccountOpen(false)
          trackOperation(operationId, `Создание учётки ${identity}`)
        }}
      />

      <GrantAccessDrawer
        open={grantUserOpen}
        fixedConnectionId={connectionId}
        onClose={() => setGrantUserOpen(false)}
        onStarted={(operationId, principalName) => {
          setGrantUserOpen(false)
          trackOperation(operationId, `Выдача доступа ${principalName}`)
        }}
      />
    </div>
  )
}

interface DeletedSummaryProps {
  account: Account
}

// Компактная сводка tombstone в колонке «Доступ»: когда и кем удалён;
// причина удаления (если есть) — в title. У старых tombstone'ов без
// deleted_at остаётся прежний прочерк с пояснением.
function DeletedSummary({ account }: DeletedSummaryProps) {
  const when = account.deleted_at != null ? formatDateTime(account.deleted_at) : null
  const who = account.deleted_by ?? null
  const reason = account.delete_reason ?? null
  if (when === null && who === null) {
    return (
      <span
        className="text-faint"
        title="Аккаунт удалён до ввода учёта деталей: кто/когда/почему неизвестно"
      >
        —
      </span>
    )
  }
  const parts = [`удалён ${when ?? '—'}`, ...(who !== null ? [who] : [])]
  return (
    <span
      className="text-[12px] text-faint"
      title={reason !== null && reason !== '' ? `Причина: ${reason}` : undefined}
    >
      {parts.join(' · ')}
    </span>
  )
}

interface AccessSummaryProps {
  rolesOnly?: boolean
  bindings: Account['bindings']
  permissionsById: Map<string, Permission>
  resourcesById: Map<string, Resource>
}

// Колонка «Доступ»: компактная сводка фактических (observed + managed)
// прав аккаунта прямо в списке, без захода в панель. Пустой список — прочерк.
function AccessSummary({ bindings, permissionsById, resourcesById, rolesOnly = false }: AccessSummaryProps) {
  if (bindings === undefined) {
    return <span className="text-faint">…</span>
  }
  const entries = buildAccessEntries(bindings, permissionsById, resourcesById)
  if (rolesOnly && entries.length === 0) return <span className="text-xs text-muted">Нет ролей</span>
  if (entries.length === 0) {
    return (
      <span className="text-faint" title="Discovery не нашёл прав у аккаунта">
        —
      </span>
    )
  }
  // maxVisible=2: колонка «Доступ» — самая широкая в таблице, три чипа
  // вместе с длинной identity распирали её за пределы экрана; остальные
  // права доступны через «+N».
  return <AccessChipList entries={entries} maxVisible={2} wrapLabels />
}
