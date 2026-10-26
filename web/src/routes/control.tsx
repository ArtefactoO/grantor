import { Fragment, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getRouteApi, Link, useNavigate } from '@tanstack/react-router'
import { ArrowUpRight, Bot, ChevronRight, KeyRound, Plug, RefreshCw, ScrollText, ShieldAlert, SlidersHorizontal, User, UserCog } from '@project/ui/icons'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { ConnectionPicker } from '../components/ConnectionPicker'
import {
  Button,
  Card,
  Dialog,
  EmptyState,
  ErrorState,
  IconButton,
  Input,
  SearchInput,
  selectionTabClassName,
  LoadingSkeleton,
  RowSkeleton,
  cn,
} from '@project/ui'
import { SegmentedFilter } from '../components/ui/selection-chips'
import { OperationTimeline } from '../components/operation-timeline'
import { ControlConnectors } from './control-connectors'
import { AttentionInbox } from './control-attention'
import { StatusChip } from '../components/ui/badge'
import { SidePanel } from './connection-panels'
import { api, apiList, apiListPage, apiPost } from '../lib/api'
import { connectionSearchValue, useConnectionScope } from '../lib/connection-context'
import {
  connectionEngineLabel,
  connectionEnvironmentLabel,
} from '../lib/connection-presentation'
import {
  auditMatchesQuery,
  controlTabsForRole,
  controlFilterForTab,
  DEFAULT_CONTROL_TAB,
  findingBaselineRef,
  findingLinkTarget,
  findingMatchesFilter,
  groupFindings,
  findingMatchesQuery,
  isUnresolvedOperationFailure,
  operationMatchesFilter,
  operationMatchesQuery,
} from '../lib/control-search'
import type { ControlFilter, ControlOperationFilter, ControlTab } from '../lib/control-search'
import { journalHasMore, mergeJournal } from '../lib/control-journal'
import type { JournalRow } from '../lib/control-journal'
import { JournalKindFilter, JournalRangeFilter } from './control-journal-filters'
import { controlTabFilterOptions } from '../lib/filter-presentation'
import type { ControlFilterCounts } from '../lib/filter-presentation'
import { errorMessage } from '../lib/errorMessage'
import { POLL_OPERATION_MS, POLL_OPERATIONS_MS } from '../lib/intervals'
import { qk } from '../lib/queryKeys'
import {
  accountAdoptContext,
  accountAdoptModeLabel,
  accountManagedLinkContext,
  operationFailureMessages,
  operationDisplayLabel,
  operationStatusLabel,
} from '../lib/operation-presentation'
import { auditDomain, auditSubject, groupByDay, isServiceActor } from '../lib/audit-presentation'
import { auditResultTone, driftKindTone, effectiveOperationStatus, operationStatusTone, shortId } from '../lib/status'
import { formatDateTime, formatRelative } from '../lib/time'
import type { Account, AuditEvent, DriftFinding, DriftReport, Operation, Permission, Principal, RetryOperationResponse } from '../lib/types'
import { auditActionLabel, auditResultLabel, driftKindLabel, externalIdentityStatusLabel, UI_COPY } from '../lib/ui-copy'
import { ScopePoliciesPage } from './scope-policies'

const routeApi = getRouteApi('/control')
const ACTIVE = new Set(['pending', 'pending_approval', 'running'])
const ADMIN_CREDENTIAL_OPERATION_KINDS = new Set([
  'connection.admin_credential.switch',
  'connection.admin_credential.rotate',
])

export function isRetryableAdminCredentialOperation(operation: Operation): boolean {
  return operation.parent_id === null && operation.status === 'failed' &&
    operation.retryable === true && ADMIN_CREDENTIAL_OPERATION_KINDS.has(operation.kind)
}

export function isRetryableDatabaseProvisioningOperation(operation: Operation): boolean {
  return operation.parent_id === null && operation.kind === 'postgres.resource.create.database_with_roles.v2' &&
    (operation.status === 'failed' || operation.status === 'partial') && operation.retryable === true
}
/** Размер страницы каждого источника ленты; «Показать ещё» наращивает его. */
const JOURNAL_PAGE_SIZE = 100
/** Потолок страницы — серверный maxPageLimit. */
const JOURNAL_MAX_PAGE_SIZE = 500
/** Сброс окна периода: пресет задаёт свои границы поверх пустых. */
const emptyWindow = { created_from: undefined, created_before: undefined }

export function operationConnectionIds(operation: Operation): string[] {
  return [...new Set(
    [operation.connection_id, ...(operation.children ?? []).map((child) => child.connection_id)]
      .filter((id): id is string => id !== null),
  )]
}

export function operationEffectiveConnectionId(operation: Operation): string | null {
  const ids = operationConnectionIds(operation)
  return ids.length === 1 ? ids[0] : null
}

export function shouldPollOperation(operation: Operation | undefined): boolean {
  if (operation === undefined) return true
  return ACTIVE.has(effectiveOperationStatus(operation))
}

type Selected =
  | { type: 'operation'; value: Operation }
  | { type: 'finding'; value: DriftFinding }
  | { type: 'audit'; value: AuditEvent }

export function ControlPage() {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const canResolve = roleAtLeast(auth.role, 'operator')
  const search = routeApi.useSearch()
  const navigate = useNavigate({ from: '/control' })
  const queryClient = useQueryClient()
  const requestedTab: ControlTab = search.tab ?? DEFAULT_CONTROL_TAB
  const tab: ControlTab =
    requestedTab === 'environments' && !isAdmin
      ? DEFAULT_CONTROL_TAB
      : requestedTab
  const filter = controlFilterForTab(tab, search.status)
  const query = search.query ?? ''
  const [selected, setSelected] = useState<Selected | null>(null)
  const [decision, setDecision] = useState<'approve' | 'reject' | null>(null)
  const { query: connectionsQuery, connections, resolution } = useConnectionScope(search.connection, true)
  const connectionId = resolution.kind === 'selected' ? resolution.connectionId : ''
  const scopeQueryable = search.connection === undefined || resolution.kind === 'selected'
  // Подписи подключений объявлены здесь, а не рядом с рендером: их читают
  // фабрики useMemo ниже, а те выполняются прямо во время рендера — объявление
  // после них попадало бы в temporal dead zone и роняло всю страницу.
  const connectionName = (id: string | null) => connections.find((item) => item.id === id)?.display_name ?? (id === null ? '—' : shortId(id))
  const connectionEngine = (id: string | null) => {
    const engine = connections.find((item) => item.id === id)?.engine
    return engine === undefined ? '—' : connectionEngineLabel(engine)
  }
  const connectionEnvironment = (id: string | null) => {
    const environment = connections.find((item) => item.id === id)?.environment
    return environment === undefined ? '—' : connectionEnvironmentLabel(environment)
  }

  useEffect(() => {
    if (requestedTab !== 'environments' || isAdmin) return
    void navigate({
      replace: true,
      search: (previous) => ({
        ...previous,
        tab: DEFAULT_CONTROL_TAB,
        status: 'all',
      }),
    })
  }, [isAdmin, navigate, requestedTab])

  // «Показать ещё» наращивает общий размер страницы обоих источников: два
  // независимых offset'а не дают стабильного порядка слияния.
  const [pageSize, setPageSize] = useState(JOURNAL_PAGE_SIZE)
  useEffect(() => {
    setPageSize(JOURNAL_PAGE_SIZE)
  }, [connectionId, filter, search.created_from, search.created_before, search.kind])

  const operationParams = new URLSearchParams({ limit: String(pageSize) })
  operationParams.set('top_level_only', 'true')
  if (connectionId !== '') operationParams.set('connection_id', connectionId)
  if (search.created_from !== undefined) operationParams.set('created_from', search.created_from)
  if (search.created_before !== undefined) operationParams.set('created_before', search.created_before)
  if (search.kind !== undefined) operationParams.set('kind', search.kind)
  // Статусы и manual фильтруются на сервере: иначе системные синки и success
  // съедают страницу, и нужные строки не долетают до клиента.
  if (filter === 'manual') operationParams.set('actor_type', 'user')
  if (filter === 'active') operationParams.set('status', 'pending,pending_approval,running')
  if (filter === 'approval') operationParams.set('status', 'pending_approval')
  if (filter === 'errors') {
    operationParams.set('status', 'failed,partial,cancelled')
    operationParams.set('unresolved_only', 'true')
  }
  const operationsQuery = useQuery({
    queryKey: qk.operationsList(connectionId, filter, search.kind ?? '', search.created_from ?? '', search.created_before ?? '', pageSize),
    queryFn: ({ signal }) => apiListPage<Operation>(`/api/v1/operations?${operationParams}`, 'operations', signal),
    enabled: scopeQueryable,
    refetchInterval: (result) =>
      result.state.data?.items.some((item) =>
        ACTIVE.has(effectiveOperationStatus(item)),
      )
        ? POLL_OPERATIONS_MS
        : false,
  })
  const selectedOperationQuery = useQuery({
    queryKey: qk.operation(search.operation ?? ''),
    queryFn: ({ signal }) => api<Operation>(`/api/v1/operations/${search.operation}`, { signal }),
    enabled: search.operation !== undefined,
    refetchInterval: (result) =>
      shouldPollOperation(result.state.data) ? POLL_OPERATION_MS : false,
  })
  const selectedOperationForInventory = selectedOperationQuery.data ??
    (selected?.type === 'operation' ? selected.value : undefined)
  const selectedOperationConnectionId = selectedOperationForInventory === undefined
    ? null
    : operationEffectiveConnectionId(selectedOperationForInventory)
  const selectedAccountsQuery = useQuery({
    queryKey: qk.connectionAccounts(selectedOperationConnectionId ?? ''),
    queryFn: ({ signal }) =>
      apiList<Account>(
        `/api/v1/connections/${selectedOperationConnectionId}/accounts?include=bindings,provisioning`,
        'accounts',
        signal,
      ),
    enabled: selectedOperationConnectionId !== null,
  })
  const selectedPermissionsQuery = useQuery({
    queryKey: qk.connectionPermissions(selectedOperationConnectionId ?? ''),
    queryFn: ({ signal }) =>
      apiList<Permission>(
        `/api/v1/connections/${selectedOperationConnectionId}/permissions`,
        'permissions',
        signal,
      ),
    enabled: selectedOperationConnectionId !== null,
  })
  const approvalsQuery = useQuery({
    queryKey: qk.approvals(),
    queryFn: ({ signal }) => apiList<Operation>('/api/v1/approvals', 'operations', signal),
    enabled: scopeQueryable && isAdmin,
    refetchInterval: 10_000,
  })
  // Инбокс не зависит от периода и фильтров ленты: «требует внимания»
  // означает «висит прямо сейчас», а не «попало в выбранное окно».
  const [attentionOffset, setAttentionOffset] = useState(0)
  useEffect(() => { setAttentionOffset(0) }, [connectionId, filter, query])
  const attentionParams = new URLSearchParams({
    status: 'failed,partial,cancelled',
    top_level_only: 'true',
    unresolved_only: 'true',
    limit: '100',
    offset: String(attentionOffset),
  })
  if (connectionId !== '') attentionParams.set('connection_id', connectionId)
  const attentionErrorsQuery = useQuery({
    queryKey: [...qk.operationsUnresolved(connectionId), attentionOffset],
    queryFn: ({ signal }) =>
      apiListPage<Operation>(`/api/v1/operations?${attentionParams}`, 'operations', signal),
    enabled: scopeQueryable,
    refetchInterval: POLL_OPERATIONS_MS,
  })
  // Счётчик подтверждений на вкладке виден и не-админу: сам список ждущих
  // операций admin-only, а число — обычная выборка операций по статусу.
  const approvalCountParams = new URLSearchParams({ status: 'pending_approval', limit: '1' })
  if (connectionId !== '') approvalCountParams.set('connection_id', connectionId)
  const approvalCountQuery = useQuery({
    queryKey: qk.operationsPendingApprovalCount(connectionId),
    queryFn: ({ signal }) =>
      apiListPage<Operation>(`/api/v1/operations?${approvalCountParams}`, 'operations', signal),
    enabled: scopeQueryable,
    refetchInterval: POLL_OPERATIONS_MS,
  })
  const driftQuery = useQuery({
    queryKey: qk.drift(connectionId),
    queryFn: ({ signal }) => api<DriftReport>(`/api/v1/drift${connectionId === '' ? '' : `?connection_id=${encodeURIComponent(connectionId)}`}`, { signal }),
    enabled: scopeQueryable,
  })
  // Лента показывает только события вне операций: у операции есть своя
  // строка, а её собственные события живут в детальной панели.
  const auditParams = new URLSearchParams({ limit: String(pageSize) })
  auditParams.set('standalone', 'true')
  if (connectionId !== '') auditParams.set('connection_id', connectionId)
  if (search.created_from !== undefined) auditParams.set('occurred_from', search.created_from)
  if (search.created_before !== undefined) auditParams.set('occurred_before', search.created_before)
  const auditQuery = useQuery({
    queryKey: qk.audit(connectionId, search.created_from ?? '', search.created_before ?? '', pageSize),
    queryFn: ({ signal }) => apiListPage<AuditEvent>(`/api/v1/audit?${auditParams}`, 'events', signal),
    // События не имеют статуса операции: на статусных чипах и при фильтре по
    // типу лента показывает только операции, и запрос не нужен.
    enabled: scopeQueryable && tab === 'operations'
      && (filter === 'all' || filter === 'events') && search.kind === undefined,
  })
  // След выбранной операции: её собственные audit-события приходят отдельным
  // запросом, а не выбираются из общей ленты, которая их больше не содержит.
  const operationAuditQuery = useQuery({
    queryKey: qk.auditByOperation(search.operation ?? ''),
    queryFn: ({ signal }) =>
      apiList<AuditEvent>(
        `/api/v1/audit?operation_id=${encodeURIComponent(search.operation ?? '')}&limit=200`,
        'events',
        signal,
      ),
    enabled: search.operation !== undefined,
  })
  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) => apiList<Principal>('/api/v1/principals', 'principals', signal),
  })
  const resolveMutation = useMutation({
    mutationFn: (operation: Operation) =>
      api<Operation>(`/api/v1/operations/${operation.id}/resolve`, { method: 'POST' }),
    onSuccess: (resolved) => {
      setSelected((current) => current?.type === 'operation' && current.value.id === resolved.id
        ? { type: 'operation', value: resolved }
        : current)
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      void queryClient.invalidateQueries({ queryKey: ['audit'] })
    },
  })
  const retryMutation = useMutation({
    mutationFn: (operation: Operation) =>
      api<RetryOperationResponse>(`/api/v1/operations/${operation.id}/retry`, { method: 'POST' }),
    onSuccess: async (_response, operation) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.operation(operation.id) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
        queryClient.invalidateQueries({ queryKey: qk.connection(operation.connection_id ?? '') }),
        queryClient.invalidateQueries({ queryKey: ['audit'] }),
      ])
    },
  })

  const operations = useMemo(() => {
    const items = operationsQuery.data?.items ?? []
    const selectedOperation = selectedOperationQuery.data
    if (selectedOperation === undefined) {
      return items
    }
    if (items.some((item) => item.id === selectedOperation.id)) {
      return items.map((item) =>
        item.id === selectedOperation.id ? selectedOperation : item,
      )
    }
    if (connectionId !== '' && !operationConnectionIds(selectedOperation).includes(connectionId)) {
      return items
    }
    return [selectedOperation, ...items]
  }, [connectionId, operationsQuery.data?.items, selectedOperationQuery.data])
  const approvals = (approvalsQuery.data ?? []).filter((item) => connectionId === '' || item.connection_id === connectionId)
  const findings = driftQuery.data?.findings ?? []
  const baselinedFindings = driftQuery.data?.baselined ?? []
  const events = auditQuery.data?.items ?? []
  const operationAuditEvents = operationAuditQuery.data ?? []
  const principalNames = useMemo(
    () =>
      new Map(
        (principalsQuery.data ?? []).map((principal) => [
          principal.id,
          principal.display_name,
        ]),
      ),
    [principalsQuery.data],
  )
  const selectedAccounts = useMemo(
    () => new Map((selectedAccountsQuery.data ?? []).map((account) => [account.id, account])),
    [selectedAccountsQuery.data],
  )
  const selectedPermissions = useMemo(
    () => new Map((selectedPermissionsQuery.data ?? []).map((permission) => [permission.id, permission])),
    [selectedPermissionsQuery.data],
  )
  useEffect(() => {
    if (selectedOperationQuery.data !== undefined) {
      retryMutation.reset()
      setSelected({ type: 'operation', value: selectedOperationQuery.data })
    }
  // retryMutation.reset is stable; data identity is the selection boundary.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOperationQuery.data])
  const visibleOperations = useMemo(
    () => (filter === 'events' ? [] : operations).filter((item) =>
      operationMatchesFilter(item, filter as ControlOperationFilter)
      && operationMatchesQuery(item, query, [connectionName(item.connection_id)])),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- connectionName зависит от списка подключений
    [filter, operations, query, connections],
  )
  const visibleFindings = useMemo(
    () => (filter === 'baselined' ? baselinedFindings : findings)
      .filter((item) => (filter === 'baselined' || findingMatchesFilter(item, filter)) && findingMatchesQuery(item, query)),
    [baselinedFindings, filter, findings, query],
  )
  // События вплетаются в ленту только на «Все» и на своём чипе: у статусных
  // фильтров (активные, ошибки, подтверждения) нет смысла для audit-события.
  const visibleEvents = useMemo(
    () => (filter === 'all' || filter === 'events' ? events : [])
      .filter((item) => auditMatchesQuery(item, query, [connectionName(item.connection_id)])),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- connectionName зависит от списка подключений
    [events, filter, query, connections],
  )
  const journalRows = useMemo(
    () => mergeJournal(visibleOperations, visibleEvents, pageSize),
    [pageSize, visibleEvents, visibleOperations],
  )
  const canLoadMore = pageSize < JOURNAL_MAX_PAGE_SIZE && journalHasMore(
    { operations: operations.length, events: events.length },
    { operations: operationsQuery.data?.total, events: auditQuery.data?.total },
  )
  const observedKinds = useMemo(() => operations.map((item) => item.kind), [operations])
  const unresolvedErrors = attentionErrorsQuery.data?.items ?? []
  const activeOperations = operations.filter((item) =>
    operationMatchesFilter(item, 'active'))
  // Бейджи вкладок — из серверных total, а не из загруженной страницы:
  // счётчик, считающий только первые сто строк, вводит в заблуждение ровно
  // тогда, когда он нужен.
  const approvalsTotal = approvalCountQuery.data?.total ?? 0
  const unresolvedTotal = attentionErrorsQuery.data?.total ?? 0
  const tabBadges: Partial<Record<ControlTab, number>> = {
    attention: approvalsTotal + unresolvedTotal,
    findings: findings.length,
  }
  useEffect(() => {
    if (attentionErrorsQuery.data && attentionOffset > 0 && attentionOffset >= unresolvedTotal) setAttentionOffset(0)
  }, [attentionErrorsQuery.data, attentionOffset, unresolvedTotal])
  const filterCounts: ControlFilterCounts = {
    all: tab === 'attention'
      ? approvalsTotal + unresolvedTotal
      : tab === 'operations'
        ? operations.length + events.length
        : findings.length,
    active: activeOperations.length,
    approval: approvalsTotal,
    manual: operations.filter((item) => operationMatchesFilter(item, 'manual')).length,
    errors: unresolvedTotal,
    events: events.length,
    drift: findings.length,
    access: findings.filter((item) => findingMatchesFilter(item, 'access')).length,
    resources: findings.filter((item) => findingMatchesFilter(item, 'resources')).length,
    connections: findings.filter((item) => findingMatchesFilter(item, 'connections')).length,
    baselined: baselinedFindings.length,
  }
  const filterOptions = controlTabFilterOptions(tab, filterCounts, filter)
  const visibleTabs = controlTabsForRole(isAdmin)
  const patchSearch = (next: Partial<{ tab: ControlTab; status: ControlFilter; query: string; connection: string | undefined; operation: string | undefined; kind: string | undefined }>) => {
    void navigate({ search: (previous) => ({ ...previous, ...next }) })
  }
  const selectOperation = (value: Operation) => {
    // Строка списка намеренно содержит сокращённую operation без children.
    // URL запускает detail-query и оставляет выбранную операцию доступной для
    // polling, обновления статуса и прямой ссылки.
    retryMutation.reset()
    setSelected({ type: 'operation', value })
    patchSearch({ operation: value.id })
  }
  const refresh = () => {
    void Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.operations() }),
      queryClient.invalidateQueries({ queryKey: qk.approvals() }),
      queryClient.invalidateQueries({ queryKey: qk.drift() }),
      queryClient.invalidateQueries({ queryKey: ['audit'] }),
      queryClient.invalidateQueries({ queryKey: qk.principals() }),
    ])
  }
  // Отключённый запрос вечно остаётся pending, поэтому ждём только те
  // источники, которые нужны текущей вкладке.
  const attentionQueries = filter === 'errors'
    ? [attentionErrorsQuery]
    : [approvalCountQuery, ...(isAdmin ? [approvalsQuery] : []),
      ...(filter === 'approval' ? [] : [attentionErrorsQuery])]
  const tabQueries = tab === 'operations'
    ? [operationsQuery, ...(auditQuery.fetchStatus === 'idle' && auditQuery.isPending ? [] : [auditQuery])]
    : tab === 'attention' ? attentionQueries : [driftQuery]
  const pending = connectionsQuery.isPending || tabQueries.some((item) => item.isPending)
  const firstError = connectionsQuery.error
    ?? tabQueries.map((item) => item.error).find((item) => item != null)
    ?? null

  return (
    <div className="mx-auto max-w-7xl space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold">Контроль</h1>
          <p className="mt-1 text-sm text-muted">Подтверждения, операции, несоответствия и аудит в одном рабочем потоке.</p>
        </div>
        <IconButton label="Обновить данные контроля" onClick={refresh}
          icon={<RefreshCw className="size-4" aria-hidden="true" />} />
      </header>

      <div className="flex items-start gap-6">
      <div className="min-w-0 flex-1 space-y-4">

      <div className="flex flex-wrap gap-1 border-b border-line" role="tablist" aria-label="Раздел контроля">
        {visibleTabs.map(([value, label]) => (
          <button key={value} type="button" role="tab" aria-selected={tab === value}
            onClick={() => {
              setSelected(null)
              patchSearch({ tab: value, status: 'all', operation: undefined })
            }}
            className={selectionTabClassName(tab === value, 'muted', 'px-3 py-2 text-sm')}>
            {label}
            {(tabBadges[value] ?? 0) > 0 && <span className="ml-1.5 text-xs text-muted">{tabBadges[value]}</span>}
          </button>
        ))}
      </div>

      {tab !== 'environments' && tab !== 'connectors' && <div className="flex flex-wrap items-center gap-2">
        <ConnectionPicker allowAll connections={connections} value={search.connection}
          onValueChange={(value) => patchSearch({ connection: connectionSearchValue(value) })}
          disabled={connectionsQuery.isPending || connectionsQuery.isError} label="Фильтр по подключению" className="w-72 max-w-full" />
        <div className="min-w-56 flex-1">
          <SearchInput
            value={query}
            onChange={(value) => patchSearch({ query: value || undefined })}
            placeholder="Поиск по операции, пользователю или ресурсу…"
            ariaLabel="Поиск в контроле"
            debounceMs={250}
          />
        </div>
      </div>}

      {tab === 'operations' && <div className="flex flex-wrap items-center gap-3">
        <JournalRangeFilter
          window={{ created_from: search.created_from, created_before: search.created_before }}
          onChange={(next) => void navigate({ search: (previous) => ({ ...previous, ...emptyWindow, ...next }) })}
        />
        <JournalKindFilter value={search.kind ?? ''} observedKinds={observedKinds}
          onValueChange={(value) => patchSearch({ kind: value === '' ? undefined : value })} />
      </div>}

      {tab !== 'environments' && tab !== 'connectors' && <SegmentedFilter
        label="Фильтр текущей вкладки"
        value={filter}
        options={filterOptions}
        onChange={(value) => patchSearch({ status: value })}
      />}

      {tab === 'connectors' ? <ControlConnectors canEdit={isAdmin} />
        : tab === 'environments' ? <ScopePoliciesPage embedded />
        : !scopeQueryable ? <EmptyState title="Подключение недоступно" description="Выберите доступное подключение или глобальный обзор." />
        : firstError !== null ? <ErrorState message={errorMessage(firstError)} onRetry={refresh} />
        : pending ? <LoadingSkeleton><RowSkeleton rows={6} leading /></LoadingSkeleton>
        : tab === 'attention' ? (
          <>
          <AttentionFeed
            key={`${connectionId}:${filter}:${query}:${attentionOffset}`}
            approvals={(filter === 'all' || filter === 'approval')
              ? approvals.filter((item) => operationMatchesQuery(item, query))
              : []}
            operations={(filter === 'all' || filter === 'errors')
              ? unresolvedErrors.filter((item) => operationMatchesQuery(item, query))
              : []}
            connectionName={connectionName}
            onSelect={(item) => {
              if (item.type === 'operation') selectOperation(item.value)
              else setSelected(item)
            }}
            canApprove={isAdmin} canResolve={canResolve} currentActor={auth.email} />
          {(filter === 'all' || filter === 'errors') && unresolvedTotal > 100 && <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
            <span>Ошибки: {attentionOffset + 1}–{Math.min(attentionOffset + 100, unresolvedTotal)} из {unresolvedTotal}. Выбор действует на показанные строки.</span>
            <div className="flex gap-2">
              <Button variant="outline" disabled={attentionOffset === 0} onClick={() => setAttentionOffset((offset) => Math.max(0, offset - 100))}>Назад</Button>
              <Button variant="outline" disabled={attentionOffset + 100 >= unresolvedTotal} onClick={() => setAttentionOffset((offset) => offset + 100)}>Далее</Button>
            </div>
          </div>}
          </>
        ) : tab === 'operations' ? (
          <>
            <JournalList rows={journalRows} connectionName={connectionName}
              principalNames={principalNames} accountsById={selectedAccounts}
              onSelectOperation={selectOperation}
              onSelectEvent={(value) => setSelected({ type: 'audit', value })} />
            {canLoadMore && <div className="flex justify-center">
              <Button variant="ghost" size="sm" onClick={() => setPageSize((current) => Math.min(current * 2, JOURNAL_MAX_PAGE_SIZE))}>
                Показать ещё
              </Button>
            </div>}
          </>
        ) : <FindingList items={visibleFindings} connectionName={connectionName} onSelect={(value) => setSelected({ type: 'finding', value })} />}

      </div>
      {selected !== null && <DetailPanel selected={selected} auditEvents={operationAuditEvents} canApprove={isAdmin} canResolve={canResolve} currentActor={auth.email}
        connectionName={connectionName} connectionEngine={connectionEngine}
        connectionEnvironment={connectionEnvironment}
        principalNames={principalNames} accountsById={selectedAccounts} permissionsById={selectedPermissions}
        resolvePending={resolveMutation.isPending} resolveError={resolveMutation.error}
        retryPending={retryMutation.isPending} retryError={retryMutation.error}
        canRetryRootOperation={isAdmin}
        onRetry={(operation) => retryMutation.mutate(operation)}
        onResolve={(operation) => resolveMutation.mutate(operation)}
        onClose={() => { setSelected(null); patchSearch({ operation: undefined }) }} onDecision={(value) => setDecision(value)} />}
      <ApprovalDecisionDialog operation={selected?.type === 'operation' ? selected.value : null} decision={decision}
        currentActor={auth.email} onClose={() => setDecision(null)} onDone={() => { setDecision(null); setSelected(null) }} />
      </div>
    </div>
  )
}

// Инбокс: только то, что ждёт решения человека. Несоответствия сюда не
// попадают — у них своя вкладка, и дублирование делало счётчики
// несопоставимыми.
function AttentionFeed({ approvals, operations, connectionName, onSelect, canApprove, canResolve, currentActor }: {
  approvals: Operation[]; operations: Operation[]; connectionName: (id: string | null) => string;
  onSelect: (item: Selected) => void; canApprove: boolean; canResolve: boolean; currentActor: string
}) {
  return <AttentionInbox approvals={approvals} operations={operations} connectionName={connectionName}
    onSelect={(value) => onSelect({ type: 'operation', value })}
    canApprove={canApprove} canResolve={canResolve} currentActor={currentActor} />
}

// action — навигация в обход панели (например, deep-link находки). Живёт
// сиблингом кнопки строки, а не внутри неё: интерактив внутри интерактива
// невалиден и ломает клавиатуру.
function ControlRow({ title, subtitle, leading, trailing, action, onClick }: { title: string; subtitle: ReactNode; leading?: ReactNode; trailing: ReactNode; action?: ReactNode; onClick: () => void }) {
  const row = <button type="button" onClick={onClick} className="flex w-full min-w-0 items-center gap-3 px-4 py-3 text-left hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-accent">
    {leading}
    <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium text-text">{title}</span><span className="mt-0.5 block truncate text-xs text-muted">{subtitle}</span></span>{trailing}
  </button>
  if (action === undefined) return row
  return <div className="flex items-center">
    <div className="min-w-0 flex-1">{row}</div>
    <div className="shrink-0 pr-3">{action}</div>
  </div>
}

/**
 * Baseline находки: принять как ожидаемое (с причиной) либо вернуть в
 * активный дрифт. Целевые системы не меняются — решение живёт в metadata,
 * попадает в audit и обратимо.
 */
function FindingBaselineActions({ finding, canResolve, onDone }: { finding: DriftFinding; canResolve: boolean; onDone: () => void }) {
  const queryClient = useQueryClient()
  const [reason, setReason] = useState('')
  const settle = async () => {
    await queryClient.invalidateQueries({ queryKey: qk.drift() })
    onDone()
  }
  const accept = useMutation({
    mutationFn: () => apiPost('/api/v1/drift/baselines', {
      kind: finding.kind,
      ref_id: findingBaselineRef(finding),
      connection_id: finding.connection_id,
      reason: reason.trim(),
    }),
    onSuccess: settle,
  })
  const remove = useMutation({
    mutationFn: () => api(`/api/v1/drift/baselines/${finding.baseline_id}`, { method: 'DELETE' }),
    onSuccess: settle,
  })

  if (finding.baseline_id !== undefined) {
    return <Card className="mt-5 space-y-2 p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">Принято как ожидаемое</div>
      {finding.reason !== undefined && finding.reason !== '' && (
        <div className="text-sm text-text">{finding.reason}</div>
      )}
      <div className="text-xs text-muted">Принял: {finding.created_by ?? '—'}</div>
      {remove.isError && <p role="alert" className="text-sm text-danger">{errorMessage(remove.error)}</p>}
      {canResolve && <div className="flex justify-end">
        <Button size="sm" variant="outline" disabled={remove.isPending} onClick={() => remove.mutate()}>
          {remove.isPending ? 'Возвращаем…' : 'Вернуть в дрифт'}
        </Button>
      </div>}
    </Card>
  }
  if (!canResolve || findingBaselineRef(finding) === null) return null
  return <Card className="mt-5 space-y-2 p-3">
    <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">Принять как ожидаемое</div>
    <p className="text-xs text-muted">
      Находка уйдёт из активного дрифта в список Baseline, оставаясь видимой и
      обратимой. Целевая система не меняется.
    </p>
    <Input
      value={reason}
      onChange={(event) => setReason(event.target.value)}
      placeholder="Причина (например: заведено до grantor)"
      aria-label="Причина принятия"
    />
    {accept.isError && <p role="alert" className="text-sm text-danger">{errorMessage(accept.error)}</p>}
    <div className="flex justify-end">
      <Button size="sm" variant="outline" disabled={accept.isPending} onClick={() => accept.mutate()}>
        {accept.isPending ? 'Сохраняем…' : 'Принять как ожидаемое'}
      </Button>
    </div>
  </Card>
}

/** Стрелка-переход из находки к её аккаунту/ресурсу на карточке подключения. */
function FindingLink({ finding }: { finding: DriftFinding }) {
  const target = findingLinkTarget(finding)
  return (
    <Link
      to="/connections/$connectionId"
      params={{ connectionId: target.connectionId }}
      search={target.search}
      aria-label="Открыть в подключении"
      title="Открыть в подключении"
      className="flex size-8 items-center justify-center rounded-md border border-transparent text-muted hover:bg-panel2 hover:text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
    >
      <ArrowUpRight className="size-4" aria-hidden="true" />
    </Link>
  )
}

const DOMAIN_ICONS = {
  access: KeyRound,
  account: UserCog,
  binding: KeyRound,
  connection: Plug,
  operation: SlidersHorizontal,
  principal: User,
  security: ShieldAlert,
  other: ScrollText,
} as const

const DOMAIN_TONES: Record<string, string> = {
  security: 'text-danger',
  access: 'text-accent',
  principal: 'text-accent',
}

/** Иконка домена события: тип строки виден до чтения текста. */
function DomainIcon({ action }: { action: string }) {
  const domain = auditDomain(action)
  const Icon = DOMAIN_ICONS[domain]
  return <span className={`flex size-7 shrink-0 items-center justify-center rounded-md bg-panel2 ${DOMAIN_TONES[domain] ?? 'text-faint'}`}>
    <Icon aria-hidden={true} className="size-3.5" />
  </span>
}

/** Актор с пометкой процесса: система и человек отвечают за разное. */
function ActorLabel({ actorType, actorId }: { actorType: string; actorId: string }) {
  if (!isServiceActor(actorType)) return <>{actorId}</>
  return <span className="inline-flex items-center gap-1">
    <Bot aria-hidden={true} className="inline size-3" />
    {actorId}
  </span>
}


/** Подзаголовок строки: значимые части через · и время с точным значением в подсказке. */
function RowMeta({ parts, timestamp }: { parts: Array<ReactNode>; timestamp: string | null }) {
  const visible = parts.filter((part) => part !== null && part !== undefined && part !== '' && part !== '—')
  return <>
    {visible.map((part, index) => <Fragment key={index}>{index > 0 && ' · '}{part}</Fragment>)}
    {timestamp !== null && <>
      {visible.length > 0 && ' · '}
      <time dateTime={timestamp} title={formatDateTime(timestamp)}>{formatRelative(timestamp)}</time>
    </>}
  </>
}

/**
 * Единая лента: операции и события вне операций в одной хронологии,
 * сгруппированные по дням. Тип строки видно по значку и трейлингу — статус у
 * операции, результат у события.
 */
function JournalList({ rows, connectionName, principalNames, accountsById, onSelectOperation, onSelectEvent }: { rows: JournalRow[]; connectionName: (id: string | null) => string; principalNames: ReadonlyMap<string, string>; accountsById: ReadonlyMap<string, Account>; onSelectOperation: (item: Operation) => void; onSelectEvent: (item: AuditEvent) => void }) {
  if (rows.length === 0) return <EmptyState icon={ScrollText} title="Записей не найдено" />
  return <div className="space-y-4">{groupByDay(rows, (row) => row.at).map((group) => <section key={group.label}>
    <h3 className="mb-1.5 px-1 text-[11px] font-semibold uppercase tracking-wider text-faint">{group.label}</h3>
    <Card className="divide-y divide-line overflow-hidden">{group.items.map((row) => row.type === 'operation'
      ? <OperationRow key={row.id} item={row.operation} connectionName={connectionName} onSelect={onSelectOperation} />
      : <ControlRow key={row.id}
        leading={<DomainIcon action={row.event.action} />}
        title={auditActionLabel(row.event.action)}
        subtitle={<RowMeta parts={[auditSubject(row.event, connectionName, principalNames, accountsById), <ActorLabel key="actor" actorType={row.event.actor_type} actorId={row.event.actor_id} />]} timestamp={row.event.occurred_at} />}
        trailing={<StatusChip tone={auditResultTone(row.event.result)}>{auditResultLabel(row.event.result)}</StatusChip>}
        onClick={() => onSelectEvent(row.event)} />)}</Card>
  </section>)}</div>
}

function OperationRow({ item, connectionName, onSelect }: { item: Operation; connectionName: (id: string | null) => string; onSelect: (item: Operation) => void }) {
  const status = effectiveOperationStatus(item)
  return <ControlRow leading={<DomainIcon action={item.kind} />} title={operationDisplayLabel(item)} subtitle={<RowMeta parts={[connectionName(operationEffectiveConnectionId(item)), <ActorLabel key="actor" actorType={item.actor_type} actorId={item.actor_id} />]} timestamp={item.finished_at ?? item.created_at} />} trailing={<span className="flex items-center gap-2">{item.resolved_at != null && <StatusChip tone="unmg">Resolved</StatusChip>}<StatusChip tone={operationStatusTone(status)}>{operationStatusLabel(status)}</StatusChip></span>} onClick={() => onSelect(item)} />
}

function FindingList({ items, connectionName, onSelect }: { items: DriftFinding[]; connectionName: (id: string | null) => string; onSelect: (item: DriftFinding) => void }) {
  if (items.length === 0) return <EmptyState title="Несоответствий не найдено" />
  return <Card className="divide-y divide-line overflow-hidden">
    <FindingGroups items={items} connectionName={connectionName} onSelect={onSelect} />
  </Card>
}

/**
 * Строки находок со схлопыванием одинаковых: сто «внешних грантов» одного
 * подключения — одна раскрываемая строка с счётчиком, а не сто. Одиночная
 * находка рендерится плоской строкой без лишнего клика.
 */
function FindingGroups({ items, connectionName, onSelect }: { items: DriftFinding[]; connectionName: (id: string | null) => string; onSelect: (item: DriftFinding) => void }) {
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set())
  const groups = groupFindings(items)
  const findingRow = (item: DriftFinding, key: string, nested: boolean) => (
    <ControlRow
      key={key}
      title={nested
        ? [item.account_identity, item.resource_name].filter(Boolean).join(' · ') || item.detail || driftKindLabel(item.kind)
        : item.detail || driftKindLabel(item.kind)}
      subtitle={nested
        ? item.detail || driftKindLabel(item.kind)
        : [connectionName(item.connection_id), item.account_identity, item.resource_name].filter(Boolean).join(' · ')}
      trailing={nested ? <span /> : <StatusChip tone={driftKindTone(item.kind)}>{UI_COPY.drift}</StatusChip>}
      action={<FindingLink finding={item} />}
      onClick={() => onSelect(item)}
    />
  )
  return <>{groups.map((group) => {
    const key = `${group.kind}-${group.connectionId}`
    if (group.items.length === 1) return findingRow(group.items[0], key, false)
    const open = expanded.has(key)
    return <Fragment key={key}>
      <ControlRow
        leading={<ChevronRight aria-hidden="true" className={cn('size-4 shrink-0 text-faint', open && 'rotate-90')} />}
        title={`${driftKindLabel(group.kind)}: ${connectionName(group.connectionId)}`}
        subtitle={open ? 'Скрыть список' : 'Показать список'}
        trailing={<StatusChip tone={driftKindTone(group.kind)}>{group.items.length} · {UI_COPY.drift}</StatusChip>}
        onClick={() => setExpanded((current) => {
          const next = new Set(current)
          if (next.has(key)) next.delete(key)
          else next.add(key)
          return next
        })}
      />
      {open && <div className="divide-y divide-line/60 border-t border-line/60 bg-panel2/30 pl-6">
        {group.items.map((item, index) => findingRow(item, `${key}-${index}`, true))}
      </div>}
    </Fragment>
  })}</>
}

type AuditMetadata = Record<string, unknown>

function auditMetadata(value: unknown): AuditMetadata {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {}
  return value as AuditMetadata
}

function metadataText(metadata: AuditMetadata, key: string): string | null {
  const value = metadata[key]
  return typeof value === 'string' && value.trim() !== '' ? value : null
}

/**
 * Показывает только безопасный фактический контекст, уже присутствующий в
 * auditEventJSON и metadata конкретного события. Поля разных action не
 * синтезируются: если producer их не записал, строка не появляется.
 */
export function AuditAccessContext({ event }: { event: AuditEvent }) {
  const metadata = auditMetadata(event.metadata)
  const account = metadataText(metadata, 'account') ?? metadataText(metadata, 'engine_identity') ?? event.account_id
  const role = metadataText(metadata, 'permission') ?? metadataText(metadata, 'role')
  const requesterID = metadataText(metadata, 'requester_actor_id')
  const requesterType = metadataText(metadata, 'requester_actor_type')
  const reason = metadataText(metadata, 'reason')
  const directory = metadataText(metadata, 'provider')
  const directoryStatus = metadataText(metadata, 'status')
  const previousStatus = metadataText(metadata, 'previous_status')
  const subject = metadataText(metadata, 'subject')
  const selfApproved =
    typeof metadata.self_approved === 'boolean' ? metadata.self_approved : null
  const entries: Array<[string, string, boolean?]> = []

  if (account !== null) entries.push(['Аккаунт', account, true])
  if (role !== null) entries.push(['Роль / доступ', role, true])
  if (requesterID !== null) {
    entries.push([
      'Запросил',
      requesterType === null ? requesterID : `${requesterType}: ${requesterID}`,
      true,
    ])
  }
  if (event.action === 'operation.approved') {
    entries.push(['Подтвердил', `${event.actor_type}: ${event.actor_id}`, true])
  } else if (event.action === 'operation.rejected') {
    entries.push(['Отклонил', `${event.actor_type}: ${event.actor_id}`, true])
  }
  if (selfApproved !== null) entries.push(['Самоподтверждение', selfApproved ? 'Да' : 'Нет'])
  if (directory !== null) entries.push(['Каталог', directory])
  if (subject !== null) entries.push(['Субъект каталога', subject, true])
  if (directoryStatus !== null) {
    entries.push(['Статус', externalIdentityStatusLabel(directoryStatus)])
  }
  if (previousStatus !== null) {
    entries.push(['Было', externalIdentityStatusLabel(previousStatus)])
  }
  // reason дублирует статус у событий каталога — там он и есть новый статус.
  if (reason !== null && reason !== directoryStatus) entries.push(['Причина', reason])
  if (event.operation_id !== null) entries.push(['Изменение', event.operation_id, true])
  const bindingID = metadataText(metadata, 'binding_id')
  if (bindingID !== null) entries.push(['Binding', bindingID, true])
  const adoptMode = metadataText(metadata, 'mode')
  if (adoptMode !== null) {
    entries.push(['Режим управления', accountAdoptModeLabel(adoptMode)])
  }
  if (typeof metadata.adopted_bindings === 'number') {
    entries.push(['Принято доступов', String(metadata.adopted_bindings)])
  }

  return <Card className="mt-5 p-3">
    <h3 className="text-xs font-semibold text-faint">Контекст изменения</h3>
    <dl className="mt-3 space-y-2">
      {entries.map(([label, value, mono]) => <div key={label} className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
        <dt className="text-muted">{label}</dt>
        <dd className={`min-w-0 break-words text-right text-text ${mono === true ? 'font-mono text-xs' : ''}`}>{value}</dd>
      </div>)}
      <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
        <dt className="text-muted">Событие</dt>
        <dd className="text-right font-mono text-xs text-text">#{event.id}</dd>
      </div>
    </dl>
  </Card>
}

interface OperationContextProps {
  operation: Operation
  auditEvents: readonly AuditEvent[]
  principalNames?: ReadonlyMap<string, string>
  accountsById?: ReadonlyMap<string, Account>
  permissionsById?: ReadonlyMap<string, Permission>
}

function BulkRoleContext({
  operation,
  accountsById,
  permissionsById,
}: {
  operation: Operation
  accountsById: ReadonlyMap<string, Account>
  permissionsById: ReadonlyMap<string, Permission>
}) {
  const children = operation.children ?? []
  if (
    (operation.kind !== 'bulk.grant' && operation.kind !== 'bulk.account_roles') ||
    children.length === 0
  ) return null
  const managesRoles = operation.kind === 'bulk.account_roles'

  return <Card className="mt-5 overflow-hidden">
    <div className="border-b border-line/50 px-3 py-2.5">
      <h3 className="text-xs font-semibold text-faint">
        {managesRoles ? 'Изменения ролей' : 'Назначения'}
      </h3>
      <p className="mt-1 text-xs text-muted">
        {children.length} {children.length === 1 ? 'роль' : children.length < 5 ? 'роли' : 'ролей'}
      </p>
    </div>
    <div className="divide-y divide-line/35">
      {children.map((child) => {
        const account = child.account_id === null ? undefined : accountsById.get(child.account_id)
        const binding = account?.bindings?.find((item) => item.id === child.binding_id)
        const permission = binding === undefined
          ? undefined
          : permissionsById.get(binding.permission_definition_id)
        return <div
          key={child.id}
          className="grid grid-cols-1 gap-2 px-3 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-3"
        >
          <div className="min-w-0">
            <div className="whitespace-normal font-mono text-xs text-text [overflow-wrap:anywhere]">
              {permission?.name ?? (binding?.permission_definition_id ?? 'Роль загружается…')}
            </div>
            <div className="mt-0.5 whitespace-normal text-xs text-muted [overflow-wrap:anywhere]">
              {managesRoles && (
                <span className="mr-2 text-text">
                  {child.kind === 'access.revoke' || child.kind === 'postgres.stats_membership.revoke.v1' ? 'Снять' : 'Назначить'}
                </span>
              )}
              Аккаунт: <span className="font-mono">{account?.engine_identity ?? child.account_id ?? '—'}</span>
            </div>
          </div>
          <StatusChip
            tone={operationStatusTone(child.status)}
            className="justify-self-start sm:justify-self-end"
          >
            {operationStatusLabel(child.status)}
          </StatusChip>
        </div>
      })}
    </div>
  </Card>
}

export function OperationContext({
  operation,
  auditEvents,
  principalNames = new Map(),
  accountsById = new Map(),
  permissionsById = new Map(),
}: OperationContextProps) {
  const adopt = accountAdoptContext(operation, auditEvents)
  const managedLink = accountManagedLinkContext(operation, auditEvents, principalNames)
  const bulkRoles = <BulkRoleContext
    operation={operation}
    accountsById={accountsById}
    permissionsById={permissionsById}
  />
  if (operation.kind === 'bulk.grant' || operation.kind === 'bulk.account_roles') {
    return bulkRoles
  }
  if (adopt === null && managedLink === null) {
    return <Card className="mt-5 p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">Источник</div>
      <div className="mt-1 text-sm text-text">{operation.actor_type}: {operation.actor_id}</div>
    </Card>
  }

  return <Card className="mt-5 p-3">
    <h3 className="text-xs font-semibold text-faint">Параметры операции</h3>
    <dl className="mt-3 space-y-2">
      <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
        <dt className="text-muted">Аккаунт</dt>
        <dd className="min-w-0 break-words text-right font-mono text-xs text-text">{adopt?.account ?? managedLink?.account}</dd>
      </div>
      {adopt !== null && <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
        <dt className="text-muted">Режим</dt>
        <dd className="text-right text-text">{adopt.mode}</dd>
      </div>}
      {adopt?.adoptedBindings !== null && adopt?.adoptedBindings !== undefined && <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
        <dt className="text-muted">Принято доступов</dt>
        <dd className="text-right text-text">{adopt.adoptedBindings}</dd>
      </div>}
      {managedLink !== null && <>
        <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
          <dt className="text-muted">Пользователь</dt>
          <dd className="min-w-0 break-words text-right font-mono text-xs text-text">{managedLink.principal}</dd>
        </div>
        {managedLink.environment !== null && <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
          <dt className="text-muted">Окружение</dt>
          <dd className="text-right text-text">{managedLink.environment}</dd>
        </div>}
        {managedLink.credentialSource !== null && <div className="grid grid-cols-[7.5rem_minmax(0,1fr)] gap-3 text-sm">
          <dt className="text-muted">Credential</dt>
          <dd className="text-right text-text">{managedLink.credentialSource === 'existing' ? 'Общий существующий' : managedLink.credentialSource === 'generated' ? 'Сгенерирован' : 'Задан оператором'}</dd>
        </div>}
      </>}
    </dl>
  </Card>
}

function DetailPanel({ selected, auditEvents, canApprove, canResolve,
  canRetryRootOperation, currentActor, connectionName, connectionEngine,
  connectionEnvironment, principalNames, accountsById, permissionsById,
  resolvePending, resolveError, retryPending, retryError, onResolve, onRetry,
  onClose, onDecision }: {
  selected: Selected
  auditEvents: readonly AuditEvent[]
  canApprove: boolean
  canResolve: boolean
  canRetryRootOperation: boolean
  currentActor: string
  connectionName: (id: string | null) => string
  connectionEngine: (id: string | null) => string
  connectionEnvironment: (id: string | null) => string
  principalNames: ReadonlyMap<string, string>
  accountsById: ReadonlyMap<string, Account>
  permissionsById: ReadonlyMap<string, Permission>
  resolvePending: boolean
  resolveError: Error | null
  retryPending: boolean
  retryError: Error | null
  onResolve: (operation: Operation) => void
  onRetry: (operation: Operation) => void
  onClose: () => void
  onDecision: (decision: 'approve' | 'reject') => void
}) {
  const isOperation = selected.type === 'operation'
  const title = isOperation ? operationDisplayLabel(selected.value) : selected.type === 'finding' ? selected.value.detail || driftKindLabel(selected.value.kind) : auditActionLabel(selected.value.action)
  // Техническое имя события нужно для поиска по логам, но заголовком оно
  // нечитаемо и рвётся переносом посреди слова.
  const subtitle = selected.type === 'audit' ? selected.value.action : isOperation ? selected.value.kind : null
  const connectionId = isOperation
    ? operationEffectiveConnectionId(selected.value)
    : selected.value.connection_id
  const operationErrors = isOperation ? operationFailureMessages(selected.value) : []
  return <SidePanel onClose={onClose} title={title}>
    {subtitle !== null && <p className="mb-4 break-all font-mono text-xs text-faint">{subtitle}</p>}
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
      {connectionId !== null && <><dt className="text-muted">Окружение</dt><dd className="text-right text-text">{connectionEnvironment(connectionId)}</dd>
      <dt className="text-muted">Подключение</dt><dd className="text-right text-text">{connectionName(connectionId)}</dd>
      <dt className="text-muted">Движок</dt><dd className="text-right text-text">{connectionEngine(connectionId)}</dd></>}
      {selected.type === 'operation' && <><dt className="text-muted">Статус</dt><dd className="text-right">{operationStatusLabel(effectiveOperationStatus(selected.value))}</dd><dt className="text-muted">Запросил</dt><dd className="break-all text-right">{selected.value.actor_id}</dd><dt className="text-muted">Создано</dt><dd className="text-right">{formatDateTime(selected.value.created_at)}</dd>{selected.value.finished_at !== null && <><dt className="text-muted">Завершено</dt><dd className="text-right">{formatDateTime(selected.value.finished_at)}</dd></>}{selected.value.resolved_at != null && <><dt className="text-muted">Resolved</dt><dd className="text-right">{formatDateTime(selected.value.resolved_at)}</dd><dt className="text-muted">Resolved by</dt><dd className="break-all text-right">{selected.value.resolved_by ?? '—'}</dd></>}{operationErrors.map((message, index) => <Fragment key={`${message}-${index}`}><dt className="text-muted">{index === 0 ? 'Ошибка' : 'Причина'}</dt><dd className="break-words text-right text-danger">{message}</dd></Fragment>)}</>}
      {selected.type === 'finding' && <><dt className="text-muted">Тип</dt><dd className="text-right">{driftKindLabel(selected.value.kind)}</dd></>}
      {selected.type === 'audit' && <><dt className="text-muted">Результат</dt><dd className="text-right">{auditResultLabel(selected.value.result)}</dd><dt className="text-muted">Исполнитель</dt><dd className="break-all text-right">{selected.value.actor_id}</dd><dt className="text-muted">Время</dt><dd className="text-right">{formatDateTime(selected.value.occurred_at)}</dd></>}
    </dl>
    {selected.type === 'audit' ? <AuditAccessContext event={selected.value} /> : selected.type === 'operation' ? <><OperationTimeline operation={selected.value} /><OperationContext operation={selected.value} auditEvents={auditEvents} principalNames={principalNames} accountsById={accountsById} permissionsById={permissionsById} /></> : <>
      <Card className="mt-5 p-3">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-faint">Источник</div>
        <div className="mt-1 text-sm text-text">{driftKindLabel(selected.value.kind)}</div>
        {/* Техническое имя вида — для поиска по коду и логам. */}
        <div className="mt-0.5 font-mono text-xs text-faint">{selected.value.kind}</div>
      </Card>
      <FindingBaselineActions finding={selected.value} canResolve={canResolve} onDone={onClose} />
      <div className="mt-5 flex justify-end">
        <Link
          to="/connections/$connectionId"
          params={{ connectionId: findingLinkTarget(selected.value).connectionId }}
          search={findingLinkTarget(selected.value).search}
          className="inline-flex h-8 items-center gap-1.5 rounded-md border border-line px-3 text-sm text-text hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          {selected.value.account_id ? 'Открыть аккаунт' : selected.value.resource_id ? 'Открыть ресурс' : 'Открыть подключение'}
          <ArrowUpRight className="size-3.5" aria-hidden="true" />
        </Link>
      </div>
    </>}
    {isOperation && selected.value.status === 'pending_approval' && canApprove && <div className="mt-5 flex flex-wrap justify-end gap-2"><Button variant="danger" size="sm" onClick={() => onDecision('reject')}>Отклонить</Button><Button size="sm" onClick={() => onDecision('approve')}>{selected.value.actor_id === currentActor ? 'Подтвердить свой запрос' : 'Подтвердить и выполнить'}</Button></div>}
    {isOperation && (selected.value.kind === 'resource.create.database_with_roles' ||
      selected.value.kind === 'postgres.resource.create.database_with_roles.v2') &&
      selected.value.database_provisioning != null && <DatabaseProvisioningContext operation={selected.value} />}
    {isOperation && canRetryRootOperation &&
      (isRetryableAdminCredentialOperation(selected.value) || isRetryableDatabaseProvisioningOperation(selected.value)) && (
      <div className="mt-5 space-y-2">
        {retryError !== null && (
          <p role="alert" className="text-sm text-danger">{errorMessage(retryError)}</p>
        )}
        <div className="flex justify-end">
          <Button size="sm" onClick={() => onRetry(selected.value)} disabled={retryPending}>
            {retryPending ? 'Ставим в очередь…' : isRetryableDatabaseProvisioningOperation(selected.value)
              ? 'Продолжить создание' : 'Повторить credential operation'}
          </Button>
        </div>
      </div>
    )}
    {isOperation && isUnresolvedOperationFailure(selected.value) && canResolve && <div className="mt-5 space-y-2">{resolveError !== null && <p role="alert" className="text-sm text-danger">{errorMessage(resolveError)}</p>}<div className="flex justify-end"><Button size="sm" onClick={() => onResolve(selected.value)} disabled={resolvePending}>{resolvePending ? 'Сохраняем…' : 'Отметить решённой'}</Button></div></div>}
  </SidePanel>
}

const DATABASE_PROVISIONING_PHASES: Record<string, string> = {
  pending: 'Ожидает запуска',
  database_creating: 'Создание базы',
  database_created: 'База создана, подготовка ролей',
  catalog_prepared: 'Пара ролей подготовлена',
  read_created: 'Роль чтения создана',
  complete: 'База и обе роли готовы',
}

function DatabaseProvisioningContext({ operation }: { operation: Operation }) {
  const progress = operation.database_provisioning
  if (progress == null) return null
  const steps = [
    { name: progress.database_name, label: 'База', done: progress.database_created },
    { name: progress.read_role, label: 'Чтение', done: progress.read_created },
    { name: progress.read_write_role, label: 'Чтение и запись', done: progress.read_write_created },
  ]
  return (
    <section className="mt-5 space-y-3" aria-label="Создание базы и ролей">
      <h3 className="text-sm font-semibold text-text">Создание базы и ролей</h3>
      <p className="text-xs text-muted">{DATABASE_PROVISIONING_PHASES[progress.phase] ?? progress.phase}</p>
      <ul className="divide-y divide-line border-y border-line">
        {steps.map((step) => (
          <li key={step.label} className="flex flex-wrap justify-between gap-2 py-2 text-xs">
            <span className="min-w-0 text-muted">{step.label}: <span className="break-all font-mono text-text">{step.name}</span></span>
            <span className={step.done ? 'text-ok' : 'text-muted'}>{step.done ? 'Создано' : 'Не завершено'}</span>
          </li>
        ))}
      </ul>
      {progress.error_code && <p className="break-words text-xs text-danger">Код ошибки: {progress.error_code}</p>}
      {(operation.status === 'failed' || operation.status === 'partial') && (
        <p className="text-xs leading-relaxed text-muted">
          Уже созданные объекты сохраняются. Продолжение запускается для всей операции; роли пользователям не назначаются.
        </p>
      )}
    </section>
  )
}

export function ApprovalDecisionDialog({ operation, decision, currentActor, onClose, onDone }: { operation: Operation | null; decision: 'approve' | 'reject' | null; currentActor: string; onClose: () => void; onDone: () => void }) {
  const queryClient = useQueryClient()
  const mutation = useMutation({
    mutationFn: () => api(`/api/v1/operations/${operation?.id}/${decision}`, { method: 'POST' }),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: qk.approvals() }); void queryClient.invalidateQueries({ queryKey: qk.operations() }); void queryClient.invalidateQueries({ queryKey: ['audit'] }); onDone() },
  })
  if (operation === null || decision === null) return null
  const approve = decision === 'approve'
  const self = approve && operation.actor_id === currentActor
  return <Dialog open onClose={onClose} title={approve ? 'Подтвердить операцию' : 'Отклонить операцию'} description="Финальное подтверждение решения">
    <p className="text-sm text-muted">{self ? 'Это ваш собственный запрос. Подтвердите ещё раз: после решения операция будет поставлена на выполнение, а действие попадёт в аудит.' : approve ? 'После подтверждения операция будет поставлена на выполнение, а решение попадёт в аудит.' : 'Операция не будет выполнена, а решение попадёт в аудит.'}</p>
    <p className="mt-3 text-sm text-text">{operationDisplayLabel(operation)} <span className="font-mono text-xs text-muted">· {operation.id}</span></p>
    {mutation.isError && <p role="alert" className="mt-3 text-sm text-danger">{errorMessage(mutation.error)}</p>}
    <div className="mt-5 flex justify-end gap-2"><Button variant="outline" onClick={onClose} disabled={mutation.isPending}>Отмена</Button><Button variant={approve ? 'primary' : 'danger'} onClick={() => mutation.mutate()} disabled={mutation.isPending}>{mutation.isPending ? 'Сохраняем…' : approve ? 'Подтвердить и выполнить' : 'Отклонить'}</Button></div>
  </Dialog>
}
