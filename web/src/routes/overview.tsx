import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import {
  ArrowRight,
  CheckCircle2,
  Globe2,
  LayoutDashboard,
  ListChecks,
  Plus,
  TriangleAlert,
} from '@project/ui/icons'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { StatusChip } from '../components/ui/badge'
import { Button, buttonClassName, Card, PageSurfaceHeader, StatTile, Spinner, Tooltip } from '@project/ui'
import { apiList, apiListPage } from '../lib/api'
import {
  connectionNeedsAttention,
} from '../lib/connection-presentation'
import { POLL_OVERVIEW_MS } from '../lib/intervals'
import { localDayRange } from '../lib/operation-time'
import { qk } from '../lib/queryKeys'
import { operationStatusTone } from '../lib/status'
import { formatDateTime, formatRelative } from '../lib/time'
import type { Connection, Operation } from '../lib/types'
import { UI_COPY } from '../lib/ui-copy'
import {
  isRecentActivityOperation,
  operationLabel,
  operationStatusLabel,
  RECENT_ACTIVITY_KINDS,
} from '../lib/operation-presentation'
import { AddConnectionDrawer, ConnectionDirectory } from './connections'
import { EnvironmentCreateDialog } from './environment-create-dialog'

const RECENT_LIMIT = 5

interface OverviewHealthStripProps {
  attention: number
  pendingApproval: number
  errors: number
  pending?: boolean
  error?: boolean
  onRetry?: () => void
}

/** Compact overview status: the detailed healthy explanation stays in a tooltip. */
export function OverviewHealthStrip({
  attention,
  pendingApproval,
  errors,
  pending = false,
  error = false,
  onRetry,
}: OverviewHealthStripProps) {
  if (error) {
    return (
      <div role="alert" className="flex flex-wrap items-center gap-2 text-xs text-danger">
        <TriangleAlert className="size-4 shrink-0" aria-hidden="true" />
        <span>Не удалось проверить состояние</span>
        {onRetry && <Button variant="outline" size="sm" onClick={onRetry}>Повторить проверку</Button>}
      </div>
    )
  }
  if (pending) {
    return <div role="status" className="flex items-center gap-2 text-xs text-muted"><Spinner />Проверка состояния…</div>
  }
  const needsAttention = attention > 0 || pendingApproval > 0 || errors > 0
  const detail = `${
    attention > 0
      ? `${attention} подключений требуют внимания.`
      : 'Проблемных подключений нет.'
  } ${
    pendingApproval > 0
      ? `${pendingApproval} операций ждут подтверждения.`
      : 'Ожидающих подтверждения операций нет.'
  } ${errors > 0 ? `${errors} операций завершились с ошибкой.` : 'Ошибок операций нет.'}`

  if (!needsAttention) {
    return (
      <Tooltip content={detail} disabledTarget targetLabel="Подробнее о состоянии">
        <StatusChip tone="ok">{UI_COPY.healthy}</StatusChip>
      </Tooltip>
    )
  }

  return (
    <div
      className="flex min-h-9 items-center gap-2.5 rounded-lg border border-warn/35 bg-panel2/35 px-3 py-2 shadow-[var(--highlight-inset)]"
    >
      <TriangleAlert className="size-4 shrink-0 text-warn" aria-hidden="true" />
      <span className="min-w-0 flex-1 text-xs font-medium">
        {`Требуются действия: ${attention} подключений · ${pendingApproval} подтверждений · ${errors} ошибок`}
      </span>
      <Link
        to="/control"
        search={{ tab: 'attention' }}
        className={buttonClassName('outline', 'sm')}
      >
        Открыть контроль
        <ArrowRight className="size-3.5" aria-hidden="true" />
      </Link>
    </div>
  )
}

export function recentOperatorOperations<T extends Pick<Operation, 'actor_type' | 'kind' | 'parent_id'>>(
  operations: readonly T[],
): T[] {
  return operations.filter(isRecentActivityOperation)
}

const recentActivityParams = new URLSearchParams({
  actor_type: 'user',
  kind: RECENT_ACTIVITY_KINDS.join(','),
  top_level_only: 'true',
  limit: String(RECENT_LIMIT),
})

export function OverviewPage() {
  const auth = useAuth()
  const [addOpen, setAddOpen] = useState(false)
  const [addEnvironmentOpen, setAddEnvironmentOpen] = useState(false)
  const today = localDayRange()
  const connectionsQuery = useQuery({
    queryKey: qk.connections(),
    queryFn: ({ signal }) =>
      apiList<Connection>('/api/v1/connections', 'connections', signal),
    refetchInterval: POLL_OVERVIEW_MS,
  })
  const operationsQuery = useQuery({
    queryKey: qk.operationsRecent(),
    queryFn: ({ signal }) =>
      apiList<Operation>(`/api/v1/operations?${recentActivityParams}`, 'operations', signal),
    refetchInterval: POLL_OVERVIEW_MS,
  })
  const pendingApprovalQuery = useQuery({
    queryKey: qk.operationsPendingApproval(),
    queryFn: ({ signal }) =>
      apiListPage<Operation>(
        '/api/v1/operations?status=pending_approval&limit=1',
        'operations',
        signal,
      ),
    refetchInterval: POLL_OVERVIEW_MS,
  })
  const operationErrorsQuery = useQuery({
    queryKey: qk.operationsErrorCount(),
    queryFn: ({ signal }) =>
      apiListPage<Operation>(
        '/api/v1/operations?status=failed,partial,cancelled&top_level_only=true&unresolved_only=true&limit=1',
        'operations',
        signal,
      ),
    refetchInterval: POLL_OVERVIEW_MS,
  })
  const todayOperationsQuery = useQuery({
    queryKey: qk.operationsToday('user', today.createdFrom, today.createdBefore),
    queryFn: ({ signal }) =>
      apiListPage<Operation>(
        `/api/v1/operations?${new URLSearchParams({
          limit: '1',
          // Как у «Последних действий»: системные операции (rediscovery,
          // maintenance) не считаются — метрика про работу людей.
          actor_type: 'user',
          created_from: today.createdFrom,
          created_before: today.createdBefore,
        }).toString()}`,
        'operations',
        signal,
      ),
    refetchInterval: POLL_OVERVIEW_MS,
  })

  const connections = connectionsQuery.data ?? []
  const operations = operationsQuery.data ?? []
  const operatorOperations = recentOperatorOperations(operations)
  const attention = connections.filter(connectionNeedsAttention).length
  const pendingApproval = pendingApprovalQuery.data?.total ?? 0
  const operationErrors = operationErrorsQuery.data?.total ?? 0
  const healthQueries = [connectionsQuery, pendingApprovalQuery, operationErrorsQuery]
  const healthPending = healthQueries.some((query) => query.isPending)
  const healthError = healthQueries.some((query) => query.isError)
  const healthKnown = !healthPending && !healthError
  const retryHealth = () => {
    void Promise.all(healthQueries.map((query) => query.refetch()))
  }
  const canRefresh = roleAtLeast(auth.role, 'operator')
  const canCreate = roleAtLeast(auth.role, 'admin')

  return (
    <div className="mx-auto max-w-6xl">
      <Card className="overflow-hidden">
        <PageSurfaceHeader
          title="Обзор"
          description="Состояние подключений и последние действия"
          icon={<LayoutDashboard className="size-4" aria-hidden="true" />}
          actions={canCreate ? (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setAddEnvironmentOpen(true)}
                title="Окружение можно завести до первого подключения"
              >
                <Globe2 className="size-3.5" aria-hidden="true" />
                Окружение
              </Button>
              <Button onClick={() => setAddOpen(true)}>
                <Plus className="size-4" aria-hidden="true" />
                Добавить подключение
              </Button>
            </div>
          ) : undefined}
        />

        <div className="space-y-4 p-4">
      <OverviewHealthStrip
        attention={attention}
        pendingApproval={pendingApproval}
        errors={operationErrors}
        pending={healthPending}
        error={healthError}
        onRetry={retryHealth}
      />

      <div className="grid gap-3 sm:grid-cols-3">
        <a href="#connections" className="rounded-lg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
          <StatTile
            label="Подключения"
            value={connectionsQuery.isSuccess ? connections.length : null}
            note={connectionsQuery.isError ? 'Не удалось загрузить подключения'
              : connectionsQuery.isPending ? 'Подключения загружаются'
              : connections.length === 0 ? 'Подключений пока нет'
              : attention > 0 ? `${attention} требуют внимания` : 'Все работают штатно'}
            hint="Перейти к списку"
            interactive
          />
        </a>
        <Link to="/control" search={{ tab: 'attention' }} className="rounded-lg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
          <StatTile
            label="Требует внимания"
            value={healthKnown ? attention + pendingApproval + operationErrors : null}
            tone={attention + pendingApproval + operationErrors > 0 ? 'warn' : 'default'}
            note={healthError ? 'Состояние источников неизвестно'
              : healthPending ? 'Проверяем подключения и операции'
              : `${attention} подключений · ${pendingApproval} подтверждений · ${operationErrors} ошибок`}
            hint="Деградации, расхождения и подтверждения"
            interactive
          />
        </Link>
        <Link
          to="/control"
          search={{
            tab: 'operations',
            status: 'all',
            created_from: today.createdFrom,
            created_before: today.createdBefore,
          }}
          className="rounded-lg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        >
          <StatTile
            label="Операций сегодня"
            value={todayOperationsQuery.isSuccess ? todayOperationsQuery.data.total : null}
            note={todayOperationsQuery.isError ? 'Не удалось загрузить число операций'
              : todayOperationsQuery.isPending ? 'Операции загружаются'
              : `Часовой пояс: ${today.timeZone}`}
            hint="Открыть операции за сегодня"
            interactive
          />
        </Link>
      </div>

      <div className="grid min-w-0 gap-3">
        <ConnectionDirectory
          stateKey={auth.email}
          connections={connections}
          pending={connectionsQuery.isPending}
          error={connectionsQuery.isError}
          onRetry={() => void connectionsQuery.refetch()}
          canRefresh={canRefresh}
        />

        <section className="min-w-0 overflow-hidden rounded-[10px] border border-line bg-panel shadow-[var(--highlight-inset)]">
          <div className="flex h-11 items-center gap-2 border-b border-line px-3">
            <ListChecks className="size-4 text-muted" aria-hidden="true" />
            <span className="text-sm font-medium">Последние действия</span>
            <Link to="/control" search={{ tab: 'operations', status: 'all' }} className="grantor-touch-target ml-auto inline-flex items-center text-xs text-muted hover:text-text">Все операции</Link>
          </div>
          {operationsQuery.isError ? (
            <div className="px-3 py-8 text-center text-sm text-danger">Не удалось загрузить операции.</div>
          ) : operationsQuery.isPending ? (
            <div className="flex justify-center py-10"><Spinner /></div>
          ) : operatorOperations.length === 0 ? (
            <div className="px-3 py-8 text-center text-sm text-muted">Действий оператора пока нет.</div>
          ) : (
            <div className="divide-y divide-line/70">
              {operatorOperations.slice(0, RECENT_LIMIT).map((operation) => (
                <Link
                  key={operation.id}
                  to="/control"
                  search={{
                    tab: 'operations',
                    status: 'all',
                    connection: operation.connection_id ?? undefined,
                    query: operation.id,
                  }}
                  className="flex min-h-11 items-center gap-2.5 px-3 py-1.5 transition-colors hover:bg-panel2"
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium">{operationLabel(operation.kind)}</span>
                    <span className="block truncate text-[11px] text-muted" title={formatDateTime(operation.created_at)}>
                      {operation.connection_id === null
                        ? formatRelative(operation.created_at)
                        : `${connections.find((connection) => connection.id === operation.connection_id)?.display_name ?? 'Подключение'} · ${formatRelative(operation.created_at)}`}
                    </span>
                  </span>
                  {operation.status === 'success' ? (
                    <Tooltip content={operationStatusLabel(operation.status)} disabledTarget>
                      <CheckCircle2 className="size-4 shrink-0 text-ok" aria-hidden="true" />
                    </Tooltip>
                  ) : (
                    <StatusChip tone={operationStatusTone(operation.status)}>{operationStatusLabel(operation.status)}</StatusChip>
                  )}
                </Link>
              ))}
            </div>
          )}
        </section>
      </div>
        </div>
      </Card>
      <AddConnectionDrawer
        open={addOpen}
        onClose={() => setAddOpen(false)}
        connections={connections}
      />
      <EnvironmentCreateDialog
        open={addEnvironmentOpen}
        onClose={() => setAddEnvironmentOpen(false)}
      />
    </div>
  )
}
