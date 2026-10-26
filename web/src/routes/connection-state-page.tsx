// «Состояние» является отдельным connection-scoped инструментом: оно не
// конкурирует с каталогами аккаунтов, прав, ресурсов и ролей за место во
// вкладках подключения, но сохраняет тот же manifest/snapshot workflow.
import { useQuery } from '@tanstack/react-query'
import { getRouteApi, Link } from '@tanstack/react-router'
import { ArrowLeft } from '@project/ui/icons'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type { Connection } from '../lib/types'
import { errorMessage } from '../lib/errorMessage'
import { EngineBadge, StatusChip, TagBadge } from '../components/ui/badge'
import { DetailPageSkeleton, ErrorState, CopyableValue } from '@project/ui'
import { connectionStatusTone } from '../lib/status'
import { connectionEnvironmentLabel } from '../lib/connection-presentation'
import { connectionStatusLabel } from '../lib/ui-copy'
import { ConnectionStateTool } from './connection-state-tool'

const routeApi = getRouteApi('/connections/$connectionId/state')

export function ConnectionStatePage() {
  const { connectionId } = routeApi.useParams()
  const connectionQuery = useQuery({
    queryKey: qk.connection(connectionId),
    queryFn: ({ signal }) =>
      api<Connection>(`/api/v1/connections/${connectionId}`, { signal }),
  })

  if (connectionQuery.isError) {
    return (
      <div className="mx-auto max-w-6xl">
        <ErrorState
          message={errorMessage(connectionQuery.error)}
          onRetry={() => void connectionQuery.refetch()}
        />
      </div>
    )
  }

  if (connectionQuery.isPending) {
    return <DetailPageSkeleton />
  }

  const connection = connectionQuery.data
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <Link
        to="/connections/$connectionId"
        params={{ connectionId }}
        className="inline-flex items-center gap-1.5 text-sm text-muted transition-colors hover:text-text"
      >
        <ArrowLeft className="size-4" aria-hidden="true" />
        Подключение
      </Link>

      <div className="flex min-w-0 flex-wrap items-center gap-2 border-b border-line pb-3">
        <EngineBadge engine={connection.engine} />
        <CopyableValue
          value={connection.display_name}
          label="Копировать название подключения"
          valueClassName="font-mono text-lg font-semibold leading-tight"
        >
          {connection.display_name}
        </CopyableValue>
        <TagBadge>{connectionEnvironmentLabel(connection.environment)}</TagBadge>
        <StatusChip tone={connectionStatusTone(connection.status)}>
          {connectionStatusLabel(connection.status)}
        </StatusChip>
      </div>

      <ConnectionStateTool connection={connection} />
    </div>
  )
}
