import { ShieldCheck, TriangleAlert } from '@project/ui/icons'
import type { Connection } from '../lib/types'
import { postgresProvisioningIssue, postgresProvisioningReady } from '../lib/postgres-provisioning-authority'
import { formatDateTime } from '../lib/time'

export function PostgresProvisioningNotice({
  connection,
  showReady = false,
  id,
}: {
  connection: Connection
  showReady?: boolean
  id?: string
}) {
  if (connection.engine !== 'postgres') return null
  const issue = postgresProvisioningIssue(connection)
  const ready = postgresProvisioningReady(connection)
  if (issue === null && !showReady) return null
  const authority = connection.postgres_provisioning_authority
  const admin = authority?.observed_admin_identity || authority?.expected_admin_identity || '—'
  const observed = authority?.observed_at ? formatDateTime(authority.observed_at) : 'нет подтверждённой проверки'
  if (ready) {
    return (
      <div id={id} role="status" className="flex min-w-0 items-start gap-2 rounded-md border border-ok/40 bg-ok-soft px-3 py-2 text-sm text-ok">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
        <div className="min-w-0">
          <p className="font-medium">PostgreSQL SUPERUSER подтверждён</p>
          <p className="mt-0.5 break-words text-xs leading-relaxed">
            Admin <span className="font-mono">{admin}</span> · проверено {observed}
          </p>
        </div>
      </div>
    )
  }
  return (
    <div id={id} role="status" className="flex min-w-0 items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-sm text-warn">
      <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <p className="font-medium">Создание PostgreSQL-ресурсов недоступно</p>
        <p className="mt-1 max-w-3xl break-words text-xs leading-relaxed">{issue}</p>
        {authority !== null && authority !== undefined && (
          <p className="mt-1 break-words text-xs leading-relaxed">
            <span className="font-mono">{authority.status} · {authority.reason}</span>
            {' · '}admin <span className="font-mono">{admin}</span> · {observed}
          </p>
        )}
      </div>
    </div>
  )
}
