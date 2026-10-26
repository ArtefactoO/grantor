import { Database } from '@project/ui/icons'
import type { Resource } from '../lib/types'
import { cn, MetadataChip } from '@project/ui'

export interface AccountDatabaseOwnershipProps {
  databases: readonly Resource[]
  detail?: boolean
  className?: string
}

/** Compact, read-only presentation of direct PostgreSQL database ownership. */
export function AccountDatabaseOwnership({
  databases,
  detail = false,
  className,
}: AccountDatabaseOwnershipProps) {
  if (databases.length === 0) return null
  const maxVisible = detail ? 8 : 3
  const visible = databases.slice(0, maxVisible)
  const hidden = databases.slice(maxVisible)

  return (
    <div
      aria-label="Базы во владении"
      className={cn(detail ? 'space-y-1.5' : 'mt-1 flex min-w-0 flex-wrap items-center gap-1', className)}
    >
      <span className={cn(
        detail
          ? 'block text-xs font-semibold uppercase tracking-wider text-faint'
          : 'text-[11px] font-sans text-faint',
      )}>
        Владеет базами
      </span>
      <div className="flex min-w-0 flex-wrap gap-1">
        {visible.map((database) => (
          <MetadataChip
            key={database.id}
            title={`Прямой владелец базы ${database.name}`}
          >
            <Database className="size-3 shrink-0" aria-hidden="true" />
            <span className="truncate">{database.name}</span>
          </MetadataChip>
        ))}
        {hidden.length > 0 && (
          <MetadataChip title={hidden.map((database) => database.name).join(', ')}>
            +{hidden.length}
          </MetadataChip>
        )}
      </div>
    </div>
  )
}
