import { Cable } from '@project/ui/icons'
import { Combobox } from '@project/ui'
import type { ComboboxOption } from '@project/ui'
import { EngineBadge, StatusChip, TagBadge } from './ui/badge'
import { connectionStatusTone } from '../lib/status'
import { connectionStatusLabel } from '../lib/ui-copy'
import { connectionEnvironmentLabel } from '../lib/connection-presentation'
import type { Connection } from '../lib/types'

const ALL_CONNECTIONS_VALUE = '__grantor_all_connections__'

export interface ConnectionPickerProps {
  connections: Connection[]
  value?: string
  onValueChange: (value: string) => void
  allowAll?: boolean
  disabled?: boolean
  label?: string
  className?: string
}

/** Удаляет userinfo/query/path: endpoint участвует в поиске только host:port. */
export function safeEndpointSearchToken(endpoint: string): string {
  const candidate = endpoint.includes('://') ? endpoint : `tcp://${endpoint}`
  try {
    return new URL(candidate).host.toLocaleLowerCase()
  } catch {
    return (
      endpoint
        .replace(/^([^:/?#]+:\/\/)?[^/@\s]+@/, '$1')
        .replace(/^[^:]+:\/\//, '')
        .split(/[/?#]/, 1)[0]
        ?.trim()
        .toLocaleLowerCase() ?? ''
    )
  }
}

export function connectionSearchKeywords(connection: Connection): string[] {
  return [
    connection.display_name,
    connection.engine,
    connection.environment,
    ...connection.tags,
    ...connection.endpoints.map(safeEndpointSearchToken),
  ].filter((value) => value !== '')
}

export function connectionPickerOptions(
  connections: Connection[],
  allowAll: boolean,
): ComboboxOption[] {
  const options = connections.map((connection): ComboboxOption => ({
    value: connection.id,
    label: connection.display_name,
    description: `${connection.engine} / ${connection.environment || 'без окружения'}`,
    keywords: connectionSearchKeywords(connection),
    icon: <EngineBadge engine={connection.engine} />,
    meta: (
      <StatusChip tone={connectionStatusTone(connection.status)}>
        {connectionStatusLabel(connection.status)}
      </StatusChip>
    ),
    trigger: (
      <span className="flex min-w-0 items-center gap-2">
        <EngineBadge engine={connection.engine} />
        {connection.environment !== '' && (
          <TagBadge>{connectionEnvironmentLabel(connection.environment)}</TagBadge>
        )}
        <span className="min-w-0 truncate font-mono text-[13px]">
          {connection.display_name}
        </span>
      </span>
    ),
  }))
  if (allowAll) {
    options.unshift({
      value: ALL_CONNECTIONS_VALUE,
      label: 'Все подключения',
      description: 'Глобальный обзор',
      keywords: ['all', 'global', 'все'],
      icon: <Cable className="size-3.5" aria-hidden="true" />,
    })
  }
  return options
}

export function ConnectionPicker({
  connections,
  value,
  onValueChange,
  allowAll = false,
  disabled = false,
  label = 'Подключение',
  className,
}: ConnectionPickerProps) {
  return (
    <Combobox
      value={allowAll && value === undefined ? ALL_CONNECTIONS_VALUE : value}
      options={connectionPickerOptions(connections, allowAll)}
      onValueChange={(nextValue) => {
        onValueChange(nextValue === ALL_CONNECTIONS_VALUE ? '' : nextValue)
      }}
      label={label}
      searchLabel="Поиск подключения"
      placeholder={value !== undefined ? 'Подключение недоступно' : 'Выберите подключение…'}
      searchPlaceholder="Имя, движок, окружение, тег или endpoint…"
      emptyText="Подключения не найдены"
      disabled={disabled}
      className={className}
      contentClassName="min-w-72 max-w-[calc(100vw-2rem)]"
    />
  )
}
