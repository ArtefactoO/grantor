// Вкладка «Коннекторы»: кто из сегментов на связи и когда истекают их
// сертификаты.
//
// До неё состояние агента было видно только в логах gateway, а истечение
// сертификата обнаруживалось по падающим операциям.
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { HelpCircle, Pencil, Plug, ShieldAlert, Trash2 } from '@project/ui/icons'
import { api, apiList } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { formatDateTime, formatRelative } from '../lib/time'
import type { ConnectorSession } from '../lib/types'
import {
  Button,
  Card,
  Combobox,
  CopyButton,
  IconButton,
  Input,
  Tooltip,
  EmptyState,
  RowSkeleton,
} from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { QueryStates } from '../components/ui/query-states'

/** Типы развёртывания: зеркало connectorstate.ValidDeploymentKind. */
const DEPLOYMENT_LABELS: Record<string, string> = {
  kubernetes: 'Kubernetes',
  vm: 'Виртуальная машина',
  other: 'Другое',
}

const DEPLOYMENT_OPTIONS = [
  { value: '', label: 'Как сообщил агент' },
  { value: 'kubernetes', label: DEPLOYMENT_LABELS.kubernetes },
  { value: 'vm', label: DEPLOYMENT_LABELS.vm },
  { value: 'other', label: DEPLOYMENT_LABELS.other },
]

/** За сколько дней до конца срок сертификата считается тревожным. */
const CERTIFICATE_WARNING_DAYS = 90

/**
 * Команда ротации. Показывается прямо в карточке: инструкция, которую надо
 * искать в документации в момент инцидента, равносильна её отсутствию.
 */
function rotateCommand(connectorId: string): string {
  return `scripts/connector-cert-rotate.sh --gateway-san dns:<адрес-gateway> --connector-id ${connectorId}`
}

const CERTIFICATE_HINT = 'Сертификат выпускается заново тем же CA: окна недоступности нет, порядок перезапуска не важен. В Kubernetes после записи в Vault ExternalSecret и reloader сделают остальное сами; вне Kubernetes добавьте --export-dir и перенесите PEM на машину агента.'

const STATUS_LABELS: Record<string, string> = {
  online: 'Online',
  stale: 'Stale',
  offline: 'Offline',
}

const STATUS_TONES: Record<string, 'ok' | 'warn' | 'danger'> = {
  online: 'ok',
  stale: 'warn',
  offline: 'danger',
}

export function ControlConnectors({ canEdit = false }: { canEdit?: boolean }) {
  const query = useQuery({
    queryKey: ['connectors'],
    queryFn: ({ signal }) => apiList<ConnectorSession>('/api/v1/connectors', 'connectors', signal),
  })

  return (
    <QueryStates
      query={query}
      skeleton={<RowSkeleton rows={2} leading />}
      empty={
        <EmptyState
          icon={Plug}
          title="Коннекторов нет"
          description="Агенты изолированных сегментов ещё не подключались к gateway."
        />
      }
    >
      {(connectors) => (
        <div className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {connectors.map((connector) => (
            <ConnectorCard key={connector.connector_id} connector={connector} canEdit={canEdit} />
          ))}
        </div>
      )}
    </QueryStates>
  )
}

function ConnectorCard({ connector, canEdit }: { connector: ConnectorSession; canEdit: boolean }) {
  const expiring = connector.certificate_days_left <= CERTIFICATE_WARNING_DAYS
  const expired = connector.certificate_days_left < 0
  const [editing, setEditing] = useState(false)
  const named = connector.display_name !== ''
  const deployment = DEPLOYMENT_LABELS[connector.deployment_kind] ?? ''

  return (
    <Card className="p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Plug aria-hidden="true" className="size-4 shrink-0 text-faint" />
        <span className={named
          ? 'min-w-0 flex-1 truncate text-sm font-medium text-text'
          : 'min-w-0 flex-1 truncate font-mono text-sm text-text'}>
          {named ? connector.display_name : connector.connector_id}
        </span>
        {connector.protocol_version !== '' && (
          <span className="font-mono text-[11px] text-faint">{connector.protocol_version}</span>
        )}
        <StatusChip tone={STATUS_TONES[connector.status] ?? 'unmg'}>
          {STATUS_LABELS[connector.status] ?? connector.status}
        </StatusChip>
        {canEdit && !editing && (
          <IconButton label="Изменить имя и тип" compact onClick={() => setEditing(true)}
            icon={<Pencil aria-hidden="true" className="size-3.5" />} />
        )}
      </div>

      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-[11px]">
        {/* CN сертификата остаётся видимым всегда: он адресует PKI, Vault и
            релиз агента, а отображаемое имя — только подпись. */}
        {named && <span className="font-mono text-faint">{connector.connector_id}</span>}
        {deployment !== '' && (
          <span className="rounded border border-line bg-panel2 px-1.5 py-0.5 text-muted">
            {deployment}
            {connector.deployment_source === 'agent' && ' · по данным агента'}
          </span>
        )}
        {deployment === '' && <span className="text-faint">тип не указан</span>}
      </div>

      {editing && <ConnectorProfileForm connector={connector} onClose={() => setEditing(false)} />}

      <dl className="mt-2.5 space-y-1 text-xs">
        <div className="flex flex-wrap gap-x-1.5">
          <dt className="text-muted">Последний кадр:</dt>
          <dd className="text-text">
            <time dateTime={connector.last_seen_at} title={formatDateTime(connector.last_seen_at)}>
              {formatRelative(connector.last_seen_at)}
            </time>
          </dd>
          <dt className="text-muted">· на связи с</dt>
          <dd className="text-text">{formatDateTime(connector.connected_at)}</dd>
        </div>
        <div className="flex flex-wrap items-center gap-x-1.5">
          <dt className="flex items-center gap-1 text-muted">
            Сертификат
            <Tooltip content={CERTIFICATE_HINT}>
              <span tabIndex={0} aria-label="Как обновить сертификат" className="cursor-help text-faint">
                <HelpCircle aria-hidden="true" className="size-3.5" />
              </span>
            </Tooltip>
            :
          </dt>
          <dd>
            <span className={expiring ? 'text-danger' : 'text-text'}>
              {formatDateTime(connector.certificate_not_after)}
            </span>
            <span className="ml-1.5 text-muted">
              {expired
                ? 'истёк'
                : `${connector.certificate_days_left} дн.`}
            </span>
          </dd>
        </div>
      </dl>

      {expiring && (
        <div className="mt-3 rounded-md border border-danger/40 bg-danger-soft px-3 py-2">
          <p className="flex items-start gap-2 text-xs text-danger">
            <ShieldAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
            {expired
              ? 'Сертификат истёк: агент не пройдёт mTLS, операции сегмента будут падать.'
              : 'Сертификат скоро истечёт. После этого агент перестанет подключаться. Перевыпустите сертификат заранее.'}
          </p>
          <div className="mt-2 flex items-center gap-2">
            <code className="min-w-0 flex-1 overflow-x-auto whitespace-pre rounded bg-panel2 px-2 py-1 font-mono text-[11px] text-text">
              {rotateCommand(connector.connector_id)}
            </code>
            <CopyButton value={rotateCommand(connector.connector_id)} compact />
          </div>
        </div>
      )}

      {canEdit && connector.status === 'offline' && (
        <ForgetConnector connectorId={connector.connector_id} />
      )}

      {connector.capabilities.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1">
          {connector.capabilities.map((capability) => (
            <span
              key={capability}
              className="rounded border border-line bg-panel2 px-1.5 py-0.5 font-mono text-[11px] text-muted"
            >
              {capability}
            </span>
          ))}
        </div>
      )}
    </Card>
  )
}

/**
 * Правка представления connector'а: имя и тип развёртывания. Идентификатор
 * (CN сертификата) не редактируется — сменить его можно только перевыпуском.
 */
function ConnectorProfileForm({ connector, onClose }: { connector: ConnectorSession; onClose: () => void }) {
  const queryClient = useQueryClient()
  const [name, setName] = useState(connector.display_name)
  const [kind, setKind] = useState(
    connector.deployment_source === 'operator' ? connector.deployment_kind : '',
  )
  const save = useMutation({
    mutationFn: () =>
      api(`/api/v1/connectors/${encodeURIComponent(connector.connector_id)}`, {
        method: 'PATCH',
        // api() сериализует body сам: готовая строка ушла бы JSON-литералом.
        body: { display_name: name, deployment_kind: kind },
      }),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['connectors'] })
      onClose()
    },
  })

  return (
    <div className="mt-3 space-y-2 rounded-md border border-line bg-panel2/40 p-2">
      <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={80}
        placeholder={connector.connector_id} aria-label="Отображаемое имя коннектора" />
      <Combobox value={kind} options={DEPLOYMENT_OPTIONS} onValueChange={setKind}
        label="Тип развёртывания" placeholder="Как сообщил агент" />
      {save.error !== null && <p role="alert" className="text-xs text-danger">{errorMessage(save.error)}</p>}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onClose}>Отмена</Button>
        <Button size="sm" onClick={() => save.mutate()} disabled={save.isPending}>
          {save.isPending ? 'Сохраняем…' : 'Сохранить'}
        </Button>
      </div>
    </div>
  )
}

/**
 * «Забыть» строку отключённого connector'а. Нужно после перевыпуска
 * сертификата с другим CN: старая карточка иначе висит вечным offline.
 * Подключившись снова, connector заведёт запись заново.
 */
function ForgetConnector({ connectorId }: { connectorId: string }) {
  const queryClient = useQueryClient()
  const [confirming, setConfirming] = useState(false)
  const forget = useMutation({
    mutationFn: () =>
      api(`/api/v1/connectors/${encodeURIComponent(connectorId)}`, { method: 'DELETE' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['connectors'] }),
  })

  if (!confirming) {
    return <div className="mt-3">
      <Button size="sm" variant="ghost" onClick={() => setConfirming(true)}>
        <Trash2 aria-hidden="true" className="size-3.5" /> Забыть
      </Button>
    </div>
  }
  return (
    <div className="mt-3 space-y-2 rounded-md border border-line bg-panel2/40 p-2">
      <p className="text-xs text-muted">
        Запись будет удалена. Если агент подключится снова, она появится заново.
      </p>
      {forget.error !== null && <p role="alert" className="text-xs text-danger">{errorMessage(forget.error)}</p>}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>Отмена</Button>
        <Button size="sm" onClick={() => forget.mutate()} disabled={forget.isPending}>
          {forget.isPending ? 'Удаляем…' : 'Забыть'}
        </Button>
      </div>
    </div>
  )
}
