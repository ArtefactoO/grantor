import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Button, Card, Dialog, EmptyState } from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { ApiError } from '../lib/api'
import { ATTENTION_REQUEST_INTERVAL_MS, sendAttentionDecision, waitForAttentionRequest } from '../lib/attention-request'
import { errorMessage } from '../lib/errorMessage'
import { isUnresolvedOperationFailure } from '../lib/control-search'
import { operationDisplayLabel, operationStatusLabel } from '../lib/operation-presentation'
import { effectiveOperationStatus, operationStatusTone } from '../lib/status'
import { qk } from '../lib/queryKeys'
import { formatDateTime, formatRelative } from '../lib/time'
import type { Operation } from '../lib/types'

type Action = 'resolve' | 'approve' | 'reject'
const labels: Record<Action, string> = {
  resolve: 'Отметить разобранными', approve: 'Одобрить', reject: 'Отклонить',
}

export function AttentionInbox({ approvals, operations, connectionName, onSelect, canApprove, canResolve, currentActor }: {
  approvals: Operation[]
  operations: Operation[]
  connectionName: (id: string | null) => string
  onSelect: (operation: Operation) => void
  canApprove: boolean
  canResolve: boolean
  currentActor: string
}) {
  const client = useQueryClient()
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [confirmation, setConfirmation] = useState<{ action: Action; items: Operation[] } | null>(null)
  const [pending, setPending] = useState(false)
  const executing = useRef(false)
  const activeBatch = useRef<AbortController | null>(null)
  const [rateLimitWait, setRateLimitWait] = useState<number | null>(null)
  const [progress, setProgress] = useState(0)
  const [result, setResult] = useState<{ succeeded: number; remaining: number; errors: Array<{ item: Operation; message: string }> } | null>(null)
  const allBox = useRef<HTMLInputElement>(null)
  const items = [...(canApprove ? approvals : []), ...operations]
  const eligible = (item: Operation, action: Action) => action === 'resolve'
    ? canResolve && isUnresolvedOperationFailure(item)
    : canApprove && item.status === 'pending_approval'
  const selectable = items.filter((item) => eligible(item, 'resolve') || eligible(item, 'approve'))
  const selectedItems = selectable.filter((item) => selected.has(item.id))
  const allSelected = selectable.length > 0 && selectedItems.length === selectable.length
  const selectableKey = selectable.map((item) => item.id).join(',')
  useEffect(() => () => { activeBatch.current?.abort() }, [])
  useEffect(() => {
    const visible = new Set(selectableKey.split(','))
    setSelected((previous) => new Set([...previous].filter((id) => visible.has(id))))
  }, [selectableKey])
  useEffect(() => {
    if (allBox.current) allBox.current.indeterminate = selectedItems.length > 0 && !allSelected
  }, [allSelected, selectedItems.length])

  const run = async () => {
    if (confirmation === null || executing.current) return
    executing.current = true
    setPending(true)
    setProgress(0)
    setRateLimitWait(null)
    const controller = new AbortController()
    activeBatch.current = controller
    const { signal } = controller
    const errors: Array<{ item: Operation; message: string }> = []
    const succeeded = new Set<string>()
    // One request per operation preserves server scope, lifecycle, approval and
    // audit gates. A partial failure never replays the successful decisions.
    try {
      for (const [index, item] of confirmation.items.entries()) {
        if (index > 0) await waitForAttentionRequest(ATTENTION_REQUEST_INTERVAL_MS, signal)
        try {
          await sendAttentionDecision(`/api/v1/operations/${item.id}/${confirmation.action}`, signal, setRateLimitWait)
          succeeded.add(item.id)
        } catch (error) {
          if (signal.aborted) return
          errors.push({ item, message: errorMessage(error) })
          if (error instanceof ApiError && error.status === 429) break
        }
        setProgress((value) => value + 1)
      }
      setSelected((previous) => new Set([...previous].filter((id) => !succeeded.has(id))))
      setResult({ succeeded: succeeded.size, errors, remaining: confirmation.items.length - succeeded.size - errors.length })
      setConfirmation(null)
    } catch (error) {
      if (!signal.aborted) throw error
    } finally {
      await Promise.allSettled([
        client.invalidateQueries({ queryKey: qk.operations() }),
        client.invalidateQueries({ queryKey: qk.approvals() }),
        client.invalidateQueries({ queryKey: ['audit'] }),
      ])
      executing.current = false
      activeBatch.current = null
      setPending(false)
      setRateLimitWait(null)
    }
  }

  return <div className="space-y-3" aria-busy={pending}>
    {selectable.length > 0 && <div className="flex flex-wrap items-center gap-3 rounded-md border border-line p-3">
      <label className="flex min-h-9 cursor-pointer items-center gap-2 text-sm">
        <input ref={allBox} type="checkbox" className="size-4 accent-accent"
          checked={allSelected} disabled={pending}
          onChange={(event) => setSelected(event.target.checked ? new Set(selectable.map((item) => item.id)) : new Set())} />
        Выбрать показанные
      </label>
      <span className="text-sm text-muted" role="status">Выбрано: {selectedItems.length}</span>
      <div className="flex flex-wrap gap-2 sm:ml-auto">
        {(['resolve', 'approve', 'reject'] as const).filter((action) => action === 'resolve' ? canResolve : canApprove).map((action) => {
          const targets = selectedItems.filter((item) => eligible(item, action))
          return <Button key={action} variant={action === 'reject' ? 'danger' : 'outline'}
            disabled={pending || targets.length === 0}
            onClick={() => setConfirmation({ action, items: targets })}>
            {labels[action]} ({targets.length})
          </Button>
        })}
      </div>
    </div>}

    {result && <div className="space-y-2 text-sm">
      <p role="status">Обработано: {result.succeeded}. Ошибок: {result.errors.length}.</p>
      {result.remaining > 0 && <p role="status" className="text-muted">API продолжает ограничивать запросы. Выполнение приостановлено; ещё не отправлено: {result.remaining}. Эти строки остаются выбранными.</p>}
      {result.errors.length > 0 && <div role="alert" className="rounded-md border border-danger/40 p-3 text-danger">
        <p>Необработанные строки остаются выбранными. Проверьте ошибки перед повтором.</p>
        <ul className="mt-2 max-h-48 space-y-2 overflow-auto">
          {result.errors.map(({ item, message }) => <li key={item.id} className="break-words">
            {operationDisplayLabel(item)} · {connectionName(item.connection_id)} · {item.id}: {message}
          </li>)}
        </ul>
      </div>}
    </div>}

    {items.length === 0 ? <EmptyState title="Внимание не требуется" description="Операций, ожидающих решения или разбора ошибки, нет." />
      : <Card className="divide-y divide-line overflow-hidden">{items.map((item) => {
        const status = effectiveOperationStatus(item)
        const selectableItem = eligible(item, 'resolve') || eligible(item, 'approve')
        return <div key={item.id} className="flex items-center">
          {selectableItem && <label className="flex min-h-11 shrink-0 cursor-pointer items-center px-3">
            <input type="checkbox" className="size-4 accent-accent" checked={selected.has(item.id)} disabled={pending}
              aria-label={`Выбрать: ${operationDisplayLabel(item)} · ${connectionName(item.connection_id)} · ${item.id}`}
              onChange={(event) => setSelected((previous) => {
                const next = new Set(previous)
                if (event.target.checked) next.add(item.id)
                else next.delete(item.id)
                return next
              })} />
          </label>}
          <button type="button" onClick={() => onSelect(item)}
            className="flex min-w-0 flex-1 flex-wrap items-center gap-3 px-4 py-3 text-left hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-accent">
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium text-text">{operationDisplayLabel(item)}</span>
              <span className="mt-0.5 block truncate text-xs text-muted">{connectionName(item.connection_id)} · {item.error || item.actor_id}</span>
              {(item.finished_at ?? item.created_at) && <time className="mt-0.5 block text-xs text-muted"
                dateTime={item.finished_at ?? item.created_at} title={formatDateTime(item.finished_at ?? item.created_at)}>
                {formatRelative(item.finished_at ?? item.created_at)}
              </time>}
            </span>
            <StatusChip tone={operationStatusTone(status)}>{operationStatusLabel(status)}</StatusChip>
          </button>
        </div>
      })}</Card>}

    {confirmation && <Dialog open onClose={() => { if (!executing.current) setConfirmation(null) }}
      title={`${labels[confirmation.action]}: ${confirmation.items.length}`}>
      <p className="text-sm text-muted">{confirmation.action === 'resolve'
        ? 'Ошибки исчезнут из «Требует внимания». История и результат выполнения сохранятся. Повторного запуска операций не будет.'
        : confirmation.action === 'approve'
          ? 'Выбранные операции будут одобрены и поставлены на выполнение. Решения попадут в аудит.'
          : 'Выбранные операции будут отклонены. Решения попадут в аудит.'}</p>
      {confirmation.action === 'approve' && confirmation.items.some((item) => item.actor_id === currentActor) &&
        <p className="mt-3 text-sm text-warn">Среди выбранных есть ваши собственные запросы. Подтверждая, вы разрешаете их выполнение.</p>}
      <ul className="mt-3 max-h-60 space-y-2 overflow-auto text-sm">
        {confirmation.items.map((item) => <li key={item.id} className="break-words">
          {operationDisplayLabel(item)} · {connectionName(item.connection_id)}
          <span className="block text-xs text-muted">{item.id}</span>
        </li>)}
      </ul>
      {pending && <p role="status" className="mt-3 text-sm">Обработано {progress} из {confirmation.items.length}</p>}
      {rateLimitWait !== null && <p role="status" className="mt-2 text-sm text-muted">Лимит запросов API: пауза {Math.ceil(rateLimitWait / 1000)} с, затем выполнение продолжится автоматически.</p>}
      <div className="mt-5 flex flex-wrap justify-end gap-2">
        <Button variant="outline" disabled={pending} onClick={() => setConfirmation(null)}>Отмена</Button>
        <Button variant={confirmation.action === 'reject' ? 'danger' : 'primary'} disabled={pending} onClick={() => void run()}>
          {pending ? 'Обрабатываем…' : confirmation.action === 'approve' ? 'Подтвердить и выполнить' : labels[confirmation.action]}
        </Button>
      </div>
    </Dialog>}
  </div>
}
