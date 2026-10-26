// Компактный трекер асинхронной операции. В отличие от обычного notice он
// остаётся активным до terminal status, показывает elapsed time и сообщает
// владельцу экрана, когда пора обновить зависимые проекции.
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'
import { CheckCircle2, CircleAlert, Clock3, X } from '@project/ui/icons'
import { api } from '../lib/api'
import { qk } from '../lib/queryKeys'
import type { Operation } from '../lib/types'
import {
  bulkOperationInProgress,
  effectiveOperationStatus,
  operationStatusTone,
} from '../lib/status'
import { operationFailureMessages, operationStatusLabel } from '../lib/operation-presentation'
import { POLL_OPERATION_MS } from '../lib/intervals'
import { errorMessage } from '../lib/errorMessage'
import { cn, IconButton, Spinner } from '@project/ui'
import { motionTransition, MOTION_TRANSITION, MOTION_VARIANTS } from '@project/ui/motion'
import { StatusChip } from './ui/badge'

export interface OperationProgressNoticeProps {
  operationId: string
  label: string
  onSettled: (operation: Operation) => void
  onOpenDetails?: (operation: Operation) => void
  onClose: () => void
  /** Positioning belongs to the host (inline toolbar or floating panel rail). */
  className?: string
  /** Однострочный режим для постоянного слота в панели объекта. */
  compact?: boolean
  /** Existing account notices keep watching failed operations for automatic retries. */
  pollFailures?: boolean
  autoCloseSuccess?: boolean
  closeWhileRunning?: boolean
  details?: ReactNode
  statusLabel?: (status: string) => string
  failureMessage?: (operation: Operation) => string
}

export type OperationAnchor = 'account' | 'access'

export interface TrackedOperation {
  id: string
  label: string
  accountId: string | null
  anchor: OperationAnchor
}

function effectiveStatus(operation: Operation): string {
  return effectiveOperationStatus(operation)
}

function executionFinished(operation: Operation): boolean {
  return ['success', 'partial', 'failed', 'cancelled'].includes(effectiveStatus(operation))
}

function retryOutcomePending(operation: Operation): boolean {
  const status = effectiveStatus(operation)
  // An old API cannot tell us that the automatic retry queue has stopped.
  return (status === 'failed' || status === 'partial') && operation.retry_pending !== false
}

export function operationDurationMs(operation: Operation, now = Date.now()): number {
  // Полная длительность пользовательского запроса включает очередь и approval:
  // от создания операции до её terminal timestamp.
  const start = Date.parse(operation.created_at)
  const finish = operation.finished_at === null ? now : Date.parse(operation.finished_at)
  if (!Number.isFinite(start) || !Number.isFinite(finish)) return 0
  return Math.max(0, finish - start)
}

export function operationObservedDurationMs(
  operation: Operation,
  observedAt: number,
): number {
  const startedAt = Date.parse(operation.created_at)
  const observedDuration = Number.isFinite(startedAt)
    ? Math.max(0, observedAt - startedAt)
    : 0
  return Math.max(operationDurationMs(operation, observedAt), observedDuration)
}

export function formatOperationDuration(durationMs: number, running = false): string {
  const safeDurationMs = Math.max(0, durationMs)
  if (safeDurationMs < 1000) {
    return running ? '< 1 с' : `${Math.round(safeDurationMs)} мс`
  }
  const totalSeconds = Math.floor(safeDurationMs / 1000)
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return minutes === 0 ? `${seconds} с` : `${minutes} мин ${seconds.toString().padStart(2, '0')} с`
}

export function OperationProgressNotice({
  operationId,
  label,
  onSettled,
  onOpenDetails,
  onClose,
  className,
  compact = false,
  pollFailures = true,
  autoCloseSuccess = true,
  closeWhileRunning = false,
  details,
  statusLabel = operationStatusLabel,
  failureMessage,
}: OperationProgressNoticeProps) {
  const reducedMotion = useReducedMotion()
  const [now, setNow] = useState(Date.now())
  const settledRef = useRef<string | null>(null)
  const sawRunningOperationRef = useRef(false)
  const terminalObservedAtRef = useRef<number | null>(null)
  const onSettledRef = useRef(onSettled)
  const onCloseRef = useRef(onClose)
  onSettledRef.current = onSettled
  onCloseRef.current = onClose

  const operationQuery = useQuery({
    queryKey: qk.operation(operationId),
    queryFn: ({ signal }) =>
      api<Operation>(`/api/v1/operations/${operationId}`, { signal }),
    refetchInterval: (query) => {
      const operation = query.state.data
      return operation === undefined || !executionFinished(operation) ||
        (!pollFailures && retryOutcomePending(operation)) ||
        (pollFailures && (operation.status === 'partial' || operation.status === 'failed'))
        ? POLL_OPERATION_MS
        : false
    },
  })

  const operation = operationQuery.data
  const retryPending = !pollFailures && operation !== undefined && retryOutcomePending(operation)
  const running = operation === undefined || bulkOperationInProgress(operation) || !executionFinished(operation) || retryPending
  const status = retryPending ? operation.retry_pending === true ? 'retry_pending' : 'retry_unknown'
    : operation === undefined ? 'pending' : effectiveStatus(operation)
  const failed = status === 'failed' || status === 'partial'
  const succeeded = status === 'success'
  if (operation !== undefined && running) {
    sawRunningOperationRef.current = true
    terminalObservedAtRef.current = null
  }
  if (
    operation !== undefined
    && !running
    && sawRunningOperationRef.current
    && terminalObservedAtRef.current === null
  ) {
    terminalObservedAtRef.current = Date.now()
  }

  useEffect(() => {
    if (!running) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [operationId, running])

  useEffect(() => {
    const settlement = operation === undefined ? null : `${operation.id}:${effectiveStatus(operation)}:${operation.updated_at}`
    if (operation === undefined || running || settledRef.current === settlement) return
    settledRef.current = settlement
    onSettledRef.current(operation)
  }, [operation, running])

  useEffect(() => {
    if (!autoCloseSuccess || status !== 'success') return
    const timer = window.setTimeout(() => onCloseRef.current(), 4000)
    return () => window.clearTimeout(timer)
  }, [operationId, status, autoCloseSuccess])

  const duration = operation === undefined
    ? 0
    : running
      ? retryPending ? operationObservedDurationMs(operation, now) : operationDurationMs(operation, now)
      : terminalObservedAtRef.current === null
        ? operationDurationMs(operation, now)
        : operationObservedDurationMs(operation, terminalObservedAtRef.current)
  const failureMessages = operation === undefined ? [] : operationFailureMessages(operation)
  const failureText = operation === undefined ? undefined
    : failureMessage === undefined ? failureMessages[0] : failureMessage(operation)
  const summary = <>
    <span className="relative size-4 shrink-0" aria-hidden="true">
      <AnimatePresence initial={false}>
        <motion.span
          key={running ? 'running' : status}
          className="absolute inset-0"
          initial={reducedMotion ? false : 'hidden'}
          animate="visible"
          exit="exit"
          variants={MOTION_VARIANTS.statusIcon}
          transition={motionTransition('feedback', reducedMotion)}
        >
          {running ? <Spinner className="size-4 text-warn" />
            : failed ? <CircleAlert className="size-4 text-danger" />
              : succeeded ? <CheckCircle2 className="size-4 text-ok" />
                : <CircleAlert className="size-4 text-muted" />}
        </motion.span>
      </AnimatePresence>
    </span>
    <span className={cn('min-w-0 font-medium text-text', compact ? 'truncate' : 'break-words')} title={label}>{label}</span>
    <StatusChip tone={running ? 'warn' : operationStatusTone(status)}>
      {operation === undefined && operationQuery.isError ? 'Статус неизвестен' : statusLabel(status)}
    </StatusChip>
    <span className="ml-auto inline-flex shrink-0 items-center gap-1 tabular-nums text-muted" aria-hidden="true">
      <Clock3 className="size-3.5" />
      {formatOperationDuration(duration, running)}
    </span>
  </>

  return (
    <motion.div
      initial={reducedMotion ? false : 'hidden'}
      animate="visible"
      exit="exit"
      variants={MOTION_VARIANTS.notice}
      transition={motionTransition('feedback', reducedMotion)}
      className={cn(
        'relative min-w-0 overflow-hidden rounded-md border px-3 py-2 text-sm',
        failed ? 'border-danger/40 bg-danger-soft' : running ? 'border-warn/40 bg-warn-soft'
          : succeeded ? 'border-ok/40 bg-ok-soft' : 'border-line bg-panel2/40',
        compact && 'grantor-touch-notice h-9 px-2 py-0',
        className,
      )}
      role="status"
      aria-live="polite"
    >
      <div className="flex min-w-0 items-start gap-2">
        {onOpenDetails === undefined ? (
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2">{summary}</div>
        ) : <button
          type="button"
          disabled={operation === undefined}
          onClick={() => operation !== undefined && onOpenDetails(operation)}
          className="grantor-touch-target ui-control-feedback flex min-w-0 flex-1 items-center gap-2 rounded text-left hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent disabled:cursor-default"
          title={operation === undefined ? undefined : 'Открыть детали операции в Контроле'}
        >
          {summary}
        </button>}
        {(!running || closeWhileRunning || operationQuery.isError) && <CloseButton onClose={onClose} />}
      </div>
      {!compact && failed && failureText !== undefined && (
        onOpenDetails !== undefined ? <button type="button"
          onClick={() => operation !== undefined && onOpenDetails(operation)}
          className="grantor-touch-target ui-control-feedback mt-1.5 block w-full break-words rounded text-left text-xs text-danger hover:bg-danger-soft focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
          {failureText}
        </button> : <p className="mt-1.5 break-words text-xs text-danger">
          {failureText}
        </p>
      )}
      {operationQuery.isError && (
        <div role="alert" className="mt-1.5 space-y-1 text-xs text-danger">
          <p className="break-words">Не удалось обновить статус: {errorMessage(operationQuery.error)}.
            {operation === undefined ? ' Результат операции неизвестен.' : ' Показан последний полученный статус.'}</p>
        </div>
      )}
      {(details !== undefined || operationQuery.isError) && (
        <div className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
          {details}
          {operationQuery.isError && (
            <button type="button" disabled={operationQuery.isFetching}
              onClick={() => void operationQuery.refetch()}
              className="grantor-touch-target ui-control-feedback rounded text-text underline underline-offset-4 hover:bg-panel2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
              Обновить статус
            </button>
          )}
        </div>
      )}
      {running && (
        <div className="absolute inset-x-0 bottom-0 h-0.5 overflow-hidden bg-warn/15" aria-hidden="true">
          {reducedMotion ? <span className="block h-full bg-warn" /> : <motion.span
            className="block h-full w-1/3 bg-warn"
            initial={{ x: '-110%' }}
            animate={{ x: '410%' }}
            transition={MOTION_TRANSITION.operationProgress}
          />}
        </div>
      )}
    </motion.div>
  )
}

function CloseButton({ onClose }: { onClose: () => void }) {
  return (
    <IconButton
      compact
      onClick={onClose}
      label="Скрыть операцию"
      icon={<X className="size-4" aria-hidden="true" />}
    />
  )
}
