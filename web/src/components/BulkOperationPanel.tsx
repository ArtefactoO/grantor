// Панель запущенной bulk-операции: children и aggregate_status с
// поллингом каждые POLL_OPERATION_MS до терминального сводного статуса.
// Используется деталью пользователя (principal-centric выдача) и другими
// массовыми операциями.
import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ListChecks, ShieldCheck, X } from '@project/ui/icons'
import { api, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { operationLabel, operationStatusLabel } from '../lib/operation-presentation'
import { errorMessage } from '../lib/errorMessage'
import type { Account, Operation } from '../lib/types'
import { bulkOperationInProgress, operationStatusTone, shortId } from '../lib/status'
import { indexById } from '../lib/indexById'
import { POLL_OPERATION_MS } from '../lib/intervals'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  Button,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Spinner,
  ErrorBanner,
} from '@project/ui'
import { StatusChip } from './ui/badge'
import { ConfirmActionDialog } from './ui/confirm-dialog'

export interface BulkOperationPanelProps {
  operationId: string
  accounts: Account[]
  onClose: () => void
  /** Однократно вызывается при достижении терминального статуса. */
  onSettled?: (operation: Operation) => void
}

type ApprovalDecision = 'approve' | 'reject'

interface InlineApprovalTarget {
  kind: 'single' | 'batch'
  operations: Operation[]
}

export function BulkOperationPanel({
  operationId,
  accounts,
  onClose,
  onSettled,
}: BulkOperationPanelProps) {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const queryClient = useQueryClient()
  const [decision, setDecision] = useState<ApprovalDecision | null>(null)
  const [decisionError, setDecisionError] = useState<string | null>(null)
  const operationQuery = useQuery({
    queryKey: qk.operation(operationId),
    queryFn: ({ signal }) => api<Operation>(`/api/v1/operations/${operationId}`, { signal }),
    refetchInterval: (query) => {
      const op = query.state.data
      return op === undefined || bulkOperationInProgress(op) ? POLL_OPERATION_MS : false
    },
  })

  const accountsById = useMemo(() => indexById(accounts), [accounts])

  const op = operationQuery.data
  const aggregate = op?.aggregate_status ?? ''
  const children = op?.children ?? []
  const polling = op !== undefined && bulkOperationInProgress(op)

  // Сигнал завершения для вызывающего (обновить связанные кэши): один раз
  // на операцию, при первом терминальном снимке.
  const settledRef = useRef('')
  useEffect(() => {
    if (op === undefined || polling || settledRef.current === operationId) return
    settledRef.current = operationId
    onSettled?.(op)
  }, [op, polling, operationId, onSettled])
  const pendingChildren = children.filter((child) => child.status === 'pending_approval')
  const approvalTarget: InlineApprovalTarget | null =
    pendingChildren.length > 0
      ? { kind: 'batch', operations: pendingChildren }
      : op?.status === 'pending_approval'
        ? { kind: 'single', operations: [op] }
        : null

  const decisionMutation = useMutation({
    mutationFn: (nextDecision: ApprovalDecision) => {
      if (approvalTarget === null) {
        throw new Error('Операция больше не ожидает подтверждения.')
      }
      const action =
        approvalTarget.kind === 'batch'
          ? nextDecision === 'approve'
            ? 'approve-children'
            : 'reject-children'
          : nextDecision
      return apiPost<unknown>(`/api/v1/operations/${operationId}/${action}`)
    },
    onSuccess: () => {
      setDecisionError(null)
      setDecision(null)
      void queryClient.invalidateQueries({ queryKey: qk.operation(operationId) })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      void queryClient.invalidateQueries({ queryKey: qk.approvals() })
      void queryClient.invalidateQueries({ queryKey: ['audit'] })
    },
    onError: (error: unknown) => {
      setDecisionError(errorMessage(error))
    },
  })

  return (
    <div className="rounded-lg border border-line bg-panel">
      <div className="flex h-11 items-center gap-2.5 border-b border-line px-3">
        <ListChecks className="size-4 shrink-0 text-muted" />
        <span className="text-sm font-medium text-text">Операция</span>
        <span className="font-mono text-[12px] text-muted" title={operationId}>
          {shortId(operationId)}
        </span>
        {aggregate !== '' && (
          <StatusChip tone={operationStatusTone(aggregate)}>{operationStatusLabel(aggregate)}</StatusChip>
        )}
        {polling && <Spinner className="size-3.5" />}
        <div className="flex-1" />
        <Button
          variant="ghost"
          size="sm"
          onClick={onClose}
          aria-label="Скрыть панель операции"
        >
          <X className="size-4" />
        </Button>
      </div>

      {operationQuery.isError ? (
        <div className="px-3 py-3 text-sm text-danger">
          {errorMessage(operationQuery.error)}
        </div>
      ) : op === undefined ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : (
        <>
          {approvalTarget !== null && (
            <InlineApproval
              target={approvalTarget}
              accountsById={accountsById}
              isAdmin={isAdmin}
              pending={decisionMutation.isPending}
              error={decisionError}
              onDecision={setDecision}
            />
          )}

          {children.length === 0 ? (
            <div className="px-3 py-3 text-sm text-faint">Дочерних операций нет.</div>
          ) : (
            <Table>
              <TableHeader>
                <tr>
                  <TableHead>Операция</TableHead>
                  <TableHead>Аккаунт</TableHead>
                  <TableHead>Статус</TableHead>
                  <TableHead>Ошибка</TableHead>
                </tr>
              </TableHeader>
              <TableBody>
                {children.map((child) => (
                  <TableRow key={child.id}>
                    <TableCell className="text-[13px]">{operationLabel(child.kind)}</TableCell>
                    <TableCell
                      className="font-mono text-[12px] text-muted"
                      title={child.account_id ?? undefined}
                    >
                      {child.account_id !== null
                        ? (accountsById.get(child.account_id)?.engine_identity ??
                          shortId(child.account_id))
                        : '—'}
                    </TableCell>
                    <TableCell>
                      <StatusChip tone={operationStatusTone(child.status)}>
                        {operationStatusLabel(child.status)}
                      </StatusChip>
                    </TableCell>
                    <TableCell className="max-w-[280px]">
                      {child.error !== '' ? (
                        <span
                          className="block truncate text-[13px] text-danger"
                          title={child.error}
                        >
                          {child.error}
                        </span>
                      ) : (
                        <span className="text-faint">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}

          <ConfirmActionDialog
            open={decision !== null && approvalTarget !== null}
            title={decision === 'reject' ? 'Отклонить изменение' : 'Подтвердить изменение'}
            description={
              approvalTarget === null ? null : (
                <>
                  {approvalTarget.kind === 'batch'
                    ? decision === 'reject'
                      ? `${approvalTarget.operations.length} ожидающих операций пачки не будут выполнены. Решение попадёт в аудит.`
                      : `${approvalTarget.operations.length} ожидающих операций пачки будут отправлены на выполнение. Решение и подтверждающий попадут в аудит.`
                    : decision === 'reject'
                      ? `${operationLabel(approvalTarget.operations[0].kind)}: изменение не будет выполнено. Решение попадёт в аудит.`
                      : `${operationLabel(approvalTarget.operations[0].kind)}: изменение будет отправлено на выполнение. Решение и подтверждающий попадут в аудит.`}
                </>
              )
            }
            confirmLabel={decision === 'reject' ? 'Отклонить' : 'Подтвердить и выполнить'}
            danger={decision === 'reject'}
            pending={decisionMutation.isPending}
            onConfirm={() => {
              if (decision !== null) decisionMutation.mutate(decision)
            }}
            onClose={() => {
              if (!decisionMutation.isPending) setDecision(null)
            }}
          />
        </>
      )}
    </div>
  )
}

interface InlineApprovalProps {
  target: InlineApprovalTarget
  accountsById: Map<string, Account>
  isAdmin: boolean
  pending: boolean
  error: string | null
  onDecision: (decision: ApprovalDecision) => void
}

/** Approval stays beside the change that created it; only admin can decide. */
function InlineApproval({
  target,
  accountsById,
  isAdmin,
  pending,
  error,
  onDecision,
}: InlineApprovalProps) {
  return (
    <section
      aria-label="Подтверждение операции"
      className="m-3 rounded-lg border border-warn/35 bg-warn-soft/35 p-3"
    >
      <div className="flex items-center gap-2 text-sm font-medium text-text">
        <ShieldCheck className="size-4 text-warn" aria-hidden="true" />
        Нужно явное подтверждение
        <StatusChip tone="warn">{operationStatusLabel('pending_approval')}</StatusChip>
      </div>

      <ul className="mt-3 divide-y divide-line border-y border-line text-sm">
        {target.operations.map((operation) => {
          const account =
            operation.account_id === null ? undefined : accountsById.get(operation.account_id)
          return (
            <li
              key={operation.id}
              className="grid gap-1 py-2 sm:grid-cols-[minmax(0,1fr)_minmax(110px,.7fr)_auto] sm:items-center sm:gap-3"
            >
              <span className="text-[12px] text-text">{operationLabel(operation.kind)}</span>
              <span
                className="font-mono text-[12px] text-muted"
                title={operation.account_id ?? undefined}
              >
                {operation.account_id === null
                  ? 'без аккаунта'
                  : (account?.engine_identity ?? shortId(operation.account_id))}
              </span>
              <StatusChip tone={operationStatusTone(operation.status)}>
                {operationStatusLabel(operation.status)}
              </StatusChip>
            </li>
          )
        })}
      </ul>

      <p className="mt-3 text-xs text-muted">
        {isAdmin
          ? 'Подтвердить может текущий admin, включая инициатора. Решение и self-approval фиксируются в аудите.'
          : 'Решение доступно только admin. Операция не начнётся до подтверждения.'}
      </p>

      {error !== null && (
        <div className="mt-3">
          <ErrorBanner>{error}</ErrorBanner>
        </div>
      )}

      {isAdmin && (
        <div className="mt-3 flex flex-wrap gap-2">
          <Button size="sm" disabled={pending} onClick={() => onDecision('approve')}>
            Подтвердить и выполнить
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={pending}
            onClick={() => onDecision('reject')}
          >
            Отклонить
          </Button>
        </div>
      )}
    </section>
  )
}
