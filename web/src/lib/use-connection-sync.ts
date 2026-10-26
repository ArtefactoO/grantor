import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import { errorMessage } from './errorMessage'
import { POLL_OPERATION_MS } from './intervals'
import { qk } from './queryKeys'
import { operationInProgress } from './status'
import type { Operation } from './types'

export type ConnectionSyncState = 'idle' | 'syncing' | 'success' | 'error'

export function useConnectionSync(connectionId: string) {
  const queryClient = useQueryClient()
  const [operationId, setOperationId] = useState<string | null>(null)
  const [state, setState] = useState<ConnectionSyncState>('idle')
  const [failure, setFailure] = useState<string | null>(null)
  const successTimer = useRef<number | null>(null)

  const clearSuccessTimer = () => {
    if (successTimer.current !== null) {
      window.clearTimeout(successTimer.current)
      successTimer.current = null
    }
  }

  useEffect(() => clearSuccessTimer, [])

  const refreshMutation = useMutation({
    mutationFn: () =>
      api<{ operation_id: string }>(`/api/v1/connections/${connectionId}/refresh`, {
        method: 'POST',
      }),
    onMutate: () => {
      clearSuccessTimer()
      setState('syncing')
      setFailure(null)
    },
    onSuccess: (data) => {
      setOperationId(data.operation_id)
    },
    onError: (error: unknown) => {
      setState('error')
      setFailure(errorMessage(error))
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: qk.connections() })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
    },
  })

  const operationQuery = useQuery({
    queryKey: qk.operation(operationId ?? ''),
    queryFn: ({ signal }) =>
      api<Operation>(`/api/v1/operations/${operationId}`, { signal }),
    enabled: operationId !== null,
    refetchInterval: (query) => {
      const operation = query.state.data
      return operation === undefined || operationInProgress(operation.status)
        ? POLL_OPERATION_MS
        : false
    },
  })

  useEffect(() => {
    if (operationId === null || !operationQuery.isError) return
    setOperationId(null)
    setState('error')
    setFailure(errorMessage(operationQuery.error))
  }, [operationId, operationQuery.error, operationQuery.isError])

  useEffect(() => {
    const operation = operationId === null ? undefined : operationQuery.data
    if (operation === undefined || operationInProgress(operation.status)) return

    setOperationId(null)
    if (operation.status === 'success') {
      setState('success')
      setFailure(null)
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connections() }),
        queryClient.invalidateQueries({ queryKey: qk.accounts() }),
        queryClient.invalidateQueries({ queryKey: qk.resources() }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
        queryClient.invalidateQueries({ queryKey: qk.drift() }),
      ])
      successTimer.current = window.setTimeout(() => {
        setState('idle')
        successTimer.current = null
      }, 1_500)
      return
    }

    setState('error')
    setFailure(
      operation.error !== ''
        ? operation.error
        : `операция завершилась со статусом ${operation.status}`,
    )
  }, [operationId, operationQuery.data, queryClient])

  const syncing =
    refreshMutation.isPending ||
    (operationId !== null &&
      (operationQuery.data === undefined || operationInProgress(operationQuery.data.status)))

  return {
    state: syncing ? ('syncing' as const) : state,
    failure,
    syncing,
    sync: () => {
      if (!syncing) refreshMutation.mutate()
    },
  }
}
