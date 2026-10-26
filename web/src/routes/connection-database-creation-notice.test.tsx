import type { ReactNode } from 'react'
import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Operation } from '../lib/types'
import { OperationProgressNotice } from '../components/operation-progress-notice'
import { DatabaseCreationNotice } from './connection-database-create-dialog'
import { qk } from '../lib/queryKeys'

vi.mock('../lib/intervals', () => ({ POLL_OPERATION_MS: 20 }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, to, search }: { children: ReactNode; to: string; search: Record<string, string> }) => (
    <a href={`${to}?${new URLSearchParams(search)}`}>{children}</a>
  ),
}))

function operation(overrides: Partial<Operation> = {}): Operation {
  return {
    id: 'database-root', parent_id: null, idempotency_key: null,
    kind: 'postgres.resource.create.database_with_roles.v2', status: 'running',
    connection_id: 'connection-1', principal_id: null, account_id: null,
    resource_id: 'resource-1', binding_id: null, payload: {}, error: '',
    actor_type: 'user', actor_id: 'admin@example.invalid', approved_by: null,
    approved_at: null, correlation_id: 'correlation-1',
    created_at: '2026-10-12T10:00:00Z', started_at: '2026-10-12T10:00:01Z',
    finished_at: null, updated_at: '2026-10-12T10:00:01Z',
    retry_pending: false,
    ...overrides,
  }
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status, headers: { 'content-type': 'application/json' },
  })
}

const clients: QueryClient[] = []
function Wrapper({ children }: { children: ReactNode }) {
  const [client] = useState(() => {
    const value = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    clients.push(value)
    return value
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

// React Query uses real short polling intervals here so lifecycle tests also
// exercise request cancellation and the observer's refetchInterval contract.
const pause = () => new Promise<void>((resolve) => setTimeout(resolve, 80))

afterEach(() => {
  cleanup()
  clients.splice(0).forEach((client) => client.clear())
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function show(onSettled = vi.fn(), onClose = vi.fn(), operationId = 'database-root') {
  return { onSettled, onClose, ...render(
    <DatabaseCreationNotice operationId={operationId} databaseName="appdb" createDefaultRoles
      onSettled={onSettled} onClose={onClose} />, { wrapper: Wrapper },
  ) }
}

describe('database creation operation tracker', () => {
  it.each(['failed', 'partial'])('waits for the scheduled retry of a %s attempt before announcing its outcome', async (status) => {
    let current = operation({ status, retry_pending: true, aggregate_status: 'success' })
    const fetchSpy = vi.fn(async () => response(current))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled } = show()
    expect(await screen.findByText('Ожидает повторной попытки')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveClass('bg-warn-soft')
    expect(screen.queryByText('Создано')).not.toBeInTheDocument()
    expect(screen.queryByText('Ошибка выполнения')).not.toBeInTheDocument()
    expect(screen.queryByText('Частичный результат')).not.toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThan(1))
    expect(onSettled).not.toHaveBeenCalled()

    current = operation({ status: 'running', updated_at: '2026-10-12T10:00:04Z' })
    await screen.findByText('Выполняется')
    expect(onSettled).not.toHaveBeenCalled()
    current = operation({ status: 'success', updated_at: '2026-10-12T10:00:09Z' })
    await screen.findByText('Создано')
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    const finishedCalls = fetchSpy.mock.calls.length
    await pause()
    expect(fetchSpy).toHaveBeenCalledTimes(finishedCalls)
  })

  it('continues watching a failed old-API response until the retry state becomes known', async () => {
    let current = operation({ status: 'failed', retry_pending: undefined })
    const fetchSpy = vi.fn(async () => response(current))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled } = show()
    expect(await screen.findByText('Проверяем состояние повтора')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThan(1))
    expect(onSettled).not.toHaveBeenCalled()
    current = operation({ status: 'failed', retry_pending: false })
    await screen.findByText('Ошибка выполнения')
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    const finishedCalls = fetchSpy.mock.calls.length
    await pause()
    expect(fetchSpy).toHaveBeenCalledTimes(finishedCalls)
  })

  it('keeps tracking the durable workflow after its currently existing children succeed', async () => {
    let current = operation({ aggregate_status: 'success' })
    const fetchSpy = vi.fn(async (_input: RequestInfo | URL) => response(current))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled, onClose } = show()
    expect(await screen.findByText('Выполняется')).toBeInTheDocument()
    expect(screen.queryByText('Создано')).not.toBeInTheDocument()
    expect(onSettled).not.toHaveBeenCalled()

    current = { ...current, status: 'success', finished_at: '2026-10-12T10:00:05Z' }
    expect(await screen.findByText('Создано')).toBeInTheDocument()
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    const finishedCalls = fetchSpy.mock.calls.length
    await pause()
    expect(fetchSpy).toHaveBeenCalledTimes(finishedCalls)
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByRole('link', { name: 'Открыть операцию' })).toHaveAttribute(
      'href', '/control?tab=operations&operation=database-root',
    )
  })

  it.each([
    ['partial', 'Частичный результат'], ['failed', 'Ошибка выполнения'], ['cancelled', 'Отменено'],
  ])('stops on %s without announcing success or submitting CREATE again', async (status, label) => {
    const current = operation({
      status, aggregate_status: 'success', finished_at: '2026-10-12T10:00:05Z',
      error: status === 'cancelled' ? '' : 'read_write_role_failed',
    })
    const requests: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(`${init?.method ?? 'GET'} ${input}`)
      return response(current)
    }))
    const { onSettled, onClose } = show()
    expect(await screen.findByText(label)).toBeInTheDocument()
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    const finishedCalls = requests.length
    await pause()
    expect(requests).toHaveLength(finishedCalls)
    expect(screen.queryByText('Создано')).not.toBeInTheDocument()
    expect(screen.getByRole('status')).not.toHaveClass('bg-ok-soft')
    expect(onClose).not.toHaveBeenCalled()
    expect(requests).toEqual(['GET /api/v1/operations/database-root'])
  })

  it('does not settle an ordinary bulk while its children are still running', async () => {
    const current = operation({ kind: 'bulk.database_roles', status: 'partial', aggregate_status: 'running' })
    const fetchSpy = vi.fn(async () => response(current))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled } = show()
    expect(await screen.findByText('Выполняется')).toBeInTheDocument()
    await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThan(1))
    expect(onSettled).not.toHaveBeenCalled()
  })

  it('keeps observing an unfamiliar status without announcing completion', async () => {
    const fetchSpy = vi.fn(async () => response(operation({ status: 'future-stage' })))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled } = show()
    await screen.findByText('Статус уточняется')
    await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThan(1))
    expect(onSettled).not.toHaveBeenCalled()
    expect(screen.queryByText('Создано')).not.toBeInTheDocument()
  })

  it('follows a resumed workflow under the same ID when its cached operation is refreshed', async () => {
    let current = operation({ status: 'partial', error: 'read_write_role_failed' })
    const fetchSpy = vi.fn(async (_input: RequestInfo | URL) => response(current))
    vi.stubGlobal('fetch', fetchSpy)
    const { onSettled } = show()
    await screen.findByText('Частичный результат')
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    current = operation({ updated_at: '2026-10-12T10:00:06Z' })
    expect(screen.queryByRole('button', { name: 'Обновить статус' })).not.toBeInTheDocument()
    await clients.at(-1)?.refetchQueries({ queryKey: qk.operation('database-root') })
    await screen.findByText('Выполняется')
    current = operation({ status: 'success', updated_at: '2026-10-12T10:00:09Z' })
    await screen.findByText('Создано')
    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(2))
    expect(fetchSpy.mock.calls.every(([input]) => input === '/api/v1/operations/database-root')).toBe(true)
  })

  it('explains the saved partial result and its next step without internal error codes', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => response(operation({
      status: 'partial', error: 'read_write_role_failed',
      database_provisioning: {
        phase: 'read_created', database_created: true, read_created: true, read_write_created: false,
        database_name: 'appdb', read_role: 'r_appdb', read_write_role: 'rw_appdb',
        error_code: 'read_write_role_failed',
      },
    }))))
    show()
    expect(await screen.findByText(/База и роль чтения созданы/)).toHaveTextContent(
      'Создание роли записи не завершено. Откройте операцию',
    )
    expect(screen.queryByText('read_write_role_failed')).not.toBeInTheDocument()
  })

  it('separates an unreadable status from execution failure and retries only the GET', async () => {
    let unavailable = true
    const requests: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(`${init?.method ?? 'GET'} ${input}`)
      return unavailable ? response({ error: 'status unavailable' }, 503) : response(operation())
    }))
    const { onSettled } = show()
    expect(await screen.findByRole('alert')).toHaveTextContent('Результат операции неизвестен')
    expect(screen.getByText('Статус неизвестен')).toBeInTheDocument()
    expect(screen.queryByText('Ошибка выполнения')).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Открыть операцию' })).toHaveAttribute(
      'href', '/control?tab=operations&operation=database-root',
    )
    unavailable = false
    fireEvent.click(screen.getByRole('button', { name: 'Обновить статус' }))
    expect(await screen.findByText('Выполняется')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument())
    expect(onSettled).not.toHaveBeenCalled()
    expect(requests.every((value) => value === 'GET /api/v1/operations/database-root')).toBe(true)
  })

  it('keeps the last operation status when a later status read fails', async () => {
    let unavailable = false
    vi.stubGlobal('fetch', vi.fn(async () => unavailable
      ? response({ error: 'status unavailable' }, 503) : response(operation())))
    const { onSettled } = show()
    await screen.findByText('Выполняется')
    unavailable = true
    expect(await screen.findByRole('alert')).toHaveTextContent('Показан последний полученный статус')
    expect(screen.getByText('Выполняется')).toBeInTheDocument()
    expect(screen.queryByText('Ошибка выполнения')).not.toBeInTheDocument()
    expect(onSettled).not.toHaveBeenCalled()
  })

  it('cancels an in-flight read when hidden and creates no further polling requests', async () => {
    let signal: AbortSignal | undefined
    const fetchSpy = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init?.signal ?? undefined
      return new Promise<Response>(() => {})
    })
    vi.stubGlobal('fetch', fetchSpy)
    const { unmount, onClose } = show()
    await waitFor(() => expect(fetchSpy).toHaveBeenCalledOnce())
    fireEvent.click(screen.getByRole('button', { name: 'Скрыть операцию' }))
    expect(onClose).toHaveBeenCalledOnce()
    unmount()
    expect(signal?.aborted).toBe(true)
    await pause()
    expect(fetchSpy).toHaveBeenCalledOnce()
  })

  it('cancels the old request and ignores its result when the tracked ID changes', async () => {
    let oldSignal: AbortSignal | undefined
    let finishOld!: (result: Response) => void
    vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith('database-root')) {
        oldSignal = init?.signal ?? undefined
        return new Promise<Response>((resolve) => { finishOld = resolve })
      }
      return Promise.resolve(response(operation({ id: 'new-root', status: 'cancelled' })))
    }))
    const { rerender, onSettled, onClose } = show()
    await waitFor(() => expect(finishOld).toBeDefined())
    rerender(<DatabaseCreationNotice operationId="new-root" databaseName="newdb"
      onSettled={onSettled} onClose={onClose} />)
    expect(oldSignal?.aborted).toBe(true)
    finishOld(response(operation({ status: 'success' })))
    expect(await screen.findByText('Отменено')).toBeInTheDocument()
    expect(screen.queryByText('Создано')).not.toBeInTheDocument()
    await waitFor(() => expect(onSettled).toHaveBeenCalledOnce())
    expect(onSettled).toHaveBeenCalledWith(expect.objectContaining({ id: 'new-root' }))
  })

  it('preserves automatic retry observation for existing generic notices', async () => {
    const fetchSpy = vi.fn(async () => response(operation({ kind: 'account.create', status: 'failed' })))
    vi.stubGlobal('fetch', fetchSpy)
    render(<OperationProgressNotice operationId="database-root" label="Создание аккаунта"
      onSettled={vi.fn()} onOpenDetails={vi.fn()} onClose={vi.fn()} />, { wrapper: Wrapper })
    await screen.findByText('Failed')
    await waitFor(() => expect(fetchSpy.mock.calls.length).toBeGreaterThan(1))
  })
})
