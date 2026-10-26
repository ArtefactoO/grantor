import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AttentionInbox } from './control-attention'
import type { Operation } from '../lib/types'
import { ApiError } from '../lib/api'

const post = vi.fn()
vi.mock('../lib/api', async (original) => ({ ...await original<typeof import('../lib/api')>(), api: (...args: unknown[]) => post(...args) }))
const error = (id: string) => ({ id, parent_id: null, kind: 'connection.discover', status: 'failed',
  connection_id: 'connection', actor_id: 'worker', error: 'HBA failure', resolved_at: null,
} as Operation)
const approval = (id: string, actor = 'admin@test') => ({ ...error(id), kind: 'access.grant', status: 'pending_approval', actor_id: actor, error: '' })

function mount({ admin = true, operator = true, operations = [error('e1'), error('e2')], approvals = [approval('a1')] } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const onSelect = vi.fn()
  const props = { operations, approvals, connectionName: () => 'prod', onSelect,
    canApprove: admin, canResolve: operator, currentActor: 'admin@test' }
  const view = render(<QueryClientProvider client={client}><AttentionInbox {...props} /></QueryClientProvider>)
  return { ...view, onSelect, props, client }
}

describe('attention bulk actions', () => {
  beforeEach(() => { post.mockReset(); post.mockResolvedValue({}) })

  it('resolves only selected errors after confirmation and keeps failed items selected', async () => {
    post.mockImplementation((path: string) => path.includes('e2') ? Promise.reject(new Error('scope changed')) : Promise.resolve({}))
    mount()
    const user = userEvent.setup()
    await user.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
    await user.click(screen.getByRole('button', { name: 'Отметить разобранными (2)' }))
    expect(post).not.toHaveBeenCalled()
    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText(/Повторного запуска операций не будет/)).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Отметить разобранными' }))
    await screen.findByText('Обработано: 1. Ошибок: 1.')
    expect(post.mock.calls.map(([path]) => path)).toEqual(['/api/v1/operations/e1/resolve', '/api/v1/operations/e2/resolve'])
    expect(screen.getByRole('checkbox', { name: /Выбрать:.*e1$/ })).not.toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Выбрать:.*e2$/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Выбрать:.*a1$/ })).toBeChecked()
    expect(screen.getByRole('alert')).toHaveTextContent('scope changed')
  })

  it.each(['approve', 'reject'] as const)('sends %s only for approvals and warns about self-approval', async (action) => {
    mount()
    const user = userEvent.setup()
    await user.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
    await user.click(screen.getByRole('button', { name: action === 'approve' ? 'Одобрить (1)' : 'Отклонить (1)' }))
    const dialog = screen.getByRole('dialog')
    if (action === 'approve') expect(within(dialog).getByText(/ваши собственные запросы/)).toBeInTheDocument()
    expect(post).not.toHaveBeenCalled()
    await user.click(within(dialog).getByRole('button', { name: action === 'approve' ? 'Подтвердить и выполнить' : 'Отклонить' }))
    await waitFor(() => expect(post).toHaveBeenCalledExactlyOnceWith(`/api/v1/operations/a1/${action}`, expect.objectContaining({ method: 'POST' })))
  })

  it('does not expose approvals to operators or mutations to viewers', () => {
    const operator = mount({ admin: false })
    expect(screen.queryByRole('button', { name: /Одобрить/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /a1$/ })).not.toBeInTheDocument()
    operator.unmount()
    mount({ admin: false, operator: false })
    expect(screen.queryAllByRole('checkbox')).toHaveLength(0)
    expect(screen.queryByRole('button', { name: /Отметить разобранными/ })).not.toBeInTheDocument()
  })

  it('selecting a checkbox does not open details and stale rows leave the selection', async () => {
    const { onSelect, rerender, props, client } = mount()
    await userEvent.click(screen.getByRole('checkbox', { name: /Выбрать:.*e1$/ }))
    expect(onSelect).not.toHaveBeenCalled()
    rerender(<QueryClientProvider client={client}><AttentionInbox {...props} operations={[error('e2')]} /></QueryClientProvider>)
    await waitFor(() => expect(screen.getByText('Выбрано: 0')).toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Отметить разобранными (0)' })).toBeDisabled()
  })

  it('paces the queue, waits on 429 and retries only the rejected row', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const starts: number[] = []
      let throttled = false
      post.mockImplementation((path: string) => {
        starts.push(Date.now())
        if (path.includes('e2') && !throttled) {
          throttled = true
          return Promise.reject(new ApiError(429, 'rate limit exceeded', null, null, 2000))
        }
        return Promise.resolve({})
      })
      mount({ operations: [error('e1'), error('e2'), error('e3')], approvals: [] })
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      await user.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
      await user.click(screen.getByRole('button', { name: 'Отметить разобранными (3)' }))
      await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отметить разобранными' }))
      await act(async () => { await vi.advanceTimersByTimeAsync(500) })
      expect(screen.getByText(/Лимит запросов API: пауза 2 с/)).toBeInTheDocument()
      expect(post.mock.calls.map(([path]) => path)).toEqual(['/api/v1/operations/e1/resolve', '/api/v1/operations/e2/resolve'])
      await act(async () => { await vi.advanceTimersByTimeAsync(2500) })
      expect(screen.getByText('Обработано: 3. Ошибок: 0.')).toBeInTheDocument()
      expect(post.mock.calls.map(([path]) => path)).toEqual(['/api/v1/operations/e1/resolve', '/api/v1/operations/e2/resolve', '/api/v1/operations/e2/resolve', '/api/v1/operations/e3/resolve'])
      expect(starts[1] - starts[0]).toBeGreaterThanOrEqual(500)
      expect(starts[2] - starts[1]).toBeGreaterThanOrEqual(2000)
      expect(starts[3] - starts[2]).toBeGreaterThanOrEqual(500)
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    } finally { vi.useRealTimers() }
  })

  it('stops a persistently throttled queue and retains unsent rows', async () => {
    post.mockRejectedValue(new ApiError(429, 'rate limit exceeded', null, null, 120_000))
    mount({ approvals: [] })
    await userEvent.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
    await userEvent.click(screen.getByRole('button', { name: 'Отметить разобранными (2)' }))
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отметить разобранными' }))
    await screen.findByText(/ещё не отправлено: 1/)
    expect(post).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('checkbox', { name: /Выбрать:.*e1$/ })).toBeChecked()
    expect(screen.getByRole('checkbox', { name: /Выбрать:.*e2$/ })).toBeChecked()
  })

  it('completes a full 100-row page against the API token bucket, starting with no tokens', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      let tokens = 0
      let previous = Date.now()
      let rejected = 0
      const applied = new Set<string>()
      post.mockImplementation((path: string) => {
        const now = Date.now()
        tokens = Math.min(20, tokens + (now - previous) * 2 / 1000)
        previous = now
        if (tokens < 1) {
          rejected++
          return Promise.reject(new ApiError(429, 'rate limit exceeded', null, null, 1000))
        }
        tokens--
        expect(applied.has(path)).toBe(false)
        applied.add(path)
        return Promise.resolve({})
      })
      mount({ operations: Array.from({ length: 100 }, (_, i) => error(`e${i}`)), approvals: [] })
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      await user.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
      await user.click(screen.getByRole('button', { name: 'Отметить разобранными (100)' }))
      await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отметить разобранными' }))
      await act(async () => { await vi.advanceTimersByTimeAsync(51_000) })
      expect(screen.getByText('Обработано: 100. Ошибок: 0.')).toBeInTheDocument()
      expect(applied.size).toBe(100)
      expect(rejected).toBe(1)
      expect(post).toHaveBeenCalledTimes(101)
    } finally { vi.useRealTimers() }
  })

  it('cancels delayed retries when leaving the inbox', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      post.mockRejectedValue(new ApiError(429, 'rate limit exceeded', null, null, 2000))
      const { unmount } = mount({ approvals: [] })
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      await user.click(screen.getByRole('checkbox', { name: 'Выбрать показанные' }))
      await user.click(screen.getByRole('button', { name: 'Отметить разобранными (2)' }))
      await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отметить разобранными' }))
      expect(screen.getByText(/Лимит запросов API/)).toBeInTheDocument()
      unmount()
      await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
      expect(post).toHaveBeenCalledTimes(1)
      expect(post.mock.calls[0][1].signal.aborted).toBe(true)
    } finally { vi.useRealTimers() }
  })
})
