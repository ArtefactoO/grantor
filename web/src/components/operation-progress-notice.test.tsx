import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Operation } from '../lib/types'

const motionPreference = vi.hoisted(() => ({ reduced: false }))
vi.mock('motion/react', async (importOriginal) => ({
  ...await importOriginal<typeof import('motion/react')>(),
  useReducedMotion: () => motionPreference.reduced,
}))
import {
  formatOperationDuration,
  OperationProgressNotice,
  operationDurationMs,
  operationObservedDurationMs,
} from './operation-progress-notice'

function operation(overrides: Partial<Operation> = {}): Operation {
  return {
    id: 'operation-1', parent_id: null, idempotency_key: null,
    kind: 'account.delete', status: 'success', connection_id: 'connection-1',
    principal_id: null, account_id: 'account-1', resource_id: null, binding_id: null,
    payload: {}, error: '', actor_type: 'user', actor_id: 'admin@example.com',
    approved_by: null, approved_at: null, correlation_id: 'correlation-1',
    created_at: '2026-07-22T10:00:00.000Z', started_at: '2026-07-22T10:00:01.000Z',
    finished_at: '2026-07-22T10:01:04.000Z', updated_at: '2026-07-22T10:01:04.000Z',
    ...overrides,
  }
}

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => {
  motionPreference.reduced = false
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('OperationProgressNotice', () => {
  it('formats elapsed operation time from backend timestamps', () => {
    const value = operation()
    expect(operationDurationMs(value)).toBe(64_000)
    expect(formatOperationDuration(64_000)).toBe('1 мин 04 с')
    expect(formatOperationDuration(63.244)).toBe('63 мс')
    expect(formatOperationDuration(25, true)).toBe('< 1 с')
  })

  it('keeps terminal time monotonic when polling observes completion later', () => {
    const value = operation({
      created_at: '2026-07-22T10:00:00.000Z',
      started_at: '2026-07-22T10:00:00.013Z',
      finished_at: '2026-07-22T10:00:00.013Z',
      updated_at: '2026-07-22T10:00:00.013Z',
    })

    const duration = operationObservedDurationMs(
      value,
      Date.parse('2026-07-22T10:00:02.100Z'),
    )

    expect(duration).toBe(2_100)
    expect(formatOperationDuration(duration)).toBe('2 с')
  })

  it('shows terminal duration and settles exactly once', async () => {
    const value = operation()
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))
    const onSettled = vi.fn()

    render(
      <Wrapper>
        <OperationProgressNotice
          operationId={value.id}
          label="Удаление аккаунта test"
          onSettled={onSettled}
          onOpenDetails={vi.fn()}
          onClose={vi.fn()}
        />
      </Wrapper>,
    )

    expect(await screen.findByText('Удаление аккаунта test')).toBeInTheDocument()
    expect(await screen.findByText('1 мин 04 с')).toBeInTheDocument()
    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(1))
    expect(onSettled).toHaveBeenCalledWith(value)
    expect(screen.queryByTitle(value.id)).not.toBeInTheDocument()
  })

  it('keeps compact feedback on one reserved line', async () => {
    const value = operation()
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))

    render(
      <Wrapper>
        <OperationProgressNotice
          operationId={value.id}
          label="Назначение роли с очень длинным названием"
          onSettled={vi.fn()}
          onOpenDetails={vi.fn()}
          onClose={vi.fn()}
          compact
        />
      </Wrapper>,
    )

    const notice = await screen.findByRole('status')
    expect(notice).toHaveClass('h-9', 'py-0', 'grantor-touch-notice')
    expect(screen.getByText('Назначение роли с очень длинным названием')).toHaveClass(
      'truncate',
    )
  })

  it('closes through a keyboard icon action without opening operation details', async () => {
    const value = operation()
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))
    const user = userEvent.setup()
    const onClose = vi.fn()
    const onOpenDetails = vi.fn()
    render(<Wrapper><OperationProgressNotice
      operationId={value.id}
      label="Назначение роли"
      onSettled={vi.fn()}
      onOpenDetails={onOpenDetails}
      onClose={onClose}
      autoCloseSuccess={false}
    /></Wrapper>)
    const close = await screen.findByRole('button', { name: 'Скрыть операцию' })
    expect(close).toHaveClass('ui-control-feedback', 'grantor-touch-target')
    close.focus()
    await user.keyboard('{Enter}')
    expect(onClose).toHaveBeenCalledOnce()
    expect(onOpenDetails).not.toHaveBeenCalled()
  })

  it('keeps a running operation visible without a moving progress strip under reduced motion', () => {
    motionPreference.reduced = true
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>(() => undefined)))
    const { container } = render(<Wrapper><OperationProgressNotice
      operationId="operation-1"
      label="Назначение роли"
      onSettled={vi.fn()}
      onClose={vi.fn()}
    /></Wrapper>)
    expect(screen.getByRole('status')).toHaveStyle({ opacity: '1' })
    expect(screen.getByText('Назначение роли')).toBeVisible()
    expect(container.querySelector('[style*="translate"]')).not.toBeInTheDocument()
  })

  it('automatically hides a successful operation after four seconds', async () => {
    const value = operation()
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))
    const onClose = vi.fn()
    const setTimeoutSpy = vi.spyOn(window, 'setTimeout')

    render(
      <Wrapper>
        <OperationProgressNotice
          operationId={value.id}
          label="Удаление аккаунта test"
          onSettled={vi.fn()}
          onOpenDetails={vi.fn()}
          onClose={onClose}
        />
      </Wrapper>,
    )

    await vi.waitFor(() => expect(screen.getByText('Done')).toBeInTheDocument())
    expect(onClose).not.toHaveBeenCalled()
    expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 4000)
  })

  it('explains a child failure and opens its operation details', async () => {
    const value = operation({
      status: 'partial', aggregate_status: 'partial', error: '',
      children: [operation({
        id: 'child-1', parent_id: 'operation-1', status: 'failed',
        error: 'plan: postgres: account "test2": adapter: object not found',
      })],
    })
    vi.stubGlobal('fetch', vi.fn(async () => response(value)))
    const onOpenDetails = vi.fn()

    render(
      <Wrapper>
        <OperationProgressNotice
          operationId={value.id}
          label="Добавление аккаунта test2"
          onSettled={vi.fn()}
          onOpenDetails={onOpenDetails}
          onClose={vi.fn()}
        />
      </Wrapper>,
    )

    expect(await screen.findByText('Аккаунт «test2» ещё не создан в подключении.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Добавление аккаунта test2'))
    expect(onOpenDetails).toHaveBeenCalledWith(value)
  })
})
