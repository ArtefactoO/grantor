import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { ConnectionSyncButton } from './connection-sync-button'

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children, client }: { children: ReactNode; client: QueryClient }) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

afterEach(() => vi.restoreAllMocks())

describe('ConnectionSyncButton', () => {
  it('shows the approved busy animation for the whole refresh request', async () => {
    const user = userEvent.setup()
    let finishRefresh: ((value: Response) => void) | undefined
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      () =>
        new Promise<Response>((resolve) => {
          finishRefresh = resolve
        }),
    )
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const { container } = render(
      <Wrapper client={client}>
        <ConnectionSyncButton connectionId="conn-a" connectionName="primary" />
      </Wrapper>,
    )

    await user.click(screen.getByRole('button', { name: 'Синхронизировать primary' }))

    const syncing = screen.getByRole('button', { name: 'Идёт синхронизация primary' })
    expect(syncing).toHaveAttribute('aria-busy', 'true')
    expect(syncing).toBeDisabled()
    expect(container.querySelector('svg.ui-sync-glyph')).toBeInTheDocument()
    expect(container.querySelector('span.ui-sync-arc')).toHaveClass(
      'absolute',
      'inset-px',
      'rounded-full',
      'border-2',
      'border-t-current',
    )

    finishRefresh?.(response({ error: 'target unavailable' }, 503))
    await screen.findByRole('button', { name: 'Повторить синхронизацию primary' })
  })

  it('posts refresh, follows the operation and exposes the successful terminal state', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input)
      if (path === '/api/v1/connections/conn-a/refresh') {
        expect(init?.method).toBe('POST')
        return response({ operation_id: 'operation-a' }, 202)
      }
      if (path === '/api/v1/operations/operation-a') {
        return response({
          id: 'operation-a',
          status: 'success',
          error: '',
        })
      }
      throw new Error(`unexpected request: ${path}`)
    })
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    const onSuccess = vi.fn()

    render(
      <Wrapper client={client}>
        <ConnectionSyncButton connectionId="conn-a" connectionName="primary" onSuccess={onSuccess} />
      </Wrapper>,
    )
    await user.click(screen.getByRole('button', { name: 'Синхронизировать primary' }))

    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Снимок primary обновлён' })).toBeInTheDocument(),
    )
    expect(
      fetchMock.mock.calls.filter(([input]) => String(input) === '/api/v1/connections/conn-a/refresh'),
    ).toHaveLength(1)
    expect(
      fetchMock.mock.calls.some(([input]) => String(input) === '/api/v1/operations/operation-a'),
    ).toBe(true)
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['connections'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['operations'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['accounts'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['resources'] })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: ['drift'] })
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
  })

  it('keeps a failed refresh actionable as retry', async () => {
    const user = userEvent.setup()
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ error: 'target unavailable' }, 503))
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    })

    render(
      <Wrapper client={client}>
        <ConnectionSyncButton connectionId="conn-a" connectionName="primary" />
      </Wrapper>,
    )
    await user.click(screen.getByRole('button', { name: 'Синхронизировать primary' }))

    const retry = await screen.findByRole('button', { name: 'Повторить синхронизацию primary' })
    await user.hover(retry)
    expect(await screen.findByRole('tooltip')).toHaveTextContent('target unavailable')
  })
})
