import type { ReactNode } from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { ErrorComponentProps } from '@tanstack/react-router'
import { RouterProvider } from '@tanstack/react-router'
import { describe, expect, it, vi } from 'vitest'

vi.mock('../components/layout/AppShell', () => ({
  AppShell: ({ children }: { children: ReactNode }) => <main>{children}</main>,
}))

vi.mock('./connection-detail', () => ({
  ConnectionDetailPage: () => <div>route:connection-detail</div>,
}))
vi.mock('./connection-state-page', () => ({
  ConnectionStatePage: () => <div>route:connection-state</div>,
}))
vi.mock('./control', () => ({ ControlPage: () => <div>route:control</div> }))
vi.mock('./overview', () => ({ OverviewPage: () => <div>route:overview</div> }))
vi.mock('./principals', () => ({ PrincipalsPage: () => <div>route:principals</div> }))
vi.mock('./principal-detail', () => ({
  PrincipalDetailPage: () => <div>route:principal-detail</div>,
}))
import { NotFound, RouteError, RoutePending, router } from './router'

describe('route-level state integration', () => {
  it('opens a scoped deep link and removes stale page state after a route switch', async () => {
    window.scrollTo = vi.fn()
    await act(async () => {
      await router.navigate({
        to: '/operations',
        search: { connection: 'connection-deep-link' },
      })
    })
    render(<RouterProvider router={router} />)

    expect(await screen.findByText('route:control')).toBeInTheDocument()
    expect(router.state.location.search).toMatchObject({
      connection: 'connection-deep-link',
      tab: 'operations',
    })

    await act(async () => {
      await router.navigate({ to: '/principals' })
    })
    await waitFor(() => expect(screen.getByText('route:principals')).toBeInTheDocument())
    expect(screen.queryByText('route:control')).not.toBeInTheDocument()
    expect(router.state.location.search).toEqual({})
  })

  it('adapts approvals deep links to the approval filter in Control', async () => {
    await act(async () => {
      await router.navigate({ to: '/approvals' })
    })
    render(<RouterProvider router={router} />)

    expect(await screen.findByText('route:control')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/control')
    expect(router.state.location.search).toMatchObject({ tab: 'operations', status: 'approval' })
  })

  it('keeps old environment bookmarks inside the admin Control tab', async () => {
    await act(async () => {
      await router.navigate({ to: '/scope-policies' })
    })
    render(<RouterProvider router={router} />)

    expect(await screen.findByText('route:control')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/control')
    expect(router.state.location.search).toMatchObject({ tab: 'environments' })
  })

  it('redirects removed global inventory links to their connection', async () => {
    for (const to of ['/resources', '/access'] as const) {
      await act(async () => {
        await router.navigate({ to, search: { connection: 'connection-legacy' } })
      })
      expect(router.state.location.pathname).toBe('/connections/connection-legacy')
    }

    await act(async () => {
      await router.navigate({ to: '/manifest', search: { connection: 'connection-legacy' } })
    })
    expect(router.state.location.pathname).toBe('/connections/connection-legacy/state')

    await act(async () => {
      await router.navigate({ to: '/resources' })
    })
    expect(router.state.location.pathname).toBe('/overview')
  })

  it('keeps the old root URL as a compatibility redirect to Overview', async () => {
    await act(async () => {
      await router.navigate({ to: '/' })
    })
    expect(router.state.location.pathname).toBe('/overview')
    render(<RouterProvider router={router} />)
    expect(await screen.findByText('route:overview')).toBeInTheDocument()
  })

  it('renders stable loading, empty/not-found and actionable error boundaries', async () => {
    const retry = vi.fn()
    const user = userEvent.setup()
    const view = render(<RoutePending />)
    expect(screen.getByRole('status')).toHaveTextContent('Загрузка страницы')

    view.rerender(<NotFound />)
    expect(screen.getByText('Страница не найдена')).toBeInTheDocument()

    view.rerender(
      RouteError({ error: new Error('chunk unavailable'), reset: retry } as ErrorComponentProps),
    )
    expect(screen.getByText('chunk unavailable')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /повтор/i }))
    expect(retry).toHaveBeenCalledOnce()
  })
})
