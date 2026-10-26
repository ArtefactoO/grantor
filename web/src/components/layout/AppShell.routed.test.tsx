import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider } from '@tanstack/react-router'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../../auth/AuthProvider', () => ({
  AuthProvider: ({ children }: { children: ReactNode }) => children,
  roleAtLeast: () => true,
  useAuth: () => ({
    email: 'operator@example.test',
    role: 'admin',
    csrfToken: 'test-token',
  }),
}))

describe('routed responsive app shell', () => {
  beforeEach(() => {
    localStorage.clear()
    window.history.replaceState({}, '', '/route-that-does-not-exist')
  })

  it('opens the labelled mobile drawer, traps focus and restores it after Escape', async () => {
    const user = userEvent.setup()
    const { router } = await import('../../routes/router')
    await router.load()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    )

    expect(screen.getByRole('main')).toHaveClass('[scrollbar-gutter:stable]')
    const trigger = await screen.findByRole('button', { name: 'Открыть навигацию' })
    expect(screen.queryByText('Поиск…')).not.toBeInTheDocument()

    await user.click(trigger)

    const drawer = screen.getByRole('dialog', { name: 'Навигация' })
    expect(drawer).toHaveAccessibleDescription('Основные разделы Grantor')
    expect(screen.getByRole('link', { name: 'Обзор' })).toHaveFocus()
    expect(trigger.closest('[aria-hidden="true"]')).not.toBeNull()

    await user.keyboard('{Escape}')

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(trigger).toHaveFocus())
  })

  it('closes mobile navigation after a routed link activation', async () => {
    const user = userEvent.setup()
    const { router } = await import('../../routes/router')
    await router.load()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })

    render(
      <QueryClientProvider client={queryClient}>
        <RouterProvider router={router} />
      </QueryClientProvider>,
    )

    await user.click(await screen.findByRole('button', { name: 'Открыть навигацию' }))
    await user.click(screen.getByRole('link', { name: 'Обзор' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(window.location.pathname).toBe('/overview')
  })
})
