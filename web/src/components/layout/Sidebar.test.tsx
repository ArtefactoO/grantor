import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

let mockPathname = '/connections/conn-selected'

vi.mock('@tanstack/react-router', () => ({
  useRouterState: ({ select }: { select: (state: unknown) => unknown }) =>
    select({
      location: {
        pathname: mockPathname,
        search: {},
      },
    }),
  Link: ({
    to,
    search,
    params,
    children,
    ...props
  }: {
    to: string
    search?: { connection?: string }
    params?: { connectionId?: string }
    children: ReactNode
    [key: string]: unknown
  }) => {
    const query = search?.connection
      ? `?connection=${encodeURIComponent(search.connection)}`
      : ''
    const path = params?.connectionId
      ? to.replace('$connectionId', params.connectionId)
      : to
    return (
      <a href={`${path}${query}`} {...props}>
        {children}
      </a>
    )
  },
}))

vi.mock('../../lib/connection-context', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../lib/connection-context')>()
  return {
    ...actual,
    useConnectionScope: (connectionId: string | undefined) => ({
      query: { isSuccess: true },
      connections: [],
      resolution:
        connectionId === undefined
          ? { kind: 'required', connectionId: '' }
          : // conn-deleted моделирует подключение, которого больше нет:
            // список загружен успешно, а идентификатора в нём не оказалось.
            connectionId === 'conn-deleted'
            ? { kind: 'unavailable', connectionId }
            : {
                kind: 'selected',
                connectionId,
                connection: {
                  id: connectionId,
                  display_name:
                    connectionId === 'conn-remembered'
                      ? 'remembered-postgres'
                      : 'local-ui-review',
                },
              },
    }),
  }
})

import { Sidebar } from './Sidebar'

describe('Sidebar connection navigation', () => {
  beforeEach(() => {
    localStorage.clear()
    sessionStorage.clear()
    mockPathname = '/connections/conn-selected'
  })

  // Сайдбар помнит последнее подключение в sessionStorage и рисует его по
  // сохранённому имени. Если подключение удалили (или базу пересоздали),
  // пункт продолжал висеть до первого клика по нему.
  it('forgets a remembered connection that no longer exists', () => {
    sessionStorage.setItem('grantor:last-connection-id', 'conn-deleted')
    sessionStorage.setItem('grantor:last-connection-name', 'local-mongodb')
    mockPathname = '/overview'

    render(<Sidebar />)

    expect(screen.queryByText('local-mongodb')).not.toBeInTheDocument()
    expect(sessionStorage.getItem('grantor:last-connection-id')).toBeNull()
    expect(sessionStorage.getItem('grantor:last-connection-name')).toBeNull()
  })

  it('keeps the selected connection scope only for the remaining scoped module', () => {
    render(<Sidebar />)

    const nav = screen.getByRole('navigation')
    expect(nav).toHaveClass('overflow-x-hidden')
    expect(screen.getByRole('link', { name: 'Контроль' })).toHaveAttribute(
      'href',
      '/control?connection=conn-selected',
    )

    expect(screen.queryByRole('link', { name: 'Окружения' })).not.toBeInTheDocument()
    expect(screen.getByText('Control Plane')).toBeVisible()
    expect(nav.closest('aside')).toHaveClass('w-[210px]')
    expect(screen.queryByRole('button', { name: 'Свернуть меню' })).not.toBeInTheDocument()
    expect(nav).toHaveClass('overflow-x-hidden')

    const connectionLink = screen.getByRole('link', { name: 'local-ui-review' })
    expect(connectionLink).toHaveAttribute('href', '/connections/conn-selected')
    expect(connectionLink).toHaveAttribute('aria-current', 'page')
    expect(connectionLink).toHaveClass(
      'bg-selected',
      'text-text',
      '[box-shadow:inset_0_0_0_1px_var(--selection-outline)]',
    )
    expect(connectionLink).not.toHaveClass('active:scale-[0.98]')
  })

  it('keeps a stable nested slot under Overview while selection changes', () => {
    const view = render(<Sidebar />)

    expect(screen.queryByRole('link', { name: 'Подключения' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'local-ui-review' })).toHaveAttribute(
      'href',
      '/connections/conn-selected',
    )
    expect(screen.queryByRole('link', { name: 'Ресурсы' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Доступы' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Состояние' })).not.toBeInTheDocument()

    mockPathname = '/principals'
    view.rerender(<Sidebar />)
    expect(screen.getByRole('link', { name: 'local-ui-review' })).toHaveAttribute(
      'href',
      '/connections/conn-selected',
    )
    expect(screen.getByRole('link', { name: 'Пользователи' })).toHaveAttribute(
      'aria-current',
      'page',
    )
  })

  it('does not render a connection placeholder before a real connection is selected', () => {
    mockPathname = '/overview'

    render(<Sidebar />)

    expect(screen.queryByText('Подключение')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Подключение' })).not.toBeInTheDocument()
  })

  it('restores the last selected connection after remounting on another module', () => {
    sessionStorage.setItem('grantor:last-connection-id', 'conn-remembered')
    sessionStorage.setItem('grantor:last-connection-name', 'remembered-postgres')
    mockPathname = '/control'

    render(<Sidebar />)

    expect(screen.getByRole('link', { name: 'remembered-postgres' })).toHaveAttribute(
      'href',
      '/connections/conn-remembered',
    )
  })

  it('keeps the connection navigation selected on the State tool route', () => {
    mockPathname = '/connections/conn-selected/state'
    render(<Sidebar />)

    expect(screen.getByRole('link', { name: 'local-ui-review' })).toHaveAttribute(
      'aria-current',
      'page',
    )
  })
})
