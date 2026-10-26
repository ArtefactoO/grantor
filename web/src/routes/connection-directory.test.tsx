import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection } from '../lib/types'
import { qk } from '../lib/queryKeys'
import { ConnectionDirectory } from './connection-directory'

const apiMock = vi.hoisted(() => vi.fn())
vi.mock('../lib/api', async () => ({ ...await vi.importActual('../lib/api'), api: apiMock }))
vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, params, ...rest }: { children: ReactNode; params: { connectionId: string } }) => <a href={`/connections/${params.connectionId}`} {...rest}>{children}</a>,
}))
const connection = (id: string, engine = 'redis', environment = 'test'): Connection => ({
  id, engine, environment, display_name: id, tags: [], endpoints: ['target:6379'], execution_mode: 'direct', tls_config: null,
  admin_credential_mode: 'vault', vault_admin_path: '', capabilities: ['discover'], discovery_config: null,
  status: 'active', server_version: '', topology: null, last_discovery_at: null,
  created_at: '2026-10-15T00:00:00Z', updated_at: '2026-10-15T00:00:00Z',
})
const connections = [connection('favorite-db', 'postgres', 'prod'), ...Array.from({ length: 25 }, (_, i) => connection(`redis-${String(i).padStart(2, '0')}`))]
function setup(items = connections) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  client.setQueryData(qk.favoriteConnections(), { connection_ids: ['favorite-db'] })
  const view = () => <QueryClientProvider client={client}><ConnectionDirectory connections={items} pending={false} error={false} canRefresh={false} onRetry={vi.fn()} stateKey="viewer" /></QueryClientProvider>
  return { ...render(view()), view, client }
}

describe('grouped connection directory', () => {
  beforeEach(() => { sessionStorage.clear(); apiMock.mockReset(); apiMock.mockResolvedValue({ connection_ids: ['favorite-db'] }) })

  it('keeps favorites at the top, pages only an expanded engine and preserves view on return', async () => {
    const user = userEvent.setup()
    const { unmount, view } = setup()
    expect(within(screen.getByRole('region', { name: 'Избранные подключения' })).getByRole('link', { name: /favorite-db/ })).toBeVisible()
    expect(screen.getAllByRole('link', { name: /favorite-db/ })).toHaveLength(1)
    expect(screen.getByText('1–20 из 25')).toBeVisible()
    expect(screen.getByRole('combobox', { name: 'Движок подключения' })).toHaveTextContent('26')
    await user.click(screen.getByRole('button', { name: 'Следующая страница: TEST · Redis' }))
    expect(screen.getByText('21–25 из 25')).toBeVisible()
    expect(screen.queryByRole('link', { name: /redis-00/ })).not.toBeInTheDocument()
    unmount()
    render(view())
    expect(screen.getByText('21–25 из 25')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'TEST 25' }))
    expect(screen.queryByRole('link', { name: /redis-24/ })).not.toBeInTheDocument()
  })

  it('uses dependent counts and saves a star through the current user API', async () => {
    const user = userEvent.setup()
    const { client } = setup()
    await user.click(screen.getByRole('combobox', { name: 'Окружение подключения' }))
    expect(screen.getByRole('option', { name: 'All environments 2' })).toBeVisible()
    expect(screen.getByRole('option', { name: 'TEST' })).toBeVisible()
    await user.click(screen.getByRole('option', { name: 'TEST' }))
    expect(screen.getByRole('combobox', { name: 'Движок подключения' })).toHaveTextContent('25')
    apiMock.mockResolvedValue(undefined)
    // Keep the post-write refetch authoritative too.
    apiMock.mockImplementation((_path: string, options?: { method?: string }) => Promise.resolve(options?.method === 'PUT' ? undefined : { connection_ids: ['favorite-db', 'redis-00'] }))
    await user.click(screen.getByRole('button', { name: 'Добавить в избранное: redis-00' }))
    await waitFor(() => expect(apiMock).toHaveBeenCalledWith('/api/v1/me/favorite-connections/redis-00', { method: 'PUT' }))
    await waitFor(() => expect(client.getQueryData(qk.favoriteConnections())).toEqual({ connection_ids: ['favorite-db', 'redis-00'] }))
    expect(screen.getAllByRole('link', { name: /redis-00/ })).toHaveLength(1)
    await user.click(screen.getByRole('radio', { name: 'Избранное 1' }))
    expect(screen.getByRole('combobox', { name: 'Движок подключения' })).toHaveTextContent('1')
    expect(screen.getAllByRole('link')).toHaveLength(1)
  })

  it('does not silently discard favorites on an API failure', async () => {
    const user = userEvent.setup()
    setup()
    apiMock.mockRejectedValue(new Error('network unavailable'))
    await user.click(screen.getByRole('button', { name: 'Убрать из избранного: favorite-db' }))
    expect(await screen.findByText(/Не удалось сохранить избранное/)).toBeVisible()
    expect(screen.getByRole('button', { name: 'Убрать из избранного: favorite-db' })).toHaveAttribute('aria-pressed', 'true')
  })

  it('opens the selected environment without expanding every engine', async () => {
    const user = userEvent.setup()
    setup([...connections, connection('mongo-test', 'mongodb')])
    await user.click(screen.getByRole('combobox', { name: 'Окружение подключения' }))
    await user.click(screen.getByRole('option', { name: 'TEST' }))
    expect(screen.getByRole('button', { name: 'TEST 26' })).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('button', { name: 'Redis 25' })).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('link', { name: /redis-00/ })).not.toBeInTheDocument()
  })

  it('keeps keyboard focus when a starred row moves between groups', async () => {
    const user = userEvent.setup()
    setup()
    apiMock.mockImplementation((_path: string, options?: { method?: string }) => Promise.resolve(options?.method === 'PUT' ? undefined : { connection_ids: ['favorite-db', 'redis-00'] }))
    screen.getByRole('button', { name: 'Добавить в избранное: redis-00' }).focus()
    await user.keyboard('{Enter}')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Убрать из избранного: redis-00' })).toHaveFocus())
  })
})
