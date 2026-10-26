import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection } from '../lib/types'

vi.mock('../auth/AuthProvider', () => ({
  roleAtLeast: () => true,
  useAuth: () => ({ role: 'admin' }),
}))

vi.mock('../components/BulkOperationPanel', () => ({
  BulkOperationPanel: ({ operationId }: { operationId: string }) => (
    <div>Операция {operationId}</div>
  ),
}))

vi.mock('@number-flow/react', () => ({
  default: ({ value }: { value: number }) => <span>{value}</span>,
}))

import { ConnectionStateTool } from './connection-state-tool'

const connection: Connection = {
  id: 'connection-1',
  display_name: 'animation-board',
  engine: 'mongodb',
  environment: 'test',
  tags: [],
  endpoints: [],
  execution_mode: 'direct',
  tls_config: {},
  admin_credential_mode: 'vault',
  vault_admin_path: '',
  capabilities: [],
  discovery_config: {},
  status: 'active',
  server_version: '',
  topology: {},
  last_discovery_at: '2026-07-22T08:00:00Z',
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function response(body: string): Response {
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'application/yaml' },
  })
}

describe('connection-scoped State tool', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('loads Managed as an editable manifest and switches multi-section state to read-only', async () => {
    const fetchMock = vi.fn(async (path: string) => {
      const url = String(path)
      if (url.includes('sections=managed%2Croles')) {
        return response('kind: access_snapshot\nmanaged: []\nroles: []\n')
      }
      return response('version: v1\nentries: []\n')
    })
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    render(<ConnectionStateTool connection={connection} />, { wrapper: Wrapper })

    expect(screen.getByRole('heading', { name: 'Состояние подключения' })).toBeVisible()
    const manifest = await screen.findByLabelText('Текст манифеста')
    await waitFor(() => expect(manifest).toHaveValue('version: v1\nentries: []\n'))
    expect(manifest).not.toHaveAttribute('readonly')

    await user.click(screen.getByRole('checkbox', { name: 'Roles' }))
    const snapshot = await screen.findByLabelText('Текст аудит-снимка')
    await waitFor(() => expect(snapshot).toHaveValue(
      'kind: access_snapshot\nmanaged: []\nroles: []\n',
    ))
    expect(snapshot).toHaveAttribute('readonly')
    expect(screen.queryByRole('button', { name: 'Построить план' })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.map(([path]) => String(path))).toEqual([
      '/api/v1/access/export?connection=connection-1&sections=managed&format=yaml',
      '/api/v1/access/export?connection=connection-1&sections=managed%2Croles&format=yaml',
    ])
  })

  it('keeps file upload and the shared All chip inside the selected connection', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response('version: v1\nentries: []\n')))
    const user = userEvent.setup()
    render(<ConnectionStateTool connection={connection} />, { wrapper: Wrapper })
    await screen.findByLabelText('Текст манифеста')

    expect(screen.getByRole('button', { name: 'Загрузить' })).toBeEnabled()
    expect(screen.getByRole('checkbox', { name: 'All' })).toHaveAttribute('aria-checked', 'mixed')
    const uploaded = new File(
      ['kind: access_snapshot\nconnection:\n  id: connection-1\naccounts: []\n'],
      'snapshot.yaml',
      { type: 'application/yaml' },
    )
    await user.upload(screen.getByLabelText('Файл состояния'), uploaded)

    expect(await screen.findByLabelText('Текст аудит-снимка')).toHaveAttribute('readonly')
    expect(screen.getByRole('checkbox', { name: 'Accounts' })).toHaveAttribute('aria-checked', 'true')
  })

  // Молчаливое исчезновение plan/apply после загрузки снапшота оставляло
  // пользователя без объяснения; notice ведёт к managed-манифесту.
  it('explains the read-only snapshot right after upload and offers the way back', async () => {
    // Новый Response на каждый вызов: тело читается однократно, а извлечение
    // управляемого состояния делает второй запрос.
    vi.stubGlobal('fetch', vi.fn(async () => response('version: v1\nentries: []\n')))
    const user = userEvent.setup()
    render(<ConnectionStateTool connection={connection} />, { wrapper: Wrapper })
    await screen.findByLabelText('Текст манифеста')
    expect(screen.queryByText(/аудит-документ: plan и apply/)).not.toBeInTheDocument()

    const uploaded = new File(
      ['kind: access_snapshot\nconnection:\n  id: connection-1\naccounts: []\n'],
      'snapshot.yaml',
      { type: 'application/yaml' },
    )
    await user.upload(screen.getByLabelText('Файл состояния'), uploaded)

    const notice = await screen.findByRole('status', { name: 'Загружен аудит-снимок' })
    expect(notice).toHaveTextContent(/plan и apply\s+для него недоступны/)
    await user.click(
      within(notice).getByRole('button', { name: 'Извлечь управляемое состояние' }),
    )

    // Возврат к managed-манифесту: notice исчезает, plan снова доступен.
    expect(await screen.findByRole('button', { name: 'Построить план' })).toBeInTheDocument()
    expect(screen.queryByText(/plan и apply\s+для него недоступны/)).not.toBeInTheDocument()
  })
})
