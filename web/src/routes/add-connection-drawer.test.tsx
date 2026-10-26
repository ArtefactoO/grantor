import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Connection } from '../lib/types'
import { AddConnectionDrawer } from './connections'

const apiMock = vi.hoisted(() => vi.fn())
const apiListMock = vi.hoisted(() => vi.fn())

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return { ...actual, api: apiMock, apiList: apiListMock }
})

function connection(environment: string): Connection {
  return {
    id: `connection-${environment}`,
    display_name: environment,
    engine: 'postgres',
    environment,
    tags: [],
    endpoints: ['localhost:5432'],
    execution_mode: 'direct',
    tls_config: null,
    admin_credential_mode: 'vault',
    vault_admin_path: '',
    capabilities: [],
    discovery_config: null,
    status: 'active',
    server_version: '',
    topology: null,
    last_discovery_at: null,
    created_at: '2026-07-22T10:00:00Z',
    updated_at: '2026-07-22T10:00:00Z',
  }
}

function renderDrawer(connections: Connection[]) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <AddConnectionDrawer open onClose={vi.fn()} connections={connections} />
    </QueryClientProvider>,
  )
}

describe('AddConnectionDrawer', () => {
  beforeEach(() => {
    apiMock.mockReset()
    apiListMock.mockReset()
    apiMock.mockResolvedValue({ engines: ['postgres', 'mongodb', 'mysql', 'rabbitmq', 'clickhouse', 'kafka', 'redis'] })
  })
  it('reuses discovered environments and keeps creating a new one explicit', async () => {
    apiListMock.mockResolvedValue([])
    const user = userEvent.setup()
    renderDrawer([connection('prod'), connection('dev'), connection('DEV')])

    const environment = screen.getByRole('combobox', { name: 'Окружение' })
    await user.click(environment)
    expect(screen.getAllByRole('option', { name: /dev/i })).toHaveLength(1)
    expect(screen.getByRole('option', { name: 'prod' })).toBeInTheDocument()

    await user.click(screen.getByRole('option', { name: 'Добавить новое окружение' }))
    expect(screen.getByRole('textbox', { name: 'Новое окружение' })).toBeVisible()
  })

  // Окружение может существовать только в реестре — без единого подключения.
  it('merges registry environments into the picker', async () => {
    apiListMock.mockResolvedValue([{ name: 'stage', created_at: '2026-07-29T10:00:00Z' }])
    const user = userEvent.setup()
    renderDrawer([connection('prod')])

    const environment = screen.getByRole('combobox', { name: 'Окружение' })
    await waitFor(() => expect(apiListMock).toHaveBeenCalled())
    await user.click(environment)
    expect(screen.getByRole('option', { name: 'stage' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'prod' })).toBeInTheDocument()
  })

  // Единая форма показывала «Базу для discovery» и RabbitMQ, которому она не
  // нужна; состав полей теперь определяет движок.
  it('adapts discovery fields to the selected engine', async () => {
    apiListMock.mockResolvedValue([])
    const user = userEvent.setup()
    renderDrawer([])

    expect(screen.getByRole('textbox', { name: /База для discovery/ })).toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'RabbitMQ' }))
    expect(screen.queryByRole('textbox', { name: /База для discovery/ })).not.toBeInTheDocument()

    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'Kafka' }))
    expect(screen.getByRole('combobox', { name: /SASL mechanism/ })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: /Security protocol/ })).toBeInTheDocument()
  })

  it('submits only the current engine discovery keys', async () => {
    apiListMock.mockResolvedValue([])
    apiMock.mockResolvedValue(connection('prod'))
    const user = userEvent.setup()
    renderDrawer([connection('prod')])

    await user.type(screen.getByRole('textbox', { name: /Отображаемое имя/ }), 'rabbit test')
    await user.click(screen.getByRole('combobox', { name: 'Окружение' }))
    await user.click(screen.getByRole('option', { name: 'prod' }))
    // Заполняем database у postgres, затем меняем движок: ключ не должен
    // утечь в payload RabbitMQ.
    await user.type(screen.getByRole('textbox', { name: /База для discovery/ }), 'appdb')
    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'RabbitMQ' }))
    await user.type(screen.getByRole('textbox', { name: /Endpoints/ }), 'rabbit:15672')
    await user.type(screen.getByRole('textbox', { name: /Пользователь/ }), 'admin')
    await user.type(screen.getByLabelText('Пароль'), 'secret')
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    await waitFor(() => expect(apiMock).toHaveBeenCalled())
    const [, options] = apiMock.mock.calls.at(-1) as [string, { body: Record<string, unknown> }]
    expect(options.body.engine).toBe('rabbitmq')
    expect(options.body).not.toHaveProperty('discovery_config')
  })

  it('moves endpoint guidance into a tooltip and keeps credential copy compact', async () => {
    apiListMock.mockResolvedValue([])
    const user = userEvent.setup()
    renderDrawer([])

    expect(screen.getByText('Admin credential')).toBeInTheDocument()
    expect(screen.queryByText(/уходит только в Vault/i)).not.toBeInTheDocument()
    const hint = screen.getByLabelText('Подсказка: Endpoints')
    await user.hover(hint)
    expect(await screen.findByText('По одному host:port на строку')).toHaveAttribute(
      'role',
      'tooltip',
    )
  })

  it('registers Redis no-auth explicitly without retaining or submitting credentials', async () => {
    apiListMock.mockResolvedValue([])
    apiMock.mockImplementation((path: string) => Promise.resolve(path === '/api/v1/engines' ? { engines: ['postgres', 'redis'] } : connection('test')))
    const user = userEvent.setup()
    renderDrawer([connection('test')])
    await user.type(screen.getByRole('textbox', { name: /Отображаемое имя/ }), 'redis inventory')
    await user.click(screen.getByRole('combobox', { name: 'Окружение' }))
    await user.click(screen.getByRole('option', { name: 'test' }))
    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'Redis' }))
    await user.type(screen.getByRole('textbox', { name: /Endpoints/ }), 'redis.test.svc.cluster.local:6379')
    await user.type(screen.getByRole('textbox', { name: /Пользователь/ }), 'previous-user')
    await user.type(screen.getByLabelText('Пароль'), 'discard-this-value')
    await user.click(screen.getByRole('combobox', { name: 'Авторизация Redis' }))
    await user.click(screen.getByRole('option', { name: 'Без пароля · default' }))
    expect(screen.queryByLabelText('Пароль')).not.toBeInTheDocument()
    expect(screen.getByText(/для просмотра инвентаря/)).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Создать' }))
    await waitFor(() => expect(apiMock).toHaveBeenCalledWith('/api/v1/connections', expect.objectContaining({
      method: 'POST', body: expect.objectContaining({ engine: 'redis', auth_mode: 'none' }),
    })))
    const call = apiMock.mock.calls.find(([path]) => path === '/api/v1/connections')
    expect(call?.[1].body).not.toHaveProperty('admin_credential')
    expect(JSON.stringify(call?.[1].body)).not.toContain('discard-this-value')
  })

  it('restores mandatory empty password fields after leaving Redis no-auth', async () => {
    apiListMock.mockResolvedValue([])
    apiMock.mockResolvedValue({ engines: ['redis', 'postgres'] })
    const user = userEvent.setup()
    renderDrawer([])
    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'Redis' }))
    await user.click(screen.getByRole('combobox', { name: 'Авторизация Redis' }))
    await user.click(screen.getByRole('option', { name: 'Без пароля · default' }))
    await user.click(screen.getByRole('combobox', { name: 'Движок' }))
    await user.click(screen.getByRole('option', { name: 'PostgreSQL' }))
    expect(screen.queryByRole('combobox', { name: 'Авторизация Redis' })).not.toBeInTheDocument()
    expect(screen.getByLabelText('Пароль')).toBeRequired()
    expect(screen.getByLabelText('Пароль')).toHaveValue('')
  })
})
