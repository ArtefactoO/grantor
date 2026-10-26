import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { EnvironmentCreateDialog } from './environment-create-dialog'

const apiMock = vi.hoisted(() => vi.fn())
const apiListMock = vi.hoisted(() => vi.fn())

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return { ...actual, api: apiMock, apiList: apiListMock }
})

function renderDialog(onClose = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  render(
    <QueryClientProvider client={client}>
      <EnvironmentCreateDialog open onClose={onClose} />
    </QueryClientProvider>,
  )
  return onClose
}

describe('создание окружения', () => {
  it('создаёт окружение и закрывает диалог', async () => {
    apiListMock.mockResolvedValue([])
    apiMock.mockResolvedValue({ name: 'stage', created_at: '2026-07-29T10:00:00Z' })
    const user = userEvent.setup()
    const onClose = renderDialog()

    await user.type(screen.getByRole('textbox', { name: /Название/ }), '  stage  ')
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    await waitFor(() => expect(onClose).toHaveBeenCalled())
    expect(apiMock).toHaveBeenCalledWith('/api/v1/environments', {
      method: 'POST',
      body: { name: 'stage' },
    })
  })

  // Имя — сегмент Vault-пути env-credential: '/' сломал бы путь секрета.
  it('не даёт отправить имя со слэшем', async () => {
    apiMock.mockReset()
    apiListMock.mockResolvedValue([])
    const user = userEvent.setup()
    renderDialog()

    await user.type(screen.getByRole('textbox', { name: /Название/ }), 'stage/eu')
    expect(screen.getByRole('button', { name: 'Создать' })).toBeDisabled()
    expect(apiMock).not.toHaveBeenCalled()
  })

  // Без списка существующих легко завести дубль по памяти.
  it('показывает существующие окружения и блокирует дубль', async () => {
    apiMock.mockReset()
    apiListMock.mockResolvedValue([
      { name: 'prod', created_at: '2026-07-29T10:00:00Z' },
      { name: 'test', created_at: '2026-07-29T10:00:00Z' },
    ])
    const user = userEvent.setup()
    renderDialog()

    expect(await screen.findByText('Уже есть:')).toBeInTheDocument()
    expect(screen.getByText('prod')).toBeInTheDocument()

    await user.type(screen.getByRole('textbox', { name: /Название/ }), 'TEST')
    expect(screen.getByText('Такое окружение уже существует')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Создать' })).toBeDisabled()
    expect(apiMock).not.toHaveBeenCalled()
  })
})
