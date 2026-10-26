import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import type { ConnectorSession } from '../lib/types'
import { ControlConnectors } from './control-connectors'

const apiListMock = vi.hoisted(() => vi.fn())

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api')
  return { ...actual, apiList: apiListMock }
})

const connector = (overrides: Partial<ConnectorSession> = {}): ConnectorSession => ({
  connector_id: 'test',
  status: 'online',
  connected_at: '2026-07-29T08:00:00Z',
  last_seen_at: '2026-07-29T08:30:00Z',
  certificate_not_after: '2031-07-28T08:45:15Z',
  certificate_days_left: 1825,
  capabilities: ['discover', 'account.create'],
  protocol_version: 'v1',
  display_name: '',
  deployment_kind: '',
  deployment_source: '',
  ...overrides,
})

function renderTab(canEdit = false) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return render(<ControlConnectors canEdit={canEdit} />, { wrapper })
}

describe('вкладка коннекторов', () => {
  it('показывает состояние сегмента и его движки', async () => {
    apiListMock.mockResolvedValue([connector()])
    renderTab()

    expect(await screen.findByText('test')).toBeInTheDocument()
    expect(screen.getByText('Online')).toBeInTheDocument()
    expect(screen.getByText('discover')).toBeInTheDocument()
  })

  // Инструкция, которую надо искать в документации в момент инцидента,
  // равносильна её отсутствию.
  it('подсказывает команду ротации, когда срок подходит', async () => {
    apiListMock.mockResolvedValue([connector({ certificate_days_left: 30 })])
    renderTab()

    expect(await screen.findByText(/connector-cert-rotate\.sh/)).toBeInTheDocument()
    expect(screen.getByText(/скоро истечёт/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Копировать/ })).toBeInTheDocument()
  })

  it('не пугает командой, пока срок далёк', async () => {
    apiListMock.mockResolvedValue([connector()])
    renderTab()

    expect(await screen.findByText('test')).toBeInTheDocument()
    expect(screen.queryByText(/connector-cert-rotate\.sh/)).not.toBeInTheDocument()
  })

  it('называет истёкший сертификат истёкшим', async () => {
    apiListMock.mockResolvedValue([connector({ certificate_days_left: -2 })])
    renderTab()

    expect(await screen.findByText('истёк')).toBeInTheDocument()
    expect(screen.getByText(/не пройдёт mTLS/)).toBeInTheDocument()
  })

  it('объясняет пустоту вместо пустого места', async () => {
    apiListMock.mockResolvedValue([])
    renderTab()

    expect(await screen.findByText('Коннекторов нет')).toBeInTheDocument()
  })

  // CN сертификата адресует PKI, Vault и релиз агента, поэтому остаётся
  // видимым и после того, как оператор задал человеческое имя.
  it('показывает имя оператора, не пряча идентификатор сертификата', async () => {
    apiListMock.mockResolvedValue([connector({
      display_name: 'Сегмент VDO',
      deployment_kind: 'vm',
      deployment_source: 'operator',
    })])
    renderTab()

    expect(await screen.findByText('Сегмент VDO')).toBeInTheDocument()
    expect(screen.getByText('test')).toBeInTheDocument()
    expect(screen.getByText(/Виртуальная машина/)).toBeInTheDocument()
  })

  it('отмечает тип, объявленный самим агентом', async () => {
    apiListMock.mockResolvedValue([connector({
      deployment_kind: 'kubernetes',
      deployment_source: 'agent',
    })])
    renderTab()

    expect(await screen.findByText(/Kubernetes · по данным агента/)).toBeInTheDocument()
  })

  it('называет тип неуказанным, пока о нём никто не сообщил', async () => {
    apiListMock.mockResolvedValue([connector()])
    renderTab()

    expect(await screen.findByText('тип не указан')).toBeInTheDocument()
  })

  // Тело PATCH уходит через api(), который сериализует его сам: готовая
  // строка превращалась в JSON-литерал, и сервер отвечал «invalid JSON body».
  it('отправляет профиль объектом, а не строкой', async () => {
    apiListMock.mockResolvedValue([connector()])
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ connector_id: 'test' }), {
        status: 200, headers: { 'Content-Type': 'application/json' },
      }),
    )
    renderTab(true)

    await userEvent.click(await screen.findByRole('button', { name: 'Изменить имя и тип' }))
    await userEvent.type(screen.getByLabelText('Отображаемое имя коннектора'), 'Сегмент VDO')
    await userEvent.click(screen.getByRole('button', { name: 'Сохранить' }))

    await waitFor(() => expect(fetchSpy).toHaveBeenCalled())
    const [, init] = fetchSpy.mock.calls.at(-1) as [string, RequestInit]
    expect(JSON.parse(String(init.body))).toEqual({
      display_name: 'Сегмент VDO', deployment_kind: '',
    })
    fetchSpy.mockRestore()
  })
})
