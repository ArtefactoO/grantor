import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { setCsrf } from '../lib/api'
import type { PersonalAPIKey, PersonalAPIKeysResponse } from '../lib/personal-api-keys'
import { Topbar } from './layout/Topbar'

const auth = vi.hoisted(() => ({ email: 'operator@example.test', role: 'operator', csrfToken: 'test-csrf' }))
vi.mock('../auth/AuthProvider', async () => {
  const actual = await vi.importActual<typeof import('../auth/AuthProvider')>('../auth/AuthProvider')
  return { ...actual, useAuth: () => auth }
})

const fetchMock = vi.fn<typeof fetch>()
const endpoint = '/api/v1/me/api-keys'
const oneTimeValue = 'synthetic-one-time-api-key-for-ui-test'

function key(overrides: Partial<PersonalAPIKey> = {}): PersonalAPIKey {
  return {
    id: 'key-1', user_id: 'user-1', name: 'CI', role: 'viewer', created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 86_400_000).toISOString(),
    last_used_at: null, revoked_at: null, environments: null, ...overrides,
  }
}

function list(overrides: Partial<PersonalAPIKeysResponse> = {}): PersonalAPIKeysResponse {
  return {
    api_keys: [], user_id: 'user-1', max_expires_at: new Date(Date.now() + 90 * 86_400_000).toISOString(),
    allowed_roles: ['viewer', 'operator'], ...overrides,
  }
}

function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderTopbar() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  const view = render(
    <QueryClientProvider client={client}>
      <Topbar mobileNavigationOpen={false} onOpenMobileNavigation={vi.fn()} />
    </QueryClientProvider>,
  )
  return { client, ...view }
}

async function openKeys(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Мои API-ключи' }))
  await screen.findByText('У вас пока нет API-ключей.')
}

function posts() {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')
}

describe('personal API keys', () => {
  beforeEach(() => {
    auth.email = 'operator@example.test'
    auth.role = 'operator'
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    localStorage.clear()
    setCsrf('test-csrf', 'X-Test-CSRF')
  })

  it('loads only after opening and never offers a role above the current user', async () => {
    fetchMock.mockResolvedValue(json(list({ allowed_roles: ['viewer', 'operator', 'admin'] })))
    const user = userEvent.setup()
    renderTopbar()
    expect(fetchMock).not.toHaveBeenCalled()
    const opener = screen.getByRole('button', { name: 'Мои API-ключи' })
    await openKeys(user)
    expect(screen.getByRole('textbox', { name: /^Название ключа/ })).toHaveFocus()
    await user.click(screen.getByRole('combobox', { name: 'Права ключа' }))
    expect(screen.getByRole('option', { name: 'Просмотр (viewer)' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Изменения (operator)' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'Администрирование (admin)' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })

  it('locks issue until the response, sends CSRF, and keeps the one-time value out of every cache', async () => {
    let completeIssue!: (response: Response) => void
    const issued = key()
    let created = false
    fetchMock.mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') return new Promise<Response>((resolve) => { completeIssue = resolve })
      return json(list({ api_keys: created ? [{ ...issued, token: oneTimeValue } as PersonalAPIKey] : [] }))
    })
    const user = userEvent.setup()
    const { client } = renderTopbar()
    await openKeys(user)
    await user.type(screen.getByRole('textbox', { name: /^Название ключа/ }), '  CI  ')
    await user.click(screen.getByRole('button', { name: 'Выпустить ключ' }))
    expect(posts()).toHaveLength(1)
    const init = posts()[0][1]!
    const body = JSON.parse(init.body as string) as { name: string; role: string; expires_at: string }
    expect(body.name).toBe('CI')
    expect(body.role).toBe('viewer')
    expect(Date.parse(body.expires_at) - Date.now()).toBeGreaterThan(29 * 86_400_000)
    expect(new Headers(init.headers).get('X-Test-CSRF')).toBe('test-csrf')
    expect(init.credentials).toBe('same-origin')
    expect(screen.getByRole('textbox', { name: /^Название ключа/ })).toBeDisabled()
    await user.keyboard('{Escape}')
    await user.click(screen.getAllByRole('button', { name: 'Закрыть' })[0])
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(posts()).toHaveLength(1)
    created = true
    await act(async () => { completeIssue(json({ api_key: { ...issued, token: oneTimeValue }, token: oneTimeValue }, 201)) })
    expect(await screen.findByText(oneTimeValue)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Копировать API-ключ' }))
    expect(await screen.findByRole('button', { name: 'Скопировано' })).toBeInTheDocument()
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state))).not.toContain(oneTimeValue)
    expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain(oneTimeValue)
    expect(JSON.stringify(localStorage)).not.toContain(oneTimeValue)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByText(oneTimeValue)).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Мои API-ключи' }))
    expect(await screen.findByRole('button', { name: 'Отозвать ключ CI' })).toBeInTheDocument()
    expect(screen.queryByText(oneTimeValue)).not.toBeInTheDocument()
  })

  it('caps expiry at the server session bound even when it is less than seven days', async () => {
    const maximum = new Date(Date.now() + 2 * 86_400_000).toISOString()
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? json({ api_key: key({ expires_at: maximum }), token: oneTimeValue }, 201)
      : json(list({ max_expires_at: maximum, allowed_roles: ['viewer'] })))
    auth.role = 'viewer'
    const user = userEvent.setup()
    renderTopbar()
    await openKeys(user)
    await user.click(screen.getByRole('combobox', { name: 'Срок действия' }))
    expect(screen.getAllByRole('option')).toHaveLength(1)
    expect(screen.queryByRole('option', { name: '7 дней' })).not.toBeInTheDocument()
    await user.keyboard('{Escape}')
    await user.type(screen.getByRole('textbox', { name: /^Название ключа/ }), 'local')
    await user.click(screen.getByRole('button', { name: 'Выпустить ключ' }))
    await screen.findByText(oneTimeValue)
    expect(JSON.parse(posts()[0][1]?.body as string)).toEqual({ name: 'local', role: 'viewer', expires_at: maximum })
  })

  it('drops a late one-time response when the current user changes', async () => {
    let completeIssue!: (response: Response) => void
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? new Promise<Response>((resolve) => { completeIssue = resolve })
      : json(list()))
    const user = userEvent.setup()
    const { client, rerender } = renderTopbar()
    await openKeys(user)
    await user.type(screen.getByRole('textbox', { name: /^Название ключа/ }), 'CI')
    await user.click(screen.getByRole('button', { name: 'Выпустить ключ' }))
    auth.email = 'other-user@example.test'
    auth.role = 'viewer'
    rerender(<QueryClientProvider client={client}><Topbar mobileNavigationOpen={false} onOpenMobileNavigation={vi.fn()} /></QueryClientProvider>)
    await act(async () => { completeIssue(json({ api_key: key(), token: oneTimeValue }, 201)) })
    expect(screen.getByRole('dialog', { name: 'Мои API-ключи' })).toHaveTextContent('other-user@example.test')
    expect(screen.queryByText(oneTimeValue)).not.toBeInTheDocument()
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state))).not.toContain(oneTimeValue)
    expect(posts()).toHaveLength(1)
  })

  it('does not display a response for a cookie owner different from the loaded metadata', async () => {
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? json({ api_key: key({ user_id: 'different-user' }), token: oneTimeValue }, 201)
      : json(list()))
    const user = userEvent.setup()
    const { client } = renderTopbar()
    await openKeys(user)
    await user.type(screen.getByRole('textbox', { name: /^Название ключа/ }), 'CI')
    await user.click(screen.getByRole('button', { name: 'Выпустить ключ' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Учётная запись в браузере изменилась')
    expect(screen.queryByText(oneTimeValue)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Выпустить ключ' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Обновить' })).toBeDisabled()
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state))).not.toContain(oneTimeValue)
  })

  it('does not retry an uncertain issue and requires checking and revoking its possible result', async () => {
    let created = false
    let revoked = false
    fetchMock.mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') { created = true; throw new TypeError('network disconnected') }
      if (init?.method === 'DELETE') { revoked = true; return new Response(null, { status: 204 }) }
      return json(list({ api_keys: created ? [key({ revoked_at: revoked ? new Date().toISOString() : null })] : [] }))
    })
    const user = userEvent.setup()
    renderTopbar()
    await openKeys(user)
    await user.type(screen.getByRole('textbox', { name: /^Название ключа/ }), 'CI')
    await user.click(screen.getByRole('button', { name: 'Выпустить ключ' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('ключ мог быть создан')
    expect(posts()).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Выпустить ключ' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Проверить список' }))
    await screen.findByText('Ключ с именем «CI» найден. Отзовите его перед повторным выпуском.')
    expect(screen.getByRole('button', { name: 'Выпустить ключ' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Отозвать ключ CI' }))
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Отозвать' }))
    expect(await screen.findByText('Отозван')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Выпустить ключ' })).toBeEnabled()
    expect(posts()).toHaveLength(1)
  })

  it('requires a revoke confirmation and holds it through the HTTP acknowledgement', async () => {
    let completeRevoke!: (response: Response) => void
    let revoked = false
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'DELETE'
      ? new Promise<Response>((resolve) => { completeRevoke = resolve })
      : json(list({ api_keys: [key({ revoked_at: revoked ? new Date().toISOString() : null })] })))
    const user = userEvent.setup()
    renderTopbar()
    await user.click(screen.getByRole('button', { name: 'Мои API-ключи' }))
    await user.click(await screen.findByRole('button', { name: 'Отозвать ключ CI' }))
    await user.keyboard('{Escape}')
    expect(fetchMock.mock.calls.filter(([, init]) => init?.method === 'DELETE')).toHaveLength(0)
    await user.click(screen.getByRole('button', { name: 'Отозвать ключ CI' }))
    await user.click(screen.getByRole('button', { name: 'Отозвать' }))
    const confirmation = screen.getByRole('dialog', { name: 'Отозвать API-ключ' })
    expect(within(confirmation).getByRole('button', { name: 'Отмена' })).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(confirmation).toBeInTheDocument()
    revoked = true
    await act(async () => { completeRevoke(new Response(null, { status: 204 })) })
    expect(await screen.findByText('Отозван')).toBeInTheDocument()
    const call = fetchMock.mock.calls.find(([, init]) => init?.method === 'DELETE')!
    expect(call[0]).toBe(`${endpoint}/key-1`)
    expect(new Headers(call[1]?.headers).get('X-Test-CSRF')).toBe('test-csrf')
  })
})
