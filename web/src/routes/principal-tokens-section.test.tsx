import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { setCsrf } from '../lib/api'
import { ServiceTokensSection } from './principal-tokens-section'

const fetchMock = vi.fn<typeof fetch>()
const plaintext = 'synthetic-service-token-for-ui-test'
const permissionLabel = 'Разрешить добавление подключений'

function json(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderSection() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: 2 } } })
  const view = render(<QueryClientProvider client={client}><ServiceTokensSection principalId="service-1" principalName="Deploy service" /></QueryClientProvider>)
  return { client, ...view }
}

async function openIssue(user: ReturnType<typeof userEvent.setup>) {
  await screen.findByText('API-токенов нет')
  await user.click(screen.getAllByRole('button', { name: 'Выпустить токен' })[0])
  await user.type(screen.getByRole('textbox', { name: /^Имя/ }), 'CI')
}

function posts() {
  return fetchMock.mock.calls.filter(([, init]) => init?.method === 'POST')
}

describe('service token onboarding permission', () => {
  beforeEach(() => {
    fetchMock.mockReset()
    vi.stubGlobal('fetch', fetchMock)
    setCsrf('test-csrf', 'X-Test-CSRF')
  })

  it('keeps connection creation disabled unless explicitly selected', async () => {
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? json({ id: 'token-1', principal_id: 'service-1', name: 'CI', token: plaintext, permissions: [] }, 201)
      : json({ tokens: [] }))
    const user = userEvent.setup()
    renderSection()
    await openIssue(user)
    expect(screen.getByRole('checkbox', { name: permissionLabel })).not.toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Выпустить' }))
    await screen.findByText(plaintext)
    expect(JSON.parse(posts()[0][1]?.body as string)).toEqual({ name: 'CI', permissions: [] })
    expect(new Headers(posts()[0][1]?.headers).get('X-Test-CSRF')).toBe('test-csrf')
  })

  it('issues an explicit grant, holds the form through acknowledgement, and clears the one-time value', async () => {
    let completeIssue!: (response: Response) => void
    let created = false
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? new Promise<Response>((resolve) => { completeIssue = resolve })
      : json({ tokens: created ? [{ id: 'token-1', principal_id: 'service-1', name: 'CI', created_at: '2026-10-14T00:00:00Z', last_used_at: null, revoked_at: null, permissions: ['connections:create'], token: plaintext }] : [] }))
    const user = userEvent.setup()
    const { client } = renderSection()
    await openIssue(user)
    await user.click(screen.getByRole('checkbox', { name: permissionLabel }))
    await user.click(screen.getByRole('button', { name: 'Выпустить' }))
    expect(posts()).toHaveLength(1)
    expect(JSON.parse(posts()[0][1]?.body as string)).toEqual({ name: 'CI', permissions: ['connections:create'] })
    expect(screen.getByRole('checkbox', { name: permissionLabel })).toBeDisabled()
    expect(screen.getByRole('textbox', { name: /^Имя/ })).toBeDisabled()
    await user.keyboard('{Escape}')
    await user.click(screen.getByRole('button', { name: 'Закрыть' }))
    expect(screen.getByRole('dialog', { name: 'Выпустить токен' })).toBeInTheDocument()
    created = true
    await act(async () => { completeIssue(json({ id: 'token-1', principal_id: 'service-1', name: 'CI', permissions: ['connections:create'], token: plaintext }, 201)) })
    await screen.findByText(plaintext)
    expect(JSON.stringify(client.getMutationCache().getAll().map((mutation) => mutation.state))).not.toContain(plaintext)
    expect(JSON.stringify(client.getQueryCache().getAll().map((query) => query.state))).not.toContain(plaintext)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByText(plaintext)).not.toBeInTheDocument())
    expect(await screen.findByText('Добавление подключений')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Выпустить токен' }))
    expect(screen.getByRole('checkbox', { name: permissionLabel })).not.toBeChecked()
  })

  it('discards a late response after switching the selected service principal', async () => {
    let completeIssue!: (response: Response) => void
    fetchMock.mockImplementation(async (_url, init) => init?.method === 'POST'
      ? new Promise<Response>((resolve) => { completeIssue = resolve })
      : json({ tokens: [] }))
    const user = userEvent.setup()
    const { client, rerender } = renderSection()
    await openIssue(user)
    await user.click(screen.getByRole('button', { name: 'Выпустить' }))
    rerender(<QueryClientProvider client={client}><ServiceTokensSection principalId="service-2" principalName="Another service" /></QueryClientProvider>)
    await act(async () => { completeIssue(json({ id: 'token-1', principal_id: 'service-1', name: 'CI', token: plaintext, permissions: ['connections:create'] }, 201)) })
    expect(screen.queryByText(plaintext)).not.toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(JSON.stringify(client.getMutationCache().getAll().map((mutation) => mutation.state))).not.toContain(plaintext)
  })

  it('does not retry issuance on a lost response even when global mutations normally retry', async () => {
    fetchMock.mockImplementation(async (_url, init) => {
      if (init?.method === 'POST') throw new TypeError('network disconnected')
      return json({ tokens: [] })
    })
    const user = userEvent.setup()
    renderSection()
    await openIssue(user)
    await user.click(screen.getByRole('button', { name: 'Выпустить' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('токен мог быть создан')
    expect(posts()).toHaveLength(1)
    expect(screen.getByRole('checkbox', { name: permissionLabel })).toBeEnabled()
  })
})
