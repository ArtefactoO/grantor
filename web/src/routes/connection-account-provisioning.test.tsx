import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account } from '../lib/types'
import { qk } from '../lib/queryKeys'
import { POLL_OPERATION_MS } from '../lib/intervals'
import {
  AccountProvisioningNotice,
  accountProvisioningPollInterval,
  accountProvisioningPresentation,
  provisioningBlockedReason,
  useAccountProvisioning,
} from './connection-account-provisioning'
import type { AccountProvisioning } from './connection-account-provisioning'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, search }: { children: ReactNode; search: { operation: string } }) => (
    <a href={`/control?tab=operations&operation=${search.operation}`}>{children}</a>
  ),
}))

const account: Account = {
  id: 'pending-account',
  principal_id: null,
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'service_existing_user',
  authentication_scope: '',
  credential_mode: 'provided',
  vault_path: 'accounts/pending-account/credential',
  status: 'provisioning',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-08-26T13:23:43Z',
  updated_at: '2026-08-26T13:23:43Z',
}

const failed: AccountProvisioning = {
  account_id: account.id,
  updated_at: '2026-08-26T13:25:05.123456Z',
  state: 'failed',
  operation_id: 'failed-create-operation',
  operation_kind: 'account.create',
  operation_status: 'failed',
  operation_error: 'role already exists on the target',
  recoverable: true,
  retryable: true,
}

const verificationReady: AccountProvisioning = {
  ...failed,
  operation_kind: 'postgres.account.provision.v1',
  operation_error: 'password verification failed',
  recoverable: false,
  retryable: false,
  verification_ready: true,
  creation_phase: 'created',
}

function response(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
}

function Harness({
  target = account,
  isAdmin = true,
  canOperate = isAdmin,
  onStarted = vi.fn(),
}: {
  target?: Account
  isAdmin?: boolean
  canOperate?: boolean
  onStarted?: Parameters<typeof AccountProvisioningNotice>[0]['onOperationStarted']
}) {
  const provisioning = useAccountProvisioning(target)
  const presentation = accountProvisioningPresentation(provisioning)
  return (
    <>
      <span>{presentation.label}</span>
      {target.status === 'provisioning' && (
        <AccountProvisioningNotice
          account={target}
          provisioning={provisioning}
          isAdmin={isAdmin}
          canOperate={canOperate}
          onOperationStarted={onStarted}
        />
      )}
    </>
  )
}

function renderNotice(props: Parameters<typeof Harness>[0] = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return {
    client,
    ...render(<QueryClientProvider client={client}><Harness {...props} /></QueryClientProvider>),
  }
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('account provisioning presentation', () => {
  it('polls running operations only, and stops on failed reads and terminal states', () => {
    expect(accountProvisioningPollInterval({ ...failed, state: 'running' }, false)).toBe(POLL_OPERATION_MS)
    expect(accountProvisioningPollInterval({ ...failed, state: 'running' }, true)).toBe(false)
    expect(accountProvisioningPollInterval(failed, false)).toBe(false)
    expect(accountProvisioningPollInterval({ ...failed, state: 'unavailable' }, false)).toBe(false)
    expect(accountProvisioningPollInterval(undefined, false)).toBe(false)
  })

  it.each([
    'not_provisioning', 'no_failed_creation', 'busy', 'managed_bindings',
    'role_policy', 'connection_unavailable', 'connection_admin',
    'creation_outcome_unknown', 'creation_intent_changed',
  ])('explains the blocked reason %s without exposing a machine code as UI copy', (reason) => {
    expect(provisioningBlockedReason(reason)).not.toContain(reason)
    expect(provisioningBlockedReason(reason)).not.toBe(provisioningBlockedReason('future_reason'))
  })

  it('does not fetch provisioning metadata for active or missing records', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch')
    const { client, rerender } = renderNotice({ target: { ...account, status: 'active' } })
    await act(async () => {})
    rerender(
      <QueryClientProvider client={client}>
        <Harness target={{ ...account, status: 'missing' }} />
      </QueryClientProvider>,
    )
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('shows running status without a recovery action', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ ...failed, state: 'running', recoverable: false }))
    renderNotice()
    expect(await screen.findByText('Создание выполняется')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
  })

  it('shows failed creation to readonly users without a recovery action', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(failed))
    renderNotice({ isAdmin: false })
    expect(await screen.findByText('Создание не удалось')).toBeInTheDocument()
    expect(screen.getByText(/Восстановить запись из кластера может администратор/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Открыть операцию' }))
      .toHaveAttribute('href', '/control?tab=operations&operation=failed-create-operation')
  })

  it('explains unavailable state and offers a safe read retry only', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      ...failed,
      state: 'unavailable',
      recoverable: false,
      blocked_reason: 'no_failed_creation',
    }))
    renderNotice()
    expect(await screen.findByText('Статус создания недоступен')).toBeInTheDocument()
    expect(screen.getByText(/Не найдена завершившаяся с ошибкой операция создания/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Проверить состояние' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
  })

  it('fails closed after a read error even when recoverable data remains cached', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(failed))
      .mockRejectedValueOnce(new TypeError('offline'))
      .mockResolvedValue(response(failed))
    renderNotice()
    expect(await screen.findByRole('button', { name: 'Восстановить из кластера' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Проверить состояние' }))
    expect(await screen.findByText('Статус создания недоступен')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent('Восстановление недоступно до успешной проверки')
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Проверить состояние' }))
    expect(await screen.findByRole('button', { name: 'Восстановить из кластера' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })
})

describe('verification-only account creation continuation', () => {
  it('lets an operator continue an already created account without a confirmation or another CREATE', async () => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const posts: Array<{ path: string; body: unknown }> = []
    let reads = 0
    const freshUpdatedAt = '2026-10-12T13:00:00.123456Z'
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const path = String(input)
      if (options?.method === 'POST') {
        posts.push({ path, body: JSON.parse(String(options.body)) })
        return response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending', verification_only: true }, 202)
      }
      reads++
      return response(reads === 1 ? verificationReady : { ...verificationReady, updated_at: freshUpdatedAt })
    })
    renderNotice({ isAdmin: false, canOperate: true, onStarted })
    expect(await screen.findByText('Учётка создана, проверка не завершена')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Продолжить создание' })).toHaveClass('grantor-touch-target')
    expect(screen.getByText(/Учётка уже создана/)).toHaveTextContent('Пароль не меняется, учётка повторно не создаётся')
    await user.click(screen.getByRole('button', { name: 'Продолжить создание' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(
      'verification-operation', `Проверка учётки · ${account.engine_identity}`, 'account',
    ))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(posts).toEqual([{
      path: `/api/v1/accounts/${account.id}/verify-creation`,
      body: {
        request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
        updated_at: freshUpdatedAt,
        operation_id: verificationReady.operation_id,
      },
    }])
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
  })

  it.each([
    { verification_ready: undefined },
    { verification_ready: false },
    { creation_phase: 'creating' },
    { creation_phase: 'planned' },
    { creation_phase: 'verified' },
    { operation_kind: 'postgres.account.create.v2' },
    { operation_kind: 'account.create' },
    { operation_status: 'running' },
    { state: 'running' },
    { state: 'unavailable' },
    { account_id: 'another-account' },
    { operation_id: '' },
    { updated_at: '' },
  ] satisfies Partial<AccountProvisioning>[])(
    'does not offer verification without the exact current server eligibility: %o', async (change) => {
      const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ ...verificationReady, ...change }))
      renderNotice()
      await waitFor(() => expect(screen.queryByText('Проверяем операцию создания…')).not.toBeInTheDocument())
      expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
      expect(fetchMock.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true)
    },
  )

  it('shows the saved state to a viewer without offering continuation', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(verificationReady))
    renderNotice({ isAdmin: false, canOperate: false })
    await screen.findByText('Учётка создана, проверка не завершена')
    expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
  })

  it('explains an unknown CREATE outcome and blocks all creation/recovery actions', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({
      ...verificationReady, creation_phase: 'creating', verification_ready: false,
      blocked_reason: 'creation_outcome_unknown', recoverable: true, retryable: true,
    }))
    renderNotice()
    expect(await screen.findByText('Результат создания не подтверждён')).toBeInTheDocument()
    expect(screen.getByText(/Сначала проверьте, появилась ли учётка в базе/)).toHaveTextContent('повторное создание не запускается')
    expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
  })

  it.each([
    { verification_ready: false, blocked_reason: 'creation_intent_changed' },
    { account_id: 'another-account' },
    { operation_id: 'another-source-operation' },
    { state: 'running' },
  ] satisfies Partial<AccountProvisioning>[])(
    'rechecks eligibility on click and never submits against a changed source: %o', async (change) => {
      const user = userEvent.setup()
      const fetchMock = vi.spyOn(globalThis, 'fetch')
        .mockResolvedValueOnce(response(verificationReady))
        .mockResolvedValue(response({ ...verificationReady, ...change }))
      const onStarted = vi.fn()
      renderNotice({ onStarted })
      await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
      expect(await screen.findByText(/Состояние создания изменилось или недоступно/)).toBeInTheDocument()
      expect(fetchMock.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true)
      expect(onStarted).not.toHaveBeenCalled()
    },
  )

  it('does not use cached eligibility after a failed fresh read', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(response(verificationReady))
      .mockRejectedValue(new TypeError('offline'))
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    expect(await screen.findByText(/Состояние создания изменилось или недоступно/)).toBeInTheDocument()
    expect(screen.getByText(/Не удалось проверить создание/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
    expect(fetchMock.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true)
  })

  it('serializes double clicks while checking freshness and awaiting the POST response', async () => {
    const onStarted = vi.fn()
    const posts: unknown[] = []
    let reads = 0
    let finishFresh!: (value: Response) => void
    let finishPost!: (value: Response) => void
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, options) => {
      if (options?.method === 'POST') {
        posts.push(JSON.parse(String(options.body)))
        return new Promise<Response>((resolve) => { finishPost = resolve })
      }
      reads++
      if (reads === 2) return new Promise<Response>((resolve) => { finishFresh = resolve })
      return response(verificationReady)
    })
    renderNotice({ onStarted })
    const button = await screen.findByRole('button', { name: 'Продолжить создание' })
    fireEvent.click(button)
    fireEvent.click(button)
    expect(screen.getByRole('button', { name: 'Проверяем…' })).toBeDisabled()
    expect(posts).toHaveLength(0)
    await act(async () => finishFresh(response(verificationReady)))
    await waitFor(() => expect(posts).toHaveLength(1))
    fireEvent.click(screen.getByRole('button', { name: 'Проверяем…' }))
    expect(posts).toHaveLength(1)
    await act(async () => finishPost(response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending', verification_only: true })))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
  })

  it.each(['lost', 'malformed', 'wrong-account', 'missing-marker', '408', '429', '503'])(
    'retains the exact request after an uncertain %s acknowledgement', async (failure) => {
      const user = userEvent.setup()
      const posts: Array<{ path: string; body: unknown }> = []
      const onStarted = vi.fn()
      vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
        if (options?.method !== 'POST') return response(verificationReady)
        posts.push({ path: String(input), body: JSON.parse(String(options.body)) })
        if (posts.length === 1) {
          if (failure === 'lost') throw new TypeError('response lost')
          if (failure === 'malformed') return response({})
          if (failure === 'wrong-account') return response({ account_id: 'other-account', operation_id: 'verification-operation', status: 'pending', verification_only: true })
          if (failure === 'missing-marker') return response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending' })
          return response({ error: 'request acknowledgement unavailable' }, Number(failure))
        }
        return response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending', verification_only: true, deduplicated: true }, 202)
      })
      const { client } = renderNotice({ onStarted })
      await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
      expect(await screen.findByText(/Результат запроса не подтверждён/)).toBeInTheDocument()
      expect(onStarted).not.toHaveBeenCalled()
      act(() => { client.setQueryData(qk.accountProvisioning(account.id), { ...verificationReady, state: 'unavailable', verification_ready: false }) })
      await user.click(screen.getByRole('button', { name: 'Повторить запрос проверки' }))
      await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
      expect(posts).toHaveLength(2)
      expect(posts[1]).toEqual(posts[0])
      expect(posts.every((post) => post.path.endsWith('/verify-creation'))).toBe(true)
      expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    },
  )

  it('releases the request after a definite rejection and requires a new successful check', async () => {
    const user = userEvent.setup()
    const posts: Array<{ request_id: string }> = []
    let ready = true
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (_input, options) => {
      if (options?.method !== 'POST') return response({ ...verificationReady, verification_ready: ready })
      posts.push(JSON.parse(String(options.body)))
      if (posts.length === 1) {
        ready = false
        return response({ error: 'account changed' }, 409)
      }
      return response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending', verification_only: true }, 202)
    })
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    expect(await screen.findByText(/Проверка не запущена/)).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument())
    expect(screen.queryByRole('button', { name: 'Повторить запрос проверки' })).not.toBeInTheDocument()
    ready = true
    await user.click(screen.getByRole('button', { name: 'Проверить состояние' }))
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    await waitFor(() => expect(posts).toHaveLength(2))
    expect(posts[1].request_id).not.toEqual(posts[0].request_id)
  })

  it('never replays an uncertain request to a different selected account', async () => {
    const user = userEvent.setup()
    const posts: string[] = []
    const other = { ...account, id: 'other-account', engine_identity: 'other-user' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (options?.method === 'POST') {
        posts.push(String(input))
        throw new TypeError('response lost')
      }
      return response(String(input).includes('other-account')
        ? { ...verificationReady, account_id: other.id, state: 'unavailable', verification_ready: false }
        : verificationReady)
    })
    const { client, rerender } = renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    await screen.findByRole('button', { name: 'Повторить запрос проверки' })
    rerender(<QueryClientProvider client={client}><Harness target={other} /></QueryClientProvider>)
    await screen.findByText('Статус создания недоступен')
    expect(screen.queryByRole('button', { name: 'Повторить запрос проверки' })).not.toBeInTheDocument()
    expect(posts).toEqual([`/api/v1/accounts/${account.id}/verify-creation`])
  })

  it('ignores an old acknowledgement after the selected account changes', async () => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    let finishPost!: (value: Response) => void
    const other = { ...account, id: 'other-account' }
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (options?.method === 'POST') return new Promise<Response>((resolve) => { finishPost = resolve })
      return response(String(input).includes('other-account')
        ? { ...verificationReady, account_id: other.id, state: 'unavailable', verification_ready: false }
        : verificationReady)
    })
    const { client, rerender } = renderNotice({ onStarted })
    await user.click(await screen.findByRole('button', { name: 'Продолжить создание' }))
    await waitFor(() => expect(finishPost).toBeDefined())
    rerender(<QueryClientProvider client={client}><Harness target={other} onStarted={onStarted} /></QueryClientProvider>)
    await act(async () => finishPost(response({ account_id: account.id, operation_id: 'verification-operation', status: 'pending', verification_only: true })))
    expect(onStarted).not.toHaveBeenCalled()
  })
})

describe('account provisioning recovery', () => {
  it('keeps an absent group recoverable and never retries its CREATE automatically after failed discovery', async () => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const path = String(input)
      if (options?.method === 'POST') posts.push(path)
      if (path === `/api/v1/accounts/${account.id}/provisioning`) {
        return response({ ...failed, operation_kind: 'role.create' })
      }
      if (path.endsWith('/recover-provisioning')) {
        return response({ account_id: account.id, operation_id: 'absent-group-discovery', status: 'failed', deduplicated: true })
      }
      if (path === '/api/v1/operations/absent-group-discovery') {
        return response({ id: 'absent-group-discovery', kind: 'connection.discover', status: 'failed', error: 'account was not observed in the target snapshot' })
      }
      if (path === `/api/v1/operations/${failed.operation_id}/retry`) {
        return response({ operation_id: failed.operation_id, retried: [failed.operation_id], skipped_cancelled: [] })
      }
      throw new Error(`unexpected request: ${path}`)
    })
    renderNotice({ target: { ...account, kind: 'group' }, onStarted })
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('Если запись не найдена или кластер недоступен')
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' }))
    expect(await screen.findByText(/Восстановление не завершено/)).toBeInTheDocument()
    expect(await screen.findByRole('button', { name: 'Повторить создание' })).toBeInTheDocument()
    expect(posts).toEqual([`/api/v1/accounts/${account.id}/recover-provisioning`])

    await user.click(screen.getByRole('button', { name: 'Повторить создание' }))
    const dialog = screen.getByRole('dialog', { name: 'Повторить создание' })
    expect(dialog).toHaveTextContent('Это изменение кластера, а не проверка существующей записи')
    expect(posts).toHaveLength(1)
    await user.click(within(dialog).getByRole('button', { name: 'Повторить создание' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(
      failed.operation_id, `Повтор создания · ${account.engine_identity}`, 'account',
    ))
    expect(posts).toEqual([
      `/api/v1/accounts/${account.id}/recover-provisioning`,
      `/api/v1/operations/${failed.operation_id}/retry`,
    ])
  })

  it.each(['login', 'group'])('confirms metadata-only recovery and starts fresh discovery for a %s', async (kind) => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const posts: unknown[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const path = String(input)
      if (path === `/api/v1/accounts/${account.id}/provisioning`) return response(failed)
      if (path === `/api/v1/accounts/${account.id}/recover-provisioning`) {
        posts.push(JSON.parse(String(options?.body)))
        return response({ account_id: account.id, operation_id: 'fresh-discovery', status: 'pending' }, 202)
      }
      throw new Error(`unexpected request: ${path}`)
    })
    const { client } = renderNotice({ target: { ...account, kind }, onStarted })
    const invalidate = vi.spyOn(client, 'invalidateQueries')
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    const dialog = screen.getByRole('dialog', { name: 'Восстановить из кластера' })
    expect(dialog).toHaveTextContent('её пароль, права и владение базами не изменятся')
    expect(dialog).toHaveTextContent('Только после подтверждения Grantor снимет незавершённое создание и перестанет использовать непроверенный пароль')
    expect(posts).toHaveLength(0)
    await user.click(within(dialog).getByRole('button', { name: 'Восстановить из кластера' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(
      'fresh-discovery', `Восстановление из кластера · ${account.engine_identity}`, 'account',
    ))
    expect(posts).toEqual([{
      request_id: expect.stringMatching(/^[0-9a-f-]{36}$/),
      updated_at: failed.updated_at,
      operation_id: failed.operation_id,
    }])
    expect(invalidate).toHaveBeenCalledWith({ queryKey: qk.connection(account.connection_id) })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: qk.accounts() })
    expect(invalidate).toHaveBeenCalledWith({ queryKey: qk.operations() })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('does not POST when confirmation is cancelled', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(failed))
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Отмена' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('reuses the exact request after a lost response even if provisioning is already released', async () => {
    const user = userEvent.setup()
    const posts: unknown[] = []
    const onStarted = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const path = String(input)
      if (path === `/api/v1/accounts/${account.id}/provisioning`) return response(failed)
      if (path === `/api/v1/accounts/${account.id}/recover-provisioning`) {
        posts.push(JSON.parse(String(options?.body)))
        if (posts.length === 1) throw new TypeError('response lost')
        return response({ account_id: account.id, operation_id: 'fresh-discovery', status: 'pending', deduplicated: true }, 202)
      }
      throw new Error(`unexpected request: ${path}`)
    })
    const { client } = renderNotice({ onStarted })
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' }))
    expect(await screen.findByText(/Результат запроса не подтверждён/)).toBeInTheDocument()
    act(() => {
      client.setQueryData(qk.accountProvisioning(account.id), {
        ...failed, state: 'unavailable', recoverable: false, blocked_reason: 'not_provisioning',
      })
    })
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить запрос' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledTimes(1))
    expect(posts).toHaveLength(2)
    expect(posts[1]).toEqual(posts[0])
  })

  it('prevents duplicate submissions while awaiting a response', async () => {
    const user = userEvent.setup()
    const posts: unknown[] = []
    let resolvePost!: (value: Response) => void
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (String(input).endsWith('/recover-provisioning')) {
        posts.push(JSON.parse(String(options?.body)))
        return new Promise<Response>((resolve) => { resolvePost = resolve })
      }
      return response(failed)
    })
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    const confirm = within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' })
    await user.dblClick(confirm)
    expect(confirm).toBeDisabled()
    expect(posts).toHaveLength(1)
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await act(async () => resolvePost(response({ account_id: account.id, operation_id: 'discovery', status: 'pending' }, 202)))
  })

  it('does not claim a successful recovery from an incomplete response', async () => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => (
      response(String(input).endsWith('/recover-provisioning') ? {} : failed)
    ))
    renderNotice({ onStarted })
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' }))
    expect(await screen.findByText(/Результат запроса не подтверждён/)).toBeInTheDocument()
    expect(onStarted).not.toHaveBeenCalled()
    expect(screen.queryByText(/Синхронизация запущена/)).not.toBeInTheDocument()
  })

  it('requires a fresh successful eligibility check after a deterministic rejection', async () => {
    const user = userEvent.setup()
    let rejected = false
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      if (String(input).endsWith('/recover-provisioning')) {
        rejected = true
        return response({ error: 'account has managed bindings' }, 409)
      }
      return response(rejected ? { ...failed, recoverable: false, blocked_reason: 'managed_bindings' } : failed)
    })
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Восстановить из кластера' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' }))
    expect(await screen.findByText(/Восстановление не запущено/)).toBeInTheDocument()
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Восстановить из кластера' })).toBeDisabled()
    expect(within(screen.getByRole('dialog')).getByText(/У записи есть управляемые права/)).toBeInTheDocument()
  })
})

describe('explicit creation retry', () => {
  it('keeps explicit CREATE retry available for a known absent account with the new source kind', async () => {
    const user = userEvent.setup()
    const posts: string[] = []
    const onStarted = vi.fn()
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (options?.method === 'POST') {
        posts.push(String(input))
        return response({ operation_id: failed.operation_id, retried: [failed.operation_id], skipped_cancelled: [] })
      }
      return response({
        ...verificationReady, creation_phase: 'planned', verification_ready: false, retryable: true,
      })
    })
    renderNotice({ isAdmin: false, canOperate: true, onStarted })
    await user.click(await screen.findByRole('button', { name: 'Повторить создание' }))
    expect(screen.queryByRole('button', { name: 'Продолжить создание' })).not.toBeInTheDocument()
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить создание' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledOnce())
    expect(posts).toEqual([`/api/v1/operations/${failed.operation_id}/retry`])
  })

  it.each(['account.create', 'role.create'])('lets an operator retry the verified %s source after confirmation only', async (operationKind) => {
    const user = userEvent.setup()
    const onStarted = vi.fn()
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      const path = String(input)
      if (options?.method === 'POST') {
        posts.push(path)
        return response({ operation_id: failed.operation_id, retried: [failed.operation_id], skipped_cancelled: [] })
      }
      return response({ ...failed, operation_kind: operationKind })
    })
    renderNotice({ isAdmin: false, canOperate: true, onStarted })
    await user.click(await screen.findByRole('button', { name: 'Повторить создание' }))
    expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
    expect(posts).toHaveLength(0)
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить создание' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(
      failed.operation_id, `Повтор создания · ${account.engine_identity}`, 'account',
    ))
    expect(posts).toEqual([`/api/v1/operations/${failed.operation_id}/retry`])
  })

  it('never offers a retry without server permission or for another account', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(response({ ...failed, retryable: false }))
    const { client } = renderNotice()
    expect(await screen.findByText('Создание не удалось')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
    act(() => { client.setQueryData(qk.accountProvisioning(account.id), { ...failed, account_id: 'other-account' }) })
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Повторить создание' })).not.toBeInTheDocument()
      expect(screen.queryByRole('button', { name: 'Восстановить из кластера' })).not.toBeInTheDocument()
    })
  })

  it('does not silently switch source operations after opening the confirmation', async () => {
    const user = userEvent.setup()
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(response(failed))
    const { client } = renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Повторить создание' }))
    act(() => {
      client.setQueryData(qk.accountProvisioning(account.id), { ...failed, operation_id: 'another-create-operation' })
    })
    await waitFor(() => expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить создание' })).toBeDisabled())
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('checks status after a lost retry response and does not retry CREATE automatically', async () => {
    const user = userEvent.setup()
    const posts: string[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, options) => {
      if (options?.method === 'POST') {
        posts.push(String(input))
        throw new TypeError('response lost')
      }
      return response(posts.length === 0 ? failed : { ...failed, state: 'running', retryable: false, recoverable: false })
    })
    renderNotice()
    await user.click(await screen.findByRole('button', { name: 'Повторить создание' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить создание' }))
    expect(await screen.findByText('Операция уже выполняется.')).toBeInTheDocument()
    expect(within(screen.getByRole('dialog')).getByRole('button', { name: 'Повторить создание' })).toBeDisabled()
    expect(posts).toEqual([`/api/v1/operations/${failed.operation_id}/retry`])
  })
})
