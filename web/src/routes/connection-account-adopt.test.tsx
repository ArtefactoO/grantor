import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account } from '../lib/types'
import { AdoptAccountDialog } from './connection-account-dialogs'

// Регрессия на семантику adopt: режимы «подтвердить существующий пароль» и
// «задать новый» обязаны различаться и в подписях, и в отправляемом теле.
// Прежний единственный режим «Задать пароль» назывался так, будто пароль
// проверяется, а на деле перезаписывал его на целевой системе — опечатка
// оператора тихо ломала приложение, пользующееся учёткой.

const account: Account = {
  id: 'account-unmanaged',
  principal_id: null,
  connection_id: 'connection',
  kind: 'login',
  engine_identity: 'legacy_app',
  authentication_scope: '',
  credential_mode: null,
  vault_path: '',
  status: 'active',
  ownership: 'unmanaged',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

function renderAdopt() {
  const onClose = vi.fn()
  const onAdopted = vi.fn()
  render(
    <AdoptAccountDialog
      open
      account={account}
      unmanagedBindings={[]}
      permissionsById={new Map()}
      onClose={onClose}
      onAdopted={onAdopted}
    />,
    { wrapper: Wrapper },
  )
  return { onClose, onAdopted }
}

describe('AdoptAccountDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('names all four modes and says honestly which of them change the password', () => {
    renderAdopt()

    expect(screen.getByText('Принять без пароля')).toBeInTheDocument()
    expect(screen.getByText('Подтвердить текущий пароль')).toBeInTheDocument()
    expect(screen.getByText('Задать новый пароль')).toBeInTheDocument()
    expect(screen.getByText('Сгенерировать новый пароль')).toBeInTheDocument()

    // Подтверждение обещает неизменность учётки, оба «новых пароля» —
    // прямым текстом замену.
    expect(screen.getByText(/Пароль учётки НЕ меняется/)).toBeInTheDocument()
    expect(
      screen.getByText(/будет ЗАМЕНЁН на введённый: прежний перестанет работать/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/будет ЗАМЕНЁН сгенерированным: прежний перестанет работать/),
    ).toBeInTheDocument()
  })

  it('sends verify_password with the existing password and labels the field accordingly', async () => {
    const fetchMock = vi.fn(async (_path: string, _options?: RequestInit) =>
      jsonResponse(202, {
        account_id: account.id,
        operation_id: 'operation-verify',
        adopted_bindings: 0,
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const { onAdopted } = renderAdopt()
    const secret = 'RealPass123'

    await user.click(screen.getByText('Подтвердить текущий пароль'))
    await user.type(screen.getByLabelText('Текущий пароль учётки'), secret)
    await user.click(screen.getByRole('button', { name: 'Взять под управление' }))

    await waitFor(() =>
      expect(onAdopted).toHaveBeenCalledWith({
        operationId: 'operation-verify',
        adoptedBindings: 0,
      }),
    )
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [path, options] = fetchMock.mock.calls[0]
    expect(path).toBe(`/api/v1/accounts/${account.id}/adopt`)
    expect(JSON.parse(String(options?.body))).toEqual({
      mode: 'verify_password',
      password: secret,
      adopt_bindings: false,
    })
  })

  it('sends set_password (never the legacy password mode) when a new password is set', async () => {
    const fetchMock = vi.fn(async (_path: string, _options?: RequestInit) =>
      jsonResponse(202, {
        account_id: account.id,
        operation_id: 'operation-set',
        adopted_bindings: 0,
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderAdopt()

    await user.click(screen.getByText('Задать новый пароль'))
    await user.type(screen.getByLabelText('Новый пароль'), 'BrandNewPass1')
    await user.click(screen.getByRole('button', { name: 'Взять под управление' }))

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1))
    const [, options] = fetchMock.mock.calls[0]
    expect(JSON.parse(String(options?.body))).toEqual({
      mode: 'set_password',
      password: 'BrandNewPass1',
      adopt_bindings: false,
    })
  })

  it('shows the server refusal for engines that cannot confirm a password', async () => {
    const fetchMock = vi.fn(async (_path: string, _options?: RequestInit) =>
      jsonResponse(409, {
        error: 'engine "kafka" cannot confirm an existing password',
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    renderAdopt()

    await user.click(screen.getByText('Подтвердить текущий пароль'))
    await user.type(screen.getByLabelText('Текущий пароль учётки'), 'RealPass123')
    await user.click(screen.getByRole('button', { name: 'Взять под управление' }))

    expect(await screen.findByText(/cannot confirm an existing password/)).toBeInTheDocument()
  })
})
