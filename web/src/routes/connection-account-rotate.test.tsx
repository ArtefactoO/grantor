// Регрессия на осознанный выбор при ротации аккаунта на общем пароле
// пользователя. Проверяется весь путь панели: кнопка «Ротация» → 409
// shared_credential_requires_choice от бэкенда → диалог выбора без
// предвыбранного варианта → оба маршрута (общий пароль и отвязка).
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection, SharedCredentialChoice } from '../lib/types'
import { ApiError } from '../lib/api'
import { AccountDetailPanel } from './connection-account-panel'
import { sharedCredentialChoice } from './connection-account-rotate'

// Панель привязанного аккаунта рисует ссылку на пользователя; роутер этим
// тестам не нужен — сценарий про ротацию, а не про навигацию.
vi.mock('@tanstack/react-router', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@tanstack/react-router')>()
  return {
    ...actual,
    Link: ({ children }: { children: ReactNode }) => <span>{children}</span>,
  }
})

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'operator@example.com', role: 'operator', csrfToken: 'csrf' }),
  }
})

const account: Account = {
  id: 'account-1',
  principal_id: 'principal-1',
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'reports_bot',
  authentication_scope: '',
  credential_mode: 'existing_vault_ref',
  vault_path: 'principals/principal-1/environments/prod/credential',
  status: 'active',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

const connection: Connection = {
  id: 'connection-1',
  display_name: 'postgres-prod',
  engine: 'postgres',
  environment: 'prod',
  tags: [],
  endpoints: [],
  execution_mode: 'direct',
  tls_config: {},
  admin_credential_mode: 'vault',
  vault_admin_path: '',
  capabilities: [],
  discovery_config: {},
  status: 'active',
  server_version: '16',
  topology: {},
  last_discovery_at: null,
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

function choiceContext(overrides: Partial<SharedCredentialChoice> = {}): SharedCredentialChoice {
  return {
    principal_id: 'principal-1',
    principal_display_name: 'Payments Service',
    environment: 'prod',
    affected_accounts: 3,
    affected_connections: [
      { connection_id: 'connection-1', display_name: 'postgres-prod', account_id: 'account-1' },
      { connection_id: 'connection-2', display_name: 'redis-prod', account_id: 'account-2' },
      { connection_id: 'connection-3', display_name: 'kafka-prod', account_id: 'account-3' },
    ],
    confirm_threshold: 2,
    requires_confirm: true,
    ...overrides,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function Wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>
}

interface RequestLogEntry {
  path: string
  body: unknown
}

// renderPanel поднимает панель аккаунта и отвечает на её запросы: ротация
// аккаунта без намерения — 409 с контекстом выбора (как у бэкенда).
function renderPanel(choice: SharedCredentialChoice) {
  const requests: RequestLogEntry[] = []
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const path = String(input)
    const body =
      init?.body !== undefined && init.body !== null
        ? (JSON.parse(String(init.body)) as unknown)
        : undefined
    if (path === '/api/v1/accounts/account-1/bindings?category=roles') return jsonResponse(200, { bindings: [] })
    if (path === '/api/v1/principals') return jsonResponse(200, { principals: [] })
    if (path === '/api/v1/accounts/account-1/rotate') {
      requests.push({ path, body })
      if (body === undefined) {
        return jsonResponse(409, {
          error: 'account shares the credential of its principal',
          code: 'shared_credential_requires_choice',
          shared_credential: choice,
        })
      }
      return jsonResponse(202, {
        account_id: 'account-1',
        operation_id: 'operation-detach',
        vault_path: 'accounts/account-1/credential',
        detached: true,
      })
    }
    if (path.startsWith('/api/v1/principals/principal-1/rotate')) {
      requests.push({ path, body })
      return jsonResponse(202, { operation_id: 'operation-shared', children: [] })
    }
    throw new Error(`unexpected request: ${path}`)
  })
  const onNotice = vi.fn()
  const onOperationStarted = vi.fn()
  render(
    <Wrapper>
      <AccountDetailPanel
        account={account}
        connection={connection}
        permissions={[]}
        permissionsById={new Map()}
        resourcesById={new Map()}
        onClose={vi.fn()}
        onNotice={onNotice}
        onOperationStarted={onOperationStarted}
      />
    </Wrapper>,
  )
  return { requests, onNotice, onOperationStarted }
}

/** Кнопка действия внутри диалога выбора (не кнопка «Ротация» панели). */
function submitButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: 'Ротировать' })
}

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('выбор при ротации аккаунта на общем пароле', () => {
  it('открывает диалог без предвыбранного варианта и с неактивной кнопкой', async () => {
    const user = userEvent.setup()
    renderPanel(choiceContext())

    await user.click(screen.getByRole('button', { name: 'Ротировать пароль' }))

    // Диалог показывает контекст: пользователя, окружение и масштаб.
    expect(await screen.findByText(/Ротация пароля: reports_bot/)).toBeInTheDocument()
    expect(screen.getByText(/Payments Service/)).toBeInTheDocument()
    expect(screen.getByText(/postgres-prod, redis-prod, kafka-prod/)).toBeInTheDocument()

    // Ничего не предвыбрано, действие недоступно.
    for (const radio of screen.getAllByRole('radio')) {
      expect(radio).not.toBeChecked()
    }
    expect(submitButton()).toBeDisabled()
    // Чекбокса подтверждения до выбора варианта нет.
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('требует чекбокс подтверждения для общего пароля выше порога', async () => {
    const user = userEvent.setup()
    const { requests, onOperationStarted } = renderPanel(choiceContext())

    await user.click(screen.getByRole('button', { name: 'Ротировать пароль' }))
    await screen.findByText(/Ротация пароля: reports_bot/)
    await user.click(screen.getByText('Ротировать общий пароль'))

    // Чекбокс появляется в этом же диалоге, второго окна нет.
    const confirm = screen.getByRole('checkbox', {
      name: /Понимаю, что пароль сменится в 3 системах/,
    })
    expect(submitButton()).toBeDisabled()

    await user.click(confirm)
    expect(submitButton()).toBeEnabled()
    await user.click(submitButton())

    await waitFor(() => expect(onOperationStarted).toHaveBeenCalled())
    const rotate = requests.filter((r) => r.path.startsWith('/api/v1/principals/'))
    expect(rotate).toHaveLength(1)
    expect(rotate[0].path).toBe('/api/v1/principals/principal-1/rotate?environment=prod')
    expect(rotate[0].body).toEqual({ confirm: true })
    expect(onOperationStarted).toHaveBeenCalledWith(
      'operation-shared',
      expect.stringContaining('ротация общего пароля пользователя'),
      'account',
    )
  })

  it('не требует чекбокс, когда затронутых аккаунтов не больше порога', async () => {
    const user = userEvent.setup()
    const { requests } = renderPanel(
      choiceContext({
        affected_accounts: 2,
        requires_confirm: false,
        affected_connections: [
          { connection_id: 'connection-1', display_name: 'postgres-prod', account_id: 'account-1' },
          { connection_id: 'connection-2', display_name: 'redis-prod', account_id: 'account-2' },
        ],
      }),
    )

    await user.click(screen.getByRole('button', { name: 'Ротировать пароль' }))
    await screen.findByText(/Ротация пароля: reports_bot/)
    await user.click(screen.getByText('Ротировать общий пароль'))

    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(submitButton()).toBeEnabled()
    await user.click(submitButton())

    await waitFor(() =>
      expect(requests.some((r) => r.path.startsWith('/api/v1/principals/'))).toBe(true),
    )
    const rotate = requests.find((r) => r.path.startsWith('/api/v1/principals/'))
    expect(rotate?.body).toEqual({ confirm: false })
  })

  it('отвязывает аккаунт вторым вариантом — без чекбокса и второго окна', async () => {
    const user = userEvent.setup()
    const { requests, onOperationStarted } = renderPanel(choiceContext())

    await user.click(screen.getByRole('button', { name: 'Ротировать пароль' }))
    await screen.findByText(/Ротация пароля: reports_bot/)
    await user.click(screen.getByText('Отвязать и выдать собственный пароль'))

    // Отвязка затрагивает только этот аккаунт: подтверждение не нужно.
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(submitButton()).toBeEnabled()
    await user.click(submitButton())

    await waitFor(() => expect(onOperationStarted).toHaveBeenCalled())
    expect(requests.filter((r) => r.path.startsWith('/api/v1/principals/'))).toHaveLength(0)
    const detach = requests.filter((r) => r.path === '/api/v1/accounts/account-1/rotate')
    // Первый запрос — тот самый пробный без намерения (он и принёс контекст).
    expect(detach.map((r) => r.body)).toEqual([undefined, { detach: true }])
  })

  it('на аккаунте с личным паролем оставляет прежний короткий confirm', async () => {
    const user = userEvent.setup()
    const requests: RequestLogEntry[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return jsonResponse(200, { bindings: [] })
      if (path === '/api/v1/principals') return jsonResponse(200, { principals: [] })
      requests.push({
        path,
        body: init?.body != null ? (JSON.parse(String(init.body)) as unknown) : undefined,
      })
      return jsonResponse(202, { account_id: 'account-1', operation_id: 'operation-plain' })
    })
    render(
      <Wrapper>
        <AccountDetailPanel
          account={{ ...account, credential_mode: 'generated', vault_path: 'accounts/account-1' }}
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.click(screen.getByRole('button', { name: 'Ротировать пароль' }))

    // Прежний диалог подтверждения, а не выбор: лишнего клика не добавилось.
    expect(await screen.findByRole('dialog', { name: 'Ротация пароля' })).toBeInTheDocument()
    expect(screen.queryByText('Ротировать общий пароль')).not.toBeInTheDocument()
    expect(requests).toHaveLength(0)
  })

  it('возвращает отвязанный аккаунт на общий пароль пользователя', async () => {
    const user = userEvent.setup()
    const requests: RequestLogEntry[] = []
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const path = String(input)
      if (path === '/api/v1/accounts/account-1/bindings?category=roles') return jsonResponse(200, { bindings: [] })
      if (path === '/api/v1/principals') return jsonResponse(200, { principals: [] })
      requests.push({
        path,
        body: init?.body != null ? (JSON.parse(String(init.body)) as unknown) : undefined,
      })
      return jsonResponse(202, {
        account_id: 'account-1',
        operation_id: 'operation-attach',
        vault_path: 'principals/principal-1/environments/prod/credential',
        attached: true,
      })
    })
    render(
      <Wrapper>
        <AccountDetailPanel
          account={{ ...account, credential_mode: 'generated', vault_path: 'accounts/account-1' }}
          connection={connection}
          permissions={[]}
          permissionsById={new Map()}
          resourcesById={new Map()}
          onClose={vi.fn()}
          onNotice={vi.fn()}
          onOperationStarted={vi.fn()}
        />
      </Wrapper>,
    )

    await user.click(screen.getByRole('button', { name: 'Вернуть на общий пароль' }))
    await user.click(screen.getByRole('button', { name: 'Вернуть' }))

    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0]).toEqual({
      path: '/api/v1/accounts/account-1/rotate',
      body: { attach: true },
    })
  })
})

describe('sharedCredentialChoice', () => {
  it('разбирает только 409 со своим кодом', () => {
    const choice = choiceContext()
    const conflict = new ApiError(409, 'conflict', 'shared_credential_requires_choice', {
      shared_credential: choice,
    })
    expect(sharedCredentialChoice(conflict)).toEqual(choice)

    // Прочие ошибки остаются обычными ошибками экрана.
    expect(sharedCredentialChoice(new ApiError(409, 'status conflict'))).toBeNull()
    expect(
      sharedCredentialChoice(new ApiError(409, 'other', 'rotation_requires_confirm', {})),
    ).toBeNull()
    expect(sharedCredentialChoice(new Error('network'))).toBeNull()
    // Код без контекста — не повод открывать пустой диалог.
    expect(
      sharedCredentialChoice(
        new ApiError(409, 'x', 'shared_credential_requires_choice', { shared_credential: null }),
      ),
    ).toBeNull()
  })
})
