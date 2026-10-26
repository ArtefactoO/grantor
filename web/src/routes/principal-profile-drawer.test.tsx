import { useState } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Account, Connection, Permission, PrincipalCredentialEnvironment, PrincipalDetail, Resource } from '../lib/types'
import { PrincipalProfileDrawer } from './principal-profile-drawer'
import { OFFBOARD_COUNTDOWN_SECONDS } from './principal-detail-actions'

vi.mock('../auth/AuthProvider', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../auth/AuthProvider')>()
  return {
    ...actual,
    useAuth: () => ({ email: 'admin@example.com', role: 'admin', csrfToken: 'csrf' }),
  }
})

const account: Account = {
  id: 'account-1',
  principal_id: 'principal-1',
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: 'deploy_bot',
  authentication_scope: '',
  credential_mode: 'existing_vault_ref',
  // Указатель обязан вести в раздел СВОЕГО принципала: только такой аккаунт
  // реально сидит на общем секрете окружения.
  vault_path: 'principals/principal-1/environments/prod/credential',
  status: 'active',
  ownership: 'managed',
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
}

function detail(status = 'active', purgeAfter: string | null = null): PrincipalDetail {
  return {
    id: 'principal-1',
    type: 'service',
    display_name: status === 'deleted' ? 'Deleted Bot' : 'Deploy Bot',
    external_provider: 'gitlab',
    external_subject: 'deploy-bot',
    external_identity_status: 'active',
    external_identity_checked_at: '2026-07-21T10:00:00Z',
    external_identity_status_changed_at: '2026-07-21T09:00:00Z',
    status,
    attributes: {},
    purge_after: purgeAfter,
    accounts: status === 'deleted' ? [{ ...account, status: 'deleted' }] : [account],
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  }
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

const permission: Permission = {
  id: 'permission-1',
  connection_id: connection.id,
  engine: 'postgres',
  external_id: 'role:deploy_role',
  name: 'deploy_role',
  scope_resource_id: null,
  assignable: true,
  status: 'observed',
  dangerous: false,
  attributes: {},
  created_at: '2026-07-20T00:00:00Z',
  updated_at: '2026-07-20T00:00:00Z',
    normalized: {
      category: 'role', action: '', resource: 'deploy_role', scope: '',
      dangerous: false, danger_reason: '', details: null, raw: 'deploy_role',
    },
}

let principalResponse = detail()
let connectionsResponse = [connection]
let credentialResponse: PrincipalCredentialEnvironment[] = [
  { environment: 'prod', connections: 1, configured: true },
]
let resourcesResponse: Resource[] = []

// Тело последнего POST /offboard: тесты проверяют, что согласие на чужие
// пароли уходит на бэкенд ровно тем, что отметил оператор.
let offboardBody: { takeover_credentials: boolean } | null = null

afterEach(() => {
  vi.useRealTimers()
})

beforeEach(() => {
  setWideViewport(false)
  offboardBody = null
  principalResponse = detail()
  connectionsResponse = [connection]
  credentialResponse = [{ environment: 'prod', connections: 1, configured: true }]
  resourcesResponse = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input)
      if (path === '/api/v1/principals/principal-1') {
        return new Response(JSON.stringify(principalResponse), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === '/api/v1/connections') {
        return new Response(JSON.stringify({ connections: connectionsResponse }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === '/api/v1/principals/principal-1/credentials') {
        if ((init?.method ?? 'GET') === 'POST') {
          const body = JSON.parse(String(init?.body)) as { environment: string }
          credentialResponse = credentialResponse.map((item) =>
            item.environment === body.environment ? { ...item, configured: true } : item,
          )
          return new Response(JSON.stringify({
            environment: body.environment,
            configured: true,
            created: true,
          }), { status: 201, headers: { 'content-type': 'application/json' } })
        }
        return new Response(JSON.stringify({ credentials: credentialResponse }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === '/api/v1/principals/principal-1/offboard?confirm=true') {
        offboardBody = JSON.parse(String(init?.body)) as { takeover_credentials: boolean }
        return new Response(JSON.stringify({
          operation_id: 'operation-1',
          children: [],
          unmanaged_accounts: [],
          credential_takeover_required: [],
        }), { status: 202, headers: { 'content-type': 'application/json' } })
      }
      if (path === '/api/v1/operations/operation-1') {
        return new Response(JSON.stringify({
          id: 'operation-1',
          kind: 'bulk.principal_offboard',
          status: 'success',
          aggregate_status: 'success',
          children: [],
        }), { status: 200, headers: { 'content-type': 'application/json' } })
      }
      if (path === '/api/v1/principals/principal-1/purge?confirm=true' && init?.method === 'DELETE') {
        return new Response(JSON.stringify({ principal_id: 'principal-1', purged: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === '/api/v1/accounts/account-1/bindings') {
        return new Response(JSON.stringify({
          bindings: [{
            id: 'binding-1',
            account_id: account.id,
            permission_definition_id: permission.id,
            scope_resource_id: null,
            source: 'service',
            desired_state: 'present',
            observed_state: 'present',
            status: 'synced',
            expires_at: null,
            created_at: '2026-07-20T00:00:00Z',
            updated_at: '2026-07-20T00:00:00Z',
          }],
        }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === `/api/v1/connections/${connection.id}/permissions`) {
        return new Response(JSON.stringify({ permissions: [permission] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path === `/api/v1/connections/${connection.id}/resources`) {
        return new Response(JSON.stringify({ resources: resourcesResponse }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      if (path.includes('/tokens')) {
        return new Response(JSON.stringify({ tokens: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      throw new Error(`unexpected fetch ${path}`)
    }),
  )
})

function Harness() {
  const [open, setOpen] = useState(false)
  const [backgroundActions, setBackgroundActions] = useState(0)
  const [client] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  )
  return (
    <QueryClientProvider client={client}>
      <button type="button" onClick={() => setOpen(true)}>Открыть Deploy Bot</button>
      <button type="button" onClick={() => setBackgroundActions((value) => value + 1)}>
        {`Фоновое действие: ${backgroundActions}`}
      </button>
      <PrincipalProfileDrawer
        principalId={open ? 'principal-1' : null}
        principalName={principalResponse.display_name}
        onClose={() => setOpen(false)}
      />
    </QueryClientProvider>
  )
}

describe('PrincipalProfileDrawer', () => {
  it.each([
    { kind: 'login', ownership: 'managed', label: 'Managed' },
    { kind: 'service', ownership: 'unmanaged', label: 'Unmanaged' },
    { kind: 'group', ownership: 'managed', label: null },
    { kind: 'group', ownership: 'unmanaged', label: null },
    { kind: 'role', ownership: 'managed', label: null },
    { kind: 'role', ownership: 'unmanaged', label: null },
  ])('limits ownership badges to target identities: $kind/$ownership', async ({ kind, ownership, label }) => {
    principalResponse = { ...detail(), accounts: [{ ...account, kind, ownership }] }
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    const row = await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' })
    if (label === null) {
      expect(within(row).queryByText(/^(Managed|Unmanaged)$/)).not.toBeInTheDocument()
    } else {
      expect(within(row).getByText(label)).toBeInTheDocument()
    }

    await user.click(row)
    const profile = screen.getByRole('dialog', { name: 'Deploy Bot' })
    if (label === null) {
      expect(within(profile).queryByText(/^(Managed|Unmanaged)$/)).not.toBeInTheDocument()
    } else {
      expect(within(profile).getByText(label)).toBeInTheDocument()
    }
  })

  it('shows direct database ownership in the account row and nested account profile', async () => {
    resourcesResponse = [
      {
        id: 'database-owned',
        connection_id: connection.id,
        parent_id: null,
        kind: 'database',
        external_id: 'database:analytics',
        name: 'analytics',
        canonical_path: 'analytics',
        attributes: { owner: account.engine_identity },
        fingerprint: 'database-owned',
        observed_at: '2026-08-25T00:00:00Z',
        status: 'observed',
        ownership: 'unmanaged',
        created_at: '2026-08-25T00:00:00Z',
        updated_at: '2026-08-25T00:00:00Z',
      },
      {
        id: 'database-role-owned',
        connection_id: connection.id,
        parent_id: null,
        kind: 'database',
        external_id: 'database:team_data',
        name: 'team_data',
        canonical_path: 'team_data',
        attributes: { owner: 'reporting_team' },
        fingerprint: 'database-role-owned',
        observed_at: '2026-08-25T00:00:00Z',
        status: 'observed',
        ownership: 'unmanaged',
        created_at: '2026-08-25T00:00:00Z',
        updated_at: '2026-08-25T00:00:00Z',
      },
    ]
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    const accountRow = await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' })
    const rowOwnership = await within(accountRow).findByLabelText('Базы во владении')
    expect(rowOwnership).toHaveTextContent('analytics')
    expect(rowOwnership).not.toHaveTextContent('team_data')

    await user.click(accountRow)
    const profileOwnership = await screen.findByLabelText('Базы во владении')
    expect(profileOwnership).toHaveTextContent('analytics')
    expect(profileOwnership).not.toHaveTextContent('team_data')
  })

  it('is modal below lg, traps focus and makes the page background inert', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const opener = screen.getByRole('button', { name: 'Открыть Deploy Bot' })

    await user.click(opener)
    const profile = await screen.findByRole('dialog', { name: 'Deploy Bot' })
    const close = screen.getByRole('button', { name: 'Закрыть профиль' })

    expect(profile).toHaveAttribute('aria-modal', 'true')
    expect(profile).toHaveAttribute('data-modal', 'true')
    expect(opener.closest('[aria-hidden="true"]')).not.toBeNull()
    await waitFor(() => expect(profile).toHaveFocus())
    expect(close).not.toHaveFocus()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()

    await user.tab()
    expect(close).toHaveFocus()
    await user.tab({ shift: true })
    expect(profile).toContainElement(document.activeElement as HTMLElement)
  })

  it('is a non-blocking inspector on wide screens', async () => {
    setWideViewport(true)
    const user = userEvent.setup()
    render(<Harness />)
    const opener = screen.getByRole('button', { name: 'Открыть Deploy Bot' })

    await user.click(opener)
    const profile = await screen.findByRole('dialog', { name: 'Deploy Bot' })

    expect(profile).not.toHaveAttribute('aria-modal')
    expect(profile).toHaveAttribute('data-modal', 'false')
    expect(document.querySelector('[data-slot="principal-profile-overlay"]')).toBeNull()
    expect(opener.closest('[aria-hidden="true"]')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'Фоновое действие: 0' }))
    expect(screen.getByRole('button', { name: 'Фоновое действие: 1' })).toBeInTheDocument()
    expect(profile).toBeInTheDocument()
  })

  it('opens nested factual account details, then Escape returns and closes with focus restore', async () => {
    const user = userEvent.setup()
    render(<Harness />)
    const opener = screen.getByRole('button', { name: 'Открыть Deploy Bot' })

    await user.click(opener)
    await user.click(await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' }))
    expect(screen.getByText('Credential mode')).toBeInTheDocument()
    expect(screen.getByText('existing_vault_ref')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    expect(await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' })).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })

  it('shows current role assignments beside the linked account', async () => {
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    const profile = await screen.findByRole('dialog', { name: 'Deploy Bot' })
    expect(within(profile).getAllByText('Deploy Bot')).toHaveLength(1)
    expect(await screen.findByText('Аккаунты и доступы')).toBeInTheDocument()
    expect(screen.getByRole('table', { name: 'Аккаунты и доступы пользователя' })).toBeInTheDocument()
    const accountRow = await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' })
    expect(accountRow).toHaveClass('space-y-2')
    expect(accountRow).not.toHaveClass('overflow-x-auto')
    expect(await screen.findByText('deploy_role')).toBeInTheDocument()
    const connectionLink = screen.getByRole('link', { name: /postgres-prod/ })
    expect(connectionLink).toHaveAttribute('href', '/connections/connection-1')
    expect(connectionLink).toHaveClass('ui-metadata-chip')
    const kindBadge = within(accountRow).getByTitle('Login · Service')
    const environmentChip = within(accountRow).getByText('PROD')
    expect(kindBadge.querySelector('[data-principal-type="service"]')).not.toBeNull()
    expect(kindBadge.parentElement).toContainElement(environmentChip)
    expect(screen.getByRole('combobox', { name: 'Фильтр по окружению' })).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Фильтр по подключению' })).toBeInTheDocument()
    const unlink = within(accountRow).getByRole('button', { name: 'Отвязать от пользователя' })
    expect(unlink).toHaveClass('ui-icon-button', 'size-6')
    expect(unlink).not.toHaveTextContent('Отвязать')
    expect(screen.getByText('Managed')).toBeInTheDocument()
    expect(screen.getAllByText('Active')).not.toHaveLength(0)
    expect(screen.getByText(/^создан:/)).toHaveClass('text-[11px]', 'text-faint')
  })

  it('focuses the token form instead of the dialog close action', async () => {
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    await user.click(await screen.findByRole('button', { name: 'Выпустить токен' }))

    const issueDialog = await screen.findByRole('dialog', { name: 'Выпустить токен' })
    expect(
      within(issueDialog).getByRole('textbox', { name: /^Имя/ }),
    ).toHaveFocus()
    expect(within(issueDialog).getByRole('button', { name: 'Закрыть' })).not.toHaveFocus()
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })

  it('uses a compact message when the principal has no linked accounts', async () => {
    principalResponse = { ...detail(), accounts: [] }
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    const message = await screen.findByText('Нет привязанных аккаунтов.')
    expect(message.parentElement).toHaveClass('py-2')
    expect(screen.getByText(/Выдайте доступ или свяжите существующий аккаунт/)).toBeInTheDocument()
  })

  it('renders a deleted principal and its account without mutating actions', async () => {
    principalResponse = detail('deleted')
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    expect(await screen.findByText('Deleted Bot')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Выдать доступ/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Ротировать пароль/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Получить учётные данные/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Вывести из системы/ })).not.toBeInTheDocument()

    await user.click(await screen.findByRole('row', { name: 'Открыть аккаунт deploy_bot' }))
    expect(screen.getByText(/только для просмотра/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Отвязать' })).not.toBeInTheDocument()
  })

  it('permanently removes an offboarded principal after its last account is gone', async () => {
    principalResponse = { ...detail('deleted'), accounts: [] }
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    await user.click(await screen.findByRole('button', { name: 'Удалить навсегда' }))
    const confirm = await screen.findByRole('dialog', { name: 'Удалить пользователя навсегда' })
    expect(confirm).toHaveTextContent('Исторический audit сохранится')
    await user.click(within(confirm).getByRole('button', { name: 'Удалить навсегда' }))

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })

  it('separates external identity state and shows the managed offboard scope', async () => {
    principalResponse = {
      ...detail(),
      external_identity_status: 'disabled',
    }
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    expect(await screen.findByText('gitlab · Disabled')).toBeInTheDocument()
    expect(screen.getByText('Credential по окружениям')).toBeInTheDocument()
    expect(screen.getByText('Configured')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Вывести из системы' }))
    expect(await screen.findByRole('dialog', { name: 'Вывести пользователя из системы' })).toBeInTheDocument()
    expect(await screen.findByText(/закроет доступ по managed-аккаунтам \(1\)/)).toBeInTheDocument()
    // Обещание закрыть и вход, а не только права, по обеим топологиям пароля.
    expect(await screen.findByText(/и личные пароли аккаунтов/)).toBeInTheDocument()
    expect(await screen.findByText(/1 активных доступов/)).toBeInTheDocument()
    // Диалог обязан обещать обратимость: она и есть суть нового поведения.
    expect(await screen.findByText(/Ничего не удаляется сразу/)).toBeInTheDocument()
  })

  // Аккаунт, принятый под управление без пароля: grantor им не владеет,
  // поэтому offboard по умолчанию его не трогает и требует явного согласия.
  it('asks for consent before rotating a password grantor does not own', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const adopted: Account = {
        ...account,
        id: 'account-2',
        engine_identity: 'legacy_bot',
        credential_mode: null,
        vault_path: '',
      }
      principalResponse = { ...detail(), accounts: [account, adopted] }
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      render(<Harness />)

      await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
      await user.click(await screen.findByRole('button', { name: 'Вывести из системы' }))
      const dialog = await screen.findByRole('dialog', { name: 'Вывести пользователя из системы' })

      expect(within(dialog).getByText(/Пароли 1 аккаунтов grantor не принадлежат/)).toBeInTheDocument()
      const consent = within(dialog).getByRole('checkbox')
      expect(consent).not.toBeChecked()

      await user.click(consent)
      await user.click(within(dialog).getByRole('button', { name: 'Вывести из системы' }))

      // Окно отмены: запрос не уходит, пока секунды не истекли.
      expect(offboardBody).toBeNull()
      await vi.advanceTimersByTimeAsync(OFFBOARD_COUNTDOWN_SECONDS * 1000)
      await waitFor(() => expect(offboardBody).toEqual({ takeover_credentials: true }))
    } finally {
      vi.useRealTimers()
    }
  })

  // Без согласия флаг уходит выключенным: молчаливое присвоение чужого
  // пароля — ровно то, от чего защищает чекбокс.
  it('offboards without takeover when consent is not given', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      render(<Harness />)

      await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
      await user.click(await screen.findByRole('button', { name: 'Вывести из системы' }))
      const dialog = await screen.findByRole('dialog', { name: 'Вывести пользователя из системы' })
      expect(within(dialog).queryByRole('checkbox')).not.toBeInTheDocument()
      await user.click(within(dialog).getByRole('button', { name: 'Вывести из системы' }))

      await vi.advanceTimersByTimeAsync(OFFBOARD_COUNTDOWN_SECONDS * 1000)
      await waitFor(() => expect(offboardBody).toEqual({ takeover_credentials: false }))
    } finally {
      vi.useRealTimers()
    }
  })

  // Окно отмены существует ради промаха: клик «Отменить» до истечения секунд
  // не отправляет НИЧЕГО — состояние не меняется ни в grantor, ни на целях.
  it('cancels an armed offboard before the countdown fires', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime.bind(vi) })
      render(<Harness />)

      await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
      await user.click(await screen.findByRole('button', { name: 'Вывести из системы' }))
      const dialog = await screen.findByRole('dialog', { name: 'Вывести пользователя из системы' })
      await user.click(within(dialog).getByRole('button', { name: 'Вывести из системы' }))

      expect(await screen.findByText(/начнётся через/)).toBeInTheDocument()
      await user.click(screen.getByRole('button', { name: 'Отменить' }))

      await vi.advanceTimersByTimeAsync(OFFBOARD_COUNTDOWN_SECONDS * 1000 + 1000)
      expect(offboardBody).toBeNull()
      expect(screen.queryByText(/начнётся через/)).not.toBeInTheDocument()
      expect(screen.getByText(/ничего не изменилось/i)).toBeInTheDocument()
    } finally {
      vi.useRealTimers()
    }
  })

  it('shows connection environments without accounts and creates their Vault credential', async () => {
    connectionsResponse = [
      connection,
      { ...connection, id: 'connection-2', display_name: 'postgres-test', environment: 'test' },
    ]
    credentialResponse = [
      { environment: 'prod', connections: 1, configured: true },
      { environment: 'test', connections: 1, configured: false },
    ]
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    expect(await screen.findByText('test')).toBeInTheDocument()
    expect(screen.getByText('подключений: 1 · аккаунтов: 0')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Создать' }))
    expect(await screen.findByRole('dialog', { name: 'Создать credential' })).toBeInTheDocument()
    expect(screen.getByText(/автоматически переиспользуется/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Создать' }))

    await waitFor(() => {
      const calls = vi.mocked(fetch).mock.calls
      const call = calls.find(([path, init]) =>
        String(path).endsWith('/credentials') && init?.method === 'POST')
      expect(call).toBeDefined()
      expect(JSON.parse(String(call?.[1]?.body))).toEqual({ environment: 'test', mode: 'generated' })
    })
    expect(await screen.findByText('Credential для окружения test создан в Vault')).toBeInTheDocument()
  })

  // Вывод из системы обратим до истечения срока: экран обязан это показать
  // и дать возврат, иначе восстановление снова превращается в ручные вызовы.
  it('offers to cancel an offboarding that is still reversible', async () => {
    principalResponse = detail('pending_purge', '2026-08-28T10:00:00Z')
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    expect(await screen.findByText('Пользователь выводится из системы')).toBeInTheDocument()
    expect(screen.getByText(/восстановить можно до/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Отменить вывод/ })).toBeInTheDocument()
  })

  // Раньше один сбой метаданных Vault ронял всю секцию баннером; строка с
  // неизвестным состоянием не должна предлагать «Создать».
  it('renders an unknown credential state without failing the section', async () => {
    credentialResponse = [
      { environment: 'prod', connections: 1, configured: null },
    ]
    const user = userEvent.setup()
    render(<Harness />)

    await user.click(screen.getByRole('button', { name: 'Открыть Deploy Bot' }))
    expect(await screen.findByText('Unknown')).toBeInTheDocument()
    expect(screen.queryByText('failed to inspect credential metadata')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Создать' })).not.toBeInTheDocument()
  })
})

function setWideViewport(matches: boolean) {
  vi.stubGlobal('matchMedia', vi.fn().mockImplementation((query: string) => ({
    matches: query === '(min-width: 1024px)' ? matches : false,
    media: query,
    onchange: null,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })))
}
