import { useState } from 'react'
import type { ReactNode } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@tanstack/react-router', () => ({
  Link: ({ children, search }: { children: ReactNode; search?: { operation?: string } }) => (
    <a href={`/control?operation=${search?.operation ?? ''}`}>{children}</a>
  ),
}))

import type { Connection, ConnectionAdminCredentialChange } from '../lib/types'
import {
  AdminCredentialChangePanel,
  AdminCredentialControlButton,
  adminCredentialErrorLabel,
  adminCredentialPhaseLabel,
  canManageAdminCredential,
  canRotateAdminCredential,
  canSwitchAdminCredential,
  ConnectionAdminCredentialDialog,
  isTerminalAdminCredentialChange,
  shouldPollAdminCredentialChange,
} from './connection-admin-credential'

const ACTIVE_CHANGE: ConnectionAdminCredentialChange = {
  operation_id: 'operation-credential-1',
  mode: 'rotate',
  phase: 'candidate_proving',
  status: 'running',
  cancel_allowed: true,
  target_side_effect_possible: false,
  retryable: false,
  error_code: null,
  started_at: '2026-08-25T10:00:00Z',
  updated_at: '2026-08-25T10:00:05Z',
}

function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: 'connection-1',
    display_name: 'Primary DB',
    engine: 'postgres',
    environment: 'test',
    tags: [],
    endpoints: ['db.example.com:5432'],
    execution_mode: 'direct',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: 'connections/connection-1/admin',
    capabilities: [
      'connection.admin_credential.switch',
      'connection.admin_credential.rotate',
    ],
    discovery_config: {},
    status: 'active',
    server_version: '16.4',
    topology: {},
    last_discovery_at: '2026-08-25T09:00:00Z',
    created_at: '2026-08-20T10:00:00Z',
    updated_at: '2026-08-25T09:30:00.123456Z',
    admin_credential_change: null,
    ...overrides,
  }
}

function response(body: unknown, status = 200): Response {
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

describe('admin credential capability and presentation', () => {
  it('keeps rotate capability-driven and switch available as Vault recovery', () => {
    expect(canRotateAdminCredential(connection())).toBe(true)
    expect(canRotateAdminCredential(connection({ capabilities: [] }))).toBe(false)
    expect(canSwitchAdminCredential(connection({ capabilities: [] }))).toBe(true)
    expect(canSwitchAdminCredential(connection({
      capabilities: [],
      vault_admin_path: '',
    }))).toBe(false)
    expect(canManageAdminCredential(false, connection())).toBe(false)
    expect(canManageAdminCredential(true, connection())).toBe(true)
  })

  it('polls only active credential lifecycle state', () => {
    expect(shouldPollAdminCredentialChange(connection({
      status: 'credential_updating',
      admin_credential_change: ACTIVE_CHANGE,
    }))).toBe(true)
    expect(shouldPollAdminCredentialChange(connection({
      admin_credential_change: { ...ACTIVE_CHANGE, phase: 'completed', status: 'success' },
    }))).toBe(false)
    expect(shouldPollAdminCredentialChange(connection({
      status: 'degraded',
      admin_credential_change: { ...ACTIVE_CHANGE, phase: 'target_applied', status: 'failed' },
    }))).toBe(false)
    expect(shouldPollAdminCredentialChange(connection())).toBe(false)
    expect(isTerminalAdminCredentialChange({
      ...ACTIVE_CHANGE,
      phase: 'target_applied',
      status: 'failed',
    })).toBe(true)
    expect(isTerminalAdminCredentialChange(ACTIVE_CHANGE)).toBe(false)
  })

  it('localizes stable values and safely falls back for future values', () => {
    expect(adminCredentialPhaseLabel('preparing')).toBe('Подготовка candidate')
    expect(adminCredentialPhaseLabel('candidate_proving')).toBe('Проверка candidate')
    expect(adminCredentialPhaseLabel('future_phase')).toBe('Future phase')
    expect(adminCredentialErrorLabel('invalid_candidate')).toMatch(/не прошёл проверку/)
    expect(adminCredentialErrorLabel('future_error')).toContain('future_error')
  })

  it('keeps the connection-detail entry point admin-only and disables it while busy', () => {
    const onOpen = vi.fn()
    const { rerender } = render(
      <AdminCredentialControlButton
        connection={connection()}
        isAdmin={false}
        busy={false}
        onOpen={onOpen}
      />,
    )
    expect(screen.queryByRole('button', { name: 'Управление admin credential' }))
      .not.toBeInTheDocument()

    rerender(
      <AdminCredentialControlButton
        connection={connection()}
        isAdmin
        busy
        onOpen={onOpen}
      />,
    )
    expect(screen.getByRole('button', { name: 'Управление admin credential' })).toBeDisabled()
  })
})

describe('ConnectionAdminCredentialDialog', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('switches Redis to explicit no-auth without a password payload', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ operation_id: 'switch-none' }, 202))
    vi.stubGlobal('fetch', fetchMock)
    const user = userEvent.setup()
    const onStarted = vi.fn()
    render(<ConnectionAdminCredentialDialog connection={connection({ engine: 'redis' })} open onClose={vi.fn()} onStarted={onStarted} />, { wrapper: Wrapper })
    await user.click(screen.getByRole('combobox', { name: 'Авторизация Redis' }))
    await user.click(screen.getByRole('option', { name: 'Без пароля · default' }))
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Проверить и сменить' }))
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith('switch-none', 'switch', false))
    const body = JSON.parse(fetchMock.mock.calls[0][1].body)
    expect(body).toMatchObject({ auth_mode: 'none', updated_at: expect.any(String), request_id: expect.any(String) })
    expect(body).not.toHaveProperty('username')
    expect(body).not.toHaveProperty('password')
  })

  it('allows password recovery for no-auth Redis and never offers rotation', async () => {
    const user = userEvent.setup()
    render(<ConnectionAdminCredentialDialog connection={connection({ engine: 'redis', auth_mode: 'none', capabilities: ['connection.admin_credential.switch'], vault_admin_path: '' })} open onClose={vi.fn()} onStarted={vi.fn()} />, { wrapper: Wrapper })
    expect(screen.queryByText('Ротировать password')).not.toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'Авторизация Redis' }))
    await user.click(screen.getByRole('option', { name: 'Пароль' }))
    expect(screen.getByLabelText('Password')).toBeRequired()
    expect(screen.getByRole('button', { name: 'Проверить и сменить' })).toBeDisabled()
  })

  it('does not offer rotate without its effective capability', async () => {
    render(
      <ConnectionAdminCredentialDialog
        connection={connection({ capabilities: [] })}
        open
        onClose={() => undefined}
        onStarted={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    await waitFor(() => expect(screen.getByText('Сменить учётку')).toBeVisible())
    expect(screen.queryByText('Ротировать password')).not.toBeInTheDocument()
  })

  it('uses the sticky footer, focuses username and restores focus after Escape', async () => {
    function Harness() {
      const [open, setOpen] = useState(false)
      return (
        <>
          <button type="button" onClick={() => setOpen(true)}>Открыть credential</button>
          <ConnectionAdminCredentialDialog
            connection={connection()}
            open={open}
            onClose={() => setOpen(false)}
            onStarted={() => undefined}
          />
        </>
      )
    }
    const user = userEvent.setup()
    render(<Harness />, { wrapper: Wrapper })
    const trigger = screen.getByRole('button', { name: 'Открыть credential' })

    await user.click(trigger)
    const dialog = screen.getByRole('dialog', { name: 'Admin credential подключения' })
    await waitFor(() => expect(
      screen.getByRole('radiogroup', { name: 'Операция с admin credential' }),
    ).toBeVisible())
    expect(dialog.querySelector('[data-slot="dialog-body"]')).toHaveClass('overflow-y-auto')
    expect(dialog.querySelector('[data-slot="dialog-footer"]')).toContainElement(
      screen.getByRole('button', { name: 'Проверить и сменить' }),
    )
    await waitFor(() => expect(screen.getByRole('textbox', { name: /Username/ })).toHaveFocus())

    await user.keyboard('{Escape}')
    await waitFor(() => expect(dialog).not.toBeInTheDocument())
    expect(trigger).toHaveFocus()
  })

  it('clears password and reuses request_id after a lost switch response', async () => {
    const requests: Array<Record<string, unknown>> = []
    const paths: string[] = []
    let posts = 0
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posts += 1
      paths.push(String(input))
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      if (posts === 1) throw new TypeError('response lost')
      return response({ operation_id: 'operation-switch' }, 202)
    }))
    const onStarted = vi.fn()
    const user = userEvent.setup()
    render(
      <ConnectionAdminCredentialDialog
        connection={connection()}
        open
        onClose={() => undefined}
        onStarted={onStarted}
      />,
      { wrapper: Wrapper },
    )

    await user.type(screen.getByRole('textbox', { name: /Username/ }), 'grantor_next')
    const password = screen.getByLabelText('Password')
    await user.type(password, 'candidate-secret')
    await user.click(screen.getByRole('button', { name: 'Проверить и сменить' }))

    expect(await screen.findByText('сеть недоступна или API не отвечает')).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent('Password очищен')
    expect(password).toHaveValue('')
    expect(screen.queryByDisplayValue('candidate-secret')).not.toBeInTheDocument()
    expect(screen.getByText(/Password очищен/)).toBeVisible()

    await user.type(password, 'candidate-secret')
    await user.click(screen.getByRole('button', { name: 'Повторить запрос' }))
    await waitFor(() => expect(requests).toHaveLength(2))
    expect(requests[0]).toEqual({
      request_id: expect.any(String),
      updated_at: '2026-08-25T09:30:00.123456Z',
      username: 'grantor_next',
      password: 'candidate-secret',
    })
    expect(requests[1]?.request_id).toBe(requests[0]?.request_id)
    expect(paths).toEqual([
      '/api/v1/connections/connection-1/admin-credential/switch',
      '/api/v1/connections/connection-1/admin-credential/switch',
    ])
    expect(onStarted).toHaveBeenCalledWith('operation-switch', 'switch', false)
  })

  it('posts generated rotate without a password field', async () => {
    const requests: Array<Record<string, unknown>> = []
    const paths: string[] = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      paths.push(String(input))
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      return response({ operation_id: 'operation-rotate' }, 202)
    }))
    const user = userEvent.setup()
    render(
      <ConnectionAdminCredentialDialog
        connection={connection({
          vault_admin_path: '',
          capabilities: ['connection.admin_credential.rotate'],
        })}
        open
        onClose={() => undefined}
        onStarted={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    expect(screen.queryByText('Сменить учётку')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Password')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Новый password')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Запустить ротацию' }))
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0]).toEqual({
      request_id: expect.any(String),
      updated_at: '2026-08-25T09:30:00.123456Z',
      mode: 'generated',
    })
    expect(requests[0]).not.toHaveProperty('password')
    expect(paths).toEqual(['/api/v1/connections/connection-1/admin-credential/rotate'])
  })

  it('posts provided rotate and removes its password from controlled state', async () => {
    const requests: Array<{ path: string; body: Record<string, unknown> }> = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({
        path: String(input),
        body: JSON.parse(String(init?.body)) as Record<string, unknown>,
      })
      return response({ operation_id: 'operation-rotate-provided' }, 202)
    }))
    const user = userEvent.setup()
    render(
      <ConnectionAdminCredentialDialog
        connection={connection({
          vault_admin_path: '',
          capabilities: ['connection.admin_credential.rotate'],
        })}
        open
        onClose={() => undefined}
        onStarted={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    await user.click(screen.getByText('Задать password'))
    const password = screen.getByLabelText('Новый password')
    await user.type(password, 'provided-secret')
    await user.click(screen.getByRole('button', { name: 'Запустить ротацию' }))
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0]).toEqual({
      path: '/api/v1/connections/connection-1/admin-credential/rotate',
      body: {
        request_id: expect.any(String),
        updated_at: '2026-08-25T09:30:00.123456Z',
        mode: 'provided',
        password: 'provided-secret',
      },
    })
    expect(password).toHaveValue('')
  })

  it('reconciles a lost response from the secret-free connection projection', async () => {
    let requestId = ''
    vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      requestId = (JSON.parse(String(init?.body)) as { request_id: string }).request_id
      throw new TypeError('response lost')
    }))
    const onStarted = vi.fn()
    const onClose = vi.fn()
    const props = {
      open: true,
      onClose,
      onStarted,
    }
    const user = userEvent.setup()
    const { rerender } = render(
      <ConnectionAdminCredentialDialog connection={connection()} {...props} />,
      { wrapper: Wrapper },
    )
    await user.type(screen.getByRole('textbox', { name: /Username/ }), 'grantor_next')
    await user.type(screen.getByLabelText('Password'), 'candidate-secret')
    await user.click(screen.getByRole('button', { name: 'Проверить и сменить' }))
    expect(await screen.findByText('сеть недоступна или API не отвечает')).toBeVisible()

    rerender(
      <ConnectionAdminCredentialDialog
        connection={connection({
          status: 'credential_updating',
          admin_credential_change: { ...ACTIVE_CHANGE, operation_id: 'another-admin-operation', mode: 'switch' },
        })}
        {...props}
      />,
    )
    expect(onStarted).not.toHaveBeenCalled()
    expect(screen.getByRole('dialog', { name: 'Admin credential подключения' })).toBeInTheDocument()

    rerender(
      <ConnectionAdminCredentialDialog
        connection={connection({
          status: 'credential_updating',
          admin_credential_change: { ...ACTIVE_CHANGE, operation_id: requestId, mode: 'switch' },
        })}
        {...props}
      />,
    )
    await waitFor(() => expect(onStarted).toHaveBeenCalledWith(
      requestId,
      'switch',
      true,
    ))
    expect(onClose).toHaveBeenCalled()
  })
})

describe('AdminCredentialChangePanel', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('shows progress and reuses a safe cancel request_id after a lost response', async () => {
    const stagedChange = { ...ACTIVE_CHANGE, phase: 'staged' }
    const requests: Array<Record<string, unknown>> = []
    const paths: string[] = []
    let posts = 0
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      posts += 1
      paths.push(String(input))
      requests.push(JSON.parse(String(init?.body)) as Record<string, unknown>)
      if (posts === 1) throw new TypeError('response lost')
      return response({ operation_id: ACTIVE_CHANGE.operation_id }, 202)
    }))
    const onNotice = vi.fn()
    const user = userEvent.setup()
    const { rerender } = render(
      <AdminCredentialChangePanel
        connection={connection({ status: 'credential_updating', admin_credential_change: stagedChange })}
        isAdmin
        onNotice={onNotice}
        onRefresh={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    expect(screen.getAllByText('Candidate сохранён').length).toBeGreaterThan(0)
    expect(screen.getByRole('link', { name: /Операция/ })).toHaveAttribute(
      'href',
      `/control?operation=${ACTIVE_CHANGE.operation_id}`,
    )
    await user.click(screen.getByRole('button', { name: 'Отменить до side effect' }))
    expect(await screen.findByText('сеть недоступна или API не отвечает')).toBeVisible()
    expect(screen.getByRole('alert')).toHaveTextContent('сеть недоступна')
    rerender(
      <AdminCredentialChangePanel
        connection={connection({
          status: 'credential_updating',
          updated_at: '2026-08-25T10:00:06.000000Z',
          admin_credential_change: ACTIVE_CHANGE,
        })}
        isAdmin
        onNotice={onNotice}
        onRefresh={() => undefined}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Отменить до side effect' }))
    await waitFor(() => expect(requests).toHaveLength(2))
    expect(requests[1]?.request_id).toBe(requests[0]?.request_id)
    expect(requests[0]).toEqual({
      request_id: expect.any(String),
      updated_at: '2026-08-25T09:30:00.123456Z',
    })
    expect(requests[1]?.updated_at).toBe(requests[0]?.updated_at)
    expect(paths).toEqual([
      '/api/v1/connections/connection-1/admin-credential/cancel',
      '/api/v1/connections/connection-1/admin-credential/cancel',
    ])
    expect(onNotice).toHaveBeenCalled()
  })

  it('blocks cancel after possible target side effect and exposes retry/error recovery', () => {
    render(
      <AdminCredentialChangePanel
        connection={connection({
          status: 'credential_updating',
          admin_credential_change: {
            ...ACTIVE_CHANGE,
            phase: 'target_applied',
            cancel_allowed: false,
            target_side_effect_possible: true,
            retryable: true,
            error_code: 'metadata_commit_failed',
            status: 'failed',
          },
        })}
        isAdmin
        onNotice={() => undefined}
        onRefresh={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    expect(screen.queryByRole('button', { name: /Отменить/ })).not.toBeInTheDocument()
    expect(screen.getByText(/Учётные данные в целевой системе или Vault уже могли измениться/)).toBeVisible()
    expect(screen.getByText(/metadata commit не подтверждён/)).toBeVisible()
    expect(screen.getByText('metadata_commit_failed')).toBeVisible()
    expect(screen.getByText(/допускает top-level retry/)).toBeVisible()
  })

  it('does not claim target mutation phases for switch', () => {
    render(
      <AdminCredentialChangePanel
        connection={connection({
          status: 'credential_updating',
          admin_credential_change: {
            ...ACTIVE_CHANGE,
            mode: 'switch',
            phase: 'promoting',
            target_side_effect_possible: true,
            cancel_allowed: false,
          },
        })}
        isAdmin
        onNotice={() => undefined}
        onRefresh={() => undefined}
      />,
      { wrapper: Wrapper },
    )

    expect(screen.getAllByText('Продвижение в Vault').length).toBeGreaterThan(0)
    expect(screen.queryByText('Изменение target')).not.toBeInTheDocument()
    expect(screen.queryByText('Target изменён')).not.toBeInTheDocument()
  })

  it('renders explicit loading recovery and no panel for an empty active state', async () => {
    const onRefresh = vi.fn()
    const user = userEvent.setup()
    const { rerender } = render(
      <AdminCredentialChangePanel
        connection={connection({ status: 'credential_updating', admin_credential_change: null })}
        isAdmin
        onNotice={() => undefined}
        onRefresh={onRefresh}
      />,
      { wrapper: Wrapper },
    )

    expect(screen.getByText(/ещё не загрузилось/)).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Повторить загрузку' }))
    expect(onRefresh).toHaveBeenCalled()

    rerender(
      <AdminCredentialChangePanel
        connection={connection()}
        isAdmin
        onNotice={() => undefined}
        onRefresh={onRefresh}
      />,
    )
    expect(screen.queryByLabelText('Admin credential progress')).not.toBeInTheDocument()
  })
})
