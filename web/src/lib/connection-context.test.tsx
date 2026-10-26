import { useState } from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { describe, expect, it, vi } from 'vitest'
import { ConnectionPicker, safeEndpointSearchToken } from '../components/ConnectionPicker'
import {
  connectionFromLocation,
  connectionSearchForRoute,
  resolveConnectionScope,
  validateConnectionSearch,
} from './connection-context'
import { qk } from './queryKeys'
import type { Connection } from './types'

const connections: Connection[] = [
  {
    id: 'conn-a',
    display_name: 'payments-main',
    engine: 'postgres',
    environment: 'production',
    tags: ['billing', 'critical'],
    endpoints: ['postgres://operator:secret@pg-a.internal:5432/payments?sslmode=require'],
    execution_mode: 'direct',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: 'hidden',
    capabilities: [],
    discovery_config: {},
    status: 'active',
    server_version: '16',
    topology: {},
    last_discovery_at: null,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  },
  {
    id: 'conn-b',
    display_name: 'payments-main replica',
    engine: 'redis',
    environment: 'staging',
    tags: ['settlements'],
    endpoints: ['redis-b.internal:6379/0'],
    execution_mode: 'connector',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: 'hidden',
    capabilities: [],
    discovery_config: {},
    status: 'disabled',
    server_version: '7',
    topology: {},
    last_discovery_at: null,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  },
]

describe('connection URL contract', () => {
  it('preserves an unknown string id so the route can report it as unavailable', () => {
    expect(validateConnectionSearch({ connection: ' deleted-id ' })).toEqual({
      connection: 'deleted-id',
    })
    expect(
      resolveConnectionScope('deleted-id', connections, false),
    ).toEqual({ kind: 'unavailable', connectionId: 'deleted-id' })
  })

  it('requires a connection on scoped routes and never falls back to first active', () => {
    expect(resolveConnectionScope(undefined, connections, false)).toEqual({
      kind: 'required',
      connectionId: '',
    })
  })

  it('resolves overlapping names by exact stable id', () => {
    const scope = resolveConnectionScope('conn-b', connections, false)
    expect(scope.kind).toBe('selected')
    if (scope.kind === 'selected') {
      expect(scope.connection.display_name).toBe('payments-main replica')
      expect(scope.connection.engine).toBe('redis')
    }
  })

  it('carries detail or query scope only into remaining connection-aware routes', () => {
    expect(connectionFromLocation('/connections/conn-b', {})).toBe('conn-b')
    expect(connectionFromLocation('/connections/conn-b/state', {})).toBe('conn-b')
    expect(connectionFromLocation('/audit', { connection: 'conn-a' })).toBe('conn-a')
    expect(connectionSearchForRoute('/control', 'conn-b')).toEqual({
      connection: 'conn-b',
    })
    expect(connectionSearchForRoute('/resources', 'conn-b')).toEqual({})
    expect(connectionSearchForRoute('/manifest', 'conn-b')).toEqual({})
    expect(connectionSearchForRoute('/principals', 'conn-b')).toEqual({})
  })
})

function PickerProbe() {
  const [value, setValue] = useState<string>()
  return (
    <ConnectionPicker
      connections={connections}
      value={value}
      onValueChange={setValue}
    />
  )
}

describe('ConnectionPicker', () => {
  it('shows the environment between the engine icon and connection name', () => {
    render(
      <ConnectionPicker
        connections={connections}
        value="conn-b"
        onValueChange={vi.fn()}
      />,
    )
    const picker = screen.getByRole('combobox', { name: 'Подключение' })
    expect(picker).toHaveTextContent(/STAGE.*payments-main replica/)
  })

  it('maps the global option to an empty URL selection', async () => {
    const user = userEvent.setup()
    const onValueChange = vi.fn()
    render(
      <ConnectionPicker
        allowAll
        connections={connections}
        onValueChange={onValueChange}
      />,
    )
    expect(screen.getByRole('combobox', { name: 'Подключение' })).toHaveTextContent(
      'Все подключения',
    )
    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.click(screen.getByRole('option', { name: /Все подключения/ }))
    expect(onValueChange).toHaveBeenCalledWith('')
  })

  it.each([
    ['settlements', 'payments-main replica'],
    ['redis', 'payments-main replica'],
    ['staging', 'payments-main replica'],
    ['redis-b.internal:6379', 'payments-main replica'],
    ['billing', 'payments-main'],
  ])('searches %s metadata without exposing credentials', async (term, expected) => {
    const user = userEvent.setup()
    render(<PickerProbe />)
    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.type(screen.getByRole('combobox', { name: 'Поиск подключения' }), term)
    expect(
      screen
        .getAllByRole('option')
        .some((option) => option.textContent?.includes(expected) === true),
    ).toBe(true)
    expect(document.body).not.toHaveTextContent('operator:secret')
  })

  it('selects the exact overlapping-name connection with the keyboard', async () => {
    const user = userEvent.setup()
    render(<PickerProbe />)
    await user.click(screen.getByRole('combobox', { name: 'Подключение' }))
    await user.type(
      screen.getByRole('combobox', { name: 'Поиск подключения' }),
      'settlements',
    )
    await user.keyboard('{ArrowDown}{Enter}')
    expect(screen.getByRole('combobox', { name: 'Подключение' })).toHaveTextContent(
      'payments-main replica',
    )
  })

  it('sanitizes endpoint search tokens', () => {
    expect(
      safeEndpointSearchToken(
        'postgres://operator:secret@pg-a.internal:5432/payments?sslmode=require',
      ),
    ).toBe('pg-a.internal:5432')
  })
})

describe('scoped query isolation', () => {
  it('does not render a late response from the previous connection', async () => {
    const resolvers = new Map<string, (value: string) => void>()
    const load = vi.fn(
      (connectionId: string) =>
        new Promise<string>((resolve) => {
          resolvers.set(connectionId, resolve)
        }),
    )

    function Probe({ connectionId }: { connectionId: string }) {
      const query = useQuery({
        queryKey: qk.connectionResources(connectionId),
        queryFn: () => load(connectionId),
      })
      return <div>{query.data ?? 'loading'}</div>
    }

    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const view = render(
      <QueryClientProvider client={client}>
        <Probe connectionId="conn-a" />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(load).toHaveBeenCalledWith('conn-a'))
    view.rerender(
      <QueryClientProvider client={client}>
        <Probe connectionId="conn-b" />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(load).toHaveBeenCalledWith('conn-b'))

    await act(async () => {
      resolvers.get('conn-b')?.('resource from conn-b')
    })
    await waitFor(() =>
      expect(screen.getByText('resource from conn-b')).toBeInTheDocument(),
    )

    await act(async () => {
      resolvers.get('conn-a')?.('resource from conn-a')
    })
    await waitFor(() =>
      expect(screen.getByText('resource from conn-b')).toBeInTheDocument(),
    )
    expect(screen.queryByText('resource from conn-a')).not.toBeInTheDocument()
  })
})
