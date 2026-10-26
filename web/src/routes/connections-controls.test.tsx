import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { Connection } from '../lib/types'
import {
  ConnectionFacetFilters,
  ConnectionListControls,
  connectionFacetOptions,
  useConnectionFacetFilters,
} from './connections'

describe('ConnectionListControls', () => {
  it('uses shared search and an exclusive status selector', async () => {
    const onSearchChange = vi.fn()
    const onFilterChange = vi.fn()
    const user = userEvent.setup()

    render(
      <ConnectionListControls
        search=""
        onSearchChange={onSearchChange}
        filter="all"
        onFilterChange={onFilterChange}
        counts={{ all: 5, synced: 4, error: 1 }}
        environments={[
          { value: 'PROD', label: 'PROD', count: 3 },
          { value: 'TEST', label: 'TEST', count: 2 },
        ]}
        environment="__all__"
        onEnvironmentChange={vi.fn()}
        engines={[
          { value: 'postgres', label: 'PostgreSQL', count: 4 },
          { value: 'redis', label: 'Redis', count: 1 },
        ]}
        engine="__all__"
        onEngineChange={vi.fn()}
      />,
    )

    await user.type(screen.getByRole('textbox', { name: 'Поиск подключений' }), 'redis')
    expect(onSearchChange).toHaveBeenCalled()
    await user.click(screen.getByRole('combobox', { name: 'Состояние подключения' }))
    expect(screen.getByRole('option', { name: 'Любое состояние 5' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('option', { name: 'Sync 4' })).toHaveAttribute('aria-selected', 'false')
    expect(screen.getByRole('option', { name: 'Error 1' })).toHaveAttribute('aria-selected', 'false')
    await user.click(screen.getByRole('option', { name: 'Error 1' }))
    expect(onFilterChange).toHaveBeenCalledWith('error')
    await user.click(screen.getByRole('combobox', { name: 'Состояние подключения' }))
    await user.click(screen.getByRole('option', { name: 'Любое состояние 5' }))
    expect(onFilterChange).toHaveBeenCalledWith('all')
  })

  it('exposes independent environment and engine filters only when useful', async () => {
    const onEnvironmentChange = vi.fn()
    const onEngineChange = vi.fn()
    const user = userEvent.setup()

    const { rerender } = render(
      <ConnectionListControls
        search=""
        onSearchChange={vi.fn()}
        filter="all"
        onFilterChange={vi.fn()}
        counts={{ all: 5, synced: 4, error: 1 }}
        environments={[
          { value: 'PROD', label: 'PROD', count: 3 },
          { value: 'TEST', label: 'TEST', count: 2 },
        ]}
        environment="__all__"
        onEnvironmentChange={onEnvironmentChange}
        engines={[
          { value: 'postgres', label: 'PostgreSQL', count: 4 },
          { value: 'redis', label: 'Redis', count: 1 },
        ]}
        engine="__all__"
        onEngineChange={onEngineChange}
      />,
    )

    await user.click(screen.getByRole('combobox', { name: 'Окружение подключения' }))
    expect(screen.getByRole('option', { name: 'All environments 2' })).toBeInTheDocument()
    await user.click(screen.getByRole('option', { name: 'TEST' }))
    expect(onEnvironmentChange).toHaveBeenCalledWith('TEST')
    await user.click(screen.getByRole('combobox', { name: 'Движок подключения' }))
    await user.click(screen.getByRole('option', { name: 'Redis 1' }))
    expect(onEngineChange).toHaveBeenCalledWith('redis')

    rerender(
      <ConnectionListControls
        search=""
        onSearchChange={vi.fn()}
        filter="all"
        onFilterChange={vi.fn()}
        counts={{ all: 1, synced: 1, error: 0 }}
        environments={[{ value: 'PROD', label: 'PROD', count: 1 }]}
        environment="__all__"
        onEnvironmentChange={onEnvironmentChange}
        engines={[{ value: 'postgres', label: 'PostgreSQL', count: 1 }]}
        engine="__all__"
        onEngineChange={onEngineChange}
      />,
    )

    expect(screen.queryByRole('combobox', { name: 'Окружение подключения' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: 'Движок подключения' })).not.toBeInTheDocument()
  })
})

describe('ConnectionFacetFilters', () => {
  it('builds and reuses environment and engine facets in stable order', () => {
    const connection = (id: string, environment: string, engine: string): Connection => ({
      id,
      display_name: id,
      environment,
      engine,
      tags: [],
      endpoints: [],
      execution_mode: 'direct',
      tls_config: null,
      admin_credential_mode: 'vault',
      vault_admin_path: '',
      capabilities: [],
      discovery_config: null,
      status: 'active',
      server_version: '',
      topology: null,
      last_discovery_at: null,
      created_at: '2026-07-21T00:00:00Z',
      updated_at: '2026-07-21T00:00:00Z',
    })

    const facets = connectionFacetOptions([
      connection('redis-test', 'test', 'redis'),
      connection('pg-prod', 'prod', 'postgres'),
      connection('pg-test', 'test', 'postgres'),
    ])

    expect(facets.environments).toEqual([
      { value: 'PROD', label: 'PROD', count: 1 },
      { value: 'TEST', label: 'TEST', count: 2 },
    ])
    expect(facets.engines).toEqual([
      { value: 'postgres', label: 'PostgreSQL', count: 2 },
      { value: 'redis', label: 'Redis', count: 1 },
    ])
  })

  it('shows only useful facets and emits the selected engine', async () => {
    const user = userEvent.setup()
    const onEngineChange = vi.fn()
    render(
      <ConnectionFacetFilters
        total={5}
        environments={[{ value: 'TEST', label: 'TEST', count: 5 }]}
        environment="__all__"
        onEnvironmentChange={vi.fn()}
        engines={[
          { value: 'postgres', label: 'PostgreSQL', count: 2 },
          { value: 'redis', label: 'Redis', count: 3 },
        ]}
        engine="__all__"
        onEngineChange={onEngineChange}
      />,
    )

    expect(screen.queryByRole('combobox', { name: 'Окружение подключения' })).not.toBeInTheDocument()
    await user.click(screen.getByRole('combobox', { name: 'Движок подключения' }))
    await user.click(screen.getByRole('option', { name: 'Redis 3' }))
    expect(onEngineChange).toHaveBeenCalledWith('redis')
  })

  it('resets a selected facet when refreshed data no longer contains it', async () => {
    const redis = [
      connectionFixture('redis-test', 'test', 'redis'),
      connectionFixture('pg-test', 'test', 'postgres'),
    ]
    const postgresOnly = [connectionFixture('pg-test', 'test', 'postgres')]
    const { result, rerender } = renderHook(
      ({ connections }) => useConnectionFacetFilters(connections),
      { initialProps: { connections: redis } },
    )

    act(() => result.current.setEngine('redis'))
    expect(result.current.engine).toBe('redis')

    rerender({ connections: postgresOnly })
    await waitFor(() => expect(result.current.engine).toBe('__all__'))
  })
})

function connectionFixture(id: string, environment: string, engine: string): Connection {
  return {
    id,
    display_name: id,
    environment,
    engine,
    tags: [],
    endpoints: [],
    execution_mode: 'direct',
    tls_config: null,
    admin_credential_mode: 'vault',
    vault_admin_path: '',
    capabilities: [],
    discovery_config: null,
    status: 'active',
    server_version: '',
    topology: null,
    last_discovery_at: null,
    created_at: '2026-07-21T00:00:00Z',
    updated_at: '2026-07-21T00:00:00Z',
  }
}
