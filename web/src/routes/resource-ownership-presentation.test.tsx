import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Resource } from '../lib/types'
import { inventoryStatusLabel, resourceKindLabel } from '../lib/ui-copy'
import { ResourceDetailPanel, ResourceTree } from './resource-tree'

const clients: QueryClient[] = []

function resource(ownership: string): Resource {
  return {
    id: 'database-1', connection_id: 'connection-1', parent_id: null,
    kind: 'database', external_id: 'analytics', name: 'analytics',
    canonical_path: '/analytics', attributes: { owner: 'app_owner' },
    fingerprint: 'fixture', observed_at: '2026-08-26T09:00:00Z',
    status: 'observed', ownership,
    created_at: '2026-08-26T09:00:00Z', updated_at: '2026-08-26T09:00:00Z',
  }
}

afterEach(() => {
  cleanup()
  clients.splice(0).forEach((client) => client.clear())
  vi.unstubAllGlobals()
})

describe('resource ownership presentation', () => {
  it.each(['managed', 'unmanaged'])('does not label a %s database in the tree', (ownership) => {
    render(<ResourceTree nodes={[{ resource: resource(ownership), children: [] }]} selectedId={null} onSelect={vi.fn()} />)
    expect(screen.getByText('analytics')).toBeVisible()
    expect(screen.getByText(resourceKindLabel('database'))).toBeInTheDocument()
    expect(screen.queryByText(/^(?:Managed|Unmanaged)$/i)).not.toBeInTheDocument()
    expect(screen.queryByTitle(/Ресурс управляется|Ресурс обнаружен/)).not.toBeInTheDocument()
  })

  it.each(['managed', 'unmanaged'])('keeps discovery status and actual database owner for a %s resource', async (ownership) => {
    vi.stubGlobal('matchMedia', vi.fn((query: string) => ({
      matches: query.includes('min-width: 1024px'), media: query, onchange: null,
      addEventListener: vi.fn(), removeEventListener: vi.fn(),
      addListener: vi.fn(), removeListener: vi.fn(), dispatchEvent: vi.fn(),
    })))
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ bindings: [] }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })))
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
    clients.push(client)
    render(<QueryClientProvider client={client}>
      <ResourceDetailPanel resource={resource(ownership)} permissionsById={new Map()} onClose={vi.fn()} />
    </QueryClientProvider>)
    await userEvent.click(screen.getByRole('button', { name: /Права доступа/ }))
    await waitFor(() => expect(screen.getByText('Для ресурса нет назначений доступа')).toBeVisible())
    expect(screen.getByText(inventoryStatusLabel('observed'))).toBeVisible()
    expect(screen.queryByText(/^(?:Managed|Unmanaged)$/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Атрибуты движка/ }))
    await waitFor(() => expect(screen.getByText('app_owner')).toBeVisible())
  })
})
