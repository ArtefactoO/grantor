import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { SnapshotAccount } from '../lib/types'
import { GrantedAccessTab } from './connection-detail'

const clients: QueryClient[] = []
afterEach(() => {
  clients.splice(0).forEach((client) => client.clear())
  vi.unstubAllGlobals()
})

async function renderAccounts(accounts: SnapshotAccount[]) {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const snapshot = String(input).includes('sections=')
    return new Response(JSON.stringify(snapshot
      ? { kind: 'access_snapshot', connection: { id: 'connection-1', display_name: 'Postgres' }, managed: [], accounts }
      : { version: 'v1', entries: [] }), {
      status: 200, headers: { 'content-type': 'application/json' },
    })
  }))
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  clients.push(client)
  render(<QueryClientProvider client={client}>
    <GrantedAccessTab connectionId="connection-1" connectionName="Postgres" />
  </QueryClientProvider>)
  await userEvent.click(screen.getByRole('checkbox', { name: 'Accounts' }))
  await screen.findByRole('row', { name: /legacy_role/ })
}

describe('account snapshot ownership presentation', () => {
  it('shows ownership for logins but not group roles in the same snapshot', async () => {
    const accounts = [
      { engine_identity: 'legacy_role', kind: 'group', ownership: 'managed', status: 'active' },
      { engine_identity: 'service_login', kind: 'login', ownership: 'managed', status: 'active' },
    ]
    await renderAccounts(accounts)
    expect(within(screen.getByRole('row', { name: /legacy_role/ })).queryByText('Managed')).not.toBeInTheDocument()
    expect(within(screen.getByRole('row', { name: /service_login/ })).getByText('Managed')).toBeVisible()
    expect(accounts[0].ownership).toBe('managed')
  })

  it('does not render an empty Ownership column for a role-only snapshot', async () => {
    await renderAccounts([{ engine_identity: 'legacy_role', kind: 'group', ownership: 'unmanaged', status: 'active' }])
    expect(screen.queryByRole('columnheader', { name: 'Ownership' })).not.toBeInTheDocument()
    expect(within(screen.getByRole('row', { name: /legacy_role/ })).queryByText('Unmanaged')).not.toBeInTheDocument()
  })
})
