import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import type { Resource } from '../lib/types'
import { AccountDatabaseOwnership } from './account-database-ownership'

function database(index: number): Resource {
  return {
    id: `db-${index}`,
    connection_id: 'connection-1',
    parent_id: null,
    kind: 'database',
    external_id: `db:db-${index}`,
    name: `db_${index}`,
    canonical_path: `db_${index}`,
    attributes: { owner: 'svc' },
    fingerprint: `db-${index}`,
    observed_at: '2026-08-25T00:00:00Z',
    status: 'observed',
    ownership: 'unmanaged',
    created_at: '2026-08-25T00:00:00Z',
    updated_at: '2026-08-25T00:00:00Z',
  }
}

describe('AccountDatabaseOwnership', () => {
  it('bounds compact account rows and summarizes the remaining databases', () => {
    render(<AccountDatabaseOwnership databases={Array.from({ length: 10 }, (_, index) => database(index))} />)

    expect(screen.getByText('db_0')).toBeVisible()
    expect(screen.getByText('db_2')).toBeVisible()
    expect(screen.queryByText('db_3')).not.toBeInTheDocument()
    expect(screen.getByText('+7')).toHaveAttribute('title', expect.stringContaining('db_9'))
  })
})
