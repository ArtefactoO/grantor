import { describe, expect, it } from 'vitest'
import type { Account, Connection, Resource } from './types'
import { directlyOwnedPostgresDatabases } from './postgres-database-ownership'

const account = {
  connection_id: 'connection-1',
  engine_identity: 'reports_bot',
} satisfies Pick<Account, 'connection_id' | 'engine_identity'>

const connection = {
  id: 'connection-1',
  engine: 'postgres',
} satisfies Pick<Connection, 'id' | 'engine'>

function resource(
  id: string,
  overrides: Partial<Pick<Resource, 'connection_id' | 'kind' | 'status' | 'attributes'>> = {},
): Resource {
  return {
    id,
    connection_id: 'connection-1',
    parent_id: null,
    kind: 'database',
    external_id: `database:${id}`,
    name: id,
    canonical_path: id,
    attributes: { owner: 'reports_bot' },
    fingerprint: id,
    observed_at: '2026-08-25T00:00:00Z',
    status: 'observed',
    ownership: 'unmanaged',
    created_at: '2026-08-25T00:00:00Z',
    updated_at: '2026-08-25T00:00:00Z',
    ...overrides,
  }
}

describe('directlyOwnedPostgresDatabases', () => {
  it('returns only observed PostgreSQL databases with an exact owner match', () => {
    const owned = resource('analytics')
    const values = [
      owned,
      resource('inherited-via-role', { attributes: { owner: 'reporting_team' } }),
      resource('stale', { status: 'stale' }),
      resource('schema', { kind: 'schema' }),
      resource('other-connection', { connection_id: 'connection-2' }),
      resource('missing-owner', { attributes: {} }),
      resource('non-string-owner', { attributes: { owner: 42 } }),
    ]

    expect(directlyOwnedPostgresDatabases(account, connection, values)).toEqual([owned])
  })

  it('does not infer database ownership for another engine or a missing connection', () => {
    const values = [resource('analytics')]

    expect(directlyOwnedPostgresDatabases(account, { ...connection, engine: 'mysql' }, values))
      .toEqual([])
    expect(directlyOwnedPostgresDatabases(account, undefined, values)).toEqual([])
  })
})
