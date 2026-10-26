import { describe, expect, it } from 'vitest'
import { recentOperatorOperations } from './overview'

describe('recentOperatorOperations', () => {
  it('keeps human actions and removes background and service automation', () => {
    const operations = [
      { id: 'manual-sync', actor_type: 'user', kind: 'connection.discover', parent_id: null },
      { id: 'auto-sync', actor_type: 'service', kind: 'connection.discover', parent_id: null },
      { id: 'bulk-child', actor_type: 'user', kind: 'access.grant', parent_id: 'bulk' },
      { id: 'grant-role', actor_type: 'user', kind: 'access.grant', parent_id: null },
    ]

    expect(recentOperatorOperations(operations).map((operation) => operation.id)).toEqual([
      'grant-role',
    ])
  })
})
