import { describe, expect, it } from 'vitest'
import type { Connection, ScopePolicy } from '../lib/types'
import {
  ENVIRONMENT_ALL,
  scopeCellState,
  scopePolicyImpact,
} from './scope-policy-matrix'
import type { ScopeMatrixSubject } from './scope-policy-matrix'

const subject: ScopeMatrixSubject = {
  kind: 'principal',
  id: 'service-1',
  name: 'Deploy Bot',
  description: 'service principal',
}

function policy(environment: string, id = environment): ScopePolicy {
  return {
    id,
    subject_kind: subject.kind,
    subject: subject.id,
    environment,
    created_at: '2026-07-20T00:00:00Z',
  }
}

function connection(id: string, environment: string): Connection {
  return {
    id,
    display_name: id,
    engine: 'postgres',
    environment,
    tags: [],
    endpoints: [],
    execution_mode: 'direct',
    tls_config: {},
    admin_credential_mode: 'vault',
    vault_admin_path: '',
    capabilities: [],
    discovery_config: {},
    status: 'active',
    server_version: '',
    topology: {},
    last_discovery_at: null,
    created_at: '2026-07-20T00:00:00Z',
    updated_at: '2026-07-20T00:00:00Z',
  }
}

describe('scope policy matrix semantics', () => {
  it('shows an explicit redundant rule instead of hiding it behind wildcard inheritance', () => {
    const policies = [policy(ENVIRONMENT_ALL, 'all'), policy('test', 'test')]

    expect(scopeCellState(policies, subject, 'test')).toBe('explicit')
    expect(scopeCellState(policies, subject, 'prod')).toBe('inherited')
    expect(scopeCellState(policies, subject, ENVIRONMENT_ALL)).toBe('explicit')
  })

  it('counts only connections whose effective access changes when wildcard is removed', () => {
    const policies = [policy(ENVIRONMENT_ALL, 'all'), policy('test', 'test')]
    const connections = [
      connection('test-db', 'test'),
      connection('prod-db', 'prod'),
      connection('unscoped-db', ''),
    ]

    const impact = scopePolicyImpact(
      policies,
      subject,
      ENVIRONMENT_ALL,
      connections,
    )

    expect(impact.operation).toBe('delete')
    expect(impact.affectedConnections.map((item) => item.id)).toEqual([
      'prod-db',
      'unscoped-db',
    ])
    expect(impact.redundantConcretePolicies).toHaveLength(1)
  })

  it('reports zero effective impact when deleting concrete rule covered by wildcard', () => {
    const policies = [policy(ENVIRONMENT_ALL, 'all'), policy('test', 'test')]

    expect(
      scopePolicyImpact(policies, subject, 'test', [connection('test-db', 'test')])
        .affectedConnections,
    ).toEqual([])
  })
})
