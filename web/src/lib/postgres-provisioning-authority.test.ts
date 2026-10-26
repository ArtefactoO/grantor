import { describe, expect, it } from 'vitest'
import type { Connection } from './types'
import { postgresProvisioningIssue, postgresProvisioningReady } from './postgres-provisioning-authority'

function connection(overrides: Partial<Connection> = {}): Connection {
  return {
    id: 'connection-1', display_name: 'PostgreSQL', engine: 'postgres', environment: 'test',
    tags: [], endpoints: ['db:5432'], execution_mode: 'direct', tls_config: {},
    admin_credential_mode: 'vault', vault_admin_path: 'connections/connection-1/admin',
    capabilities: ['postgres.superuser_direct.v1'], discovery_config: {}, status: 'active',
    server_version: '16', topology: { system_identifier: '42' },
    last_discovery_at: '2026-08-27T10:00:00Z', created_at: '2026-08-27T09:00:00Z',
    updated_at: '2026-08-27T10:00:00Z',
    postgres_provisioning_authority: {
      status: 'confirmed', reason: 'superuser_confirmed', observed_at: '2026-08-27T10:00:00Z',
      expected_admin_identity: 'grantor', observed_admin_identity: 'grantor',
      credential_incarnation: 7, config_incarnation: 'a'.repeat(64),
      target_identity: 'postgres:system:42',
    },
    ...overrides,
  }
}

describe('PostgreSQL provisioning readiness', () => {
  it('requires both the current confirmed authority and the v2 capability', () => {
    expect(postgresProvisioningReady(connection())).toBe(true)
    expect(postgresProvisioningReady(connection({ capabilities: [] }))).toBe(false)
    expect(postgresProvisioningReady(connection({ postgres_provisioning_authority: null }))).toBe(false)
    expect(postgresProvisioningReady(connection({ status: 'discovering' }))).toBe(false)
  })

  it.each([
    ['superuser_required', 'не является PostgreSQL SUPERUSER'],
    ['admin_identity_mismatch', 'другую admin identity'],
    ['read_only_target', 'read-only узел'],
    ['credential_incarnation_missing', 'Admin credential не подтверждён'],
    ['target_identity_unavailable', 'Не удалось подтвердить PostgreSQL-кластер'],
  ])('turns %s into recovery-oriented copy', (reason, expected) => {
    const authority = connection().postgres_provisioning_authority!
    const issue = postgresProvisioningIssue(connection({
      capabilities: [],
      postgres_provisioning_authority: { ...authority, status: 'invalid_current_version', reason },
    }))
    expect(issue).toContain(expected)
  })
})
