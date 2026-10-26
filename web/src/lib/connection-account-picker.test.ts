import { describe, expect, it } from 'vitest'
import type { Account, Principal } from './types'
import { buildConnectionAccountPickerProjection } from './connection-account-picker'

const principal = (id: string, status: Principal['status']): Principal => ({
  id,
  type: 'human',
  display_name: 'test',
  external_provider: '',
  external_subject: '',
  status,
  attributes: {},
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
})

const account = (
  id: string,
  principalId: string | null,
  status: Account['status'],
): Account => ({
  id,
  principal_id: principalId,
  connection_id: 'connection-1',
  kind: 'login',
  engine_identity: id,
  authentication_scope: '',
  credential_mode: 'generated',
  vault_path: '',
  status,
  ownership: 'managed',
  attributes: {},
  bindings: [],
  created_at: '2026-07-22T00:00:00Z',
  updated_at: '2026-07-22T00:00:00Z',
})

describe('connection account picker projection', () => {
  it('removes deleted principal duplicates from the selectable catalog', () => {
    const projection = buildConnectionAccountPickerProjection(
      [principal('deleted-test', 'deleted'), principal('active-test', 'active')],
      [account('active-account', 'active-test', 'active')],
    )

    expect(projection.principals.map((item) => item.id)).toEqual(['active-test'])
    expect(projection.accountByPrincipalId.get('active-test')?.id).toBe('active-account')
  })

  it('keeps only unlinked local tombstones as standalone restore entries', () => {
    const projection = buildConnectionAccountPickerProjection(
      [principal('active-test', 'active'), principal('deleted-user', 'deleted')],
      [
        account('linked-deleted', 'active-test', 'deleted'),
        account('offboarded-deleted', 'deleted-user', 'deleted'),
        account('local-deleted', null, 'deleted'),
      ],
    )

    expect(projection.accountByPrincipalId.get('active-test')?.id).toBe('linked-deleted')
    expect(projection.localDeletedAccounts.map((item) => item.id)).toEqual(['local-deleted'])
  })

  it('prefers a live account when one principal has several engine identities', () => {
    const projection = buildConnectionAccountPickerProjection(
      [principal('active-test', 'active')],
      [
        account('old-login', 'active-test', 'deleted'),
        account('current-login', 'active-test', 'active'),
      ],
    )

    expect(projection.accountByPrincipalId.get('active-test')?.id).toBe('current-login')
  })
})
