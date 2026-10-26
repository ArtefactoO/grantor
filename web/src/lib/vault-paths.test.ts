import { describe, expect, it } from 'vitest'
import { principalCredentialVaultPath } from './vault-paths'

// Зеркало internal/providers/vault/paths.go + environmentOf: путь показывается
// оператору для поиска секрета, разъехавшийся формат отправил бы его не туда.
describe('principalCredentialVaultPath', () => {
  it('builds the shared credential path of an environment', () => {
    expect(principalCredentialVaultPath('11111111-2222-3333-4444-555555555555', 'prod')).toBe(
      'principals/11111111-2222-3333-4444-555555555555/environments/prod/credential',
    )
  })

  it('scopes an empty environment as default, like the backend', () => {
    expect(principalCredentialVaultPath('principal-1', '')).toBe(
      'principals/principal-1/environments/default/credential',
    )
  })
})
