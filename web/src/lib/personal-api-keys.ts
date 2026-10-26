export type PersonalAPIKeyRole = 'viewer' | 'operator' | 'admin'

export interface PersonalAPIKey {
  id: string
  user_id: string
  name: string
  role: PersonalAPIKeyRole
  created_at: string
  expires_at: string
  last_used_at: string | null
  revoked_at: string | null
  environments: string[] | null
}

export interface PersonalAPIKeysResponse {
  api_keys: PersonalAPIKey[]
  user_id: string
  max_expires_at: string
  allowed_roles: PersonalAPIKeyRole[]
}

export interface IssuePersonalAPIKeyResponse {
  api_key: PersonalAPIKey
  token: string
}

/** Keep the metadata cache on an explicit allowlist, including issue responses. */
export function personalAPIKeyMetadata(key: PersonalAPIKey): PersonalAPIKey {
  return {
    id: key.id,
    user_id: key.user_id,
    name: key.name,
    role: key.role,
    created_at: key.created_at,
    expires_at: key.expires_at,
    last_used_at: key.last_used_at,
    revoked_at: key.revoked_at,
    environments: key.environments === null ? null : [...key.environments],
  }
}
