import type { Account, Connection, Resource } from './types'

/**
 * Returns databases that PostgreSQL reports as directly owned by this exact
 * account. Role membership is deliberately not interpreted here: discovery's
 * `attributes.owner` is the only source of truth for this presentation.
 */
export function directlyOwnedPostgresDatabases(
  account: Pick<Account, 'connection_id' | 'engine_identity'>,
  connection: Pick<Connection, 'id' | 'engine'> | undefined,
  resources: readonly Resource[],
): Resource[] {
  if (connection === undefined || connection.engine !== 'postgres') return []

  return resources
    .filter((resource) =>
      resource.connection_id === account.connection_id &&
      resource.connection_id === connection.id &&
      resource.kind === 'database' &&
      resource.status === 'observed' &&
      resourceOwner(resource.attributes) === account.engine_identity,
    )
    .sort((left, right) => left.name.localeCompare(right.name))
}

function resourceOwner(attributes: unknown): string | null {
  if (attributes === null || typeof attributes !== 'object' || Array.isArray(attributes)) {
    return null
  }
  const owner = (attributes as Record<string, unknown>).owner
  return typeof owner === 'string' ? owner : null
}
