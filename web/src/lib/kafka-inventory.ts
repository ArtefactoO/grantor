import type { Connection } from './types'

/** PLAIN credentials live in broker configuration, outside the Kafka user API. */
export function kafkaPlainInventoryOnly(connection: Connection): boolean {
  const topology = connection.topology as Record<string, unknown> | null
  const configuration = connection.discovery_config as Record<string, unknown> | null
  return connection.engine === 'kafka' &&
    topology?.acl_authorizer === 'disabled' &&
    configuration?.sasl_mechanism === 'plain'
}
