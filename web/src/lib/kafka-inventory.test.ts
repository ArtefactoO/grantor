import { describe, expect, it } from 'vitest'
import { kafkaPlainInventoryOnly } from './kafka-inventory'
import type { Connection } from './types'

describe('Kafka PLAIN catalog explanation', () => {
  const connection = {
    engine: 'kafka', discovery_config: { sasl_mechanism: 'plain' },
    topology: { acl_authorizer: 'disabled' },
  } as Connection

  it('requires the confirmed disabled authorizer and PLAIN mechanism', () => {
    expect(kafkaPlainInventoryOnly(connection)).toBe(true)
    expect(kafkaPlainInventoryOnly({ ...connection, topology: null })).toBe(false)
    expect(kafkaPlainInventoryOnly({ ...connection, topology: {} })).toBe(false)
    expect(kafkaPlainInventoryOnly({ ...connection, discovery_config: { sasl_mechanism: 'scram-sha-512' } })).toBe(false)
    expect(kafkaPlainInventoryOnly({ ...connection, engine: 'redis' })).toBe(false)
  })
})
