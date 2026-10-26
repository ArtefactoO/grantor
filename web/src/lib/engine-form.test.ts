import { describe, expect, it } from 'vitest'
import { buildDiscoveryConfig, engineFormSpec, ENGINE_FORMS } from './engine-form'

describe('per-engine форма подключения', () => {
  // Единая форма показывала «Базу для discovery» движкам, которые её не
  // читают, — состав полей закреплён по факту чтения в адаптерах.
  it('движки без discovery-параметров не получают полей', () => {
    for (const engine of ['rabbitmq', 'clickhouse', 'redis']) {
      expect(engineFormSpec(engine).discoveryFields, engine).toHaveLength(0)
    }
  })

  it('поля соответствуют ключам, которые читает бекенд', () => {
    const keysOf = (engine: string) =>
      engineFormSpec(engine).discoveryFields.map((field) => field.key)
    expect(keysOf('postgres')).toEqual(['database'])
    expect(keysOf('mysql')).toEqual(['database', 'default_account_host'])
    expect(keysOf('mongodb')).toEqual(['auth_source', 'replica_set'])
    expect(keysOf('kafka')).toEqual(['sasl_mechanism', 'security_protocol'])
  })

  it('неизвестный движок получает generic-набор, а не пустую форму', () => {
    expect(engineFormSpec('future-engine').discoveryFields.length).toBeGreaterThan(0)
  })

  // Ключи чужого движка не должны утекать в payload при смене движка в
  // форме: бекенд ответит 400 на sasl_mechanism у postgres.
  it('buildDiscoveryConfig отдаёт только поля текущего движка', () => {
    const values = {
      database: 'appdb',
      sasl_mechanism: 'plain',
      auth_source: 'admin',
    }
    expect(buildDiscoveryConfig('postgres', values)).toEqual({ database: 'appdb' })
    expect(buildDiscoveryConfig('kafka', values)).toEqual({ sasl_mechanism: 'plain' })
  })

  it('пустые значения не попадают в discovery_config', () => {
    expect(buildDiscoveryConfig('postgres', { database: '  ' })).toBeUndefined()
    expect(buildDiscoveryConfig('rabbitmq', { database: 'ignored' })).toBeUndefined()
  })

  it('каждый движок объявляет подсказку по endpoints', () => {
    for (const [engine, spec] of Object.entries(ENGINE_FORMS)) {
      expect(spec.endpointsPlaceholder, engine).not.toBe('')
      expect(spec.endpointsHint, engine).not.toBe('')
    }
  })
})
