// Per-engine поля формы подключения. Единая форма для всех движков
// показывала «Базу для discovery» RabbitMQ и прятала SASL у Kafka; здесь
// описано, что каждый движок реально читает из discovery_config и по какому
// порту ходит. Бекенд-двойник — validateDiscoveryConfig (create и PATCH):
// расхождение таблицы с ним всплывает как 400 при отправке формы.

export type DiscoveryFieldKey =
  | 'database'
  | 'auth_source'
  | 'default_account_host'
  | 'replica_set'
  | 'sasl_mechanism'
  | 'security_protocol'

export interface DiscoveryFieldSpec {
  key: DiscoveryFieldKey
  label: string
  /** Подпись под полем: что означает пустое значение. */
  hint: string
  placeholder?: string
  /** Селект вместо свободного ввода. */
  options?: ReadonlyArray<{ value: string; label: string }>
}

export interface EngineFormSpec {
  /** Поля discovery_config, которые движок действительно читает. */
  discoveryFields: ReadonlyArray<DiscoveryFieldSpec>
  endpointsPlaceholder: string
  /** Сколько endpoints использует адаптер: кроме mongodb/kafka — только первый. */
  endpointsHint: string
}

const SASL_MECHANISM_OPTIONS = [
  { value: '', label: 'scram-sha-256 (по умолчанию)' },
  { value: 'none', label: 'none (без SASL)' },
  { value: 'plain', label: 'plain' },
  { value: 'scram-sha-256', label: 'scram-sha-256' },
  { value: 'scram-sha-512', label: 'scram-sha-512' },
] as const

const SECURITY_PROTOCOL_OPTIONS = [
  { value: '', label: 'авто (по SASL и TLS)' },
  { value: 'plaintext', label: 'plaintext' },
  { value: 'sasl_plaintext', label: 'sasl_plaintext' },
  { value: 'sasl_ssl', label: 'sasl_ssl' },
  { value: 'ssl', label: 'ssl' },
] as const

const DATABASE_FIELD: DiscoveryFieldSpec = {
  key: 'database',
  label: 'База для discovery',
  hint: 'discovery_config.database',
  placeholder: 'appdb',
}

export const ENGINE_FORMS: Readonly<Record<string, EngineFormSpec>> = {
  postgres: {
    discoveryFields: [{ ...DATABASE_FIELD, hint: 'Пусто: база postgres' }],
    endpointsPlaceholder: 'db.example.com:5432',
    endpointsHint: 'Адаптер использует только первый endpoint',
  },
  mysql: {
    discoveryFields: [
      { ...DATABASE_FIELD, hint: 'Пусто: подключение без базы по умолчанию' },
      {
        key: 'default_account_host',
        label: 'Host учётных записей',
        hint: 'Часть identity user@host создаваемых учёток; пусто: "%"',
        placeholder: '%',
      },
    ],
    endpointsPlaceholder: 'db.example.com:3306',
    endpointsHint: 'Адаптер использует только первый endpoint',
  },
  mongodb: {
    discoveryFields: [
      {
        key: 'auth_source',
        label: 'Auth database',
        hint: 'База аутентификации admin credential и учёток; пусто: admin',
        placeholder: 'admin',
      },
      {
        key: 'replica_set',
        label: 'Replica set',
        hint: 'Пусто: без явного replica set',
        placeholder: 'rs0',
      },
    ],
    endpointsPlaceholder: 'mongo-1.example.com:27017\nmongo-2.example.com:27017',
    endpointsHint: 'Используются все endpoints',
  },
  kafka: {
    discoveryFields: [
      {
        key: 'sasl_mechanism',
        label: 'SASL mechanism',
        hint: 'Механизм аутентификации admin credential',
        options: SASL_MECHANISM_OPTIONS,
      },
      {
        key: 'security_protocol',
        label: 'Security protocol',
        hint: 'ssl/sasl_ssl требуют настроенного TLS',
        options: SECURITY_PROTOCOL_OPTIONS,
      },
    ],
    endpointsPlaceholder: 'broker-1.example.com:9092\nbroker-2.example.com:9092',
    endpointsHint: 'Все endpoints используются как seed brokers',
  },
  rabbitmq: {
    discoveryFields: [],
    endpointsPlaceholder: 'rabbit.example.com:15672',
    endpointsHint: 'Management HTTP API (обычно порт 15672); только первый endpoint',
  },
  clickhouse: {
    discoveryFields: [],
    endpointsPlaceholder: 'clickhouse.example.com:8123',
    endpointsHint: 'HTTP-интерфейс (обычно порт 8123); только первый endpoint',
  },
  redis: {
    discoveryFields: [],
    endpointsPlaceholder: 'redis.example.com:6379',
    endpointsHint: 'Адаптер использует только первый endpoint',
  },
}

const FALLBACK_FORM: EngineFormSpec = {
  discoveryFields: [DATABASE_FIELD],
  endpointsPlaceholder: 'host:port',
  endpointsHint: 'По одному host:port на строку',
}

/** Спецификация формы движка; неизвестный движок получает generic-набор. */
export function engineFormSpec(engine: string): EngineFormSpec {
  return ENGINE_FORMS[engine] ?? FALLBACK_FORM
}

/**
 * Собирает discovery_config из значений формы: только поля текущего движка
 * и только непустые значения — чужие ключи не утекают при смене движка.
 */
export function buildDiscoveryConfig(
  engine: string,
  values: Partial<Record<DiscoveryFieldKey, string>>,
): Record<string, string> | undefined {
  const config: Record<string, string> = {}
  for (const field of engineFormSpec(engine).discoveryFields) {
    const value = (values[field.key] ?? '').trim()
    if (value !== '') config[field.key] = value
  }
  return Object.keys(config).length > 0 ? config : undefined
}
