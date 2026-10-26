export interface RabbitMQPermissionTemplate {
  key: string
  name: string
  description: string
  vhost: string
  configure: string
  write: string
  read: string
  dangerous: boolean
}

export const EMPTY_RABBITMQ_PERMISSION_TEMPLATE: RabbitMQPermissionTemplate = {
  key: '',
  name: '',
  description: '',
  vhost: '',
  configure: '^$',
  write: '^$',
  read: '^$',
  dangerous: false,
}

export function readRabbitMQPermissionTemplates(value: unknown): RabbitMQPermissionTemplate[] {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return []
  const raw = (value as Record<string, unknown>).rabbitmq_permission_templates
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    if (typeof item !== 'object' || item === null || Array.isArray(item)) return []
    const record = item as Record<string, unknown>
    const stringField = (key: string) => typeof record[key] === 'string' ? record[key] as string : ''
    return [{
      key: stringField('key'),
      name: stringField('name'),
      description: stringField('description'),
      vhost: stringField('vhost'),
      configure: stringField('configure'),
      write: stringField('write'),
      read: stringField('read'),
      dangerous: record.dangerous === true,
    }]
  })
}

export function rabbitMQTemplateIsBroad(template: RabbitMQPermissionTemplate): boolean {
  return template.configure === '.*' || template.write === '.*' || template.read === '.*'
}
