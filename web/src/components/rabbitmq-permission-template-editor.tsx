import { Plus, Trash2 } from '@project/ui/icons'
import { Button, Field, Input, Textarea } from '@project/ui'
import {
  EMPTY_RABBITMQ_PERMISSION_TEMPLATE,
  rabbitMQTemplateIsBroad,
} from '../lib/rabbitmq-permission-templates'
import type { RabbitMQPermissionTemplate } from '../lib/rabbitmq-permission-templates'

export interface RabbitMQPermissionTemplateEditorProps {
  templates: readonly RabbitMQPermissionTemplate[]
  disabled?: boolean
  onChange: (templates: RabbitMQPermissionTemplate[]) => void
}

export function RabbitMQPermissionTemplateEditor({
  templates,
  disabled = false,
  onChange,
}: RabbitMQPermissionTemplateEditorProps) {
  const update = <K extends keyof RabbitMQPermissionTemplate>(
    index: number,
    key: K,
    value: RabbitMQPermissionTemplate[K],
  ) => {
    onChange(templates.map((template, current) =>
      current === index ? { ...template, [key]: value } : { ...template },
    ))
  }

  return (
    <section className="space-y-3" aria-labelledby="rabbitmq-permission-templates-title">
      <div className="space-y-3">
        <div>
          <h3 id="rabbitmq-permission-templates-title" className="text-xs font-semibold uppercase tracking-wide text-muted">
            Шаблоны прав RabbitMQ
          </h3>
          <p className="mt-1 text-xs text-faint">
            Операторы назначают только эти проверенные наборы configure/write/read. Произвольных regex в выдаче нет.
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={disabled}
          onClick={() => onChange([
            ...templates.map((template) => ({ ...template })),
            { ...EMPTY_RABBITMQ_PERMISSION_TEMPLATE },
          ])}
        >
          <Plus className="size-3.5" />
          Добавить
        </Button>
      </div>

      {templates.length === 0 ? (
        <p className="rounded-md border border-dashed border-line px-3 py-4 text-center text-xs text-faint">
          Шаблоны не заведены. Legacy-права полного доступа к vhost остаются доступны отдельно.
        </p>
      ) : templates.map((template, index) => (
        <fieldset key={index} disabled={disabled} className="space-y-3 rounded-md border border-line bg-panel p-3">
          <legend className="px-1 text-xs font-medium text-muted">
            {template.name.trim() || `Шаблон ${index + 1}`}
          </legend>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Ключ" hint="Стабильный machine id; не менять после назначения">
              <Input
                value={template.key}
                required
                pattern="[a-z0-9][a-z0-9_-]{0,63}"
                className="font-mono text-[13px]"
                placeholder="etl-worker"
                onChange={(event) => update(index, 'key', event.target.value)}
              />
            </Field>
            <Field label="Vhost">
              <Input
                value={template.vhost}
                required
                className="font-mono text-[13px]"
                placeholder="sl-project"
                onChange={(event) => update(index, 'vhost', event.target.value)}
              />
            </Field>
          </div>
          <Field label="Название">
            <Input
              value={template.name}
              required
              placeholder="ETL worker queues"
              onChange={(event) => update(index, 'name', event.target.value)}
            />
          </Field>
          <Field label="Описание">
            <Textarea
              value={template.description}
              required
              placeholder="Каким сервисам и для какого потока предназначен шаблон"
              onChange={(event) => update(index, 'description', event.target.value)}
            />
          </Field>
          <div className="grid gap-3">
            {(['configure', 'write', 'read'] as const).map((key) => (
              <Field
                key={key}
                label={`${key} regex`}
                hint={'Безопасный subset: `.*` либо `^literal$`; alternation: `^(one|two)$`, wildcard: `.*`.'}
              >
                <Input
                  value={template[key]}
                  required
                  className="font-mono text-[12px]"
                  onChange={(event) => update(index, key, event.target.value)}
                />
              </Field>
            ))}
          </div>
          {rabbitMQTemplateIsBroad(template) && (
            <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
              Broad: хотя бы один regex разрешает все имена (`.*`). Это информационная пометка; dangerous задаётся отдельно.
            </p>
          )}
          <div className="flex flex-wrap items-center justify-between gap-3">
            <label className="flex items-center gap-2 text-xs text-muted">
              <input
                type="checkbox"
                checked={template.dangerous}
                onChange={(event) => update(index, 'dangerous', event.target.checked)}
                className="size-4 accent-[var(--accent)]"
              />
              Dangerous: назначение только admin с подтверждением
            </label>
            <Button
              type="button"
              variant="danger"
              size="sm"
              onClick={() => onChange(templates.filter((_, current) => current !== index).map((item) => ({ ...item })))}
            >
              <Trash2 className="size-3.5" />
              Удалить
            </Button>
          </div>
        </fieldset>
      ))}
    </section>
  )
}
