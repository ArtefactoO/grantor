// Панель подробностей права. Использует общий Drawer — тот же, что у
// аккаунтов, поэтому Escape, ловушка фокуса, inert-фон и возврат фокуса на
// исходную строку работают единообразно и здесь их переопределять не нужно.
//
// Содержимое отвечает на вопрос «что это за право и откуда оно взялось»:
// разобранные поля, специфика движка и полное исходное выражение. Каждое
// значение можно скопировать отдельно, всё право — целиком.
import type { PermissionEntry } from '../lib/permission-view'
import { categoryLabel, detailLabel } from '../lib/permission-view'
import { CopyableValue, Drawer } from '@project/ui'

export interface PermissionDetailsDrawerProps {
  entry: PermissionEntry | null
  engine: string
  accountLabel?: string
  onClose: () => void
}

export function PermissionDetailsDrawer({
  entry,
  engine,
  accountLabel,
  onClose,
}: PermissionDetailsDrawerProps) {
  if (entry === null) {
    return null
  }

  const { view } = entry

  return (
    <Drawer open onClose={onClose} title="Право доступа" description={entry.label}>
      <div className="space-y-4">
        {/*
          Полное выражение — первое и без сокращения: ради него панель и
          открывают. CopyableValue переносит длинные идентификаторы по
          безопасным границам, не теряя символов.
        */}
        <section className="space-y-1">
          <h3 className="text-[11px] uppercase tracking-wide text-muted">Полное выражение</h3>
          <CopyableValue value={entry.raw} fill identifierWrap label="Скопировать право" />
        </section>

        {entry.dangerous && (
          <section className="rounded border border-danger/40 bg-danger/5 p-2">
            <h3 className="text-[11px] uppercase tracking-wide text-danger">Опасное право</h3>
            <p className="mt-1 text-xs text-fg">{view.danger_reason}</p>
          </section>
        )}

        <section className="space-y-2">
          <h3 className="text-[11px] uppercase tracking-wide text-muted">Что это</h3>
          <FieldList
            fields={[
              { label: 'Движок', value: engine },
              { label: 'Вид', value: categoryLabel(view.category) },
              { label: 'Действие', value: view.action },
              { label: 'Ресурс', value: view.resource },
              // Область показывается, только когда добавляет смысл: у kafka
              // scope-ресурсом выступает сам топик, и вторая одинаковая
              // строка ничего не сообщает.
              { label: 'Область действия', value: view.scope === view.resource ? '' : view.scope },
              { label: 'Аккаунт', value: accountLabel ?? '' },
            ]}
          />
        </section>

        <section className="space-y-2">
          <h3 className="text-[11px] uppercase tracking-wide text-muted">Состояние</h3>
          <FieldList
            fields={[
              {
                label: 'Управление',
                value: entry.managed ? 'управляется grantor' : 'вне управления (unmanaged)',
                copyable: false,
              },
              {
                label: 'В целевой системе',
                value: entry.present ? 'присутствует' : 'отсутствует',
                copyable: false,
              },
              { label: 'Синхронизация', value: entry.status, copyable: false },
            ]}
          />
        </section>

        {view.details !== null && view.details.length > 0 && (
          <section className="space-y-2">
            <h3 className="text-[11px] uppercase tracking-wide text-muted">Параметры движка</h3>
            <FieldList
              fields={view.details.map((detail) => ({
                label: detailLabel(detail.key),
                value: detail.value,
              }))}
            />
          </section>
        )}
      </div>
    </Drawer>
  )
}

interface Field {
  label: string
  value: string
  copyable?: boolean
}

/**
 * Список «подпись — значение». Пустые значения пропускаются: пустая строка в
 * панели читается как «неизвестно», хотя на деле поле просто неприменимо к
 * этому виду права.
 */
function FieldList({ fields }: { fields: Field[] }) {
  const shown = fields.filter((field) => field.value !== '')
  if (shown.length === 0) {
    return null
  }
  return (
    <dl className="space-y-1.5">
      {shown.map((field) => (
        <div key={field.label} className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-2">
          <dt className="text-xs text-muted">{field.label}</dt>
          <dd className="min-w-0 text-xs text-fg">
            {field.copyable === false ? (
              <span>{field.value}</span>
            ) : (
              <CopyableValue
                value={field.value}
                fill
                compactAction
                label={`Скопировать: ${field.label}`}
              />
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}
