import { useMemo } from 'react'
import { Button, CopyButton, Dialog, Field, Textarea } from '@project/ui'
import { roleSnapshotDocument, roleTemplateByKey, roleTemplateForPermission } from '../lib/role-template-selection'
import { serializeRoleTemplatesDocument } from '../lib/role-template-document'
import type { RoleTemplateCatalog } from '../lib/role-template-document'
import type { Connection, Permission } from '../lib/types'

export interface ConnectionRoleDefinitionDialogProps {
  connection: Connection
  templateKey?: string
  permission?: Permission
  onClose: () => void
  onCreate?: (catalog: RoleTemplateCatalog) => void
}

export function ConnectionRoleDefinitionDialog({
  connection, templateKey, permission, onClose, onCreate,
}: ConnectionRoleDefinitionDialogProps) {
  const template = useMemo(() => templateKey !== undefined
    ? roleTemplateByKey(connection, templateKey)
    : permission !== undefined ? roleTemplateForPermission(connection, permission) : null,
  [connection, templateKey, permission])
  const document = useMemo(() => {
    try {
      return template !== null ? serializeRoleTemplatesDocument(template)
        : permission !== undefined ? roleSnapshotDocument(permission) : null
    } catch {
      return null
    }
  },
  [template, permission])
  const name = template?.templates[0]?.name ?? permission?.name ?? templateKey

  return (
    <Dialog
      open
      title="Описание роли"
      description={template !== null ? 'Шаблон роли для копирования и создания по образцу.' : 'Снимок роли из discovery; не документ для создания.'}
      onClose={onClose}
      footer={(
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" onClick={onClose}>Закрыть описание</Button>
          {template !== null && document !== null && onCreate !== undefined && (
            <Button onClick={() => onCreate(template)}>Создать по образцу</Button>
          )}
        </div>
      )}
    >
      <div className="space-y-3">
        <h3 className="break-words text-sm font-medium text-text">{name}</h3>
        <p className={`text-xs leading-relaxed ${template === null && permission !== undefined ? 'text-warn' : 'text-muted'}`}>
          {template !== null
            ? 'Это сохранённый шаблон желаемых прав, а не фактическое состояние. Скопируйте JSON в «Создать шаблон → JSON» и измените key и нужные параметры. Для новой роли измените также role_name.'
            : permission !== undefined
              ? 'Копирование прав этой роли пока недоступно. Ниже только метаданные из discovery, их нельзя вставить в создание шаблона.'
              : 'Шаблон больше не найден в каталоге подключения. Закройте описание и обновите список.'}
        </p>
        {template !== null && (
          <p className="text-xs leading-relaxed text-muted">
            {template.engine === 'rabbitmq'
              ? 'Сохраните новый шаблон, затем назначьте его аккаунту через управление ролями.'
              : 'Сохраните новый шаблон, дождитесь синхронизации и проверьте изменения перед «Применить policy».'}
          </p>
        )}
        {template !== null && document === null && (
          <p role="alert" className="text-xs text-warn">
            Шаблон не соответствует формату JSON v1. Исправьте его через «Редактировать шаблоны».
          </p>
        )}
        {document !== null && (
          <>
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span>{template !== null ? 'Шаблон для создания · JSON v1' : 'Метаданные · не для создания'}</span>
              <CopyButton value={document} label={template !== null ? 'Копировать JSON роли' : 'Копировать снимок роли'} />
            </div>
            <Field label={template !== null ? 'JSON роли' : 'Снимок роли JSON'}>
              <Textarea value={document} readOnly spellCheck={false} className="min-h-72 resize-y font-mono text-[12px]" />
            </Field>
          </>
        )}
      </div>
    </Dialog>
  )
}
