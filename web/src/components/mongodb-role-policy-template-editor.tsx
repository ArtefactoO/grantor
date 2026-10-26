import { useEffect, useId, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronRight, Plus, Trash2, TriangleAlert } from '@project/ui/icons'
import type {
  MongoDBRolePolicyPrivilege,
  MongoDBRolePolicyResource,
  MongoDBRolePolicyRoleRef,
  MongoDBRolePolicyTemplate,
} from '../lib/types'
import {
  cloneMongoDBRolePolicyTemplate,
  EMPTY_MONGODB_ROLE_POLICY_PRIVILEGE,
  EMPTY_MONGODB_ROLE_POLICY_ROLE_REF,
  EMPTY_MONGODB_ROLE_POLICY_TEMPLATE,
  MONGODB_ROLE_POLICY_ACTIONS,
  mongoDBActionSupportsResource,
  mongoDBResourceForKind,
  mongoDBResourceKind,
  mongoDBRolePolicyTemplateIssues,
  mongoDBTemplateDangerPreview,
} from '../lib/mongodb-role-policy-templates'
import type { MongoDBResourceKind } from '../lib/mongodb-role-policy-templates'
import { Button, Combobox, Field, Input, MultiCombobox } from '@project/ui'

export interface MongoDBRolePolicyTemplateEditorProps {
  templates: readonly MongoDBRolePolicyTemplate[]
  databaseHint?: string
  disabled?: boolean
  onChange: (templates: MongoDBRolePolicyTemplate[]) => void
}

interface LazyEditorDisclosureProps {
  label: string
  meta?: ReactNode
  metaDescription?: string
  className?: string
  forceOpen?: boolean
  render: () => ReactNode
}

/** Closed disclosures do not evaluate render(), keeping large catalogs bounded. */
function LazyEditorDisclosure({
  label,
  meta,
  metaDescription,
  className = '',
  forceOpen = false,
  render,
}: LazyEditorDisclosureProps) {
  const [open, setOpen] = useState(false)
  const bodyId = useId()
  const metaId = useId()
  useEffect(() => {
    if (forceOpen) setOpen(true)
  }, [forceOpen])
  const visible = forceOpen || open
  return (
    <section className={className}>
      <button
        type="button"
        aria-expanded={visible}
        aria-controls={bodyId}
        aria-describedby={metaDescription !== undefined ? metaId : undefined}
        aria-disabled={forceOpen || undefined}
        aria-label={`${visible ? 'Свернуть' : 'Развернуть'} ${label}`}
        className="flex min-h-10 w-full items-center gap-2 px-3 py-2 text-left text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
        onClick={() => {
          if (!forceOpen) setOpen((current) => !current)
        }}
      >
        <ChevronRight
          className={`size-3.5 shrink-0 ${visible ? 'rotate-90' : ''}`}
          aria-hidden="true"
        />
        <span className="min-w-0 flex-1 break-words">{label}</span>
        {meta !== undefined && (
          <span className="min-w-0 max-w-[52%] truncate text-faint" aria-hidden="true">
            {meta}
          </span>
        )}
        {metaDescription !== undefined && (
          <span id={metaId} className="sr-only">{metaDescription}</span>
        )}
      </button>
      {visible && <div id={bodyId}>{render()}</div>}
    </section>
  )
}

function editorResourceLabel(resource: MongoDBRolePolicyResource): string {
  if ('cluster' in resource) return 'cluster'
  if ('any_resource' in resource) return 'anyResource (запрещён)'
  const database = resource.db ?? ''
  const collection = resource.collection ?? ''
  if (database === '' && collection === '') return 'all databases'
  if (database === '') return `all databases · ${collection}`
  return collection === '' ? `${database}.*` : `${database}.${collection}`
}

interface MongoDBTemplateDisclosureProps {
  template: MongoDBRolePolicyTemplate
  templateIndex: number
  forceOpen: boolean
  render: (context: {
    dangerPreview: string[]
    issues: string[]
    templateLabel: string
  }) => ReactNode
}

interface MongoDBTemplateAnalysis {
  dangerPreview: string[]
  issues: string[]
}

const templateAnalysisCache = new WeakMap<
  MongoDBRolePolicyTemplate,
  MongoDBTemplateAnalysis
>()

function analyzeTemplate(template: MongoDBRolePolicyTemplate): MongoDBTemplateAnalysis {
  const cached = templateAnalysisCache.get(template)
  if (cached !== undefined) return cached
  const analysis = {
    dangerPreview: mongoDBTemplateDangerPreview(template),
    issues: mongoDBRolePolicyTemplateIssues(template),
  }
  templateAnalysisCache.set(template, analysis)
  return analysis
}

function MongoDBTemplateDisclosure({
  template,
  templateIndex,
  forceOpen,
  render,
}: MongoDBTemplateDisclosureProps) {
  const { dangerPreview, issues } = useMemo(() => analyzeTemplate(template), [template])
  const templateLabel = template.name.trim() || template.key.trim() || `Policy ${templateIndex + 1}`
  const identity = `${template.role_database || '—'}.${template.role_name || '—'}`
  return (
    <LazyEditorDisclosure
      label={`Policy: ${templateLabel}`}
      forceOpen={forceOpen}
      meta={(
        <span className="inline-flex min-w-0 max-w-full items-center gap-1.5">
          <span className="min-w-0 truncate" title={identity}>
            {identity} · {template.privileges.length} privileges · {template.inherited_roles.length} roles
          </span>
          {issues.length > 0 && (
            <span className="shrink-0 rounded-full bg-warn-soft px-1.5 py-0.5 text-[10px] text-warn">
              Invalid · {issues.length}
            </span>
          )}
        </span>
      )}
      metaDescription={`${identity}; ${template.privileges.length} privileges; ${template.inherited_roles.length} inherited roles${issues.length > 0 ? `; Invalid: ${issues.length} issues` : ''}`}
      className="overflow-hidden rounded-md border border-line bg-panel"
      render={() => render({ dangerPreview, issues, templateLabel })}
    />
  )
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length
}

function actionCategory(action: string): string {
  if (/(?:User|Role|Password|Authentication|CustomData)|grantRole|revokeRole|impersonate/.test(action)) {
    return 'Users and roles'
  }
  if (/^(?:find|insert|update|remove|changeStream|bypassDocumentValidation)$/.test(action)) {
    return 'Data access'
  }
  if (/(?:Collection|Index|coll|dbHash|dbStats|validate|planCache|Search)/.test(action)) {
    return 'Collections and indexes'
  }
  if (/^(?:get|list|serverStatus|hostInfo|top|inprog|queryStats|shardingState|replSetGet)/.test(action)) {
    return 'Diagnostics'
  }
  return 'Cluster and maintenance'
}

const ACTION_OPTIONS = MONGODB_ROLE_POLICY_ACTIONS.map((action) => ({
  value: action,
  label: action,
  description: actionCategory(action),
  keywords: [actionCategory(action)],
}))

const RESOURCE_KIND_OPTIONS = [
  {
    value: 'collection',
    label: 'Collection',
    description: 'Одна коллекция в одной базе',
  },
  {
    value: 'database',
    label: 'Database',
    description: 'Все non-system collections базы',
  },
  {
    value: 'collection_across_databases',
    label: 'Collection in all databases',
    description: 'Только для custom role в admin; dangerous',
  },
  {
    value: 'all_databases',
    label: 'All databases',
    description: 'Только для custom role в admin; dangerous',
  },
  {
    value: 'cluster',
    label: 'Cluster',
    description: 'Только для custom role в admin; dangerous',
  },
] satisfies Array<{ value: MongoDBResourceKind; label: string; description: string }>

function draft(databaseHint: string): MongoDBRolePolicyTemplate {
  const roleDatabase = databaseHint.trim()
  return {
    ...cloneMongoDBRolePolicyTemplate(EMPTY_MONGODB_ROLE_POLICY_TEMPLATE),
    role_database: roleDatabase,
  }
}

function clonePrivilege(privilege: MongoDBRolePolicyPrivilege): MongoDBRolePolicyPrivilege {
  return cloneMongoDBRolePolicyTemplate({
    ...EMPTY_MONGODB_ROLE_POLICY_TEMPLATE,
    privileges: [privilege],
  }).privileges[0] ?? { ...EMPTY_MONGODB_ROLE_POLICY_PRIVILEGE }
}

export function MongoDBRolePolicyTemplateEditor({
  templates,
  databaseHint = '',
  disabled = false,
  onChange,
}: MongoDBRolePolicyTemplateEditorProps) {
  const replaceTemplate = (
    index: number,
    update: (template: MongoDBRolePolicyTemplate) => MongoDBRolePolicyTemplate,
  ) => {
    onChange(templates.map((template, current) =>
      current === index ? update(template) : template))
  }

  const updateField = <K extends keyof MongoDBRolePolicyTemplate>(
    index: number,
    key: K,
    value: MongoDBRolePolicyTemplate[K],
  ) => replaceTemplate(index, (template) => ({ ...template, [key]: value }))

  const updateInheritedRole = (
    templateIndex: number,
    roleIndex: number,
    key: keyof MongoDBRolePolicyRoleRef,
    value: string,
  ) => replaceTemplate(templateIndex, (template) => ({
    ...template,
    inherited_roles: template.inherited_roles.map((role, current) =>
      current === roleIndex ? { ...role, [key]: value } : role),
  }))

  const updatePrivilege = (
    templateIndex: number,
    privilegeIndex: number,
    update: (privilege: MongoDBRolePolicyPrivilege) => MongoDBRolePolicyPrivilege,
  ) => replaceTemplate(templateIndex, (template) => ({
    ...template,
    privileges: template.privileges.map((privilege, current) => {
      return current === privilegeIndex ? update(clonePrivilege(privilege)) : privilege
    }),
  }))

  const firstInvalidTemplateIndex = useMemo(
    () => templates.findIndex((template) => analyzeTemplate(template).issues.length > 0),
    [templates],
  )

  return (
    <section className="space-y-3" aria-labelledby="mongodb-role-policy-templates-title">
      <div className="space-y-3">
        <div className="min-w-0 flex-1">
          <h3
            id="mongodb-role-policy-templates-title"
            className="text-xs font-semibold uppercase tracking-wide text-muted"
          >
            MongoDB custom-role policies
          </h3>
          <p className="mt-1 max-w-3xl text-xs text-faint">
            Шаблон задаёт exact custom role: прямые privileges и наследование. Операторы
            назначают только synced-роль; произвольного BSON и target-команд в форме нет.
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={disabled || templates.length >= 64}
          onClick={() => onChange([
            ...templates,
            draft(databaseHint),
          ])}
        >
          <Plus className="size-3.5" aria-hidden="true" />
          Добавить policy
        </Button>
      </div>

      {templates.length >= 64 && (
        <p className="text-xs text-warn">Достигнут лимит каталога: 64 policies.</p>
      )}

      {templates.length === 0 ? (
        <p className="rounded-md border border-dashed border-line px-3 py-4 text-center text-xs text-faint">
          Policies не заведены. Built-in read/readWrite продолжают назначаться как обычные роли.
        </p>
      ) : templates.map((template, templateIndex) => (
          <MongoDBTemplateDisclosure
            key={templateIndex}
            template={template}
            templateIndex={templateIndex}
            forceOpen={templateIndex === firstInvalidTemplateIndex}
            render={({ dangerPreview, issues, templateLabel }) => {
              const firstInvalidPrivilegeIndex = template.privileges.findIndex((_, index) =>
                issues.some((issue) => issue.startsWith(`Privilege ${index + 1}:`)))
              return (
              <fieldset disabled={disabled} className="space-y-4 border-t border-line p-3">
                <legend className="sr-only">{templateLabel}</legend>

                {issues.length > 0 && (
                  <div role="alert" className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
                    <p className="font-medium">Исправьте policy перед сохранением</p>
                    <ul className="mt-1 list-disc space-y-1 ps-4">
                      {issues.slice(0, 6).map((issue) => <li key={issue}>{issue}</li>)}
                    </ul>
                    {issues.length > 6 && <p className="mt-1">И ещё: {issues.length - 6}.</p>}
                  </div>
                )}

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Ключ" hint="Стабильный machine id; identity нельзя менять после управления">
                <Input
                  value={template.key}
                  required
                  pattern="[a-z0-9][a-z0-9_-]{0,63}"
                  maxLength={64}
                  className="font-mono text-[13px]"
                  placeholder="etl-reader"
                  onChange={(event) => updateField(templateIndex, 'key', event.target.value)}
                />
              </Field>
              <Field label="Role database" hint="База, в которой хранится custom role">
                <Input
                  value={template.role_database}
                  required
                  maxLength={63}
                  pattern="[A-Za-z0-9_][A-Za-z0-9_-]{0,62}"
                  className="font-mono text-[13px]"
                  placeholder="appdb"
                  onChange={(event) => replaceTemplate(templateIndex, (current) => {
                    const nextDatabase = event.target.value
                    return {
                      ...current,
                      role_database: nextDatabase,
                      inherited_roles: current.role_database !== 'admin'
                        ? current.inherited_roles.map((role) => ({ ...role, db: nextDatabase }))
                        : current.inherited_roles,
                      privileges: current.privileges.map((privilege) => {
                        if ('cluster' in privilege.resource || 'any_resource' in privilege.resource ||
                          current.role_database === 'admin') return privilege
                        return {
                          ...privilege,
                          resource: { ...privilege.resource, db: nextDatabase },
                        }
                      }),
                    }
                  })}
                />
              </Field>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <Field label="Custom role">
                <Input
                  value={template.role_name}
                  required
                  maxLength={128}
                  pattern="[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
                  className="font-mono text-[13px]"
                  placeholder="etlReader"
                  onChange={(event) => updateField(templateIndex, 'role_name', event.target.value)}
                />
              </Field>
              <Field label="Название" hint={`${utf8Bytes(template.name)}/128 bytes`}>
                <Input
                  value={template.name}
                  required
                  maxLength={128}
                  placeholder="ETL: чтение событий"
                  onChange={(event) => updateField(templateIndex, 'name', event.target.value)}
                />
              </Field>
            </div>

            <Field
              label="Описание"
              hint={`${utf8Bytes(template.description)}/512 bytes; одна строка, без control characters`}
            >
              <Input
                value={template.description}
                required
                maxLength={512}
                placeholder="Для каких сервисов и данных предназначена policy"
                onChange={(event) => updateField(templateIndex, 'description', event.target.value)}
              />
            </Field>

            <section className="space-y-2 border-t border-line/70 pt-3" aria-labelledby={`mongodb-inherited-${templateIndex}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <h4 id={`mongodb-inherited-${templateIndex}`} className="text-xs font-medium text-muted">
                    Наследуемые роли
                  </h4>
                  <p className="mt-0.5 text-xs text-faint">
                    Built-in: только read/readWrite. Остальные роли должны быть templates этого каталога;
                    циклы и неготовые dependencies блокируются.
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-label={`Добавить роль в policy ${templateLabel}`}
                  disabled={disabled || template.inherited_roles.length >= 64}
                  onClick={() => replaceTemplate(templateIndex, (current) => ({
                    ...current,
                    inherited_roles: [
                      ...current.inherited_roles,
                      {
                        ...EMPTY_MONGODB_ROLE_POLICY_ROLE_REF,
                        db: current.role_database === 'admin' ? '' : current.role_database,
                      },
                    ],
                  }))}
                >
                  <Plus className="size-3.5" aria-hidden="true" />
                  Добавить роль
                </Button>
              </div>

              {template.inherited_roles.length === 0 ? (
                <p className="text-xs text-faint">Прямого наследования нет.</p>
              ) : (
                <div className="space-y-2">
                  {template.inherited_roles.map((role, roleIndex) => (
                    <div
                      key={roleIndex}
                      className="grid min-w-0 gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]"
                    >
                      <Field label={`Role ${roleIndex + 1}`}>
                        <Input
                          value={role.role}
                          required
                          maxLength={128}
                          pattern="[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
                          className="font-mono text-[13px]"
                          placeholder="read"
                          onChange={(event) => updateInheritedRole(
                            templateIndex,
                            roleIndex,
                            'role',
                            event.target.value,
                          )}
                        />
                      </Field>
                      <Field label={`Database ${roleIndex + 1}`}>
                        <Input
                          value={role.db}
                          required
                          maxLength={63}
                          pattern="[A-Za-z0-9_][A-Za-z0-9_-]{0,62}"
                          readOnly={template.role_database !== 'admin'}
                          className="font-mono text-[13px]"
                          placeholder="appdb"
                          onChange={(event) => updateInheritedRole(
                            templateIndex,
                            roleIndex,
                            'db',
                            event.target.value,
                          )}
                        />
                      </Field>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={disabled}
                        className="self-end text-danger"
                        aria-label={`Удалить наследуемую роль ${roleIndex + 1} из ${templateLabel}`}
                        onClick={() => replaceTemplate(templateIndex, (current) => ({
                          ...current,
                          inherited_roles: current.inherited_roles
                            .filter((_, currentIndex) => currentIndex !== roleIndex),
                        }))}
                      >
                        <Trash2 className="size-3.5" aria-hidden="true" />
                        Удалить
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <section className="space-y-3 border-t border-line/70 pt-3" aria-labelledby={`mongodb-privileges-${templateIndex}`}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <h4 id={`mongodb-privileges-${templateIndex}`} className="text-xs font-medium text-muted">
                    Прямые privileges
                  </h4>
                  <p className="mt-0.5 text-xs text-faint">
                    Namespace, cross-database или cluster resource; actions только из allowlist.
                  </p>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  aria-label={`Добавить privilege в policy ${templateLabel}`}
                  disabled={disabled || template.privileges.length >= 128}
                  onClick={() => replaceTemplate(templateIndex, (current) => ({
                    ...current,
                    privileges: [
                      ...current.privileges,
                      {
                        ...clonePrivilege(EMPTY_MONGODB_ROLE_POLICY_PRIVILEGE),
                        resource: { db: current.role_database, collection: '' },
                      },
                    ],
                  }))}
                >
                  <Plus className="size-3.5" aria-hidden="true" />
                  Добавить privilege
                </Button>
              </div>

              {template.privileges.length === 0 ? (
                <p className="text-xs text-faint">Прямых privileges нет; роль может состоять только из inheritance.</p>
              ) : (
                <div className="divide-y divide-line/70 rounded-md border border-line/70">
                  {template.privileges.map((privilege, privilegeIndex) => {
                    const privilegeIssuePrefix = `Privilege ${privilegeIndex + 1}:`
                    const privilegeIssues = issues.filter((issue) => issue.startsWith(privilegeIssuePrefix))
                    return (
                      <LazyEditorDisclosure
                        key={privilegeIndex}
                        label={`Privilege ${privilegeIndex + 1}: ${editorResourceLabel(privilege.resource)}`}
                        forceOpen={privilegeIndex === firstInvalidPrivilegeIndex}
                        meta={privilegeIssues.length > 0
                          ? `${privilege.actions.length} actions · Invalid`
                          : `${privilege.actions.length} actions`}
                        metaDescription={`${privilege.actions.length} actions${privilegeIssues.length > 0 ? `; Invalid: ${privilegeIssues.length} issues` : ''}`}
                        render={() => {
                          const kind = mongoDBResourceKind(privilege.resource)
                          const databaseResource = 'db' in privilege.resource ? privilege.resource : null
                          const adminRole = template.role_database === 'admin'
                          const incompatibleActions = privilege.actions.filter(
                            (action) => !mongoDBActionSupportsResource(action, kind),
                          )
                          const incompatibleScope = !adminRole && (
                            kind === 'cluster' || kind === 'all_databases' ||
                            kind === 'collection_across_databases'
                          )
                          return (
                            <fieldset
                              disabled={disabled}
                              className="grid min-w-0 gap-3 border-t border-line/70 p-3 sm:grid-cols-2"
                            >
                              <legend className="sr-only">Privilege {privilegeIndex + 1}</legend>
                              {privilegeIssues.length > 0 && (
                                <ul className="list-disc space-y-1 rounded-md bg-warn-soft px-7 py-2 text-xs text-warn sm:col-span-2">
                                  {privilegeIssues.map((issue) => <li key={issue}>{issue}</li>)}
                                </ul>
                              )}
                        <Field label={`Resource ${privilegeIndex + 1}`}>
                          <Combobox
                            value={kind}
                            label={`Resource ${privilegeIndex + 1}`}
                            disabled={disabled}
                            placeholder={kind === 'any_resource'
                              ? 'anyResource запрещён. Выберите replacement'
                              : 'Выберите resource'}
                            options={RESOURCE_KIND_OPTIONS.map((option) => ({
                              ...option,
                              disabled: option.value === 'cluster' ||
                                option.value === 'all_databases' ||
                                option.value === 'collection_across_databases'
                                ? !adminRole
                                : false,
                            }))}
                            onValueChange={(value) => updatePrivilege(
                              templateIndex,
                              privilegeIndex,
                              (current) => ({
                                ...current,
                                resource: (() => {
                                  const next = mongoDBResourceForKind(
                                    (value || 'collection') as MongoDBResourceKind,
                                    current.resource,
                                  )
                                  return !adminRole && 'db' in next
                                    ? { ...next, db: template.role_database }
                                    : next
                                })(),
                              }),
                            )}
                          />
                        </Field>
                        <Field label={`Actions ${privilegeIndex + 1}`} hint="Только опубликованный allowlist">
                          <MultiCombobox
                            selected={new Set(privilege.actions)}
                            options={ACTION_OPTIONS.map((option) => ({
                              ...option,
                              disabled: !mongoDBActionSupportsResource(option.value, kind) &&
                                !privilege.actions.includes(option.value),
                            }))}
                            label={`Actions ${privilegeIndex + 1}`}
                            placeholder="Выберите actions"
                            allLabel="Все разрешённые actions"
                            disabled={disabled}
                            onChange={(selected) => updatePrivilege(
                              templateIndex,
                              privilegeIndex,
                              (current) => ({
                                ...current,
                                actions: MONGODB_ROLE_POLICY_ACTIONS.filter((action) => selected.has(action)),
                              }),
                            )}
                          />
                          {incompatibleActions.length > 0 && (
                            <p className="mt-1 text-xs text-danger">
                              Не подходят выбранному resource: {incompatibleActions.join(', ')}.
                              Уберите их перед сохранением.
                            </p>
                          )}
                        </Field>

                        {(kind === 'database' || kind === 'collection') && adminRole && (
                          <Field label={`Database scope ${privilegeIndex + 1}`}>
                            <Input
                              value={databaseResource?.db ?? ''}
                              required
                              maxLength={63}
                              pattern="[A-Za-z0-9_][A-Za-z0-9_-]{0,62}"
                              className="font-mono text-[13px]"
                              placeholder="appdb"
                              onChange={(event) => updatePrivilege(
                                templateIndex,
                                privilegeIndex,
                                (current) => ({
                                  ...current,
                                  resource: {
                                    db: event.target.value,
                                    collection: 'db' in current.resource
                                      ? current.resource.collection
                                      : '',
                                  },
                                }),
                              )}
                            />
                          </Field>
                        )}
                        {(kind === 'database' || kind === 'collection') && !adminRole && (
                          <div className="self-end rounded-md bg-panel2 px-3 py-2 text-xs text-muted">
                            Scope database:{' '}
                            <span className="break-all font-mono text-text">{template.role_database || '—'}</span>
                          </div>
                        )}
                        {kind !== 'cluster' && kind !== 'any_resource' && (
                          <Field
                            label={`Collection ${privilegeIndex + 1}`}
                            hint="Пусто: вся выбранная database scope"
                          >
                            <Input
                              value={databaseResource?.collection ?? ''}
                              maxLength={255}
                              pattern="[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}"
                              className="font-mono text-[13px]"
                              placeholder="events"
                              onChange={(event) => updatePrivilege(
                                templateIndex,
                                privilegeIndex,
                                (current) => ({
                                  ...current,
                                  resource: {
                                    db: 'db' in current.resource ? current.resource.db : '',
                                    collection: event.target.value,
                                  },
                                }),
                              )}
                            />
                          </Field>
                        )}

                        {(kind === 'any_resource' || incompatibleScope) && (
                          <p className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-xs text-danger sm:col-span-2">
                            {kind === 'any_resource'
                              ? 'anyResource не поддерживается managed templates. Выберите допустимый resource.'
                              : 'Cross-database и cluster resource разрешены только custom role в базе admin.'}
                          </p>
                        )}

                        <div className="flex items-end justify-end sm:col-span-2">
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            disabled={disabled}
                            className="text-danger"
                            aria-label={`Удалить privilege ${privilegeIndex + 1} из ${templateLabel}`}
                            onClick={() => replaceTemplate(templateIndex, (current) => ({
                              ...current,
                              privileges: current.privileges
                                .filter((_, currentIndex) => currentIndex !== privilegeIndex),
                            }))}
                          >
                            <Trash2 className="size-3.5" aria-hidden="true" />
                            Удалить privilege
                          </Button>
                        </div>
                            </fieldset>
                          )
                        }}
                      />
                    )
                  })}
                </div>
              )}
            </section>

            {dangerPreview.length > 0 && (
              <div className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-warn">
                <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                <div className="min-w-0 text-xs leading-relaxed">
                  <p className="font-medium">Предварительный dangerous preview</p>
                  <ul className="mt-1 list-disc space-y-1 ps-4">
                    {dangerPreview.map((reason) => <li key={reason}>{reason}</li>)}
                  </ul>
                  <p className="mt-1.5 text-faint">
                    Это подсказка формы. Итоговый dangerous вычисляет adapter по фактическим
                    actions, resource и наследованию после discovery.
                  </p>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-line/70 pt-3">
              <p className="max-w-2xl text-xs text-faint">
                Удаление template, который уже managed или назначен аккаунтам, будет отклонено.
              </p>
              <Button
                type="button"
                variant="danger"
                size="sm"
                disabled={disabled}
                aria-label={`Удалить policy: ${templateLabel}`}
                onClick={() => onChange(
                  templates
                    .filter((_, current) => current !== templateIndex),
                )}
              >
                <Trash2 className="size-3.5" aria-hidden="true" />
                Удалить policy
              </Button>
            </div>
              </fieldset>
              )
            }}
          />
      ))}
    </section>
  )
}
