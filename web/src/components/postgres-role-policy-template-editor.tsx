import { useId, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { ChevronRight, Plus, Trash2 } from '@project/ui/icons'
import type { PostgresRolePolicyTemplate } from '../lib/types'
import {
  addPostgresPolicyRole,
  createPostgresPolicySuggestionResolver,
} from '../lib/postgres-role-policy-suggestions'
import type { PostgresPolicySuggestionSnapshot, PostgresPolicySuggestions } from '../lib/postgres-role-policy-suggestions'
import { formatDateTime } from '../lib/time'
import {
  clonePostgresRolePolicyTemplate as cloneTemplate,
  EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE,
  pairedPostgresRolePolicyDrafts,
  postgresRolePolicyLines,
} from '../lib/postgres-role-policy-templates'
import { Button, Combobox, Field, Input, Textarea } from '@project/ui'

export interface PostgresRolePolicyTemplateEditorProps {
  templates: readonly PostgresRolePolicyTemplate[]
  databaseHint?: string
  /** Only an explicitly created draft pair shares scope; existing policies stay independent. */
  initialPair?: boolean
  disabled?: boolean
  connectionId?: string
  suggestionSnapshot?: PostgresPolicySuggestionSnapshot
  suggestionsPending?: boolean
  suggestionsError?: string | null
  onLoadSuggestions?: () => void
  onChange: (templates: PostgresRolePolicyTemplate[]) => void
}

type ScopeField = 'database' | 'schemas' | 'owner_roles' | 'creator_roles'
type DraftPair = readonly [number, number]

function sameScope(first: PostgresRolePolicyTemplate, second: PostgresRolePolicyTemplate): boolean {
  return first.database === second.database &&
    (['schemas', 'owner_roles', 'creator_roles'] as const).every((field) =>
      first[field].length === second[field].length &&
      first[field].every((value, index) => value === second[field][index]),
    )
}

function validPair(templates: readonly PostgresRolePolicyTemplate[], pair: DraftPair | null): pair is DraftPair {
  if (pair === null) return false
  const [read, write] = pair.map((index) => templates[index])
  return read !== undefined && write !== undefined && read.profile === 'read' &&
    write.profile === 'read_write' && sameScope(read, write)
}

function templateLabel(template: PostgresRolePolicyTemplate, index: number): string {
  return template.name.trim() || template.key.trim() || `Шаблон ${index + 1}`
}

function MetadataDisclosure({ label, initialOpen, children }: {
  label: string
  initialOpen: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(initialOpen)
  return (
    <details open={open} onToggle={(event) => setOpen(event.currentTarget.open)} className="border-t border-line pt-2">
      <summary className="grantor-touch-target flex cursor-pointer list-none items-center gap-1.5 text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
        <ChevronRight className={`size-3.5 ${open ? 'rotate-90' : ''}`} aria-hidden="true" />
        {label}
      </summary>
      <div className="mt-3 space-y-3">{children}</div>
    </details>
  )
}

export function PostgresRolePolicyTemplateEditor({
  templates,
  databaseHint = '',
  initialPair = false,
  disabled = false,
  connectionId,
  suggestionSnapshot,
  suggestionsPending = false,
  suggestionsError = null,
  onLoadSuggestions,
  onChange,
}: PostgresRolePolicyTemplateEditorProps) {
  const editorId = useId()
  const [pair, setPair] = useState<DraftPair | null>(() =>
    initialPair && validPair(templates, [0, 1]) ? [0, 1] : null,
  )
  const [selection, setSelection] = useState<number | 'pair'>(() =>
    initialPair && validPair(templates, [0, 1]) ? 'pair' : 0,
  )
  const activePair = validPair(templates, pair) ? pair : null
  const hasSelectionList = templates.length - (activePair === null ? 0 : 1) > 1
  const paired = selection === 'pair' && activePair !== null
  const selectedIndex = paired ? activePair[0] : Math.min(
    typeof selection === 'number' ? selection : pair?.[0] ?? 0,
    Math.max(templates.length - 1, 0),
  )
  const selected = templates[selectedIndex]
  const scopeIndices = paired ? activePair : [selectedIndex]
  const excludedRoleNames = scopeIndices.map((index) => templates[index]?.role_name.trim() ?? '')
  const resolveSuggestions = useMemo(() => suggestionSnapshot === undefined
    ? undefined : createPostgresPolicySuggestionResolver(suggestionSnapshot), [suggestionSnapshot])

  const update = <K extends keyof PostgresRolePolicyTemplate>(
    index: number, key: K, value: PostgresRolePolicyTemplate[K],
  ) => {
    if (disabled) return
    onChange(templates.map((template, current) => current === index ? { ...template, [key]: value } : template))
  }
  const updateScope = <K extends ScopeField>(key: K, value: PostgresRolePolicyTemplate[K]) => {
    if (disabled) return
    onChange(templates.map((template, index) => scopeIndices.includes(index) ? { ...template, [key]: value } : template))
  }
  const remove = (indices: readonly number[]) => {
    if (disabled) return
    // Keep the surviving templates and their scope arrays stable for cached evidence.
    onChange(templates.filter((_, index) => !indices.includes(index)))
    setPair(null)
    setSelection(Math.max(0, indices[0] - 1))
  }
  const addPair = () => {
    if (disabled || templates.length > 62) return
    setPair([templates.length, templates.length + 1])
    setSelection('pair')
    onChange([...templates, ...pairedPostgresRolePolicyDrafts(databaseHint)])
  }
  const addOne = () => {
    if (disabled || templates.length >= 64) return
    setSelection(templates.length)
    onChange([...templates, cloneTemplate(EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE)])
  }

  return (
    <section className="space-y-4" aria-labelledby={`${editorId}-title`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id={`${editorId}-title`} className="text-sm font-medium text-text">Шаблоны PostgreSQL</h3>
        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
            disabled={disabled || templates.length > 62} onClick={addPair}>
            <Plus className="size-3.5" aria-hidden="true" />Черновик пары READ/RW
          </Button>
          <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
            disabled={disabled || templates.length >= 64} onClick={addOne}>
            <Plus className="size-3.5" aria-hidden="true" />Добавить одну
          </Button>
        </div>
      </div>

      {templates.length === 0 ? (
        <p className="py-4 text-center text-xs text-faint">
          Шаблонов пока нет. Добавьте пару READ/RW или один шаблон со своими параметрами.
        </p>
      ) : (
        <div className={hasSelectionList ? 'grid items-start gap-4 lg:grid-cols-[12rem_minmax(0,1fr)]' : ''}>
          {hasSelectionList && (
            <div className="max-h-44 space-y-1 overflow-y-auto lg:max-h-96" aria-label="Выбор шаблона">
              {activePair !== null && (
                <button type="button" aria-pressed={paired} aria-controls={editorId}
                  className={`w-full rounded-md px-3 py-2 text-left text-xs transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${paired ? 'bg-accent-soft text-text' : 'text-muted hover:bg-hover'}`}
                  onClick={() => setSelection('pair')}>
                  <span className="block font-medium">Пара READ/RW</span>
                  <span className="mt-1 block break-all font-mono text-faint">
                    {activePair.map((index) => templates[index].role_name || 'Без имени').join(' · ')}
                  </span>
                </button>
              )}
              {templates.map((template, index) => activePair?.includes(index) ? null : (
                <button key={index} type="button" aria-pressed={!paired && selectedIndex === index} aria-controls={editorId}
                  aria-label={`Редактировать шаблон: ${templateLabel(template, index)}`}
                  className={`w-full rounded-md px-3 py-2 text-left text-xs transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${!paired && selectedIndex === index ? 'bg-accent-soft text-text' : 'text-muted hover:bg-hover'}`}
                  onClick={() => setSelection(index)}>
                  <span className="block break-words font-medium">{templateLabel(template, index)}</span>
                  <span className="mt-1 block break-all font-mono text-faint">
                    {template.role_name || 'Без имени'} · {template.profile === 'read' ? 'READ' : 'RW'}
                  </span>
                  <span className="mt-1 block break-words text-faint">
                    {template.database || 'Без базы'} · {template.schemas.join(', ') || 'Без схем'}
                  </span>
                </button>
              ))}
            </div>
          )}

          {selected !== undefined && (
            <fieldset id={editorId} disabled={disabled} className="min-w-0 space-y-3">
              <legend className="sr-only">{paired ? 'Общие параметры пары READ/RW' : templateLabel(selected, selectedIndex)}</legend>
              {paired ? (
                <>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-medium text-text">Пара READ/RW</p>
                    <Button type="button" variant="ghost" size="sm" className="grantor-touch-target"
                      disabled={disabled} onClick={() => { setSelection(activePair[0]); setPair(null) }}>
                      Редактировать отдельно
                    </Button>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    {activePair.map((index) => (
                      <div key={index} className="min-w-0 space-y-1">
                        <Field label={templates[index].profile === 'read' ? 'READ · NOLOGIN-роль' : 'RW · NOLOGIN-роль'}>
                          <Input value={templates[index].role_name} required maxLength={63}
                            pattern="[A-Za-z_][A-Za-z0-9_]{0,62}" className="font-mono text-[13px]"
                            onChange={(event) => update(index, 'role_name', event.target.value)} />
                        </Field>
                        <p className="text-xs text-faint">
                          {templates[index].profile === 'read' ? 'CONNECT, USAGE, SELECT' : 'READ + INSERT, UPDATE, DELETE'}
                        </p>
                      </div>
                    ))}
                  </div>
                  <p className="text-xs text-muted">База, схемы и роли ниже общие для обоих шаблонов. DDL и TRUNCATE не выдаются.</p>
                </>
              ) : (
                <>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <Field label="Ключ" tooltip="Стабильный идентификатор; не меняйте после применения">
                      <Input value={selected.key} required pattern="[a-z0-9][a-z0-9_-]{0,63}" maxLength={64}
                        className="font-mono text-[13px]" placeholder="appdb-read"
                        onChange={(event) => update(selectedIndex, 'key', event.target.value)} />
                    </Field>
                    <Field label="Название">
                      <Input value={selected.name} required maxLength={128} placeholder="App DB: чтение"
                        onChange={(event) => update(selectedIndex, 'name', event.target.value)} />
                    </Field>
                    <Field label="NOLOGIN-роль">
                      <Input value={selected.role_name} required maxLength={63} pattern="[A-Za-z_][A-Za-z0-9_]{0,62}"
                        className="font-mono text-[13px]" placeholder="r_appdb"
                        onChange={(event) => update(selectedIndex, 'role_name', event.target.value)} />
                    </Field>
                    <Field label="Профиль" tooltip="DDL, CREATE, TRUNCATE и ownership не выдаются">
                      <Combobox value={selected.profile} label={`Профиль policy ${selectedIndex + 1}`} disabled={disabled}
                        options={[
                          { value: 'read', label: 'Read', description: 'CONNECT, USAGE, SELECT' },
                          { value: 'read_write', label: 'Read + write', description: 'DML без DDL и TRUNCATE' },
                        ]}
                        onValueChange={(value) => update(selectedIndex, 'profile', value === 'read_write' ? 'read_write' : 'read')} />
                    </Field>
                  </div>
                  {initialPair && activePair === null && templates.length > 1 && (
                    <p className="text-xs text-muted">Шаблоны редактируются отдельно. Их различия сохраняются.</p>
                  )}
                </>
              )}

              <div className="grid gap-3 sm:grid-cols-2">
                <Field label="База данных">
                  <Input value={selected.database} required maxLength={63} pattern="[A-Za-z_][A-Za-z0-9_]{0,62}"
                    className="font-mono text-[13px]" placeholder="appdb"
                    onChange={(event) => updateScope('database', event.target.value)} />
                </Field>
                <Field label="Схемы" tooltip="По одной схеме на строку">
                  <Textarea value={selected.schemas.join('\n')} required rows={2}
                    className="min-h-16 font-mono text-[13px]" placeholder="public"
                    onChange={(event) => updateScope('schemas', postgresRolePolicyLines(event.target.value))} />
                </Field>
                <Field label="Owner-роли" tooltip="Владельцы существующих объектов; по одной роли на строку">
                  <Textarea value={selected.owner_roles.join('\n')} required rows={2}
                    className="min-h-16 font-mono text-[13px]" placeholder="app_owner"
                    onChange={(event) => updateScope('owner_roles', postgresRolePolicyLines(event.target.value))} />
                </Field>
                <Field label="Creator-роли" tooltip="Роли миграций для прав на будущие объекты; по одной роли на строку">
                  <Textarea value={selected.creator_roles.join('\n')} required rows={2}
                    className="min-h-16 font-mono text-[13px]" placeholder="app_migrations"
                    onChange={(event) => updateScope('creator_roles', postgresRolePolicyLines(event.target.value))} />
                </Field>
              </div>
              <p className="text-xs text-muted">Owner: владельцы текущих объектов. Creator: роли, от которых создаются будущие объекты.</p>

              <div className="space-y-2 text-xs text-muted" aria-live="polite">
                {onLoadSuggestions !== undefined ? (
                  <div className="flex flex-wrap items-center gap-2">
                    <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
                      disabled={disabled || suggestionsPending} onClick={onLoadSuggestions}>
                      {suggestionsPending ? 'Загрузка подсказок…' : suggestionSnapshot === undefined
                        ? 'Загрузить подсказки Owner/Creator' : 'Обновить подсказки Owner/Creator'}
                    </Button>
                    {suggestionSnapshot !== undefined && (
                      <span>Синхронизация: {formatDateTime(suggestionSnapshot.connection.last_discovery_at)}</span>
                    )}
                  </div>
                ) : suggestionSnapshot === undefined && (
                  <p>Подсказки доступны после успешной синхронизации подключения.</p>
                )}
                {suggestionsError !== null && (
                  <p role="alert" className="text-danger">Не удалось загрузить подсказки. {suggestionsError} Повторите загрузку.</p>
                )}
              </div>
              {resolveSuggestions !== undefined && connectionId !== undefined && !suggestionsPending && suggestionsError === null && (
                <PostgresPolicyOwnerSuggestions template={selected} excludedRoleNames={excludedRoleNames}
                  suggestions={resolveSuggestions(connectionId, selected.database, selected.schemas)} disabled={disabled}
                  onAccept={(field, role) => updateScope(field, addPostgresPolicyRole(selected[field], role))}
                  onAcceptOwners={(roles) => updateScope('owner_roles', roles.reduce(
                    (current, role) => addPostgresPolicyRole(current, role), selected.owner_roles,
                  ))} />
              )}

              <MetadataDisclosure key={paired ? 'pair-metadata' : `metadata-${selectedIndex}`}
                label={paired ? 'Названия, ключи и описания' : 'Описание шаблона'}
                initialOpen={scopeIndices.some((index) => templates[index].description.trim() === '' ||
                  templates[index].name.trim() === '' || templates[index].key.trim() === '')}>
                  {scopeIndices.map((index) => (
                    <div key={index} className="space-y-3">
                      {paired && (
                        <>
                          <h4 className="text-xs font-medium text-text">{templates[index].profile === 'read' ? 'READ' : 'RW'}</h4>
                          <div className="grid gap-3 sm:grid-cols-2">
                            <Field label={templates[index].profile === 'read' ? 'Ключ READ' : 'Ключ RW'}>
                              <Input value={templates[index].key} required pattern="[a-z0-9][a-z0-9_-]{0,63}" maxLength={64}
                                className="font-mono text-[13px]" onChange={(event) => update(index, 'key', event.target.value)} />
                            </Field>
                            <Field label={templates[index].profile === 'read' ? 'Название READ' : 'Название RW'}>
                              <Input value={templates[index].name} required maxLength={128}
                                onChange={(event) => update(index, 'name', event.target.value)} />
                            </Field>
                          </div>
                        </>
                      )}
                      <Field label={paired ? `Описание ${templates[index].profile === 'read' ? 'READ' : 'RW'}` : 'Описание'}>
                        <Textarea value={templates[index].description} required maxLength={512} rows={2}
                          placeholder="Для каких сервисов и данных предназначен шаблон"
                          onChange={(event) => update(index, 'description', event.target.value)} />
                      </Field>
                    </div>
                  ))}
              </MetadataDisclosure>
              <div className="flex justify-end border-t border-line pt-3">
                <Button type="button" variant="danger" size="sm" className="grantor-touch-target" disabled={disabled}
                  aria-label={paired ? 'Удалить пару READ/RW' : `Удалить policy: ${selected.name.trim() || selected.key || selectedIndex + 1}`}
                  onClick={() => remove(scopeIndices)}>
                  <Trash2 className="size-3.5" aria-hidden="true" />{paired ? 'Удалить пару' : 'Удалить'}
                </Button>
              </div>
            </fieldset>
          )}
        </div>
      )}
    </section>
  )
}

function PostgresPolicyOwnerSuggestions({
  template, excludedRoleNames, suggestions, disabled, onAccept, onAcceptOwners,
}: {
  template: PostgresRolePolicyTemplate
  excludedRoleNames: readonly string[]
  suggestions: PostgresPolicySuggestions
  disabled: boolean
  onAccept: (field: 'owner_roles' | 'creator_roles', role: string) => void
  onAcceptOwners: (roles: string[]) => void
}) {
  const hasRole = (field: 'owner_roles' | 'creator_roles', role: string) => template[field].some((value) => value.trim() === role)
  const remainingOwners = suggestions.candidates.filter((candidate) =>
    !hasRole('owner_roles', candidate.role) && !excludedRoleNames.includes(candidate.role),
  ).map((candidate) => candidate.role)
  return (
    <div className="space-y-2 border-t border-line pt-3 text-xs" aria-live="polite">
      <h4 className="font-medium text-text">Подсказки для выбранных схем</h4>
      {suggestions.blockers.length > 0 ? (
        <ul className="space-y-1 text-warn">
          {suggestions.blockers.map((message) => <li key={message}>{message}</li>)}
        </ul>
      ) : (
        <>
          <p className="max-w-prose leading-relaxed text-muted">
            Подсказки дополняют ручные значения. Владельцы текущих объектов могут быть кандидатами для Creator;
            роль будущих миграций подтвердите отдельно.
          </p>
          {suggestions.emptySchemas.length > 0 && (
            <p className="text-muted">
              В схемах нет обнаруженных объектов: {suggestions.emptySchemas.join(', ')}.
              Владельца схемы можно добавить, роль будущих миграций укажите отдельно.
            </p>
          )}
          {suggestions.missingObjectCount > 0 && (
            <p className="text-muted">Ранее обнаруженные, теперь отсутствующие объекты исключены: {suggestions.missingObjectCount}.</p>
          )}
          {suggestions.candidates.length > 1 && (
            <div className="flex flex-wrap items-center gap-2">
              <p className="text-muted">У выбранных схем и объектов несколько владельцев.</p>
              <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
                disabled={disabled || remainingOwners.length === 0 || template.owner_roles.length + remainingOwners.length > 64}
                onClick={() => onAcceptOwners(remainingOwners)}>
                {remainingOwners.length === 0 ? 'Все владельцы добавлены' : 'Добавить всех владельцев'}
              </Button>
            </div>
          )}
          <ul className="divide-y divide-line">
            {suggestions.candidates.map((candidate) => (
              <li key={candidate.role} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <div className="min-w-0 flex-1 basis-48">
                  <p className="break-all font-mono text-text">{candidate.role}</p>
                  <p className="mt-1 break-words leading-relaxed text-muted">
                    {candidate.schemaNames.length > 0 && `Владелец схем: ${candidate.schemaNames.join(', ')}. `}
                    {candidate.objectsBySchema.length > 0 && `Владелец объектов: ${candidate.objectsBySchema.map(({ schema, count }) => `${schema} (${count})`).join(', ')}.`}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
                    aria-label={`Добавить ${candidate.role} в Owner-роли`}
                    disabled={disabled || hasRole('owner_roles', candidate.role) || excludedRoleNames.includes(candidate.role) || template.owner_roles.length >= 64}
                    onClick={() => onAccept('owner_roles', candidate.role)}>
                    {hasRole('owner_roles', candidate.role) ? 'Добавлен в Owner' : 'Добавить в Owner'}
                  </Button>
                  <Button type="button" variant="outline" size="sm" className="grantor-touch-target"
                    aria-label={`Добавить ${candidate.role} в Creator-роли`}
                    disabled={disabled || hasRole('creator_roles', candidate.role) || excludedRoleNames.includes(candidate.role) || template.creator_roles.length >= 64}
                    onClick={() => onAccept('creator_roles', candidate.role)}>
                    {hasRole('creator_roles', candidate.role) ? 'Добавлен в Creator' : 'Добавить в Creator'}
                  </Button>
                </div>
              </li>
            ))}
          </ul>
          <p className="max-w-prose leading-relaxed text-muted">
            Синхронизация показывает текущих владельцев. Она не определяет будущего создателя,
            его право создавать объекты и уже настроенные права на новые объекты.
          </p>
        </>
      )}
    </div>
  )
}
