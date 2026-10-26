import { useId, useMemo, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { MongoDBRolePolicyTemplateEditor } from '../components/mongodb-role-policy-template-editor'
import { PostgresRolePolicyTemplateEditor } from '../components/postgres-role-policy-template-editor'
import { RabbitMQPermissionTemplateEditor } from '../components/rabbitmq-permission-template-editor'
import { Button, Dialog, ErrorBanner, CopyButton, Field, Textarea, Spinner } from '@project/ui'
import { SegmentedFilter } from '../components/ui/selection-chips'
import { api, ApiError } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import {
  cloneMongoDBRolePolicyTemplate,
  EMPTY_MONGODB_ROLE_POLICY_TEMPLATE,
  readMongoDBRolePolicyTemplates,
} from '../lib/mongodb-role-policy-templates'
import {
  clonePostgresRolePolicyTemplate,
  EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE,
  pairedPostgresRolePolicyDrafts,
  readPostgresRolePolicyTemplates,
} from '../lib/postgres-role-policy-templates'
import { qk } from '../lib/queryKeys'
import {
  EMPTY_RABBITMQ_PERMISSION_TEMPLATE,
  readRabbitMQPermissionTemplates,
} from '../lib/rabbitmq-permission-templates'
import type {
  Connection,
  MongoDBRolePolicyTemplate,
  PatchConnectionRequest,
  PatchConnectionResponse,
  Resource,
} from '../lib/types'
import type { PostgresPolicySuggestionSnapshot } from '../lib/postgres-role-policy-suggestions'
import { connectionStatusLabel } from '../lib/ui-copy'
import {
  parseRoleTemplatesDocument,
  roleTemplateCatalogIssues,
  serializeRoleTemplatesDocument,
} from '../lib/role-template-document'
import type { RoleTemplateCatalog } from '../lib/role-template-document'
import { shouldPollAdminCredentialChange } from './connection-admin-credential'

export type AccessTemplateEditorIntent = 'catalog' | 'create' | 'pair'

export interface ConnectionAccessTemplatesDialogProps {
  connection: Connection
  open: boolean
  isAdmin: boolean
  intent?: AccessTemplateEditorIntent
  initialTemplates?: RoleTemplateCatalog
  initialMode?: 'form' | 'json'
  onClose: () => void
  onSaved?: (updated: PatchConnectionResponse) => void
}

type Catalog = RoleTemplateCatalog | { engine: 'unsupported'; templates: [] }

const CATALOG_KEYS = {
  postgres: 'postgres_role_policy_templates',
  rabbitmq: 'rabbitmq_permission_templates',
  mongodb: 'mongodb_role_policy_templates',
} as const

// Mirrors connections.CanReconfigure: recovery states remain editable, unknown
// future statuses stay fail-closed until their operational contract is known.
const EDITABLE_CONNECTION_STATUSES = new Set([
  'draft', 'active', 'degraded', 'connection_failed', 'discovery_failed',
])

export function supportsAccessTemplates(engine: string): boolean {
  return engine === 'postgres' || engine === 'rabbitmq' || engine === 'mongodb'
}

export function canEditAccessTemplates(connection: Connection, isAdmin: boolean): boolean {
  return isAdmin && supportsAccessTemplates(connection.engine) &&
    EDITABLE_CONNECTION_STATUSES.has(connection.status) &&
    !shouldPollAdminCredentialChange(connection)
}

function discoveryConfig(connection: Connection): Record<string, unknown> {
  const value = connection.discovery_config
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {}
  // The pinned snapshot must not share nested future config fields with query data.
  return structuredClone(value as Record<string, unknown>)
}

function readCatalog(engine: string, config: Record<string, unknown>): Catalog {
  switch (engine) {
    case 'postgres': return { engine, templates: readPostgresRolePolicyTemplates(config) }
    case 'rabbitmq': return { engine, templates: readRabbitMQPermissionTemplates(config) }
    case 'mongodb': return { engine, templates: readMongoDBRolePolicyTemplates(config) }
    default: return { engine: 'unsupported', templates: [] }
  }
}

function initialCatalog(catalog: Catalog, intent: AccessTemplateEditorIntent, databaseHint: string): Catalog {
  if (intent === 'catalog') return catalog
  if (catalog.engine === 'postgres') {
    return {
      ...catalog,
      templates: [
        ...(intent === 'pair'
          ? pairedPostgresRolePolicyDrafts(databaseHint)
          : [clonePostgresRolePolicyTemplate(EMPTY_POSTGRES_ROLE_POLICY_TEMPLATE)]),
        ...catalog.templates,
      ],
    }
  }
  // A READ/RW pair has no defined contract on other engines.
  if (intent === 'pair') return catalog
  if (catalog.engine === 'rabbitmq') {
    return { ...catalog, templates: [{ ...EMPTY_RABBITMQ_PERMISSION_TEMPLATE }, ...catalog.templates] }
  }
  if (catalog.engine === 'mongodb' && catalog.templates.length < 64) {
    return {
      ...catalog,
      templates: [cloneMongoDBRolePolicyTemplate(EMPTY_MONGODB_ROLE_POLICY_TEMPLATE), ...catalog.templates],
    }
  }
  return catalog
}

const normalizedMongoTemplateCache = new WeakMap<MongoDBRolePolicyTemplate, MongoDBRolePolicyTemplate>()

function normalizeMongoTemplate(template: MongoDBRolePolicyTemplate): MongoDBRolePolicyTemplate {
  const cached = normalizedMongoTemplateCache.get(template)
  if (cached !== undefined) return cached
  const result = {
    ...cloneMongoDBRolePolicyTemplate(template),
    key: template.key.trim(),
    name: template.name.trim(),
    description: template.description.trim(),
    role_name: template.role_name.trim(),
    role_database: template.role_database.trim(),
    inherited_roles: template.inherited_roles.map((role) => ({ role: role.role.trim(), db: role.db.trim() })),
    privileges: template.privileges.map((privilege) => ({
      resource: 'db' in privilege.resource
        ? { db: (privilege.resource.db ?? '').trim(), collection: (privilege.resource.collection ?? '').trim() }
        : { ...privilege.resource },
      actions: privilege.actions.map((action) => action.trim()).filter(Boolean),
    })),
  }
  normalizedMongoTemplateCache.set(template, result)
  return result
}

function normalizedCatalog(catalog: Catalog): Catalog {
  switch (catalog.engine) {
    case 'postgres':
      return { engine: catalog.engine, templates: catalog.templates.map((template) => ({
        ...template,
        key: template.key.trim(),
        name: template.name.trim(),
        description: template.description.trim(),
        role_name: template.role_name.trim(),
        database: template.database.trim(),
        schemas: template.schemas.map((value) => value.trim()).filter(Boolean),
        owner_roles: template.owner_roles.map((value) => value.trim()).filter(Boolean),
        creator_roles: template.creator_roles.map((value) => value.trim()).filter(Boolean),
      })) }
    case 'rabbitmq':
      return { engine: catalog.engine, templates: catalog.templates.map((template) => ({
        ...template,
        key: template.key.trim(),
        name: template.name.trim(),
        description: template.description.trim(),
        // The vhost and regex strings are exact identities, including spaces.
      })) }
    case 'mongodb': return { engine: catalog.engine, templates: catalog.templates.map(normalizeMongoTemplate) }
    default: return catalog
  }
}

function appendCatalog(saved: Catalog, draft: Catalog): Catalog {
  switch (draft.engine) {
    case 'postgres': return saved.engine === draft.engine
      ? { engine: draft.engine, templates: [...saved.templates, ...draft.templates] } : draft
    case 'rabbitmq': return saved.engine === draft.engine
      ? { engine: draft.engine, templates: [...saved.templates, ...draft.templates] } : draft
    case 'mongodb': return saved.engine === draft.engine
      ? { engine: draft.engine, templates: [...saved.templates, ...draft.templates] } : draft
    default: return draft
  }
}

/** Mounting a new session is the only way to replace the pinned CAS baseline. */
export function ConnectionAccessTemplatesDialog(props: ConnectionAccessTemplatesDialogProps) {
  if (!props.open) return null
  return <AccessTemplatesSession key={props.connection.id} {...props} />
}

function AccessTemplatesSession({
  connection,
  isAdmin,
  intent = 'catalog',
  initialTemplates,
  initialMode = 'form',
  onClose,
  onSaved,
}: ConnectionAccessTemplatesDialogProps) {
  const queryClient = useQueryClient()
  const formId = useId()
  const initialFocusRef = useRef<HTMLElement | null>(null)
  const [baseline] = useState(() => {
    const config = discoveryConfig(connection)
    const catalog = readCatalog(connection.engine, config)
    return {
      id: connection.id,
      engine: connection.engine,
      updatedAt: connection.updated_at,
      config,
      catalog,
      normalized: JSON.stringify(normalizedCatalog(catalog)),
      databaseHint: typeof config.database === 'string' ? config.database : '',
      creating: intent !== 'catalog' && canEditAccessTemplates(connection, isAdmin),
    }
  })
  const [openedDraft] = useState<Catalog>(() => {
    if (baseline.creating && baseline.catalog.templates.length >= 64) {
      return { ...baseline.catalog, templates: [] }
    }
    if (baseline.creating && initialTemplates?.engine === baseline.engine) {
      return structuredClone(initialTemplates)
    }
    return initialCatalog(
      baseline.creating ? { ...baseline.catalog, templates: [] } : baseline.catalog,
      canEditAccessTemplates(connection, isAdmin) ? intent : 'catalog',
      baseline.databaseHint,
    )
  })
  const [catalog, setCatalog] = useState(openedDraft)
  const [initialDocument] = useState(() => {
    if (initialMode !== 'json' || openedDraft.engine === 'unsupported') return { text: '', error: null }
    try {
      return { text: serializeRoleTemplatesDocument(openedDraft), error: null }
    } catch (error) {
      // A malformed legacy catalog must remain repairable in the fields editor.
      return { text: '', error: errorMessage(error) }
    }
  })
  const [mode, setMode] = useState(initialDocument.error === null ? initialMode : 'form')
  const [serialized, setSerialized] = useState(initialDocument.text)
  const [documentText, setDocumentText] = useState(initialDocument.text)
  const [formError, setFormError] = useState<string | null>(initialDocument.error)
  const [importRejected, setImportRejected] = useState(false)
  const [conflicted, setConflicted] = useState(false)
  const [discardPrompt, setDiscardPrompt] = useState(false)
  const [suggestionsRequested, setSuggestionsRequested] = useState(false)
  const suggestionsQuery = useQuery({
    queryKey: [...qk.connectionResources(baseline.id), 'policy-suggestions', connection.last_discovery_at, connection.updated_at],
    // Full resources contain owner metadata; the lightweight tree does not.
    // Observation timestamps below fence racing discovery responses.
    queryFn: async ({ signal }): Promise<PostgresPolicySuggestionSnapshot> => {
      const [source, inventory] = await Promise.all([
        api<Connection>(`/api/v1/connections/${baseline.id}`, { signal }),
        api<{ resources?: Resource[] }>(`/api/v1/connections/${baseline.id}/resources`, { signal }),
      ])
      if (!Array.isArray(inventory.resources)) throw new Error('resource_inventory_unavailable')
      return { connection: source, resources: inventory.resources }
    },
    enabled: suggestionsRequested && isAdmin && baseline.engine === 'postgres' && mode === 'form',
    retry: false,
  })
  const normalized = useMemo(() => JSON.stringify(normalizedCatalog(catalog)), [catalog])
  const openedNormalized = useMemo(() => JSON.stringify(normalizedCatalog(openedDraft)), [openedDraft])
  // Opening Create inserts a draft, but it is not a user edit. Formatting or
  // invalid JSON typed by the user still needs the same discard protection.
  const textDirty = mode === 'json' && documentText !== serialized
  const dirty = normalized !== openedNormalized || textDirty
  const hasChanges = textDirty || (baseline.creating
    ? catalog.templates.length > 0 : normalized !== baseline.normalized)
  const allowed = canEditAccessTemplates(connection, isAdmin) && connection.engine === baseline.engine

  const mutation = useMutation({
    mutationFn: (body: PatchConnectionRequest) => api<PatchConnectionResponse>(
      `/api/v1/connections/${baseline.id}`,
      { method: 'PATCH', body },
    ),
    retry: false,
    onSuccess: async (updated) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connections() }),
        updated.operation_id !== undefined
          ? queryClient.invalidateQueries({ queryKey: qk.operations() })
          : Promise.resolve(),
      ])
      onSaved?.(updated)
      onClose()
    },
    onError: async (error: unknown) => {
      if (error instanceof ApiError && error.status === 409) {
        setConflicted(true)
        setFormError('Подключение изменилось. Закройте редактор и откройте его заново с актуальными данными. Ваши изменения автоматически не применялись.')
        // Refresh the next session's source, never the current session's pinned
        // baseline. The detail query stays mounted behind this dialog.
        await queryClient.invalidateQueries({ queryKey: qk.connection(baseline.id), exact: true })
        return
      }
      setFormError(errorMessage(error))
    },
  })
  const creationLimitReached = baseline.creating && baseline.catalog.templates.length >= 64
  const disabled = !allowed || mutation.isPending || conflicted || creationLimitReached

  const update = (next: Catalog) => {
    if (disabled) return
    setCatalog(next)
    setFormError(null)
    setImportRejected(false)
    setDiscardPrompt(false)
  }
  const requestClose = () => {
    if (mutation.isPending) return
    if (dirty) setDiscardPrompt(true)
    else onClose()
  }
  const changeMode = (next: 'form' | 'json') => {
    if (disabled || catalog.engine === 'unsupported') return
    if (next === 'form') {
      try {
        update(parseRoleTemplatesDocument(documentText, catalog.engine))
      } catch (error) {
        setFormError(errorMessage(error))
        setImportRejected(true)
        return
      }
    } else {
      try {
        // Large Mongo catalogs stay lazy while typing into a field. Serialize
        // only on an explicit mode change, never on every form keystroke.
        const text = serializeRoleTemplatesDocument(catalog)
        setSerialized(text)
        setDocumentText(text)
        setFormError(null)
        setImportRejected(false)
      } catch (error) {
        setFormError(errorMessage(error))
        return
      }
    }
    setMode(next)
  }
  const discardImport = () => {
    if (disabled) return
    // Only the explicitly cancelled text is discarded. The last structured
    // draft, its edits, and its pinned CAS baseline remain unchanged.
    setDocumentText(serialized)
    setFormError(null)
    setImportRejected(false)
    setDiscardPrompt(false)
    setMode('form')
    requestAnimationFrame(() => initialFocusRef.current?.focus())
  }
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (disabled || !hasChanges || catalog.engine === 'unsupported') return
    setFormError(null)
    setImportRejected(false)
    let draft: Catalog = catalog
    if (mode === 'json') {
      try {
        draft = parseRoleTemplatesDocument(documentText, catalog.engine)
      } catch (error) {
        setFormError(errorMessage(error))
        setImportRejected(true)
        return
      }
    }
    const normalizedDraft = normalizedCatalog(draft)
    const next = baseline.creating ? appendCatalog(baseline.catalog, normalizedDraft) : normalizedDraft
    if (next.engine === 'unsupported' || JSON.stringify(next) === baseline.normalized) return
    const issues = roleTemplateCatalogIssues(next)
    if (issues.length > 0) {
      setFormError(issues[0])
      return
    }
    if (!event.currentTarget.reportValidity()) return
    const config = { ...baseline.config }
    const key = CATALOG_KEYS[next.engine]
    if (next.templates.length === 0) delete config[key]
    else config[key] = next.templates
    mutation.mutate({ updated_at: baseline.updatedAt, discovery_config: config })
  }

  let lockedReason: string | null = null
  if (!isAdmin) lockedReason = 'Создавать и изменять шаблоны может только администратор.'
  else if (!supportsAccessTemplates(connection.engine)) lockedReason = 'Для этого движка управляемые шаблоны пока не поддерживаются.'
  else if (shouldPollAdminCredentialChange(connection)) lockedReason = 'Дождитесь завершения изменения учётки подключения, прежде чем редактировать шаблоны.'
  else if (!allowed) lockedReason = `Редактирование недоступно: подключение находится в статусе ${connectionStatusLabel(connection.status)}.`

  return (
    <Dialog
      open
      size="wide"
      onClose={requestClose}
      title="Шаблоны доступа"
      description="Каталог разрешённых шаблонов подключения. Сохранение не меняет права в целевой системе."
      initialFocusRef={initialFocusRef}
      closeOnOverlayClick={false}
      footer={(
        <div className="space-y-3">
          {formError !== null && (
            <div role="alert" className="space-y-2">
              <ErrorBanner>{formError}</ErrorBanner>
              {importRejected && mode === 'json' && (
                <>
                  <p className="text-xs text-muted">Поля не изменены. Возврат отменит вставленный JSON.</p>
                  <Button variant="outline" size="sm" disabled={disabled} onClick={discardImport}>
                    Отменить импорт и вернуться к полям
                  </Button>
                </>
              )}
            </div>
          )}
          {discardPrompt && (
            <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn" role="alert">
              <p>Есть несохранённые изменения.</p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => setDiscardPrompt(false)}>
                  Продолжить редактирование
                </Button>
                <Button variant="danger" size="sm" onClick={onClose}>
                  Отменить изменения
                </Button>
              </div>
            </div>
          )}
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" onClick={requestClose} disabled={mutation.isPending}>Отмена</Button>
            <Button type="submit" form={formId} disabled={disabled || !hasChanges}>
              {mutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
              Сохранить шаблоны
            </Button>
          </div>
        </div>
      )}
    >
      <form
        id={formId}
        ref={(node) => {
          initialFocusRef.current = node?.querySelector<HTMLElement>('input:enabled:not([type="hidden"]), textarea:enabled') ?? null
        }}
        onSubmit={submit}
        className="space-y-4"
        autoComplete="off"
      >
        <p className="text-xs leading-relaxed text-muted">
          Сохранение запустит синхронизацию. Права применяются отдельно, после проверки шаблона.
        </p>
        {lockedReason !== null && <p role="status" className="text-sm text-warn">{lockedReason}</p>}
        {creationLimitReached && (
          <p role="status" className="text-sm text-warn">
            В каталоге уже 64 шаблона. Чтобы добавить новый, сначала удалите неиспользуемый через «Редактировать шаблоны».
          </p>
        )}
        {isAdmin && catalog.engine !== 'unsupported' && (
          <SegmentedFilter
            label="Способ редактирования шаблонов"
            value={mode}
            options={[
              { value: 'form', label: 'Поля', disabled },
              { value: 'json', label: 'JSON', disabled },
            ]}
            onChange={changeMode}
          />
        )}
        {isAdmin && mode === 'json' && catalog.engine !== 'unsupported' && (
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
              <span>Документ шаблонов · JSON v1</span>
              <CopyButton value={documentText} label="Копировать JSON шаблонов" />
            </div>
            <Field label="JSON шаблонов">
              <Textarea
                value={documentText}
                disabled={disabled}
                aria-describedby={`${formId}-json-hint`}
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className="min-h-72 resize-y font-mono text-[12px]"
                onChange={(event) => {
                  setDocumentText(event.target.value)
                  setFormError(null)
                  setImportRejected(false)
                  setDiscardPrompt(false)
                }}
              />
            </Field>
            <p id={`${formId}-json-hint`} className="text-xs leading-relaxed text-faint">
              {baseline.creating
                ? catalog.engine === 'rabbitmq'
                  ? 'Новые шаблоны будут добавлены к каталогу. Измените key и нужные regex; существующие шаблоны не заменяются.'
                  : 'Новые шаблоны будут добавлены к каталогу. Измените key и role_name; существующие шаблоны не заменяются.'
                : 'Это весь каталог подключения. Удаление записи из JSON удаляет шаблон из каталога, если он не используется.'}
            </p>
          </div>
        )}
        {isAdmin && mode === 'form' && catalog.engine === 'postgres' && (
          <PostgresRolePolicyTemplateEditor
            templates={catalog.templates}
            databaseHint={baseline.databaseHint}
            initialPair={baseline.creating && intent === 'pair' && initialTemplates === undefined}
            disabled={disabled}
            connectionId={baseline.id}
            suggestionSnapshot={suggestionsQuery.data}
            suggestionsPending={suggestionsQuery.isFetching}
            suggestionsError={suggestionsQuery.isError
              ? errorMessage(suggestionsQuery.error) === 'resource_inventory_unavailable'
                ? 'Полный список объектов недоступен.' : errorMessage(suggestionsQuery.error)
              : null}
            onLoadSuggestions={() => {
              if (suggestionsRequested) void suggestionsQuery.refetch()
              else setSuggestionsRequested(true)
            }}
            onChange={(templates) => update({ engine: 'postgres', templates })}
          />
        )}
        {isAdmin && mode === 'form' && catalog.engine === 'rabbitmq' && (
          <RabbitMQPermissionTemplateEditor
            templates={catalog.templates}
            disabled={disabled}
            onChange={(templates) => update({ engine: 'rabbitmq', templates })}
          />
        )}
        {isAdmin && mode === 'form' && catalog.engine === 'mongodb' && (
          <MongoDBRolePolicyTemplateEditor
            templates={catalog.templates}
            disabled={disabled}
            onChange={(templates) => update({ engine: 'mongodb', templates })}
          />
        )}
      </form>
    </Dialog>
  )
}
