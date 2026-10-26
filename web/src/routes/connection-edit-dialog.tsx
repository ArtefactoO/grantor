import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { qk } from '../lib/queryKeys'
import type {
  Connection,
  PatchConnectionRequest,
  PatchConnectionResponse,
} from '../lib/types'
import { Button } from '@project/ui'
import { Dialog } from '@project/ui'
import { ErrorBanner } from '@project/ui'
import { Field, Input, Textarea } from '@project/ui'
import { Combobox } from '@project/ui'
import { Spinner } from '@project/ui'
import { connectionStatusLabel } from '../lib/ui-copy'
import { buildDiscoveryConfig, engineFormSpec } from '../lib/engine-form'
import type { DiscoveryFieldKey } from '../lib/engine-form'
import {
  canManageAdminCredential,
  shouldPollAdminCredentialChange,
} from './connection-admin-credential'

interface TLSConfigForm {
  mode: string
  caCertPEM: string
  clientCertPEM: string
  insecureSkipVerify: boolean
}

/** Значения discovery-полей; видимый набор определяет движок подключения. */
type DiscoveryConfigForm = Partial<Record<DiscoveryFieldKey, string>>

interface ConnectionEditForm {
  displayName: string
  tags: string
  environment: string
  endpoints: string
  tls: TLSConfigForm
  discovery: DiscoveryConfigForm
  discoveryConfig: Record<string, unknown>
}

type EditableField =
  | 'displayName'
  | 'tags'
  | 'environment'
  | 'endpoints'
  | 'tls'
  | 'discovery'

type FieldErrors = Partial<Record<EditableField, string>>

interface TLSConfigDTO {
  mode?: unknown
  ca_cert_pem?: unknown
  client_cert_pem?: unknown
  insecure_skip_verify?: unknown
}


const MAX_CERTIFICATE_FILE_BYTES = 1024 * 1024

export async function readPublicCertificateFile(file: File): Promise<string> {
  if (!/\.(?:pem|crt|cer)$/i.test(file.name)) {
    throw new Error('Выберите файл сертификата с расширением .pem, .crt или .cer.')
  }
  if (file.size > MAX_CERTIFICATE_FILE_BYTES) {
    throw new Error('Файл сертификата не должен превышать 1 МБ.')
  }
  const value = await file.text()
  if (/-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/.test(value)) {
    throw new Error('Private key загружать нельзя. Выберите только публичный сертификат.')
  }
  if (!value.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('Файл не содержит PEM-сертификат.')
  }
  return value
}

export interface EditConnectionDialogProps {
  connection: Connection
  open: boolean
  isAdmin?: boolean
  adminCredentialOpen?: boolean
  onManageAdminCredential?: () => void
  onClose: () => void
  onSaved?: (connection: PatchConnectionResponse) => void
}

function objectValue(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function stringValue(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function initialForm(connection: Connection): ConnectionEditForm {
  const tls = objectValue(connection.tls_config) as TLSConfigDTO
  const stored = objectValue(connection.discovery_config)
  const discovery: DiscoveryConfigForm = {}
  for (const field of engineFormSpec(connection.engine).discoveryFields) {
    discovery[field.key] = stringValue(stored[field.key])
  }
  return {
    displayName: connection.display_name,
    tags: connection.tags.join('\n'),
    environment: connection.environment,
    endpoints: connection.endpoints.join('\n'),
    tls: {
      mode: stringValue(tls.mode),
      caCertPEM: stringValue(tls.ca_cert_pem),
      clientCertPEM: stringValue(tls.client_cert_pem),
      insecureSkipVerify:
        typeof tls.insecure_skip_verify === 'boolean'
          ? tls.insecure_skip_verify
          : false,
    },
    discovery,
    discoveryConfig: { ...stored },
  }
}

function lines(value: string): string[] {
  return value
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '')
}

function normalized(engine: string, form: ConnectionEditForm) {
  // Catalogs now live in Roles. Editing discovery must preserve their exact
  // stored values and any other fields this form does not own.
  const discovery: Record<string, unknown> = { ...form.discoveryConfig }
  for (const field of engineFormSpec(engine).discoveryFields) delete discovery[field.key]
  Object.assign(discovery, buildDiscoveryConfig(engine, form.discovery) ?? {})
  return {
    displayName: form.displayName.trim(),
    tags: lines(form.tags),
    environment: form.environment.trim(),
    endpoints: lines(form.endpoints),
    tls: {
      mode: form.tls.mode,
      // PEM сохраняется байт-в-байт: изменение соседнего TLS-поля не должно
      // попутно нормализовать выданный сервером сертификатный документ.
      ca_cert_pem: form.tls.caCertPEM,
      client_cert_pem: form.tls.clientCertPEM,
      insecure_skip_verify: form.tls.insecureSkipVerify,
    },
    // Только поля движка: фиксированный набор ключей молча стирал бы
    // сохранённые чужие свойства (auth_source у mongodb и т.п.).
    discovery,
  }
}

function same(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right)
}

function buildConnectionPatch(
  connection: Connection,
  form: ConnectionEditForm,
  normalizedBefore?: ReturnType<typeof normalized>,
): PatchConnectionRequest | null {
  const before = normalizedBefore ?? normalized(connection.engine, initialForm(connection))
  const after = normalized(connection.engine, form)
  const payload: PatchConnectionRequest = { updated_at: connection.updated_at }

  if (after.displayName !== before.displayName) {
    payload.display_name = after.displayName
  }
  if (!same(after.tags, before.tags)) {
    payload.tags = after.tags
  }
  if (after.environment !== before.environment) {
    payload.environment = after.environment
  }
  if (!same(after.endpoints, before.endpoints)) {
    payload.endpoints = after.endpoints
  }
  if (!same(after.tls, before.tls)) {
    payload.tls_config = after.tls
  }
  if (!same(after.discovery, before.discovery)) {
    payload.discovery_config = after.discovery
  }

  return Object.keys(payload).length > 1 ? payload : null
}

function fieldForServerError(message: string): EditableField | null {
  if (message.includes('display_name')) return 'displayName'
  if (message.includes('environment')) return 'environment'
  if (message.includes('endpoint')) return 'endpoints'
  if (message.includes('tls_config')) return 'tls'
  if (message.includes('discovery_config')) return 'discovery'
  if (message.includes('tags')) return 'tags'
  return null
}

function fieldErrorId(field: EditableField): string {
  return `connection-edit-${field}-error`
}

function FieldError({ field, errors }: { field: EditableField; errors: FieldErrors }) {
  const message = errors[field]
  if (message === undefined) return null
  return (
    <p id={fieldErrorId(field)} className="mt-1 text-xs text-danger">
      {message}
    </p>
  )
}

export function EditConnectionDialog({
  connection,
  open,
  isAdmin = false,
  adminCredentialOpen = false,
  onManageAdminCredential,
  onClose,
  onSaved,
}: EditConnectionDialogProps) {
  const queryClient = useQueryClient()
  const firstFieldRef = useRef<HTMLInputElement>(null)
  const wasOpenRef = useRef(false)
  const credentialActionRef = useRef<HTMLButtonElement>(null)
  const credentialHeadingRef = useRef<HTMLHeadingElement>(null)
  const wasCredentialOpenRef = useRef(false)
  const [baseline, setBaseline] = useState(connection)
  const [form, setForm] = useState<ConnectionEditForm>(() => initialForm(connection))
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({})
  const [formError, setFormError] = useState<string | null>(null)
  const [discardPrompt, setDiscardPrompt] = useState(false)

  useEffect(() => {
    if (open && !wasOpenRef.current) {
      setBaseline(connection)
      setForm(initialForm(connection))
      setFieldErrors({})
      setFormError(null)
      setDiscardPrompt(false)
    }
    wasOpenRef.current = open
  }, [connection, open])

  useEffect(() => {
    const restore = wasCredentialOpenRef.current && !adminCredentialOpen && open
    wasCredentialOpenRef.current = adminCredentialOpen
    if (!restore) return
    const frame = requestAnimationFrame(() => {
      const action = credentialActionRef.current
      if (action !== null && !action.disabled) action.focus()
      else credentialHeadingRef.current?.focus()
    })
    return () => cancelAnimationFrame(frame)
  }, [adminCredentialOpen, open])

  const normalizedBaseline = useMemo(
    () => normalized(baseline.engine, initialForm(baseline)),
    [baseline],
  )
  const payload = useMemo(
    () => buildConnectionPatch(baseline, form, normalizedBaseline),
    [baseline, form, normalizedBaseline],
  )
  const dirty = payload !== null
  const credentialBusy = shouldPollAdminCredentialChange(connection)
  const locked = connection.status === 'validating' || connection.status === 'discovering' ||
    connection.status === 'deleted' || credentialBusy
  const operationalLocked = locked || connection.status === 'disabled'

  const clearFieldError = (field: EditableField) => {
    setFieldErrors((current) => {
      if (current[field] === undefined) return current
      const next = { ...current }
      delete next[field]
      return next
    })
    setFormError(null)
    setDiscardPrompt(false)
  }

  const discoveryFields = engineFormSpec(connection.engine).discoveryFields
  const setDiscoveryField = (key: DiscoveryFieldKey, value: string) => {
    setForm((current) => ({
      ...current,
      discovery: { ...current.discovery, [key]: value },
    }))
  }

  const loadCertificate = async (
    event: ChangeEvent<HTMLInputElement>,
    field: 'caCertPEM' | 'clientCertPEM',
  ) => {
    const file = event.target.files?.[0]
    event.target.value = ''
    if (file === undefined) return
    clearFieldError('tls')
    try {
      const value = await readPublicCertificateFile(file)
      setForm((current) => ({
        ...current,
        tls: { ...current.tls, [field]: value },
      }))
    } catch (error) {
      setFieldErrors({ tls: errorMessage(error) })
    }
  }

  const mutation = useMutation({
    mutationFn: (body: PatchConnectionRequest) =>
      api<PatchConnectionResponse>(`/api/v1/connections/${connection.id}`, {
        method: 'PATCH',
        body,
      }),
    onSuccess: async (updated) => {
      setFieldErrors({})
      setFormError(null)
      await Promise.all([
        // qk.connections() — общий prefix списка и detail; одной инвалидации
        // достаточно, чтобы не запускать detail refetch дважды.
        queryClient.invalidateQueries({ queryKey: qk.connections() }),
        updated.operation_id !== undefined
          ? queryClient.invalidateQueries({ queryKey: qk.operations() })
          : Promise.resolve(),
      ])
      onSaved?.(updated)
      onClose()
    },
    onError: (error: unknown) => {
      const message = errorMessage(error)
      const field = fieldForServerError(message)
      if (field !== null) {
        setFieldErrors({ [field]: message })
        setFormError(null)
        return
      }
      if (error instanceof ApiError && error.status === 409) {
        setFormError(`${message}. Перезагрузите данные подключения и повторите изменение.`)
        return
      }
      setFormError(message)
    },
  })

  const requestClose = () => {
    if (mutation.isPending || adminCredentialOpen) return
    if (dirty) {
      setDiscardPrompt(true)
      return
    }
    onClose()
  }

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (locked || adminCredentialOpen || mutation.isPending) return
    setFieldErrors({})
    setFormError(null)

    if (form.displayName.trim() === '') {
      setFieldErrors({ displayName: 'Укажите отображаемое имя.' })
      return
    }
    if (form.environment.trim() === '') {
      setFieldErrors({ environment: 'Укажите окружение.' })
      return
    }
    if (!operationalLocked && lines(form.endpoints).length === 0) {
      setFieldErrors({ endpoints: 'Добавьте хотя бы один endpoint.' })
      return
    }
    if (payload !== null) mutation.mutate(payload)
  }

  return (
    <Dialog
      open={open}
      onClose={requestClose}
      title="Редактировать подключение"
      description="Изменение метаданных и параметров подключения"
      initialFocusRef={firstFieldRef}
      closeOnOverlayClick={false}
      footer={
        <div className="space-y-3">
          {discardPrompt && (
            <div className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">
              <p>Есть несохранённые изменения.</p>
              <div className="mt-2 flex flex-wrap gap-2">
                <Button variant="outline" size="sm" onClick={() => setDiscardPrompt(false)}>
                  Продолжить редактирование
                </Button>
                <Button size="sm" variant="danger" onClick={onClose}>
                  Отменить изменения
                </Button>
              </div>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={requestClose} disabled={mutation.isPending}>
              Отмена
            </Button>
            <Button
              type="submit"
              form="connection-edit-form"
              disabled={!dirty || mutation.isPending || locked || adminCredentialOpen}
            >
              {mutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
              Сохранить
            </Button>
          </div>
        </div>
      }
    >
      {canManageAdminCredential(isAdmin, connection) && onManageAdminCredential !== undefined && (
        <section
          className="mb-5 space-y-2 border-b border-line pb-4"
          aria-labelledby="connection-edit-admin-credential"
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <h2
                id="connection-edit-admin-credential"
                ref={credentialHeadingRef}
                tabIndex={-1}
                className="text-sm font-semibold text-text"
              >
                Админская учётка подключения
              </h2>
              <p className="mt-1 text-xs leading-relaxed text-muted">
                Смена учётки и ротация пароля выполняются отдельно от сохранения настроек.
              </p>
            </div>
            <Button
              ref={credentialActionRef}
              type="button"
              variant="outline"
              size="sm"
              disabled={dirty || mutation.isPending || credentialBusy}
              onClick={onManageAdminCredential}
            >
              Изменить учётку или пароль
            </Button>
          </div>
          {dirty && (
            <p className="text-xs text-muted">
              Сначала сохраните или отмените изменения подключения.
            </p>
          )}
          {credentialBusy && (
            <p className="text-xs text-warn" role="status">
              Учётка обновляется. Прогресс и разрешённые действия доступны на странице подключения.
            </p>
          )}
        </section>
      )}
      <form
        id="connection-edit-form"
        onSubmit={submit}
        className="space-y-5"
        autoComplete="off"
      >
        <section className="space-y-3" aria-labelledby="connection-edit-metadata">
          <div>
            <h2 id="connection-edit-metadata" className="text-xs font-semibold uppercase tracking-wide text-muted">
              Метаданные
            </h2>
            <p className="mt-1 text-xs text-faint">
              Имя и теги не запускают discovery и не меняют снимок кластера.
            </p>
          </div>
          <Field label="Отображаемое имя">
            <Input
              ref={firstFieldRef}
              value={form.displayName}
              disabled={locked}
              aria-invalid={fieldErrors.displayName !== undefined}
              aria-describedby={fieldErrors.displayName !== undefined ? fieldErrorId('displayName') : undefined}
              onChange={(event) => {
                clearFieldError('displayName')
                setForm((current) => ({ ...current, displayName: event.target.value }))
              }}
              required
            />
            <FieldError field="displayName" errors={fieldErrors} />
          </Field>
          <Field label="Теги" hint="по одному тегу на строку">
            <Textarea
              value={form.tags}
              disabled={locked}
              aria-invalid={fieldErrors.tags !== undefined}
              aria-describedby={fieldErrors.tags !== undefined ? fieldErrorId('tags') : undefined}
              onChange={(event) => {
                clearFieldError('tags')
                setForm((current) => ({ ...current, tags: event.target.value }))
              }}
              className="min-h-16 font-mono text-[13px]"
            />
            <FieldError field="tags" errors={fieldErrors} />
          </Field>
        </section>

        <section className="space-y-3 border-t border-line pt-4" aria-labelledby="connection-edit-operational">
          <div>
            <h2 id="connection-edit-operational" className="text-xs font-semibold uppercase tracking-wide text-muted">
              Параметры подключения
            </h2>
            <p className="mt-1 text-xs text-faint">
              Любое изменение сбросит старый снимок и запустит новый discovery.
            </p>
          </div>

          {operationalLocked && (
            <div className="rounded-md border border-line bg-panel2 px-3 py-2 text-xs text-muted">
              {connection.status === 'disabled'
                ? 'Отключённое подключение можно переименовать, но его параметры нельзя менять. Сначала включите подключение.'
                : `Редактирование временно недоступно: подключение находится в статусе ${connectionStatusLabel(connection.status)}.`}
            </div>
          )}

          <Field label="Окружение">
            <Input
              value={form.environment}
              disabled={operationalLocked}
              aria-invalid={fieldErrors.environment !== undefined}
              aria-describedby={fieldErrors.environment !== undefined ? fieldErrorId('environment') : undefined}
              onChange={(event) => {
                clearFieldError('environment')
                setForm((current) => ({ ...current, environment: event.target.value }))
              }}
              required
            />
            <FieldError field="environment" errors={fieldErrors} />
          </Field>

          <Field label="Endpoints" hint="по одному host:port на строку">
            <Textarea
              value={form.endpoints}
              disabled={operationalLocked}
              aria-invalid={fieldErrors.endpoints !== undefined}
              aria-describedby={fieldErrors.endpoints !== undefined ? fieldErrorId('endpoints') : undefined}
              onChange={(event) => {
                clearFieldError('endpoints')
                setForm((current) => ({ ...current, endpoints: event.target.value }))
              }}
              className="font-mono text-[13px]"
              required
            />
            <FieldError field="endpoints" errors={fieldErrors} />
          </Field>

          <details className="group rounded-md border border-line bg-panel2/30">
            <summary className="cursor-pointer select-none px-3 py-2.5 text-sm font-medium text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
              TLS
              <span className="ml-2 text-xs font-normal text-faint">
                режим и публичные сертификаты
              </span>
            </summary>
            <div className="space-y-3 border-t border-line p-3">
              <Field label="TLS режим">
                <Combobox
                  value={form.tls.mode}
                  label="TLS режим"
                  disabled={operationalLocked}
                  options={[
                    { value: '', label: 'По умолчанию (без TLS)' },
                    { value: 'disabled', label: 'Отключён явно' },
                    { value: 'require', label: 'TLS без обязательной проверки CA' },
                    { value: 'verify-ca', label: 'TLS с проверкой CA' },
                    { value: 'verify-full', label: 'TLS с проверкой CA и hostname' },
                  ]}
                  onValueChange={(value) => {
                    clearFieldError('tls')
                    setForm((current) => ({
                      ...current,
                      tls: { ...current.tls, mode: value },
                    }))
                  }}
                />
              </Field>

              <label className="flex items-start gap-2 rounded-md border border-line bg-panel2/50 p-3 text-sm text-muted">
                <input
                  type="checkbox"
                  checked={form.tls.insecureSkipVerify}
                  disabled={operationalLocked}
                  onChange={(event) => {
                    clearFieldError('tls')
                    setForm((current) => ({
                      ...current,
                      tls: { ...current.tls, insecureSkipVerify: event.target.checked },
                    }))
                  }}
                  className="mt-0.5 size-4 accent-[var(--accent)]"
                />
                <span>
                  Не проверять сертификат
                  <span className="mt-0.5 block text-xs text-danger">
                    Небезопасно: используйте только как временную меру.
                  </span>
                </span>
              </label>

              <Field label="CA certificate (PEM)" hint="Публичный CA-сертификат; private key здесь не хранится">
                <Input
                  type="file"
                  accept=".pem,.crt,.cer,application/x-pem-file,application/pkix-cert,text/plain"
                  disabled={operationalLocked}
                  aria-label="Загрузить CA-сертификат из файла"
                  onChange={(event) => void loadCertificate(event, 'caCertPEM')}
                />
                <Textarea
                  value={form.tls.caCertPEM}
                  aria-label="CA certificate PEM"
                  disabled={operationalLocked}
                  aria-invalid={fieldErrors.tls !== undefined}
                  aria-describedby={fieldErrors.tls !== undefined ? fieldErrorId('tls') : undefined}
                  onChange={(event) => {
                    clearFieldError('tls')
                    setForm((current) => ({
                      ...current,
                      tls: { ...current.tls, caCertPEM: event.target.value },
                    }))
                  }}
                  className="mt-2 font-mono text-[12px]"
                />
              </Field>

              <Field label="Client certificate (PEM)" hint="Только публичный сертификат; private key не загружается">
                <Input
                  type="file"
                  accept=".pem,.crt,.cer,application/x-pem-file,application/pkix-cert,text/plain"
                  disabled={operationalLocked}
                  aria-label="Загрузить клиентский сертификат из файла"
                  onChange={(event) => void loadCertificate(event, 'clientCertPEM')}
                />
                <Textarea
                  value={form.tls.clientCertPEM}
                  aria-label="Client certificate PEM"
                  disabled={operationalLocked}
                  aria-invalid={fieldErrors.tls !== undefined}
                  aria-describedby={fieldErrors.tls !== undefined ? fieldErrorId('tls') : undefined}
                  onChange={(event) => {
                    clearFieldError('tls')
                    setForm((current) => ({
                      ...current,
                      tls: { ...current.tls, clientCertPEM: event.target.value },
                    }))
                  }}
                  className="mt-2 font-mono text-[12px]"
                />
                <FieldError field="tls" errors={fieldErrors} />
              </Field>
            </div>
          </details>

          <details className="group rounded-md border border-line bg-panel2/30">
            <summary className="cursor-pointer select-none px-3 py-2.5 text-sm font-medium text-text focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent">
              Discovery
              <span className="ml-2 text-xs font-normal text-faint">
                параметры обнаружения ресурсов
              </span>
            </summary>
            <div className="space-y-3 border-t border-line p-3">
              {discoveryFields.length === 0 && (
                <p className="text-xs text-muted">
                  У движка {connection.engine} нет настраиваемых параметров discovery.
                </p>
              )}
              {discoveryFields.map((field) =>
                field.options !== undefined ? (
                  <Field key={field.key} label={field.label} hint={field.hint}>
                    <Combobox
                      value={form.discovery[field.key] ?? ''}
                      label={field.label}
                      disabled={operationalLocked}
                      options={[...field.options]}
                      onValueChange={(value) => {
                        clearFieldError('discovery')
                        setDiscoveryField(field.key, value)
                      }}
                    />
                  </Field>
                ) : (
                  <Field key={field.key} label={field.label} hint={field.hint}>
                    <Input
                      value={form.discovery[field.key] ?? ''}
                      disabled={operationalLocked}
                      aria-invalid={fieldErrors.discovery !== undefined}
                      aria-describedby={
                        fieldErrors.discovery !== undefined ? fieldErrorId('discovery') : undefined
                      }
                      onChange={(event) => {
                        clearFieldError('discovery')
                        setDiscoveryField(field.key, event.target.value)
                      }}
                      placeholder={field.placeholder}
                      className="font-mono text-[13px]"
                    />
                  </Field>
                ),
              )}
              <FieldError field="discovery" errors={fieldErrors} />
            </div>
          </details>
        </section>

        <section className="rounded-md border border-line bg-panel2/50 p-3" aria-label="Неизменяемые параметры">
          <div className="text-xs font-medium text-muted">Изменяются отдельными операциями</div>
          <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-faint">Движок</dt>
            <dd className="font-mono text-text">{connection.engine}</dd>
            <dt className="text-faint">Режим выполнения</dt>
            <dd className="font-mono text-text">{connection.execution_mode}</dd>
            {connection.engine === 'redis' && <>
              <dt className="text-faint">Авторизация</dt>
              <dd className="text-text">{connection.auth_mode === 'none' ? 'Без пароля · default' : 'Пароль'}</dd>
            </>}
            <dt className="text-faint">Admin credential</dt>
            <dd className="text-text">ротация не входит в эту форму</dd>
          </dl>
        </section>

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}
      </form>
    </Dialog>
  )
}
