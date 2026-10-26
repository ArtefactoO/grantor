import { useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus } from '@project/ui/icons'
import { Button, Combobox, Drawer, ErrorBanner, Field, Input, Spinner, Textarea } from '@project/ui'
import { api, apiList, ApiError } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type { Connection, CreateConnectionRequest, EnvironmentEntry } from '../lib/types'
import { connectionEngineLabel } from '../lib/connection-presentation'
import { EnginePicker } from '../components/engine-picker'
import { buildDiscoveryConfig, engineFormSpec } from '../lib/engine-form'
import type { DiscoveryFieldKey } from '../lib/engine-form'
import { ConnectionAuthModeField, RedisNoAuthNotice } from './connection-auth-mode-field'
import type { ConnectionAuthMode } from '../lib/types'

// Фолбэк списка движков, пока GET /api/v1/engines не ответил (или недоступен):
// форма остаётся рабочей и без registry. Источник истины — бэкенд; новый
// движок появляется в форме без правок фронта, имя даёт
// connectionEngineLabel (неизвестный ключ показывается как есть).
export const ENGINE_OPTIONS = [
  { value: 'postgres', label: 'PostgreSQL' },
  { value: 'mongodb', label: 'MongoDB' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'rabbitmq', label: 'RabbitMQ' },
  { value: 'clickhouse', label: 'ClickHouse' },
  { value: 'kafka', label: 'Kafka' },
  { value: 'redis', label: 'Redis' },
]

/** Список движков из registry бэкенда с фолбэком на локальный перечень. */
export function useEngineOptions() {
  const enginesQuery = useQuery({
    queryKey: qk.engines(),
    queryFn: ({ signal }) => api<{ engines: string[] }>('/api/v1/engines', { signal }),
    staleTime: Infinity,
  })
  const engines = enginesQuery.data?.engines
  if (engines === undefined || engines.length === 0) return ENGINE_OPTIONS
  return engines.map((engine) => ({ value: engine, label: connectionEngineLabel(engine) }))
}

export {
  ALL_CONNECTION_FACETS, ConnectionDirectory, ConnectionListControls, ConnectionFacetFilters,
  connectionFacetOptions, useConnectionFacetFilters,
} from './connection-directory'
export type { ConnectionDirectoryProps, ConnectionFacetOption } from './connection-directory'

// Форма добавления подключения (admin): POST /api/v1/connections.
interface AddConnectionDrawerProps {
  open: boolean
  onClose: () => void
  connections: Connection[]
}

interface ConnectionForm {
  displayName: string
  engine: string
  environment: string
  endpoints: string
  executionMode: string
  /** Значения discovery-полей; какие из них видимы, решает движок. */
  discovery: Partial<Record<DiscoveryFieldKey, string>>
  username: string
  password: string
  authMode: ConnectionAuthMode
}

const EMPTY_FORM: ConnectionForm = {
  displayName: '',
  engine: 'postgres',
  environment: '',
  endpoints: '',
  executionMode: 'direct',
  discovery: {},
  username: '',
  password: '',
  authMode: 'password',
}

// Режимы выполнения операций подключения (connections.execution_mode).
const EXECUTION_MODE_OPTIONS = [
  { value: 'direct', label: 'Прямое подключение' },
  { value: 'connector', label: 'Через коннектор (изолированный сегмент)' },
]

const ADD_ENVIRONMENT = '__add_environment__'

export function AddConnectionDrawer({ open, onClose, connections }: AddConnectionDrawerProps) {
  const queryClient = useQueryClient()
  const engineOptions = useEngineOptions()
  const [form, setForm] = useState<ConnectionForm>(EMPTY_FORM)
  const [formError, setFormError] = useState<string | null>(null)
  const [environmentSelection, setEnvironmentSelection] = useState('')
  // Реестр + окружения существующих подключений: реестровое окружение может
  // ещё не иметь ни одного подключения.
  const registryQuery = useQuery({
    queryKey: qk.environments(),
    queryFn: ({ signal }) =>
      apiList<EnvironmentEntry>('/api/v1/environments', 'environments', signal),
    enabled: open,
  })
  const environments = useMemo(() => {
    const byNormalizedName = new Map<string, string>()
    for (const entry of registryQuery.data ?? []) {
      byNormalizedName.set(entry.name.toLocaleLowerCase(), entry.name)
    }
    for (const connection of connections) {
      const environment = connection.environment.trim()
      if (environment !== '') byNormalizedName.set(environment.toLocaleLowerCase(), environment)
    }
    return [...byNormalizedName.values()].sort((left, right) => left.localeCompare(right))
  }, [connections, registryQuery.data])

  const setField = <K extends keyof ConnectionForm>(key: K, value: ConnectionForm[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }
  const setDiscoveryField = (key: DiscoveryFieldKey, value: string) => {
    setForm((prev) => ({ ...prev, discovery: { ...prev.discovery, [key]: value } }))
  }
  const engineForm = engineFormSpec(form.engine)

  const close = () => {
    setFormError(null)
    onClose()
  }

  const createMutation = useMutation({
    mutationFn: (payload: CreateConnectionRequest) =>
      api<Connection>('/api/v1/connections', { method: 'POST', body: payload }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.connections() })
      setForm(EMPTY_FORM)
      setEnvironmentSelection('')
      setFormError(null)
      onClose()
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        setFormError(err.message)
      } else {
        setFormError(errorMessage(err))
      }
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (form.environment.trim() === '') {
      setFormError('Выберите существующее окружение или добавьте новое.')
      return
    }
    const endpoints = form.endpoints
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '')
    const payload: CreateConnectionRequest = {
      display_name: form.displayName.trim(),
      engine: form.engine,
      environment: form.environment.trim(),
      endpoints,
      execution_mode: form.executionMode,
      ...(form.engine === 'redis' ? { auth_mode: form.authMode } : {}),
      ...(form.engine === 'redis' && form.authMode === 'none' ? {} : { admin_credential: {
        username: form.username,
        password: form.password,
      } }),
    }
    const discovery = buildDiscoveryConfig(form.engine, form.discovery)
    if (discovery !== undefined) {
      payload.discovery_config = discovery
    }
    createMutation.mutate(payload)
  }

  return (
    <Drawer open={open} onClose={close} title="Новое подключение">
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        <Field label="Отображаемое имя">
          <Input
            value={form.displayName}
            onChange={(e) => setField('displayName', e.target.value)}
            placeholder="payments (prod)"
            required
          />
        </Field>

        <Field label="Движок">
          <EnginePicker
            value={form.engine}
            options={engineOptions}
            onValueChange={(value) => setForm(current => ({ ...current, engine: value, authMode: 'password', username: '', password: '' }))}
          />
        </Field>

        <Field label="Окружение">
          <Combobox
            value={environmentSelection}
            label="Окружение"
            searchLabel="Поиск окружения"
            placeholder="Выберите окружение…"
            searchPlaceholder="Название окружения…"
            options={[
              ...environments.map((environment) => ({
                value: environment,
                label: environment,
              })),
              {
                value: ADD_ENVIRONMENT,
                label: 'Добавить новое окружение',
                icon: <Plus className="size-3.5" />,
              },
            ]}
            onValueChange={(value) => {
              setEnvironmentSelection(value)
              setField('environment', value === ADD_ENVIRONMENT ? '' : value)
            }}
          />
          {environmentSelection === ADD_ENVIRONMENT && (
            <Input
              value={form.environment}
              onChange={(event) => setField('environment', event.target.value)}
              placeholder="dev / stage / prod"
              className="mt-2"
              aria-label="Новое окружение"
              autoFocus
              required
            />
          )}
        </Field>

        <Field
          label="Режим выполнения"
          hint="коннектор используется для целевых систем в изолированном сегменте"
        >
          <Combobox
            value={form.executionMode}
            label="Режим выполнения"
            options={[...EXECUTION_MODE_OPTIONS]}
            onValueChange={(value) => setField('executionMode', value)}
          />
        </Field>

        <Field
          label="Endpoints"
          tooltip="По одному host:port на строку"
          hint={engineForm.endpointsHint}
        >
          <Textarea
            value={form.endpoints}
            onChange={(e) => setField('endpoints', e.target.value)}
            placeholder={engineForm.endpointsPlaceholder}
            className="font-mono text-[13px]"
            required
          />
        </Field>

        {engineForm.discoveryFields.map((field) =>
          field.options !== undefined ? (
            <Field key={field.key} label={field.label} hint={field.hint}>
              <Combobox
                value={form.discovery[field.key] ?? ''}
                label={field.label}
                options={[...field.options]}
                onValueChange={(value) => setDiscoveryField(field.key, value)}
              />
            </Field>
          ) : (
            <Field key={field.key} label={field.label} hint={field.hint}>
              <Input
                value={form.discovery[field.key] ?? ''}
                onChange={(e) => setDiscoveryField(field.key, e.target.value)}
                placeholder={field.placeholder}
                className="font-mono text-[13px]"
              />
            </Field>
          ),
        )}

        <div className="rounded-md border border-line bg-panel2/50 p-3">
          <div className="mb-3 text-xs font-medium text-muted">
            Admin credential
          </div>
          {form.engine === 'redis' && <div className="mb-3"><ConnectionAuthModeField value={form.authMode} onChange={authMode => setForm(current => ({ ...current, authMode, username: '', password: '' }))} /></div>}
          {form.engine === 'redis' && form.authMode === 'none' ? <RedisNoAuthNotice /> : <div className="space-y-3">
            <Field label="Пользователь">
              <Input
                value={form.username}
                onChange={(e) => setField('username', e.target.value)}
                autoComplete="off"
                className="font-mono text-[13px]"
                required
              />
            </Field>
            <Field label="Пароль">
              <Input
                type="password"
                value={form.password}
                onChange={(e) => setField('password', e.target.value)}
                autoComplete="off"
                required
              />
            </Field>
          </div>}
        </div>

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={close} disabled={createMutation.isPending}>
            Отмена
          </Button>
          <Button type="submit" disabled={createMutation.isPending}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Создать
          </Button>
        </div>
      </form>
    </Drawer>
  )
}
