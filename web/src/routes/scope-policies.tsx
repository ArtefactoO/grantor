import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Check,
  Info,
  Plus,
  Shield,
  ShieldCheck,
  ShieldMinus,
  ShieldPlus,
  Users,
} from '@project/ui/icons'
import { api, apiDelete, apiList, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  Connection,
  CreateScopePolicyRequest,
  EnvironmentEntry,
  Principal,
  RuntimeConfig,
  ScopePolicy,
} from '../lib/types'
import { shortId } from '../lib/status'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { Button, Drawer, Spinner, EmptyState, ErrorState, ErrorBanner, cn } from '@project/ui'
import { PrincipalTypeIcon, StatusChip } from '../components/ui/badge'
import { UI_COPY } from '../lib/ui-copy'
import { EnvironmentCreateDialog } from './environment-create-dialog'
import {
  ENVIRONMENT_ALL,
  OPERATOR_ROLE,
  exactPolicyFor,
  scopeCellState,
  scopePolicyImpact,
} from './scope-policy-matrix'
import type { ScopeMatrixSubject } from './scope-policy-matrix'

export type ScopeEnforcementState =
  | { kind: 'loading' }
  | { kind: 'ready'; mode: 'enforce' | 'disabled' }
  | { kind: 'error'; message: string }
  | { kind: 'unavailable' }

export interface ScopeEnforcementStatusProps {
  state: ScopeEnforcementState
}

/** Фактическое состояние ограничений. Наличие правил не доказывает, что они применяются. */
export function ScopeEnforcementStatus({ state }: ScopeEnforcementStatusProps) {
  let value: string = UI_COPY.unavailable
  let tone: 'ok' | 'warn' | 'unmg' = 'unmg'
  let title = 'Режим ограничения доступа недоступен'
  let description =
    'Сервис не сообщил, включены ли ограничения. Сохранённые правила могут не применяться.'

  if (state.kind === 'loading') {
    value = UI_COPY.loading
    title = 'Проверяем ограничение доступа'
    description = 'Проверяем, применяются ли правила.'
  } else if (state.kind === 'ready') {
    value = state.mode === 'enforce' ? UI_COPY.enabled : UI_COPY.disabled
    if (state.mode === 'enforce') {
      tone = 'ok'
      title = 'Ограничение включено'
      description =
        'Пользователи и сервисы видят только разрешённые окружения. Без разрешения доступ закрыт.'
    } else {
      tone = 'warn'
      title = 'Ограничение выключено'
      description =
        'Сохранённые правила сейчас не ограничивают доступ к подключениям.'
    }
  } else if (state.kind === 'error') {
    value = UI_COPY.failed
    tone = 'warn'
    title = 'Не удалось проверить ограничение'
    description = `Не удалось проверить состояние: ${state.message}`
  }

  return (
    <section
      aria-labelledby="scope-enforcement-title"
      className="border-l-[3px] border-accent bg-accent-soft px-4 py-3"
    >
      <div className="flex flex-wrap items-center gap-2">
        <Shield className="size-4 text-accent" aria-hidden="true" />
        <h2 id="scope-enforcement-title" className="text-sm font-medium text-text">
          {title}
        </h2>
        <StatusChip tone={tone}>{value}</StatusChip>
        {state.kind === 'loading' && <Spinner className="size-3.5" />}
      </div>
      <p className="mt-1 text-sm text-muted">{description}</p>
      <span className="sr-only">Режим ограничения доступа</span>
    </section>
  )
}

interface PendingChange {
  subject: ScopeMatrixSubject
  environment: string
}

export interface ScopePoliciesPageProps {
  embedded?: boolean
}

export function ScopePoliciesPage({ embedded = false }: ScopePoliciesPageProps = {}) {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const queryClient = useQueryClient()
  const [pendingChange, setPendingChange] = useState<PendingChange | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [createEnvironmentOpen, setCreateEnvironmentOpen] = useState(false)

  const policiesQuery = useQuery({
    queryKey: qk.scopePolicies(),
    queryFn: ({ signal }) =>
      apiList<ScopePolicy>('/api/v1/scope-policies', 'policies', signal),
    enabled: isAdmin,
  })
  const runtimeConfigQuery = useQuery({
    queryKey: qk.runtimeConfig(),
    queryFn: ({ signal }) => api<RuntimeConfig>('/api/v1/runtime-config', { signal }),
    enabled: isAdmin,
  })
  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
    enabled: isAdmin,
  })
  const connectionsQuery = useQuery({
    queryKey: qk.connections(),
    queryFn: ({ signal }) =>
      apiList<Connection>('/api/v1/connections', 'connections', signal),
    enabled: isAdmin,
  })

  const registryQuery = useQuery({
    queryKey: qk.environments(),
    queryFn: ({ signal }) =>
      apiList<EnvironmentEntry>('/api/v1/environments', 'environments', signal),
    enabled: isAdmin,
  })

  const policies = policiesQuery.data ?? []
  const connections = connectionsQuery.data ?? []
  const principals = principalsQuery.data ?? []

  // Реестр + окружения подключений: колонка реестрового окружения видна и
  // до первого подключения в нём.
  const environments = useMemo(
    () =>
      [
        ...new Set([
          ...(registryQuery.data ?? []).map((entry) => entry.name),
          ...connections.map((connection) => connection.environment).filter(Boolean),
        ]),
      ].sort((left, right) => left.localeCompare(right)),
    [connections, registryQuery.data],
  )

  const subjects = useMemo<ScopeMatrixSubject[]>(() => {
    const services = principals
      .filter((principal) => principal.type === 'service')
      .map((principal) => ({
        kind: 'principal' as const,
        id: principal.id,
        name: principal.display_name,
        description: 'Сервис',
      }))

    // Сохраняем управляемость правил, субъект которых уже отсутствует в
    // текущем списке принципалов: молча скрывать такие allow-правила опасно.
    const known = new Set(services.map((subject) => subject.id))
    for (const policy of policies) {
      if (policy.subject_kind === 'principal' && !known.has(policy.subject)) {
        known.add(policy.subject)
        services.push({
          kind: 'principal',
          id: policy.subject,
          name: shortId(policy.subject),
          description: 'Удалённый сервис',
        })
      }
    }
    services.sort((left, right) => left.name.localeCompare(right.name))
    return [
      {
        kind: 'role',
        id: OPERATOR_ROLE,
        name: 'Все операторы',
        description: 'Операторы',
      },
      ...services,
    ]
  }, [policies, principals])

  const impact = useMemo(() => {
    if (pendingChange === null) return null
    return scopePolicyImpact(
      policies,
      pendingChange.subject,
      pendingChange.environment,
      connections,
    )
  }, [connections, pendingChange, policies])

  const changeMutation = useMutation({
    mutationFn: async (change: PendingChange) => {
      const policy = exactPolicyFor(policies, change.subject, change.environment)
      if (policy !== undefined) {
        return apiDelete<{ deleted: string }>(`/api/v1/scope-policies/${policy.id}`)
      }
      const payload: CreateScopePolicyRequest = {
        subject_kind: change.subject.kind,
        subject: change.subject.id,
        environment: change.environment,
      }
      return apiPost<ScopePolicy>('/api/v1/scope-policies', payload)
    },
    onSuccess: () => {
      setActionError(null)
      setPendingChange(null)
      void queryClient.invalidateQueries({ queryKey: qk.scopePolicies() })
    },
    onError: (err: unknown) => setActionError(errorMessage(err)),
  })

  if (!isAdmin) {
    return (
      <div className="mx-auto max-w-6xl space-y-4">
        <h1 className="text-lg font-semibold">Доступ к окружениям</h1>
        <EmptyState
          icon={ShieldCheck}
          title="Недостаточно прав"
          description="Управление доступом пользователей и сервисов к окружениям требует роли администратора."
        />
      </div>
    )
  }

  const matrixPending =
    policiesQuery.isPending || principalsQuery.isPending || connectionsQuery.isPending
  const matrixError =
    policiesQuery.isError || principalsQuery.isError || connectionsQuery.isError

  return (
    <div className={cn(!embedded && 'mx-auto max-w-6xl', 'space-y-4')}>
      {!embedded && <header className="flex flex-wrap items-start gap-3 border-b border-line pb-4">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-accent text-accent-ink">
          <ShieldCheck className="size-4" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <h1 className="text-lg font-semibold">Доступ к окружениям</h1>
          <p className="max-w-3xl text-sm text-muted">
            Определяет, какие подключения видят и используют операторы и сервисы.
            Роли внутри подключённых систем здесь не выдаются.
          </p>
        </div>
      </header>}

      {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}

      <ScopeEnforcementStatus
        state={
          runtimeConfigQuery.isPending
            ? { kind: 'loading' }
            : runtimeConfigQuery.isError
              ? { kind: 'error', message: errorMessage(runtimeConfigQuery.error) }
              : runtimeConfigQuery.data === undefined
                ? { kind: 'unavailable' }
                : { kind: 'ready', mode: runtimeConfigQuery.data.scope_enforcement }
        }
      />

      <section aria-labelledby="scope-matrix-title" className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 id="scope-matrix-title" className="text-sm font-semibold text-text">
              Матрица доступа
            </h2>
            <p className="mt-1 text-sm text-muted">
              Нажмите ячейку, чтобы сначала увидеть последствия изменения.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => setCreateEnvironmentOpen(true)}>
            <Plus className="size-3.5" />
            Добавить окружение
          </Button>
        </div>

        {matrixError ? (
          <ErrorState
            message="Не удалось загрузить правила, субъектов или подключения."
            onRetry={() => {
              void policiesQuery.refetch()
              void principalsQuery.refetch()
              void connectionsQuery.refetch()
            }}
          />
        ) : matrixPending ? (
          <div className="flex items-center justify-center gap-2 py-16 text-sm text-muted">
            <Spinner className="size-5" />
            Загрузка матрицы…
          </div>
        ) : (
          <>
            <div className="overflow-x-auto rounded-lg border border-line bg-panel">
              <div
                role="grid"
                aria-label="Доступ субъектов к окружениям"
                className="grid min-w-[650px]"
                style={{
                  gridTemplateColumns: `minmax(190px, 1.35fr) repeat(${environments.length + 1}, minmax(104px, .65fr))`,
                }}
              >
                <div role="columnheader" className="bg-panel2 px-3 py-2.5 text-xs text-muted">
                  Пользователь или сервис
                </div>
                {[...environments, ENVIRONMENT_ALL].map((environment) => (
                  <div
                    key={environment}
                    role="columnheader"
                    className="bg-panel2 px-3 py-2.5 text-center text-xs text-muted"
                  >
                    {environment === ENVIRONMENT_ALL ? 'Все окружения' : environment}
                  </div>
                ))}

                {subjects.map((subject) => {
                  return (
                    <div key={`${subject.kind}:${subject.id}`} role="row" className="contents">
                      <div role="rowheader" className="flex min-w-0 items-center gap-2.5 border-t border-line px-3 py-2.5">
                        <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-panel2 text-muted">
                          {subject.kind === 'role' ? (
                            <Users className="size-3.5" aria-hidden="true" />
                          ) : (
                            <PrincipalTypeIcon type="service" />
                          )}
                        </span>
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-medium text-text">
                            {subject.name}
                          </span>
                          <span className="mt-0.5 block truncate text-xs text-muted">
                            {subject.description}
                          </span>
                        </span>
                      </div>
                      {[...environments, ENVIRONMENT_ALL].map((environment) => {
                        const state = scopeCellState(policies, subject, environment)
                        const inherited = state === 'inherited'
                        const label =
                          environment === ENVIRONMENT_ALL ? 'все окружения' : environment
                        return (
                          <div
                            key={environment}
                            role="gridcell"
                            className="grid place-items-center border-t border-line px-3 py-2.5"
                          >
                            <button
                              type="button"
                              aria-label={`${subject.name}: ${label}, ${
                                state === 'explicit'
                                  ? 'разрешено явно'
                                  : inherited
                                    ? 'разрешено через все окружения'
                                    : 'запрещено'
                              }`}
                              aria-pressed={state !== 'denied'}
                              disabled={inherited}
                              title={
                                inherited
                                  ? 'Доступ наследуется через «Все окружения». Измените общую ячейку.'
                                  : 'Показать последствия изменения'
                              }
                              onClick={() => {
                                setActionError(null)
                                setPendingChange({ subject, environment })
                              }}
                              className={cn(
                                'grantor-touch-target ui-control-feedback inline-grid h-7 w-9 place-items-center rounded-full border text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent',
                                state === 'explicit' &&
                                  'border-accent bg-accent text-accent-ink',
                                state === 'denied' &&
                                  'border-line bg-transparent hover:bg-panel2 hover:text-text',
                                inherited &&
                                  'cursor-not-allowed border-dashed border-line bg-panel2 text-faint',
                              )}
                            >
                              {state !== 'denied' && <Check className="size-3.5" aria-hidden="true" />}
                            </button>
                          </div>
                        )
                      })}
                    </div>
                  )
                })}
              </div>
            </div>

            <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-muted" aria-label="Легенда">
              <LegendMark kind="explicit" label="разрешено явно" />
              <LegendMark kind="inherited" label="разрешено через «Все окружения»" />
              <LegendMark kind="denied" label="запрещено" />
            </div>
          </>
        )}
      </section>

      <EnvironmentCreateDialog
        open={createEnvironmentOpen}
        onClose={() => setCreateEnvironmentOpen(false)}
      />

      <Drawer
        open={pendingChange !== null}
        onClose={() => {
          if (!changeMutation.isPending) setPendingChange(null)
        }}
        closeOnOverlayClick={!changeMutation.isPending}
        title={impact?.operation === 'delete' ? 'Убрать доступ' : 'Разрешить доступ'}
        description="Последствия изменения доступа к окружению"
      >
        {pendingChange !== null && impact !== null && (
          <div className="space-y-4">
            <div className="flex items-center gap-3 border-b border-line pb-4">
              {impact.operation === 'delete' ? (
                <ShieldMinus className="size-5 text-danger" aria-hidden="true" />
              ) : (
                <ShieldPlus className="size-5 text-accent" aria-hidden="true" />
              )}
              <div className="min-w-0">
                <div className="truncate text-sm font-medium text-text">
                  {pendingChange.subject.name}
                </div>
                <div className="mt-0.5 text-xs text-muted">
                  Окружение:{' '}
                  {pendingChange.environment === ENVIRONMENT_ALL
                    ? 'все окружения'
                    : pendingChange.environment}
                </div>
              </div>
            </div>

            <div>
              <h3 className="text-sm font-semibold text-text">Что изменится</h3>
              <div className="mt-2 divide-y divide-line border-y border-line">
                <ImpactRow label="Подключения" value={String(impact.affectedConnections.length)} />
                <ImpactRow
                  label="Действия в Grantor"
                  value={
                    impact.affectedConnections.length === 0
                      ? 'не изменятся'
                      : impact.operation === 'delete'
                        ? 'будут запрещены'
                        : 'будут разрешены'
                  }
                />
              </div>
              {impact.affectedConnections.length > 0 && (
                <ul className="mt-2 space-y-1 text-xs text-muted">
                  {impact.affectedConnections.slice(0, 6).map((connection) => (
                    <li key={connection.id} className="flex justify-between gap-3">
                      <span className="truncate">{connection.display_name}</span>
                      <span className="shrink-0">{connection.environment || 'без окружения'}</span>
                    </li>
                  ))}
                  {impact.affectedConnections.length > 6 && (
                    <li>Ещё {impact.affectedConnections.length - 6}</li>
                  )}
                </ul>
              )}
            </div>

            {actionError !== null && <ErrorBanner>{actionError}</ErrorBanner>}

            <ImpactNotice change={pendingChange} impact={impact} />

            <div className="flex justify-end gap-2 pt-1">
              <Button
                variant="outline"
                onClick={() => setPendingChange(null)}
                disabled={changeMutation.isPending}
              >
                Отмена
              </Button>
              <Button
                variant={impact.operation === 'delete' ? 'danger' : 'primary'}
                onClick={() => changeMutation.mutate(pendingChange)}
                disabled={changeMutation.isPending}
              >
                {changeMutation.isPending && <Spinner className="size-3.5" />}
                {impact.operation === 'delete' ? 'Убрать доступ' : 'Разрешить'}
              </Button>
            </div>
          </div>
        )}
      </Drawer>
    </div>
  )
}

function LegendMark({ kind, label }: { kind: 'explicit' | 'inherited' | 'denied'; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        className={cn(
          'size-3 rounded-full border',
          kind === 'explicit' && 'border-accent bg-accent',
          kind === 'inherited' && 'border-dashed border-line bg-panel2',
          kind === 'denied' && 'border-line',
        )}
        aria-hidden="true"
      />
      {label}
    </span>
  )
}

function ImpactRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-2.5 text-sm">
      <span className="text-muted">{label}</span>
      <strong className="font-medium text-text">{value}</strong>
    </div>
  )
}

function ImpactNotice({
  change,
  impact,
}: {
  change: PendingChange
  impact: ReturnType<typeof scopePolicyImpact>
}) {
  let message =
    impact.operation === 'delete'
      ? 'Права внутри целевых систем не изменятся. Ограничивается только работа через Grantor.'
      : 'Разрешение открывает просмотр и допустимые действия Grantor, но не выдаёт роли в целевой системе.'

  if (change.environment === ENVIRONMENT_ALL && impact.operation === 'create') {
    message =
      impact.redundantConcretePolicies.length > 0
        ? `Существующие конкретные правила (${impact.redundantConcretePolicies.length}) останутся сохранены. Grantor не удаляет их автоматически.`
        : 'Разрешение будет действовать для текущих и будущих окружений.'
  } else if (change.environment === ENVIRONMENT_ALL && impact.operation === 'delete') {
    message =
      impact.redundantConcretePolicies.length > 0
        ? `Конкретные правила (${impact.redundantConcretePolicies.length}) останутся активны. Доступ исчезнет только там, где отдельного правила нет.`
        : 'Это последнее разрешение субъекта. После удаления он не увидит ни одного подключения.'
  } else if (impact.wildcardPolicy !== undefined) {
    message =
      'Эффективный доступ не изменится: он продолжит наследоваться через «Все окружения».'
  }

  return (
    <div className="flex items-start gap-2.5 rounded-lg bg-panel2 px-3 py-2.5 text-sm text-muted">
      <Info className="mt-0.5 size-4 shrink-0 text-accent" aria-hidden="true" />
      <p>{message}</p>
    </div>
  )
}
