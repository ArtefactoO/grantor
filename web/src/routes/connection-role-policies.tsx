import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, FileDiff, ShieldCheck } from '@project/ui/icons'
import { api, apiList } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { qk } from '../lib/queryKeys'
import type {
  PostgresRolePolicy,
  PostgresRolePolicyMutationRequest,
  PostgresRolePolicyMutationResponse,
  Connection,
} from '../lib/types'
import { Button, EmptyState, ErrorBanner, InlineNotice } from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { QueryStates } from '../components/ui/query-states'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'

export type PostgresRolePolicyAction = 'create' | 'apply' | 'adopt' | 'repair'

interface PendingRolePolicyAction {
  policy: PostgresRolePolicy
  action: PostgresRolePolicyAction
  targetIdentity: string | null
}

export interface PostgresRolePoliciesSectionProps {
  connectionId: string
  connection?: Connection
  isAdmin: boolean
  templateActions?: ReactNode
  onOpenTemplate?: (key: string) => void
}

const ROLE_POLICY_REFRESH_MS = 1_500

export function postgresRolePolicyRefreshInterval(
  policies: readonly PostgresRolePolicy[] | undefined,
): number | false {
  return policies?.some((policy) => policy.transition_active)
    ? ROLE_POLICY_REFRESH_MS
    : false
}

const ACTION_COPY: Record<PostgresRolePolicyAction, {
  button: string
  title: string
  confirm: string
}> = {
  create: {
    button: 'Создать роль с правами',
    title: 'Создать PostgreSQL-роль с правами?',
    confirm: 'Создать',
  },
  apply: {
    button: 'Применить policy',
    title: 'Применить PostgreSQL policy?',
    confirm: 'Применить',
  },
  adopt: {
    button: 'Принять под управление',
    title: 'Принять PostgreSQL policy под управление?',
    confirm: 'Принять',
  },
  repair: {
    button: 'Исправить drift',
    title: 'Исправить PostgreSQL policy?',
    confirm: 'Исправить',
  },
}

/**
 * The UI mirrors the fail-closed lifecycle; the backend repeats every guard.
 * Existing mismatched unmanaged roles may be converged only through explicit
 * Apply; Adopt remains exact-only.
 */
export function postgresRolePolicyAction(
  policy: PostgresRolePolicy,
): PostgresRolePolicyAction | null {
  if (!policy.apply_supported || policy.transition_active) return null
  if (policy.creatable === true) return 'create'
  if (policy.status === 'missing' || policy.observed_summary.role?.exists === false) return null
  if (policy.managed) {
    return policy.repairable ? 'repair' : null
  }
  if (policy.exact) return 'adopt'
  return 'apply'
}

function policyStatus(policy: PostgresRolePolicy): {
  label: string
  tone: 'ok' | 'warn' | 'danger' | 'unmg'
} {
  if (policy.transition_active && policy.status === 'failed') {
    return { label: 'Ожидает повтора', tone: 'warn' }
  }
  if (policy.transition_active || policy.status === 'pending') {
    return { label: 'Операция выполняется', tone: 'warn' }
  }
  if (policy.status === 'failed') return { label: 'Операция не завершилась', tone: 'danger' }
  if (policy.status === 'blocked') return { label: 'Заблокирована', tone: 'danger' }
  if (policy.observed_summary.role?.exists === false) return { label: 'Роль отсутствует', tone: 'warn' }
  if (!policy.apply_supported) return { label: 'Мутация недоступна', tone: 'warn' }
  if (policy.managed && policy.exact) return { label: 'Синхронизировано', tone: 'ok' }
  if (policy.managed) return { label: 'Расхождение', tone: 'danger' }
  if (policy.exact) return { label: 'Готово к принятию', tone: 'unmg' }
  if (policy.status === 'missing' || policy.observed_fingerprint === '') {
    return { label: 'Не применена', tone: 'unmg' }
  }
  return { label: 'Не совпадает', tone: 'warn' }
}

const BLOCKED_REASON_LABELS: Record<string, string> = {
  database_unavailable: 'База данных недоступна для проверки policy.',
  topology_probe_failed: 'Не удалось проверить writable primary.',
  target_identity_mismatch: 'Не удалось доказать, что endpoint указывает на тот же PostgreSQL cluster.',
  policy_observation_failed: 'Не удалось полностью прочитать состояние роли и ACL.',
  read_only_replica: 'Policy нельзя менять на read-only replica.',
  configured_schema_missing: 'Одна из настроенных схем отсутствует.',
  configured_owner_role_missing: 'Одна из owner-ролей отсутствует.',
  configured_creator_role_missing: 'Одна из creator-ролей отсутствует.',
  role_has_unsafe_attributes: 'Существующая роль имеет небезопасные атрибуты.',
  role_owns_database_objects: 'Policy-роль владеет объектами; ownership нужно убрать вручную.',
  role_inherits_other_roles: 'Policy-роль наследует другую роль.',
  unexpected_role_admin_option: 'У стороннего участника есть ADMIN OPTION на policy-роль.',
  alternate_role_admin_grantor: 'У admin-роли есть membership от постороннего grantor; требуется ручная очистка.',
  role_has_dependent_grants: 'Policy-роль передала свои права другой роли; зависимые grants нужно отозвать вручную.',
  cross_database_check_incomplete: 'Не удалось проверить ownership и ACL роли во всех базах кластера.',
  role_has_cross_database_acl: 'У policy-роли есть ACL в другой базе; удалите их вручную перед управлением.',
  apply_unsupported: 'Текущая конфигурация подключения не поддерживает применение этой policy.',
  template_removed: 'Применённый или используемый шаблон удалён из каталога.',
  template_identity_changed: 'Физическая identity managed policy была изменена.',
  superuser_required: 'Admin credential подключения не является PostgreSQL SUPERUSER.',
  authority_probe_failed: 'Не удалось проверить полномочия admin credential.',
  admin_credential_missing: 'Admin credential подключения не настроен.',
  credential_incarnation_missing: 'Версия admin credential не подтверждена.',
  config_incarnation_missing: 'Версия конфигурации подключения не подтверждена.',
  admin_identity_mismatch: 'PostgreSQL возвращает другую admin identity.',
  read_only_target: 'Подключение ведёт на read-only узел.',
  target_identity_unavailable: 'Не удалось подтвердить PostgreSQL-кластер.',
}

function blockedReasonLabel(reason: string): string {
  if (reason === '') return ''
  return BLOCKED_REASON_LABELS[reason] ?? reason
}

function delta(policy: PostgresRolePolicy, key: 'missing' | 'extra'): string[] {
  const value = policy.observed_summary?.[key]
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item !== '')
    : []
}

function deltaCount(policy: PostgresRolePolicy, key: 'missing' | 'extra'): number {
  const count = policy.observed_summary?.[`${key}_count`]
  return typeof count === 'number' && Number.isFinite(count) ? count : delta(policy, key).length
}

function policyTokenLabel(value: string): string {
  const match = /^acl:(\[.*\]):([^:]+)(:GRANT_OPTION)?$/.exec(value)
  if (match === null) return value.replaceAll(':', ' · ')
  try {
    const scope = JSON.parse(match[1]) as unknown
    if (!Array.isArray(scope) || !scope.every((part) => typeof part === 'string')) return value
    const [kind, ...parts] = scope
    const privilege = `${match[2]}${match[3] === undefined ? '' : ' WITH GRANT OPTION'}`
    if (kind === 'default') {
      const [creator, schema, objectKind] = parts
      return `default · ${creator} · ${schema} · ${objectKind}: ${privilege}`
    }
    return `current · ${kind} · ${parts.join('.')}: ${privilege}`
  } catch {
    return value
  }
}

function Values({ values, empty }: { values: readonly string[]; empty: string }) {
  if (values.length === 0) return <p className="text-xs text-faint">{empty}</p>
  return (
    <ul className="space-y-1">
      {values.map((value, index) => (
        <li
          key={`${value}-${index}`}
          className="break-all rounded bg-panel2 px-2 py-1 font-mono text-[11px] leading-relaxed text-muted"
        >
          <span title={value}>{policyTokenLabel(value)}</span>
        </li>
      ))}
    </ul>
  )
}

function PolicyDelta({ policy }: { policy: PostgresRolePolicy }) {
  const missing = delta(policy, 'missing')
  const extra = delta(policy, 'extra')
  const missingCount = deltaCount(policy, 'missing')
  const extraCount = deltaCount(policy, 'extra')
  if (missing.length === 0 && extra.length === 0) return null

  return (
    <details className="group rounded-md border border-line/70 bg-panel2/20">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <FileDiff className="size-3.5 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1">
          ACL diff: не хватает {missingCount}, лишних {extraCount}
        </span>
        <span className="text-faint group-open:hidden" aria-hidden="true">Показать</span>
        <span className="hidden text-faint group-open:inline" aria-hidden="true">Скрыть</span>
      </summary>
      <div className="grid gap-3 border-t border-line/70 p-3 sm:grid-cols-2">
        <section aria-label="Недостающие права">
          <h4 className="mb-2 text-xs font-medium text-warn">Не хватает</h4>
          <Values values={missing} empty="Недостающих ACL нет." />
        </section>
        <section aria-label="Лишние права">
          <h4 className="mb-2 text-xs font-medium text-danger">Лишнее</h4>
          <Values values={extra} empty="Лишних ACL нет." />
        </section>
      </div>
      {policy.observed_summary.truncated === true && (
        <p className="border-t border-line/70 px-3 py-2 text-xs text-warn">
          Preview ограничен. Подтверждение затронет все {missingCount + extraCount} расхождений.
        </p>
      )}
    </details>
  )
}

function PolicySummary({ policy }: { policy: PostgresRolePolicy }) {
  const spec = policy.desired_spec
  const values = [
    ['Роль', spec.role_name],
    ['База', spec.database],
    ['Профиль', spec.profile === 'read_write' ? 'read + write' : 'read'],
    ['Схемы', spec.schemas.join(', ') || '—'],
    ['Owner-роли', spec.owner_roles.join(', ') || '—'],
    ['Creator-роли', spec.creator_roles.join(', ') || '—'],
  ] as const

  return (
    <dl className="grid min-w-0 gap-x-4 gap-y-1 text-xs sm:grid-cols-[auto_minmax(0,1fr)_auto_minmax(0,1fr)]">
      {values.map(([label, value]) => (
        <div key={label} className="contents">
          <dt className="text-faint">{label}</dt>
          <dd className="min-w-0 break-all font-mono text-muted" title={value}>{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function confirmationDescription({ policy, action }: PendingRolePolicyAction) {
  const missing = delta(policy, 'missing')
  const extra = delta(policy, 'extra')
  const missingCount = deltaCount(policy, 'missing')
  const extraCount = deltaCount(policy, 'extra')
  if (action === 'adopt') {
    return (
      <p>
        Роль <span className="font-mono text-text">{policy.desired_spec.role_name}</span> уже
        точно совпадает с policy. Grantor зафиксирует её как managed, не меняя ACL.
      </p>
    )
  }
  if (action === 'repair' || (action === 'apply' && (missingCount > 0 || extraCount > 0))) {
    return (
      <div className="space-y-3">
        <p>
          Grantor напрямую приведёт текущие ACL и default privileges роли{' '}
          <span className="font-mono text-text">{policy.desired_spec.role_name}</span> к шаблону.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <section aria-label="Недостающие права перед repair">
            <h4 className="mb-1.5 text-xs font-medium text-warn">Добавится ({missingCount})</h4>
            <Values values={missing} empty="Ничего." />
          </section>
          <section aria-label="Лишние права перед repair">
            <h4 className="mb-1.5 text-xs font-medium text-danger">Будет удалено ({extraCount})</h4>
            <Values values={extra} empty="Ничего." />
          </section>
        </div>
        {policy.observed_summary.truncated === true && (
          <p className="text-xs text-warn">
            Список сокращён; Grantor применит весь diff из {missingCount + extraCount} расхождений.
          </p>
        )}
      </div>
    )
  }
  return (
    <p>
      Grantor {action === 'create' ? 'создаст' : 'настроит'} NOLOGIN-роль{' '}
      <span className="font-mono text-text">{policy.desired_spec.role_name}</span> в базе{' '}
      <span className="font-mono text-text">{policy.desired_spec.database}</span>, права на
      текущие объекты и default privileges. Аккаунтам policy автоматически не назначается.
    </p>
  )
}

export function PostgresRolePoliciesSection({
  connectionId,
  connection,
  isAdmin,
  templateActions,
  onOpenTemplate,
}: PostgresRolePoliciesSectionProps) {
  const queryClient = useQueryClient()
  const [pendingAction, setPendingAction] = useState<PendingRolePolicyAction | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [mutationError, setMutationError] = useState<string | null>(null)
  const hadActiveTransition = useRef(false)

  const policiesQuery = useQuery({
    queryKey: qk.connectionRolePolicies(connectionId),
    queryFn: ({ signal }) => apiList<PostgresRolePolicy>(
      `/api/v1/connections/${connectionId}/role-policies`,
      'policies',
      signal,
    ),
    refetchInterval: (query) => postgresRolePolicyRefreshInterval(
      query.state.data as PostgresRolePolicy[] | undefined,
    ),
  })

  useEffect(() => {
    const active = (policiesQuery.data ?? []).some((policy) => policy.transition_active)
    if (hadActiveTransition.current && !active) {
      void Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
      ])
    }
    hadActiveTransition.current = active
  }, [connectionId, policiesQuery.data, queryClient])

  const mutation = useMutation({
    mutationFn: ({ policy, action, targetIdentity }: PendingRolePolicyAction) => {
      const body: PostgresRolePolicyMutationRequest = {
        request_id: globalThis.crypto.randomUUID(),
        version: policy.version,
        observed_fingerprint: policy.observed_fingerprint,
        confirm: true,
      }
      if (action === 'create') {
        if (targetIdentity === null) throw new Error('Не подтверждён PostgreSQL-кластер. Синхронизируйте подключение и откройте подтверждение заново.')
        body.expected_target_identity = targetIdentity
      }
      return api<PostgresRolePolicyMutationResponse>(
        `/api/v1/connections/${connectionId}/role-policies/${encodeURIComponent(policy.template_key)}/${action}`,
        { method: 'POST', body },
      )
    },
    onSuccess: async (response, variables) => {
      setPendingAction(null)
      setMutationError(null)
      setNotice(
        `${ACTION_COPY[variables.action].button}: операция ${response.operation_id} поставлена в очередь.`,
      )
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connectionRolePolicies(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
      ])
    },
    onError: (error: unknown) => {
      setPendingAction(null)
      setMutationError(errorMessage(error))
    },
  })

  return (
    <section className="space-y-3" aria-labelledby="postgres-role-policies-title">
      <div className="flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-start sm:justify-between">
        <div className="min-w-0 sm:flex-1">
          <h2 id="postgres-role-policies-title" className="text-sm font-semibold text-text">
            Роли доступа PostgreSQL
          </h2>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            Создайте роли чтения и записи для базы, затем назначьте их нужным аккаунтам.
          </p>
        </div>
        {templateActions}
      </div>

      {notice !== null && <InlineNotice text={notice} onClose={() => setNotice(null)} />}
      {mutationError !== null && <ErrorBanner>{mutationError}</ErrorBanner>}
      {connection !== undefined && <PostgresProvisioningNotice connection={connection} showReady />}

      <QueryStates
        query={policiesQuery}
        empty={(
          <EmptyState
            icon={ShieldCheck}
            title="Роли доступа ещё не настроены"
            description={isAdmin
              ? 'Нажмите «Создать роли для базы». Владельца и параметры доступа Grantor подставит автоматически.'
              : 'Администратор ещё не опубликовал шаблоны ролей для этого подключения.'}
            className="py-7"
          />
        )}
      >
        {(policies) => (
          <div className="space-y-3">
            <div className="divide-y divide-line overflow-hidden rounded-md border border-line">
              {policies.map((policy) => {
                const state = policyStatus(policy)
                const action = postgresRolePolicyAction(policy)
                return (
                  <article key={policy.id || policy.template_key} className="space-y-3 bg-panel px-3 py-3">
                    <div className="flex flex-wrap items-start justify-between gap-2">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <h3 className="min-w-0 break-words text-sm font-medium text-text">
                            {onOpenTemplate === undefined ? policy.name : (
                              <button
                                type="button"
                                className="grantor-touch-target ui-control-feedback text-left underline decoration-line underline-offset-4 hover:decoration-current focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
                                aria-label={`Открыть шаблон ${policy.name}`}
                                onClick={() => onOpenTemplate(policy.template_key)}
                              >
                                {policy.name}
                              </button>
                            )}
                          </h3>
                          <StatusChip tone={state.tone}>{state.label}</StatusChip>
                        </div>
                        {policy.description !== '' && (
                          <p className="mt-1 max-w-3xl break-words text-xs leading-relaxed text-muted">
                            {policy.description}
                          </p>
                        )}
                      </div>
                      {isAdmin && action !== null && (
                        <Button
                          size="sm"
                          variant={action === 'repair' ? 'outline' : 'primary'}
                          disabled={mutation.isPending}
                          aria-label={`${ACTION_COPY[action].button}: ${policy.name}`}
                          onClick={() => {
                            setMutationError(null)
                            const topology = connection?.topology as Record<string, unknown> | null | undefined
                            const systemID = topology?.system_identifier
                            const targetIdentity = typeof systemID === 'string' && /^\d{1,20}$/.test(systemID)
                              ? `postgres:system:${systemID}` : null
                            setPendingAction({ policy, action, targetIdentity })
                          }}
                        >
                          {action === 'repair' ? (
                            <FileDiff className="size-3.5" aria-hidden="true" />
                          ) : (
                            <CheckCircle2 className="size-3.5" aria-hidden="true" />
                          )}
                          {ACTION_COPY[action].button}
                        </Button>
                      )}
                    </div>

                    <PolicySummary policy={policy} />
                    <PolicyDelta policy={policy} />
                    {!policy.exact && !policy.managed && policy.status !== 'missing' && (
                      <p className="text-xs text-warn">
                        Существующая роль не совпадает с шаблоном. Adopt разрешён только после exact-сверки;
                        Apply явно приведёт безопасную роль к policy напрямую через PostgreSQL.
                      </p>
                    )}
                    {policy.blocked_reason !== '' && action === null && (
                      <p className="text-xs text-warn">{blockedReasonLabel(policy.blocked_reason)}</p>
                    )}
                  </article>
                )
              })}
            </div>
          </div>
        )}
      </QueryStates>

      <ConfirmActionDialog
        open={pendingAction !== null}
        title={pendingAction === null ? '' : ACTION_COPY[pendingAction.action].title}
        description={pendingAction === null ? null : confirmationDescription(pendingAction)}
        confirmLabel={pendingAction === null ? '' : ACTION_COPY[pendingAction.action].confirm}
        danger={pendingAction !== null &&
          pendingAction.action !== 'adopt' && deltaCount(pendingAction.policy, 'extra') > 0}
        pending={mutation.isPending}
        onConfirm={() => {
          if (pendingAction !== null) mutation.mutate(pendingAction)
        }}
        onClose={() => {
          if (!mutation.isPending) setPendingAction(null)
        }}
      />
    </section>
  )
}
