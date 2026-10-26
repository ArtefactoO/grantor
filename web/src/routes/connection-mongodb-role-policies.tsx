import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  CheckCircle2,
  FileDiff,
  Network,
  ShieldAlert,
  ShieldCheck,
} from '@project/ui/icons'
import { api, apiList } from '../lib/api'
import { errorMessage } from '../lib/errorMessage'
import { qk } from '../lib/queryKeys'
import type {
  MongoDBRolePolicy,
  MongoDBRolePolicyPrivilege,
  MongoDBRolePolicyRoleRef,
  RolePolicyMutationRequest,
  RolePolicyMutationResponse,
} from '../lib/types'
import { Button, EmptyState, ErrorBanner, InlineNotice } from '@project/ui'
import { StatusChip } from '../components/ui/badge'
import { ConfirmActionDialog } from '../components/ui/confirm-dialog'
import { QueryStates } from '../components/ui/query-states'

export type MongoDBRolePolicyAction = 'apply' | 'adopt' | 'repair'

interface PendingMongoDBRolePolicyAction {
  policy: MongoDBRolePolicy
  action: MongoDBRolePolicyAction
  requestId: string
}

export interface MongoDBRolePoliciesSectionProps {
  connectionId: string
  isAdmin: boolean
  connectionActive: boolean
  templateActions?: ReactNode
  onOpenTemplate?: (key: string) => void
}

const ROLE_POLICY_REFRESH_MS = 1_500

export function mongoDBRolePolicyRefreshInterval(
  policies: readonly MongoDBRolePolicy[] | undefined,
): number | false {
  return policies?.some((policy) => policy.transition_active)
    ? ROLE_POLICY_REFRESH_MS
    : false
}

const ACTION_COPY: Record<MongoDBRolePolicyAction, {
  button: string
  title: string
  confirm: string
}> = {
  apply: {
    button: 'Применить policy',
    title: 'Применить MongoDB policy?',
    confirm: 'Применить',
  },
  adopt: {
    button: 'Принять под управление',
    title: 'Принять MongoDB policy под управление?',
    confirm: 'Принять',
  },
  repair: {
    button: 'Исправить drift',
    title: 'Исправить MongoDB policy?',
    confirm: 'Исправить',
  },
}

export function mongoDBRolePolicyAction(
  policy: MongoDBRolePolicy,
): MongoDBRolePolicyAction | null {
  if (!policy.apply_supported || policy.transition_active) return null
  if (policy.managed) return policy.repairable ? 'repair' : null
  return policy.exact ? 'adopt' : 'apply'
}

function policyStatus(policy: MongoDBRolePolicy): {
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
  target_identity_unavailable: 'Не удалось доказать identity MongoDB deployment; запустите discovery.',
  admin_authentication_required: 'Для role-policy нужен аутентифицированный admin credential.',
  admin_authority_observation_failed: 'Не удалось безопасно проверить effective privileges admin credential; мутации закрыты.',
  role_management_privileges_missing: 'Admin credential не хватает privileges для rolesInfo/createRole/updateRole.',
  configured_role_is_builtin: 'Built-in роль нельзя материализовать как custom-role policy.',
  role_has_authentication_restrictions: 'У роли есть authenticationRestrictions; эта policy их не управляет.',
  role_is_connection_admin_dependency: 'Policy-роль даёт доступ admin credential подключения; её нельзя менять без риска self-revoke.',
  inherited_role_missing: 'Одна из настроенных наследуемых ролей не найдена.',
  inherited_policy_not_ready: 'Зависимая custom-role policy ещё не managed/synced.',
  inherited_policy_drift: 'Зависимая custom-role policy имеет drift; сначала исправьте её.',
  role_observation_failed: 'Не удалось полностью прочитать direct и inherited состояние роли.',
  read_only_target: 'MongoDB target доступен только для чтения; требуется writable primary.',
  unsupported_role_resource_shape: 'У роли есть resource shape, который managed policy не поддерживает.',
  apply_unsupported: 'Текущая конфигурация подключения не поддерживает применение этой policy.',
  template_removed: 'Применённый или используемый шаблон удалён из каталога.',
  template_identity_changed: 'Role name или role database managed policy были изменены.',
}

function blockedReasonLabel(reason: string): string {
  if (reason === '') return ''
  return BLOCKED_REASON_LABELS[reason] ?? reason
}

function values(policy: MongoDBRolePolicy, key: 'missing' | 'extra'): string[] {
  const value = policy.observed_summary?.[key]
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === 'string' && item !== '')
    : []
}

function valueCount(policy: MongoDBRolePolicy, key: 'missing' | 'extra'): number {
  const count = policy.observed_summary?.[`${key}_count`]
  return typeof count === 'number' && Number.isFinite(count) ? count : values(policy, key).length
}

function policyTokenLabel(value: string): string {
  const roleLabels: Record<string, string> = {
    'role:exists': 'Custom role существует',
    'role:custom': 'Роль не является built-in',
    'role:no_authentication_restrictions': 'Нет direct authenticationRestrictions',
    'role:no_inherited_authentication_restrictions': 'Нет inherited authenticationRestrictions',
  }
  if (value in roleLabels) return roleLabels[value] ?? value
  if (value.startsWith('inherits:')) return `Наследовать ${value.slice('inherits:'.length)}`
  if (value.startsWith('effective_inherits:')) {
    return `Effective inheritance: ${value.slice('effective_inherits:'.length)}`
  }
  if (value.startsWith('dependency_exists:')) {
    return `Зависимая роль существует: ${value.slice('dependency_exists:'.length)}`
  }
  const privilegePrefix = value.startsWith('effective_privilege:')
    ? 'effective_privilege:'
    : value.startsWith('privilege:') ? 'privilege:' : ''
  if (privilegePrefix !== '') {
    const body = value.slice(privilegePrefix.length)
    const separator = body.lastIndexOf(':')
    if (separator > 0) {
      const label = `${body.slice(0, separator)}: ${body.slice(separator + 1)}`
      return privilegePrefix === 'effective_privilege:' ? `Effective · ${label}` : label
    }
  }
  return value
}

function dangerReasonLabel(reason: string): string {
  if (reason === 'privilege_observation_incomplete') {
    return 'rolesInfo не доказал полный effective privilege set.'
  }
  if (reason === 'unsupported_resource_shape') {
    return 'rolesInfo вернул resource shape вне managed contract.'
  }
  const unsupportedResource = /^(direct|inherited):unsupported_resource_shape$/.exec(reason)
  if (unsupportedResource !== null) {
    return `${unsupportedResource[1] === 'direct' ? 'Direct' : 'Inherited'} resource shape вне managed contract.`
  }
  const action = /^(direct|inherited):dangerous_action:(.+)$/.exec(reason)
  if (action !== null) {
    return `${action[1] === 'direct' ? 'Direct' : 'Inherited'} action вне safe data subset: ${action[2]}.`
  }
  const resource = /^(direct|inherited):broad_resource:(.+)$/.exec(reason)
  if (resource !== null) {
    return `${resource[1] === 'direct' ? 'Direct' : 'Inherited'} broad resource: ${resource[2]}.`
  }
  return reason
}

function SafeValues({ values: items, empty }: { values: readonly string[]; empty: string }) {
  if (items.length === 0) return <p className="text-xs text-faint">{empty}</p>
  return (
    <ul className="space-y-1">
      {items.map((value, index) => (
        <li
          key={`${value}-${index}`}
          className="break-all rounded bg-panel2 px-2 py-1 font-mono text-[11px] leading-relaxed text-muted"
          title={value}
        >
          {policyTokenLabel(value)}
        </li>
      ))}
    </ul>
  )
}

function roleRefLabel(role: MongoDBRolePolicyRoleRef): string {
  return `${role.db}.${role.role}`
}

function resourceLabel(privilege: MongoDBRolePolicyPrivilege): string {
  const resource = privilege.resource
  if ('cluster' in resource) return 'cluster'
  if ('any_resource' in resource) return 'anyResource'
  const db = resource.db ?? ''
  const collection = resource.collection ?? ''
  if (db === '' && collection === '') return 'all databases'
  if (db === '') return `all databases · ${collection}`
  return collection === '' ? `${db}.*` : `${db}.${collection}`
}

function PrivilegeValues({
  privileges,
  empty,
}: {
  privileges: readonly MongoDBRolePolicyPrivilege[]
  empty: string
}) {
  if (privileges.length === 0) return <p className="text-xs text-faint">{empty}</p>
  return (
    <ul className="space-y-1.5">
      {privileges.map((privilege, index) => (
        <li key={`${resourceLabel(privilege)}-${index}`} className="min-w-0 text-xs">
          <span className="break-all font-mono text-text">{resourceLabel(privilege)}</span>
          <span className="mx-1.5 text-faint" aria-hidden="true">—</span>
          <span className="break-words font-mono text-muted">
            {[...privilege.actions].sort().join(', ') || 'без actions'}
          </span>
        </li>
      ))}
    </ul>
  )
}

function RoleValues({ roles, empty }: { roles: readonly MongoDBRolePolicyRoleRef[]; empty: string }) {
  if (roles.length === 0) return <p className="text-xs text-faint">{empty}</p>
  return (
    <ul className="flex flex-wrap gap-1.5">
      {roles.map((role, index) => (
        <li
          key={`${roleRefLabel(role)}-${index}`}
          className="max-w-full break-all rounded bg-panel2 px-2 py-1 font-mono text-[11px] text-muted"
        >
          {roleRefLabel(role)}
        </li>
      ))}
    </ul>
  )
}

function PolicySummary({ policy }: { policy: MongoDBRolePolicy }) {
  const spec = policy.desired_spec
  return (
    <dl className="grid min-w-0 gap-x-4 gap-y-1 text-xs sm:grid-cols-[auto_minmax(0,1fr)_auto_minmax(0,1fr)]">
      <div className="contents">
        <dt className="text-faint">Custom role</dt>
        <dd className="min-w-0 break-all font-mono text-muted" title={spec.role_name}>
          {spec.role_name}
        </dd>
      </div>
      <div className="contents">
        <dt className="text-faint">Role database</dt>
        <dd className="min-w-0 break-all font-mono text-muted" title={spec.role_database}>
          {spec.role_database}
        </dd>
      </div>
      <div className="contents">
        <dt className="text-faint">Direct privileges</dt>
        <dd className="tabular-nums text-muted">{spec.privileges.length}</dd>
      </div>
      <div className="contents">
        <dt className="text-faint">Inherited roles</dt>
        <dd className="tabular-nums text-muted">{spec.inherited_roles.length}</dd>
      </div>
    </dl>
  )
}

function DesiredDetails({ policy }: { policy: MongoDBRolePolicy }) {
  const [open, setOpen] = useState(false)
  const spec = policy.desired_spec
  return (
    <details
      className="group rounded-md border border-line/70 bg-panel2/20"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <ShieldCheck className="size-3.5 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1">
          Template: {spec.privileges.length} direct privileges · {spec.inherited_roles.length} inherited roles
        </span>
        <span className="text-faint group-open:hidden" aria-hidden="true">Показать</span>
        <span className="hidden text-faint group-open:inline" aria-hidden="true">Скрыть</span>
      </summary>
      {open && (
        <div className="grid gap-4 border-t border-line/70 p-3 sm:grid-cols-2">
          <section aria-label="Privileges из MongoDB template">
            <h4 className="mb-2 text-xs font-medium text-muted">Direct privileges</h4>
            <PrivilegeValues privileges={spec.privileges} empty="Прямых privileges нет." />
          </section>
          <section aria-label="Inherited roles из MongoDB template">
            <h4 className="mb-2 text-xs font-medium text-muted">Inherited roles</h4>
            <RoleValues roles={spec.inherited_roles} empty="Inheritance нет." />
          </section>
        </div>
      )}
    </details>
  )
}

function PolicyDelta({ policy }: { policy: MongoDBRolePolicy }) {
  const [open, setOpen] = useState(false)
  const missing = values(policy, 'missing')
  const extra = values(policy, 'extra')
  const missingCount = valueCount(policy, 'missing')
  const extraCount = valueCount(policy, 'extra')
  if (missingCount === 0 && extraCount === 0) return null

  return (
    <details
      className="group rounded-md border border-line/70 bg-panel2/20"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <FileDiff className="size-3.5 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1">
          Role diff: не хватает {missingCount}, лишних {extraCount}
        </span>
        <span className="text-faint group-open:hidden" aria-hidden="true">Показать</span>
        <span className="hidden text-faint group-open:inline" aria-hidden="true">Скрыть</span>
      </summary>
      {open && (
        <>
          <div className="grid gap-3 border-t border-line/70 p-3 sm:grid-cols-2">
            <section aria-label="Недостающие элементы MongoDB role policy">
              <h4 className="mb-2 text-xs font-medium text-warn">Добавятся</h4>
              <SafeValues values={missing} empty="Недостающих элементов нет." />
            </section>
            <section aria-label="Лишние элементы MongoDB role policy">
              <h4 className="mb-2 text-xs font-medium text-danger">Будут удалены</h4>
              <SafeValues values={extra} empty="Лишних элементов нет." />
            </section>
          </div>
          {policy.observed_summary.truncated === true && (
            <p className="border-t border-line/70 px-3 py-2 text-xs text-warn">
              Preview ограничен. updateRole заменит обе direct-массива и применит все{' '}
              {missingCount + extraCount} расхождений.
            </p>
          )}
        </>
      )}
    </details>
  )
}

function ObservedDetails({ policy }: { policy: MongoDBRolePolicy }) {
  const [open, setOpen] = useState(false)
  const summary = policy.observed_summary
  const directPrivileges = summary.direct_privileges ?? []
  const directRoles = summary.direct_inherited_roles ?? []
  const inheritedPrivileges = summary.inherited_privileges ?? []
  const inheritedRoles = summary.inherited_roles ?? []
  const dangerReasons = summary.danger_reasons ?? []
  const dependencyBlockers = summary.dependency_blockers ?? []
  const directPrivilegeCount = summary.direct_privileges_count ?? directPrivileges.length
  const directRoleCount = summary.direct_inherited_roles_count ?? directRoles.length
  const inheritedPrivilegeCount = summary.inherited_privileges_count ?? inheritedPrivileges.length
  const inheritedRoleCount = summary.inherited_roles_count ?? inheritedRoles.length
  const authRestrictionCount = (summary.auth_restrictions_count ?? 0) +
    (summary.inherited_auth_restrictions_count ?? 0)
  const hasDetails = directPrivileges.length > 0 || directRoles.length > 0 ||
    inheritedPrivileges.length > 0 || inheritedRoles.length > 0 || dangerReasons.length > 0 ||
    dependencyBlockers.length > 0 || summary.exists === true
  if (!hasDetails) return null

  return (
    <details
      className="group rounded-md border border-line/70 bg-panel2/20"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs font-medium text-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent [&::-webkit-details-marker]:hidden">
        <Network className="size-3.5 shrink-0" aria-hidden="true" />
        <span className="min-w-0 flex-1">Фактический rolesInfo</span>
        <span className="text-faint group-open:hidden" aria-hidden="true">Показать</span>
        <span className="hidden text-faint group-open:inline" aria-hidden="true">Скрыть</span>
      </summary>
      {open && <div className="space-y-4 border-t border-line/70 p-3">
        <div className="grid gap-4 sm:grid-cols-2">
          <section aria-label="Прямые privileges">
            <h4 className="mb-2 text-xs font-medium text-muted">
              Direct privileges ({directPrivilegeCount})
            </h4>
            <PrivilegeValues privileges={directPrivileges} empty="Прямых privileges нет." />
          </section>
          <section aria-label="Прямо наследуемые роли">
            <h4 className="mb-2 text-xs font-medium text-muted">
              Direct inherited roles ({directRoleCount})
            </h4>
            <RoleValues roles={directRoles} empty="Прямого inheritance нет." />
          </section>
          <section aria-label="Эффективные inherited privileges">
            <h4 className="mb-2 text-xs font-medium text-muted">
              Inherited privileges ({inheritedPrivilegeCount})
            </h4>
            <PrivilegeValues privileges={inheritedPrivileges} empty="Inherited privileges нет." />
          </section>
          <section aria-label="Все inherited roles">
            <h4 className="mb-2 text-xs font-medium text-muted">
              Inherited roles ({inheritedRoleCount})
            </h4>
            <RoleValues roles={inheritedRoles} empty="Inherited roles нет." />
          </section>
        </div>
        {dangerReasons.length > 0 && (
          <section aria-label="Причины dangerous">
            <h4 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-danger">
              <ShieldAlert className="size-3.5" aria-hidden="true" />
              Почему policy dangerous
            </h4>
            <ul className="list-disc space-y-1 ps-4 text-xs text-danger">
              {dangerReasons.map((reason) => <li key={reason}>{dangerReasonLabel(reason)}</li>)}
            </ul>
          </section>
        )}
        {dependencyBlockers.length > 0 && (
          <section aria-label="Неготовые зависимые policies">
            <h4 className="mb-1.5 text-xs font-medium text-warn">Dependency blockers</h4>
            <SafeValues values={dependencyBlockers} empty="Зависимости готовы." />
            <p className="mt-1.5 text-xs text-faint">
              Сначала примените или исправьте эти policies; затем повторите discovery.
            </p>
          </section>
        )}
        {authRestrictionCount > 0 && (
          <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
            Обнаружено authenticationRestrictions: {authRestrictionCount}. Managed policy их не
            изменяет; Apply/Adopt/Repair заблокированы.
          </p>
        )}
        {summary.truncated === true && (
          <p className="text-xs text-warn">
            rolesInfo preview ограничен 20 privilege entries и общим бюджетом 100 actions;
            числа в заголовках полные.
          </p>
        )}
      </div>}
    </details>
  )
}

function confirmationDescription({ policy, action }: PendingMongoDBRolePolicyAction) {
  const missing = values(policy, 'missing')
  const extra = values(policy, 'extra')
  const missingCount = valueCount(policy, 'missing')
  const extraCount = valueCount(policy, 'extra')
  const role = `${policy.desired_spec.role_database}.${policy.desired_spec.role_name}`
  if (action === 'adopt') {
    return (
      <p>
        Роль <span className="font-mono text-text">{role}</span> точно совпадает с policy.
        Grantor зафиксирует её как managed без createRole/updateRole.
      </p>
    )
  }
  if (action === 'apply' &&
    (policy.status === 'missing' || policy.observed_summary.exists === false)) {
    return (
      <p>
        Grantor выполнит createRole для{' '}
        <span className="font-mono text-text">{role}</span> с exact privileges и inherited
        roles из шаблона. Аккаунтам роль автоматически не назначается.
      </p>
    )
  }
  if (action === 'repair' || (action === 'apply' && (missingCount > 0 || extraCount > 0))) {
    return (
      <div className="space-y-3">
        <p>
          updateRole заменит обе direct-массива роли{' '}
          <span className="font-mono text-text">{role}</span>: privileges и inherited roles.
          Effective inherited state в команду не копируется.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <section aria-label="Недостающие элементы перед MongoDB repair">
            <h4 className="mb-1.5 text-xs font-medium text-warn">Добавится ({missingCount})</h4>
            <SafeValues values={missing} empty="Ничего." />
          </section>
          <section aria-label="Лишние элементы перед MongoDB repair">
            <h4 className="mb-1.5 text-xs font-medium text-danger">Будет удалено ({extraCount})</h4>
            <SafeValues values={extra} empty="Ничего." />
          </section>
        </div>
        {policy.observed_summary.truncated === true && (
          <p className="text-xs text-warn">
            Список сокращён; updateRole применит весь diff из {missingCount + extraCount} расхождений.
          </p>
        )}
      </div>
    )
  }
  return (
    <p>
      Grantor приведёт custom role <span className="font-mono text-text">{role}</span> к exact
      privileges и inherited roles из шаблона. Аккаунтам роль автоматически не назначается.
    </p>
  )
}

export function MongoDBRolePoliciesSection({
  connectionId,
  isAdmin,
  connectionActive,
  templateActions,
  onOpenTemplate,
}: MongoDBRolePoliciesSectionProps) {
  const queryClient = useQueryClient()
  const [pendingAction, setPendingAction] = useState<PendingMongoDBRolePolicyAction | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [mutationError, setMutationError] = useState<string | null>(null)
  const hadActiveTransition = useRef(false)

  const policiesQuery = useQuery({
    queryKey: qk.connectionRolePolicies(connectionId),
    queryFn: ({ signal }) => apiList<MongoDBRolePolicy>(
      `/api/v1/connections/${connectionId}/role-policies`,
      'policies',
      signal,
    ),
    refetchInterval: (query) => mongoDBRolePolicyRefreshInterval(
      query.state.data as MongoDBRolePolicy[] | undefined,
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

  useEffect(() => {
    if (pendingAction === null || mutationError === null) return
    const current = (policiesQuery.data ?? []).find(
      (policy) => policy.template_key === pendingAction.policy.template_key,
    )
    if (current === undefined || current.version <= pendingAction.policy.version) return

    setPendingAction(null)
    void Promise.all([
      queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
      queryClient.invalidateQueries({ queryKey: qk.operations() }),
    ])
    if (current.transition_active) {
      setMutationError(null)
      setNotice(
        `${ACTION_COPY[pendingAction.action].button}: сервер принял операцию; выполнение продолжается.`,
      )
      return
    }
    if (current.managed && current.exact) {
      setMutationError(null)
      setNotice(`${ACTION_COPY[pendingAction.action].button}: сервер подтвердил синхронизацию.`)
      return
    }
    setMutationError(
      `${ACTION_COPY[pendingAction.action].button}: сервер завершил операцию со статусом «${policyStatus(current).label}».`,
    )
  }, [connectionId, mutationError, pendingAction, policiesQuery.data, queryClient])

  const blockedReasons = useMemo(
    () => [...new Set((policiesQuery.data ?? [])
      .map((policy) => policy.blocked_reason)
      .filter((reason) => reason !== '')
      .map(blockedReasonLabel))],
    [policiesQuery.data],
  )

  const mutation = useMutation({
    mutationFn: ({ policy, action, requestId }: PendingMongoDBRolePolicyAction) => {
      const body: RolePolicyMutationRequest = {
        request_id: requestId,
        version: policy.version,
        observed_fingerprint: policy.observed_fingerprint,
        confirm: true,
      }
      return api<RolePolicyMutationResponse>(
        `/api/v1/connections/${connectionId}/role-policies/${encodeURIComponent(policy.template_key)}/${action}`,
        { method: 'POST', body },
      )
    },
    onSuccess: async (response, variables) => {
      setPendingAction(null)
      setMutationError(null)
      setNotice(`${ACTION_COPY[variables.action].button}: операция ${response.operation_id} поставлена в очередь.`)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connectionRolePolicies(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.connectionPermissions(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
      ])
    },
    onError: async (error: unknown) => {
      setMutationError(errorMessage(error))
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: qk.connectionRolePolicies(connectionId) }),
        queryClient.invalidateQueries({ queryKey: qk.operations() }),
      ])
    },
  })

  return (
    <section className="space-y-3" aria-labelledby="mongodb-role-policies-title">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h2 id="mongodb-role-policies-title" className="text-sm font-semibold text-text">
            Шаблоны доступа MongoDB
          </h2>
          <p className="mt-1 max-w-3xl text-xs text-muted">
            Шаблон управляет правами и наследованием custom role. Встроенные read/readWrite
            по-прежнему назначаются как обычные роли.
          </p>
        </div>
        {templateActions}
      </div>

      {notice !== null && <InlineNotice text={notice} onClose={() => setNotice(null)} />}
      {mutationError !== null && pendingAction === null && <ErrorBanner>{mutationError}</ErrorBanner>}
      {isAdmin && !connectionActive && (
        <div role="status" className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs text-warn">
          Apply, Adopt и Repair доступны только для active connection.
        </div>
      )}

      <QueryStates
        query={policiesQuery}
        empty={(
          <EmptyState
            icon={ShieldCheck}
            title="Шаблоны доступа не настроены"
            description={isAdmin
              ? 'Создайте шаблон здесь. Сохранение шаблона не меняет MongoDB. Применение выполняется отдельно.'
              : 'Администратор ещё не опубликовал custom-role templates для этого подключения.'}
            className="py-7"
          />
        )}
      >
        {(policies) => (
          <div className="space-y-3">
            {blockedReasons.length > 0 && (
              <div role="status" className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2.5 text-warn">
                <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
                <div className="min-w-0">
                  <p className="text-sm font-medium">Часть policies нельзя изменить</p>
                  <ul className="mt-1 list-disc space-y-1 ps-4 text-xs leading-relaxed">
                    {blockedReasons.map((reason) => <li key={reason}>{reason}</li>)}
                  </ul>
                  <p className="mt-1.5 text-xs text-faint">
                    Назначение drifted policy блокируется, но текущее состояние остаётся видимым.
                  </p>
                </div>
              </div>
            )}

            <div className="divide-y divide-line overflow-hidden rounded-md border border-line">
              {policies.map((policy) => {
                const state = policyStatus(policy)
                const action = connectionActive ? mongoDBRolePolicyAction(policy) : null
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
                          {policy.dangerous && <StatusChip tone="danger">Dangerous</StatusChip>}
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
                            setPendingAction({
                              policy,
                              action,
                              requestId: globalThis.crypto.randomUUID(),
                            })
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
                    <DesiredDetails policy={policy} />
                    <PolicyDelta policy={policy} />
                    <ObservedDetails policy={policy} />
                    {!policy.exact && !policy.managed && policy.status !== 'missing' && (
                      <p className="text-xs text-warn">
                        Существующая custom role не совпадает с шаблоном. Adopt доступен только
                        после exact-сверки; Apply явно заменит direct privileges и roles.
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
        description={pendingAction === null ? null : (
          <div className="space-y-3">
            {mutationError !== null && <ErrorBanner>{mutationError}</ErrorBanner>}
            {confirmationDescription(pendingAction)}
          </div>
        )}
        confirmLabel={pendingAction === null ? '' : ACTION_COPY[pendingAction.action].confirm}
        danger={pendingAction !== null && (
          pendingAction.policy.dangerous ||
          (pendingAction.action !== 'adopt' && valueCount(pendingAction.policy, 'extra') > 0)
        )}
        pending={mutation.isPending}
        onConfirm={() => {
          if (pendingAction !== null) mutation.mutate(pendingAction)
        }}
        onClose={() => {
          if (!mutation.isPending) {
            setPendingAction(null)
            setMutationError(null)
          }
        }}
      />
    </section>
  )
}
