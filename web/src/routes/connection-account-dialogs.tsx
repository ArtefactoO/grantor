// Диалоги и drawers экрана «Аккаунты»: создание managed-аккаунта, управление
// ролями аккаунта, привязка к пользователю и удаление. Открываются из вкладки
// (CreateAccountDrawer) и из панели выбранного аккаунта (остальные).
import { useEffect, useMemo, useRef, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { apiList, apiPost } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import type {
  Account,
  AccountOperationResponse,
  AdoptAccountMetadataResponse,
  AdoptAccountOperationResponse,
  AdoptAccountRequest,
  Binding,
  BulkCreateBindingsRequest,
  BulkCreateBindingsResponse,
  Connection,
  CreateAccountRequest,
  LinkAccountRequest,
  LinkAndManageAccountRequest,
  LinkAndManageAccountResponse,
  ManageAccountRolesRequest,
  ManageAccountRolesResponse,
  Permission,
  Principal,
  PrincipalCredentialEnvironment,
} from '../lib/types'
import { shortId } from '../lib/status'
import { permissionAccessEntry, permissionNameLabel } from '../lib/access-entries'
import type { AccessEntry } from '../lib/access-entries'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import {
  cn,
  selectionSurfaceClassName,
  Button,
  Drawer,
  Dialog,
  Field,
  Input,
  Spinner,
  ErrorBanner,
  RadioOptionCard,
  SearchInput,
} from '@project/ui'
import { PrincipalTypeChip, StatusChip } from '../components/ui/badge'
import { DangerConfirm } from '../components/ui/danger-confirm'
import { AccessChipList, ElevatedAccessDot } from '../components/ui/access-chips'
import { inventoryStatusLabel } from '../lib/ui-copy'
import { environmentLabel } from './principal-detail-shared'
import {
  isSharedRoleKind,
  supportsManagedCredentialLink,
} from '../lib/account-actions'
import { OperationRehearsal } from '../components/operation-rehearsal'
import { MAX_BULK_ITEMS } from '../lib/limits'
import { isActiveAccessBinding, isAssignedManagedBinding } from '../lib/active-access'
import { postgresProvisioningIssue } from '../lib/postgres-provisioning-authority'
import { PostgresProvisioningNotice } from '../components/postgres-provisioning-notice'

// ---------------------------------------------------------------------------
// Создание managed-аккаунта: POST /api/v1/accounts (operator+).

interface CreateAccountDrawerProps {
  connectionId: string
  connection?: Connection
  open: boolean
  onClose: () => void
  onStarted: (operationId: string, identity: string) => void
}

interface AccountForm {
  engineIdentity: string
  mode: 'generated' | 'provided'
  username: string
  password: string
}

const EMPTY_ACCOUNT_FORM: AccountForm = {
  engineIdentity: '',
  mode: 'generated',
  username: '',
  password: '',
}

export function CreateAccountDrawer({
  connectionId,
  connection,
  open,
  onClose,
  onStarted,
}: CreateAccountDrawerProps) {
  const queryClient = useQueryClient()
  const identityInputRef = useRef<HTMLInputElement | null>(null)
  const [form, setForm] = useState<AccountForm>(EMPTY_ACCOUNT_FORM)
  const [formError, setFormError] = useState<string | null>(null)
  const provisioningIssue = connection === undefined ? null : postgresProvisioningIssue(connection)
  const provisioningBlockerId = connection === undefined ? undefined : `postgres-account-create-${connection.id}-blocker`

  const setField = <K extends keyof AccountForm>(key: K, value: AccountForm[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }

  const close = () => {
    setFormError(null)
    onClose()
  }

  const createMutation = useMutation({
    mutationFn: (payload: CreateAccountRequest) =>
      apiPost<AccountOperationResponse>('/api/v1/accounts', payload),
    onSuccess: (data, payload) => {
      void queryClient.invalidateQueries({
        queryKey: qk.connectionAccounts(connectionId),
      })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      setForm(EMPTY_ACCOUNT_FORM)
      setFormError(null)
      onStarted(data.operation_id, payload.engine_identity)
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err))
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (provisioningIssue !== null) {
      setFormError(provisioningIssue)
      return
    }
    const identity = form.engineIdentity.trim()
    if (/\s/.test(identity)) {
      setFormError('Логин в подключении не должен содержать пробельных символов')
      return
    }
    const username = form.username.trim()
    const payload: CreateAccountRequest = {
      connection_id: connectionId,
      engine_identity: identity,
      credential:
        form.mode === 'generated'
          ? { mode: 'generated' }
          : username !== ''
            ? { mode: 'provided', username, password: form.password }
            : { mode: 'provided', password: form.password },
    }
    createMutation.mutate(payload)
  }

  return (
    <Drawer open={open} onClose={close} title="Создать учётку" initialFocusRef={identityInputRef}>
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {connection !== undefined && (
          <p className="break-words text-sm text-muted">
            {connection.display_name} · {environmentLabel(connection)}
          </p>
        )}
        {connection?.engine === 'postgres' && <PostgresProvisioningNotice connection={connection} id={provisioningBlockerId} />}
        <Field
          label="Логин в подключении"
          tooltip="Имя аккаунта непосредственно в целевой базе или кластере."
        >
          <Input
            ref={identityInputRef}
            value={form.engineIdentity}
            onChange={(e) => setField('engineIdentity', e.target.value)}
            placeholder="svc_reporting"
            className="font-mono text-[13px]"
            autoComplete="off"
            required
          />
        </Field>

        <div>
          <span className="mb-1.5 block text-xs font-medium text-muted">Пароль</span>
          <div className="space-y-1.5">
            <RadioOptionCard
              name="credential-mode"
              label="Сгенерировать"
              hint="пароль создаст адаптер и сохранит в Vault"
              checked={form.mode === 'generated'}
              onSelect={() => setField('mode', 'generated')}
            />
            <RadioOptionCard
              name="credential-mode"
              label="Задать вручную"
              hint="пароль задаёт оператор; уходит только в Vault"
              checked={form.mode === 'provided'}
              onSelect={() => setField('mode', 'provided')}
            />
          </div>
        </div>

        {form.mode === 'provided' && (
          <div className="space-y-3 rounded-md border border-line bg-panel2/50 p-3">
            <Field label="Пользователь" hint="необязательно; по умолчанию используется логин в подключении">
              <Input
                value={form.username}
                onChange={(e) => setField('username', e.target.value)}
                className="font-mono text-[13px]"
                autoComplete="off"
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
          </div>
        )}

        {formError !== null && <div role="alert"><ErrorBanner>{formError}</ErrorBanner></div>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={close} disabled={createMutation.isPending}>
            Отмена
          </Button>
          <Button type="submit" aria-describedby={provisioningIssue === null ? undefined : provisioningBlockerId}
            disabled={createMutation.isPending || provisioningIssue !== null}>
            {createMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Создать учётку
          </Button>
        </div>
      </form>
    </Drawer>
  )
}

// ---------------------------------------------------------------------------
// Управление ролями аккаунта: один bulk parent группирует выдачу и отзыв.

interface ManageRolesDrawerProps {
  open: boolean
  /** Reuse the same role delta editor inside an existing drawer. */
  embedded?: boolean
  blockedReason?: string
  onPendingChange?: (pending: boolean) => void
  account: Account
  permissions: Permission[]
  bindings: Binding[]
  onClose: () => void
  onStarted: (
    operationId: string,
    changes: { added: string[]; removed: string[] },
  ) => void
}

interface PermissionTemplateMeta {
  name: string
  description: string
  vhost: string
  configure: string
  write: string
  read: string
  broad: boolean
}

function stringAttribute(attributes: unknown, ...keys: string[]): string {
  if (attributes === null || typeof attributes !== 'object' || Array.isArray(attributes)) {
    return ''
  }
  const record = attributes as Record<string, unknown>
  for (const key of keys) {
    if (typeof record[key] === 'string') return record[key]
  }
  return ''
}

function booleanAttribute(attributes: unknown, ...keys: string[]): boolean {
  if (attributes === null || typeof attributes !== 'object' || Array.isArray(attributes)) {
    return false
  }
  const record = attributes as Record<string, unknown>
  return keys.some((key) => record[key] === true)
}

function permissionTemplateMeta(permission: Permission): PermissionTemplateMeta {
  const configure = stringAttribute(permission.attributes, 'configure')
  const write = stringAttribute(permission.attributes, 'write')
  const read = stringAttribute(permission.attributes, 'read')
  return {
    name: stringAttribute(permission.attributes, 'template_name', 'display_name') || permission.name,
    description: stringAttribute(permission.attributes, 'description', 'template_description'),
    vhost: stringAttribute(permission.attributes, 'vhost') || permission.normalized.scope,
    configure,
    write,
    read,
    broad:
      booleanAttribute(permission.attributes, 'broad', 'broad_configure') ||
      (configure === '.*' && write === '.*' && read === '.*'),
  }
}

function matchesPermissionSearch(permission: Permission, query: string): boolean {
  if (query === '') return true
  const meta = permissionTemplateMeta(permission)
  return [
    permission.name,
    permission.external_id,
    meta.name,
    meta.description,
    meta.vhost,
    meta.configure,
    meta.write,
    meta.read,
  ].some((value) => value.toLocaleLowerCase('ru').includes(query))
}

export function ManageRolesDrawer({
  open,
  embedded = false,
  blockedReason,
  onPendingChange,
  account,
  permissions,
  bindings,
  onClose,
  onStarted,
}: ManageRolesDrawerProps) {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const [search, setSearch] = useState('')
  const [permissionIds, setPermissionIds] = useState<Set<string>>(new Set())
  const [dangerConfirmed, setDangerConfirmed] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const submissionPendingRef = useRef(false)
  const onPendingChangeRef = useRef(onPendingChange)
  onPendingChangeRef.current = onPendingChange
  const selectionSession = useRef<{ accountId: string; baseline: Set<string> } | null>(null)

  const assignedPermissionIds = useMemo(
    () => new Set(
      // Тот же предикат, что у 409 на повторную выдачу: сломанное право
      // (failed/drift) считается неназначенным и доступно для починки.
      bindings
        .filter(isAssignedManagedBinding)
        .map((binding) => binding.permission_definition_id),
    ),
    [bindings],
  )
  const exclusiveDesiredBindings = useMemo(
    () => bindings.filter((binding) =>
      (binding.assignment_key?.trim() ?? '') !== '' &&
      binding.source === 'service' &&
      binding.desired_state === 'present'),
    [bindings],
  )
  const selectedBaselinePermissionIds = useMemo(() => {
    const selected = new Set(assignedPermissionIds)
    for (const binding of exclusiveDesiredBindings) {
      selected.add(binding.permission_definition_id)
    }
    return selected
  }, [assignedPermissionIds, exclusiveDesiredBindings])
  const observedPermissionIds = useMemo(() => new Set(bindings.filter(isActiveAccessBinding)
    .map((binding) => binding.observed_permission_definition_id ?? binding.permission_definition_id)), [bindings])
  const pinnedPermissionIds = useMemo(() => new Set([...selectedBaselinePermissionIds, ...observedPermissionIds]),
    [selectedBaselinePermissionIds, observedPermissionIds])
  // Missing-право остаётся в списке, только если уже назначено: снять его
  // нужно уметь, а выдать заново — нет (API отвечает 409).
  const manageable = useMemo(
    () =>
      permissions.filter(
        (permission) =>
          selectedBaselinePermissionIds.has(permission.id) ||
          (permission.assignable && permission.status !== 'missing'),
      ),
    [permissions, selectedBaselinePermissionIds],
  )

  useEffect(() => {
    if (!open) {
      selectionSession.current = null
      return
    }
    const previous = selectionSession.current
    if (previous === null || previous.accountId !== account.id) {
      setSearch('')
      setPermissionIds(new Set(selectedBaselinePermissionIds))
      setDangerConfirmed(false)
      setFormError(null)
    } else {
      // Refresh may replace bindings while the operator edits. Rebase untouched
      // roles onto the new snapshot, preserving the operator's pending delta.
      setPermissionIds((current) => {
        const next = new Set(selectedBaselinePermissionIds)
        for (const id of new Set([...previous.baseline, ...current])) {
          if (current.has(id) !== previous.baseline.has(id)) {
            if (current.has(id)) next.add(id)
            else next.delete(id)
          }
        }
        return next.size === current.size && [...next].every((id) => current.has(id)) ? current : next
      })
    }
    selectionSession.current = { accountId: account.id, baseline: new Set(selectedBaselinePermissionIds) }
  }, [open, account.id, selectedBaselinePermissionIds])

  const assignmentGroups = useMemo(() => {
    const groups = new Map<string, Permission[]>()
    for (const permission of manageable) {
      const key = permission.assignment_key?.trim() ?? ''
      if (key === '') continue
      const group = groups.get(key) ?? []
      group.push(permission)
      groups.set(key, group)
    }
    for (const group of groups.values()) {
      group.sort((left, right) => left.name.localeCompare(right.name, 'ru'))
    }
    return groups
  }, [manageable])
  const regularPermissions = useMemo(
    () => manageable.filter((permission) => (permission.assignment_key?.trim() ?? '') === ''),
    [manageable],
  )
  const normalizedSearch = search.trim().toLocaleLowerCase('ru')
  const filteredAssignmentGroups = useMemo(
    () => [...assignmentGroups.entries()].filter(([, group]) =>
      group.some((permission) => pinnedPermissionIds.has(permission.id) || permissionIds.has(permission.id) || matchesPermissionSearch(permission, normalizedSearch))),
    [assignmentGroups, normalizedSearch, permissionIds, pinnedPermissionIds],
  )
  const filteredRegularPermissions = useMemo(
    () => regularPermissions.filter((permission) =>
      pinnedPermissionIds.has(permission.id) || permissionIds.has(permission.id) || matchesPermissionSearch(permission, normalizedSearch)),
    [normalizedSearch, regularPermissions, permissionIds, pinnedPermissionIds],
  )
  const roleOptions = useMemo(() => {
    const rank = (permission: Permission) => pinnedPermissionIds.has(permission.id) ? 0 : permissionIds.has(permission.id) ? 1 : 2
    return [
      ...filteredAssignmentGroups.map(([assignmentKey, group]) => ({ kind: 'group' as const, assignmentKey, group, rank: Math.min(...group.map(rank)), name: group[0].name })),
      ...filteredRegularPermissions.map((permission) => ({ kind: 'permission' as const, permission, rank: rank(permission), name: permission.name })),
    ].sort((a, b) => a.rank - b.rank || a.name.localeCompare(b.name, 'ru'))
  }, [filteredAssignmentGroups, filteredRegularPermissions, permissionIds, pinnedPermissionIds])

  const transitionByAssignmentKey = useMemo(() => {
    const transitions = new Map<string, Binding>()
    for (const binding of bindings) {
      const key = binding.assignment_key?.trim() ?? ''
      if (
        key !== '' &&
        binding.transition_operation_id != null
      ) {
        transitions.set(key, binding)
      }
    }
    return transitions
  }, [bindings])
  const bindingByAssignmentKey = useMemo(() => {
    const slots = new Map<string, Binding>()
    for (const binding of bindings) {
      const key = binding.assignment_key?.trim() ?? ''
      if (key !== '') slots.set(key, binding)
    }
    return slots
  }, [bindings])
  const permissionsById = useMemo(
    () => new Map(permissions.map((permission) => [permission.id, permission])),
    [permissions],
  )

  const additions = useMemo(
    () =>
      manageable.filter(
        (permission) =>
          permissionIds.has(permission.id) &&
          !assignedPermissionIds.has(permission.id) &&
          !bindings.some((binding) =>
            binding.permission_definition_id === permission.id &&
            binding.transition_operation_id != null),
      ),
    [assignedPermissionIds, bindings, manageable, permissionIds],
  )
  const removedPermissions = useMemo(
    () =>
      manageable.filter(
        (permission) =>
          selectedBaselinePermissionIds.has(permission.id) &&
          !permissionIds.has(permission.id),
      ),
    [manageable, permissionIds, selectedBaselinePermissionIds],
  )
  const removedPermissionIds = useMemo(
    () => new Set(removedPermissions.map((permission) => permission.id)),
    [removedPermissions],
  )
  const removedBindings = useMemo(
    () =>
      // Ровно тот предикат, которым строился assignedPermissionIds: снять
      // галочку можно только с того, что показывалось назначенным.
      bindings.filter(
        (binding) =>
          (isAssignedManagedBinding(binding) || exclusiveDesiredBindings.includes(binding)) &&
          removedPermissionIds.has(binding.permission_definition_id),
      ),
    [bindings, exclusiveDesiredBindings, removedPermissionIds],
  )
  const replacementPreviews = useMemo(() => {
    const removedByAssignmentKey = new Map(
      removedPermissions
        .filter((permission) => (permission.assignment_key?.trim() ?? '') !== '')
        .map((permission) => [permission.assignment_key!.trim(), permission]),
    )
    return additions.flatMap((toPermission) => {
      const key = toPermission.assignment_key?.trim() ?? ''
      const fromPermission = key === '' ? undefined : removedByAssignmentKey.get(key)
      return fromPermission === undefined
        ? []
        : [{ key, from: fromPermission, to: toPermission }]
    })
  }, [additions, removedPermissions])
  const dangerous = additions.some((permission) => permission.dangerous)
  const changeCount = additions.length + removedBindings.length

  const manageMutation = useMutation({
    mutationFn: (payload: ManageAccountRolesRequest) =>
      apiPost<ManageAccountRolesResponse>(
        `/api/v1/accounts/${account.id}/roles`,
        payload,
      ),
    onSuccess: (data) => {
      return onStarted(data.operation_id, {
        added: additions.map((permission) => permission.name),
        removed: removedPermissions.map((permission) => permission.name),
      })
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err))
    },
    onSettled: () => {
      submissionPendingRef.current = false
      onPendingChangeRef.current?.(false)
    },
  })

  const close = () => {
    if (!submissionPendingRef.current && !manageMutation.isPending) onClose()
  }

  const canSubmit =
    roleAtLeast(auth.role, 'operator') &&
    (account.status === 'active' || account.status === 'disabled') &&
    !isSharedRoleKind(account.kind) &&
    blockedReason === undefined &&
    changeCount > 0 &&
    changeCount <= MAX_BULK_ITEMS &&
    !manageMutation.isPending &&
    (!dangerous || (isAdmin && dangerConfirmed))

  const submit = () => {
    if (!canSubmit || submissionPendingRef.current) {
      return
    }
    const payload: ManageAccountRolesRequest = {
      add_permission_ids: additions.map((permission) => permission.id),
      remove_binding_ids: removedBindings.map((binding) => binding.id),
    }
    if (dangerous) {
      payload.confirm = true
    }
    submissionPendingRef.current = true
    onPendingChangeRef.current?.(true)
    manageMutation.mutate(payload)
  }

  const editor = (
      <div className="space-y-4">
        {blockedReason !== undefined && <ErrorBanner>{blockedReason}</ErrorBanner>}
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Поиск роли…"
          ariaLabel="Поиск роли"
        />

        {manageable.length === 0 ? (
          <div className="text-sm text-faint">
            В подключении нет ролей, доступных для управления.
          </div>
        ) : roleOptions.length === 0 ? (
          <div className="text-sm text-faint">Ничего не найдено по «{search.trim()}».</div>
        ) : (
          <div className="max-h-[45vh] space-y-3 overflow-y-auto rounded-md border border-line p-1.5">
            {roleOptions.map((option) => {
              if (option.kind === 'group') {
                const { assignmentKey, group } = option
                const selectedPermission = group.find((permission) => permissionIds.has(permission.id))
                const slotBinding = bindingByAssignmentKey.get(assignmentKey)
                const transition = transitionByAssignmentKey.get(assignmentKey)
                const transitionFailed = transition?.status === 'failed'
                const observedPermission = transition?.observed_permission_definition_id == null
                  ? null
                  : (permissionsById.get(transition.observed_permission_definition_id) ?? null)
                const desiredPermission = transition == null
                  ? null
                  : (permissionsById.get(transition.permission_definition_id) ?? null)
                const slotDesiredPermission = slotBinding == null
                  ? null
                  : (permissionsById.get(slotBinding.permission_definition_id) ?? null)
                const dangerousSlotLocked = !isAdmin && slotDesiredPermission?.dangerous === true
                const groupMeta = permissionTemplateMeta(group[0])
                const drifted =
                  transition === undefined &&
                  slotBinding?.desired_state === 'present' &&
                  (slotBinding.status === 'drift' || slotBinding.status === 'failed')
                const driftExpected = slotBinding == null
                  ? null
                  : (permissionsById.get(slotBinding.permission_definition_id) ?? null)
                const driftObserved = slotBinding?.observed_permission_definition_id == null
                  ? null
                  : (permissionsById.get(slotBinding.observed_permission_definition_id) ?? null)
                const expectedMeta = driftExpected == null ? null : permissionTemplateMeta(driftExpected)
                const actualConfigure = stringAttribute(slotBinding?.observed_attributes, 'configure')
                const actualWrite = stringAttribute(slotBinding?.observed_attributes, 'write')
                const actualRead = stringAttribute(slotBinding?.observed_attributes, 'read')

                return (
                  <fieldset
                    key={`assignment-${assignmentKey}`}
                    className="space-y-1.5 rounded-md border border-line/80 bg-panel2/20 p-2"
                    disabled={(transition !== undefined && !transitionFailed) || dangerousSlotLocked}
                  >
                    <legend className="px-1 text-xs font-medium text-muted">
                      {groupMeta.vhost === '' ? 'Взаимоисключающие права' : `vhost ${groupMeta.vhost}`}
                    </legend>

                    {transition !== undefined && (
                      <div
                        role={transitionFailed ? 'alert' : 'status'}
                        className={cn(
                          'rounded border px-2 py-1.5 text-xs text-muted',
                          transitionFailed
                            ? 'border-danger/35 bg-danger/5'
                            : 'border-accent/35 bg-accent/5',
                        )}
                      >
                        {transitionFailed ? 'Замена не завершилась: ' : 'Выполняется замена: '}
                        <span className="font-mono text-text">
                          {observedPermission?.name ?? shortId(transition.observed_permission_definition_id ?? '')}
                          {' → '}
                          {desiredPermission?.name ?? shortId(transition.permission_definition_id)}
                        </span>
                        {transitionFailed && (
                          <span className="mt-1 block">
                            Повторите failed operation либо выберите исходный шаблон, чтобы запустить явный reverse.
                          </span>
                        )}
                      </div>
                    )}

                    {dangerousSlotLocked && (
                      <div className="rounded border border-danger/35 bg-danger/5 px-2 py-1.5 text-xs text-muted">
                        Изменять назначенный dangerous-шаблон может только администратор.
                      </div>
                    )}

                    {drifted && (
                      <div role="alert" className="space-y-1.5 rounded border border-danger/35 bg-danger/5 px-2 py-1.5 text-xs text-muted">
                        <div>
                          Drift: ожидалось{' '}
                          <span className="font-mono text-text">{driftExpected?.name ?? 'выбранный шаблон'}</span>,
                          {' '}фактически{' '}
                          <span className="font-mono text-text">
                            {driftObserved?.name ?? (slotBinding?.observed_state === 'absent' ? 'право отсутствует' : 'неизвестная тройка regex')}
                          </span>.
                        </div>
                        <div className="grid gap-x-2 font-mono text-[11px] sm:grid-cols-[5rem_minmax(0,1fr)_minmax(0,1fr)]">
                          <span />
                          <span className="text-faint">Ожидалось</span>
                          <span className="text-faint">Фактически</span>
                          {([
                            ['configure', expectedMeta?.configure ?? '', actualConfigure],
                            ['write', expectedMeta?.write ?? '', actualWrite],
                            ['read', expectedMeta?.read ?? '', actualRead],
                          ] as const).map(([label, expected, actual]) => (
                            <span key={label} className="contents">
                              <span className="text-faint">{label}</span>
                              <code className="break-all text-muted">{expected || '—'}</code>
                              <code className="break-all text-danger">{actual || '—'}</code>
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    <label
                      className={cn(
                        'flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 transition-colors',
                        selectionSurfaceClassName(selectedPermission === undefined),
                      )}
                    >
                      <input
                        type="radio"
                        name={`assignment-${assignmentKey}`}
                        checked={selectedPermission === undefined}
                        onChange={() => {
                          setPermissionIds((current) => {
                            const next = new Set(current)
                            for (const permission of group) next.delete(permission.id)
                            return next
                          })
                          setDangerConfirmed(false)
                        }}
                        className="accent-accent"
                      />
                      <span className="text-sm text-text">Без доступа</span>
                    </label>

                    {group.map((permission) => {
                      const selected = permissionIds.has(permission.id)
                      const meta = permissionTemplateMeta(permission)
                      const isObservedDuringTransition =
                        transition?.observed_permission_definition_id === permission.id
                      const isDesiredInSlot =
                        slotBinding?.desired_state === 'present' &&
                        slotBinding.permission_definition_id === permission.id

                      return (
                        <label
                          key={permission.id}
                          className={cn(
                            'flex cursor-pointer items-start gap-2.5 rounded-md px-2.5 py-2 transition-colors',
                            selectionSurfaceClassName(selected),
                          )}
                        >
                          <input
                            type="radio"
                            name={`assignment-${assignmentKey}`}
                            checked={selected}
                            disabled={permission.dangerous && !isAdmin}
                            onChange={() => {
                              setPermissionIds((current) => {
                                const next = new Set(current)
                                for (const member of group) next.delete(member.id)
                                next.add(permission.id)
                                return next
                              })
                              setDangerConfirmed(false)
                            }}
                            className="mt-0.5 accent-accent"
                          />
                          <span className="min-w-0 flex-1 space-y-1">
                            <span className="flex flex-wrap items-center gap-1.5">
                              <span className="font-mono text-[13px] text-text">{meta.name}</span>
                              {meta.broad && <StatusChip tone="warn">broad</StatusChip>}
                              {permission.dangerous && <StatusChip tone="danger">dangerous</StatusChip>}
                              {isDesiredInSlot && !transition && (
                                <StatusChip tone={drifted ? 'danger' : 'ok'}>
                                  {drifted ? 'Drift' : 'Назначена'}
                                </StatusChip>
                              )}
                              {isObservedDuringTransition && (
                                <StatusChip tone="warn">Сейчас фактически</StatusChip>
                              )}
                              {selected && transition?.permission_definition_id === permission.id && (
                                <StatusChip tone="accent">Ожидается</StatusChip>
                              )}
                            </span>
                            {meta.description !== '' && (
                              <span className="block text-xs leading-4 text-faint">{meta.description}</span>
                            )}
                            <span className="grid gap-x-2 text-[11px] text-faint sm:grid-cols-[5rem_minmax(0,1fr)]">
                              <span>configure</span><code className="break-all text-muted">{meta.configure}</code>
                              <span>write</span><code className="break-all text-muted">{meta.write}</code>
                              <span>read</span><code className="break-all text-muted">{meta.read}</code>
                            </span>
                          </span>
                        </label>
                      )
                    })}
                  </fieldset>
                )
              }
              const { permission } = option
              const selected = permissionIds.has(permission.id)
              const assigned = assignedPermissionIds.has(permission.id)
              const roleState = assigned
                ? selected
                  ? { label: 'Назначена', tone: 'ok' as const }
                  : { label: 'Будет снята', tone: 'danger' as const }
                : selected
                  ? { label: 'Будет добавлена', tone: 'accent' as const }
                  : observedPermissionIds.has(permission.id)
                    ? { label: 'Выдана вне Grantor', tone: 'warn' as const }
                    : null

              return (
                <label
                  key={permission.id}
                  className={cn(
                    'flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 transition-colors',
                    selectionSurfaceClassName(selected),
                  )}
                >
                  <input
                    type="checkbox"
                    checked={selected}
                    disabled={
                      (!selected &&
                        (!permission.assignable || permissionIds.size >= MAX_BULK_ITEMS)) ||
                      (permission.dangerous && !isAdmin)
                    }
                    onChange={() => {
                      setPermissionIds((current) => {
                        const next = new Set(current)
                        if (next.has(permission.id)) next.delete(permission.id)
                        else next.add(permission.id)
                        return next
                      })
                      setDangerConfirmed(false)
                    }}
                    className="accent-accent"
                  />
                  <span className="min-w-0 flex-1">
                    {/* Нормализованная подпись (access-format); сырое имя — в
                        title, external id остаётся вторичной строкой. */}
                    <span
                      className="block truncate font-mono text-[13px] text-text"
                      title={permission.name}
                    >
                      {permissionNameLabel(permission, permission.name)}
                    </span>
                    <span className="block truncate font-mono text-[11px] text-faint">
                      {permission.external_id}
                    </span>
                  </span>
                  {roleState !== null && (
                    <StatusChip tone={roleState.tone}>{roleState.label}</StatusChip>
                  )}
                  {permission.dangerous && <ElevatedAccessDot />}
                </label>
              )
            })}
          </div>
        )}

        {dangerous && (
          <DangerConfirm
            title="Опасное право"
            label="Я понимаю, что выдаю опасное право"
            checked={dangerConfirmed}
            onChange={setDangerConfirmed}
            isAdmin={isAdmin}
          />
        )}

        {changeCount > 0 && (
          <OperationRehearsal
            title="Изменение ролей аккаунта"
            detail={`Изменится только выбранная дельта ролей аккаунта ${account.engine_identity}.`}
            danger={dangerous}
            impact={(
              <div className="grid gap-1 text-xs text-muted sm:grid-cols-2">
                <span>Аккаунт</span>
                <span className="break-all font-mono text-text">{account.engine_identity}</span>
                <span>Добавить</span>
                <span className="space-y-0.5">
                  {additions.length === 0
                    ? <span className="text-faint">—</span>
                    : additions.map((permission) => (
                      <span key={permission.id} className="block break-all font-mono text-text">
                        {permission.name}
                      </span>
                    ))}
                </span>
                <span>Снять</span>
                <span className="space-y-0.5">
                  {removedPermissions.length === 0
                    ? <span className="text-faint">—</span>
                    : removedPermissions.map((permission) => (
                      <span key={permission.id} className="block break-all font-mono text-text">
                        {permission.name}
                      </span>
                    ))}
                </span>
                {replacementPreviews.length > 0 && (
                  <>
                    <span>Атомарно заменить</span>
                    <span className="space-y-0.5">
                      {replacementPreviews.map((replacement) => (
                        <span key={replacement.key} className="block break-all font-mono text-text">
                          {replacement.from.name} → {replacement.to.name}
                        </span>
                      ))}
                    </span>
                  </>
                )}
              </div>
            )}
          />
        )}

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={close} disabled={manageMutation.isPending}>
            Отмена
          </Button>
          <Button disabled={!canSubmit} onClick={submit}>
            {manageMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Применить изменения
          </Button>
        </div>
      </div>
  )

  if (embedded) return open ? editor : null
  return (
    <Drawer open={open} onClose={close} closeOnOverlayClick={!manageMutation.isPending} title={`Управление ролями: ${account.engine_identity}`}>
      {editor}
    </Drawer>
  )
}

// ---------------------------------------------------------------------------
// Назначение групповой роли участникам: та же permission и тот же bulk-grant,
// что используются в остальных сценариях выдачи. Отличается только точка
// входа: оператор начинает с карточки роли, а не с карточки пользователя.

interface AssignSharedRoleDrawerProps {
  open: boolean
  roleAccount: Account
  permission: Permission
  principals: Principal[]
  onClose: () => void
  onStarted: (operationId: string, accountNames: string[]) => void
}

export function AssignSharedRoleDrawer({
  open,
  roleAccount,
  permission,
  principals,
  onClose,
  onStarted,
}: AssignSharedRoleDrawerProps) {
  const auth = useAuth()
  const isAdmin = roleAtLeast(auth.role, 'admin')
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [accountIds, setAccountIds] = useState<Set<string>>(new Set())
  const [dangerConfirmed, setDangerConfirmed] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const accountsQuery = useQuery({
    queryKey: qk.connectionAccounts(roleAccount.connection_id, 'summary'),
    queryFn: ({ signal }) =>
      apiList<Account>(
        `/api/v1/connections/${roleAccount.connection_id}/accounts?view=summary&include=bindings,provisioning`,
        'accounts',
        signal,
      ),
    enabled: open,
  })
  const principalById = useMemo(
    () => new Map(principals.map((principal) => [principal.id, principal])),
    [principals],
  )
  const candidates = useMemo(
    () =>
      (accountsQuery.data ?? [])
        .filter(
          (account) =>
            account.status === 'active' &&
            !isSharedRoleKind(account.kind) &&
            account.id !== roleAccount.id,
        )
        .map((account) => {
          const assigned = (account.bindings ?? []).some(
            (binding) =>
              binding.permission_definition_id === permission.id &&
              isAssignedManagedBinding(binding),
          )
          const principal =
            account.principal_id === null
              ? null
              : (principalById.get(account.principal_id) ?? null)
          return { account, assigned, principal }
        })
        .sort((left, right) => {
          const leftName = left.principal?.display_name ?? left.account.engine_identity
          const rightName = right.principal?.display_name ?? right.account.engine_identity
          return leftName.localeCompare(rightName, 'ru')
        }),
    [accountsQuery.data, permission.id, principalById, roleAccount.id],
  )
  const filtered = useMemo(() => {
    const query = search.trim().toLocaleLowerCase('ru')
    if (query === '') return candidates
    return candidates.filter(({ account, principal }) =>
      [account.engine_identity, principal?.display_name, principal?.external_subject]
        .filter((value): value is string => value !== undefined && value !== null)
        .some((value) => value.toLocaleLowerCase('ru').includes(query)),
    )
  }, [candidates, search])
  const selectedAccounts = useMemo(
    () =>
      candidates
        .filter(({ account, assigned }) => !assigned && accountIds.has(account.id))
        .map(({ account }) => account),
    [accountIds, candidates],
  )

  useEffect(() => {
    if (!open) return
    setSearch('')
    setAccountIds(new Set())
    setDangerConfirmed(false)
    setFormError(null)
  }, [open])

  const assignMutation = useMutation({
    mutationFn: (payload: BulkCreateBindingsRequest) =>
      apiPost<BulkCreateBindingsResponse>('/api/v1/bindings/bulk', payload),
    onSuccess: (data) => {
      void queryClient.invalidateQueries({
        queryKey: qk.connectionAccounts(roleAccount.connection_id),
      })
      void queryClient.invalidateQueries({ queryKey: qk.operations() })
      onStarted(
        data.operation_id,
        selectedAccounts.map((account) => account.engine_identity),
      )
    },
    onError: (error: unknown) => setFormError(errorMessage(error)),
  })

  const dangerousAllowed = !permission.dangerous || (isAdmin && dangerConfirmed)
  const canSubmit =
    selectedAccounts.length > 0 &&
    selectedAccounts.length <= MAX_BULK_ITEMS &&
    dangerousAllowed &&
    !assignMutation.isPending

  const submit = () => {
    if (!canSubmit) return
    const payload: BulkCreateBindingsRequest = {
      items: selectedAccounts.map((account) => ({
        account_id: account.id,
        permission_id: permission.id,
      })),
    }
    if (permission.dangerous) payload.confirm = true
    assignMutation.mutate(payload)
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={`Назначить роль: ${roleAccount.engine_identity}`}
    >
      <div className="space-y-4">
        <SearchInput
          value={search}
          onChange={setSearch}
          placeholder="Пользователь или аккаунт…"
          ariaLabel="Поиск пользователя или аккаунта"
        />

        {accountsQuery.isPending ? (
          <div className="flex items-center gap-2 text-sm text-muted">
            <Spinner className="size-3.5" />
            Загружаем аккаунты…
          </div>
        ) : accountsQuery.isError ? (
          <ErrorBanner>Не удалось загрузить аккаунты подключения.</ErrorBanner>
        ) : candidates.length === 0 ? (
          <div className="text-sm text-faint">
            В подключении пока нет аккаунтов, которым можно назначить эту роль.
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-sm text-faint">Ничего не найдено по «{search.trim()}».</div>
        ) : (
          <div className="max-h-[48vh] space-y-1 overflow-y-auto rounded-md border border-line p-1.5">
            {filtered.map(({ account, assigned, principal }) => {
              const selected = accountIds.has(account.id)
              return (
                <label
                  key={account.id}
                  className={cn(
                    'flex items-center gap-2.5 rounded-md px-2.5 py-2 transition-colors',
                    assigned ? 'cursor-default opacity-70' : 'cursor-pointer',
                    selectionSurfaceClassName(selected),
                  )}
                >
                  <input
                    type="checkbox"
                    checked={assigned || selected}
                    disabled={
                      assigned ||
                      (!selected && accountIds.size >= MAX_BULK_ITEMS)
                    }
                    onChange={() =>
                      setAccountIds((current) => {
                        const next = new Set(current)
                        if (next.has(account.id)) next.delete(account.id)
                        else next.add(account.id)
                        return next
                      })
                    }
                    className="accent-accent"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm text-text">
                      {principal?.display_name ?? account.engine_identity}
                    </span>
                    <span className="block truncate font-mono text-[11px] text-faint">
                      {principal === null
                        ? `Локальный аккаунт · ${account.engine_identity}`
                        : account.engine_identity}
                    </span>
                  </span>
                  {principal !== null && <PrincipalTypeChip type={principal.type} />}
                  {assigned && <StatusChip tone="ok">Назначена</StatusChip>}
                </label>
              )
            })}
          </div>
        )}

        {permission.dangerous && (
          <DangerConfirm
            title="Роль даёт широкие полномочия"
            label="Я подтверждаю назначение роли выбранным аккаунтам"
            checked={dangerConfirmed}
            onChange={setDangerConfirmed}
            isAdmin={isAdmin}
          />
        )}

        {selectedAccounts.length > 0 && (
          <OperationRehearsal
            title={`Назначение роли ${permission.name}`}
            detail={`Роль получат выбранные аккаунты: ${selectedAccounts.length}. Остальные назначения не изменятся.`}
            danger={permission.dangerous}
            impact={(
              <div className="grid gap-1 text-xs text-muted sm:grid-cols-2">
                <span>Роль</span>
                <span className="break-all font-mono text-text">{permission.name}</span>
                <span>Аккаунты</span>
                <span className="space-y-0.5">
                  {selectedAccounts.map((account) => (
                    <span key={account.id} className="block break-all font-mono text-text">
                      {account.engine_identity}
                    </span>
                  ))}
                </span>
              </div>
            )}
          />
        )}

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose} disabled={assignMutation.isPending}>
            Отмена
          </Button>
          <Button disabled={!canSubmit} onClick={submit}>
            {assignMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Назначить роль
          </Button>
        </div>
      </div>
    </Drawer>
  )
}

// ---------------------------------------------------------------------------
// Привязка аккаунта к пользователю: metadata-only /link не меняет target;
// /link-and-manage асинхронно переводит аккаунт на общий credential принципала
// в окружении; ownership изменится только после успешной worker-операции.

export type LinkPrincipalMode = 'record' | 'managed'

interface LinkPrincipalDialogProps {
  open: boolean
  account: Account
  connection: Connection
  /** Для уже связанного аккаунта principal и managed-режим фиксированы. */
  lockedPrincipalId?: string | null
  initialMode?: LinkPrincipalMode
  onClose: () => void
  onLinked: (
    principalName: string,
    mode: LinkPrincipalMode,
    operationId?: string,
  ) => void
}

export function LinkPrincipalDialog({
  open,
  account,
  connection,
  lockedPrincipalId = null,
  initialMode = 'record',
  onClose,
  onLinked,
}: LinkPrincipalDialogProps) {
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [principalId, setPrincipalId] = useState<string | null>(null)
  const [mode, setMode] = useState<LinkPrincipalMode>('record')
  const [credentialMode, setCredentialMode] = useState<'generated' | 'provided'>('generated')
  const [password, setPassword] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  // Сброс поиска и выбора при каждом открытии диалога.
  useEffect(() => {
    if (open) {
      setSearch('')
      setPrincipalId(lockedPrincipalId)
      setMode(initialMode)
      setCredentialMode('generated')
      setPassword('')
      setFormError(null)
    }
  }, [initialMode, lockedPrincipalId, open])

  const principalsQuery = useQuery({
    queryKey: qk.principals(),
    queryFn: ({ signal }) =>
      apiList<Principal>('/api/v1/principals', 'principals', signal),
    enabled: open,
  })

  const principals = principalsQuery.data ?? []
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (q === '') {
      return principals
    }
    return principals.filter(
      (p) =>
        p.display_name.toLowerCase().includes(q) ||
        p.external_subject.toLowerCase().includes(q),
    )
  }, [principals, search])

  const selected = principals.find((p) => p.id === principalId) ?? null
  const supportsManagedLink =
    account.status === 'active' &&
    account.kind === 'login' &&
    supportsManagedCredentialLink(connection)

  const credentialEnvironmentsQuery = useQuery({
    queryKey: qk.principalCredentials(principalId ?? ''),
    queryFn: ({ signal }) =>
      apiList<PrincipalCredentialEnvironment>(
        `/api/v1/principals/${principalId}/credentials`,
        'credentials',
        signal,
      ),
    enabled: open && mode === 'managed' && principalId !== null,
  })
  const targetEnvironment = environmentLabel(connection)
  // configured=null («неизвестно») трактуется как не настроенный: создание
  // идемпотентно (Ensure), поэтому лишний запрос безопасен, а пропуск — нет.
  const sharedCredentialConfigured =
    credentialEnvironmentsQuery.data?.some(
      (item) => item.environment === targetEnvironment && item.configured === true,
    ) === true
  const managedContextPending =
    mode === 'managed' &&
    principalId !== null &&
    credentialEnvironmentsQuery.isPending

  const linkMutation = useMutation<
    Account | LinkAndManageAccountResponse,
    unknown,
    {
      mode: LinkPrincipalMode
      payload: LinkAccountRequest | LinkAndManageAccountRequest
    }
  >({
    mutationFn: ({
      mode: selectedMode,
      payload,
    }) =>
      selectedMode === 'managed'
        ? apiPost<LinkAndManageAccountResponse>(
            `/api/v1/accounts/${account.id}/link-and-manage`,
            payload,
          )
        : apiPost<Account>(`/api/v1/accounts/${account.id}/link`, payload),
    onSuccess: (data, variables) => {
      setPassword('')
      setFormError(null)
      const operationId =
        variables.mode === 'managed' && 'operation_id' in data
          ? data.operation_id
          : undefined
      onLinked(selected?.display_name ?? '', variables.mode, operationId)
      void queryClient.invalidateQueries({ queryKey: qk.accounts() })
      void queryClient.invalidateQueries({ queryKey: qk.connectionAccounts(account.connection_id) })
      void queryClient.invalidateQueries({ queryKey: qk.principals() })
      void queryClient.invalidateQueries({ queryKey: qk.principal(selected?.id ?? '') })
      if (variables.mode === 'managed') {
        void queryClient.invalidateQueries({ queryKey: qk.operations() })
      }
    },
    onError: (err: unknown) => {
      setPassword('')
      setFormError(errorMessage(err))
    },
  })

  const linkDisabled =
    selected === null ||
    linkMutation.isPending ||
    managedContextPending ||
    (mode === 'managed' && credentialEnvironmentsQuery.isError) ||
    (mode === 'managed' &&
      !sharedCredentialConfigured &&
      credentialMode === 'provided' &&
      (password.length < 12 || password.length > 256))

  const submitLink = () => {
    if (selected === null) return

    const managedPayload: LinkAndManageAccountRequest = {
      principal_id: selected.id,
      ...(sharedCredentialConfigured
        ? {}
        : {
            credential: {
              mode: credentialMode,
              ...(credentialMode === 'provided' ? { password } : {}),
            },
          }),
    }
    setPassword('')
    linkMutation.mutate({
      mode,
      payload:
        mode === 'managed'
          ? managedPayload
          : { principal_id: selected.id },
    })
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Связать аккаунт: ${account.engine_identity}`}
      footer={
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={linkMutation.isPending}>
            Отмена
          </Button>
          <Button disabled={linkDisabled} onClick={submitLink}>
            {linkMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            {mode === 'managed' ? 'Связать и управлять' : 'Связать для учёта'}
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {lockedPrincipalId === null && (
          <SearchInput
            value={search}
            onChange={setSearch}
            placeholder="Поиск пользователя…"
            ariaLabel="Поиск пользователя"
          />
        )}

        {principalsQuery.isError ? (
          <div className="text-sm text-danger">
            {errorMessage(principalsQuery.error)}
          </div>
        ) : principalsQuery.isPending ? (
          <div className="flex justify-center py-4">
            <Spinner />
          </div>
        ) : principals.length === 0 ? (
          <div className="text-sm text-faint">Пользователей пока нет.</div>
        ) : lockedPrincipalId !== null && selected !== null ? (
          <div className="flex items-center gap-2.5 rounded-md border border-line bg-panel2/50 px-3 py-2">
            <span className="min-w-0 flex-1">
              <span className="block truncate font-mono text-sm text-text">
                {selected.display_name}
              </span>
              {selected.external_subject !== '' && (
                <span className="block truncate font-mono text-[11px] text-faint">
                  {selected.external_subject}
                </span>
              )}
            </span>
            <PrincipalTypeChip type={selected.type} />
          </div>
        ) : filtered.length === 0 ? (
          <div className="text-sm text-faint">Ничего не найдено по «{search.trim()}».</div>
        ) : (
          <div
            role="radiogroup"
            aria-label="Пользователь"
            className="space-y-1 rounded-md border border-line p-1.5"
          >
            {filtered.map((principal) => (
              <label
                key={principal.id}
                className={cn(
                  'flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-1.5 transition-colors',
                  selectionSurfaceClassName(principalId === principal.id),
                )}
              >
                <input
                  type="radio"
                  name="link-principal"
                  checked={principalId === principal.id}
                  onChange={() => setPrincipalId(principal.id)}
                  className="accent-accent"
                />
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm text-text">
                    {principal.display_name}
                  </span>
                  {principal.external_subject !== '' && (
                    <span className="block truncate font-mono text-[11px] text-faint">
                      {principal.external_subject}
                    </span>
                  )}
                </span>
                <PrincipalTypeChip type={principal.type} />
                {principal.status === 'disabled' && (
                  <StatusChip tone="unmg">{inventoryStatusLabel('disabled')}</StatusChip>
                )}
              </label>
            ))}
          </div>
        )}

        {lockedPrincipalId === null && (
          <div className="text-xs text-faint">
            Нет подходящего?{' '}
            <Link
              to="/principals"
              className="text-accent transition-opacity hover:opacity-80"
            >
              Создать пользователя можно в разделе «Пользователи»
            </Link>
            .
          </div>
        )}

        {lockedPrincipalId === null ? (
          <div className="space-y-1.5">
            <RadioOptionCard
              name="link-account-mode"
              label="Связать для учёта"
              hint="Только привязка в Grantor: пароль аккаунта и целевая система не меняются."
              checked={mode === 'record'}
              onSelect={() => setMode('record')}
            />
            {supportsManagedLink && (
              <RadioOptionCard
                name="link-account-mode"
                label="Связать и управлять"
                hint="Grantor применит общий credential пользователя для окружения подключения; если его ещё нет, создаст при этой операции."
                checked={mode === 'managed'}
                onSelect={() => setMode('managed')}
              />
            )}
          </div>
        ) : (
          <div className="rounded-md border border-line bg-panel2/50 px-3 py-2 text-xs text-muted">
            Grantor применит общий credential пользователя для окружения подключения.
          </div>
        )}

        {mode === 'managed' && selected !== null && (
          <div className="space-y-2 rounded-md border border-line bg-panel2/50 p-3">
            <div className="text-xs font-medium text-muted">
              Credential окружения {targetEnvironment}
            </div>
            {managedContextPending ? (
              <div className="flex items-center gap-2 text-xs text-muted">
                <Spinner className="size-3.5" />
                Проверяем общий credential…
              </div>
            ) : credentialEnvironmentsQuery.isError ? (
              <div className="text-xs text-danger">
                Не удалось проверить credential окружения. Повторите позже.
              </div>
            ) : sharedCredentialConfigured ? (
              <div className="text-xs text-muted">
                Общий credential уже настроен и будет переиспользован. Пароль не
                запрашивается и не меняется.
              </div>
            ) : (
              <>
                <RadioOptionCard
                  name="managed-link-credential-mode"
                  label="Сгенерировать"
                  hint="Grantor создаст первый общий пароль пользователя в этом окружении."
                  checked={credentialMode === 'generated'}
                  onSelect={() => {
                    setCredentialMode('generated')
                    setPassword('')
                  }}
                />
                <RadioOptionCard
                  name="managed-link-credential-mode"
                  label="Задать пароль"
                  hint="Пароль уйдёт в Vault и target, но не будет сохранён или показан в UI."
                  checked={credentialMode === 'provided'}
                  onSelect={() => setCredentialMode('provided')}
                />
                {credentialMode === 'provided' && (
                  <Field label="Пароль" hint="От 12 до 256 символов" htmlFor="managed-link-password">
                    <Input
                      id="managed-link-password"
                      type="password"
                      value={password}
                      minLength={12}
                      maxLength={256}
                      autoComplete="new-password"
                      onChange={(event) => setPassword(event.target.value)}
                      required
                    />
                  </Field>
                )}
              </>
            )}
          </div>
        )}

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}
      </div>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Принятие unmanaged-аккаунта под управление:
// POST /api/v1/accounts/{id}/adopt (operator+). Режим metadata — только
// метаданные grantor (200, немедленно); generate — grantor сам генерирует
// НОВЫЙ пароль и применяет его через операцию credential.rotate (202);
// set_password — заданный оператором НОВЫЙ пароль применяется к учётке той же
// операцией (202); verify_password — оператор подтверждает СУЩЕСТВУЮЩИЙ
// пароль, операция account.adopt_verify только доказывает его на целевой
// системе и ничего в ней не меняет (202).
//
// Подписи режимов обязаны различать «задать новый» и «подтвердить текущий»:
// это разные намерения с противоположными последствиями для приложения,
// которое пользуется учёткой. Единственный режим verify_password доступен не
// везде: нужен движок с проверкой пароля; connector должен поддерживать
// credential proof v1. Проверка всегда выполняется в сегменте подключения.

/** Итог adopt для вызывающего: 200-путь без операции либо 202 с операцией. */
export interface AdoptAccountResult {
  /**
   * id операции (все режимы, кроме metadata); null — принято немедленно
   * (mode=metadata).
   */
  operationId: string | null
  adoptedBindings: number
}

interface AdoptAccountDialogProps {
  readOnlyBindingsCount?: number
  directBindingsCount?: number
  dangerousDirectBindingsCount?: number
  open: boolean
  account: Account
  /**
   * Unmanaged bindings аккаунта (desired_state === null): чекбокс «Взять под
   * управление текущие права» и список их чипов. Пустой массив — чекбокс
   * заблокирован, чипы не показываются.
   */
  unmanagedBindings: Binding[]
  /** Каталог permissions подключения — для подписи чипов unmanaged прав. */
  permissionsById: Map<string, Permission>
  onClose: () => void
  onAdopted: (result: AdoptAccountResult) => void
}

export function AdoptAccountDialog({
  readOnlyBindingsCount = 0,
  directBindingsCount = 0,
  dangerousDirectBindingsCount = 0,
  open,
  account,
  unmanagedBindings,
  permissionsById,
  onClose,
  onAdopted,
}: AdoptAccountDialogProps) {
  // Общая роль (group/role) до панели adopt не доходит: бэкенд отвечает 409,
  // а UI не показывает действие. Флаг оставлен для веток, которые ещё
  // различают заголовки и текст роли и аккаунта.
  const sharedRole = isSharedRoleKind(account.kind)
  const [mode, setMode] = useState<AdoptAccountRequest['mode']>('metadata')
  const [password, setPassword] = useState('')
  const [adoptBindings, setAdoptBindings] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Сброс формы при каждом открытии диалога.
  useEffect(() => {
    if (open) {
      setMode('metadata')
      setPassword('')
      setAdoptBindings(false)
      setFormError(null)
    }
  }, [open])

  const unmanagedBindingsCount = unmanagedBindings.length + directBindingsCount
  // Чипы unmanaged прав: нормализация как в BindingsSection (движок из
  // permission, scope не резолвится — карта ресурсов сюда не проброшена),
  // дубли одинаковых подписей схлопываются как в колонке «Доступ».
  const unmanagedEntries = useMemo<AccessEntry[]>(() => {
    const byFull = new Map<string, AccessEntry>()
    for (const binding of unmanagedBindings) {
      const permission = permissionsById.get(binding.permission_definition_id)
      const entry = permissionAccessEntry(
        permission,
        shortId(binding.permission_definition_id),
      )
      const existing = byFull.get(entry.full)
      if (existing === undefined) {
        byFull.set(entry.full, entry)
      } else {
        // dangerous — липкий для одинаковой подписи.
        existing.dangerous = existing.dangerous || entry.dangerous
      }
    }
    return [...byFull.values()]
  }, [unmanagedBindings, permissionsById])

  const adoptMutation = useMutation({
    mutationFn: async (payload: AdoptAccountRequest): Promise<AdoptAccountResult> => {
      const url = `/api/v1/accounts/${account.id}/adopt`
      if (payload.mode === 'metadata') {
        const res = await apiPost<AdoptAccountMetadataResponse>(url, payload)
        return { operationId: null, adoptedBindings: res.adopted_bindings }
      }
      const res = await apiPost<AdoptAccountOperationResponse>(url, payload)
      return { operationId: res.operation_id, adoptedBindings: res.adopted_bindings }
    },
    onSuccess: (result) => {
      setFormError(null)
      onAdopted(result)
    },
    onError: (err: unknown) => {
      setFormError(errorMessage(err))
    },
  })

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (sharedRole) {
      adoptMutation.mutate({ mode: 'metadata', adopt_bindings: adoptBindings })
      return
    }
    let payload: AdoptAccountRequest
    switch (mode) {
      case 'metadata':
        payload = { mode: 'metadata', adopt_bindings: adoptBindings }
        break
      case 'generate':
        payload = { mode: 'generate', adopt_bindings: adoptBindings }
        break
      case 'verify_password':
        payload = { mode: 'verify_password', password, adopt_bindings: adoptBindings }
        break
      default:
        payload = { mode: 'set_password', password, adopt_bindings: adoptBindings }
    }
    adoptMutation.mutate(payload)
  }

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`${sharedRole ? 'Взять роль под управление' : 'Взять под управление'}: ${account.engine_identity}`}
    >
      <form onSubmit={submit} className="space-y-4" autoComplete="off">
        {!sharedRole && (
          <>
            <div className="rounded-md border border-line bg-panel2/50 p-3 text-sm text-muted">
              Текущий пароль нельзя прочитать: движки хранят только его хэш. Выберите, что
              сделать с паролем учётки: оставить как есть, подтвердить известный вам или
              заменить новым.
            </div>

            <div className="space-y-1.5">
              <RadioOptionCard
                name="adopt-mode"
                label="Принять без пароля"
                hint="Пароль учётки не меняется, но и не попадает в Grantor. Аккаунт станет Managed сразу; credentials появятся после первой ротации."
                checked={mode === 'metadata'}
                onSelect={() => setMode('metadata')}
              />
              <RadioOptionCard
                name="adopt-mode"
                label="Подтвердить текущий пароль"
                hint="Пароль учётки НЕ меняется. Grantor проверит его на целевой системе и сохранит только после успешной проверки; при неверном пароле операция завершится ошибкой, а учётка останется нетронутой."
                checked={mode === 'verify_password'}
                onSelect={() => setMode('verify_password')}
              />
              <RadioOptionCard
                name="adopt-mode"
                label="Задать новый пароль"
                hint="Пароль учётки будет ЗАМЕНЁН на введённый: прежний перестанет работать, и приложения с ним потеряют доступ. Введённый пароль не будет показан повторно."
                checked={mode === 'set_password'}
                onSelect={() => setMode('set_password')}
              />
              <RadioOptionCard
                name="adopt-mode"
                label="Сгенерировать новый пароль"
                hint="Пароль учётки будет ЗАМЕНЁН сгенерированным: прежний перестанет работать. Получить новый можно будет через одноразовую ссылку."
                checked={mode === 'generate'}
                onSelect={() => setMode('generate')}
              />
            </div>

            <OperationRehearsal
              title={`Принятие ${sharedRole ? 'роли' : 'аккаунта'} ${account.engine_identity} под управление`}
              detail={
                sharedRole
                  ? 'Grantor начнёт управлять ролью. Текущие назначения не изменятся.'
                  : mode === 'metadata'
                  ? 'Grantor начнёт управлять аккаунтом без смены текущего пароля.'
                  : mode === 'verify_password'
                    ? 'Grantor проверит указанный пароль на целевой системе и сохранит его только после успешной проверки. Пароль учётки не меняется.'
                    : mode === 'generate'
                      ? 'Grantor создаст новый пароль и применит его в целевой системе.'
                      : 'Grantor применит указанный пароль в целевой системе вместо текущего.'
              }
              impact={(
                <div className="grid gap-1 text-xs text-muted sm:grid-cols-2">
                  <span>Аккаунт</span>
                  <span className="break-all font-mono text-text">{account.engine_identity}</span>
                  <span>Текущие права</span>
                  <span className="text-text">
                    {adoptBindings ? `Будут приняты: ${unmanagedBindingsCount}` : 'Не изменятся'}
                  </span>
                </div>
              )}
            />
          </>
        )}

        {!sharedRole && (mode === 'set_password' || mode === 'verify_password') && (
          <Field
            label={mode === 'verify_password' ? 'Текущий пароль учётки' : 'Новый пароль'}
          >
            <Input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="off"
              required
            />
          </Field>
        )}

        <div className="space-y-1.5">
          <label
            title={`У аккаунта есть ${unmanagedBindingsCount} прав, обнаруженных в кластере, но пока не под управлением Grantor. Отметьте, чтобы Grantor начал отслеживать изменения, отзывать права и включать их в манифест.`}
            className={cn(
              'flex items-start gap-2 text-sm',
              unmanagedBindingsCount > 0
                ? 'cursor-pointer text-text'
                : 'cursor-not-allowed text-faint',
            )}
          >
            <input
              type="checkbox"
              checked={adoptBindings}
              disabled={unmanagedBindingsCount === 0}
              onChange={(e) => setAdoptBindings(e.target.checked)}
              className="mt-0.5 accent-accent"
            />
            Взять под управление текущие права ({unmanagedBindingsCount})
          </label>
          {readOnlyBindingsCount > 0 && <p className="pl-6 text-xs text-muted">Права, доступные только для просмотра ({readOnlyBindingsCount}), останутся вне управления.</p>}
          {directBindingsCount > 0 && <p className="pl-6 text-xs text-muted">Также будут приняты прямые grants: {directBindingsCount}. Расширенные полномочия среди них: {dangerousDirectBindingsCount}.</p>}
          {unmanagedEntries.length > 0 && (
            <AccessChipList entries={unmanagedEntries} maxVisible={3} className="pl-6" />
          )}
        </div>

        {formError !== null && <ErrorBanner>{formError}</ErrorBanner>}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="outline" onClick={onClose} disabled={adoptMutation.isPending}>
            Отмена
          </Button>
          <Button
            type="submit"
            disabled={
              adoptMutation.isPending ||
              (!sharedRole && (mode === 'set_password' || mode === 'verify_password') && password === '')
            }
          >
            {adoptMutation.isPending && <Spinner className="size-3.5 text-accent-ink" />}
            Взять под управление
          </Button>
        </div>
      </form>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Удаление аккаунта: danger-диалог с type-to-confirm (admin).

interface DeleteAccountDialogProps {
  open: boolean
  account: Account
  pending: boolean
  impact?: ReactNode
  /** reason — необязательная причина удаления; пустая строка = без причины. */
  onConfirm: (reason: string) => void
  onClose: () => void
}

/** Предел длины причины удаления в символах — совпадает с бэкендом. */
const DELETE_REASON_MAX_LEN = 500

export function DeleteAccountDialog({
  open,
  account,
  pending,
  impact,
  onConfirm,
  onClose,
}: DeleteAccountDialogProps) {
  const [typed, setTyped] = useState('')
  const [reason, setReason] = useState('')

  // Поля подтверждения и причины очищаются при каждом открытии.
  useEffect(() => {
    if (open) {
      setTyped('')
      setReason('')
    }
  }, [open])

  const match = typed === account.engine_identity

  return (
    <Dialog open={open} onClose={onClose} title="Удалить аккаунт">
      <div className="space-y-4">
        <ErrorBanner>
          Операция необратима: учётная запись будет удалена в целевой системе.
        </ErrorBanner>
        <OperationRehearsal
          title={`Удаление аккаунта ${account.engine_identity}`}
          detail="Аккаунт будет удалён в целевой системе. Запись останется в Grantor для аудита и возможного восстановления."
          danger
          impact={impact}
        />
        <Field
          label={`Введите ${account.engine_identity} для подтверждения`}
          hint="точный логин аккаунта в подключении"
        >
          <Input
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={account.engine_identity}
            className="font-mono text-[13px]"
            autoComplete="off"
          />
        </Field>
        <Field
          label="Причина (необязательно)"
          hint="сохранится на записи удалённого аккаунта и в аудите"
        >
          <Input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="например: сотрудник покинул команду"
            maxLength={DELETE_REASON_MAX_LEN}
            autoComplete="off"
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button variant="outline" onClick={onClose} disabled={pending}>
            Отмена
          </Button>
          <Button
            variant="danger"
            disabled={!match || pending}
            onClick={() => onConfirm(reason)}
          >
            {pending && <Spinner className="size-3.5" />}
            Удалить аккаунт
          </Button>
        </div>
      </div>
    </Dialog>
  )
}

// Одноразовая ссылка на креды аккаунта (POST /api/v1/accounts/{id}/share)
// показывается общим ShareLinkDialog (components/ui/share-link-dialog).
