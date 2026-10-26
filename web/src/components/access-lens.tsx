import { useMemo } from 'react'
import type { CSSProperties, ReactNode } from 'react'
import {
  Bot,
  Database,
  FolderTree,
  KeyRound,
  Link2,
  UserRound,
  Waypoints,
} from '@project/ui/icons'
import { activeAccessBindings } from '../lib/active-access'
import { isPostgresObjectPrivilege } from '../lib/postgres-object-acl'
import { shortId } from '../lib/status'
import type { Account, Binding, Connection, Permission, Principal, Resource } from '../lib/types'
import { ElevatedAccessDot } from './ui/access-chips'
import { DetailDisclosure, Spinner } from '@project/ui'

export interface AccessLensRole {
  id: string
  name: string
  dangerous: boolean
  scopes: string[]
  sources: string[]
}

export interface AccessLensModel {
  directObjects?: number
  roles: AccessLensRole[]
  scopes: AccessLensScope[]
}

export interface AccessLensScope {
  id: string | null
  label: string
}

function resourceLabel(resource: Resource | undefined, fallbackId: string): string {
  if (resource === undefined) return shortId(fallbackId)
  return resource.canonical_path !== '' ? resource.canonical_path : resource.name
}

/**
 * Строит effective access chain из текущих bindings. Одна и та же роль,
 * выданная на несколько scope, остаётся одним узлом с несколькими ресурсами.
 */
export function buildAccessLensModel(
  bindings: readonly Binding[],
  permissionsById: ReadonlyMap<string, Permission>,
  resourcesById: ReadonlyMap<string, Resource>,
): AccessLensModel {
  const rolesById = new Map<
    string,
    { id: string; name: string; dangerous: boolean; scopes: Set<string>; sources: Set<string> }
  >()
  const allScopes = new Map<string, AccessLensScope>()
  const directScopes = new Set<string>()

  for (const binding of activeAccessBindings([...bindings])) {
    const permission = permissionsById.get(binding.permission_definition_id)
    const roleId = permission?.id ?? binding.permission_definition_id
    const scopeId = binding.scope_resource_id ?? permission?.scope_resource_id ?? null
    const scope = scopeId === null
      ? 'Всё подключение'
      : resourceLabel(resourcesById.get(scopeId), scopeId)
    if (isPostgresObjectPrivilege(permission)) {
      directScopes.add(scopeId ?? binding.permission_definition_id)
      allScopes.set(scopeId ?? binding.permission_definition_id, { id: scopeId, label: scope })
      continue
    }
    const current = rolesById.get(roleId) ?? {
      id: roleId,
      name: permission?.name ?? shortId(binding.permission_definition_id),
      dangerous: permission?.dangerous ?? false,
      scopes: new Set<string>(),
      sources: new Set<string>(),
    }
    current.dangerous = current.dangerous || (permission?.dangerous ?? false)
    current.scopes.add(scope)
    if (binding.source !== '') current.sources.add(binding.source)
    rolesById.set(roleId, current)
    allScopes.set(scopeId ?? '__connection__', { id: scopeId, label: scope })
  }

  return {
    ...(directScopes.size > 0 ? { directObjects: directScopes.size } : {}),
    roles: [...rolesById.values()]
      .map((role) => ({
        ...role,
        scopes: [...role.scopes].sort((a, b) => a.localeCompare(b)),
        sources: [...role.sources].sort((a, b) => a.localeCompare(b)),
      }))
      .sort((a, b) => a.name.localeCompare(b.name)),
    scopes: [...allScopes.values()].sort((a, b) => a.label.localeCompare(b.label)),
  }
}

function plural(count: number, forms: [string, string, string]): string {
  const mod100 = count % 100
  const mod10 = count % 10
  if (mod100 >= 11 && mod100 <= 19) return `${count} ${forms[2]}`
  if (mod10 === 1) return `${count} ${forms[0]}`
  if (mod10 >= 2 && mod10 <= 4) return `${count} ${forms[1]}`
  return `${count} ${forms[2]}`
}

function LensStep({
  icon,
  label,
  children,
  last = false,
  step = 0,
}: {
  icon: ReactNode
  label: string
  children: ReactNode
  last?: boolean
  step?: number
}) {
  return (
    <div
      data-access-lens-step
      className="relative grid grid-cols-[28px_minmax(0,1fr)] gap-2.5 pb-3 last:pb-0"
      style={{ '--lens-step': step } as CSSProperties}
    >
      {!last && (
        <span
          className="absolute bottom-0 left-[13px] top-7 w-px bg-line"
          aria-hidden="true"
        />
      )}
      <span className="relative z-[1] grid size-7 place-items-center rounded-full border border-line bg-panel text-muted">
        {icon}
      </span>
      <div className="min-w-0 pt-0.5">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-faint">
          {label}
        </div>
        <div className="mt-1 min-w-0 text-[12px] text-text">{children}</div>
      </div>
    </div>
  )
}

export interface AccessLensProps {
  account: Account
  connection: Connection
  principal: Principal | null
  bindings: Binding[] | undefined
  permissionsById: ReadonlyMap<string, Permission>
  resourcesById: ReadonlyMap<string, Resource>
  pending?: boolean
  error?: boolean
}

/**
 * Компактная on-demand цепочка: в покое занимает одну строку, подробности
 * раскрываются внутри уже открытой панели аккаунта.
 */
export function AccessLens({
  account,
  connection,
  principal,
  bindings,
  permissionsById,
  resourcesById,
  pending = false,
  error = false,
}: AccessLensProps) {
  const model = useMemo(
    () => buildAccessLensModel(bindings ?? [], permissionsById, resourcesById),
    [bindings, permissionsById, resourcesById],
  )
  const principalName =
    principal === null || principal === undefined
      ? 'Без глобального пользователя'
      : principal.display_name

  return (
    <DetailDisclosure
      label="Цепочка доступа"
      icon={<Waypoints className="size-4" />}
      disabled={pending || error}
      summary={
        pending ? (
          <span className="flex min-w-0 items-center gap-2 text-xs text-muted">
            <Spinner className="size-3.5" />
            Собираем цепочку доступа…
          </span>
        ) : error ? (
          <span className="block min-w-0 text-xs text-danger">
            Не удалось загрузить связи
          </span>
        ) : (
          <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-1 text-xs">
            <span className="max-w-full truncate font-medium text-text">{principalName}</span>
            <span className="text-faint" aria-hidden="true">→</span>
            <span className="max-w-full truncate font-mono text-text">{account.engine_identity}</span>
            <span className="text-faint" aria-hidden="true">→</span>
            <span className="text-muted">
              {plural(model.roles.length, ['роль', 'роли', 'ролей'])}
            </span>
            {model.directObjects !== undefined && <span className="text-muted">· {model.directObjects} прямых объектов</span>}
            <span className="text-faint" aria-hidden="true">→</span>
            <span className="text-muted">
              {plural(model.scopes.length, ['ресурс', 'ресурса', 'ресурсов'])}
            </span>
          </span>
        )
      }
    >
      <LensStep
        step={0}
        label="Пользователь"
        icon={principal?.type === 'service'
          ? <Bot className="size-3.5" aria-hidden="true" />
          : <UserRound className="size-3.5" aria-hidden="true" />}
      >
        <span className="break-words">{principalName}</span>
      </LensStep>
      <LensStep
        step={1}
        label="Аккаунт"
        icon={<Database className="size-3.5" aria-hidden="true" />}
      >
        <span className="break-all font-mono">{account.engine_identity}</span>
        <span className="mt-0.5 block text-[11px] text-faint">
          {connection.display_name} · {connection.environment}
        </span>
      </LensStep>
      <LensStep
        step={2}
        label="Роли"
        icon={<KeyRound className="size-3.5" aria-hidden="true" />}
      >
        {model.roles.length === 0 ? (
          <span className="text-faint">Нет действующих ролей</span>
        ) : (
          <div className="flex flex-wrap gap-1.5">
            {model.roles.map((role) => (
              <span
                key={role.id}
                className="inline-flex min-w-0 items-center gap-1 rounded border border-line bg-panel px-1.5 py-0.5 font-mono text-[11px]"
                title={role.sources.length > 0
                  ? `Источник: ${role.sources.join(', ')}`
                  : undefined}
              >
                {role.dangerous && <ElevatedAccessDot />}
                <span className="max-w-full break-all">{role.name}</span>
              </span>
            ))}
          </div>
        )}
      </LensStep>
      <LensStep
        step={3}
        label="Ресурсы"
        icon={<FolderTree className="size-3.5" aria-hidden="true" />}
        last
      >
        {model.directObjects !== undefined && <p className="mb-1 text-xs text-muted">Прямые grants на {model.directObjects} объектов. Назначения ролей показаны отдельно.</p>}
        {model.scopes.length === 0 ? (
          <span className="text-faint">Ресурсы не затронуты</span>
        ) : (
          <div className="space-y-1">
            {model.scopes.map((scope) => (
              <div
                key={scope.id ?? '__connection__'}
                className="flex min-w-0 items-start gap-1.5 px-1 py-0.5"
              >
                <Link2 className="mt-0.5 size-3 shrink-0 text-faint" aria-hidden="true" />
                <span className="min-w-0 flex-1 break-all font-mono text-[11px]">
                  {scope.label}
                </span>
              </div>
            ))}
          </div>
        )}
      </LensStep>
    </DetailDisclosure>
  )
}

export function AccessImpactPreview({
  model,
  roleName,
  accountName,
}: {
  model: AccessLensModel
  roleName?: string
  accountName?: string
}) {
  return (
    <div className="mt-3 rounded-md border border-line bg-panel2/35 px-3 py-2.5 text-left">
      <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-faint">
        Будет изменено
      </div>
      <div className="space-y-1 text-xs text-text">
        {accountName !== undefined && (
          <div><span className="text-faint">Аккаунт:</span> <span className="font-mono">{accountName}</span></div>
        )}
        {roleName !== undefined ? (
          <div><span className="text-faint">Роль:</span> <span className="font-mono">{roleName}</span></div>
        ) : (
          <div><span className="text-faint">Роли:</span> {model.roles.length}</div>
        )}
        <div><span className="text-faint">Области доступа:</span> {model.scopes.length}</div>
      </div>
    </div>
  )
}
