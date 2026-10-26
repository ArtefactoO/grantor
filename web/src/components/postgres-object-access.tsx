import { useEffect, useId, useMemo, useState } from 'react'
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button, Drawer, ErrorBanner, Field, SearchInput, Spinner } from '@project/ui'
import { ChevronRight } from '@project/ui/icons'
import { roleAtLeast, useAuth } from '../auth/AuthProvider'
import { api, apiPost, ApiError } from '../lib/api'
import { qk } from '../lib/queryKeys'
import { errorMessage } from '../lib/errorMessage'
import { accountDirectObjectCount, bindingManagementEligible, directObjectSummary, objectACLIncomplete, objectRecord } from '../lib/postgres-object-acl'
import type { ObjectPrivilegeGroup } from '../lib/postgres-object-acl'
import type { Account, Binding, Connection, ManageAccountRolesResponse, Permission, Resource } from '../lib/types'

interface Props {
  expandRequest?: number
  pending?: boolean
  error?: boolean
  account: Account
  connection: Connection
  permissions: Permission[]
  bindings: Binding[]
  resourcesById: Map<string, Resource>
  onStarted: (operationId: string, label: string) => void
}

interface GroupResponse extends Omit<ObjectPrivilegeGroup, 'scopeId'> { scope_id: string }
interface ObjectPage {
  objects: GroupResponse[]
  total_entries: number
  next_cursor: string
  snapshot_version: string
  available: boolean
}
interface DefaultPage {
  rules: { database: string; creator: string; schema: string; kind: string; grantee: string; privilege: string; grant_option: boolean }[]
  total_entries: number | null
  next_cursor: string
  snapshot_version: string
  available: boolean
}
interface TargetPage {
  objects: { scope_id: string; resource: string; kind: string; owner: string }[]
  next_cursor: string
}

function present(binding: Binding): boolean { return binding.observed_state === 'present' }
function toGroup(group: GroupResponse): ObjectPrivilegeGroup { return { ...group, scopeId: group.scope_id } }
function useDebouncedQuery(value: string): string {
  const [query, setQuery] = useState(value)
  useEffect(() => { const timer = setTimeout(() => setQuery(value), 250); return () => clearTimeout(timer) }, [value])
  return query
}

export function PostgresObjectAccess({ account, connection, permissions, bindings, onStarted, expandRequest = 0 }: Props) {
  const auth = useAuth()
  const client = useQueryClient()
  const [query, setQuery] = useState('')
  const search = useDebouncedQuery(query)
  const [editing, setEditing] = useState<ObjectPrivilegeGroup | null>(null)
  const [creating, setCreating] = useState(false)
  const [expanded, setExpanded] = useState(false)
  useEffect(() => { if (expandRequest > 0) setExpanded(true) }, [expandRequest])
  const byId = useMemo(() => new Map(permissions.map(p => [p.id, p])), [permissions])
  const topology = objectRecord(connection.topology)
  const templates = objectRecord(connection.discovery_config).postgres_role_policy_templates
  const policyRole = Array.isArray(templates) && templates.some(t => objectRecord(t).role_name === account.engine_identity)
  const pageKey = qk.accountObjectPrivileges(account.id, search)
  const objectQuery = useInfiniteQuery({
    queryKey: pageKey,
    enabled: expanded,
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) => api<ObjectPage>(`/api/v1/accounts/${account.id}/object-privileges?${new URLSearchParams({ q: search, limit: '8', ...(pageParam === '' ? {} : { cursor: pageParam }) })}`, { signal }),
    getNextPageParam: last => last.next_cursor || undefined,
    retry: (count, error) => !(error instanceof ApiError && error.status === 409) && count < 1,
  })
  const groups = objectQuery.data?.pages.flatMap(page => page.objects.map(toGroup)) ?? []
  const total = objectQuery.data?.pages[0]?.total_entries ?? 0
  const available = objectQuery.data?.pages[0]?.available
  const count = accountDirectObjectCount(account, bindings, byId)
  const mutable = roleAtLeast(auth.role, 'operator') && connection.capabilities.includes('postgres.object_acl.v1') &&
    (account.status === 'active' || account.status === 'disabled') && !policyRole && !objectRecord(account.attributes).connection_admin &&
    topology.postgres_object_acl_version === 1 && available === true && !objectQuery.isError
  const stale = objectQuery.error instanceof ApiError && objectQuery.error.status === 409
  return <div className="mt-3 space-y-2 border-t border-line pt-3">
    <details className="group/direct-acl" data-postgres-direct-privileges open={expanded} onToggle={event => setExpanded(event.currentTarget.open)}>
      <summary className="grantor-touch-target ui-control-feedback flex min-h-9 cursor-pointer list-none items-center gap-2 rounded px-1 text-xs focus-visible:outline-2 focus-visible:outline-accent">
        <ChevronRight className="size-3.5 shrink-0 text-muted group-open/direct-acl:rotate-90" aria-hidden />
        <span className="font-medium">Прямые права</span><span className="ml-auto tabular-nums text-muted">{directObjectSummary(count, topology)}</span>
      </summary>
      {expanded && <div className="mt-2 space-y-3 pl-5">
        {mutable && <Button variant="outline" size="sm" onClick={() => setCreating(true)}>Выдать прямой доступ</Button>}
        {objectACLIncomplete(topology) && <p className="text-xs text-warn">Часть баз недоступна. Их права сохранены по предыдущему снимку.</p>}
        {topology.postgres_object_acl_version !== 1 && <p className="text-xs text-muted">Нет снимка прямых прав. Синхронизируйте подключение.</p>}
        {topology.postgres_object_acl_version === 1 && available === false && <p className="text-xs text-muted">Снимок прямых прав недоступен. Синхронизируйте подключение.</p>}
        {(count > 0 || query !== '') && <SearchInput value={query} onChange={setQuery} ariaLabel="Поиск прямых прав" placeholder="Объект или действие" density="compact" />}
        {objectQuery.isPending && <p className="flex items-center gap-2 text-xs text-muted"><Spinner className="size-3.5" />Загружаем прямые права</p>}
        {objectQuery.isError && <><ErrorBanner>{stale ? 'Инвентарь обновился. Загрузите список заново.' : 'Не удалось загрузить прямые права.'}</ErrorBanner><Button variant="outline" size="sm" onClick={() => { void client.resetQueries({ queryKey: pageKey, exact: true }) }}>Обновить список</Button></>}
        {objectQuery.isSuccess && available === true && groups.length === 0 && !objectACLIncomplete(topology) && topology.postgres_object_acl_version === 1 && <p className="text-xs text-muted">{search === '' ? 'Прямых grants не обнаружено' : 'Прямые права не найдены'}</p>}
        {groups.length > 0 && <ul className="divide-y divide-line">{groups.map(group => <li key={group.key} className="space-y-1.5 py-2">
          <div className="flex min-w-0 flex-wrap items-start justify-between gap-2">
            <span className="min-w-0 break-all font-mono text-xs">{group.resource}</span>
            {mutable && group.kind !== 'column' && group.owner !== account.engine_identity && group.permissions.some(p => p.assignable && p.status !== 'missing') && <Button variant="outline" size="sm" onClick={() => setEditing(group)}>Изменить</Button>}
          </div>
          <p className="break-words font-mono text-xs">{group.bindings.filter(present).map(b => group.permissions.find(p => p.id === b.permission_definition_id)?.normalized.action).filter(Boolean).join(', ')}</p>
          {group.bindings.some(b => b.status === 'failed' || b.status === 'drift' || (b.desired_state === 'present' && (!present(b) || !b.observed_effective)) || (b.desired_state === 'absent' && present(b))) && <p className="text-xs text-warn">Есть неподтвержденные изменения прав. Проверьте операции.</p>}
          <p className="text-xs text-muted">{group.kind === 'column' ? 'Права на колонку, только просмотр' : group.bindings.some(b => b.desired_state !== null) ? 'Есть управляемые права' : 'Прямые grants вне управления'}</p>
        </li>)}</ul>}
        {objectQuery.hasNextPage && <Button variant="outline" size="sm" disabled={objectQuery.isFetchingNextPage || objectQuery.isError} onClick={() => { void objectQuery.fetchNextPage() }}>{objectQuery.isFetchingNextPage && <Spinner className="size-3.5" />}Показать ещё</Button>}
        {groups.length > 0 && <p className="text-xs tabular-nums text-muted">Показано {groups.length} из {total}</p>}
      </div>}
    </details>
    <PostgresDefaultPrivileges accountId={account.id} topology={topology} />
    {(editing !== null || creating) && <ObjectPrivilegeEditor account={account} connection={connection} initial={editing} roleBindings={bindings} rolePermissions={byId}
      onClose={() => { setEditing(null); setCreating(false) }} onStarted={onStarted} />}
  </div>
}

function PostgresDefaultPrivileges({ accountId, topology }: { accountId: string; topology: unknown }) {
  const client = useQueryClient()
  const [expanded, setExpanded] = useState(false)
  const [query, setQuery] = useState('')
  const search = useDebouncedQuery(query)
  const pageKey = qk.accountDefaultPrivileges(accountId, search)
  const defaultsQuery = useInfiniteQuery({
    queryKey: pageKey,
    enabled: expanded,
    initialPageParam: '',
    queryFn: ({ pageParam, signal }) => api<DefaultPage>(`/api/v1/accounts/${accountId}/default-privileges?${new URLSearchParams({ q: search, limit: '8', ...(pageParam === '' ? {} : { cursor: pageParam }) })}`, { signal }),
    getNextPageParam: last => last.next_cursor || undefined,
    retry: (count, error) => !(error instanceof ApiError && error.status === 409) && count < 1,
  })
  const rows = defaultsQuery.data?.pages.flatMap(page => page.rules) ?? []
  const first = defaultsQuery.data?.pages[0]
  return <details className="group/default-acl" data-postgres-default-privileges open={expanded} onToggle={event => setExpanded(event.currentTarget.open)}>
    <summary className="grantor-touch-target ui-control-feedback flex min-h-9 cursor-pointer list-none items-center gap-2 rounded px-1 text-xs focus-visible:outline-2 focus-visible:outline-accent">
      <ChevronRight className="size-3.5 shrink-0 text-muted group-open/default-acl:rotate-90" aria-hidden />
      <span>Новые объекты</span><span className="ml-auto tabular-nums text-muted">{first?.available && first.total_entries !== null ? `Всего: ${first.total_entries}` : 'Только просмотр'}</span>
    </summary>
    {expanded && <div className="mt-2 space-y-3 pl-5 text-xs">
      <p className="text-muted">Default privileges применяются к будущим объектам. Здесь они доступны для просмотра.</p>
      {objectACLIncomplete(topology) && <p className="text-warn">Часть баз недоступна. Список правил может быть неполным.</p>}
      <SearchInput value={query} onChange={setQuery} ariaLabel="Поиск правил новых объектов" placeholder="База, схема или действие" density="compact" />
      {defaultsQuery.isPending && <p className="flex items-center gap-2 text-muted"><Spinner className="size-3.5" />Загружаем правила новых объектов</p>}
      {defaultsQuery.isError && <><ErrorBanner>Не удалось загрузить правила. Возможно, снимок обновился.</ErrorBanner><Button variant="outline" size="sm" onClick={() => { void client.resetQueries({ queryKey: pageKey, exact: true }) }}>Обновить правила</Button></>}
      {first?.available === false && <p className="text-muted">Нет снимка default privileges. Синхронизируйте подключение.</p>}
      {defaultsQuery.isSuccess && first?.available && rows.length === 0 && !objectACLIncomplete(topology) && <p className="text-muted">{search === '' ? 'Прямых default privileges не обнаружено' : 'Правила не найдены'}</p>}
      {rows.map((row, index) => <p key={index} className="break-words font-mono [overflow-wrap:anywhere]">{row.database} · {row.creator} · {row.schema || 'все схемы'} · {({ r: 'таблицы', S: 'sequences', f: 'функции', T: 'типы', n: 'схемы' } as Record<string, string>)[row.kind] ?? row.kind} · {row.privilege}{row.grant_option ? ' WITH GRANT OPTION' : ''}</p>)}
      {defaultsQuery.hasNextPage && <Button variant="outline" size="sm" disabled={defaultsQuery.isFetchingNextPage || defaultsQuery.isError} onClick={() => { void defaultsQuery.fetchNextPage() }}>{defaultsQuery.isFetchingNextPage && <Spinner className="size-3.5" />}Показать ещё</Button>}
      {rows.length > 0 && first?.total_entries !== null && <p className="tabular-nums text-muted">Показано {rows.length} из {first?.total_entries}</p>}
    </div>}
  </details>
}

function ObjectPrivilegeEditor({ account, connection, initial, onClose, onStarted, roleBindings, rolePermissions }: {
  account: Account; connection: Connection; initial: ObjectPrivilegeGroup | null
  roleBindings: Binding[]; rolePermissions: Map<string, Permission>
  onClose: () => void; onStarted: Props['onStarted']
}) {
  const auth = useAuth()
  const client = useQueryClient()
  const objectSelectId = useId()
  const [selected, setSelected] = useState(initial?.scopeId ?? '')
  const [query, setQuery] = useState('')
  const search = useDebouncedQuery(query)
  const [group, setGroup] = useState<ObjectPrivilegeGroup | null>(initial)
  const [checked, setChecked] = useState(new Set(initial?.bindings.filter(present).map(b => b.permission_definition_id) ?? []))
  const [review, setReview] = useState(false)
  const [confirm, setConfirm] = useState(false)
  const targets = useQuery({
    queryKey: qk.objectPrivilegeTargets(connection.id, search),
    queryFn: ({ signal }) => api<TargetPage>(`/api/v1/connections/${connection.id}/object-privilege-targets?${new URLSearchParams({ q: search, limit: '20' })}`, { signal }),
  })
  const selectedTarget = useQuery({
    queryKey: qk.accountObjectTarget(account.id, selected),
    enabled: selected !== '' && group?.scopeId !== selected,
    queryFn: ({ signal }) => api<ObjectPage>(`/api/v1/accounts/${account.id}/object-privileges?${new URLSearchParams({ scope_resource_id: selected })}`, { signal }),
    retry: false,
  })
  useEffect(() => {
    const next = selectedTarget.data?.objects[0]
    if (next === undefined || next.scope_id !== selected || group?.scopeId === selected) return
    const candidate = toGroup(next)
    setGroup(candidate); setChecked(new Set(candidate.bindings.filter(present).map(b => b.permission_definition_id)))
  }, [group?.scopeId, selected, selectedTarget.data])
  const baseline = group?.bindings.filter(present) ?? []
  const permissionsById = new Map(group?.permissions.map(p => [p.id, p]) ?? [])
  const additions = group?.permissions.filter(p => checked.has(p.id) && !baseline.some(b => b.permission_definition_id === p.id)) ?? []
  const removals = baseline.filter(b => !checked.has(b.permission_definition_id))
  const dangerous = additions.some(p => p.dangerous)
  const roleSources = roleBindings.filter(b => present(b) && rolePermissions.get(b.permission_definition_id)?.normalized.category === 'role')
  const mutation = useMutation({
    mutationFn: () => apiPost<ManageAccountRolesResponse>(`/api/v1/accounts/${account.id}/object-privileges`, {
      add_permission_ids: additions.map(p => p.id), remove_binding_ids: removals.map(b => b.id), confirm,
    }),
    onSuccess: data => {
      void client.invalidateQueries({ queryKey: qk.accountObjectPrivileges(account.id) })
      void client.invalidateQueries({ queryKey: qk.connectionAccounts(connection.id) })
      onStarted(data.operation_id, `Изменение прямых прав ${account.engine_identity}`)
      onClose()
    },
  })
  const options = targets.data?.objects ?? []
  const selectTarget = (scope: string) => {
    setSelected(scope); setGroup(null); setChecked(new Set()); setReview(false); setConfirm(false)
  }
  return <Drawer open onClose={onClose} title={review ? 'Проверить изменения' : 'Изменить прямые права'} description={`${account.engine_identity} · ${connection.display_name} · ${connection.environment}`}>
    <div className="space-y-4">
      <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-xs">
        <dt className="text-muted">Получатель</dt><dd className="min-w-0 break-all font-mono">{account.engine_identity}</dd>
        <dt className="text-muted">Подключение</dt><dd className="min-w-0 break-words">{connection.display_name}</dd>
        <dt className="text-muted">Окружение</dt><dd className="min-w-0 break-words">{connection.environment}</dd>
      </dl>
      {!review ? <>
        <SearchInput value={query} onChange={setQuery} ariaLabel="Поиск объекта для прямого доступа" placeholder="База, схема или объект" />
        <Field label="Объект" htmlFor={objectSelectId}><select id={objectSelectId} className="w-full min-w-0 rounded border border-line bg-panel2 px-3 py-2 text-sm text-text" value={selected} onChange={event => selectTarget(event.target.value)}>
          <option value="">Выберите объект</option>
          {selected !== '' && !options.some(target => target.scope_id === selected) && <option value={selected}>{group?.resource ?? selected}</option>}
          {options.map(target => <option key={target.scope_id} value={target.scope_id}>{target.resource}</option>)}
        </select></Field>
        {targets.isPending && <p className="text-xs text-muted">Ищем объекты</p>}
        {targets.isError && <ErrorBanner>Не удалось загрузить объекты. Измените поиск или откройте форму заново.</ErrorBanner>}
        {targets.data?.next_cursor && <p className="text-xs text-muted">Показаны первые 20 совпадений. Уточните поиск.</p>}
        {selected !== '' && group === null && selectedTarget.isPending && <p className="text-xs text-muted">Загружаем права выбранного объекта</p>}
        {selectedTarget.isError && <ErrorBanner>Не удалось загрузить права объекта. Выберите его заново.</ErrorBanner>}
        {group?.owner === account.engine_identity && <p className="text-xs text-muted">Учетка владеет этим объектом. Владение меняется отдельно.</p>}
        {group !== null && <fieldset className="space-y-2"><legend className="mb-2 text-sm">Прямые права после изменения</legend>
          {group.permissions.map(p => <label key={p.id} className="flex min-h-10 items-center gap-2 rounded bg-panel2 px-3 py-2 text-sm">
            <input type="checkbox" checked={checked.has(p.id)} disabled={!p.assignable || p.status === 'missing' || group.owner === account.engine_identity || baseline.some(b => b.permission_definition_id === p.id && !bindingManagementEligible(b)) || (p.dangerous && !roleAtLeast(auth.role, 'admin'))} onChange={event => setChecked(current => {
              const next = new Set(current); if (event.target.checked) next.add(p.id); else next.delete(p.id); return next
            })} /><span className="font-mono">{p.normalized.action}</span>{baseline.some(b => b.permission_definition_id === p.id && !bindingManagementEligible(b)) ? <span className="text-xs text-muted">только просмотр</span> : p.dangerous && <span className="text-xs text-warn">расширенные полномочия</span>}
          </label>)}
        </fieldset>}
        <p className="text-xs text-muted">Меняются только выбранные прямые grants. Роли, другие объекты и default privileges сохраняются.</p>
        <Button disabled={group === null || additions.length + removals.length === 0} onClick={() => setReview(true)}>Проверить изменения</Button>
      </> : <>
        <p className="break-all font-mono text-sm">{group?.resource}</p>
        <ul className="space-y-2 text-sm">
          {additions.map(p => <li key={p.id}>Выдать <span className="font-mono">{p.normalized.action}</span></li>)}
          {removals.map(b => <li key={b.id}>Отозвать <span className="font-mono">{permissionsById.get(b.permission_definition_id)?.normalized.action}</span></li>)}
        </ul>
        {removals.length > 0 && <p className="rounded bg-warn/10 p-3 text-xs text-warn">Отзыв прямого grant не является запретом. {roleSources.length > 0 ? 'У учетки также есть назначения ролей. ' : ''}{group?.public_privileges?.length ? `На объекте есть PUBLIC: ${group.public_privileges.join(', ')}. ` : ''}Доступ через роли, PUBLIC, владение и ограничения RLS учитывается отдельно.</p>}
        <p className="text-xs text-muted">Каждое право проверяется отдельной операцией. Частичный результат будет виден в списке операций.</p>
        {dangerous && <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={confirm} onChange={event => setConfirm(event.target.checked)} />Подтверждаю выдачу расширенных полномочий</label>}
        {mutation.isError && <ErrorBanner>{errorMessage(mutation.error)}</ErrorBanner>}
        <div className="flex flex-wrap gap-2"><Button disabled={mutation.isPending || (dangerous && !confirm)} onClick={() => mutation.mutate()}>{mutation.isPending && <Spinner className="size-4" />}Применить изменения</Button><Button variant="outline" disabled={mutation.isPending} onClick={() => setReview(false)}>Назад</Button></div>
      </>}
    </div>
  </Drawer>
}
